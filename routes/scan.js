const express = require('express');
const router  = express.Router();
const axios   = require('axios');
const crypto  = require('crypto');
const { requireAuth } = require('./middleware');
const db = require('../db/database');

function hashUrl(url) { return crypto.createHash('sha256').update(url.toLowerCase().trim()).digest('hex'); }
function sanitizeUrl(raw) {
  let url = raw.trim();
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  return url;
}

function computeVerdict(vtPos, vtTotal, googleFlagged, aiVerdict) {
  let score = 0;
  if (vtTotal > 0) {
    if (vtPos >= 5) score += 60;
    else if (vtPos >= 2) score += 40;
    else if (vtPos === 1) score += 20;
    score += Math.round((vtPos / vtTotal) * 30);
  }
  if (googleFlagged) score += 50;
  if (aiVerdict === 'dangerous') score += 30;
  else if (aiVerdict === 'suspicious') score += 15;
  score = Math.min(score, 100);
  let verdict = score >= 60 ? 'dangerous' : score >= 25 ? 'suspicious' : (vtTotal === 0 && !googleFlagged) ? 'unknown' : 'safe';
  return { verdict, risk_score: score };
}

async function scanWithVirusTotal(url) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key || key === 'your_virustotal_api_key_here') return { positives: 0, total: 0, skipped: true };
  try {
    await axios.post('https://www.virustotal.com/vtapi/v2/url/scan',
      new URLSearchParams({ apikey: key, url }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
    const rep = await axios.get('https://www.virustotal.com/vtapi/v2/url/report',
      { params: { apikey: key, resource: url }, timeout: 10000 });
    const d = rep.data;
    if (d.response_code === 1) return { positives: d.positives || 0, total: d.total || 0, permalink: d.permalink, raw: d };
    return { positives: 0, total: 0, pending: true };
  } catch (err) { return { positives: 0, total: 0, error: err.message }; }
}

async function checkGoogleSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key || key === 'your_google_safe_browsing_key_here') return { flagged: false, skipped: true };
  try {
    const res = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`,
      { client: { clientId: 'link-safety-checker', clientVersion: '2.0.0' },
        threatInfo: { threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }] } },
      { timeout: 8000 });
    return { flagged: !!(res.data.matches?.length), threats: res.data.matches || [] };
  } catch (err) { return { flagged: false, error: err.message }; }
}

// ── AI Analysis — tries Groq first, falls back to built-in heuristics ────────

async function analyzeWithAI(url, vtData, googleData) {

  // ── Option A: Groq (free) ──────────────────────────────────────────────
  const groqKey = process.env.GROQ_API_KEY;
  if (groqKey && groqKey !== 'your_groq_api_key_here') {
    try {
      const res = await axios.post(
        'https://api.groq.com/openai/v1/chat/completions',
        {
          model: 'llama3-70b-8192',
          max_tokens: 500,
          temperature: 0.1,
          messages: [
            {
              role: 'system',
              content: 'You are a cybersecurity expert. Always respond with valid JSON only, no markdown, no extra text.'
            },
            {
              role: 'user',
              content: `Analyze this URL for safety and phishing risk.

URL: ${url}
VirusTotal: ${vtData.positives || 0}/${vtData.total || 0} engines flagged
Google Safe Browsing: ${googleData.flagged ? 'FLAGGED AS DANGEROUS' : googleData.skipped ? 'not checked' : 'clean'}

Check for: typosquatting, phishing patterns, suspicious TLDs (.xyz/.tk/.ml), URL shorteners, lookalike domains, excessive subdomains, suspicious keywords (login, verify, secure, account, update, confirm).

Respond ONLY with this exact JSON format:
{"verdict":"safe|suspicious|dangerous|unknown","confidence":"high|medium|low","risk_score":0,"summary":"one sentence max","reasons":["reason1","reason2","reason3"],"recommendation":"one sentence advice for user"}`
            }
          ]
        },
        {
          headers: {
            'Authorization': `Bearer ${groqKey}`,
            'Content-Type': 'application/json'
          },
          timeout: 15000
        }
      );

      const text = res.data.choices[0].message.content.trim().replace(/```json|```/g, '').trim();
      const parsed = JSON.parse(text);
      return { ...parsed, provider: 'Groq (Llama 3)', skipped: false };
    } catch (err) {
      console.error('[Groq AI Error]', err.message);
      // Fall through to heuristic analysis
    }
  }

  // ── Option B: Anthropic Claude (paid) ─────────────────────────────────
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (anthropicKey && anthropicKey.startsWith('sk-ant')) {
    try {
      const res = await axios.post('https://api.anthropic.com/v1/messages', {
        model: 'claude-sonnet-4-20250514', max_tokens: 500,
        messages: [{ role: 'user', content:
          `Analyze this URL for safety.\nURL: ${url}\nVirusTotal: ${vtData.positives||0}/${vtData.total||0} flagged\nGoogle: ${googleData.flagged?'FLAGGED':'clean'}\n\nRespond ONLY with JSON:\n{"verdict":"safe|suspicious|dangerous|unknown","confidence":"high|medium|low","risk_score":0,"summary":"one sentence","reasons":["r1","r2","r3"],"recommendation":"advice"}`
        }]
      }, { headers: { 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' }, timeout: 20000 });
      const parsed = JSON.parse(res.data.content[0].text.trim().replace(/```json|```/g,'').trim());
      return { ...parsed, provider: 'Claude AI', skipped: false };
    } catch (err) {
      console.error('[Anthropic Error]', err.message);
    }
  }

  // ── Option C: Built-in heuristic analysis (no API key needed) ─────────
  return heuristicAnalysis(url, vtData, googleData);
}

function heuristicAnalysis(url, vtData, googleData) {
  const reasons = [];
  let score = 0;

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const fullUrl  = url.toLowerCase();

    // Suspicious TLDs
    const badTlds = ['.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.click','.download','.loan','.win','.bid','.stream'];
    if (badTlds.some(t => hostname.endsWith(t))) {
      score += 25; reasons.push('Uses a high-risk or free TLD commonly used in scams');
    }

    // IP address as hostname
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 40; reasons.push('URL uses a raw IP address instead of a domain name');
    }

    // Excessive subdomains
    const parts = hostname.split('.');
    if (parts.length > 4) {
      score += 20; reasons.push('Unusually high number of subdomains — common phishing pattern');
    }

    // Suspicious keywords in URL
    const phishWords = ['login','verify','secure','account','update','confirm','banking','password','signin','paypal','amazon','apple','microsoft','google','facebook'];
    const foundWords = phishWords.filter(w => fullUrl.includes(w));
    if (foundWords.length >= 2) {
      score += 30; reasons.push(`Contains multiple sensitive keywords: ${foundWords.slice(0,3).join(', ')}`);
    } else if (foundWords.length === 1) {
      score += 10; reasons.push(`Contains sensitive keyword: ${foundWords[0]}`);
    }

    // URL shorteners
    const shorteners = ['bit.ly','tinyurl','t.co','goo.gl','ow.ly','short.io','tiny.cc','is.gd','buff.ly','rebrand.ly'];
    if (shorteners.some(s => hostname.includes(s))) {
      score += 20; reasons.push('Uses a URL shortener which hides the real destination');
    }

    // Very long URL
    if (url.length > 200) {
      score += 15; reasons.push('Unusually long URL — may be obfuscating the real destination');
    }

    // Typosquatting check (common brand misspellings)
    const brands = ['google','facebook','amazon','paypal','apple','microsoft','netflix','instagram','twitter','youtube'];
    brands.forEach(brand => {
      if (hostname.includes(brand) && !hostname.endsWith(`.com`) && !hostname === `${brand}.com` && !hostname === `www.${brand}.com`) {
        score += 35; reasons.push(`Domain impersonates "${brand}" — possible typosquatting`);
      }
    });

    // HTTPS check
    if (parsed.protocol !== 'https:') {
      score += 10; reasons.push('Not using HTTPS — connection is not encrypted');
    }

    if (reasons.length === 0) {
      reasons.push('No obvious suspicious patterns detected in URL structure');
      reasons.push('Domain appears to follow standard naming conventions');
    }

  } catch {
    reasons.push('Could not fully parse URL structure');
    score += 10;
  }

  // Add VT and Google context
  if (vtData.positives > 0) reasons.push(`Flagged by ${vtData.positives} VirusTotal security engines`);
  if (googleData.flagged) reasons.push('Confirmed dangerous by Google Safe Browsing');

  score = Math.min(score, 100);
  const verdict = score >= 60 ? 'dangerous' : score >= 25 ? 'suspicious' : 'safe';
  const recMap  = {
    safe: 'This link appears safe based on URL analysis. Always stay cautious.',
    suspicious: 'Proceed with caution — avoid entering personal information.',
    dangerous: 'Do NOT visit this link. It shows multiple signs of being malicious.'
  };

  return {
    verdict,
    confidence: 'medium',
    risk_score: score,
    summary: `Heuristic analysis: ${reasons[0]}`,
    reasons,
    recommendation: recMap[verdict],
    provider: 'Built-in Heuristics',
    skipped: false
  };
}

// ── Scan endpoint ─────────────────────────────────────────────────────────────
router.post('/scan', requireAuth, async (req, res) => {
  try {
    await db.getDb();
    const { url: rawUrl, force = false } = req.body;
    if (!rawUrl) return res.status(400).json({ error: 'URL is required' });

    const url     = sanitizeUrl(rawUrl);
    const urlHash = hashUrl(url);
    const userId  = req.user.id;

    if (!force) {
      const cached = db.saveOrGetCachedScan(userId, urlHash, 60);
      if (cached) return res.json({ ...cached, ai_reasons: JSON.parse(cached.ai_reasons || '[]'), cached: true });
    }

    const [vtData, googleData] = await Promise.all([scanWithVirusTotal(url), checkGoogleSafeBrowsing(url)]);
    const aiData = await analyzeWithAI(url, vtData, googleData);
    const { verdict, risk_score } = computeVerdict(vtData.positives||0, vtData.total||0, googleData.flagged||false, aiData.verdict);

    const id = db.saveScan({
      user_id: userId, url, url_hash: urlHash, verdict, risk_score,
      vt_positives: vtData.positives||0, vt_total: vtData.total||0,
      google_flagged: googleData.flagged ? 1 : 0,
      ai_analysis: aiData.summary||'', ai_verdict: aiData.verdict||'unknown',
      ai_reasons: JSON.stringify(aiData.reasons||[]),
      ai_recommendation: aiData.recommendation||'',
      raw_vt_data: JSON.stringify(vtData.raw||{})
    });

    res.json({
      id, url, verdict, risk_score,
      vt_positives: vtData.positives||0, vt_total: vtData.total||0,
      google_flagged: googleData.flagged||false,
      ai_analysis: aiData.summary||'', ai_verdict: aiData.verdict||'unknown',
      ai_reasons: aiData.reasons||[], ai_recommendation: aiData.recommendation||'',
      ai_confidence: aiData.confidence||'medium',
      ai_provider: aiData.provider || 'Built-in Heuristics',
      vt_permalink: vtData.permalink||null,
      services: {
        virustotal: !vtData.skipped && !vtData.error,
        google_safe_browsing: !googleData.skipped && !googleData.error,
        ai: !aiData.skipped
      },
      cached: false
    });
  } catch (err) {
    console.error('[Scan Error]', err);
    res.status(500).json({ error: 'Scan failed: ' + err.message });
  }
});

router.get('/my-scans', requireAuth, async (req, res) => {
  await db.getDb();
  res.json(db.getUserScans(req.user.id, 30));
});

router.get('/my-stats', requireAuth, async (req, res) => {
  await db.getDb();
  res.json(db.getUserStats(req.user.id));
});

router.get('/global-stats', async (req, res) => {
  await db.getDb();
  res.json(db.getGlobalStats());
});

module.exports = router;
