const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const db      = require('../db/database');
const { sendVerificationEmail } = require('./email');

const JWT_SECRET  = process.env.JWT_SECRET || 'shieldscan_secret_change_in_production';
const COOKIE_OPTS = { httpOnly: true, maxAge: 7*24*60*60*1000, sameSite: 'lax' };

function getBaseUrl(req) {
  // Works on localhost AND Render/any cloud host
  if (process.env.BASE_URL) return process.env.BASE_URL;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.headers.host}`;
}

// ── Register ──────────────────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    await db.getDb();
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'All fields required.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters.' });
    if (db.findUserByEmail(email)) return res.status(400).json({ error: 'Email already registered.' });
    if (db.findUserByUsername(username)) return res.status(400).json({ error: 'Username already taken.' });

    const hash    = await bcrypt.hash(password, 10);
    const count   = db.getUserCount();
    const role    = count === 0 ? 'admin' : 'user';

    // Generate verification token
    const verifyToken   = crypto.randomBytes(32).toString('hex');
    const verifyExpires = new Date(Date.now() + 24*60*60*1000).toISOString(); // 24 hours

    db.createUser(username.trim(), email.trim().toLowerCase(), hash, role, verifyToken, verifyExpires);

    // Send verification email
    const baseUrl = getBaseUrl(req);
    const emailResult = await sendVerificationEmail(email, username, verifyToken, baseUrl);

    const devMode = emailResult?.dev === true;

    res.json({
      success: true,
      message: devMode
        ? 'Account created! Check your terminal for the verification link (dev mode — no email key set).'
        : 'Account created! Please check your email to verify your account before logging in.',
      devMode,
      // In dev mode, expose token so user can verify immediately
      devVerifyUrl: devMode ? `${baseUrl}/api/auth/verify/${verifyToken}` : undefined
    });
  } catch (err) {
    console.error('[Register]', err);
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// ── Verify Email ──────────────────────────────────────────────────────────────
router.get('/verify/:token', async (req, res) => {
  try {
    await db.getDb();
    const user = db.findUserByToken(req.params.token);

    if (!user) {
      return res.send(verifyPage('❌ Invalid Link', 'This verification link is invalid or has already been used.', 'error'));
    }

    // Check expiry
    if (new Date(user.verify_expires) < new Date()) {
      return res.send(verifyPage('⏰ Link Expired', 'This verification link has expired. Please register again.', 'error'));
    }

    db.verifyUser(user.id);
    res.send(verifyPage('✅ Email Verified!', `Welcome to ShieldScan, ${user.username}! Your account is now active. You can close this tab and log in.`, 'success'));
  } catch (err) {
    res.send(verifyPage('❌ Error', 'Something went wrong. Please try again.', 'error'));
  }
});

function verifyPage(title, message, type) {
  const color = type === 'success' ? '#10b981' : '#ef4444';
  return `<!DOCTYPE html><html><head><title>${title} — ShieldScan</title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&display=swap" rel="stylesheet">
  </head>
  <body style="margin:0;background:#060a10;font-family:'Syne',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;">
    <div style="text-align:center;max-width:440px;padding:40px;background:#0d1321;border:1px solid rgba(99,179,255,0.15);border-radius:20px;">
      <div style="font-size:52px;margin-bottom:16px;">${type === 'success' ? '🎉' : '⚠️'}</div>
      <div style="font-size:28px;font-weight:800;color:#e2e8f0;margin-bottom:12px;">${title}</div>
      <p style="color:#64748b;font-size:15px;line-height:1.7;margin:0 0 28px;">${message}</p>
      <a href="/" style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#06b6d4);color:white;text-decoration:none;padding:12px 28px;border-radius:10px;font-size:14px;font-weight:700;">
        Go to ShieldScan →
      </a>
    </div>
  </body></html>`;
}

// ── Login ─────────────────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    await db.getDb();
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

    const user = db.findUserByEmail(email.trim().toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password.' });

    // Block unverified users
    if (!user.is_verified) {
      return res.status(403).json({
        error: 'Please verify your email before logging in. Check your inbox (or terminal in dev mode).',
        unverified: true
      });
    }

    db.updateLastLogin(user.id);
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, COOKIE_OPTS);
    res.json({ success: true, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed: ' + err.message });
  }
});

// ── Logout ────────────────────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// ── Me ────────────────────────────────────────────────────────────────────────
router.get('/me', async (req, res) => {
  try {
    await db.getDb();
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.findUserById(payload.id);
    if (!user) return res.status(401).json({ error: 'User not found' });
    res.json({ user });
  } catch {
    res.status(401).json({ error: 'Invalid session' });
  }
});

module.exports = router;
