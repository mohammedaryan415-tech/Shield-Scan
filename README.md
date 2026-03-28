# 🛡️ ShieldScan — Link Safety Checker

An AI-powered URL safety checker with a beautiful dark UI. Combines **VirusTotal** (70+ security engines), **Google Safe Browsing**, **Claude AI analysis**, and a local **SQLite database** to tell you if a link is safe or a scam.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd link-safety-checker
npm install
```

### 2. Set Up API Keys
```bash
# Copy the example file
cp .env.example .env
```

Then edit `.env` and add your keys:

```env
ANTHROPIC_API_KEY=sk-ant-...       # Required for AI analysis
VIRUSTOTAL_API_KEY=...             # Required for 70+ engine scan
GOOGLE_SAFE_BROWSING_KEY=...       # Optional but recommended
```

#### Where to get API keys (all FREE):
| Service | URL | Free Tier |
|---------|-----|-----------|
| **Anthropic (Claude AI)** | https://console.anthropic.com/ | Yes, pay-per-use |
| **VirusTotal** | https://www.virustotal.com/gui/my-apikey | 4 req/min FREE |
| **Google Safe Browsing** | https://developers.google.com/safe-browsing/v4/get-started | 10,000 req/day FREE |

### 3. Run the Server
```bash
# Production
npm start

# Development (auto-restarts on change)
npm run dev
```

### 4. Open in Browser
Visit: **http://localhost:3000**

---

## 📁 Project Structure

```
link-safety-checker/
├── server.js              # Express server entry point
├── package.json
├── .env                   # Your API keys (create this!)
├── .env.example           # Template for .env
├── routes/
│   └── scan.js            # API routes + scan logic
├── db/
│   ├── database.js        # SQLite database module
│   └── links.db           # Auto-created SQLite database
└── public/
    └── index.html         # Frontend UI
```

---

## 🔌 API Endpoints

### `POST /api/scan`
Scan a URL for safety.

**Request:**
```json
{ "url": "https://example.com", "force": false }
```

**Response:**
```json
{
  "verdict": "safe|suspicious|dangerous|unknown",
  "risk_score": 0-100,
  "vt_positives": 0,
  "vt_total": 72,
  "google_flagged": false,
  "ai_analysis": "This domain appears legitimate...",
  "ai_verdict": "safe",
  "ai_reasons": ["Established domain", "No suspicious patterns"],
  "ai_recommendation": "Safe to visit",
  "cached": false
}
```

### `GET /api/recent`
Get 15 most recent scans from database.

### `GET /api/stats`
Get total scan counts by verdict.

### `GET /api/search?q=example.com`
Search past scans by URL.

---

## 🧠 How It Works

1. **URL submitted** → normalized and hashed
2. **Cache check** → if scanned in last 60 min, return cached result
3. **VirusTotal** → submits URL, gets report from 70+ antivirus engines
4. **Google Safe Browsing** → checks against Google's threat database
5. **Claude AI** → analyzes URL patterns, domain reputation, phishing signals
6. **Risk Score** calculated from all three sources (0-100)
7. **Verdict** → safe / suspicious / dangerous / unknown
8. **Saved to SQLite** database for future reference

---

## 🎨 Features

- ⚡ Real-time scanning with animated UI
- 🤖 Claude AI explains *why* a URL is suspicious
- 📊 Risk score (0-100) with visual progress bars
- 🗃️ SQLite database — all scans stored locally
- 📈 Stats dashboard (total, safe, suspicious, dangerous)
- 🕐 Recent scans history (click to re-scan)
- ⚡ 60-minute result caching (no wasted API calls)
- 📱 Responsive mobile design

---

## 🔧 VS Code Tips

1. Install the **REST Client** extension to test API directly
2. Install **SQLite Viewer** extension to browse the database
3. Use **nodemon** (already in devDependencies) for hot-reload

### Recommended VS Code Extensions:
- `humao.rest-client` — Test API endpoints
- `qwtel.sqlite-viewer` — Browse SQLite database
- `esbenp.prettier-vscode` — Code formatting

---

## ⚠️ Notes

- The app **works without API keys** but with limited functionality
- VirusTotal free tier: 4 requests/minute
- Results are cached for 60 minutes to save API quota
- The SQLite database is stored at `db/links.db`
# Shield-Scan
