require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const path         = require('path');
const fs           = require('fs');
const db           = require('./db/database');

const dbDir = path.join(__dirname, 'db');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/auth',  require('./routes/auth'));
app.use('/api',       require('./routes/scan'));
app.use('/api/admin', require('./routes/admin'));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize DB before starting server
// Set DB path for Render persistent disk
if (process.env.NODE_ENV === 'production' && !process.env.DB_PATH) {
  process.env.DB_PATH = '/data';
}

db.getDb().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🛡️  ShieldScan v2 running at http://localhost:${PORT}`);
    console.log(`\n📋 API Keys Status:`);
    console.log(`   Anthropic AI:   ${process.env.ANTHROPIC_API_KEY?.startsWith('sk-') ? '✅ Set' : '❌ Not set (add to .env)'}`);
    console.log(`   VirusTotal:     ${process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY !== 'your_virustotal_api_key_here' ? '✅ Set' : '❌ Not set (add to .env)'}`);
    console.log(`   Google SB:      ${process.env.GOOGLE_SAFE_BROWSING_KEY && process.env.GOOGLE_SAFE_BROWSING_KEY !== 'your_google_safe_browsing_key_here' ? '✅ Set' : '⚠️  Optional'}`);
    console.log(`\n💡 Tip: First user to register becomes Admin\n`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
