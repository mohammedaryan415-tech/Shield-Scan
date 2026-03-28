const path = require('path');
const fs   = require('fs');

// Support Render's persistent disk path or local db folder
const DB_DIR  = process.env.DB_PATH || path.join(__dirname);
const DB_PATH = path.join(DB_DIR, 'links.db');

let SQL, db;

async function getDb() {
  if (db) return db;
  const initSqlJs = require('sql.js');
  SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  initSchema();
  return db;
}

function persist() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function initSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      is_verified INTEGER DEFAULT 0,
      verify_token TEXT,
      verify_expires TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      last_login TEXT,
      is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      url TEXT NOT NULL,
      url_hash TEXT NOT NULL,
      verdict TEXT NOT NULL,
      risk_score INTEGER DEFAULT 0,
      vt_positives INTEGER DEFAULT 0,
      vt_total INTEGER DEFAULT 0,
      google_flagged INTEGER DEFAULT 0,
      ai_analysis TEXT,
      ai_verdict TEXT,
      ai_reasons TEXT,
      ai_recommendation TEXT,
      raw_vt_data TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_url_hash ON scans(url_hash);
    CREATE INDEX IF NOT EXISTS idx_user_id  ON scans(user_id);
    CREATE INDEX IF NOT EXISTS idx_created  ON scans(created_at);
    CREATE INDEX IF NOT EXISTS idx_verify   ON users(verify_token);
  `);
  persist();
}

function run(sql, params = []) { db.run(sql, params); persist(); }

function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) { const r = stmt.getAsObject(); stmt.free(); return r; }
  stmt.free(); return null;
}

function all(sql, params = []) {
  const rows = [], stmt = db.prepare(sql);
  stmt.bind(params);
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free(); return rows;
}

// ── Users ──────────────────────────────────────────────────────────────────

function createUser(username, email, passwordHash, role = 'user', verifyToken = null, verifyExpires = null) {
  run(
    `INSERT INTO users (username, email, password_hash, role, is_verified, verify_token, verify_expires)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [username, email, passwordHash, role,
     verifyToken ? 0 : 1,   // if no token needed (dev mode), mark verified
     verifyToken, verifyExpires]
  );
}

function findUserByEmail(email)       { return get('SELECT * FROM users WHERE email = ?', [email]); }
function findUserByUsername(username) { return get('SELECT * FROM users WHERE username = ?', [username]); }
function findUserById(id)             { return get('SELECT id, username, email, role, is_verified, created_at, last_login FROM users WHERE id = ?', [id]); }
function findUserByToken(token)       { return get('SELECT * FROM users WHERE verify_token = ?', [token]); }
function getUserCount()               { return (get('SELECT COUNT(*) as c FROM users') || {}).c || 0; }

function verifyUser(userId) {
  run(`UPDATE users SET is_verified = 1, verify_token = NULL, verify_expires = NULL WHERE id = ?`, [userId]);
}

function updateLastLogin(userId) {
  run("UPDATE users SET last_login = datetime('now') WHERE id = ?", [userId]);
}

function getAllUsers() {
  return all(`
    SELECT u.id, u.username, u.email, u.role, u.is_verified, u.created_at, u.last_login,
      COUNT(s.id) AS total_scans,
      SUM(CASE WHEN s.verdict='safe'       THEN 1 ELSE 0 END) AS safe_scans,
      SUM(CASE WHEN s.verdict='dangerous'  THEN 1 ELSE 0 END) AS dangerous_scans,
      SUM(CASE WHEN s.verdict='suspicious' THEN 1 ELSE 0 END) AS suspicious_scans
    FROM users u LEFT JOIN scans s ON s.user_id = u.id
    GROUP BY u.id ORDER BY u.created_at DESC
  `);
}

function getUserStats(userId) {
  return get(`
    SELECT COUNT(*) AS total_scans,
      SUM(CASE WHEN verdict='safe'       THEN 1 ELSE 0 END) AS safe_scans,
      SUM(CASE WHEN verdict='dangerous'  THEN 1 ELSE 0 END) AS dangerous_scans,
      SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) AS suspicious_scans,
      SUM(CASE WHEN verdict='unknown'    THEN 1 ELSE 0 END) AS unknown_scans,
      AVG(risk_score) AS avg_risk_score,
      MAX(created_at) AS last_scan_at
    FROM scans WHERE user_id = ?
  `, [userId]);
}

// ── Scans ──────────────────────────────────────────────────────────────────

function saveOrGetCachedScan(userId, urlHash, maxAgeMinutes = 60) {
  const cutoff = new Date(Date.now() - maxAgeMinutes * 60 * 1000)
    .toISOString().replace('T',' ').split('.')[0];
  return get(`SELECT * FROM scans WHERE user_id=? AND url_hash=? AND created_at>?
              ORDER BY created_at DESC LIMIT 1`, [userId, urlHash, cutoff]);
}

function saveScan(d) {
  run(`INSERT INTO scans (user_id,url,url_hash,verdict,risk_score,vt_positives,vt_total,
       google_flagged,ai_analysis,ai_verdict,ai_reasons,ai_recommendation,raw_vt_data)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [d.user_id,d.url,d.url_hash,d.verdict,d.risk_score,d.vt_positives,d.vt_total,
     d.google_flagged,d.ai_analysis,d.ai_verdict,d.ai_reasons,d.ai_recommendation,d.raw_vt_data]);
  return (get('SELECT last_insert_rowid() as id') || {}).id;
}

function getUserScans(userId, limit = 30) {
  return all(`SELECT id,url,verdict,risk_score,vt_positives,vt_total,ai_verdict,created_at
              FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT ?`, [userId, limit]);
}

function getGlobalStats() {
  const s = get(`SELECT COUNT(*) AS total_scans,
    SUM(CASE WHEN verdict='safe'       THEN 1 ELSE 0 END) AS safe_count,
    SUM(CASE WHEN verdict='dangerous'  THEN 1 ELSE 0 END) AS dangerous_count,
    SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) AS suspicious_count FROM scans`);
  const u = get('SELECT COUNT(*) AS total_users FROM users');
  return { ...s, ...u };
}

function getRecentScansAll(limit = 20) {
  return all(`SELECT s.id,s.url,s.verdict,s.risk_score,s.created_at,u.username
              FROM scans s JOIN users u ON s.user_id=u.id
              ORDER BY s.created_at DESC LIMIT ?`, [limit]);
}

function deleteUser(userId) {
  run('DELETE FROM scans WHERE user_id=?', [userId]);
  run('DELETE FROM users WHERE id=?', [userId]);
}

module.exports = {
  getDb, getUserCount,
  createUser, findUserByEmail, findUserByUsername, findUserById,
  findUserByToken, verifyUser, updateLastLogin,
  getAllUsers, getUserStats,
  saveOrGetCachedScan, saveScan, getUserScans,
  getGlobalStats, getRecentScansAll, deleteUser
};
