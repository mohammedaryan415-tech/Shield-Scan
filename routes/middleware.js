const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'shieldscan_secret_change_in_production';

function requireAuth(req, res, next) {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Login required.' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired. Please login again.' });
  }
}

function requireAdmin(req, res, next) {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Login required.' });
    req.user = jwt.verify(token, JWT_SECRET);
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
    next();
  } catch {
    res.status(401).json({ error: 'Session expired.' });
  }
}

module.exports = { requireAuth, requireAdmin };
