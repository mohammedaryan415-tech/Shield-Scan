const express = require('express');
const router  = express.Router();
const { requireAdmin } = require('./middleware');
const db = require('../db/database');

router.get('/users', requireAdmin, async (req, res) => {
  await db.getDb();
  res.json(db.getAllUsers());
});

router.get('/users/:id/scans', requireAdmin, async (req, res) => {
  await db.getDb();
  res.json({ scans: db.getUserScans(req.params.id, 50), stats: db.getUserStats(req.params.id) });
});

router.delete('/users/:id', requireAdmin, async (req, res) => {
  await db.getDb();
  db.deleteUser(req.params.id);
  res.json({ success: true });
});

router.get('/stats', requireAdmin, async (req, res) => {
  await db.getDb();
  res.json(db.getGlobalStats());
});

router.get('/recent', requireAdmin, async (req, res) => {
  await db.getDb();
  res.json(db.getRecentScansAll(20));
});

module.exports = router;
