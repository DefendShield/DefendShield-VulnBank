// Support messaging — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const marked = require('marked'); // VB-123/039 old marked -> raw HTML/XSS

function requireLogin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

router.get('/support', requireLogin, (req, res) => {
  const msgs = db.prepare('SELECT m.*, u.username FROM messages m JOIN users u ON u.id = m.user_id ORDER BY m.id DESC').all();
  res.render('support', { msgs });
});

// VB-030 stored XSS, VB-039 markdown XSS (raw HTML), VB-036 blind XSS (admin view).
router.post('/support', requireLogin, (req, res) => {
  const { subject, body } = req.body;
  db.prepare('INSERT INTO messages (user_id,subject,body) VALUES (?,?,?)')
    .run(req.user.id, subject, body);
  res.redirect('/support');
});

// Rendered markdown (old marked, sanitize off) -> XSS sink.
router.get('/message/:id', requireLogin, (req, res) => {
  const m = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!m) return res.status(404).send('No message');
  const html = marked(m.body || ''); // VB-039
  res.render('message', { m, html });
});

module.exports = router;
