// REST/JSON API + JWT — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken'); // 8.5.1 (old, alg-confusion prone)
const { db } = require('../db');

const JWT_SECRET = process.env.JWT_SECRET || 'secret123'; // VB-059 weak/hardcoded

// VB-180: token login. Password compared in plaintext.
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
  if (!user) return res.status(401).json({ error: 'bad creds' });
  const token = jwt.sign({ sub: user.id, username: user.username, role: user.role }, JWT_SECRET);
  res.json({ token });
});

// VB-014 alg:none accepted + VB-059 weak secret. Verification is hand-rolled and unsafe.
function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    const parts = token.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    if (header.alg === 'none') {
      // VB-014: trust unsigned token entirely.
      req.claims = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      return next();
    }
    req.claims = jwt.verify(token, JWT_SECRET); // VB-059 crackable
    next();
  } catch (e) {
    res.status(401).json({ error: 'invalid token: ' + e.message });
  }
}

// VB-011/182 excessive data exposure: returns passwords, SSN, PAN to any token.
router.get('/users', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM users').all());
});

// VB-179 BOLA/IDOR: no check that the account belongs to the caller.
router.get('/accounts/:id', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM accounts WHERE id = ?').get(req.params.id) || {});
});

// VB-184 broken function-level authz: admin action, no role check.
router.post('/admin/setrole', auth, (req, res) => {
  const { userId, role } = req.body;
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, userId);
  res.json({ ok: true });
});

// VB-181/183 mass assignment + no rate limit on transfer.
router.post('/transfer', auth, (req, res) => {
  const { from, to, amount } = req.body;
  db.prepare('UPDATE accounts SET balance = balance - ? WHERE id = ?').run(amount, from);
  db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?').run(amount, to);
  res.json({ ok: true });
});

// VB-188 improper inventory: old, more-verbose v1 still mounted.
router.get('/v1/users', (req, res) => {
  res.json(db.prepare('SELECT * FROM users').all()); // no auth at all
});

module.exports = router;
