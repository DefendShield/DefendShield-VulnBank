// Injection variants — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');

// ---------------------------------------------------------------------------
// VB-044 NoSQL / object injection (simulated Mongo-style operator handling).
// POST /api/nosql-login  {"username":"admin","password":{"$ne":"x"}}
// Because JSON lets password be an object, the naive operator handler matches.
// ---------------------------------------------------------------------------
router.post('/nosql-login', express.json(), (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'no user' });
  // Vulnerable operator emulation: {"$ne": x} / {"$gt": ""} bypass the check.
  let ok;
  if (password && typeof password === 'object') {
    if ('$ne' in password) ok = user.password !== password['$ne'];
    else if ('$gt' in password) ok = user.password > password['$gt'];
    else if ('$regex' in password) ok = new RegExp(password['$regex']).test(user.password);
    else ok = false;
  } else {
    ok = user.password === password;
  }
  if (!ok) return res.status(401).json({ error: 'bad creds' });
  res.json({ ok: true, user: username, role: user.role });
});

// ---------------------------------------------------------------------------
// VB-023 boolean-blind + VB-024 time-based blind SQLi.
// GET /blind?id=1              -> "exists" / "not found" (boolean oracle)
// GET /blind?id=1 AND 1=1      -> exists ; ... AND 1=2 -> not found
// GET /blind?id=1 AND 1=randomblob(100000000)  -> slow (time oracle)
// ---------------------------------------------------------------------------
router.get('/blind', (req, res) => {
  const id = req.query.id || '1';
  const sql = `SELECT id FROM users WHERE id = ${id}`; // raw injection
  try {
    const row = db.prepare(sql).get();
    res.send(row ? 'User exists' : 'User not found'); // boolean oracle only
  } catch (e) {
    res.status(500).send('err: ' + e.message);
  }
});

// ---------------------------------------------------------------------------
// VB-025 second-order SQLi: stored value reused unsafely in a later query.
// 1) POST /so/set-nick {nick:"x' UNION SELECT ..."}   -> stored verbatim
// 2) GET  /so/lookup                                  -> nick concatenated into SQL
// ---------------------------------------------------------------------------
router.post('/so/set-nick', express.urlencoded({ extended: true }), (req, res) => {
  if (!req.user) return res.status(401).send('login first');
  db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(req.body.nick, req.user.id);
  res.send('nick stored: ' + req.body.nick);
});
router.get('/so/lookup', (req, res) => {
  if (!req.user) return res.status(401).send('login first');
  const nick = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.user.id).display_name;
  // VB-025: previously-stored value now concatenated into a query.
  const sql = `SELECT id,username FROM users WHERE display_name = '${nick}'`;
  try { res.json(db.prepare(sql).all()); }
  catch (e) { res.status(500).send('err: ' + e.message); }
});

// ---------------------------------------------------------------------------
// VB-026 SQLi via HTTP header (User-Agent logged into a query).
// Send header: User-Agent: ' UNION SELECT password FROM users --
// ---------------------------------------------------------------------------
router.get('/track', (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const sql = `SELECT '${ua}' AS agent`; // trivially injectable context
  try { res.json(db.prepare(sql).get()); }
  catch (e) { res.status(500).send('err: ' + e.message); }
});

// ---------------------------------------------------------------------------
// VB-053 ReDoS: user-supplied input hits a catastrophic-backtracking regex.
// GET /validate?email=aaaaaaaaaaaaaaaaaaaaaaaa!   -> hangs CPU
// ---------------------------------------------------------------------------
router.get('/validate', (req, res) => {
  const email = req.query.email || '';
  const evil = /^([a-zA-Z0-9]+)+@/; // catastrophic backtracking
  const ok = evil.test(email);
  res.json({ email, valid: ok });
});

module.exports = router;
