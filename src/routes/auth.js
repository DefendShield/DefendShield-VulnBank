// Auth routes — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');

// ---------------------------------------------------------------------------
// LOGIN — VB-021 SQL injection login bypass, VB-091 user enumeration,
//         VB-087 no rate limit / lockout, VB-093 no session rotation.
// ---------------------------------------------------------------------------
router.get('/login', (req, res) => res.render('login', { error: null }));

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  // VB-021: raw string concatenation -> SQLi. Try:  admin' --
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  let user;
  try {
    user = db.prepare(sql).get();
  } catch (e) {
    // VB-105: leak SQL error to attacker.
    return res.status(500).render('login', { error: 'SQL error: ' + e.message });
  }
  if (!user) {
    // VB-091: distinct message reveals whether the username exists.
    const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(username);
    return res.render('login', { error: exists ? 'Wrong password' : 'No such user' });
  }
  // VB-093: session id NOT regenerated on privilege change (session fixation).
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

router.get('/logout', (req, res) => {
  // VB-096: does not destroy the server-side session properly.
  req.session.userId = null;
  res.redirect('/');
});

// ---------------------------------------------------------------------------
// REGISTER — VB-090 weak password policy, VB-007 role mass assignment.
// ---------------------------------------------------------------------------
router.get('/register', (req, res) => res.render('register', { error: null }));

router.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  // VB-090: no complexity/length check at all.
  // VB-007: role is taken straight from the request body if supplied.
  const role = req.body.role || 'user';
  try {
    const id = db.prepare('INSERT INTO users (username,password,email,role,full_name,display_name) VALUES (?,?,?,?,?,?)')
      .run(username, password, email, role, username, username).lastInsertRowid;
    db.prepare('INSERT INTO accounts (user_id,acct_number,balance,type) VALUES (?,?,?,?)')
      .run(id, 'ACCT-' + (2000 + id), 1000, 'checking');
    req.session.userId = id;
    res.redirect('/dashboard');
  } catch (e) {
    res.render('register', { error: e.message });
  }
});

// ---------------------------------------------------------------------------
// PASSWORD RESET — VB-065 predictable token, VB-081 no identity check,
//                  VB-158 host header injection in reset link.
// ---------------------------------------------------------------------------
router.get('/reset', (req, res) => res.render('reset', { msg: null }));

router.post('/reset', (req, res) => {
  const { username } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.render('reset', { msg: 'No such user' }); // VB-091 enumeration
  // VB-066/065: predictable token from a weak source.
  const token = Buffer.from(`${user.id}:${username}`).toString('base64');
  db.prepare('UPDATE users SET reset_token = ? WHERE id = ?').run(token, user.id);
  // VB-158: link is built from the attacker-controllable Host header.
  const link = `http://${req.headers.host}/reset/confirm?token=${token}`;
  res.render('reset', { msg: `Reset link (would be emailed): ${link}` });
});

router.get('/reset/confirm', (req, res) => {
  res.render('reset_confirm', { token: req.query.token });
});

router.post('/reset/confirm', (req, res) => {
  const { token, password } = req.body;
  // VB-081: token is trusted with no expiry / no secondary verification.
  const user = db.prepare('SELECT * FROM users WHERE reset_token = ?').get(token);
  if (!user) return res.send('Invalid token');
  db.prepare('UPDATE users SET password = ?, reset_token = NULL WHERE id = ?').run(password, user.id);
  res.send('Password reset. <a href="/login">Login</a>');
});

module.exports = router;
