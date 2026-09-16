// Profile — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const _ = require('lodash'); // VB-122 outdated dependency (kept for component scanning)

// VB-124: naive recursive merge that does NOT guard __proto__ -> prototype pollution.
function unsafeMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      unsafeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function requireLogin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

router.get('/profile', requireLogin, (req, res) => {
  res.render('profile', { target: req.user, msg: null });
});

// VB-003 IDOR: edit ANY profile by id.
router.get('/profile/:id', requireLogin, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).send('No user');
  res.render('profile', { target, msg: null });
});

// ---------------------------------------------------------------------------
// UPDATE — VB-007 mass assignment (role), VB-124 prototype pollution,
//   VB-043 SSTI via display_name rendered through template engine.
// ---------------------------------------------------------------------------
router.post('/profile/:id', requireLogin, (req, res) => {
  const id = req.params.id; // VB-003 no ownership check
  // VB-124: unsafe recursive merge of raw body enables __proto__ pollution.
  const merged = {};
  unsafeMerge(merged, req.body);
  // VB-007: role/email/full_name/display_name all mass-assigned from body.
  const fields = ['email', 'full_name', 'display_name', 'role', 'ssn', 'card_number'];
  for (const f of fields) {
    if (merged[f] !== undefined) {
      db.prepare(`UPDATE users SET ${f} = ? WHERE id = ?`).run(merged[f], id);
    }
  }
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.render('profile', { target, msg: 'Saved' });
});

// ---------------------------------------------------------------------------
// SSTI demo — VB-043: display_name evaluated as an EJS template.
// ---------------------------------------------------------------------------
router.get('/greet', requireLogin, (req, res) => {
  const ejs = require('ejs');
  // Try display_name =  <%= 7*7 %>  or  <%= process.env.JWT_SECRET %>
  const out = ejs.render(`Hello, ${req.user.display_name}!`);
  res.send(out);
});

module.exports = router;
