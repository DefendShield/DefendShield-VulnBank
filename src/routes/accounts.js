// Accounts / transfers / search — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');

function requireLogin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

router.get('/dashboard', requireLogin, (req, res) => {
  const accounts = db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.user.id);
  res.render('dashboard', { accounts });
});

// ---------------------------------------------------------------------------
// VB-001 IDOR: any account by id, no ownership check.
// ---------------------------------------------------------------------------
router.get('/account/:id', requireLogin, (req, res) => {
  const acct = db.prepare('SELECT * FROM accounts WHERE id = ?').get(req.params.id);
  if (!acct) return res.status(404).send('No account');
  const txs = db.prepare('SELECT * FROM transactions WHERE from_acct = ? OR to_acct = ?')
    .all(acct.id, acct.id);
  res.render('account', { acct, txs });
});

// VB-002 IDOR: any transaction by id.
router.get('/transaction/:id', requireLogin, (req, res) => {
  const tx = db.prepare('SELECT * FROM transactions WHERE id = ?').get(req.params.id);
  res.json(tx || {});
});

// ---------------------------------------------------------------------------
// TRANSFER — VB-075 negative amount, VB-008 transfer from any account,
//   VB-077 race condition (no locking/atomic check), VB-172 HTTP param
//   pollution, VB-153/154 no CSRF token, VB-030 stored XSS via memo.
// ---------------------------------------------------------------------------
router.get('/transfer', requireLogin, (req, res) => {
  const accounts = db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.user.id);
  res.render('transfer', { accounts, msg: null });
});

router.post('/transfer', requireLogin, (req, res) => {
  let { fromAcct, toAcct, amount, memo } = req.body;
  amount = parseFloat(amount);
  // VB-008: no check that fromAcct belongs to req.user.
  const from = db.prepare('SELECT * FROM accounts WHERE id = ?').get(fromAcct);
  const to = db.prepare('SELECT * FROM accounts WHERE id = ?').get(toAcct);
  if (!from || !to) return res.render('transfer', {
    accounts: db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.user.id),
    msg: 'Invalid account',
  });
  // VB-075/076: no positivity or limit check -> negative amount drains target into you.
  // VB-077: read-then-write with no transaction/lock -> race/double-spend.
  const fresh = db.prepare('SELECT balance FROM accounts WHERE id = ?').get(from.id).balance;
  if (fresh < amount) {
    // still vulnerable: negative amount passes this check
  }
  db.prepare('UPDATE accounts SET balance = balance - ? WHERE id = ?').run(amount, from.id);
  db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?').run(amount, to.id);
  // VB-030: memo stored raw, rendered unescaped later.
  db.prepare('INSERT INTO transactions (from_acct,to_acct,amount,memo) VALUES (?,?,?,?)')
    .run(from.id, to.id, amount, memo || '');
  res.render('transfer', {
    accounts: db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.user.id),
    msg: `Transferred ${amount} from ${from.acct_number} to ${to.acct_number}`,
  });
});

// ---------------------------------------------------------------------------
// SEARCH — VB-022 UNION SQLi, VB-023 blind SQLi, VB-031 reflected XSS.
// ---------------------------------------------------------------------------
router.get('/search', requireLogin, (req, res) => {
  const q = req.query.q || '';
  let rows = [];
  let error = null;
  if (q) {
    // VB-022/023: raw concatenation. Try:  ' UNION SELECT id,username,password,email,role,0,0,0,0,0,0 FROM users --
    const sql = `SELECT * FROM transactions WHERE memo LIKE '%${q}%'`;
    try { rows = db.prepare(sql).all(); }
    catch (e) { error = e.message; } // VB-105 leak
  }
  // VB-031: q reflected unescaped into the page (see search.ejs uses <%- %>).
  res.render('search', { q, rows, error });
});

module.exports = router;
