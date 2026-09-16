// More business-logic flaws — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');

function requireLogin(req, res, next) { if (!req.user) return res.status(401).json({ error: 'login' }); next(); }

// ---------------------------------------------------------------------------
// VB-104 Password change with NO current-password verification.
// POST /account/password  { "new": "hacked" }   (uses session identity only)
// Chained with any XSS/CSRF -> full account takeover.
// ---------------------------------------------------------------------------
router.post('/account/password', requireLogin, express.urlencoded({ extended: true }), (req, res) => {
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(req.body.new, req.user.id);
  res.json({ ok: true, note: 'no current password required' });
});

// ---------------------------------------------------------------------------
// VB-085 Client-trusted price: the client sends the price, server trusts it.
// POST /shop/buy  { "item":"Gold Card", "price": 0 }
// ---------------------------------------------------------------------------
router.post('/shop/buy', requireLogin, express.json(), (req, res) => {
  const { item, price } = req.body; // price should come from the server catalog
  res.json({ ok: true, charged: price, item, note: 'server trusted client-supplied price' });
});

// ---------------------------------------------------------------------------
// VB-086 Voucher/gift-card enumeration: unlimited attempts, reveals validity.
// GET /voucher?code=GIFT-0001 ...  Burp Intruder walks the space with no lockout.
// ---------------------------------------------------------------------------
const VALID_VOUCHERS = new Set(['GIFT-0042', 'GIFT-0777', 'PROMO-2026']);
router.get('/voucher', (req, res) => {
  const code = req.query.code || '';
  res.json({ code, valid: VALID_VOUCHERS.has(code) }); // no rate limit, boolean oracle
});

// ---------------------------------------------------------------------------
// VB-172 HTTP Parameter Pollution: the limit check reads the first `amount`,
// the charge uses the last -> bypass the limit.
// GET /pay?amount=1&amount=1000000
// ---------------------------------------------------------------------------
router.get('/pay', requireLogin, (req, res) => {
  let amount = req.query.amount;
  const arr = Array.isArray(amount) ? amount : [amount];
  const checked = parseFloat(arr[0]);          // validation uses FIRST value
  if (checked > 100) return res.json({ error: 'limit is 100' });
  const charged = parseFloat(arr[arr.length - 1]); // processing uses LAST value
  res.json({ ok: true, limit_checked: checked, actually_charged: charged });
});

// ---------------------------------------------------------------------------
// VB-080 Currency rounding abuse: FX conversion truncates in the user's favor,
// repeatable for profit (fractional-cent skimming).
// GET /fx?amount=0.004  -> converts, rounds so tiny amounts credit for free
// ---------------------------------------------------------------------------
router.get('/fx', requireLogin, (req, res) => {
  const amount = parseFloat(req.query.amount || '0');
  const rate = 1.5;
  const converted = Math.round(amount * rate * 100) / 100; // rounding exploited in a loop
  const debited = Math.floor(amount);                       // debit floored to 0 for <1
  res.json({ amount, debited, converted, note: 'debit floored, credit rounded -> free money in a loop' });
});

module.exports = router;
