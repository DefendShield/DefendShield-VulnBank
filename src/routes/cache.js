// Web cache & content-type issues — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();

// ---------------------------------------------------------------------------
// VB-159 Web cache poisoning via an UNKEYED header (X-Forwarded-Host).
// The response is marked cacheable and reflects an attacker-controlled header
// that a shared cache would not include in the cache key.
// GET /home-banner  with header  X-Forwarded-Host: evil.example
// ---------------------------------------------------------------------------
router.get('/home-banner', (req, res) => {
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  res.set('Cache-Control', 'public, max-age=300'); // cacheable
  res.type('html').send(`<script src="//${host}/analytics.js"></script>Welcome to ${host}`);
});

// ---------------------------------------------------------------------------
// VB-160 Web cache deception: a sensitive page is reachable with a static-looking
// suffix that a CDN would cache (e.g. /account-info/nonexistent.css), causing
// private data to be stored in a shared cache.
// GET /account-info/anything.css
// ---------------------------------------------------------------------------
router.get('/account-info/*', (req, res) => {
  res.set('Cache-Control', 'public, max-age=600'); // static-like caching
  const u = req.user || { username: 'guest', card_number: 'n/a' };
  res.type('html').send(`Private account info for ${u.username}, card ${u.card_number}`);
});

// ---------------------------------------------------------------------------
// VB-165 Content-type sniffing: user content served without X-Content-Type-Options,
// with a guessable/incorrect type, lets browsers sniff HTML -> stored XSS.
// GET /raw?body=<script>alert(1)</script>
// ---------------------------------------------------------------------------
router.get('/raw', (req, res) => {
  res.set('Content-Type', 'text/plain'); // but no nosniff -> browser may sniff HTML
  res.send(req.query.body || 'hello');
});

module.exports = router;
