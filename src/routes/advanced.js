// Advanced/assorted vulns — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const http = require('http');
const { db } = require('../db');

const LOG = path.join(__dirname, '..', '..', 'logs', 'app.log');
fs.mkdirSync(path.dirname(LOG), { recursive: true });

// ---------------------------------------------------------------------------
// VB-046 Log injection / forged entries: unsanitized input written to a log
// that is then displayed. Newlines let an attacker forge log lines.
// GET /track-event?name=login%0a2099-01-01 ADMIN GRANTED to attacker
// ---------------------------------------------------------------------------
router.get('/track-event', (req, res) => {
  const name = req.query.name || 'view';
  fs.appendFileSync(LOG, `EVENT ${name}\n`); // raw, newline not escaped
  res.send('logged');
});
router.get('/logs', (req, res) => {
  const data = fs.existsSync(LOG) ? fs.readFileSync(LOG, 'utf8') : '';
  res.type('html').send('<pre>' + data + '</pre>'); // also VB-072-style log XSS
});

// ---------------------------------------------------------------------------
// VB-050 SMTP / email header injection.
// GET /contact?to=support@bank&subject=hi%0aBcc:victim@x.com&body=...
// The injected CRLF adds arbitrary headers to the outgoing message.
// ---------------------------------------------------------------------------
router.get('/contact', (req, res) => {
  const { to = 'support@vulnbank.local', subject = '', body = '' } = req.query;
  const raw = `To: ${to}\nSubject: ${subject}\n\n${body}`; // headers built from input
  res.type('text').send('Message that would be sent:\n----\n' + raw);
});

// ---------------------------------------------------------------------------
// VB-047 XPath injection (simulated XML directory + naive matcher).
// GET /xpath?user=' or '1'='1     -> auth-bypass style
// ---------------------------------------------------------------------------
const XML_USERS = [{ user: 'admin', pass: 'admin' }, { user: 'bob', pass: 'hunter2' }];
router.get('/xpath', (req, res) => {
  const user = req.query.user || '';
  const query = `//user[username='${user}']`; // unsanitized XPath
  const bypass = /'\s*or\s*'1'='1/i.test(user) || user === "' or ''='";
  res.json({ query, matched: bypass ? XML_USERS : XML_USERS.filter(u => u.user === user) });
});

// ---------------------------------------------------------------------------
// VB-194 Expensive query with no pagination/limit -> resource exhaustion.
// GET /report?n=3   (cartesian blow-up; large n hangs the DB/CPU)
// ---------------------------------------------------------------------------
router.get('/report', (req, res) => {
  const n = Math.min(parseInt(req.query.n || '2'), 5); // capped so the lab survives demos
  let sql = 'SELECT COUNT(*) c FROM ' + Array.from({ length: n }, () => 'transactions').join(',');
  const c = db.prepare(sql).get().c; // cross join, no WHERE
  res.json({ tables_joined: n, rows_scanned: c, note: 'no pagination/limit -> DoS at scale' });
});

// ---------------------------------------------------------------------------
// VB-145 SSRF with non-HTTP scheme + VB-069 weak-blocklist bypass.
// GET /proxy?url=file:///etc/passwd
// GET /proxy?url=http://0.0.0.0:3000/debug   (bypasses a naive "localhost" block)
// ---------------------------------------------------------------------------
router.get('/proxy', (req, res) => {
  const url = req.query.url || '';
  // VB-069: naive blocklist, trivially bypassed (0.0.0.0, 127.1, decimal IP, [::1]).
  if (url.includes('localhost') || url.includes('127.0.0.1')) {
    return res.status(403).send('blocked: localhost not allowed');
  }
  if (url.startsWith('file://')) { // VB-145 file scheme
    try { return res.type('text').send(fs.readFileSync(url.replace('file://', ''), 'utf8')); }
    catch (e) { return res.status(500).send('err: ' + e.message); }
  }
  http.get(url, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => res.type('text').send(d)); })
    .on('error', e => res.status(500).send('err: ' + e.message));
});

// ---------------------------------------------------------------------------
// VB-035 Reflected XSS via Referer header; VB-038 XSS in JSON served as HTML.
// ---------------------------------------------------------------------------
router.get('/welcome', (req, res) => {
  res.type('html').send('You came from: ' + (req.headers.referer || 'direct')); // VB-035
});
router.get('/api-echo', (req, res) => {
  res.set('Content-Type', 'text/html'); // wrong type for JSON -> script executes (VB-038)
  res.send(JSON.stringify({ q: req.query.q || '' }));
});

// ---------------------------------------------------------------------------
// VB-154 CSRF via GET money movement + VB-155 JSON CSRF (no content-type check).
// GET /quick-transfer?to=2&amount=500  (state change over GET, no token)
// ---------------------------------------------------------------------------
router.get('/quick-transfer', (req, res) => {
  if (!req.user) return res.status(401).send('login');
  const from = db.prepare('SELECT id FROM accounts WHERE user_id=?').get(req.user.id);
  db.prepare('UPDATE accounts SET balance = balance - ? WHERE id=?').run(req.query.amount, from.id);
  db.prepare('UPDATE accounts SET balance = balance + ? WHERE id=?').run(req.query.amount, req.query.to);
  res.send(`transferred ${req.query.amount} to ${req.query.to} (no CSRF token)`);
});

// ---------------------------------------------------------------------------
// VB-092 Timing-based username enumeration: valid users take measurably longer.
// ---------------------------------------------------------------------------
router.get('/user-check', (req, res) => {
  const u = db.prepare('SELECT 1 FROM users WHERE username=?').get(req.query.u || '');
  if (u) { const end = Date.now() + 300; while (Date.now() < end) {} } // artificial delay
  res.json({ checked: req.query.u }); // same body -> only timing differs
});

// ---------------------------------------------------------------------------
// VB-198 EXIF metadata not stripped: report EXIF presence in an uploaded image.
// GET /exif?file=<name in uploads/>
// ---------------------------------------------------------------------------
router.get('/exif', (req, res) => {
  const f = path.join(__dirname, '..', '..', 'uploads', req.query.file || '');
  try {
    const buf = fs.readFileSync(f);
    const hasExif = buf.includes(Buffer.from('Exif')); // APP1 marker
    res.json({ file: req.query.file, exif_present: hasExif, note: 'app never strips metadata (GPS/camera leak)' });
  } catch (e) { res.status(404).json({ error: e.message }); }
});

module.exports = router;
