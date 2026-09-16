// Additional vulnerabilities (batch 5) — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');

// ---------------------------------------------------------------------------
// VB-208 Broken function-level authz via HTTP verb — no auth on PUT.
// The UI only exposes read via GET, but PUT updates ANY user (mass assignment).
//   curl -X PUT /user/1 -d '{"role":"admin"}'
// ---------------------------------------------------------------------------
router.put('/user/:id', express.json(), (req, res) => {
  const fields = ['email', 'full_name', 'role', 'ssn', 'card_number'];
  for (const f of fields) {
    if (req.body[f] !== undefined) db.prepare(`UPDATE users SET ${f}=? WHERE id=?`).run(req.body[f], req.params.id);
  }
  res.json(db.prepare('SELECT id,username,role,email FROM users WHERE id=?').get(req.params.id) || {});
});

// ---------------------------------------------------------------------------
// VB-209 IDOR via predictable account number (no ownership check).
//   GET /api/acct?num=ACCT-1000  -> treasury account
// ---------------------------------------------------------------------------
router.get('/api/acct', (req, res) => {
  res.json(db.prepare('SELECT * FROM accounts WHERE acct_number=?').get(req.query.num || '') || {});
});

// ---------------------------------------------------------------------------
// VB-210 Reflected File Download (RFD): user controls the download filename,
// enabling delivery of an executable-looking file from a trusted domain.
//   GET /statement/export?name=Meridian-Statement.bat
// ---------------------------------------------------------------------------
router.get('/statement/export', (req, res) => {
  const name = req.query.name || 'statement.txt';
  res.setHeader('Content-Disposition', `attachment; filename="${name}"`); // unsanitized
  res.type('application/octet-stream');
  res.send('||calc||\nMeridian Trust statement export');
});

// ---------------------------------------------------------------------------
// VB-211 Stored XSS via username rendered unescaped in an admin widget.
// Register a user named <script>...</script>, then an admin views this page.
//   GET /admin/recent
// ---------------------------------------------------------------------------
router.get('/admin/recent', (req, res) => {
  const users = db.prepare('SELECT username, email FROM users ORDER BY id DESC LIMIT 15').all();
  res.type('html').send('<h3>Recent sign-ups</h3>' +
    users.map(u => `<div class="row">${u.username} — ${u.email}</div>`).join('')); // raw
});

// ---------------------------------------------------------------------------
// VB-212 Prototype-pollution gadget -> privilege escalation.
// After polluting Object.prototype (VB-124 at /profile), an empty options
// object inherits isAdmin/premium, unlocking features.
//   GET /feature/flags
// ---------------------------------------------------------------------------
router.get('/feature/flags', (req, res) => {
  const opts = {}; // no own properties -> reads inherited (polluted) ones
  res.json({ isAdmin: opts.isAdmin === true, premium: opts.premium === true });
});

// ---------------------------------------------------------------------------
// VB-213 Billion-laughs / XML entity-expansion DoS (internal entities).
//   POST /import/xml2  with nested <!ENTITY lol "..."> definitions.
// Capped at 5 MB so the lab survives; reports the amplification factor.
// ---------------------------------------------------------------------------
router.post('/import/xml2', express.text({ type: '*/*' }), (req, res) => {
  const xml = req.body || '';
  const ents = {};
  const re = /<!ENTITY\s+(\w+)\s+"([^"]*)">/g;
  let m; while ((m = re.exec(xml))) ents[m[1]] = m[2];
  let body = xml.replace(/^[\s\S]*?\]>/, '');
  const CAP = 5 * 1024 * 1024;
  for (let i = 0; i < 12 && body.length < CAP; i++) {
    for (const k in ents) body = body.split('&' + k + ';').join(ents[k]);
  }
  res.json({ entities: Object.keys(ents).length, expanded_bytes: Math.min(body.length, CAP),
    note: 'unbounded entity expansion -> memory DoS at scale' });
});

// ---------------------------------------------------------------------------
// VB-214 "Remember me" logout does not clear the forgeable cookie + sets it.
//   GET /remember?user=admin  -> sets remember cookie = base64(username)
// The server-wide middleware trusts this cookie (see server.js).
// ---------------------------------------------------------------------------
router.get('/remember', (req, res) => {
  const user = req.query.user || (req.user && req.user.username) || 'guest';
  res.cookie('remember', Buffer.from(user).toString('base64'), { httpOnly: false });
  res.json({ set: true, cookie: 'remember=' + Buffer.from(user).toString('base64'),
    note: 'forge base64(username) to impersonate anyone' });
});

module.exports = router;
