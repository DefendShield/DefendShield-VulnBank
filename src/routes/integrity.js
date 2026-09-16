// Integrity / deserialization / injection-to-file — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const serialize = require('node-serialize'); // 0.0.4 — RCE on unserialize
const AdmZip = require('adm-zip');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { db } = require('../db');

const upload = multer({ dest: path.join(__dirname, '..', '..', 'uploads') });

// ---------------------------------------------------------------------------
// VB-130/131 Insecure deserialization -> RCE.
// A "preferences" blob is base64+serialized. node-serialize.unserialize will
// invoke an embedded IIFE. PoC payload (base64 of):
//   {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id > /tmp/pwned')}()"}
// Send it in the `prefs` cookie or body.
// ---------------------------------------------------------------------------
router.get('/prefs/load', (req, res) => {
  const blob = req.query.prefs || req.cookies.prefs;
  if (!blob) return res.send('provide ?prefs=<base64>');
  try {
    const json = Buffer.from(blob, 'base64').toString();
    const obj = serialize.unserialize(json); // VB-130: triggers embedded function
    res.json({ loaded: obj });
  } catch (e) {
    res.status(500).send('err: ' + e.message);
  }
});
// Teaching aid: builds a benign PoC payload (writes a marker file, no harm).
router.get('/prefs/poc', (req, res) => {
  const payload = { rce: "_$$ND_FUNC$$_function(){require('fs').writeFileSync('/tmp/vulnbank_deser_pwned','pwned')}()" };
  const b64 = Buffer.from(serialize.serialize(payload)).toString('base64');
  res.type('text').send('Send this as ?prefs= to /integrity/prefs/load :\n' + b64);
});

// ---------------------------------------------------------------------------
// VB-196 Zip Slip: archive entries are written using their raw name, so an
// entry named ../../evil.txt escapes the extraction directory.
// POST /integrity/import-zip  (multipart file field: archive)
// ---------------------------------------------------------------------------
router.post('/import-zip', upload.single('archive'), (req, res) => {
  if (!req.file) return res.send('upload a zip as field "archive"');
  const dest = path.join(__dirname, '..', '..', 'uploads', 'extracted');
  fs.mkdirSync(dest, { recursive: true });
  const zip = new AdmZip(req.file.path);
  const written = [];
  for (const entry of zip.getEntries()) {
    // VB-196: no normalization / containment check.
    const target = path.join(dest, entry.entryName);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (!entry.isDirectory) { fs.writeFileSync(target, entry.getData()); written.push(target); }
  }
  res.json({ extracted: written });
});

// ---------------------------------------------------------------------------
// VB-135/054 CSV / formula injection: transaction memos are exported into CSV
// without neutralizing leading =,+,-,@ so they execute in a spreadsheet.
// GET /integrity/export.csv
// ---------------------------------------------------------------------------
router.get('/export.csv', (req, res) => {
  const rows = db.prepare('SELECT id,from_acct,to_acct,amount,memo FROM transactions').all();
  let csv = 'id,from,to,amount,memo\n';
  for (const r of rows) csv += `${r.id},${r.from_acct},${r.to_acct},${r.amount},${r.memo}\n`; // raw memo
  res.header('Content-Type', 'text/csv');
  res.header('Content-Disposition', 'attachment; filename=statement.csv');
  res.send(csv);
});

// ---------------------------------------------------------------------------
// VB-136 Unverified webhook signature: inbound webhooks are trusted without
// validating the HMAC signature header, so anyone can spoof bank events.
// POST /integrity/webhook/receive  { "event":"deposit","amount":100000,"acct":2 }
// ---------------------------------------------------------------------------
router.post('/webhook/receive', express.json(), (req, res) => {
  // A real integration must verify req.headers['x-signature'] = HMAC(secret, body).
  const evt = req.body || {};
  if (evt.event === 'deposit') {
    db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?').run(evt.amount, evt.acct);
  }
  res.json({ accepted: true, note: 'signature NOT verified — spoofable' });
});

module.exports = router;
