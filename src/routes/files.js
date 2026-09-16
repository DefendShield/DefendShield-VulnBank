// File upload / download / SSRF — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');

function requireLogin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

// VB-114/115/164/200/201: no type/size/extension checks; keeps original name.
const storage = multer.diskStorage({
  destination: path.join(__dirname, '..', '..', 'uploads'),
  filename: (req, file, cb) => cb(null, file.originalname), // path from client
});
const upload = multer({ storage });

router.get('/upload', requireLogin, (req, res) => res.render('upload', { msg: null }));

router.post('/upload', requireLogin, upload.single('avatar'), (req, res) => {
  // Uploaded file is now web-accessible at /uploads/<name> and served by
  // sendFile with no content-type restriction (stored XSS via .svg/.html,
  // web shell if the container had a script interpreter).
  res.render('upload', { msg: 'Uploaded to /uploads/' + (req.file ? req.file.originalname : '') });
});

// ---------------------------------------------------------------------------
// VB-138/139/142: SSRF — fetch avatar from an arbitrary user-supplied URL.
// Try url = http://169.254.169.254/latest/meta-data/  or  http://127.0.0.1:3000/debug
// ---------------------------------------------------------------------------
router.get('/avatar/fetch', requireLogin, (req, res) => {
  const url = req.query.url;
  if (!url) return res.send('provide ?url=');
  const client = url.startsWith('https') ? https : http;
  client.get(url, (r) => {
    let data = '';
    r.on('data', c => data += c);
    r.on('end', () => res.type('text').send(data)); // reflect internal response
  }).on('error', e => res.send('fetch error: ' + e.message));
});

// ---------------------------------------------------------------------------
// VB-009/202 path traversal / LFI in statement download.
// Try file=../../etc/passwd   or   file=../.env
// ---------------------------------------------------------------------------
router.get('/download', requireLogin, (req, res) => {
  const file = req.query.file || 'statement.txt';
  const full = path.join(__dirname, '..', '..', 'statements', file); // no normalize guard
  try {
    const data = fs.readFileSync(full);
    res.type('text').send(data);
  } catch (e) {
    res.status(404).send('Not found: ' + e.message); // VB-105 leak
  }
});

module.exports = router;
