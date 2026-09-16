// Misc cross-cutting vulns — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const fs = require('fs');

// ---------------------------------------------------------------------------
// VB-156 Open redirect.  /redirect?url=https://evil.example
// ---------------------------------------------------------------------------
router.get('/redirect', (req, res) => {
  res.redirect(req.query.url || '/');
});

// ---------------------------------------------------------------------------
// VB-045 CRLF / header injection.  /setlang?lang=en%0d%0aSet-Cookie:admin=1
// ---------------------------------------------------------------------------
router.get('/setlang', (req, res) => {
  res.setHeader('X-Language', req.query.lang || 'en'); // unsanitized
  res.send('Language set to ' + (req.query.lang || 'en'));
});

// ---------------------------------------------------------------------------
// VB-140 SSRF webhook tester.  POST /webhook  { "url": "http://127.0.0.1:3000/debug" }
// ---------------------------------------------------------------------------
router.post('/webhook', (req, res) => {
  const url = req.body.url;
  if (!url) return res.json({ error: 'provide url' });
  const client = url.startsWith('https') ? https : http;
  const r = client.get(url, (resp) => {
    let data = '';
    resp.on('data', c => data += c);
    resp.on('end', () => res.json({ status: resp.statusCode, body: data }));
  });
  r.on('error', e => res.json({ error: e.message }));
});

// ---------------------------------------------------------------------------
// VB-161/162/163 XXE — naive XML import that expands external SYSTEM entities.
// POST /import/xml  body: raw XML with <!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]> <a>&x;</a>
// ---------------------------------------------------------------------------
router.post('/import/xml', express.text({ type: '*/*' }), (req, res) => {
  const xml = req.body || '';
  let out = xml;
  // Vulnerable entity resolver: honors SYSTEM file:// entities (classic XXE).
  const decl = xml.match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>/i);
  if (decl) {
    const [, name, uri] = decl;
    let content = '';
    try {
      if (uri.startsWith('file://')) content = fs.readFileSync(uri.replace('file://', ''), 'utf8');
      else content = '[external fetch of ' + uri + ']';
    } catch (e) { content = 'ERR:' + e.message; }
    out = out.replace(new RegExp('&' + name + ';', 'g'), content);
  }
  res.type('text').send('Parsed XML result:\n' + out);
});

// ---------------------------------------------------------------------------
// VB-075/172 demo endpoint for HTTP Parameter Pollution + business logic.
// ---------------------------------------------------------------------------
router.get('/robots.txt', (req, res) => {
  // VB-006 leaks hidden paths.
  res.type('text').send('User-agent: *\nDisallow: /admin\nDisallow: /debug\nDisallow: /backup\nDisallow: /api/v1\n');
});

module.exports = router;
