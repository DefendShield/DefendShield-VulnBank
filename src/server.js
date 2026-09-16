// ============================================================================
//  VulnBank — INTENTIONALLY VULNERABLE banking app for OWASP Top 10 training.
//  DO NOT DEPLOY. Localhost lab only.
// ============================================================================
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const path = require('path');
const { db, init } = require('./db');

init();

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// VB-105/106: verbose errors, dev mode.
app.locals.BANNER = '⚠ INTENTIONALLY VULNERABLE — TEACHING LAB ONLY — DO NOT DEPLOY ⚠';

// Body parsing — allow large/urlencoded/json (VB-193 unbounded body).
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// VB-063/093/094: weak session config, cookie not HttpOnly/Secure, no rotation on login.
app.use(session({
  secret: process.env.SESSION_SECRET || 'keyboardcat',
  resave: true,
  saveUninitialized: true,
  cookie: { httpOnly: false, secure: false, sameSite: false },
}));

// VB-012/013/119: broken CORS — reflects origin AND allows credentials.
app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  // VB-109/113: no CSP/HSTS/X-Frame/X-Content-Type; leak a version banner.
  res.header('X-Powered-By', 'MeridianTrust/1.0 Express');
  next();
});

// Make current user available to all views.
app.use((req, res, next) => {
  if (req.session.userId) {
    req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  }
  // VB-101: trust client-supplied identity headers if present.
  if (req.headers['x-user-id']) {
    req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.headers['x-user-id']);
  }
  // VB-214: trust a forgeable "remember me" cookie = base64(username).
  if (!req.user && req.cookies.remember) {
    try {
      const uname = Buffer.from(req.cookies.remember, 'base64').toString();
      req.user = db.prepare('SELECT * FROM users WHERE username = ?').get(uname);
    } catch (e) { /* ignore */ }
  }
  res.locals.user = req.user;
  res.locals.banner = app.locals.BANNER;
  next();
});

// ---- Mount feature routers ----
app.use('/', require('./routes/auth'));
app.use('/', require('./routes/accounts'));
app.use('/', require('./routes/profile'));
app.use('/', require('./routes/support'));
app.use('/', require('./routes/admin'));
app.use('/', require('./routes/files'));
app.use('/', require('./routes/misc'));
app.use('/', require('./routes/injection2'));   // NoSQL/blind/2nd-order/header SQLi, ReDoS
app.use('/', require('./routes/injection3'));   // SSI/LDAP/stacked/ORDER BY/arg injection
app.use('/', require('./routes/logic2'));       // pw-change, client price, voucher, HPP, rounding
app.use('/', require('./routes/cache'));        // cache poisoning/deception, sniffing
app.use('/', require('./routes/clientside'));   // tabnabbing, postMessage, DOM clobbering
app.use('/', require('./routes/advanced'));     // log/SMTP/XPath injection, SSRF, DoS, CSRF, timing
app.use('/', require('./routes/morevulns'));    // verb-authz, RFD, proto-gadget, XML bomb, remember-me
app.use('/api', require('./routes/api'));
app.use('/oauth', require('./routes/oauth'));    // redirect_uri, state (login CSRF)
app.use('/jwt', require('./routes/jwtlab'));     // alg confusion, kid injection
app.use('/graphql', require('./routes/graphql')); // introspection, BOLA, batching
app.use('/crypto', require('./routes/cryptolab')); // ECB, reversible token, hash-length-ext
app.use('/otp', require('./routes/otp'));         // MFA bypass/brute
app.use('/integrity', require('./routes/integrity')); // deserialization, zip slip, CSV, webhook sig

// Home
app.get('/', (req, res) => res.render('index'));

// VB-108/111: directory listing + serve backups/uploads/.git without restriction.
const serveIndex = (dir) => (req, res) => {
  const fs = require('fs');
  const base = path.join(__dirname, '..', dir);
  const sub = req.params[0] || '';
  const full = path.join(base, sub); // VB-009/010 no traversal check
  try {
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      const items = fs.readdirSync(full);
      return res.send(`<h3>Index of /${dir}/${sub}</h3><ul>` +
        items.map(i => `<li><a href="/${dir}/${path.join(sub, i)}">${i}</a></li>`).join('') + '</ul>');
    }
    res.sendFile(full);
  } catch (e) { res.status(404).send('Not found: ' + e.message); } // VB-105 leak
};
app.get('/uploads', serveIndex('uploads'));
app.get('/uploads/*', serveIndex('uploads'));
app.get('/backup', serveIndex('backup'));
app.get('/backup/*', serveIndex('backup'));

// VB-034: reflected XSS in the 404 page (path echoed unescaped).
app.use((req, res) => {
  res.status(404).type('html').send(`<h1>404</h1><p>Not found: ${decodeURIComponent(req.originalUrl)}</p>`);
});

// VB-105: global error handler leaks stack traces.
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>ERROR: ${err.stack}</pre>`);
});

const PORT = process.env.PORT || 3000;
const http = require('http');
const server = http.createServer(app);

// ---------------------------------------------------------------------------
// VB-173 Cross-Site WebSocket Hijacking + VB-174 missing message authz.
// No Origin check on the upgrade, and messages return ANY user's data with no
// authorization. A malicious cross-origin page can open ws://127.0.0.1:3000
// and pull account data.
// ---------------------------------------------------------------------------
const WebSocket = require('ws');
const wss = new WebSocket.Server({ server, path: '/ws' }); // no verifyClient/origin check
wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ hello: 'VulnBank notifications. Try {"cmd":"getUser","id":1}' }));
  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch { return ws.send('bad json'); }
    // VB-174: no authz — return any requested user/account.
    if (msg.cmd === 'getUser') {
      const u = db.prepare('SELECT * FROM users WHERE id=?').get(msg.id);
      ws.send(JSON.stringify(u || {}));
    } else if (msg.cmd === 'getAccount') {
      const a = db.prepare('SELECT * FROM accounts WHERE id=?').get(msg.id);
      ws.send(JSON.stringify(a || {}));
    } else {
      ws.send(JSON.stringify({ error: 'unknown cmd' }));
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  ${app.locals.BANNER}`);
  console.log(`  VulnBank running on http://127.0.0.1:${PORT}  (ws at /ws)\n`);
});
