// Weak cryptography lab — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const crypto = require('crypto');

const KEY = Buffer.from((process.env.DB_ENCRYPTION_KEY || '0000000000000000').padEnd(16, '0').slice(0, 16));

// ---------------------------------------------------------------------------
// VB-068 AES-ECB: identical plaintext blocks -> identical ciphertext blocks,
// leaking structure. GET /crypto/ecb?text=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// (two identical 16-byte blocks produce two identical ciphertext blocks).
// ---------------------------------------------------------------------------
router.get('/ecb', (req, res) => {
  const text = req.query.text || 'BLOCKAAAAAAAAAAABLOCKAAAAAAAAAA';
  const cipher = crypto.createCipheriv('aes-128-ecb', KEY, null);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const blocks = [];
  for (let i = 0; i < ct.length; i += 16) blocks.push(ct.slice(i, i + 16).toString('hex'));
  res.json({ mode: 'AES-128-ECB', blocks, note: 'repeated plaintext blocks = repeated ciphertext blocks' });
});

// ---------------------------------------------------------------------------
// VB-072 Reversible "encryption": a "secure" auth token that is just base64 of
// user:role and is fully attacker-forgeable.  GET /crypto/token?user=bob
// then flip the role and replay.
// ---------------------------------------------------------------------------
router.get('/token', (req, res) => {
  const user = req.query.user || 'bob';
  const role = req.query.role || 'user';
  const token = Buffer.from(`${user}:${role}`).toString('base64'); // not encryption
  res.json({ token, decode_hint: "atob(token) reveals 'user:role' — tamper and replay" });
});
router.get('/whoami', (req, res) => {
  const token = req.query.token || '';
  try {
    const [user, role] = Buffer.from(token, 'base64').toString().split(':');
    res.json({ user, role, admin: role === 'admin' }); // trusts forgeable token
  } catch (e) { res.status(400).json({ error: 'bad token' }); }
});

// ---------------------------------------------------------------------------
// VB-071 Hash length-extension: a naive MAC of md5(secret || data). An attacker
// who knows a valid (data, mac) pair can forge mac for data+padding+extension
// using a tool like `hashpump`, WITHOUT knowing the secret.
// GET /crypto/sign?data=amount=10          -> returns the MAC (demo issuer)
// GET /crypto/verify?data=...&mac=...       -> verifies with the same flawed MAC
// ---------------------------------------------------------------------------
const SECRET = process.env.SESSION_SECRET || 'keyboardcat';
function badMac(data) {
  return crypto.createHash('md5').update(SECRET + data).digest('hex'); // secret||data
}
router.get('/sign', (req, res) => {
  const data = req.query.data || 'amount=10&to=self';
  res.json({ data, mac: badMac(data), note: 'MAC = md5(secret + data) — length-extendable' });
});
router.get('/verify', (req, res) => {
  const { data, mac } = req.query;
  const ok = mac === badMac(data || '');
  res.json({ data, mac, valid: ok, forge_with: 'hashpump (append &admin=1)' });
});

// ---------------------------------------------------------------------------
// VB-070 Padding oracle: AES-128-CBC decryption returns DISTINGUISHABLE errors
// for "bad padding" vs "bad content", letting an attacker decrypt/forge without
// the key (classic CBC padding-oracle attack, e.g. with padbuster).
// GET /crypto/po/token             -> issue iv:ciphertext
// GET /crypto/po/decrypt?data=hex  -> 403 "padding" vs 400 "content" (the oracle)
// ---------------------------------------------------------------------------
router.get('/po/token', (req, res) => {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-128-cbc', KEY, iv);
  const ct = Buffer.concat([c.update('user=bob;role=user', 'utf8'), c.final()]);
  res.type('text').send(iv.toString('hex') + ':' + ct.toString('hex'));
});
router.get('/po/decrypt', (req, res) => {
  try {
    const [ivHex, ctHex] = (req.query.data || '').split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const d = crypto.createDecipheriv('aes-128-cbc', KEY, iv); // autoPadding on
    const pt = Buffer.concat([d.update(Buffer.from(ctHex, 'hex')), d.final()]).toString();
    if (!pt.includes('role=')) return res.status(400).send('content error'); // valid padding, bad content
    res.send('ok: ' + pt);
  } catch (e) {
    // Padding failure throws here -> distinct 403 = the oracle signal.
    res.status(403).send('padding error');
  }
});

module.exports = router;
