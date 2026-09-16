// Full JWT attack lab — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { db } = require('../db');

// Lab RSA keypair. Auto-generated on first run if missing (so no private key is
// committed to source control). Throwaway keys — for the JWT lab only.
const KEYDIR = path.join(__dirname, '..', '..', 'keys');
const PRIV_PATH = path.join(KEYDIR, 'private.pem');
const PUB_PATH = path.join(KEYDIR, 'public.pem');
if (!fs.existsSync(PRIV_PATH) || !fs.existsSync(PUB_PATH)) {
  fs.mkdirSync(KEYDIR, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(PRIV_PATH, privateKey);
  fs.writeFileSync(PUB_PATH, publicKey);
  console.log('[jwtlab] generated throwaway RSA keypair in keys/');
}
const PRIV = fs.readFileSync(PRIV_PATH);
const PUB = fs.readFileSync(PUB_PATH);

// Issue an RS256 token (the "correct" flow).
router.post('/rs256/login', express.json(), (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username=? AND password=?').get(username, password);
  if (!user) return res.status(401).json({ error: 'bad creds' });
  const token = jwt.sign({ sub: user.id, role: user.role }, PRIV, { algorithm: 'RS256' });
  res.json({ token, note: 'public key at /jwt/pubkey' });
});

// VB-062 Algorithm confusion (RS256 -> HS256).
// The public key is public. This buggy verifier passes the PUBLIC key as the
// secret and does NOT pin the algorithm, so an attacker can forge an HS256
// token using the public key bytes as the HMAC secret.
router.get('/rs256/whoami', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    // VB-062: misconfig — server accepts BOTH RS256 and HS256 while using the
    // PUBLIC key as the verification key. An attacker forges an HS256 token
    // using the public key bytes as the HMAC secret.
    const claims = jwt.verify(token, PUB, { algorithms: ['RS256', 'HS256'] });
    res.json({ claims, verified_with: 'public key + HS256/RS256 allowed' });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});
router.get('/pubkey', (req, res) => res.type('text').send(PUB.toString()));

// VB-060 kid injection: the `kid` header is used as a filesystem path to load
// the signing key. Attacker sets kid to a predictable/empty file (e.g.
// /dev/null) and signs the token with that empty key.
// PoC: header {"alg":"HS256","kid":"/dev/null"} signed with secret "".
router.get('/kid/whoami', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());
    const keyPath = header.kid || path.join(__dirname, '..', '..', 'keys', 'hmac.key');
    let key = '';
    try { key = fs.readFileSync(keyPath); } catch { key = ''; } // /dev/null -> empty
    const claims = jwt.verify(token, key, { algorithms: ['HS256'] });
    res.json({ claims, kid: header.kid });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// Helper so students can see a valid forged token quickly (teaching aid).
router.get('/forge-demo', (req, res) => {
  // Demonstrates the HS256-with-public-key forgery (VB-062).
  const forged = jwt.sign({ sub: 1, role: 'admin' }, PUB, { algorithm: 'HS256' });
  res.json({ forged_token: forged, try_it: 'GET /jwt/rs256/whoami with Authorization: Bearer <token>' });
});

module.exports = router;
