// Mock OAuth flow — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');

// ---------------------------------------------------------------------------
// VB-103 Unvalidated redirect_uri (open redirect / token theft).
// GET /oauth/authorize?client_id=vb&redirect_uri=https://evil.example&state=abc
// The authorize endpoint redirects to ANY redirect_uri with the code/token.
// VB-102 Missing state validation -> login CSRF (state is echoed, never checked).
// ---------------------------------------------------------------------------
router.get('/authorize', (req, res) => {
  const { redirect_uri, state } = req.query;
  if (!redirect_uri) return res.send('missing redirect_uri');
  // Should be an allow-list; instead we redirect anywhere with the secret code.
  const code = 'AUTHCODE-' + (req.user ? req.user.id : 'anon');
  const sep = redirect_uri.includes('?') ? '&' : '?';
  res.redirect(`${redirect_uri}${sep}code=${code}&state=${state || ''}`);
});

// VB-102: token exchange never verifies `state`, so a CSRF'd callback is accepted.
router.get('/callback', (req, res) => {
  const { code } = req.query; // no state check
  res.json({ logged_in_as: code, note: 'state never validated (login CSRF)' });
});

module.exports = router;
