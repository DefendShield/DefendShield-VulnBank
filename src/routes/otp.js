// OTP / MFA flaws — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();

// In-memory OTP store (per session).
const otpStore = {};

// VB-066 weak randomness + VB-098 client-side exposure: the 4-digit OTP is
// generated with Math.random() and returned to the client, so JS "validates" it.
router.get('/mfa/send', (req, res) => {
  const sid = req.sessionID;
  const otp = String(Math.floor(Math.random() * 9000) + 1000); // 4 digits, weak RNG
  otpStore[sid] = { otp, attempts: 0 };
  // VB-098: OTP leaked to the client (e.g. in the JSON / a hidden field).
  res.json({ sent: true, debug_otp: otp, hint: 'client checks this — bypass in the browser' });
});

// VB-099 no attempt limit + VB-100 OTP not invalidated after use -> brute force.
// Burp Intruder over code=0000..9999 will find it in <=10000 tries, no lockout.
router.post('/mfa/verify', express.urlencoded({ extended: true }), (req, res) => {
  const sid = req.sessionID;
  const rec = otpStore[sid];
  if (!rec) return res.status(400).json({ error: 'request an OTP first' });
  rec.attempts++; // counted but never enforced (VB-099)
  if (req.body.code === rec.otp) {
    // VB-100: OTP left valid (not deleted) -> reusable.
    return res.json({ ok: true, attempts: rec.attempts });
  }
  res.status(401).json({ ok: false, attempts: rec.attempts });
});

module.exports = router;
