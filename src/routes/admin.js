// Admin panel — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { db } = require('../db');
const { execSync } = require('child_process');

// NOTE: deliberately NO admin role check on these routes (VB-005/006/184).
// Any logged-in (or even anonymous, via VB-101 header) user can reach /admin.

router.get('/admin', (req, res) => {
  const users = db.prepare('SELECT id,username,role,email,card_number,ssn FROM users').all();
  res.render('admin', { users, output: null });
});

// VB-040/041 OS command injection: admin "network diagnostics" ping tool.
// Try host =  127.0.0.1; cat /etc/passwd    or   127.0.0.1 && env
router.post('/admin/ping', (req, res) => {
  const host = req.body.host || '';
  let output;
  try {
    output = execSync('ping -c 1 ' + host, { timeout: 5000 }).toString();
  } catch (e) {
    output = (e.stdout ? e.stdout.toString() : '') + (e.stderr ? e.stderr.toString() : e.message);
  }
  const users = db.prepare('SELECT id,username,role,email,card_number,ssn FROM users').all();
  res.render('admin', { users, output });
});

// VB-107 default creds shown; VB-108 links to backups.
// VB-106 debug endpoint dumps environment + config.
router.get('/debug', (req, res) => {
  res.type('text').send(
    'DEBUG INFO\n==========\n' +
    'env:\n' + JSON.stringify(process.env, null, 2) + '\n' +
    'cwd: ' + process.cwd() + '\n'
  );
});

// VB-126/060 version disclosure.
router.get('/version', (req, res) => {
  const pkg = require('../../package.json');
  res.json({ app: 'MeridianTrust', version: pkg.version, dependencies: pkg.dependencies, node: process.version });
});

module.exports = router;
