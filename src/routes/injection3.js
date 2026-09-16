// More injection variants — INTENTIONALLY VULNERABLE.
const express = require('express');
const router = express.Router();
const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const { db } = require('../db');

// ---------------------------------------------------------------------------
// VB-049 Server-Side Includes (SSI) injection.
// GET /ssi?tpl=<!--#exec cmd="id"-->   or   <!--#include file="/etc/hostname"-->
// ---------------------------------------------------------------------------
router.get('/ssi', (req, res) => {
  let tpl = req.query.tpl || 'Hello <!--#echo var="USER"-->';
  tpl = tpl.replace(/<!--#exec cmd="([^"]+)"-->/g, (_, c) => {
    try { return execSync(c).toString(); } catch (e) { return 'ERR:' + e.message; }
  });
  tpl = tpl.replace(/<!--#include file="([^"]+)"-->/g, (_, f) => {
    try { return fs.readFileSync(f, 'utf8'); } catch (e) { return 'ERR:' + e.message; }
  });
  tpl = tpl.replace(/<!--#echo var="([^"]+)"-->/g, (_, v) => process.env[v] || '');
  res.type('html').send(tpl);
});

// ---------------------------------------------------------------------------
// VB-048 LDAP injection (simulated directory + naive filter matcher).
// GET /ldap?user=*        -> matches everyone (auth bypass style)
// GET /ldap?user=admin)(| -> filter tampering
// ---------------------------------------------------------------------------
const DIRECTORY = [
  { uid: 'admin', dept: 'IT' }, { uid: 'alice', dept: 'Sales' }, { uid: 'bob', dept: 'Sales' },
];
router.get('/ldap', (req, res) => {
  const user = req.query.user || '';
  const filter = `(&(objectClass=person)(uid=${user}))`; // unsanitized
  // naive matcher: '*' is a wildcard -> classic LDAP wildcard injection.
  const wild = user === '*' || user.includes('*');
  const matches = DIRECTORY.filter(e => wild || e.uid === user);
  res.json({ filter, matched: matches });
});

// ---------------------------------------------------------------------------
// VB-029 stacked-query SQLi via db.exec (multiple statements).
// GET /note?data=x'); UPDATE users SET role='admin' WHERE username='alice'; --
// ---------------------------------------------------------------------------
router.get('/note', (req, res) => {
  const data = req.query.data || 'hi';
  const sql = `INSERT INTO messages (user_id,subject,body) VALUES (1,'note','${data}')`;
  try {
    db.exec(sql); // exec runs ALL statements -> stacked queries
    res.send('note saved');
  } catch (e) { res.status(500).send('err: ' + e.message); }
});

// ---------------------------------------------------------------------------
// VB-028 ORDER BY / column-name SQLi (non-parameterizable context).
// GET /sortusers?order=(CASE WHEN (SELECT password FROM users WHERE id=1) LIKE 'a%' THEN id ELSE username END)
// ---------------------------------------------------------------------------
router.get('/sortusers', (req, res) => {
  const order = req.query.order || 'id';
  const sql = `SELECT id,username,role FROM users ORDER BY ${order}`; // injectable
  try { res.json(db.prepare(sql).all()); }
  catch (e) { res.status(500).send('err: ' + e.message); }
});

// ---------------------------------------------------------------------------
// VB-042 Argument injection (option smuggling into a CLI, no shell metachars).
// GET /archive?path=--checkpoint=1 --checkpoint-action=exec=id .
// tar treats the smuggled options as flags -> command execution.
// ---------------------------------------------------------------------------
router.get('/archive', (req, res) => {
  const path = req.query.path || '.';
  const args = ['-cf', '/tmp/vb_archive.tar'].concat(path.split(' ')); // split -> separate argv
  const r = spawnSync('tar', args, { encoding: 'utf8', timeout: 5000 });
  res.type('text').send('tar stdout:\n' + (r.stdout || '') + '\nstderr:\n' + (r.stderr || ''));
});

module.exports = router;
