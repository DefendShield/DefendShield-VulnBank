// Wipe and re-seed the database for a clean student lab restart.
const fs = require('fs');
const path = require('path');
const dbFile = path.join(__dirname, '..', 'db', 'vulnbank.sqlite');
try { fs.unlinkSync(dbFile); console.log('[reseed] removed old db'); } catch {}
require('../src/db').init();
console.log('[reseed] fresh database ready');
