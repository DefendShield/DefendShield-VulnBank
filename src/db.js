// VulnBank database layer — INTENTIONALLY VULNERABLE.
// VB-055: passwords stored in PLAINTEXT. VB-058: PAN/SSN stored in clear.
const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'db', 'vulnbank.sqlite');
const db = new Database(dbPath);

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,            -- VB-055 plaintext
      email TEXT,
      role TEXT DEFAULT 'user', -- VB-007 mass-assignable
      full_name TEXT,
      ssn TEXT,                 -- VB-058 sensitive
      card_number TEXT,         -- VB-058 sensitive
      display_name TEXT,        -- VB-043 SSTI sink
      remember_token TEXT,      -- VB-095 predictable
      reset_token TEXT          -- VB-065 predictable
    );
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      acct_number TEXT,
      balance REAL DEFAULT 0,
      type TEXT DEFAULT 'checking'
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_acct INTEGER,
      to_acct INTEGER,
      amount REAL,
      memo TEXT,                -- VB-030 stored XSS
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      subject TEXT,
      body TEXT,                -- VB-030/036 stored/blind XSS
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const count = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (count === 0) seed();
}

function seed() {
  const insUser = db.prepare(
    `INSERT INTO users (username,password,email,role,full_name,ssn,card_number,display_name)
     VALUES (?,?,?,?,?,?,?,?)`
  );
  const users = [
    ['admin', 'admin', 'admin@vulnbank.local', 'admin', 'Alice Admin', '111-11-1111', '4111111111111111', 'Administrator'],
    ['support', 'support123', 'support@vulnbank.local', 'support', 'Sam Support', '222-22-2222', '4222222222222222', 'Support Agent'],
    ['alice', 'password1', 'alice@example.com', 'user', 'Alice Customer', '333-33-3333', '4333333333333333', 'Alice'],
    ['bob', 'hunter2', 'bob@example.com', 'user', 'Bob Customer', '444-44-4444', '4444444444444444', 'Bob'],
    ['carol', 'letmein', 'carol@example.com', 'user', 'Carol Customer', '555-55-5555', '4555555555555555', 'Carol'],
  ];
  const ids = users.map(u => insUser.run(...u).lastInsertRowid);

  const insAcct = db.prepare('INSERT INTO accounts (user_id,acct_number,balance,type) VALUES (?,?,?,?)');
  // Treasury/internal account belongs to admin.
  insAcct.run(ids[0], 'ACCT-1000', 9999999, 'treasury');
  insAcct.run(ids[2], 'ACCT-1001', 5000, 'checking');
  insAcct.run(ids[2], 'ACCT-1002', 12000, 'savings');
  insAcct.run(ids[3], 'ACCT-1003', 800, 'checking');
  insAcct.run(ids[4], 'ACCT-1004', 3200, 'checking');

  const insTx = db.prepare('INSERT INTO transactions (from_acct,to_acct,amount,memo) VALUES (?,?,?,?)');
  insTx.run(2, 4, 250, 'Rent split');
  insTx.run(4, 2, 60, 'Dinner');
  insTx.run(5, 2, 100, 'Gift');

  const insMsg = db.prepare('INSERT INTO messages (user_id,subject,body) VALUES (?,?,?)');
  insMsg.run(3, 'Welcome', 'Welcome to VulnBank!');
  console.log('[db] seeded fake data');
}

module.exports = { db, init };
