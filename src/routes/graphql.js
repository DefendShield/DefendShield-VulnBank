// GraphQL API — INTENTIONALLY VULNERABLE.
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const { db } = require('../db');

// VB-175: introspection left ON; VB-182: sensitive fields (password/ssn/card)
// exposed; VB-178: no field-level authz; VB-176: aliasing enables rate-limit
// bypass / brute force; VB-177: recursive types allow deeply-nested query DoS.
const schema = buildSchema(`
  type User {
    id: Int
    username: String
    password: String   # VB-182 sensitive field exposed
    email: String
    role: String
    ssn: String        # VB-182
    card_number: String
    accounts: [Account]
  }
  type Account {
    id: Int
    acct_number: String
    balance: Float
    type: String
    owner: User        # recursive -> nested-query DoS (VB-177)
  }
  type Query {
    users: [User]
    user(id: Int!): User
    account(id: Int!): Account   # VB-179 BOLA: any account by id
    login(username: String!, password: String!): User
  }
  type Mutation {
    setRole(userId: Int!, role: String!): User      # VB-206 no authz -> privesc
    transfer(from: Int!, to: Int!, amount: Float!): Account  # VB-207 no authz/limits
  }
`);

const root = {
  users: () => db.prepare('SELECT * FROM users').all().map(withRels),
  user: ({ id }) => withRels(db.prepare('SELECT * FROM users WHERE id=?').get(id)),
  // VB-179 BOLA: no ownership/authz check at all.
  account: ({ id }) => withRels(db.prepare('SELECT * FROM accounts WHERE id=?').get(id)),
  // VB-176: login exposed in GraphQL, alias-batchable for brute force.
  login: ({ username, password }) =>
    withRels(db.prepare('SELECT * FROM users WHERE username=? AND password=?').get(username, password)),
  // VB-206: mutation with no authorization -> anyone can grant admin.
  setRole: ({ userId, role }) => {
    db.prepare('UPDATE users SET role=? WHERE id=?').run(role, userId);
    return withRels(db.prepare('SELECT * FROM users WHERE id=?').get(userId));
  },
  // VB-207: transfer mutation with no ownership/limit checks.
  transfer: ({ from, to, amount }) => {
    db.prepare('UPDATE accounts SET balance = balance - ? WHERE id=?').run(amount, from);
    db.prepare('UPDATE accounts SET balance = balance + ? WHERE id=?').run(amount, to);
    return withRels(db.prepare('SELECT * FROM accounts WHERE id=?').get(to));
  },
};

function withRels(row) {
  if (!row) return null;
  const r = { ...row };
  if (r.acct_number !== undefined) {
    r.owner = () => withRels(db.prepare('SELECT * FROM users WHERE id=?').get(r.user_id));
  } else {
    r.accounts = () => db.prepare('SELECT * FROM accounts WHERE user_id=?').all(r.id).map(withRels);
  }
  return r;
}

module.exports = graphqlHTTP({
  schema,
  rootValue: root,
  graphiql: true,          // VB-175: interactive explorer + introspection enabled
  customFormatErrorFn: e => ({ message: e.message, stack: e.stack }), // VB-105 leak
});
