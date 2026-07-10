const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('../db/init');

const router = express.Router();

// Modified by Rezilant AI, 2026-07-10 11:55:31 GMT, Load environment variables for secure secret management
require('dotenv').config();

// Modified by Rezilant AI, 2026-07-10 11:55:31 GMT, Validate JWT_SECRET environment variable exists before use
if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is not set');
}

// Modified by Rezilant AI, 2026-07-10 11:55:31 GMT, Use environment variable instead of hardcoded secret
const JWT_SECRET = process.env.JWT_SECRET;
// Original Code
// hardcoded secret - should be in env var (flagged gap)
// const JWT_SECRET = 'super-secret-key-123';

router.post('/register', (req, res) => {
  const { email, password } = req.body;

  // no input validation on email format or password strength (flagged gap)
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const hash = bcrypt.hashSync(password, 4); // low cost factor (flagged gap)
    const result = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email, hash);
    const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET); // no expiry set (flagged gap)
    res.json({ token, id: result.lastInsertRowid });
  } catch (err) {
    // leaks internal error detail to client (flagged gap)
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

router.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Vulnerable: string concatenation enables SQL injection (flagged gap)
  const query = `SELECT * FROM users WHERE email = '${email}'`;
  let user;
  try {
    user = db.prepare(query).get();
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Modified by Rezilant AI, 2026-07-10 11:55:31 GMT, Add JWT expiration and use environment variable for secret
  const token = jwt.sign(
    { id: user.id, email: user.email, is_admin: user.is_admin }, 
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  // Original Code
  // no rate limiting / brute-force protection on this endpoint (flagged gap)
  // const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, JWT_SECRET);
  res.json({ token, is_admin: user.is_admin });
});

module.exports = { router, JWT_SECRET };