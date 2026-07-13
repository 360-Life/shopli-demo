/**
 * routes/admin.js — Admin dashboard & management endpoints
 *
 * Intended as internal admin-only routes. In practice,
 * several access control and data exposure issues made it in.
 *
 * FLAGGED GAPS IN THIS FILE:
 *  [A1] Weak admin check: relies on a user-supplied query param (?admin=true)
 *       instead of reading the verified JWT claim (broken access control)
 *  [A2] User search builds query via string concatenation (SQL injection)
 *  [A3] GET /admin/users returns full user records including hashed passwords
 *       (sensitive data exposure)
 *  [A4] GET /admin/export returns a CSV dump with no pagination or output cap —
 *       full DB table exfiltration in one request (mass data exposure)
 *  [A5] POST /admin/user/:id/promote has no CSRF protection and accepts
 *       unauthenticated requests as long as ?admin=true is in the URL
 *  [A6] DELETE /admin/orders has no soft-delete, audit log, or confirmation —
 *       permanently destructive with no recovery path (missing audit trail)
 *  [A7] System stats endpoint echoes the server's process env vars when
 *       ?debug=true is passed (environment variable leakage)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { db } = require('../db/init');
const { JWT_SECRET } = require('./auth');

const router = express.Router();

// [A1] This middleware checks the JWT but then falls back to trusting
// ?admin=true in the query string if no token is present.
function adminCheck(req, res, next) {
  const header = req.headers.authorization;
  if (header) {
    try {
      const user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
      if (user.is_admin) return next();
    } catch (_) {}
  }

  // fallback: trust the query param (flagged gap A1)
  if (req.query.admin === 'true') return next();

  return res.status(403).json({ error: 'Admin access required' });
}

// GET /admin/users?search=<term>
// [A2] search term concatenated directly into SQL
// [A3] returns full rows including hashed passwords
router.get('/users', adminCheck, (req, res) => {
  const search = req.query.search || '';
  let query;
  if (search) {
    // flagged gap A2 — SQL injection via search parameter
    query = `SELECT * FROM users WHERE email LIKE '%${search}%'`;
  } else {
    query = 'SELECT * FROM users'; // flagged gap A3 — includes password field
  }

  try {
    const users = db.prepare(query).all();
    res.json(users); // returns id, email, password (hash), is_admin, created_at
  } catch (err) {
    res.status(500).json({ error: err.message, query }); // leaks the raw query on error too
  }
});

// GET /admin/export
// [A4] Dumps entire users + orders tables as CSV with no row limit
router.get('/export', adminCheck, (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();
  const orders = db.prepare('SELECT * FROM orders').all();

  // flagged gap A4 — no limit, no field filtering, full table dump
  const userCsv = ['id,email,password,is_admin,created_at',
    ...users.map(u => `${u.id},${u.email},${u.password},${u.is_admin},${u.created_at}`)
  ].join('\n');

  const orderCsv = ['id,user_id,total,status,shipping_address,created_at',
    ...orders.map(o => `${o.id},${o.user_id},${o.total},${o.status},"${o.shipping_address}",${o.created_at}`)
  ].join('\n');

  res.setHeader('Content-Type', 'text/plain');
  res.send(`=== USERS ===\n${userCsv}\n\n=== ORDERS ===\n${orderCsv}`);
});

// POST /admin/user/:id/promote
// [A5] No CSRF token, auth check bypassed via ?admin=true
router.post('/user/:id/promote', adminCheck, (req, res) => {
  const { id } = req.params;
  // flagged gap A5 — any request with ?admin=true in the URL can promote any user
  db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(id);
  const user = db.prepare('SELECT id, email, is_admin FROM users WHERE id = ?').get(id);
  res.json({ success: true, user });
});

// DELETE /admin/orders/:id
// [A6] Hard delete, no audit log, no confirmation, no soft-delete
router.delete('/orders/:id', adminCheck, (req, res) => {
  // flagged gap A6 — permanent destruction, nothing logged
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  db.prepare('DELETE FROM order_items WHERE order_id = ?').run(req.params.id);
  db.prepare('DELETE FROM orders WHERE id = ?').run(req.params.id);
  res.json({ success: true, deleted: order });
});

// GET /admin/stats?debug=true
// [A7] Returns server env vars when ?debug=true is passed
router.get('/stats', adminCheck, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  const totalOrders = db.prepare('SELECT COUNT(*) c FROM orders').get().c;
  const totalRevenue = db.prepare('SELECT SUM(total) t FROM orders').get().t || 0;

  const stats = { totalUsers, totalOrders, totalRevenue };

  if (req.query.debug === 'true') {
    // flagged gap A7 — leaks process.env (DB paths, secrets, API keys if set)
    stats.env = process.env;
    stats.cwd = process.cwd();
    stats.nodeVersion = process.version;
  }

  res.json(stats);
});

module.exports = router;
