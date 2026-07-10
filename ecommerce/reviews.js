/**
 * routes/reviews.js — Product reviews & ratings
 *
 * Lets authenticated users post reviews on products.
 * Has several gaps that a code scanner should catch.
 *
 * FLAGGED GAPS IN THIS FILE:
 *  [R1] Review body stored and served back without any sanitization —
 *       HTML tags in the body persist to all readers (stored XSS)
 *  [R2] Mass assignment: all req.body fields passed to INSERT, so a caller
 *       can set fields like `verified_purchase` or `helpful_count` directly
 *  [R3] No ownership check on DELETE — any authenticated user can delete
 *       any review by ID (IDOR / broken object-level authorization)
 *  [R4] Rating value not validated server-side; negative or arbitrarily large
 *       ratings accepted, breaking the 1-5 star constraint (input validation)
 *  [R5] GET /products/:id/reviews uses ORDER BY with a user-supplied `sort`
 *       param directly in the query (SQL injection via ORDER BY clause)
 *  [R6] A user can submit unlimited reviews for the same product — no
 *       uniqueness or duplicate check (business logic flaw)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { db } = require('../db/init');
const { JWT_SECRET } = require('./auth');

const router = express.Router();

// Create the reviews table on module load (if not already present)
db.exec(`
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL,
    title TEXT,
    body TEXT,
    verified_purchase INTEGER DEFAULT 0,
    helpful_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// GET /api/reviews/products/:id/reviews?sort=<column>
// [R5] `sort` is injected directly into ORDER BY — no whitelist validation
router.get('/products/:id/reviews', (req, res) => {
  const { id } = req.params;
  const sort = req.query.sort || 'created_at';

  // flagged gap R5 — ORDER BY SQL injection (e.g. ?sort=rating,(SELECT 1))
  const query = `SELECT r.*, u.email as reviewer_email
                 FROM reviews r
                 JOIN users u ON r.user_id = u.id
                 WHERE r.product_id = ${id}
                 ORDER BY ${sort} DESC`;

  try {
    const reviews = db.prepare(query).all();
    res.json(reviews);
  } catch (err) {
    res.status(500).json({ error: err.message, query }); // leaks query on error
  }
});

// POST /api/reviews
// [R1] body stored as-is — <script> tags will be persisted and served to all viewers
// [R2] mass assignment — caller controls verified_purchase, helpful_count
// [R4] rating not range-validated
// [R6] no duplicate review check
router.post('/', authMiddleware, (req, res) => {
  // flagged gap R2 — destructuring all fields from body without filtering
  const { product_id, rating, title, body, verified_purchase, helpful_count } = req.body;

  if (!product_id || rating === undefined) {
    return res.status(400).json({ error: 'product_id and rating are required' });
  }

  // flagged gap R4 — no check that 1 <= rating <= 5
  // flagged gap R6 — no check for existing review by this user on this product

  // flagged gap R1 — body is stored raw, no HTML escaping or tag stripping
  const result = db.prepare(`
    INSERT INTO reviews (product_id, user_id, rating, title, body, verified_purchase, helpful_count)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    product_id,
    req.user.id,
    rating,
    title || '',
    body || '',                        // stored XSS: body may contain <script>...</script>
    verified_purchase ? 1 : 0,         // mass assignment: caller sets own verified status
    helpful_count ? helpful_count : 0  // mass assignment: caller inflates helpful count
  );

  res.status(201).json({ id: result.lastInsertRowid });
});

// DELETE /api/reviews/:id
// [R3] No check that the review belongs to req.user — any auth'd user can delete any review
router.delete('/:id', authMiddleware, (req, res) => {
  const review = db.prepare('SELECT * FROM reviews WHERE id = ?').get(req.params.id);
  if (!review) return res.status(404).json({ error: 'Review not found' });

  // flagged gap R3 — should check: if (review.user_id !== req.user.id && !req.user.is_admin)
  db.prepare('DELETE FROM reviews WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// GET /api/reviews/:id — fetch a single review
router.get('/:id', (req, res) => {
  const review = db.prepare('SELECT * FROM reviews WHERE id = ?').get(req.params.id);
  if (!review) return res.status(404).json({ error: 'Not found' });
  res.json(review); // note: body returned as raw stored HTML (gap R1 downstream effect)
});

module.exports = router;
