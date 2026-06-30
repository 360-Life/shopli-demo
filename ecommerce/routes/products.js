const express = require('express');
const { db } = require('../db/init');
const router = express.Router();

router.get('/', (req, res) => {
  const products = db.prepare('SELECT * FROM products').all();
  res.json(products);
});

router.get('/:id', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).json({ error: 'Not found' });
  res.json(product);
});

// Admin-only in intent, but no auth/role check actually enforced here (flagged gap - broken access control)
router.post('/', (req, res) => {
  const { name, description, price, stock, image_url } = req.body;
  const result = db.prepare(
    'INSERT INTO products (name, description, price, stock, image_url) VALUES (?,?,?,?,?)'
  ).run(name, description, price, stock, image_url);
  res.json({ id: result.lastInsertRowid });
});

router.delete('/:id', (req, res) => {
  // same missing authorization check (flagged gap)
  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

module.exports = router;
