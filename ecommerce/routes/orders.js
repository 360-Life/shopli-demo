const express = require('express');
const jwt = require('jsonwebtoken');
const { db } = require('../db/init');
const { JWT_SECRET } = require('./auth');

const router = express.Router();

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

router.post('/', authMiddleware, (req, res) => {
  const { items, shipping_address } = req.body; // items: [{product_id, quantity}]
  if (!items || !items.length) return res.status(400).json({ error: 'No items in order' });

  let total = 0;
  const lineItems = [];
  for (const item of items) {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(item.product_id);
    if (!product) continue;
    // no server-side check that stock is sufficient before decrementing (flagged gap - logic flaw)
    total += product.price * item.quantity;
    lineItems.push({ product_id: product.id, quantity: item.quantity, price: product.price });
  }

  const orderResult = db.prepare(
    'INSERT INTO orders (user_id, total, shipping_address) VALUES (?,?,?)'
  ).run(req.user.id, total, shipping_address);

  const insertItem = db.prepare(
    'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?,?,?,?)'
  );
  for (const li of lineItems) {
    insertItem.run(orderResult.lastInsertRowid, li.product_id, li.quantity, li.price);
    db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?').run(li.quantity, li.product_id);
  }

  res.json({ id: orderResult.lastInsertRowid, total });
});

// IDOR: any authenticated user can fetch any order by guessing IDs (flagged gap)
router.get('/:id', authMiddleware, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  const items = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(order.id);
  res.json({ ...order, items });
});

router.get('/', authMiddleware, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ?').all(req.user.id);
  res.json(orders);
});

module.exports = router;
