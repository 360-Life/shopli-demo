const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();

app.use(express.json());

// permissive CORS - allows any origin (flagged gap)
app.use(cors({ origin: '*' }));

app.use(express.static(path.join(__dirname, 'public')));

const { ready } = require('./db/init');

ready.then(() => {
  const { router: authRouter } = require('./routes/auth');
  const productsRouter = require('./routes/products');
  const ordersRouter = require('./routes/orders');

  app.use('/api/auth', authRouter);
  app.use('/api/products', productsRouter);
  app.use('/api/orders', ordersRouter);

  // no helmet / security headers configured (flagged gap)
  // no global rate limiter (flagged gap)

  app.use((err, req, res, next) => {
    // generic error handler leaks stack traces (flagged gap)
    res.status(500).json({ error: err.message, stack: err.stack });
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
