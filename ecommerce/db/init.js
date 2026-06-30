const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'store.db');

let SQL, sqlDb;

function save() {
  const data = sqlDb.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// Minimal synchronous-looking wrapper mimicking better-sqlite3's API
// (the underlying sql.js init is async, so callers must await `ready` first)
class Stmt {
  constructor(sql) {
    this.sql = sql;
  }
  run(...params) {
    sqlDb.run(this.sql, params);
    save();
    const idRes = sqlDb.exec('SELECT last_insert_rowid() as id');
    const lastInsertRowid = idRes.length ? idRes[0].values[0][0] : undefined;
    return { lastInsertRowid };
  }
  get(...params) {
    const stmt = sqlDb.prepare(this.sql);
    stmt.bind(params);
    let row = undefined;
    if (stmt.step()) row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  all(...params) {
    const stmt = sqlDb.prepare(this.sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  }
}

const db = {
  prepare(sql) {
    return new Stmt(sql);
  },
  exec(sql) {
    sqlDb.run(sql);
    save();
  },
};

const ready = (async () => {
  SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    sqlDb = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    sqlDb = new SQL.Database();
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      stock INTEGER DEFAULT 0,
      image_url TEXT
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      total REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      shipping_address TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      price REAL NOT NULL
    );
  `);

  const count = db.prepare('SELECT COUNT(*) c FROM products').get().c;
  if (count === 0) {
    const insert = db.prepare('INSERT INTO products (name, description, price, stock, image_url) VALUES (?,?,?,?,?)');
    insert.run('Wireless Headphones', 'Noise-cancelling over-ear headphones', 89.99, 25, 'https://picsum.photos/seed/headphones/400');
    insert.run('Mechanical Keyboard', 'RGB backlit mechanical keyboard', 64.50, 40, 'https://picsum.photos/seed/keyboard/400');
    insert.run('Smart Watch', 'Fitness tracking smart watch', 129.00, 15, 'https://picsum.photos/seed/watch/400');
    insert.run('Backpack', 'Water-resistant laptop backpack', 39.99, 60, 'https://picsum.photos/seed/backpack/400');
    insert.run('Desk Lamp', 'LED desk lamp with adjustable brightness', 22.75, 100, 'https://picsum.photos/seed/lamp/400');
    insert.run('Coffee Grinder', 'Burr coffee grinder', 54.00, 30, 'https://picsum.photos/seed/grinder/400');
  }

  const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@store.com');
  if (!adminExists) {
    const hash = bcrypt.hashSync('admin123', 4); // low salt rounds - see SECURITY_NOTES.md
    db.prepare('INSERT INTO users (email, password, is_admin) VALUES (?,?,1)').run('admin@store.com', hash);
  }
})();

module.exports = { db, ready };
