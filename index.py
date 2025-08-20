# This script creates a complete, ready-to-run Express.js + SQLite e-commerce project,
# zips it, and provides a downloadable link for the user.

import os, json, textwrap, zipfile, shutil, pathlib, datetime

base = "/mnt/data/simple-ecommerce-express"
if os.path.exists(base):
    shutil.rmtree(base)
os.makedirs(base, exist_ok=True)

# Helper to write files
def write(path, content, binary=False):
    full = os.path.join(base, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    mode = "wb" if binary else "w"
    with open(full, mode, encoding=None if binary else "utf-8") as f:
        f.write(content)

# package.json
package_json = {
  "name": "simple-ecommerce-express",
  "version": "1.0.0",
  "private": False,
  "description": "Internship Task: Simple E-commerce Store (Express.js + SQLite + Vanilla JS)",
  "main": "server.js",
  "scripts": {
    "dev": "node server.js",
    "start": "NODE_ENV=production node server.js",
    "db:reset": "node scripts/init_db.js"
  },
  "keywords": ["express", "sqlite", "ecommerce", "internship", "codealpha"],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "bcrypt": "^5.1.1",
    "better-sqlite3": "^9.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "morgan": "^1.10.0",
    "uuid": "^9.0.1"
  }
}
write("package.json", json.dumps(package_json, indent=2))

# .env example
write(".env.example", textwrap.dedent("""\
PORT=3000
JWT_SECRET=supersecret_change_me
NODE_ENV=development
"""))

# server.js
write("server.js", textwrap.dedent("""\
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Serve static frontend
app.use('/', express.static(path.join(__dirname, 'public')));

// API routes
app.use('/api/auth', require('./src/routes/auth'));
app.use('/api/products', require('./src/routes/products'));
app.use('/api/orders', require('./src/routes/orders'));

// Fallback to index.html for simple front-end navigation
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
"""))

# db.js
write("src/db.js", textwrap.dedent("""\
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, '..', 'data', 'ecommerce.sqlite');
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);

// Enforce foreign keys
db.pragma('foreign_keys = ON');

module.exports = db;
"""))

# schema.sql
write("src/schema.sql", textwrap.dedent("""\
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL CHECK(price >= 0),
  image_url TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  total REAL NOT NULL CHECK(total >= 0),
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity > 0),
  unit_price REAL NOT NULL CHECK(unit_price >= 0),
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
);
"""))

# seed.sql
write("src/seed.sql", textwrap.dedent("""\
INSERT INTO products (name, description, price, image_url) VALUES
('Classic T-Shirt', '100% cotton, comfy everyday wear.', 499.00, 'https://picsum.photos/seed/shirt/600/400'),
('Denim Jeans', 'Slim fit blue denim.', 1599.00, 'https://picsum.photos/seed/jeans/600/400'),
('Running Shoes', 'Lightweight shoes for daily runs.', 2999.00, 'https://picsum.photos/seed/shoes/600/400'),
('Backpack', 'Durable and water-resistant.', 1299.00, 'https://picsum.photos/seed/bag/600/400'),
('Wireless Earbuds', 'Crystal-clear sound with noise isolation.', 2499.00, 'https://picsum.photos/seed/earbuds/600/400');
"""))

# init_db.js script
write("scripts/init_db.js", textwrap.dedent("""\
const fs = require('fs');
const path = require('path');
const db = require('../src/db');

function runSqlFile(filePath) {
  const abs = path.join(__dirname, '..', filePath);
  const sql = fs.readFileSync(abs, 'utf8');
  db.exec(sql);
  console.log(`Executed: ${filePath}`);
}

try {
  runSqlFile('src/schema.sql');
  runSqlFile('src/seed.sql');
  console.log('Database initialized successfully.');
} catch (err) {
  console.error('DB init failed:', err);
  process.exit(1);
}
"""))

# middleware auth
write("src/middleware/auth.js", textwrap.dedent("""\
const jwt = require('jsonwebtoken');

module.exports = function(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'supersecret_change_me');
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};
"""))

# routes/auth.js
write("src/routes/auth.js", textwrap.dedent("""\
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret_change_me';
const SALT_ROUNDS = 10;

router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(409).json({ error: 'Email already registered' });
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const info = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)').run(name, email, password_hash);
    const user = { id: info.lastInsertRowid, name, email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email & password required' });
    const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const user = { id: row.id, name: row.name, email: row.email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

module.exports = router;
"""))

# routes/products.js
write("src/routes/products.js", textwrap.dedent("""\
const express = require('express');
const db = require('../db');
const router = express.Router();

router.get('/', (req, res) => {
  const rows = db.prepare('SELECT * FROM products ORDER BY id DESC').all();
  res.json(rows);
});

router.get('/:id', (req, res) => {
  const { id } = req.params;
  const row = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'Product not found' });
  res.json(row);
});

module.exports = router;
"""))

# routes/orders.js
write("src/routes/orders.js", textwrap.dedent("""\
const express = require('express');
const db = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.post('/', auth, (req, res) => {
  const { items } = req.body;
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'No items provided' });
  }

  // Validate and compute total
  let total = 0;
  const preparedProduct = db.prepare('SELECT id, price FROM products WHERE id = ?');

  const normalized = items.map(i => {
    const pid = Number(i.productId);
    const qty = Math.max(1, Number(i.quantity || 1));
    const p = preparedProduct.get(pid);
    if (!p) throw new Error(`Invalid product id: ${pid}`);
    const unit_price = Number(p.price);
    const lineTotal = unit_price * qty;
    total += lineTotal;
    return { product_id: pid, quantity: qty, unit_price };
  });

  const insertOrder = db.prepare('INSERT INTO orders (user_id, total) VALUES (?, ?)');
  const insertItem = db.prepare('INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)');

  const tx = db.transaction(() => {
    const info = insertOrder.run(req.user.id, total);
    const orderId = info.lastInsertRowid;
    for (const n of normalized) {
      insertItem.run(orderId, n.product_id, n.quantity, n.unit_price);
    }
    return orderId;
  });

  try {
    const orderId = tx();
    res.json({ orderId, total });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: e.message || 'Order failed' });
  }
});

router.get('/mine', auth, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  const itemsStmt = db.prepare('SELECT * FROM order_items WHERE order_id = ?');
  const result = orders.map(o => ({
    ...o,
    items: itemsStmt.all(o.id)
  }));
  res.json(result);
});

module.exports = router;
"""))

# Public frontend files
write("public/styles.css", textwrap.dedent("""\
:root { --brand: #0f766e; --ink: #111827; --muted: #6b7280; --bg: #f9fafb; }
*{ box-sizing:border-box }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans', 'Apple Color Emoji', 'Segoe UI Emoji'; margin:0; background:var(--bg); color:var(--ink); }
.container { max-width: 1000px; margin: 0 auto; padding: 16px; }
.header { display:flex; align-items:center; justify-content:space-between; padding: 12px 0; }
.brand { font-weight:800; font-size: 1.25rem; color: var(--brand); text-decoration:none; }
.nav a { margin-left: 12px; text-decoration:none; color: var(--ink); }
.grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap:16px; }
.card { background:white; border-radius: 16px; padding: 12px; box-shadow: 0 6px 20px rgba(0,0,0,0.06); display:flex; flex-direction:column; }
.card img { width:100%; height: 180px; object-fit: cover; border-radius: 12px; }
.card h3 { margin: 8px 0 4px; font-size: 1.1rem; }
.price { font-weight:700; margin: 4px 0; }
.btn { padding: 10px 14px; border: none; border-radius: 9999px; cursor: pointer; background: var(--brand); color: white; font-weight: 600; }
.btn.secondary { background: #334155; }
.input { width:100%; padding:10px 12px; border:1px solid #e5e7eb; border-radius:12px; margin: 6px 0 12px; }
.hero { padding: 24px 0; }
footer { margin: 40px 0 16px; color: var(--muted); text-align: center; font-size: 0.9rem; }
.alert { padding: 12px; border-radius: 12px; background:#ecfccb; border:1px solid #d9f99d; margin: 12px 0; }
.small { font-size: 0.9rem; color: var(--muted); }
"""))

# Shared header
header_html = """\
<header class="header container">
  <a class="brand" href="/">ShopLite</a>
  <nav class="nav">
    <a href="/cart.html">Cart (<span id="cart-count">0</span>)</a>
    <a href="/login.html" id="nav-login">Login</a>
    <a href="/register.html" id="nav-register">Register</a>
    <a href="#" id="nav-logout" style="display:none">Logout</a>
  </nav>
</header>
"""

# index.html
write("public/index.html", textwrap.dedent(f"""\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ShopLite – Products</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  {header_html}
  <main class="container">
    <section class="hero">
      <h1>Latest Products</h1>
      <p class="small">A basic e-commerce demo for internship submission.</p>
    </section>
    <section id="product-grid" class="grid"></section>
  </main>
  <footer>© {datetime.date.today().year} ShopLite • Built with Express + SQLite • Task by codealpha.tech</footer>
  <script src="/shared.js"></script>
  <script>
    fetch('/api/products').then(r => r.json()).then(products => {{
      const grid = document.getElementById('product-grid');
      grid.innerHTML = products.map(p => `
        <article class="card">
          <img src="${{p.image_url}}" alt="${{p.name}}"/>
          <h3>${{p.name}}</h3>
          <div class="price">₹ ${{p.price.toFixed(2)}}</div>
          <div style="margin-top:auto; display:flex; gap:8px;">
            <a class="btn secondary" href="/product.html?id=${{p.id}}">Details</a>
            <button class="btn" onclick="addToCart(${{p.id}})">Add to cart</button>
          </div>
        </article>
      `).join('');
    }});
  </script>
</body>
</html>
"""))

# product.html
write("public/product.html", textwrap.dedent(f"""\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Product • ShopLite</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  {header_html}
  <main class="container">
    <div id="product"></div>
  </main>
  <footer>© {datetime.date.today().year} ShopLite</footer>
  <script src="/shared.js"></script>
  <script>
    const params = new URLSearchParams(location.search);
    const id = params.get('id');
    fetch('/api/products/' + id).then(r => r.json()).then(p => {{
      if (p.error) {{ document.getElementById('product').innerHTML = '<p class="alert">Product not found.</p>'; return; }}
      document.getElementById('product').innerHTML = `
        <div class="card" style="grid: none;">
          <img src="${{p.image_url}}" alt="${{p.name}}" style="height:300px;"/>
          <h1>${{p.name}}</h1>
          <p>${{p.description || ''}}</p>
          <div class="price">₹ ${{p.price.toFixed(2)}}</div>
          <div style="display:flex; gap:8px;">
            <button class="btn" onclick="addToCart(${{p.id}})">Add to cart</button>
            <a href="/cart.html" class="btn secondary">Go to cart</a>
          </div>
        </div>
      `;
    }});
  </script>
</body>
</html>
"""))

# cart.html
write("public/cart.html", textwrap.dedent(f"""\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Your Cart • ShopLite</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  {header_html}
  <main class="container">
    <h1>Your Cart</h1>
    <div id="cart-items"></div>
    <div id="cart-total" style="margin-top:12px; font-weight:700;"></div>
    <button class="btn" id="checkout-btn">Checkout</button>
    <div id="message"></div>
  </main>
  <footer>© {datetime.date.today().year} ShopLite</footer>
  <script src="/shared.js"></script>
  <script>
    function render() {{
      const cart = getCart();
      if (cart.length === 0) {{
        document.getElementById('cart-items').innerHTML = '<p class="small">Your cart is empty.</p>';
        document.getElementById('cart-total').textContent = '';
        return;
      }}
      fetch('/api/products').then(r => r.json()).then(products => {{
        let total = 0;
        const html = cart.map(item => {{
          const p = products.find(pp => pp.id === item.productId);
          if (!p) return '';
          const line = p.price * item.quantity;
          total += line;
          return `
            <div class="card">
              <div style="display:flex; gap:16px; align-items:center;">
                <img src="${{p.image_url}}" style="width:120px; height:80px; object-fit:cover;"/>
                <div style="flex:1;">
                  <h3>${{p.name}}</h3>
                  <div class="small">₹ ${{p.price.toFixed(2)}} × 
                    <input class="input" style="width:80px; display:inline-block" type="number" min="1" value="${{item.quantity}}" 
                      onchange="updateQty(${{p.id}}, this.value)"/>
                  </div>
                </div>
                <button class="btn secondary" onclick="removeFromCart(${{p.id}})">Remove</button>
              </div>
            </div>
          `;
        }}).join('');
        document.getElementById('cart-items').innerHTML = html;
        document.getElementById('cart-total').textContent = 'Total: ₹ ' + total.toFixed(2);
      }});
    }}
    render();
    document.getElementById('checkout-btn').onclick = async () => {{
      const token = localStorage.getItem('token');
      if (!token) {{ showMessage('Please login to checkout.', true); return; }}
      const items = getCart();
      const resp = await fetch('/api/orders', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }},
        body: JSON.stringify({{ items }})
      }});
      const data = await resp.json();
      if (!resp.ok) {{ showMessage(data.error || 'Checkout failed', true); return; }}
      clearCart();
      render();
      showMessage('Order placed! Order ID: ' + data.orderId + ' • Total ₹ ' + data.total.toFixed(2));
    }};
  </script>
</body>
</html>
"""))

# login.html
write("public/login.html", textwrap.dedent(f"""\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login • ShopLite</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  {header_html}
  <main class="container">
    <h1>Login</h1>
    <input class="input" id="email" placeholder="Email" type="email" />
    <input class="input" id="password" placeholder="Password" type="password" />
    <button class="btn" id="login-btn">Login</button>
    <div id="message"></div>
    <p class="small">No account? <a href="/register.html">Register</a></p>
  </main>
  <footer>© {datetime.date.today().year} ShopLite</footer>
  <script src="/shared.js"></script>
  <script>
    document.getElementById('login-btn').onclick = async () => {{
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const resp = await fetch('/api/auth/login', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ email, password }})
      }});
      const data = await resp.json();
      if (!resp.ok) {{ showMessage(data.error || 'Login failed', true); return; }}
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      location.href = '/';
    }};
  </script>
</body>
</html>
"""))

# register.html
write("public/register.html", textwrap.dedent(f"""\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Register • ShopLite</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  {header_html}
  <main class="container">
    <h1>Create account</h1>
    <input class="input" id="name" placeholder="Name" />
    <input class="input" id="email" placeholder="Email" type="email" />
    <input class="input" id="password" placeholder="Password" type="password" />
    <button class="btn" id="register-btn">Register</button>
    <div id="message"></div>
  </main>
  <footer>© {datetime.date.today().year} ShopLite</footer>
  <script src="/shared.js"></script>
  <script>
    document.getElementById('register-btn').onclick = async () => {{
      const name = document.getElementById('name').value.trim();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const resp = await fetch('/api/auth/register', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ name, email, password }})
      }});
      const data = await resp.json();
      if (!resp.ok) {{ showMessage(data.error || 'Registration failed', true); return; }}
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      location.href = '/';
    }};
  </script>
</body>
</html>
"""))

# shared.js
write("public/shared.js", textwrap.dedent("""\
// Basic nav/cart helpers
function getCart() {
  try { return JSON.parse(localStorage.getItem('cart') || '[]'); } catch { return []; }
}
function setCart(items) { localStorage.setItem('cart', JSON.stringify(items)); updateCartCount(); }
function addToCart(productId, quantity = 1) {
  const cart = getCart();
  const idx = cart.findIndex(i => i.productId === productId);
  if (idx >= 0) cart[idx].quantity += quantity;
  else cart.push({ productId, quantity });
  setCart(cart);
  alert('Added to cart!');
}
function updateQty(productId, qty) {
  qty = Math.max(1, Number(qty || 1));
  const cart = getCart();
  const idx = cart.findIndex(i => i.productId === productId);
  if (idx >= 0) { cart[idx].quantity = qty; setCart(cart); }
}
function removeFromCart(productId) {
  setCart(getCart().filter(i => i.productId !== productId));
}
function clearCart() { setCart([]); }
function updateCartCount() {
  const count = getCart().reduce((a, b) => a + (b.quantity || 1), 0);
  const el = document.getElementById('cart-count');
  if (el) el.textContent = String(count);
}
function showMessage(msg, isError = false) {
  const el = document.getElementById('message');
  if (el) {
    el.className = 'alert' + (isError ? ' error' : '');
    el.textContent = msg;
  } else {
    alert(msg);
  }
}

// Auth-aware nav
function refreshNav() {
  const token = localStorage.getItem('token');
  const user = JSON.parse(localStorage.getItem('user') || 'null');
  const login = document.getElementById('nav-login');
  const reg = document.getElementById('nav-register');
  const out = document.getElementById('nav-logout');
  if (token && user) {
    if (login) login.style.display = 'none';
    if (reg) reg.style.display = 'none';
    if (out) out.style.display = 'inline';
    out.onclick = () => { localStorage.removeItem('token'); localStorage.removeItem('user'); location.reload(); }
  } else {
    if (login) login.style.display = 'inline';
    if (reg) reg.style.display = 'inline';
    if (out) out.style.display = 'none';
  }
  updateCartCount();
}
document.addEventListener('DOMContentLoaded', refreshNav);
"""))

# README.md
write("README.md", textwrap.dedent("""\
# Simple E-commerce Store (Express.js + SQLite)

> Internship Project – **Task 1: Simple E-commerce Store** (Frontend: HTML/CSS/JS • Backend: Express.js • DB: SQLite)

**Features**  
- Product listing and product details page  
- Shopping cart (client-side, localStorage)  
- User registration & login (JWT)  
- Order processing (creates orders & order items in DB)  
- Minimal, clean UI with vanilla HTML/CSS/JS  
- Ready for GitHub submission

## Quick Start

```bash
# 1) Clone and install
npm install

# 2) Initialize the SQLite database (schema + seed products)
npm run db:reset

# 3) Run the server
npm run dev
# App runs on http://localhost:3000
