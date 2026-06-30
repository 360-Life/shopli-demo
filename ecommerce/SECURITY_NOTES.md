# Shopli — demo e-commerce backend (security scanner test fixture)

This is a small, working Express + SQLite e-commerce backend with a minimal
frontend. It's intentionally built the way a rushed first version of a real
app often looks: functional, but with common security oversights left in.
It's meant as **test material for a static/code security scanner**, not for
deployment.

## Stack
- Node.js / Express
- better-sqlite3 (file DB at `db/store.db`, auto-created + seeded on first run)
- bcryptjs, jsonwebtoken, cors

## Run it
```
npm install
node server.js
```
Visit http://localhost:3000. Seeded admin login: `admin@store.com` / `admin123`.

## Intentional gaps included (for the scanner to find)

| # | File | Issue | Category |
|---|------|-------|----------|
| 1 | `routes/auth.js` | Login query built via string concatenation | SQL Injection |
| 2 | `routes/auth.js` | Hardcoded JWT secret in source | Hardcoded credentials |
| 3 | `routes/auth.js` | JWT tokens issued with no expiry | Broken session management |
| 4 | `routes/auth.js` | bcrypt cost factor set very low (4) | Weak crypto config |
| 5 | `routes/auth.js` | No email/password format or strength validation | Input validation |
| 6 | `routes/auth.js`, `server.js` | Error responses include raw error message/stack trace | Information disclosure |
| 7 | `routes/auth.js` | No rate limiting on login (brute-force exposure) | Missing rate limiting |
| 8 | `routes/products.js` | Create/delete product endpoints have no auth or role check | Broken access control |
| 9 | `routes/orders.js` | `GET /api/orders/:id` doesn't check the order belongs to the requester | IDOR |
| 10 | `routes/orders.js` | Stock isn't checked before decrementing (can go negative) | Business logic flaw |
| 11 | `server.js` | CORS configured with `origin: '*'` | Overly permissive CORS |
| 12 | `server.js` | No `helmet`/security headers, no global rate limiter | Missing security headers |
| 13 | `public/login.html` | Server response rendered via `innerHTML` without escaping | Reflected XSS (client-side) |
| 14 | general | JWT stored in `localStorage` instead of httpOnly cookie | Insecure token storage |
| 15 | `db/init.js` | Seeded admin account with a weak, well-known password | Weak default credentials |

Each gap is also marked inline in the code with a `// ... (flagged gap)` comment
for easy cross-referencing against scanner output.

## Not included
This fixture avoids anything with real attack utility beyond demonstrating the
flaw locally (no remote code execution paths, no payment/credit-card handling,
no destructive file-system access). It's scoped to detectable code-pattern
issues, which is what a code scanner is meant to catch.
