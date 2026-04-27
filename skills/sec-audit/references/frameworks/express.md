# Express.js

## Source

- https://expressjs.com/en/advanced/best-practice-security.html
- https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/CSRF_Prevention_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers Express 4.x and 5.x running on Node.js, including body-parser,
express-session, and the helmet middleware ecosystem. Does not cover
NestJS (see separate reference) or serverless Express wrappers (Vercel, AWS
Lambda adapters).

## Dangerous patterns (regex/AST hints)

### SQL string concatenation — CWE-89

- Why: Building SQL queries with `+` or template literals from `req.body`/`req.params`/`req.query` enables SQL injection.
- Grep: `query\s*\(\s*["`'].*\$\{req\.|query\s*\(\s*.*\+\s*req\.|execute\s*\(\s*["`'].*\+\s*req\.`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

### eval() or new Function() with user input — CWE-94

- Why: Passing user-controlled strings to `eval()` or `new Function()` allows arbitrary code execution in the Node.js process.
- Grep: `eval\s*\(.*req\.|new\s+Function\s*\(.*req\.`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

### Missing helmet middleware — CWE-16

- Why: Express sets no security headers by default; without helmet, responses lack CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.
- Grep: `express\(\)` — absence of `helmet` import/call in same file
- File globs: `**/app.js`, `**/server.js`, `**/index.js`
- Source: https://expressjs.com/en/advanced/best-practice-security.html

### express-session with default or weak secret — CWE-321

- Why: A guessable session secret allows forging signed session cookies to impersonate any user.
- Grep: `secret\s*:\s*["'][^"']{1,20}["']|session\(\{.*secret.*:\s*["']`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://expressjs.com/en/advanced/best-practice-security.html

### Path traversal via req.params — CWE-22

- Why: Constructing file paths with `req.params` or `req.query` without sanitizing `..` sequences allows reading arbitrary files.
- Grep: `path\.join\(.*req\.(params|query)|readFile\(.*req\.(params|query)|res\.sendFile\(.*req\.(params|query)`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

### Prototype pollution via body-parser / merge — CWE-1321

- Why: `_.merge()`, `Object.assign()`, or `qs` deep-parse with user-controlled keys can overwrite `Object.prototype`, affecting all objects in the process.
- Grep: `merge\(.*req\.body|assign\(.*req\.body|\[.*req\.body.*\]\s*=`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

## Secure patterns

```javascript
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");

const app = express();
app.use(helmet());  // sets all security headers
app.disable("x-powered-by");  // redundant with helmet but explicit

app.use(session({
  secret: process.env.SESSION_SECRET,  // from environment
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,   // requires HTTPS
    sameSite: "lax",
  },
}));
```

Source: https://expressjs.com/en/advanced/best-practice-security.html

```javascript
// Parameterized query with node-postgres
const { rows } = await pool.query(
  "SELECT * FROM users WHERE id = $1",
  [req.params.id]
);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

```javascript
// Safe file serving: resolve and check prefix
const path = require("path");
const BASE_DIR = path.resolve(__dirname, "public");

app.get("/files/:name", (req, res) => {
  const target = path.resolve(BASE_DIR, req.params.name);
  if (!target.startsWith(BASE_DIR + path.sep)) {
    return res.status(400).send("Bad request");
  }
  res.sendFile(target);
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

## Fix recipes

### Recipe: Parameterize SQL queries — addresses CWE-89

**Before (dangerous):**

```javascript
const sql = `SELECT * FROM users WHERE email = '${req.body.email}'`;
db.query(sql, callback);
```

**After (safe):**

```javascript
db.query("SELECT * FROM users WHERE email = $1", [req.body.email], callback);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

### Recipe: Add helmet and remove x-powered-by — addresses CWE-16

**Before (dangerous):**

```javascript
const app = express();
// no security headers configured
```

**After (safe):**

```javascript
const helmet = require("helmet");
const app = express();
app.use(helmet());
app.disable("x-powered-by");
```

Source: https://expressjs.com/en/advanced/best-practice-security.html

### Recipe: Harden session cookie flags — addresses CWE-614

**Before (dangerous):**

```javascript
app.use(session({ secret: "keyboard cat", cookie: {} }));
```

**After (safe):**

```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { httpOnly: true, secure: true, sameSite: "lax" },
  resave: false,
  saveUninitialized: false,
}));
```

Source: https://expressjs.com/en/advanced/best-practice-security.html

### Recipe: Prevent path traversal — addresses CWE-22

**Before (dangerous):**

```javascript
res.sendFile(path.join(__dirname, "uploads", req.params.filename));
```

**After (safe):**

```javascript
const base = path.resolve(__dirname, "uploads");
const target = path.resolve(base, req.params.filename);
if (!target.startsWith(base + path.sep)) return res.sendStatus(400);
res.sendFile(target);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

## Version notes

- Express 5.x (stable 2024+): async error handling is built-in; `next(err)` propagation no longer requires manual try/catch in async routes.
- helmet 7.x: CSP is enabled by default; earlier versions had it opt-in.
- `express-session` < 1.15: `cookie.secure` did not auto-detect HTTPS proxies; always set `app.set("trust proxy", 1)` behind a load balancer.

## Common false positives

- `eval()` used only with developer-owned template strings or JSON parse fallbacks with no user-controlled input in scope.
- `_.merge()` called only on two developer-controlled configuration objects, not on `req.body`.
- `helmet()` absent in a file that is a sub-router mounted on a parent app that already applies `helmet()` — check the parent entry point.
- Weak session secret in a dedicated test configuration file never loaded in production.
