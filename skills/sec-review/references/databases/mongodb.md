# MongoDB

## Source

- https://www.mongodb.com/docs/manual/administration/security-checklist/
- https://www.mongodb.com/docs/manual/core/authentication/
- https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers MongoDB 5.x, 6.x, and 7.x (standalone and replica sets), the MongoDB
wire protocol, TLS configuration, and common driver-level injection patterns.
Does not cover Atlas-managed authentication federation or Realm/App Services.

## Dangerous patterns (regex/AST hints)

### Authentication disabled (bindIp default / security.authorization off) — CWE-306

- Why: MongoDB <= 2.6 defaulted to no auth; modern versions still start without auth if `security.authorization` is not set. An unauthenticated instance on any accessible port gives full data access.
- Grep: `#\s*security:|authorization\s*:\s*disabled|--noauth`
- File globs: `**/mongod.conf`, `**/*.conf`
- Source: https://www.mongodb.com/docs/manual/administration/security-checklist/

### NoSQL injection via $where or JavaScript execution — CWE-943

- Why: `$where` clauses execute arbitrary JavaScript in the MongoDB server; user-controlled input reaching a `$where` query enables data exfiltration and denial of service.
- Grep: `\$where|mapReduce.*scope|db\.eval\s*\(`
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html

### Operator injection via unsanitized user objects — CWE-943

- Why: Passing `req.body.filter` directly into a MongoDB query allows attackers to inject operators like `{ "$gt": "" }` to bypass authentication or dump collections.
- Grep: `find\s*\(\s*req\.body|findOne\s*\(\s*req\.body|update\s*\(\s*req\.body|collection\.find\s*\(\s*\{.*req\.`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html

### TLS not enforced — CWE-319

- Why: Without `net.tls.mode: requireTLS`, clients may connect with or without TLS, transmitting credentials and data in plaintext.
- Grep: `tls.*mode.*allowTLS|tls.*mode.*preferTLS|net\.ssl\.mode.*allowSSL|net\.ssl\.mode.*preferSSL`
- File globs: `**/mongod.conf`
- Source: https://www.mongodb.com/docs/manual/tutorial/configure-ssl/

### Oplog or system.users accessible to application roles — CWE-732

- Why: An application role with `read` on `local` (oplog) or `admin.system.users` can harvest credentials and replicate all database changes.
- Grep: `grantRolesToUser.*readAnyDatabase|grantRolesToUser.*dbAdminAnyDatabase|roles.*readAnyDatabase`
- File globs: `**/*.js`, `**/*.ts`, `**/init.js`
- Source: https://www.mongodb.com/docs/manual/core/authorization/

## Secure patterns

```yaml
# /etc/mongod.conf — production baseline
net:
  bindIp: 127.0.0.1,10.0.1.5   # never 0.0.0.0 unless firewalled
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongod.pem
    CAFile: /etc/ssl/ca.pem

security:
  authorization: enabled

operationProfiling:
  slowOpThresholdMs: 100
```

Source: https://www.mongodb.com/docs/manual/administration/security-checklist/

```javascript
// Sanitize user input before query — check types, reject operator keys
function sanitizeFilter(input) {
  if (typeof input !== "string" && typeof input !== "number") {
    throw new Error("Invalid filter type");
  }
  return input;
}
const user = await db.collection("users").findOne({
  email: sanitizeFilter(req.body.email),
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Enable authentication and restrict bindIp — addresses CWE-306

**Before (dangerous):**

```yaml
# mongod.conf
net:
  bindIp: 0.0.0.0
# security block absent — no authorization
```

**After (safe):**

```yaml
net:
  bindIp: 127.0.0.1
security:
  authorization: enabled
```

Source: https://www.mongodb.com/docs/manual/administration/security-checklist/

### Recipe: Reject operator-shaped user input — addresses CWE-943

**Before (dangerous):**

```javascript
const user = await db.collection("users").findOne({ email: req.body.email });
```

**After (safe):**

```javascript
const email = req.body.email;
if (typeof email !== "string") return res.status(400).send("Bad request");
const user = await db.collection("users").findOne({ email });
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html

### Recipe: Require TLS — addresses CWE-319

**Before (dangerous):**

```yaml
net:
  tls:
    mode: allowTLS
```

**After (safe):**

```yaml
net:
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongod.pem
    CAFile: /etc/ssl/ca.pem
    disabledProtocols: "TLS1_0,TLS1_1"
```

Source: https://www.mongodb.com/docs/manual/tutorial/configure-ssl/

## Version notes

- MongoDB 6.0+: `$where` and server-side JavaScript (`db.eval`, `mapReduce` with `scope`) are disabled by default (`security.javascriptEnabled: false`); confirm this is not re-enabled.
- MongoDB 5.0+: `mongocryptd` and CSFLE (Client-Side Field Level Encryption) are available for encrypting sensitive fields at rest; consider for PII fields.
- MongoDB 4.4+: `net.ssl.*` config keys are deprecated in favor of `net.tls.*`; both still work but new configs should use `tls`.
- `db.eval()` was removed in MongoDB 4.4; its presence in older code is a finding.

## Common false positives

- `$where` in developer-only admin scripts never reachable via user input (e.g., one-off migration scripts) — low risk if access-controlled.
- `bindIp: 0.0.0.0` in a Docker environment where the port is not published to the host and only accessible within a private Docker network — verify `ports:` mapping.
- `authorization: disabled` in a local development-only `mongod.conf` with no production inheritance path.
