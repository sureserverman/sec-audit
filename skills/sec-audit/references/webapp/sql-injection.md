# SQL Injection

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — OWASP SQL Injection Prevention Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html — OWASP Query Parameterization Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A03:2021 Injection)
- https://cwe.mitre.org/data/definitions/89.html — CWE-89: Improper Neutralization of Special Elements in SQL Commands
- https://docs.djangoproject.com/en/stable/topics/db/sql/ — Django raw SQL documentation
- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text — SQLAlchemy text() documentation

## Scope

Covers SQL injection in server-side code across Python (Django ORM, Flask/SQLAlchemy, sqlite3), Node.js (mysql2, pg, Sequelize), Java (JDBC, JPA/Hibernate), Ruby on Rails (ActiveRecord), and Go (database/sql). Includes second-order injection (stored then later executed) and blind/time-based variants. Does not cover NoSQL injection (separate pack) or ORM-level mass-assignment issues.

## Dangerous patterns (regex/AST hints)

### String concatenation into SQL query — CWE-89

- Why: Interpolating user input directly into a query string allows an attacker to alter query structure.
- Grep: `(execute|query|raw|cursor\.execute)\s*\(\s*[f"'].*\+|%\s*\(`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.go`, `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Django ORM .raw() and .extra() with interpolation — CWE-89

- Why: `.raw()` and `.extra()` bypass the ORM's parameterization; interpolated arguments are injected directly into the SQL string.
- Grep: `\.raw\s*\(|\.extra\s*\(`
- File globs: `**/*.py`
- Source: https://docs.djangoproject.com/en/stable/topics/db/sql/

### SQLAlchemy text() without bound parameters — CWE-89

- Why: `text()` constructs literal SQL; without `:param` bind variables the string is passed raw to the driver.
- Grep: `text\s*\(\s*[f"'].*\{|text\s*\(\s*".*\+`
- File globs: `**/*.py`
- Source: https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text

### Node.js mysql2/pg query with string template literal — CWE-89

- Why: Template literals interpolate variables before the driver sees the query; placeholders (`?` or `$1`) are never used.
- Grep: `\.query\s*\(\s*\`[^`]*\$\{`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

### Java JDBC Statement.execute with concatenation — CWE-89

- Why: `Statement` (not `PreparedStatement`) executes a pre-assembled string; concatenation enables injection.
- Grep: `Statement\b(?!.*Prepared)|\.execute\s*\(\s*".*\+`
- File globs: `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

### Rails ActiveRecord string interpolation in where() — CWE-89

- Why: Passing a plain string with interpolation into `.where()` bypasses ActiveRecord's parameterization.
- Grep: `\.where\s*\(\s*"[^?]*#\{`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Go database/sql Exec/Query with Sprintf — CWE-89

- Why: `fmt.Sprintf` assembles the query before passing it to `db.Exec` or `db.Query`; no placeholder substitution occurs.
- Grep: `db\.(Exec|Query|QueryRow)\s*\(\s*fmt\.Sprintf`
- File globs: `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

### ORDER BY / column name injection — CWE-89

- Why: Column names and sort directions cannot be parameterized; user-supplied sort fields must be validated against an allowlist.
- Grep: `ORDER BY.*\+|order_by.*request\.|sort.*params\[`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.go`, `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Secure patterns

Parameterized queries (Python sqlite3 and psycopg2):

```python
# Always pass values as a second argument tuple — never interpolate
cursor.execute("SELECT * FROM users WHERE email = %s AND active = %s", (email, True))

# SQLAlchemy ORM — use bound parameters with text()
from sqlalchemy import text
result = db.execute(text("SELECT * FROM orders WHERE id = :order_id"), {"order_id": order_id})
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

Node.js pg placeholder syntax:

```js
// pg — $1 positional placeholders; mysql2 uses ?
const { rows } = await pool.query(
  'SELECT * FROM users WHERE email = $1 AND active = $2',
  [email, true]
);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

Java PreparedStatement:

```java
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM accounts WHERE username = ? AND password_hash = ?");
ps.setString(1, username);
ps.setString(2, passwordHash);
ResultSet rs = ps.executeQuery();
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

ORDER BY column allowlist (Go):

```go
var allowed = map[string]string{
    "name": "name", "created_at": "created_at",
}
col, ok := allowed[r.URL.Query().Get("sort")]
if !ok {
    col = "created_at"
}
rows, err := db.Query("SELECT * FROM items ORDER BY " + col)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Replace Python f-string query with parameterized query — addresses CWE-89

**Before (dangerous):**

```python
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
```

**After (safe):**

```python
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

### Recipe: Replace Node template-literal query with placeholder — addresses CWE-89

**Before (dangerous):**

```js
const result = await pool.query(`SELECT * FROM orders WHERE user_id = ${userId}`);
```

**After (safe):**

```js
const result = await pool.query('SELECT * FROM orders WHERE user_id = $1', [userId]);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

### Recipe: Replace JDBC Statement with PreparedStatement — addresses CWE-89

**Before (dangerous):**

```java
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
```

**After (safe):**

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
ResultSet rs = ps.executeQuery();
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

### Recipe: Fix Rails where() string interpolation — addresses CWE-89

**Before (dangerous):**

```ruby
User.where("name = '#{params[:name]}'")
```

**After (safe):**

```ruby
User.where("name = ?", params[:name])
# Or using hash conditions (preferred):
User.where(name: params[:name])
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Version notes

- Django ORM `.filter()`, `.get()`, `.exclude()` are parameterized and safe; `.raw()` and `.extra()` are sinks regardless of Django version.
- SQLAlchemy 2.0 deprecated implicit string coercion of `text()`; f-strings passed to `select()` raise a warning but still execute if driver accepts them — do not rely on this warning as a control.
- Rails ActiveRecord 6+ logs a deprecation for string-interpolated conditions; it does not prevent execution.
- Java Hibernate `createNativeQuery()` with string concatenation is a SQLi sink even when using JPA elsewhere in the codebase.
- Go's `database/sql` has no ORM layer; all query construction is manual — every dynamic query needs explicit `?` placeholders.

## Common false positives

- `cursor.execute("SELECT 1")` — static string literal with no variable interpolation; safe, but confirm no nearby dynamic assembly.
- `.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])` — Django `.raw()` with a parameter list (`params` argument) is parameterized; the Grep hint will match, but the second argument distinguishes safe from unsafe.
- `text("SELECT * FROM products ORDER BY created_at")` — SQLAlchemy `text()` with no interpolated variables is safe; flag only when the string contains `+` concatenation or f-string markers.
- Sequelize `sequelize.query(sql, { replacements: [...] })` — the `replacements` or `bind` option indicates parameterized execution; matches the query Grep pattern but is safe.
