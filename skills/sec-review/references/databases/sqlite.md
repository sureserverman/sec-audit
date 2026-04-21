# SQLite

## Source

- https://www.sqlite.org/security.html
- https://www.sqlite.org/loadext.html
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers SQLite 3.x as an embedded database accessed via Python (sqlite3 /
SQLAlchemy), Node.js (better-sqlite3, node-sqlite3), and direct C/C++ usage.
Covers file permission risks in multi-user deployments and WAL mode exposure.
Does not cover SQLite as an in-process library compiled into mobile apps
(separate review context).

## Dangerous patterns (regex/AST hints)

### SQL string interpolation / concatenation — CWE-89

- Why: Building SQL strings with f-strings, `%` formatting, or `+` concatenation from user input bypasses SQLite's parameterization and allows SQL injection.
- Grep: `execute\s*\(\s*f["\']|execute\s*\(.*%\s*\(|execute\s*\(.*\+\s*(req|user|param|input|request)`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### ATTACH DATABASE with user-controlled path — CWE-22

- Why: `ATTACH DATABASE ?` with a user-supplied path allows reading or creating arbitrary database files anywhere the process has filesystem access, including sensitive system files.
- Grep: `ATTACH\s+DATABASE\s+["\']?\s*\+|ATTACH\s+DATABASE.*req\.|ATTACH\s+DATABASE.*params\[`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.c`
- Source: https://www.sqlite.org/security.html

### load_extension enabled in application context — CWE-114

- Why: `sqlite3_enable_load_extension()` or `conn.enable_load_extension(True)` allows loading arbitrary shared libraries into the SQLite process, enabling native code execution.
- Grep: `enable_load_extension\s*\(\s*True|sqlite3_enable_load_extension|load_extension\s*\(`
- File globs: `**/*.py`, `**/*.c`, `**/*.cpp`
- Source: https://www.sqlite.org/loadext.html

### World-readable .db or .sqlite file permissions — CWE-732

- Why: A database file with permissions `644` or `666` in a shared environment allows any local user to read or write all application data.
- Grep: `chmod.*644.*\.db|chmod.*666.*\.db|os\.chmod.*0o644.*db`
- File globs: `**/*.sh`, `**/*.py`, `**/Makefile`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html

### WAL file exposed alongside database — CWE-200

- Why: SQLite WAL mode creates a `-wal` and `-shm` sidecar file that contains recent uncommitted transactions; if the directory is web-accessible or world-readable, these files leak data.
- Grep: `journal_mode\s*=\s*WAL|PRAGMA\s+journal_mode\s*=\s*WAL`
- File globs: `**/*.py`, `**/*.js`
- Source: https://www.sqlite.org/security.html

## Secure patterns

```python
import sqlite3

conn = sqlite3.connect("app.db")
# Always use parameterized queries — never interpolate
cursor = conn.execute("SELECT * FROM users WHERE email = ?", (user_email,))

# Do NOT enable load_extension in application code
# conn.enable_load_extension(True)  <-- never do this
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

```python
import os, stat

db_path = "/var/lib/myapp/app.db"
# Set file to owner read/write only
os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

# Ensure directory is also restricted
os.chmod(os.path.dirname(db_path), stat.S_IRWXU)  # 0o700
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html

```javascript
// Node.js better-sqlite3 — parameterized statement
const stmt = db.prepare("SELECT * FROM items WHERE id = ?");
const row = stmt.get(req.params.id);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Parameterize SQLite queries — addresses CWE-89

**Before (dangerous):**

```python
cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
```

**After (safe):**

```python
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Recipe: Restrict ATTACH DATABASE to static paths — addresses CWE-22

**Before (dangerous):**

```python
conn.execute(f"ATTACH DATABASE '{user_path}' AS ext")
```

**After (safe):**

```python
import os

ALLOWED_DB_DIR = "/var/lib/myapp/attachments"
safe_name = os.path.basename(db_name)  # strip directory components
target = os.path.join(ALLOWED_DB_DIR, safe_name)
if not target.startswith(ALLOWED_DB_DIR + os.sep):
    raise ValueError("Invalid database path")
conn.execute("ATTACH DATABASE ? AS ext", (target,))
```

Source: https://www.sqlite.org/security.html

### Recipe: Disable load_extension — addresses CWE-114

**Before (dangerous):**

```python
conn.enable_load_extension(True)
conn.load_extension(user_provided_extension)
```

**After (safe):**

```python
# Simply do not call enable_load_extension.
# If loading a specific trusted extension is required:
conn.enable_load_extension(True)
conn.load_extension("/opt/myapp/extensions/trusted.so")
conn.enable_load_extension(False)  # re-disable immediately after
```

Source: https://www.sqlite.org/loadext.html

## Version notes

- Python `sqlite3` module: `check_same_thread=False` is required for multi-threaded access but does not introduce injection risk; it is a threading hint, not a security bypass.
- SQLite 3.38.0+: JSON functions are built-in; parameterize JSON path arguments the same as SQL column arguments.
- WAL mode files (`.db-wal`, `.db-shm`) are created alongside the main database file; ensure web server `.htaccess` or Nginx config denies access to these extensions if the db directory is within the web root.
- SQLite does not enforce user-level access control; application-layer enforcement and OS file permissions are the sole access controls.

## Common false positives

- `enable_load_extension(True)` immediately followed by a static trusted extension path and then `enable_load_extension(False)` — acceptable pattern; verify the extension path is not user-controlled.
- `PRAGMA journal_mode = WAL` by itself — not dangerous unless the WAL file is accessible to unauthorized parties; check file permissions and directory exposure separately.
- `f"SELECT ... WHERE id = {int(user_id)}"` — explicit `int()` coercion prevents string injection; still prefer `?` parameterization for consistency.
