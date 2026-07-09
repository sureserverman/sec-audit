# Generic PHP Web Security (non-WordPress)

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html — OWASP PHP Configuration Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — OWASP Deserialization (PHP `unserialize`)
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — OWASP SQL Injection Prevention
- https://www.php.net/manual/en/security.php — PHP Security manual
- https://cwe.mitre.org/ — CWE index

## Scope

The framework-agnostic PHP security surface for the `php` lane's `["generic"]`
sub-shape (Laravel / Symfony / framework-less PHP). The phpcs WPCS security
sniffs still fire on the universal issues here (unescaped output, unsanitized
input, SQL concatenation) but with more false positives, so this pack gives the
sec-expert the non-WordPress pattern reference to reason about and quote fixes
from. Deep, framework-aware taint analysis (Laravel route handlers, Blade/Twig
SSTI, Eloquent mass-assignment) remains a coverage-gap fingerprint
(`uncovered-tech-fingerprints.md`) pending a Composer-autoload-rooted taint tool.

## Dangerous patterns (regex/AST hints)

### `unserialize()` on untrusted input — CWE-502 (object injection)

- Why: `unserialize($_GET['data'])` instantiates arbitrary PHP objects; combined
  with a "POP gadget" chain in the codebase it becomes RCE, file write, or SQLi.
  Use `json_decode`/`json_encode` for data interchange, or
  `unserialize($x, ['allowed_classes' => false])` when you must.
- Grep: `unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)` / `unserialize\s*\(\s*\$` fed from input
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Dynamic file inclusion — CWE-98 (LFI / RFI)

- Why: `include $_GET['page'] . '.php'` lets an attacker traverse the filesystem
  (`../../etc/passwd%00`) or, with `allow_url_include`, pull a remote payload.
  Never build an `include`/`require` path from input; use an allowlist map.
- Grep: `(include|include_once|require|require_once)\s*\(?\s*.*\$_(GET|POST|REQUEST)`
- Source: https://www.php.net/manual/en/security.filesystem.php

### SQL built by concatenation — CWE-89

- Why: `mysqli_query($c, "SELECT ... WHERE u = '" . $_GET['u'] . "'")` /
  `$pdo->query("... $var ...")` concatenates input into SQL. Use prepared
  statements: `$pdo->prepare('... WHERE u = ?')->execute([$u])`.
- Grep: `->(query|exec)\s*\(\s*["'][^"']*\.\s*\$` / `mysqli_query\([^,]+,\s*["'][^"']*\.\s*\$`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Command execution from input — CWE-78

- Why: `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, and backticks
  with interpolated input run a shell command an attacker controls.
- Grep: `(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*.*\$_(GET|POST|REQUEST)` / backtick strings with `$`
- Source: https://www.php.net/manual/en/function.escapeshellarg.php

### `preg_replace` with the `/e` modifier — CWE-95 (eval injection)

- Why: the `/e` modifier (removed in PHP 7, but still seen in legacy code)
  `eval`s the replacement — attacker-controlled subject or pattern is RCE. Use
  `preg_replace_callback`.
- Grep: `preg_replace\s*\(\s*["'][^"']*/[a-zA-Z]*e[a-zA-Z]*["']`
- Source: https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php

### Loose comparison of secrets / hashes — CWE-697

- Why: `==` / `!=` do type juggling — `"0e123" == "0e456"` is true (both parse as
  `0`), so a magic-hash password can bypass a `==` hash check. Use `hash_equals()`
  for MACs/tokens and `===` for identity.
- Grep: `==\s*\$?(hash|password|token|hmac|signature)` / `hash\s*\([^)]*\)\s*==`
- Source: https://www.php.net/manual/en/function.hash-equals.php

## Secure patterns

Prepared statements, JSON instead of `unserialize`, allowlisted includes:

```php
// Parameterised query (PDO).
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
$stmt->execute([$email]);

// Safe data interchange.
$data = json_decode($raw, true);            // not unserialize()

// Allowlisted page routing (no input in the path).
$pages = ['home' => 'home.php', 'about' => 'about.php'];
$file  = $pages[$_GET['page']] ?? 'home.php';
require __DIR__ . '/pages/' . $file;

// Constant-time token comparison.
if (hash_equals($expected, $provided)) { /* ok */ }
```

Source: https://www.php.net/manual/en/security.php

## Fix recipes

### Recipe: Replace concatenated SQL with a prepared statement — addresses CWE-89

**Before (dangerous):**

```php
$res = $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
```

**After (safe):**

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([(int) $_GET['id']]);
$res = $stmt->fetchAll();
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Recipe: Replace `unserialize` with `json_decode` — addresses CWE-502

**Before (dangerous):**

```php
$obj = unserialize($_COOKIE['prefs']);
```

**After (safe):**

```php
$obj = json_decode($_COOKIE['prefs'] ?? '{}', true);   // no object instantiation
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## Version notes

- PHP 7 removed the `preg_replace /e` modifier and `create_function`; PHP 8
  tightened type juggling but `==` string↔number coercion still bites — prefer
  `===` / `hash_equals`.
- `allow_url_include` / `allow_url_fopen` should be `Off` in production
  `php.ini` — an RFI (CWE-98) needs `allow_url_include=On` to fetch remote code.

## Common false positives

- A `system()`/`exec()` call with a fully literal argument (no interpolation) —
  a code smell but not injectable; treat as LOW.
- `unserialize($trusted)` where `$trusted` is an internal, non-request value with
  `['allowed_classes' => false]` — the safe form; do not flag.
- `$pdo->query()` on a static SQL literal — not injectable; the concatenation
  regex should not match, but confirm no hidden interpolation.
