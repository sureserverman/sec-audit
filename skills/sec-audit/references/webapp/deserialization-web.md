# Insecure Deserialization in Web Handlers

## Source

- https://cwe.mitre.org/data/definitions/502.html — CWE-502: Deserialization of Untrusted Data
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — OWASP Deserialization Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A08:2021 Software and Data Integrity Failures)
- https://portswigger.net/web-security/deserialization — PortSwigger: Insecure Deserialization
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html — OWASP Input Validation Cheat Sheet

## Scope

Covers insecure deserialization vulnerabilities triggered by HTTP request data (POST body, cookie, header, query string) being passed to language-native deserialization functions. Applies to Python (pickle, yaml.load), Java (ObjectInputStream), PHP (unserialize), Ruby (Marshal.load, YAML.load with unsafe_load alias), and Node.js (node-serialize). Does not cover XML external entity injection (XXE) or GraphQL query depth attacks — see separate packs.

## Dangerous patterns (regex/AST hints)

### Python: pickle.loads on HTTP request data — CWE-502

- Why: Python's `pickle` format can encode arbitrary callables; deserializing attacker-controlled pickle data executes arbitrary code on the server with the process's privileges.
- Grep: `pickle\.(loads|load|Unpickler)\s*\(`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Python: yaml.load (unsafe) on request data — CWE-502

- Why: PyYAML's `yaml.load` with the default or `Loader=yaml.Loader` processes `!!python/object` tags and can instantiate arbitrary Python objects. Use `yaml.safe_load` instead.
- Grep: `yaml\.load\s*\([^)]+\)` (check for absence of `Loader=yaml.SafeLoader` or `Loader=yaml.CSafeLoader`)
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Python: yaml.load with explicit unsafe Loader — CWE-502

- Why: `yaml.load(data, Loader=yaml.Loader)` or `Loader=yaml.UnsafeLoader` explicitly opts into dangerous deserialization even in PyYAML >= 5.1 where the no-Loader call was deprecated.
- Grep: `yaml\.load\s*\([^,]+,\s*Loader\s*=\s*yaml\.(Loader|UnsafeLoader|FullLoader)`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Java: ObjectInputStream.readObject on HTTP-sourced stream — CWE-502

- Why: Java's native deserialization executes custom `readObject` methods during deserialization; gadget chains (Apache Commons Collections, Spring, etc.) allow RCE from a crafted byte stream.
- Grep: `new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)`
- File globs: `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### PHP: unserialize on cookie or request parameter — CWE-502

- Why: PHP's `unserialize` invokes `__wakeup` and `__destruct` magic methods during deserialization; attacker-controlled serialized strings can abuse existing classes as gadgets for arbitrary code execution or file deletion.
- Grep: `unserialize\s*\(\s*\$_(COOKIE|GET|POST|REQUEST)`
- File globs: `**/*.php`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Ruby: Marshal.load on request data — CWE-502

- Why: Ruby's `Marshal.load` can instantiate arbitrary Ruby objects and trigger `initialize` or finalizer methods; it is equivalent in risk to Java ObjectInputStream and must never be used on untrusted input.
- Grep: `Marshal\.(load|restore)\s*\(`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Ruby: YAML.load (unsafe_load alias) on request data — CWE-502

- Why: In Ruby's Psych library, `YAML.load` was an alias for `unsafe_load` prior to Psych 4.0 / Ruby 3.1; it can deserialize arbitrary Ruby objects via `!ruby/object` tags. `YAML.safe_load` is always safe.
- Grep: `YAML\.load\s*\(|Psych\.load\s*\(|YAML\.unsafe_load\s*\(`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Node.js: node-serialize deserializing request data — CWE-502

- Why: The `node-serialize` npm package evaluates IIFE (immediately invoked function expressions) embedded in JSON strings during deserialization, enabling arbitrary JavaScript execution.
- Grep: `require\s*\(\s*['"]node-serialize['"]\s*\)|serialize\.unserialize\s*\(`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://portswigger.net/web-security/deserialization

## Secure patterns

Python — replace pickle/yaml.load with safe alternatives:

```python
import json
import yaml

# For structured data from HTTP: use JSON
data = json.loads(request.body)

# For YAML config files only (never user-supplied): use safe_load
config = yaml.safe_load(open('config.yaml'))
# Never: yaml.load(user_input) or yaml.load(user_input, Loader=yaml.Loader)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

Java — use a serialization filter to restrict deserializable classes (Java 9+):

```java
// Set a global deserialization filter; allow only known-safe classes
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.example.model.*;!*"  // allow only com.example.model, reject everything else
);
ObjectInputFilter.Config.setSerialFilter(filter);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

PHP — use JSON instead of serialize/unserialize for data exchange:

```php
// Safe: JSON encode/decode for cookies and session data
$data = json_encode(['user_id' => $userId, 'role' => $role]);
setcookie('session_data', base64_encode($data), [...]);

// On read:
$data = json_decode(base64_decode($_COOKIE['session_data']), true);
// Never: unserialize($_COOKIE['session_data'])
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

Ruby — use JSON or YAML.safe_load for all HTTP-origin data:

```ruby
require 'json'
require 'yaml'

# For HTTP request data: JSON only
data = JSON.parse(request.body.read)

# For config files: safe_load with permitted_classes strictly limited
config = YAML.safe_load(File.read('config.yml'), permitted_classes: [Symbol])
# Never: YAML.load(params[:data]) or Marshal.load(Base64.decode64(cookie))
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## Fix recipes

### Recipe: Python — replace pickle.loads with JSON — addresses CWE-502

**Before (dangerous):**

```python
import pickle, base64

@app.route('/load', methods=['POST'])
def load_session():
    data = base64.b64decode(request.json['session'])
    obj = pickle.loads(data)   # RCE if data is attacker-controlled
    return jsonify(obj)
```

**After (safe):**

```python
import json

@app.route('/load', methods=['POST'])
def load_session():
    # Store session as signed JSON (e.g. Flask session cookie or JWT)
    # Never deserialize raw pickle from client-supplied data
    obj = json.loads(request.json['session'])
    return jsonify(obj)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Recipe: Python — replace yaml.load with yaml.safe_load — addresses CWE-502

**Before (dangerous):**

```python
config = yaml.load(request.data)
# or:
config = yaml.load(request.data, Loader=yaml.Loader)
```

**After (safe):**

```python
config = yaml.safe_load(request.data)
# safe_load uses SafeLoader which does not support !!python/object tags
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Recipe: Java — add deserialization filter to ObjectInputStream — addresses CWE-502

**Before (dangerous):**

```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();
```

**After (safe):**

```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
ois.setObjectInputFilter(info -> {
    Class<?> cls = info.serialClass();
    if (cls != null && cls.getName().startsWith("com.example.model.")) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    return ObjectInputFilter.Status.REJECTED;
});
Object obj = ois.readObject();
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

### Recipe: PHP — replace unserialize with json_decode on cookie — addresses CWE-502

**Before (dangerous):**

```php
$prefs = unserialize(base64_decode($_COOKIE['user_prefs']));
```

**After (safe):**

```php
// Store a HMAC-signed JSON string instead of a serialized PHP object
$raw = $_COOKIE['user_prefs'] ?? '';
[$payload, $sig] = explode('.', $raw, 2) + ['', ''];
$expected = hash_hmac('sha256', $payload, APP_SECRET);
if (!hash_equals($expected, $sig)) {
    $prefs = [];
} else {
    $prefs = json_decode(base64_decode($payload), true) ?? [];
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## Version notes

- PyYAML >= 5.1 (2019) emits a warning when `yaml.load` is called without an explicit `Loader`; PyYAML >= 6.0 raises an error. However, `yaml.load(data, Loader=yaml.Loader)` is still unsafe in all PyYAML versions.
- Ruby Psych 4.0 (shipped with Ruby 3.1, 2021) changed `YAML.load` to call `safe_load` by default. Projects on Ruby < 3.1 or pinned to Psych < 4.0 still have the unsafe behavior from `YAML.load`.
- Java deserialization filters (`ObjectInputFilter`) were introduced in Java 9 and backported to Java 8u121. The global serial filter (`-Djdk.serialFilter`) is preferred for defense-in-depth.
- PHP `unserialize` has an `allowed_classes` option since PHP 7.0: `unserialize($data, ['allowed_classes' => false])` returns an `__PHP_Incomplete_Class` instead of instantiating real objects; use this as a migration step, not a permanent fix.
- `node-serialize` has no maintained patched version; replace it entirely. The `flatted` or `devalue` packages handle circular references without eval.

## Common false positives

- `pickle.load` reading from a file on disk that is written only by trusted application code (not from user input) — not a web-handler vulnerability; flag as a separate finding category if the file path itself is user-controlled.
- `yaml.safe_load` — explicitly safe; `safe_load` uses the `SafeLoader` which disallows Python-object tags. Only flag `yaml.load` variants.
- `Marshal.load` inside a Rails cache store reading from a Redis cache populated only by the application itself — lower severity if the cache backend is not directly accessible by untrusted parties; flag as medium with infrastructure caveat.
- Java `ObjectInputStream` reading from a local file or internal pipe written by trusted code — reduced attack surface; note in the finding and confirm the data source before assigning high severity.
