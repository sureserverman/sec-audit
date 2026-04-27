# Python — Subprocess, Async, and OS-Boundary Patterns

## Source

- https://docs.python.org/3/library/subprocess.html — `subprocess` (canonical)
- https://docs.python.org/3/library/os.html — `os` module (canonical)
- https://docs.python.org/3/library/asyncio.html — asyncio
- https://docs.python.org/3/library/pathlib.html — `pathlib.Path`
- https://docs.python.org/3/library/tempfile.html — `tempfile`
- https://docs.python.org/3/library/secrets.html — `secrets` (cryptographic randomness)
- https://docs.python.org/3/library/random.html — `random` (note non-cryptographic)
- https://owasp.org/www-community/attacks/Command_Injection — OWASP Command Injection
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — OWASP cheatsheet
- https://cwe.mitre.org/

## Scope

Covers Python OS-boundary surface: `subprocess.Popen` / `run` / `call` with `shell=True`, `os.system` / `os.popen` (legacy shell-spawning APIs), `os.path.join` + open-on-attacker-path traversal, `tempfile.mktemp` (deprecated, race-prone), `shutil` archive extraction (Zip Slip class), `requests`/`httpx`/`urllib` SSRF and certificate verification, `random` for security-sensitive randomness, `asyncio.subprocess_shell`, `asyncio.create_task` exception swallowing, and `concurrent.futures` exception handling. Out of scope: serialization (covered in `python/deserialization.md`); framework-specific patterns (covered in `python/framework-deepening.md`).

## Dangerous patterns (regex/AST hints)

### `subprocess.run` / `Popen` / `call` with `shell=True` and interpolated string — CWE-78

- Why: `subprocess.run("ls " + user_input, shell=True)` invokes `/bin/sh -c "ls <input>"`, which performs full shell expansion of metacharacters in the input. The safe form is `subprocess.run(["ls", user_input], shell=False)` — no shell, no interpolation, argv passed directly. `shell=True` is occasionally legitimate for composing pipelines (`shell=True` with a hard-coded constant string), but any interpolation into the command string is structurally vulnerable. The Python docs explicitly recommend `shell=False` as the default.
- Grep: `subprocess\.(run|Popen|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True` AND the first positional arg is an interpolated/concatenated string (contains `f"`, `+`, `.format`, `%`, `str.join`).
- File globs: `**/*.py`
- Source: https://docs.python.org/3/library/subprocess.html#security-considerations

### `os.system` / `os.popen` with attacker input — CWE-78

- Why: `os.system(cmd)` and `os.popen(cmd)` always invoke `/bin/sh -c`; they are the legacy shell-spawning APIs. Any string interpolation into them is shell-injection. The fix is to migrate to `subprocess.run([...], shell=False)`. `os.system` returns the exit status only (no stdout capture); migrating callers requires switching to `subprocess.run(..., capture_output=True)`. Python 3.x has not deprecated these but they are universally discouraged in modern code.
- Grep: `os\.(system|popen)\s*\(`.
- File globs: `**/*.py`
- Source: https://docs.python.org/3/library/os.html#os.system

### `tempfile.mktemp` (deprecated, race-prone) — CWE-377

- Why: `tempfile.mktemp()` returns a candidate filename without creating the file — the caller then opens it, which is a TOCTOU race window where an attacker can pre-create the path as a symlink to a sensitive target. Python's docs explicitly deprecated `mktemp` (Python 2.x) and recommend `tempfile.mkstemp` (atomic file creation, returns `(fd, path)`) or `tempfile.NamedTemporaryFile` (returns a context-managed file object) instead. The race is small but real and has been exploited in published CVEs.
- Grep: `tempfile\.mktemp\s*\(`.
- File globs: `**/*.py`
- Source: https://docs.python.org/3/library/tempfile.html#tempfile.mktemp

### `shutil.unpack_archive` / `tarfile.extractall` / `zipfile.extractall` without path validation — CWE-22

- Why: Python's archive-extraction APIs honour absolute paths and `..` segments inside the archive (Zip Slip / Tar Slip), same class as the shell-script `tar`/`unzip` finding in `shell/file-handling.md`. Python 3.12 added `tarfile.data_filter` (PEP 706) which validates each entry's path and refuses traversal — but the default for Python 3.13 is still the legacy unfiltered behaviour; explicit `tarfile.extractall(path, filter='data')` is required. For zipfile, no built-in filter exists; pre-validate `zipfile.namelist()` against `os.path.commonpath` before `extractall`.
- Grep: `(tarfile|zipfile)\b[^)]*\.extractall\s*\(` OR `shutil\.unpack_archive\s*\(` without preceding path validation.
- File globs: `**/*.py`
- Source: https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter

### `requests` / `httpx` with `verify=False` — CWE-295

- Why: `requests.get(url, verify=False)` disables TLS certificate validation. The TLS handshake completes with any certificate — including self-signed test certificates and attacker MITM certificates. A common pattern for "quick fix to handle a corp self-signed CA" that leaks into production. The fix is to ship the corp CA bundle and pass `verify="/etc/ssl/corp-ca.crt"` (the path to a trusted CA bundle), OR install the corp CA into the system trust store so `requests` uses it transparently. `httpx` follows the same API.
- Grep: `(requests|httpx|session)\.(get|post|put|patch|delete|head|options|request)\s*\([^)]*verify\s*=\s*False` OR `requests\.Session\(\)[^.]*\.verify\s*=\s*False`.
- File globs: `**/*.py`
- Source: https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification

### SSRF via `requests.get(user_supplied_url)` without an allow-list — CWE-918

- Why: A web service that accepts a URL parameter and fetches it server-side (e.g. a webhook handler, a URL preview service, an OCR-of-an-image-by-URL feature) is structurally vulnerable to SSRF: an attacker passes `http://169.254.169.254/latest/meta-data/` (AWS instance metadata) or `http://127.0.0.1:6379/` (local Redis) and the service returns the fetched content. Mitigations: validate the URL hostname against an allow-list of expected domains; resolve the hostname to an IP and reject private/link-local/loopback ranges (RFC 1918 + IPv6 equivalents); use a separate egress proxy (e.g. `tcp_proxy`-style firewall) that only allows outbound connections to the expected destinations.
- Grep: `(requests|httpx|urllib(\.request)?)\.(get|post|urlopen)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,\)]` where the argument is a variable in a function that handles HTTP request data.
- File globs: `**/*.py`
- Source: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

### `random.random` / `random.choice` for security-sensitive randomness — CWE-338

- Why: `random` is a Mersenne Twister PRNG seeded from the system clock — predictable to anyone who can observe a few outputs. Token generation, password reset codes, session IDs, salts, nonces all need cryptographic randomness. Python's `secrets` module (Python 3.6+) provides `secrets.token_urlsafe(32)`, `secrets.choice(...)`, etc. — backed by `os.urandom` (CSPRNG). The fix is mechanical: replace `random.choice` with `secrets.choice` and `random.random` with `secrets.SystemRandom().random()` in security contexts.
- Grep: `\brandom\.(random|choice|randint|sample|shuffle|uniform|getrandbits)\s*\(` in code paths handling tokens, sessions, passwords, csrf, secrets, keys.
- File globs: `**/*.py`
- Source: https://docs.python.org/3/library/secrets.html

### `asyncio.create_task` without exception handling — CWE-755

- Why: `asyncio.create_task(coro())` schedules `coro` and returns a Task. If `coro` raises an exception and the Task's result is never awaited (or its `add_done_callback` not registered), the exception is logged at task-destruction time and silently swallowed. In a long-running service, this means errors disappear without alerting. The hardened pattern is to either (a) `await` the task explicitly, or (b) attach a `.add_done_callback(lambda t: log.exception(...) if t.exception() else None)`, or (c) use `asyncio.TaskGroup` (Python 3.11+) which propagates exceptions from any child to the group's `__aexit__`.
- Grep: `asyncio\.create_task\s*\(` not followed by `await` of the task or `add_done_callback` in the same scope.
- File globs: `**/*.py`
- Source: https://docs.python.org/3/library/asyncio-task.html

## Secure patterns

Safe subprocess invocation (no shell):

```python
import subprocess

result = subprocess.run(
    ["git", "clone", "--", repo_url, str(target_dir)],
    check=True,
    capture_output=True,
    text=True,
    timeout=60,
)
```

Source: https://docs.python.org/3/library/subprocess.html#security-considerations

Cryptographic random token:

```python
import secrets

session_token = secrets.token_urlsafe(32)        # ~256 bits of entropy
api_key       = secrets.token_hex(32)            # 64 hex chars = 256 bits
```

Source: https://docs.python.org/3/library/secrets.html

SSRF allow-list:

```python
from urllib.parse import urlparse
import socket
import ipaddress

ALLOW_HOSTS = {"api.partner.example.com", "cdn.example.com"}

def fetch_safe(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("scheme not allowed")
    if parsed.hostname not in ALLOW_HOSTS:
        raise ValueError("host not in allow-list")
    # Resolve and reject private ranges:
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("private IP not allowed")
    return requests.get(url, timeout=10).content
```

Source: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

Hardened tar extraction (Python 3.12+):

```python
import tarfile

with tarfile.open(archive_path) as tf:
    tf.extractall(dest_dir, filter="data")    # PEP 706 data filter rejects abs paths and ..
```

Source: https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter

## Fix recipes

### Recipe: replace `shell=True` with argv list — addresses CWE-78

**Before (dangerous):**

```python
subprocess.run(f"git clone {repo_url}", shell=True)
```

**After (safe):**

```python
subprocess.run(
    ["git", "clone", "--", repo_url],
    check=True,
    timeout=60,
)
```

Source: https://docs.python.org/3/library/subprocess.html#security-considerations

### Recipe: replace `random` with `secrets` for tokens — addresses CWE-338

**Before (dangerous):**

```python
import random
import string

token = "".join(random.choices(string.ascii_letters + string.digits, k=32))
```

**After (safe):**

```python
import secrets

token = secrets.token_urlsafe(32)
```

Source: https://docs.python.org/3/library/secrets.html

### Recipe: install corp CA, drop `verify=False` — addresses CWE-295

**Before (dangerous):**

```python
requests.get(api_url, verify=False)
```

**After (safe):**

```python
# Corp CA bundle shipped with the application or installed on the host:
requests.get(api_url, verify="/etc/ssl/certs/corp-ca-bundle.crt")
# Or, with the CA installed system-wide:
requests.get(api_url)   # picks up the system trust store
```

Source: https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification

### Recipe: `tempfile.mkstemp` with cleanup — addresses CWE-377

**Before (dangerous):**

```python
path = tempfile.mktemp(suffix=".log")
with open(path, "w") as f:        # TOCTOU window between mktemp and open
    f.write(data)
```

**After (safe):**

```python
import tempfile

with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
    f.write(data)
    path = f.name
# file is now closed but still exists; caller is responsible for cleanup
```

Source: https://docs.python.org/3/library/tempfile.html

## Version notes

- `tarfile.data_filter` (PEP 706) is the recommended path-validation filter; it became the default in Python 3.14 (still subject to runtime opt-in via `Python -X tarfile=data` on 3.12/3.13). For older Pythons, manually validate `tarfile.getnames()` before `extractall`.
- `secrets` module is Python 3.6+. For 3.5 and earlier, use `os.urandom(32)` directly.
- `asyncio.TaskGroup` is Python 3.11+. Earlier code must use `asyncio.gather(..., return_exceptions=True)` and handle exceptions per-task explicitly.
- `requests` and `httpx` both default to verifying certificates against the system trust store. `verify=False` is the only way to disable; there's no "lower" level of verification.

## Common false positives

- `subprocess.run(..., shell=True)` with a hard-coded constant string and no interpolation — flag as INFO; the `shell=True` invocation has no injection surface.
- `random.random` in non-security contexts (test data generation, simulations, ML data shuffling) — not a vulnerability; flag only in security-tagged contexts.
- `requests.get(verify=False)` in scripts that explicitly target a self-signed lab environment with a code comment justifying the bypass — annotate; downgrade to MEDIUM.
- `tempfile.mktemp` in a `for path in tempfile.mktemp() while os.path.exists(path)` loop where the caller is implementing their own `mkstemp` semantics — usually still wrong; flag and recommend the stdlib primitive.
- `asyncio.create_task` of a coroutine that intentionally fires-and-forgets (logging, metrics emission, fire-and-forget cache refresh) — annotate; flag only when the swallowed exception would mask user-impacting failures.
