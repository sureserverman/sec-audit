# Password Storage

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — OWASP Password Storage Cheat Sheet
- https://pages.nist.gov/800-63-3/sp800-63b.html — NIST SP 800-63B Digital Identity Guidelines
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A02:2021 Cryptographic Failures)
- https://csrc.nist.gov/publications/detail/sp/800-132/final — NIST SP 800-132: Recommendation for Password-Based Key Derivation

## Scope

Covers password hashing algorithm selection, work factors, and pepper usage for storing user passwords server-side. Applies to any application that persists user credentials. Does not cover password policy enforcement at input (see NIST SP 800-63B for policy guidance) or transmission security (see tls-bcp.md).

## Dangerous patterns (regex/AST hints)

### MD5 used for password hashing — CWE-328

- Why: MD5 is cryptographically broken and extremely fast; GPU clusters crack MD5-hashed password databases in minutes.
- Grep: `md5.*password|password.*md5|hashlib\.md5|MD5\.digest`
- File globs: `**/*.py`, `**/*.rb`, `**/*.php`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### SHA-1 or unsalted SHA-256/SHA-512 — CWE-916

- Why: SHA-1 is broken; raw SHA-256/SHA-512 without a slow KDF is fast to brute-force even with per-password salts.
- Grep: `sha1.*password|hashlib\.sha1|hashlib\.sha256\(.*password|sha512.*password`
- File globs: `**/*.py`, `**/*.rb`, `**/*.php`, `**/*.go`, `**/*.java`, `**/*.js`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### bcrypt cost factor too low — CWE-916

- Why: bcrypt cost below 12 is too fast on modern hardware; OWASP recommends >=12 (minimum 10 for legacy).
- Grep: `bcrypt.*rounds\s*=\s*[0-9]|bcrypt.*cost\s*=\s*[0-9]|gensalt\([0-9]\b`
- File globs: `**/*.py`, `**/*.rb`, `**/*.php`, `**/*.js`, `**/*.ts`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### Argon2 with insufficient parameters — CWE-916

- Why: Argon2id with memory < 64 MiB or iterations < 3 is weaker than OWASP minimums.
- Grep: `argon2.*memory_cost|argon2.*time_cost|Argon2id`
- File globs: `**/*.py`, `**/*.rb`, `**/*.go`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### Password stored in plaintext — CWE-312

- Why: Any direct storage of user passwords — even base64 encoded — allows mass credential theft on database compromise.
- Grep: `user\.password\s*=\s*password|password.*=.*request\.(POST|body|form)`
- File globs: `**/*.py`, `**/*.rb`, `**/*.php`, `**/*.go`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## Secure patterns

Argon2id (recommended — OWASP first choice):

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=3,          # iterations — OWASP minimum: 3
    memory_cost=65536,    # 64 MiB — OWASP minimum: 64 MiB
    parallelism=4,        # threads
    hash_len=32,
    salt_len=16,
)

def hash_password(plaintext: str) -> str:
    return ph.hash(plaintext)

def verify_password(hashed: str, plaintext: str) -> bool:
    try:
        ph.verify(hashed, plaintext)
        if ph.check_needs_rehash(hashed):
            return True, hash_password(plaintext)  # rehash with updated params
        return True
    except VerifyMismatchError:
        return False
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

bcrypt (acceptable — OWASP second choice):

```python
import bcrypt

BCRYPT_ROUNDS = 12   # OWASP minimum: 10; recommended: 12

def hash_password(plaintext: str) -> bytes:
    return bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

def verify_password(hashed: bytes, plaintext: str) -> bool:
    return bcrypt.checkpw(plaintext.encode('utf-8'), hashed)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

Pepper pattern (optional additional layer before hashing):

```python
import hmac, hashlib, os

PEPPER = os.environ['PASSWORD_PEPPER'].encode()  # stored outside DB

def peppered_hash(plaintext: str) -> str:
    peppered = hmac.new(PEPPER, plaintext.encode(), hashlib.sha256).hexdigest()
    return ph.hash(peppered)   # then Argon2id as above
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## Fix recipes

### Recipe: Replace MD5 with Argon2id — addresses CWE-328, CWE-916

**Before (dangerous):**

```python
import hashlib
stored = hashlib.md5(password.encode()).hexdigest()
```

**After (safe):**

```python
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
stored = ph.hash(password)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### Recipe: Increase bcrypt cost factor — addresses CWE-916

**Before (dangerous):**

```python
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=6))
```

**After (safe):**

```python
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### Recipe: Replace raw SHA-256 with Argon2id — addresses CWE-916

**Before (dangerous):**

```python
import hashlib
stored = hashlib.sha256(salt + password.encode()).hexdigest()
```

**After (safe):**

```python
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
stored = ph.hash(password)  # salt is generated and embedded by Argon2
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## Version notes

- NIST SP 800-63B Section 5.1.1 removes composition rules (no mandatory uppercase/digit/symbol requirements) and minimum complexity rules; instead mandate checking passwords against known-breached lists (e.g. HIBP API).
- NIST SP 800-63B Section 5.1.1 sets a minimum password length of 8 characters and recommends allowing up to 64 characters.
- OWASP Password Storage Cheat Sheet (2024 revision) sets Argon2id as the preferred algorithm; bcrypt second; scrypt third with m=2^17, r=8, p=1 minimums.
- bcrypt has a 72-byte input limit; passwords longer than 72 bytes are silently truncated. Pre-hash with SHA-256 (in hex) then bcrypt if long passwords are expected — but prefer Argon2id which has no such limit.

## Common false positives

- `hashlib.md5` or `hashlib.sha1` used for non-credential hashing (e.g. ETag generation, cache keys, file integrity checks) — not a password storage issue; confirm the value being hashed is not a credential.
- `bcrypt.gensalt(rounds=10)` — acceptable as a lower bound but flag with note to increase to 12; not critical.
- SHA-256 used for HMAC-based password verification tokens (e.g. password reset tokens) — not a password storage issue; these are short-lived tokens, not stored credentials.
