# JSON Web Tokens (JWT)

## Source

- https://datatracker.ietf.org/doc/html/rfc7519 — RFC 7519: JSON Web Token (JWT)
- https://datatracker.ietf.org/doc/html/rfc8725 — RFC 8725: JSON Web Token Best Current Practices (JWT BCP)
- https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html — OWASP JWT Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A02:2021 Cryptographic Failures)

## Scope

Covers JSON Web Signature (JWS) and JSON Web Encryption (JWE) as defined in RFC 7519. Applies to JWT creation, parsing, and validation in any language. Does not cover OIDC ID token business-logic validation (see oidc.md) or OAuth 2.0 access token flows (see oauth2.md).

## Dangerous patterns (regex/AST hints)

### Algorithm set to "none" — CWE-347

- Why: `alg: none` instructs verifiers to accept unsigned tokens; any attacker can forge arbitrary claims.
- Grep: `alg.*none|algorithm.*none|verify.*false`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`, `**/*.rb`
- Source: https://datatracker.ietf.org/doc/html/rfc8725#section-2.1

### Algorithm confusion RS256 → HS256 — CWE-327

- Why: If a library accepts any algorithm and the public key is used as the HMAC secret, an attacker can sign tokens using the known public key.
- Grep: `decode\(|verify\(` (check that `algorithms` parameter is a strict allowlist, not omitted)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`
- Source: https://datatracker.ietf.org/doc/html/rfc8725#section-3.1

### Weak HMAC secret for HS256 — CWE-326

- Why: Short or guessable secrets enable offline brute-force of HMAC-signed tokens; HS256 requires >=256-bit secrets.
- Grep: `HS256|secret.*=.*['"][^'"]{0,31}['"]`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.env`, `**/*.yaml`
- Source: https://datatracker.ietf.org/doc/html/rfc8725#section-3.2

### kid header injection (SQL/path traversal) — CWE-20

- Why: The `kid` (key ID) header is used to look up signing keys; if used in a database query or file path without sanitization, it enables injection.
- Grep: `kid|key_id` (trace how the value is used to locate a key)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`
- Source: https://datatracker.ietf.org/doc/html/rfc8725#section-3.9

### Missing exp (expiration) claim — CWE-613

- Why: Tokens without `exp` are valid indefinitely; a stolen token cannot be invalidated short of rotating the signing key.
- Grep: `jwt\.sign\(|jwt\.encode\(` (check absence of `exp` or `expiresIn`)
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.go`, `**/*.java`
- Source: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4

## Secure patterns

Signing with explicit algorithm allowlist and required claims (Python/PyJWT):

```python
import jwt, secrets
from datetime import datetime, timedelta, timezone

SECRET = secrets.token_bytes(32)   # >= 256 bits for HS256

def issue_token(user_id: str) -> str:
    now = datetime.now(tz=timezone.utc)
    return jwt.encode(
        {
            'sub': user_id,
            'iat': now,
            'exp': now + timedelta(minutes=15),   # short-lived
            'jti': secrets.token_urlsafe(16),      # unique token ID
        },
        SECRET,
        algorithm='HS256',
    )

def verify_token(token: str) -> dict:
    return jwt.decode(
        token,
        SECRET,
        algorithms=['HS256'],           # strict allowlist — never omit
        options={'require': ['exp', 'iat', 'sub']},
    )
```

Source: https://datatracker.ietf.org/doc/html/rfc8725#section-3.1

RS256 verification with JWKS (asymmetric — public clients):

```python
from jwt import PyJWKClient
jwks_client = PyJWKClient(JWKS_URI)

def verify_rs256(token: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=['RS256'],           # never include 'HS256' in same allowlist
        audience=EXPECTED_AUDIENCE,
    )
```

Source: https://datatracker.ietf.org/doc/html/rfc8725#section-3.1

## Fix recipes

### Recipe: Disable alg=none — addresses CWE-347

**Before (dangerous):**

```js
// jsonwebtoken — omitting algorithms allows 'none'
const payload = jwt.verify(token, secret);
```

**After (safe):**

```js
const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
```

Source: https://datatracker.ietf.org/doc/html/rfc8725#section-2.1

### Recipe: Fix algorithm confusion by separating key types — addresses CWE-327

**Before (dangerous):**

```python
# Library accepts any algorithm; attacker can switch RS256 → HS256
claims = jwt.decode(token, public_key)
```

**After (safe):**

```python
# Explicit asymmetric algorithm only; HS256 not in list
claims = jwt.decode(token, public_key, algorithms=['RS256'])
```

Source: https://datatracker.ietf.org/doc/html/rfc8725#section-3.1

### Recipe: Add exp claim to token issuance — addresses CWE-613

**Before (dangerous):**

```js
const token = jwt.sign({ sub: userId }, SECRET);
```

**After (safe):**

```js
const token = jwt.sign({ sub: userId }, SECRET, { algorithm: 'HS256', expiresIn: '15m' });
```

Source: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4

### Recipe: Sanitize kid header before key lookup — addresses CWE-20

**Before (dangerous):**

```python
kid = header['kid']
key = db.query(f"SELECT key FROM keys WHERE id = '{kid}'")
```

**After (safe):**

```python
import re
kid = header.get('kid', '')
if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', kid):
    raise ValueError('Invalid kid')
key = db.query("SELECT key FROM keys WHERE id = %s", (kid,))
```

Source: https://datatracker.ietf.org/doc/html/rfc8725#section-3.9

## Version notes

- RFC 8725 (JWT BCP) was published in 2020 and supersedes informal guidance; treat it as the authoritative reference for JWT security.
- The `jku` (JWK Set URL) and `x5u` headers are dangerous if libraries follow them automatically; RFC 8725 Section 3.9 recommends ignoring or strictly allowlisting them.
- JWE (encrypted JWTs) is defined in RFC 7516; if using JWE, ensure the `alg` field refers to key encryption, not content encryption, and that the key wrapping algorithm is also allowlisted.

## Common false positives

- `algorithm: 'none'` in test helper utilities that construct unsigned tokens for unit tests — flag only in production code paths.
- Short-looking secrets in test fixtures / mock configs — flag only when the same value appears in production config or environment variable references.
- `decode` call without `verify` option in code paths that explicitly document they are handling pre-verified tokens (e.g. after a gateway already validates the signature) — reduce confidence but still flag for manual review.
