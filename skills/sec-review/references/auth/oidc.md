# OpenID Connect (OIDC)

## Source

- https://openid.net/specs/openid-connect-core-1_0.html — OpenID Connect Core 1.0
- https://openid.net/specs/openid-connect-discovery-1_0.html — OpenID Connect Discovery 1.0
- https://datatracker.ietf.org/doc/html/rfc8252 — RFC 8252: OAuth 2.0 for Native Apps (PKCE)
- https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html — OWASP JWT Cheat Sheet

## Scope

Covers OpenID Connect Core 1.0 as an identity layer on top of OAuth 2.0. Applies to ID token validation, nonce binding, hybrid flow security, token endpoint authentication, and discovery document usage. Does not cover OAuth 2.0 access token mechanics (see oauth2.md) or JWT cryptographic details (see jwt.md).

## Dangerous patterns (regex/AST hints)

### ID token validation skipped — CWE-287

- Why: Accepting an ID token without validating `iss`, `aud`, `exp`, `iat`, and signature allows token substitution attacks.
- Grep: `id_token` (check whether validation of iss/aud/exp follows)
- File globs: `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`
- Source: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

### Missing nonce validation — CWE-294

- Why: Without nonce binding, a replayed ID token from a previous session can be accepted as fresh authentication.
- Grep: `nonce` (check that nonce in token is compared to session-stored nonce)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`
- Source: https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes

### Hybrid flow with token returned from authorization endpoint — CWE-522

- Why: `response_type=code token` or `code id_token` returns tokens in the URL fragment, exposing them to the browser.
- Grep: `response_type.*code.*token|response_type.*id_token`
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`
- Source: https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth

### Discovery document fetched over HTTP or without TLS verification — CWE-295

- Why: An attacker who can MITM the discovery endpoint can substitute malicious keys and endpoints.
- Grep: `well-known/openid-configuration|openid_configuration` (check for http:// scheme or TLS verification disabled)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`
- Source: https://openid.net/specs/openid-connect-discovery-1_0.html

### aud claim not validated against client_id — CWE-287

- Why: A token issued to a different client must be rejected; failure allows confused deputy attacks.
- Grep: `aud|audience` (check for strict equality to own client_id)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`
- Source: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

## Secure patterns

Complete ID token validation (Authorization Code flow):

```python
import jwt  # PyJWT >= 2.x
from jwt import PyJWKClient

jwks_client = PyJWKClient(JWKS_URI)  # fetched from discovery doc over HTTPS

def validate_id_token(id_token: str, expected_nonce: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=['RS256', 'ES256'],    # only expected algorithms
        audience=CLIENT_ID,               # must match client_id exactly
        issuer=ISSUER,                    # must match provider's iss
        options={'require': ['exp', 'iat', 'sub', 'aud', 'iss', 'nonce']},
    )
    if claims['nonce'] != expected_nonce:
        raise ValueError('Nonce mismatch')
    return claims
```

Source: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

Nonce generation and binding:

```python
import secrets

# Before redirect to provider:
nonce = secrets.token_urlsafe(32)
session['oidc_nonce'] = nonce

# Include in authorization request:
params['nonce'] = nonce

# After callback — validate before trusting claims:
stored_nonce = session.pop('oidc_nonce', None)
validate_id_token(id_token, expected_nonce=stored_nonce)
```

Source: https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes

at_hash validation (when access token is returned alongside ID token):

```python
import hashlib, base64

def verify_at_hash(access_token: str, at_hash_claim: str, alg: str) -> bool:
    hash_fn = {'RS256': hashlib.sha256, 'ES256': hashlib.sha256}[alg]
    digest = hash_fn(access_token.encode()).digest()
    expected = base64.urlsafe_b64encode(digest[:len(digest)//2]).rstrip(b'=').decode()
    return expected == at_hash_claim
```

Source: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken

## Fix recipes

### Recipe: Add full ID token validation — addresses CWE-287

**Before (dangerous):**

```python
# Token decoded without verification
import base64, json
payload = json.loads(base64.urlsafe_b64decode(id_token.split('.')[1] + '=='))
user_id = payload['sub']
```

**After (safe):**

```python
# Full cryptographic validation using JWKS
claims = validate_id_token(id_token, expected_nonce=session.pop('oidc_nonce'))
user_id = claims['sub']
```

Source: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

### Recipe: Replace hybrid flow with Authorization Code + PKCE — addresses CWE-522

**Before (dangerous):**

```js
// Hybrid flow — id_token returned in URL fragment
const authUrl = buildUrl(AUTH_ENDPOINT, { response_type: 'code id_token', nonce });
```

**After (safe):**

```js
// Pure Authorization Code + PKCE — tokens never in URL
const authUrl = buildUrl(AUTH_ENDPOINT, {
  response_type: 'code',
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
  nonce: nonce,
  state: state,
});
```

Source: https://datatracker.ietf.org/doc/html/rfc8252

### Recipe: Validate aud claim — addresses CWE-287

**Before (dangerous):**

```python
claims = jwt.decode(id_token, key, algorithms=['RS256'])
# aud not checked
```

**After (safe):**

```python
claims = jwt.decode(id_token, key, algorithms=['RS256'], audience=CLIENT_ID)
```

Source: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

## Version notes

- OpenID Connect Core 1.0 is a stable specification; no major revisions since 2014. Implementors should track errata at openid.net.
- `at_hash` and `c_hash` are required only in hybrid flow responses; they are optional in pure Authorization Code flow.
- PKCE is not defined in OIDC Core 1.0 itself but is required for public clients per RFC 8252 and OAuth 2.1 draft.

## Common false positives

- `id_token` string in comments or log messages — not a validation bypass.
- `aud` check that compares a list (when `aud` is a JSON array) — valid per spec; ensure own `client_id` appears in the list.
- Discovery document fetched at startup and cached — acceptable; flag if cache is never refreshed or JWKS is not re-fetched on `kid` mismatch.
