# OAuth 2.0 / 2.1

## Source

- https://datatracker.ietf.org/doc/html/rfc6749 — RFC 6749: The OAuth 2.0 Authorization Framework
- https://datatracker.ietf.org/doc/html/rfc6750 — RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage
- https://datatracker.ietf.org/doc/html/rfc8252 — RFC 8252: OAuth 2.0 for Native Apps
- https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1 — OAuth 2.1 draft (consolidates security BCP)
- https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html — OWASP OAuth 2.0 Cheat Sheet

## Scope

Covers OAuth 2.0 authorization flows used in web, mobile, and native applications: Authorization Code, PKCE, Client Credentials, and Device Authorization. Covers token endpoint security and bearer token usage. Does not cover OpenID Connect ID token validation (see oidc.md) or JWT internals (see jwt.md).

## Dangerous patterns (regex/AST hints)

### Implicit flow in use — CWE-522

- Why: The implicit flow returns access tokens in the URL fragment, exposing them to browser history, referrer headers, and malicious scripts. Deprecated in OAuth 2.1.
- Grep: `response_type=token|grant_type.*implicit`
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.rb`, `**/*.go`, `**/*.java`
- Source: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1

### Missing PKCE for public clients — CWE-287

- Why: Without PKCE, an authorization code intercepted by a malicious app can be exchanged for tokens.
- Grep: `response_type=code` (check absence of `code_challenge` in the same request construction)
- File globs: `**/*.js`, `**/*.ts`, `**/*.swift`, `**/*.kt`, `**/*.dart`
- Source: https://datatracker.ietf.org/doc/html/rfc8252

### Missing or non-validated state parameter — CWE-352

- Why: The `state` parameter prevents CSRF against the authorization callback; if absent or not validated, an attacker can inject a stolen code.
- Grep: `redirect.*code|callback.*code` (check absence of state validation)
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.rb`
- Source: https://datatracker.ietf.org/doc/html/rfc6749#section-10.12

### Redirect URI not exact-matched — CWE-601

- Why: Prefix or wildcard matching of `redirect_uri` enables open redirect and authorization code theft.
- Grep: `redirect_uri.*startswith|redirect_uri.*contains|redirect_uri.*match`
- File globs: `**/*.py`, `**/*.rb`, `**/*.go`, `**/*.java`, `**/*.js`
- Source: https://datatracker.ietf.org/doc/html/rfc6749#section-10.6

### Bearer token in URL query string — CWE-598

- Why: Tokens in URLs appear in server logs, browser history, and Referer headers. RFC 6750 requires Authorization header delivery.
- Grep: `access_token=|bearer.*\?|token=.*&`
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.rb`, `**/*.go`
- Source: https://datatracker.ietf.org/doc/html/rfc6750#section-5.3

### Refresh token not rotated — CWE-613

- Why: A static refresh token, if stolen, grants indefinite access. Sender-constrained or rotated tokens limit the window.
- Grep: `refresh_token` (check whether new refresh token is issued on each use)
- File globs: `**/*.py`, `**/*.rb`, `**/*.go`, `**/*.java`, `**/*.js`
- Source: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1

## Secure patterns

Authorization Code flow with PKCE (public client):

```python
import secrets, hashlib, base64

# 1. Generate code verifier and challenge
code_verifier = secrets.token_urlsafe(64)
digest = hashlib.sha256(code_verifier.encode()).digest()
code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

# 2. Authorization request
params = {
    'response_type': 'code',
    'client_id': CLIENT_ID,
    'redirect_uri': REDIRECT_URI,          # exact pre-registered URI
    'scope': 'openid profile',
    'state': secrets.token_urlsafe(32),    # store in session for validation
    'code_challenge': code_challenge,
    'code_challenge_method': 'S256',
}

# 3. Token exchange — send code_verifier, validate state before calling
token_response = requests.post(TOKEN_ENDPOINT, data={
    'grant_type': 'authorization_code',
    'code': received_code,
    'redirect_uri': REDIRECT_URI,
    'code_verifier': code_verifier,
    'client_id': CLIENT_ID,
})
```

Source: https://datatracker.ietf.org/doc/html/rfc8252

Bearer token usage via Authorization header only:

```http
GET /api/resource HTTP/1.1
Authorization: Bearer <access_token>
```

Source: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1

## Fix recipes

### Recipe: Replace implicit flow with Authorization Code + PKCE — addresses CWE-522

**Before (dangerous):**

```js
// Implicit flow — token returned in URL fragment
const authUrl = `${AUTH_ENDPOINT}?response_type=token&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}`;
```

**After (safe):**

```js
// Authorization Code + PKCE
const codeVerifier = generateSecureRandom(64);
const codeChallenge = await sha256Base64url(codeVerifier);
const state = generateSecureRandom(32);
sessionStorage.setItem('pkce_verifier', codeVerifier);
sessionStorage.setItem('oauth_state', state);

const authUrl = `${AUTH_ENDPOINT}?response_type=code&client_id=${CLIENT_ID}`
  + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
  + `&code_challenge=${codeChallenge}&code_challenge_method=S256`
  + `&state=${state}`;
```

Source: https://datatracker.ietf.org/doc/html/rfc8252

### Recipe: Add state parameter validation — addresses CWE-352

**Before (dangerous):**

```python
def callback(request):
    code = request.GET['code']
    exchange_code(code)
```

**After (safe):**

```python
def callback(request):
    if request.GET.get('state') != request.session.pop('oauth_state', None):
        raise SuspiciousOperation('Invalid OAuth state')
    code = request.GET['code']
    exchange_code(code)
```

Source: https://datatracker.ietf.org/doc/html/rfc6749#section-10.12

### Recipe: Move bearer token from query string to header — addresses CWE-598

**Before (dangerous):**

```http
GET /api/data?access_token=eyJ... HTTP/1.1
```

**After (safe):**

```http
GET /api/data HTTP/1.1
Authorization: Bearer eyJ...
```

Source: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1

## Version notes

- OAuth 2.1 (draft) formally removes the Implicit flow and Resource Owner Password Credentials (ROPC) grant; treat both as deprecated now.
- PKCE (`code_challenge_method=S256`) is mandatory for all public clients per RFC 8252 Section 8.1 and OAuth 2.1.
- Refresh token rotation is mandated for public clients in the OAuth 2.1 draft; confidential clients should also rotate.

## Common false positives

- `response_type=token` in server-side code that is constructing an introspection or token endpoint call (not an authorization request) — check context carefully.
- `access_token=` in log scrubbing / redaction code — these are sanitization functions, not token leaks.
- State parameter absence in Client Credentials flow — Client Credentials has no user-facing redirect, so state is not applicable.
