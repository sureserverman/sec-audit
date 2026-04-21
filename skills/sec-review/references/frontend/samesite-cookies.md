# SameSite Cookies and Cookie Security Flags

## Source

- https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis — RFC 6265bis (Cookies: HTTP State Management Mechanism)
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie — MDN Set-Cookie
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies — MDN HTTP Cookies
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html — OWASP Session Management Cheat Sheet

## Scope

Covers the `Set-Cookie` response header and its security-relevant attributes: `Secure`, `HttpOnly`, `SameSite` (Lax/Strict/None), the `__Host-` and `__Secure-` cookie name prefixes, and partitioned cookies (CHIPS). Applies to all web application session and authentication cookies. Does not cover cookie encryption or CSRF tokens (see csrf.md).

## Dangerous patterns (regex/AST hints)

### Session cookie missing Secure flag — CWE-614

- Why: Without `Secure`, the cookie is transmitted over HTTP, exposing it to network eavesdropping.
- Grep: `Set-Cookie[^;\n]*(?!Secure)`
- File globs: `**/*.conf`, `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`
- Source: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

### Session cookie missing HttpOnly flag — CWE-1004

- Why: Without `HttpOnly`, the cookie is accessible from JavaScript, enabling exfiltration via XSS.
- Grep: `Set-Cookie[^;\n]*(?!HttpOnly)`
- File globs: `**/*.conf`, `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`
- Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie

### SameSite=None without Secure — CWE-352

- Why: `SameSite=None` without `Secure` is rejected by modern browsers; when accepted it allows full cross-site cookie sending.
- Grep: `SameSite=None`
- File globs: `**/*.conf`, `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`
- Source: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

### Missing SameSite attribute — CWE-352

- Why: Defaults vary by browser; relying on implicit defaults leaves the application vulnerable on older browsers.
- Grep: `Set-Cookie:(?:(?!SameSite).)*\n`
- File globs: `**/*.conf`, `**/*.py`, `**/*.rb`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### __Host- prefix without required attributes — CWE-614

- Why: `__Host-` cookies are only respected if `Secure` is set, there is no `Domain` attribute, and `Path=/`; violating these negates prefix protection.
- Grep: `__Host-`
- File globs: `**/*.conf`, `**/*.py`, `**/*.rb`, `**/*.go`, `**/*.js`
- Source: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

## Secure patterns

Fully hardened session cookie:

```
Set-Cookie: __Host-session=<token>; Secure; HttpOnly; SameSite=Lax; Path=/
```

- `__Host-` prefix: forces `Secure`, no `Domain`, `Path=/`.
- `SameSite=Lax`: prevents cross-site sending on state-changing top-level navigations via POST; allows safe top-level GET navigation (needed for links from other sites).
- Use `SameSite=Strict` if the application can tolerate breaking links from external sites (e.g. admin consoles).

Source: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

Third-party / embedded context cookie (CHIPS — Partitioned):

```
Set-Cookie: __Host-embed-token=<value>; Secure; HttpOnly; SameSite=None; Path=/; Partitioned
```

- `Partitioned` isolates the cookie per top-level site; required for legitimate third-party cookies after third-party cookie deprecation.

Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie

`__Secure-` prefix (less strict than `__Host-`; allows Domain and non-root Path):

```
Set-Cookie: __Secure-pref=<value>; Secure; SameSite=Lax; Domain=example.com; Path=/app
```

Source: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

## Fix recipes

### Recipe: Add missing Secure and HttpOnly flags — addresses CWE-614, CWE-1004

**Before (dangerous):**

```python
response.set_cookie('sessionid', session_token)
```

**After (safe):**

```python
response.set_cookie(
    'sessionid',
    session_token,
    secure=True,
    httponly=True,
    samesite='Lax',
)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### Recipe: Fix SameSite=None without Secure — addresses CWE-352

**Before (dangerous):**

```
Set-Cookie: embed_id=abc; SameSite=None
```

**After (safe):**

```
Set-Cookie: __Host-embed_id=abc; Secure; HttpOnly; SameSite=None; Path=/; Partitioned
```

Source: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

### Recipe: Upgrade to __Host- prefix — addresses CWE-614

**Before (less safe):**

```
Set-Cookie: session=<token>; Secure; HttpOnly; SameSite=Strict; Path=/
```

**After (safe — prefix enforces constraints in the browser):**

```
Set-Cookie: __Host-session=<token>; Secure; HttpOnly; SameSite=Strict; Path=/
```

Source: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

## Version notes

- `SameSite=Lax` is the browser-enforced default as of Chrome 80 (Feb 2020) and Firefox 87; however, always set the attribute explicitly — do not rely on browser defaults.
- `Partitioned` / CHIPS is supported in Chrome 114+ and Firefox 131+; not yet standardized in RFC 6265bis at time of writing but included in the draft.
- `SameSite=None` cookies without `Secure` are silently dropped by Chrome 52+, Firefox 69+.
- The `__Host-` and `__Secure-` prefixes are defined in RFC 6265bis Section 4.1.3; not in the original RFC 6265.

## Common false positives

- Missing `HttpOnly` on cookies intentionally read by JavaScript (e.g. XSRF-TOKEN in Angular's double-submit pattern) — acceptable by design; confirm the cookie does not contain the session credential itself.
- `SameSite=None` on cookies used by embedded iframes or cross-origin widgets — legitimate use case; verify `Partitioned` is also set.
- Missing `Secure` on cookies in development/test environments served over HTTP — flag only in production configurations.
