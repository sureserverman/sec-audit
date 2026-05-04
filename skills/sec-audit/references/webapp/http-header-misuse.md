# HTTP Header Misuse: Smuggling, CORS Misconfiguration, Host Header Injection

## Source

- https://portswigger.net/web-security/request-smuggling — PortSwigger: HTTP Request Smuggling
- https://portswigger.net/web-security/cors — PortSwigger: CORS Misconfigurations
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html — OWASP HTTP Headers Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html — OWASP CORS Cheat Sheet
- https://cwe.mitre.org/data/definitions/444.html — CWE-444: Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)
- https://cwe.mitre.org/data/definitions/942.html — CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- https://cwe.mitre.org/data/definitions/644.html — CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax
- https://datatracker.ietf.org/doc/html/rfc9110 — IETF RFC 9110: HTTP Semantics
- https://datatracker.ietf.org/doc/html/rfc7230 — IETF RFC 7230: HTTP/1.1 Message Syntax and Routing

## Scope

Covers three related header-layer vulnerability classes in HTTP/1.1 web applications: (1) request smuggling via TE/CL header ambiguity at the reverse-proxy/backend seam; (2) CORS misconfiguration that exposes cross-origin reads; (3) Host header injection used in password-reset poisoning and URL generation. Applies to any stack behind a reverse proxy (nginx, haproxy, AWS ALB, Cloudflare). Does not cover HTTP/2 downgrade smuggling (H2.CL/H2.TE) in depth — see PortSwigger research for H2 variants.

## Dangerous patterns (regex/AST hints)

### CL.TE / TE.CL request smuggling: conflicting Transfer-Encoding and Content-Length — CWE-444

- Why: When a front-end proxy uses Content-Length and a back-end uses Transfer-Encoding (or vice versa), an attacker can inject a partial second request into the back-end's stream, hijacking another user's request.
- Grep: `Transfer-Encoding.*chunked` in raw request fixtures or proxy config; `Content-Length` present on same request — grep config for proxy pass-through of TE headers.
- File globs: `**/*.conf`, `**/*.nginx`, `**/*.cfg`, `**/haproxy.cfg`, `**/nginx.conf`
- Source: https://portswigger.net/web-security/request-smuggling

### Reverse proxy configured to forward Transfer-Encoding header — CWE-444

- Why: Nginx, by default, strips hop-by-hop headers including `Transfer-Encoding`; if a custom config re-forwards it (e.g. `proxy_pass_header Transfer-Encoding`), the back-end may parse it differently than the front-end.
- Grep: `proxy_pass_header\s+Transfer-Encoding|proxy_set_header\s+Transfer-Encoding`
- File globs: `**/nginx.conf`, `**/*.conf`, `**/default.conf`
- Source: https://portswigger.net/web-security/request-smuggling

### CORS: Access-Control-Allow-Origin: * with credentials — CWE-942

- Why: A wildcard ACAO with `Access-Control-Allow-Credentials: true` is rejected by browsers per spec, but some frameworks fall back to reflecting the request Origin, which is equally dangerous.
- Grep: `Access-Control-Allow-Origin:\s*\*` (check same response for `Access-Control-Allow-Credentials: true`)
- File globs: `**/*.conf`, `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.java`, `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

### CORS: dynamic origin reflection without allowlist — CWE-942

- Why: Code that reads the request `Origin` header and echoes it back in `Access-Control-Allow-Origin` without checking it against a fixed allowlist grants cross-origin read to any attacker-controlled domain.
- Grep: `request\.headers\[.origin.\]|req\.headers\.origin|request\.META\[.HTTP_ORIGIN.\]` (check if value is used in CORS response header directly)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.java`
- Source: https://portswigger.net/web-security/cors

### CORS: null origin accepted — CWE-942

- Why: Accepting `Origin: null` allows sandboxed iframes and local HTML files to make credentialed cross-origin requests.
- Grep: `origin.*null|allow.*null.*origin|'null'` in CORS configuration or middleware
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.conf`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

### Host header used to build absolute URLs — CWE-644

- Why: Using `request.host`, `request.META['HTTP_HOST']`, or `req.headers.host` to construct password-reset links or redirect URLs allows an attacker who can control the Host header to redirect those links to a malicious domain.
- Grep: `request\.host|request\.META\[.HTTP_HOST.\]|req\.headers\[.host.\]|req\.hostname` (check for concatenation into URL strings)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.java`, `**/*.php`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### X-Forwarded-Host trusted without validation — CWE-644

- Why: Trusting `X-Forwarded-Host` for URL construction allows any client (when not sitting behind a proxy that strips it) to inject an arbitrary host.
- Grep: `X-Forwarded-Host|HTTP_X_FORWARDED_HOST|x.forwarded.host`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.conf`, `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### Response splitting via user-controlled header value — CWE-644

- Why: Injecting CRLF sequences into a response header value (e.g. `Location`, `Set-Cookie`) allows an attacker to inject arbitrary headers or split the HTTP response.
- Grep: `response\.set_header\s*\(|res\.setHeader\s*\(|header\s*\(` (check for user-controlled string in second argument)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.php`
- Source: https://cwe.mitre.org/data/definitions/644.html

## Secure patterns

CORS — static allowlist, never reflect the request Origin directly:

```python
# Django / DRF (django-cors-headers)
CORS_ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]
CORS_ALLOW_CREDENTIALS = True
# Never: CORS_ORIGIN_ALLOW_ALL = True with CORS_ALLOW_CREDENTIALS = True
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

```js
// Express (cors package) — allowlist check
const ALLOWED_ORIGINS = new Set(['https://app.example.com', 'https://admin.example.com']);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

Host header — use a configured, trusted hostname for URL construction, never the request Host:

```python
# Django — use settings.ALLOWED_HOSTS and django.contrib.sites
from django.conf import settings

def password_reset_link(user, token):
    # Use a configured base URL, not request.META['HTTP_HOST']
    base = settings.BASE_URL  # e.g. "https://example.com"
    return f"{base}/reset/{token}/"
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

Nginx — normalize and validate the Host header at the proxy layer:

```nginx
# Reject requests with a Host that does not match the known virtual host
server {
    listen 80 default_server;
    return 444;  # close connection without response for unknown hosts
}
server {
    listen 80;
    server_name example.com www.example.com;
    # proxy_pass to backend
}
```

Source: https://portswigger.net/web-security/request-smuggling

## Fix recipes

### Recipe: CORS — replace wildcard with origin allowlist — addresses CWE-942

**Before (dangerous):**

```python
response['Access-Control-Allow-Origin'] = '*'
response['Access-Control-Allow-Credentials'] = 'true'
```

**After (safe):**

```python
ALLOWED_ORIGINS = {'https://app.example.com', 'https://admin.example.com'}
origin = request.META.get('HTTP_ORIGIN', '')
if origin in ALLOWED_ORIGINS:
    response['Access-Control-Allow-Origin'] = origin
    response['Access-Control-Allow-Credentials'] = 'true'
    response['Vary'] = 'Origin'
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

### Recipe: CORS — replace dynamic origin reflection with allowlist — addresses CWE-942

**Before (dangerous):**

```js
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
```

**After (safe):**

```js
const ALLOWED = new Set(['https://app.example.com']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');
  }
  next();
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

### Recipe: Password reset — use configured base URL, not Host header — addresses CWE-644

**Before (dangerous):**

```python
host = request.META.get('HTTP_HOST')
reset_url = f"https://{host}/reset/{token}/"
send_email(user.email, reset_url)
```

**After (safe):**

```python
from django.conf import settings
reset_url = f"{settings.BASE_URL}/reset/{token}/"
send_email(user.email, reset_url)
# Set BASE_URL in settings.py to a hard-coded, verified value
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### Recipe: Nginx — prevent TE header forwarding to mitigate smuggling — addresses CWE-444

**Before (dangerous):**

```nginx
location / {
    proxy_pass http://backend;
    proxy_set_header Transfer-Encoding $http_transfer_encoding;
}
```

**After (safe):**

```nginx
location / {
    proxy_pass http://backend;
    # Do not forward Transfer-Encoding; nginx normalizes chunked encoding
    # proxy_http_version 1.1 enables keepalive; use with proxy_set_header Connection ""
    proxy_http_version 1.1;
    proxy_set_header Connection "";
}
```

Source: https://portswigger.net/web-security/request-smuggling

## Version notes

- HTTP/2 end-to-end connections eliminate CL.TE and TE.CL smuggling between proxy and backend because HTTP/2 has a single, unambiguous framing layer. However, H2.CL and H2.TE downgrade attacks exist when a front-end HTTP/2 proxy downgrades to HTTP/1.1 for the backend.
- `SameSite=Lax` cookies are not sent on cross-origin subresource requests, which makes CORS-based credential theft harder but not impossible — CORS misconfiguration is still exploitable for credentialed `fetch()` and `XMLHttpRequest` calls.
- Django's `ALLOWED_HOSTS` setting validates the Host header on every request (since Django 1.5) and prevents most host header injection; however, it does not protect if `USE_X_FORWARDED_HOST = True` is set without a hardened proxy stripping client-supplied `X-Forwarded-Host`.
- nginx 1.25.1+ enables HTTP/2 by default for TLS connections; ensure backend connections also use HTTP/2 or that keepalive is correctly configured to avoid H2-to-H1 downgrade smuggling.

## Common false positives

- `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials: true` — safe for public, unauthenticated API endpoints (fonts, public CDN assets, open data APIs); downgrade to informational.
- `req.hostname` in Express — Express resolves `hostname` from `req.headers.host` but strips the port and honors `trust proxy` setting; still flag if used in URL construction, but note that `trust proxy` mitigates injection from untrusted intermediaries.
- `X-Forwarded-Host` consumed by an application running behind a well-configured load balancer that strips client-supplied instances of the header — reduced risk; flag as low severity and note the infrastructure dependency.
- CRLF injection grep matches on response header assignment with a fully static string — no user data in the header value; not exploitable.
