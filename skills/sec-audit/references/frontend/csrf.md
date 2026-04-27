# Cross-Site Request Forgery (CSRF)

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — OWASP CSRF Prevention Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A01:2021 Broken Access Control)
- https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CSRF — MDN CSRF

## Scope

Covers CSRF attacks against web applications that use cookie-based session authentication. Applies to form submissions, AJAX requests with credentials, and state-changing GET endpoints. Does not cover SSRF or login CSRF (see sessions reference).

## Dangerous patterns (regex/AST hints)

### State-changing GET endpoint — CWE-352

- Why: GET requests are triggered by cross-origin resources (images, iframes, links); any state change on GET is CSRF-exploitable without a token.
- Grep: `@app\.route\([^)]*methods=[^)]*'GET'|router\.get\(|app\.get\(`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

### CSRF token validation disabled or skipped — CWE-352

- Why: Frameworks like Django, Rails, and Spring provide CSRF middleware that is sometimes explicitly disabled for convenience.
- Grep: `csrf_exempt|protect_from_forgery\s*skip|CsrfViewMiddleware|@csrf_exempt|csrf_disable|csrf\.ignore`
- File globs: `**/*.py`, `**/*.rb`, `**/*.java`, `**/*.xml`, `**/*.config`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

### Missing SameSite attribute on session cookie — CWE-352

- Why: Without `SameSite`, cookies are sent on cross-site requests, enabling CSRF even with modern browsers.
- Grep: `Set-Cookie[^;\n]*(?!SameSite)`
- File globs: `**/*.conf`, `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

### Double-submit cookie without HMAC binding — CWE-352

- Why: A plain double-submit cookie (cookie value == form field value) is bypassable if an attacker can set cookies on a parent domain.
- Grep: `csrf.*cookie|csrftoken` (check whether the value is HMAC-signed)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Secure patterns

Synchronizer token pattern (server-side session-bound token):

```python
# Django — CSRF middleware enabled by default in MIDDLEWARE list
# Ensure CsrfViewMiddleware is present (never remove it):
MIDDLEWARE = [
    ...
    'django.middleware.csrf.CsrfViewMiddleware',
    ...
]
# Template: {% csrf_token %} inside every POST form
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

HMAC-bound double-submit cookie (stateless alternative):

```python
import hmac, hashlib, secrets

def generate_csrf_token(session_id: str, secret: bytes) -> str:
    random_value = secrets.token_hex(32)
    mac = hmac.new(secret, (session_id + random_value).encode(), hashlib.sha256).hexdigest()
    return f"{random_value}.{mac}"

def verify_csrf_token(token: str, session_id: str, secret: bytes) -> bool:
    try:
        random_value, mac = token.rsplit('.', 1)
        expected = hmac.new(secret, (session_id + random_value).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, mac)
    except Exception:
        return False
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

SameSite cookie as defense-in-depth (not a standalone defense):

```
Set-Cookie: sessionid=abc123; SameSite=Lax; Secure; HttpOnly; Path=/
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Enable CSRF token for POST form — addresses CWE-352

**Before (dangerous):**

```html
<form method="POST" action="/transfer">
  <input name="amount" value="1000">
  <button type="submit">Transfer</button>
</form>
```

**After (safe):**

```html
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="amount" value="1000">
  <button type="submit">Transfer</button>
</form>
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

### Recipe: Convert state-changing GET to POST — addresses CWE-352

**Before (dangerous):**

```python
@app.route('/delete-account', methods=['GET'])
def delete_account():
    current_user.delete()
```

**After (safe):**

```python
@app.route('/delete-account', methods=['POST'])
@csrf_protect
def delete_account():
    current_user.delete()
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

### Recipe: Re-enable accidentally disabled CSRF middleware — addresses CWE-352

**Before (dangerous):**

```python
@csrf_exempt
@login_required
def update_email(request):
    user.email = request.POST['email']
```

**After (safe):**

```python
# Remove @csrf_exempt; rely on global CsrfViewMiddleware
@login_required
def update_email(request):
    user.email = request.POST['email']
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Version notes

- `SameSite=Lax` is the browser default since Chrome 80 (2020) and Firefox 87; however, relying on browser defaults is not a substitute for explicit token-based CSRF protection.
- `SameSite=None` requires the `Secure` attribute; without it the cookie is rejected by modern browsers.
- Django's CSRF middleware uses HMAC-signed double-submit cookies as of Django 4.0; earlier versions used plain comparison (still safe against network attackers but weaker against cookie-stuffing).

## Common false positives

- `@csrf_exempt` — acceptable for API endpoints that use Bearer token authentication (Authorization header) rather than cookies, since cross-origin requests cannot set arbitrary headers via HTML forms.
- Missing CSRF token on GET forms — GET forms do not change state and do not require CSRF tokens; only flag GET endpoints that perform writes.
- SameSite absence on non-session cookies (analytics, preference cookies) — CSRF concern applies only to authentication/session cookies.
