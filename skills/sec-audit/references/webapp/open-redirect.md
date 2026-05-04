# Open Redirect

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html — OWASP Unvalidated Redirects and Forwards Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A01:2021 Broken Access Control)
- https://cwe.mitre.org/data/definitions/601.html — CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html — OWASP Input Validation Cheat Sheet

## Scope

Covers open redirect vulnerabilities where attacker-controlled URLs are passed directly to HTTP redirect responses. Applies to Python (Flask/Django), Node.js (Express), Java (Spring MVC), Ruby on Rails, and Go HTTP handlers. Includes header-injection via CRLF in the redirect target and `javascript:` URI redirects. Does not cover DOM-based redirects via `window.location` (see XSS pack).

## Dangerous patterns (regex/AST hints)

### Flask redirect() with user-controlled parameter — CWE-601

- Why: Passing `request.args.get('next')` or similar directly to `redirect()` allows redirecting users to attacker-controlled sites after login.
- Grep: `redirect\s*\(\s*request\.(args|form|values)\[`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### Django HttpResponseRedirect with user input — CWE-601

- Why: `HttpResponseRedirect(request.GET['next'])` is the canonical Django open-redirect pattern; the framework does not validate the target URL.
- Grep: `HttpResponseRedirect\s*\(\s*request\.(GET|POST|META)`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### Express res.redirect() with dynamic URL — CWE-601

- Why: `res.redirect(req.query.redirect)` with no validation redirects the browser to any URL; used in phishing chains.
- Grep: `res\.redirect\s*\(\s*req\.(query|body|params)`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### Spring MVC redirect: prefix with user value — CWE-601

- Why: Returning `"redirect:" + request.getParameter("url")` from a controller method redirects to the user-supplied URL.
- Grep: `"redirect:\s*"\s*\+|return\s+"redirect:.*getParameter`
- File globs: `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### Rails redirect_to with params — CWE-601

- Why: `redirect_to params[:url]` passes raw user input to the response Location header; Rails 7 added `allow_other_host` but older code still passes without it.
- Grep: `redirect_to\s+params\[|redirect_to\s+.*params\[`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### Go http.Redirect with user-controlled URL — CWE-601

- Why: `http.Redirect(w, r, r.URL.Query().Get("to"), 302)` redirects without validation.
- Grep: `http\.Redirect\s*\([^)]*r\.(URL|FormValue|PostFormValue)`
- File globs: `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### javascript: or data: URI in redirect target — CWE-601

- Why: Some frameworks pass redirect targets directly into HTML `<meta refresh>` or `<a href>` tags; `javascript:` URIs execute code in the browser context.
- Grep: `javascript\s*:|data\s*:.*base64` (in redirect target variables)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.java`, `**/*.go`
- Source: https://cwe.mitre.org/data/definitions/601.html

## Secure patterns

Python — same-site-only validation for `next` parameter:

```python
from urllib.parse import urlparse, urljoin
from flask import request, redirect, abort

def is_safe_redirect(url: str) -> bool:
    """Allow only relative URLs or same-host absolute URLs."""
    if not url:
        return False
    parsed = urlparse(url)
    # Reject any URL that specifies a host different from the request host
    if parsed.netloc and parsed.netloc != urlparse(request.host_url).netloc:
        return False
    # Reject javascript: and data: schemes
    if parsed.scheme and parsed.scheme not in ('http', 'https', ''):
        return False
    return True

next_url = request.args.get('next', '/')
if not is_safe_redirect(next_url):
    abort(400)
return redirect(urljoin(request.host_url, next_url))
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

Rails — allowlist approach (preferred over URL inspection):

```ruby
ALLOWED_REDIRECT_PATHS = %w[/dashboard /profile /orders].freeze

def safe_redirect_path(path)
  ALLOWED_REDIRECT_PATHS.include?(path) ? path : '/dashboard'
end

redirect_to safe_redirect_path(params[:next])
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

## Fix recipes

### Recipe: Validate `next` parameter before redirect — addresses CWE-601

**Before (dangerous):**

```python
@app.route('/login', methods=['POST'])
def login():
    # ... authenticate user ...
    return redirect(request.args.get('next', '/'))
```

**After (safe):**

```python
from urllib.parse import urlparse

@app.route('/login', methods=['POST'])
def login():
    # ... authenticate user ...
    next_url = request.args.get('next', '/')
    parsed = urlparse(next_url)
    # Only allow relative paths (no scheme, no host)
    if parsed.scheme or parsed.netloc:
        next_url = '/'
    return redirect(next_url)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### Recipe: Replace open redirect with allowlist lookup — addresses CWE-601

**Before (dangerous):**

```js
// OAuth callback — redirects to wherever the state param says
const target = req.query.state;
res.redirect(target);
```

**After (safe):**

```js
const ALLOWED_ROUTES = new Map([
  ['dashboard', '/dashboard'],
  ['orders',    '/orders'],
  ['profile',   '/profile'],
]);

const key = req.query.state;
const target = ALLOWED_ROUTES.get(key) ?? '/dashboard';
res.redirect(target);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### Recipe: Fix Rails redirect_to with external URL — addresses CWE-601

**Before (dangerous):**

```ruby
redirect_to params[:return_url]
```

**After (safe):**

```ruby
# Rails 7+: allow_other_host: false is the default but be explicit
# For pre-7, validate manually:
return_url = params[:return_url]
unless return_url.start_with?('/')
  return_url = '/dashboard'
end
redirect_to return_url
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

## Version notes

- Rails 7.0 changed `redirect_to` to raise `ActionController::Redirecting::UnsafeRedirectError` for external URLs unless `allow_other_host: true` is passed; code that passes `allow_other_host: true` with user-supplied URLs is still vulnerable.
- Flask has no built-in open-redirect protection; `is_safe_url()` was removed from Flask-Login 0.6.0 — applications must implement their own check.
- Spring Security's `DefaultRedirectStrategy` does not validate target URLs; applications using Spring MVC `redirect:` view names are unprotected unless a custom `RedirectView` is used.
- Express has no redirect validation; all validation is application responsibility regardless of Express version.

## Common false positives

- `redirect_to root_path` — redirecting to a hardcoded named route helper is safe; grep matches `redirect_to` but there is no user input involved.
- `res.redirect('/login?error=invalid')` — string literal redirect with no dynamic user input is safe; confirm by checking whether the path is fully static.
- `HttpResponseRedirect(reverse('dashboard'))` — Django `reverse()` resolves a named URL pattern, not a raw user string; the pattern is not a sink.
- `http.Redirect(w, r, "/logout", http.StatusFound)` — Go redirect to a static string; flag only when the third argument references request data.
