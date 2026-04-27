# Django

## Source

- https://docs.djangoproject.com/en/stable/topics/security/
- https://docs.djangoproject.com/en/stable/ref/settings/
- https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers Django 3.2 LTS through Django 5.x, including ORM, template engine,
session/auth, and middleware stack. Does not cover Django REST Framework
separately (see API-specific references) or Channels/async patterns.

## Dangerous patterns (regex/AST hints)

### Raw SQL string interpolation — CWE-89

- Why: `.raw()`, `cursor.execute()`, and `extra()` with f-strings or % formatting bypass the ORM's parameterization and allow SQL injection.
- Grep: `\.raw\(f["\']|\.raw\(.*%\s*\(|cursor\.execute\(f["\']|extra\(where=\[f["\']`
- File globs: `**/*.py`
- Source: https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection

### Template |safe filter and mark_safe() — CWE-79

- Why: Marking user-controlled data as safe disables Django's auto-escaping and allows stored or reflected XSS.
- Grep: `\|\s*safe|mark_safe\(|format_html\(.*\+`
- File globs: `**/*.py`, `**/*.html`
- Source: https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

### DEBUG=True or hardcoded SECRET_KEY — CWE-200, CWE-321

- Why: DEBUG=True exposes stack traces with local variables in responses. A hardcoded SECRET_KEY allows session forgery, CSRF token bypass, and signed-cookie attacks.
- Grep: `DEBUG\s*=\s*True|SECRET_KEY\s*=\s*["'][^"']{8,}`
- File globs: `**/settings*.py`, `**/.env`
- Source: https://docs.djangoproject.com/en/stable/ref/settings/#secret-key

### CSRF middleware removed or exempt applied broadly — CWE-352

- Why: Removing `django.middleware.csrf.CsrfViewMiddleware` or decorating state-changing views with `@csrf_exempt` removes cross-site request forgery protection.
- Grep: `csrf_exempt|CsrfViewMiddleware.*#|# .*CsrfViewMiddleware`
- File globs: `**/*.py`
- Source: https://docs.djangoproject.com/en/stable/topics/security/#cross-site-request-forgery-csrf-protection

### Insecure SECURE_* settings — CWE-614, CWE-319

- Why: Missing HSTS, secure cookies, and X-Frame-Options headers leave sessions and content exposed over plaintext channels.
- Grep: `SESSION_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|SECURE_SSL_REDIRECT\s*=\s*False|SECURE_HSTS_SECONDS\s*=\s*0`
- File globs: `**/settings*.py`
- Source: https://docs.djangoproject.com/en/stable/topics/security/#ssl-https

### Pickle or yaml.load deserialization — CWE-502

- Why: `pickle.loads()` and `yaml.load()` with user-controlled input allow arbitrary code execution. Django's cache backend may use pickle internally if misconfigured.
- Grep: `pickle\.loads\(|yaml\.load\([^,)]+\)|yaml\.load\(.*Loader\s*=\s*None`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## Secure patterns

```python
# Parameterized ORM query — never interpolate user input
results = MyModel.objects.filter(name=user_input)

# Raw SQL with params tuple (safe)
MyModel.objects.raw("SELECT * FROM myapp_model WHERE name = %s", [user_input])

# Safe HTML rendering with format_html
from django.utils.html import format_html
html = format_html("<b>{}</b>", user_controlled_value)
```

Source: https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection

```python
# Production settings skeleton
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]  # never hardcode
DEBUG = False
ALLOWED_HOSTS = ["example.com"]
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
X_FRAME_OPTIONS = "DENY"
```

Source: https://docs.djangoproject.com/en/stable/topics/security/#ssl-https

```python
# Safe YAML loading
import yaml
data = yaml.safe_load(user_supplied_yaml)  # never yaml.load()
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## Fix recipes

### Recipe: Parameterize raw SQL — addresses CWE-89

**Before (dangerous):**

```python
query = f"SELECT * FROM orders WHERE user_id = {user_id}"
cursor.execute(query)
```

**After (safe):**

```python
cursor.execute("SELECT * FROM orders WHERE user_id = %s", [user_id])
```

Source: https://docs.djangoproject.com/en/stable/topics/security/#sql-injection-protection

### Recipe: Remove mark_safe on user data — addresses CWE-79

**Before (dangerous):**

```python
from django.utils.safestring import mark_safe
comment = mark_safe(request.POST["comment"])
```

**After (safe):**

```python
from django.utils.html import format_html, escape
comment = escape(request.POST["comment"])
# Or use format_html for structured HTML construction
```

Source: https://docs.djangoproject.com/en/stable/topics/security/#cross-site-scripting-xss-protection

### Recipe: Load SECRET_KEY from environment — addresses CWE-321

**Before (dangerous):**

```python
SECRET_KEY = "django-insecure-abc123hardcoded"
```

**After (safe):**

```python
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
```

Source: https://docs.djangoproject.com/en/stable/ref/settings/#secret-key

### Recipe: Replace yaml.load with yaml.safe_load — addresses CWE-502

**Before (dangerous):**

```python
import yaml
config = yaml.load(user_data)
```

**After (safe):**

```python
import yaml
config = yaml.safe_load(user_data)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## Version notes

- Django 4.0+: `CSRF_TRUSTED_ORIGINS` requires full scheme + host (e.g. `https://example.com`), not just hostnames; misconfiguration silently breaks CSRF validation.
- Django 4.2 LTS: `PASSWORD_HASHERS` defaults now include scrypt; ensure hosting environment has OpenSSL ≥ 1.1 for scrypt support.
- Django 3.2 LTS: `DEFAULT_AUTO_FIELD` warning noise is not a security issue; do not suppress security warnings alongside it.
- `yaml.load()` without `Loader` kwarg raises a warning in PyYAML ≥ 5.1 but still executes unsafely; `yaml.safe_load()` is the only safe call.

## Common false positives

- `mark_safe()` in custom template tags that only ever receive developer-controlled strings (e.g. hardcoded HTML wrappers) — safe when no user input flows in.
- `SECRET_KEY` patterns that match test/CI settings files clearly isolated from production (e.g. `settings_test.py` with `if not os.getenv("CI")`).
- `@csrf_exempt` on webhook receiver views that validate an HMAC signature from the request body — legitimate exemption pattern, verify HMAC check is present.
- `DEBUG = True` in `settings_dev.py` when that file is never imported in production paths.
