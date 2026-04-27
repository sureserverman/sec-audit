# Python — Framework Deepening (Django / Flask / FastAPI)

## Source

- https://docs.djangoproject.com/en/stable/topics/security/ — Django security topics (canonical)
- https://docs.djangoproject.com/en/stable/ref/csrf/ — Django CSRF
- https://flask.palletsprojects.com/en/latest/security/ — Flask security
- https://fastapi.tiangolo.com/ — FastAPI canonical
- https://docs.pydantic.dev/latest/ — Pydantic (FastAPI's validation layer)
- https://docs.python.org/3/library/secrets.html — `secrets` (session token recommendation)
- https://owasp.org/www-project-top-ten/ — OWASP Top Ten
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — OWASP XSS Prevention

## Scope

Covers Python web-framework-specific patterns NOT already in the existing `frameworks/django.md`, `frameworks/flask.md`, `frameworks/fastapi.md` reference packs. This is the deepening layer for the Python lane: ORM injection patterns the SAST tools miss, session-cookie handling, FastAPI dependency-injection bypass surfaces, Pydantic validator bypass, Django middleware ordering, Flask blueprint isolation, ASGI middleware chain hazards. Out of scope: framework-agnostic Python (covered in `python/deserialization.md` + `python/subprocess-and-async.md`); deployment / WSGI / ASGI server hardening (covered in `webservers/`).

## Dangerous patterns (regex/AST hints)

### Django ORM `.extra()` / `.raw()` with string interpolation — CWE-89

- Why: Django's QuerySet is normally injection-safe — `User.objects.filter(name=user_input)` parameterises automatically. But `.extra(where=[...])`, `.extra(select={...})`, and `.raw("SELECT ...")` accept raw SQL fragments, and string-interpolating user input into them is direct SQL injection. CVE-2022-28346 (covered in the existing `frameworks/django.md`) is one example; the broader class includes any `.extra` call with non-parameterised `where`/`select` content. The hardened pattern is to express the query via Django's Q expressions (`from django.db.models import Q`) and never use `.extra` for user-influenced filters; `.raw` is sometimes unavoidable, in which case use `params=[...]` for binding.
- Grep: `\.(extra|raw)\s*\(` in Django code where the args contain f-strings, `%`-formatting, or `+`-concatenation with a non-constant.
- File globs: `**/*.py` in projects with `django` in `requirements.txt`.
- Source: https://docs.djangoproject.com/en/stable/ref/models/querysets/#raw

### Django `mark_safe` on user-influenced HTML — CWE-79

- Why: Django templates auto-escape by default. `mark_safe(html_string)` declares "this string is already safe to render" — the template engine skips escaping. Calling `mark_safe(user_input)` directly disables XSS protection for that string. The hardened pattern is to NEVER pass attacker-influenced data to `mark_safe`; if rich HTML is needed (e.g. user-authored markdown rendered to HTML), sanitize via `bleach.clean(html, tags=...)` before marking safe.
- Grep: `mark_safe\s*\(\s*[a-zA-Z_]` — mark_safe with a variable argument (vs constant string).
- File globs: `**/*.py` (Django views, template tags, custom filters).
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### Flask `render_template_string(user_input)` — CWE-94 (SSTI)

- Why: Flask's `render_template_string` compiles and renders a Jinja2 template from a string. Passing user-influenced data as the FIRST argument is server-side template injection — Jinja2 has access to Python builtins via `{{ ''.__class__.__mro__[1].__subclasses__() }}`-style traversal, leading to RCE. The hardened pattern is `render_template("page.html", data=user_input)` which embeds the user data as a TEMPLATE CONTEXT VARIABLE (auto-escaped) rather than as TEMPLATE SOURCE.
- Grep: `render_template_string\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,\)]` where the first arg is a variable (vs constant).
- File globs: `**/*.py` in projects with `Flask` in `requirements.txt`.
- Source: https://flask.palletsprojects.com/en/latest/security/

### Flask `app.run(debug=True)` reachable from production — CWE-489

- Why: Flask's debug mode (`app.run(debug=True)` or `FLASK_DEBUG=1`) enables the Werkzeug interactive debugger — a web-accessible Python REPL with full-host access. If a debug-enabled Flask process is reachable from the network (or accidentally bound to `0.0.0.0` instead of `127.0.0.1`), any external visitor with the debugger PIN (or a recovered PIN — there have been multiple PIN-derivation CVEs over the years) gets RCE. The hardened pattern is `if __name__ == "__main__": app.run(host="127.0.0.1", debug=False)` and reliance on a real WSGI server (Gunicorn, uWSGI, Waitress) for production.
- Grep: `app\.run\s*\([^)]*debug\s*=\s*True` OR `os\.environ\[["']FLASK_DEBUG["']\]\s*=\s*["']?(1|true|True|on)`.
- File globs: `**/*.py`, `Dockerfile`, `*.dockerfile`, `wsgi.py`, `asgi.py`, `entrypoint.sh`.
- Source: https://flask.palletsprojects.com/en/latest/security/

### FastAPI dependency that returns a value derived from `Header` / `Query` without `Annotated` validation — CWE-20

- Why: FastAPI's dependency-injection system runs `Depends(my_function)` to compute values for handlers. If `my_function` reads `Header(...)` or `Query(...)` without a Pydantic-typed annotation, the value is the raw string. Subsequent code that treats the value as already-validated (e.g. casts it to int, uses it as a dict key, passes it to subprocess) inherits the validation gap. The hardened pattern is `Annotated[int, Query(ge=1, le=1000)]` — Pydantic enforces the type and bounds at parse time; invalid requests get a 422 response without ever reaching the handler.
- Grep: `Header\s*\(` OR `Query\s*\(` OR `Path\s*\(` arguments in a `Depends`-resolved function with no surrounding Pydantic type annotation.
- File globs: `**/*.py` in projects with `fastapi` in `requirements.txt`.
- Source: https://fastapi.tiangolo.com/

### FastAPI / Starlette CORS allow-origin `*` with `allow_credentials=True` — CWE-942

- Why: Same class as the Go web-framework pattern in `go/web-frameworks.md`: a wildcard origin combined with credentials is rejected by browsers, but a reflective `allow_origins=["*"]` with `allow_credentials=True` is the dangerous shape that some `CORSMiddleware` configurations use as a copy-paste default. The hardened pattern is an explicit list (`allow_origins=["https://app.example.com"]`).
- Grep: `CORSMiddleware\b[^)]*allow_origins\s*=\s*\[\s*["']?\*` AND `allow_credentials\s*=\s*True`.
- File globs: `**/*.py`
- Source: https://owasp.org/www-project-api-security/

### Django session cookie without `SECURE` / `HTTPONLY` / `SAMESITE` — CWE-1004

- Why: Django reads `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE` from `settings.py`. The defaults are `SECURE=False`, `HTTPONLY=True`, `SAMESITE='Lax'`. A production Django settings file should declare `SESSION_COOKIE_SECURE=True` (cookie only sent over HTTPS), keep `HTTPONLY=True` (not readable by JavaScript), and set `SAMESITE='Strict'` or `'Lax'` (CSRF mitigation). The same triplet applies to `CSRF_COOKIE_*`. Missing `SECURE=True` means a downgrade-to-HTTP attacker can intercept session cookies in flight.
- Grep: Django `settings.py` files where `SESSION_COOKIE_SECURE` is not defined or is `False`.
- File globs: `settings.py`, `**/settings/*.py`, `**/settings_*.py`.
- Source: https://docs.djangoproject.com/en/stable/topics/security/

### `SECRET_KEY` hard-coded in `settings.py` — CWE-798

- Why: Django's `SECRET_KEY` signs session cookies, password reset tokens, and CSRF tokens. A leaked `SECRET_KEY` (committed to git, copied from a public Stack Overflow answer, hard-coded in a Dockerfile) lets an attacker forge any signed value. The hardened pattern is `SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]` (read from env at startup) plus runbook for generating a fresh key per deployment (`python -c "import secrets; print(secrets.token_urlsafe(50))"`).
- Grep: `SECRET_KEY\s*=\s*["'][^"'$]+["']` (assignment with a string literal not referencing env).
- File globs: `settings.py`, `**/settings/*.py`.
- Source: https://docs.djangoproject.com/en/stable/topics/security/

## Secure patterns

Hardened Django settings:

```python
# settings.py
import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() == "true"
ALLOWED_HOSTS = os.environ["DJANGO_ALLOWED_HOSTS"].split(",")

# Cookie hardening:
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Strict"

# HSTS:
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Misc:
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_SSL_REDIRECT = True
```

Source: https://docs.djangoproject.com/en/stable/topics/security/

FastAPI handler with Pydantic-validated query:

```python
from typing import Annotated
from fastapi import FastAPI, Query

app = FastAPI()

@app.get("/users")
def list_users(
    page: Annotated[int, Query(ge=1, le=10000)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 20,
    q: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
):
    # page, size, q are guaranteed within bounds; FastAPI returns 422 otherwise
    return paginate(query(q), page=page, size=size)
```

Source: https://fastapi.tiangolo.com/

Flask with safe template + bleach sanitisation:

```python
import bleach
from flask import render_template

@app.route("/posts/<slug>")
def show_post(slug):
    post = Post.get(slug)
    safe_html = bleach.clean(
        post.body_html,
        tags={"p", "a", "code", "pre", "ul", "ol", "li", "em", "strong"},
        attributes={"a": ["href", "title"]},
    )
    return render_template("post.html", post=post, safe_html=safe_html)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: move `SECRET_KEY` to env-var — addresses CWE-798

**Before (dangerous):**

```python
# settings.py
SECRET_KEY = "django-insecure-abc123def456..."
```

**After (safe):**

```python
# settings.py
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]   # KeyError on missing env is the desired failure mode
```

Source: https://docs.djangoproject.com/en/stable/topics/security/

### Recipe: replace `render_template_string(user_input)` with `render_template` + context — addresses CWE-94

**Before (dangerous):**

```python
@app.route("/preview")
def preview():
    template_str = request.args.get("tpl")
    return render_template_string(template_str)
```

**After (safe):**

```python
@app.route("/preview")
def preview():
    user_data = request.args.get("data", "")
    return render_template("preview.html", user_data=user_data)
# preview.html uses {{ user_data }} — auto-escaped by Jinja2
```

Source: https://flask.palletsprojects.com/en/latest/security/

### Recipe: replace Django `.extra(where=[f"..."])` with Q expression — addresses CWE-89

**Before (dangerous):**

```python
qs = User.objects.extra(where=[f"name LIKE '%{search}%'"])
```

**After (safe):**

```python
from django.db.models import Q
qs = User.objects.filter(Q(name__icontains=search))
```

Source: https://docs.djangoproject.com/en/stable/ref/models/querysets/#raw

## Version notes

- Django 4.1+ defaults `SCRIPT_NAME` and `FORCE_SCRIPT_NAME` to safe values; older versions could silently inherit attacker-controlled `SCRIPT_NAME` from misbehaving reverse proxies.
- Flask 3.0 dropped Python 3.7 support and tightened a few default behaviours; pre-3.0 Flask deployments may be missing more recent CVE patches.
- FastAPI's dependency-injection system was generally rewritten between 0.95 and 0.100; pre-0.100 code paths may have subtle DI-cache behaviours that affect security middleware ordering.
- `bleach` was archived (no longer maintained) as of late 2024; `nh3` (the Rust-backed reimplementation) is the recommended successor for new code. Existing `bleach` usage is still functional but does not receive new HTML5 attribute updates.

## Common false positives

- `mark_safe` on hard-coded constant HTML strings (e.g. an `__html__` representation of a model class) — annotate; flag only when the input is non-constant.
- `app.run(debug=True)` in a `if __name__ == "__main__":` block clearly scoped to local development AND not invoked in any production entry point — annotate; downgrade.
- `SECRET_KEY` in `tests/settings.py` or a fixture settings file used only by `pytest` — annotate.
- `render_template_string` with a string containing only a single Jinja directive that is itself trusted (rare, but legitimate for some plugin systems) — annotate.
- FastAPI `Query` without `Annotated` in pre-0.95 codebases that haven't migrated to the modern syntax yet — flag with a "migrate to Annotated" recommendation rather than HIGH severity.
