# Flask

## Source

- https://flask.palletsprojects.com/en/stable/security/
- https://flask.palletsprojects.com/en/stable/config/
- https://cheatsheetseries.owasp.org/cheatsheets/Flask_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers Flask 2.x and 3.x, Jinja2 template engine, Werkzeug session/cookie
layer, and commonly paired extensions (Flask-CORS, Flask-Session). Does not
cover Quart (async fork) or Connexion.

## Dangerous patterns (regex/AST hints)

### render_template_string with user input — CWE-94 (SSTI)

- Why: `render_template_string()` compiles the first argument as a Jinja2 template; if any user-controlled data reaches it, attackers can execute arbitrary Python via `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`.
- Grep: `render_template_string\(.*request\.|render_template_string\(.*form\[|render_template_string\(.*args\[`
- File globs: `**/*.py`
- Source: https://flask.palletsprojects.com/en/stable/security/#server-side-template-injection

### Jinja2 autoescape disabled — CWE-79

- Why: `Environment(autoescape=False)` or `Markup()` on user data disables HTML escaping in templates, enabling XSS.
- Grep: `autoescape\s*=\s*False|Markup\(.*request\.|Markup\(.*form\[`
- File globs: `**/*.py`, `**/*.html`
- Source: https://flask.palletsprojects.com/en/stable/security/#cross-site-scripting-xss

### Hardcoded or weak SECRET_KEY — CWE-321

- Why: Flask signs session cookies with `SECRET_KEY`; a hardcoded or guessable key lets attackers forge arbitrary session data without authentication.
- Grep: `SECRET_KEY\s*=\s*["'][^"']{1,40}["']|app\.secret_key\s*=\s*["']`
- File globs: `**/*.py`, `**/.env`
- Source: https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY

### debug=True in production — CWE-94

- Why: The Werkzeug debugger PIN can be brute-forced or leaked; enabling it in production exposes an interactive Python console to any visitor.
- Grep: `app\.run\(.*debug\s*=\s*True|debug\s*=\s*True`
- File globs: `**/*.py`
- Source: https://flask.palletsprojects.com/en/stable/security/#the-debugger

### Session cookie flags missing — CWE-614

- Why: Without `SESSION_COOKIE_SECURE=True` and `SESSION_COOKIE_HTTPONLY=True`, session tokens are exposed over HTTP and to JavaScript.
- Grep: `SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|SESSION_COOKIE_SAMESITE\s*=\s*None`
- File globs: `**/*.py`
- Source: https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_SECURE

### CORS wildcard origin — CWE-942

- Why: `CORS(app, origins="*")` or `Access-Control-Allow-Origin: *` combined with `supports_credentials=True` allows any origin to read credentialed responses.
- Grep: `origins\s*=\s*["\*]|CORS_ORIGINS\s*=\s*["\*]|Access-Control-Allow-Origin.*\*`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

## Secure patterns

```python
import os
from flask import Flask

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],  # never hardcode
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
```

Source: https://flask.palletsprojects.com/en/stable/config/

```python
# Always use render_template with a file, never render_template_string with user data
from flask import render_template, escape

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template("greet.html", name=name)
    # In greet.html: {{ name }} — Jinja2 auto-escapes by default
```

Source: https://flask.palletsprojects.com/en/stable/security/#cross-site-scripting-xss

```python
# Safe CORS: explicit allowlist, no wildcard with credentials
from flask_cors import CORS
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

## Fix recipes

### Recipe: Replace render_template_string with render_template — addresses CWE-94

**Before (dangerous):**

```python
template = f"<h1>Hello {request.args['name']}</h1>"
return render_template_string(template)
```

**After (safe):**

```python
# templates/hello.html: <h1>Hello {{ name }}</h1>
return render_template("hello.html", name=request.args.get("name", ""))
```

Source: https://flask.palletsprojects.com/en/stable/security/#server-side-template-injection

### Recipe: Load SECRET_KEY from environment — addresses CWE-321

**Before (dangerous):**

```python
app.secret_key = "mysupersecretkey"
```

**After (safe):**

```python
import os
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
```

Source: https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY

### Recipe: Harden session cookie configuration — addresses CWE-614

**Before (dangerous):**

```python
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
```

**After (safe):**

```python
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
```

Source: https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_SECURE

### Recipe: Restrict CORS origins — addresses CWE-942

**Before (dangerous):**

```python
CORS(app, origins="*", supports_credentials=True)
```

**After (safe):**

```python
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

## Version notes

- Flask 2.3+: `SESSION_COOKIE_SAMESITE` defaults to `"Lax"`; earlier versions default to `None`, which requires explicit hardening.
- Flask 3.0: `app.run(debug=True)` now emits a deprecation warning if `FLASK_ENV` is not set; set `FLASK_ENV=production` to suppress false-positive debug mode warnings in some setups — but verify `debug` kwarg is also False.
- Werkzeug 2.1+: Debugger PIN is harder to brute-force but still exposes an RCE surface; never enable in production regardless of version.

## Common false positives

- `render_template_string()` called with a developer-owned string literal that contains no user data — safe if confirmed no user input flows into the template string itself.
- `SECRET_KEY` lines in `.env.example` or `config.example.py` intended as documentation placeholders — not deployed secrets.
- `debug=True` inside `if __name__ == "__main__":` blocks when a production WSGI server (gunicorn, uWSGI) is used — those servers don't call `app.run()`.
- `CORS(app, origins="*")` without `supports_credentials=True` — less severe for purely public, unauthenticated APIs; still worth noting but lower priority.
