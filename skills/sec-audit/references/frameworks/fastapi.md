# FastAPI / Starlette

## Source

- https://fastapi.tiangolo.com/tutorial/security/
- https://www.starlette.io/middleware/
- https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- https://owasp.org/www-project-top-ten/

## Scope

Covers FastAPI 0.95+ and its Starlette underpinning, including Pydantic v1
and v2 model validation, SQLAlchemy integration, and common middleware.
Does not cover async task queues (Celery, ARQ) or GraphQL layers (Strawberry).

## Dangerous patterns (regex/AST hints)

### Raw SQL via sqlalchemy text() with f-strings — CWE-89

- Why: `sqlalchemy.text()` with string interpolation bypasses parameter binding and allows SQL injection.
- Grep: `text\(f["\']|text\(.*%\s*\(|execute\(f["\']|execute\(.*format\(`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### CORS wildcard with credentials — CWE-942

- Why: `CORSMiddleware` with `allow_origins=["*"]` and `allow_credentials=True` is rejected by browsers per spec but may be misconfigured with broad origin lists that include attacker-controlled domains.
- Grep: `allow_origins\s*=\s*\[["']\*["']\]|allow_credentials\s*=\s*True`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

### Missing HTTPSRedirectMiddleware in production — CWE-319

- Why: Without HTTPS redirect middleware, clients may send credentials or tokens over plain HTTP.
- Grep: `HTTPSRedirectMiddleware` — absence in `main.py` or `app.py` when `TrustedHostMiddleware` is also absent.
- File globs: `**/main.py`, `**/app.py`
- Source: https://www.starlette.io/middleware/#httpsredirectmiddleware

### Dependency injection leaking credentials via default values — CWE-200

- Why: Using mutable default arguments or module-level globals to store secrets in dependency functions can expose them in tracebacks, logs, or via `/openapi.json` schema introspection.
- Grep: `Depends\(.*password|api_key\s*=\s*["'][^"']+["']|secret\s*=\s*["'][^"']+["']`
- File globs: `**/*.py`
- Source: https://fastapi.tiangolo.com/tutorial/security/

### Pydantic model used as ORM filter without validation enforcement — CWE-20

- Why: Calling `.dict()` (Pydantic v1) or `.model_dump()` (v2) then unpacking `**` into an ORM query passes all fields including attacker-injected keys if the model has `extra = "allow"`.
- Grep: `extra\s*=\s*["']allow["']|extra\s*=\s*Extra\.allow|model_dump\(\).*\*\*|\.dict\(\).*\*\*`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

## Secure patterns

```python
# Parameterized SQLAlchemy text() query
from sqlalchemy import text

result = db.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": user_email},
)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

```python
# Safe CORS: explicit origin list only
from starlette.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

```python
# Pydantic model with strict extra-field rejection
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    email: str

    class Config:
        extra = "forbid"  # Pydantic v1
        # Pydantic v2: model_config = ConfigDict(extra="forbid")
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

## Fix recipes

### Recipe: Parameterize SQLAlchemy text() — addresses CWE-89

**Before (dangerous):**

```python
from sqlalchemy import text
result = db.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
```

**After (safe):**

```python
from sqlalchemy import text
result = db.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": user_id})
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Recipe: Restrict CORS origins — addresses CWE-942

**Before (dangerous):**

```python
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
```

**After (safe):**

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html

### Recipe: Forbid extra fields in Pydantic models — addresses CWE-20

**Before (dangerous):**

```python
class UpdateRequest(BaseModel):
    class Config:
        extra = "allow"
```

**After (safe):**

```python
from pydantic import BaseModel, ConfigDict

class UpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    email: str
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### Recipe: Add HTTPS redirect middleware — addresses CWE-319

**Before (dangerous):**

```python
app = FastAPI()
# No HTTPS enforcement
```

**After (safe):**

```python
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
app = FastAPI()
app.add_middleware(HTTPSRedirectMiddleware)
```

Source: https://www.starlette.io/middleware/#httpsredirectmiddleware

## Version notes

- Pydantic v2 (FastAPI 0.100+): `extra = "allow"` config key changed to `model_config = ConfigDict(extra="allow")`; both forms exist in mixed codebases during migration.
- FastAPI 0.95+: OpenAPI schema is served at `/openapi.json` by default; disable in production if internal APIs should not be discoverable (`openapi_url=None`).
- Starlette `TrustedHostMiddleware` is distinct from `HTTPSRedirectMiddleware`; both should be added for production deployments.

## Common false positives

- `allow_origins=["*"]` without `allow_credentials=True` — acceptable for fully public, unauthenticated read-only APIs; still prefer an explicit list.
- `text()` calls with no interpolation (plain string literals with `:param` placeholders only) — safe by design.
- `extra = "allow"` in internal admin-only models never exposed to user input — lower risk but still worth noting.
