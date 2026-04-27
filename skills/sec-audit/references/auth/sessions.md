# Server-Side Session Management

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html — OWASP Session Management Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A07:2021 Identification and Authentication Failures)
- https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis — RFC 6265bis Cookies
- https://csrc.nist.gov/publications/detail/sp/800-63b/final — NIST SP 800-63B Digital Identity Guidelines

## Scope

Covers server-side session lifecycle management for web applications: session ID generation, session fixation prevention, session rotation, idle and absolute timeouts, secure transport, and logout invalidation. Does not cover JWT-based stateless sessions (see jwt.md) or cookie flag configuration (see samesite-cookies.md).

## Dangerous patterns (regex/AST hints)

### Session ID not regenerated after login — CWE-384

- Why: Session fixation: an attacker who plants a known session ID before login can hijack the post-login session.
- Grep: `session.*login|login.*session` (check absence of `regenerate`/`rotate`/`new_session`)
- File globs: `**/*.py`, `**/*.rb`, `**/*.php`, `**/*.js`, `**/*.ts`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### Predictable or short session ID — CWE-330

- Why: Session IDs must have at least 128 bits of entropy from a CSPRNG; short or seeded-with-time IDs are guessable.
- Grep: `random\.|Math\.random\(\)|rand\(\)|time\.time\(\)` (in session ID generation context)
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.php`, `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### No idle or absolute timeout configured — CWE-613

- Why: Sessions that never expire remain valid indefinitely after a user closes their browser.
- Grep: `SESSION_COOKIE_AGE|session.*timeout|session.*expire` (check for absence or zero/very large values)
- File globs: `**/*.py`, `**/*.rb`, `**/*.conf`, `**/*.yaml`, `**/*.json`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### Session not invalidated on logout — CWE-613

- Why: Calling only `session.clear()` or deleting the cookie client-side leaves the server-side session alive; it can be replayed with the old cookie.
- Grep: `logout|sign.out|signout` (check whether server-side session deletion follows)
- File globs: `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.php`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

## Secure patterns

Session rotation on privilege change (Python/Flask example):

```python
from flask import session
import secrets

def login_user(user):
    # Preserve any pre-login data needed
    old_data = dict(session)
    session.clear()            # invalidate old session
    # Flask generates a new session ID automatically on clear+modify
    session.update(old_data)
    session['user_id'] = user.id
    session['authenticated'] = True
    session['login_time'] = time.time()
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

Secure session ID generation (when implementing from scratch):

```python
import secrets

SESSION_ID_BYTES = 32   # 256 bits — well above OWASP 128-bit minimum

def generate_session_id() -> str:
    return secrets.token_urlsafe(SESSION_ID_BYTES)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

Idle and absolute timeout enforcement:

```python
MAX_IDLE_SECONDS = 30 * 60       # 30 minutes idle
MAX_ABSOLUTE_SECONDS = 8 * 3600  # 8 hours absolute

def check_session_validity():
    now = time.time()
    if now - session.get('last_active', 0) > MAX_IDLE_SECONDS:
        logout_user(); return False
    if now - session.get('login_time', 0) > MAX_ABSOLUTE_SECONDS:
        logout_user(); return False
    session['last_active'] = now
    return True
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

Server-side session deletion on logout:

```python
def logout():
    session_id = request.cookies.get('sessionid')
    session_store.delete(session_id)   # delete from store — not just the cookie
    response = redirect('/')
    response.delete_cookie('sessionid')
    return response
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

## Fix recipes

### Recipe: Regenerate session ID after login — addresses CWE-384

**Before (dangerous):**

```python
def login(request):
    user = authenticate(request.POST)
    request.session['user_id'] = user.id  # same session ID before and after login
```

**After (safe):**

```python
def login(request):
    user = authenticate(request.POST)
    request.session.cycle_key()           # Django: new ID, data preserved
    request.session['user_id'] = user.id
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### Recipe: Invalidate server-side session on logout — addresses CWE-613

**Before (dangerous):**

```js
app.post('/logout', (req, res) => {
  res.clearCookie('sessionid');          // cookie cleared but server session lives
  res.redirect('/');
});
```

**After (safe):**

```js
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {        // server-side session deleted
    res.clearCookie('sessionid');
    res.redirect('/');
  });
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### Recipe: Add idle timeout check — addresses CWE-613

**Before (dangerous):**

```python
# No timeout; session valid until explicit logout
@login_required
def dashboard(request):
    ...
```

**After (safe):**

```python
@login_required
def dashboard(request):
    if not check_session_validity():
        return redirect('/login?reason=timeout')
    ...
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

## Version notes

- NIST SP 800-63B Section 7.2 recommends reauthentication after no more than 30 minutes of inactivity for Authenticator Assurance Level 2 (AAL2); use this as a baseline for sensitive applications.
- Django's `session.cycle_key()` (added in Django 1.4) regenerates the session ID while preserving data; prefer it over `session.flush()` (which clears data) for post-login rotation.
- PHP `session_regenerate_id(true)` deletes the old session file when the `true` argument is passed; without it, the old session ID remains valid.

## Common false positives

- `session.clear()` or `session.flush()` in test setup/teardown — not a production logout path.
- Missing timeout configuration in framework defaults that already enforce timeouts (e.g. Rails default 30-minute session store expiry) — verify the effective default before flagging.
- IP-binding of sessions flagged as missing — IP binding breaks legitimate users behind NAT/mobile networks; downgrade severity unless the application explicitly requires it.
