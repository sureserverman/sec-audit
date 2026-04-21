# Multi-Factor Authentication (MFA)

## Source

- https://pages.nist.gov/800-63-3/sp800-63b.html — NIST SP 800-63B Digital Identity Guidelines: Authentication and Lifecycle Management
- https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html — OWASP MFA Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A07:2021 Identification and Authentication Failures)
- https://datatracker.ietf.org/doc/html/rfc6238 — RFC 6238: TOTP — Time-Based One-Time Password Algorithm

## Scope

Covers second-factor mechanisms for web and mobile applications: TOTP (software tokens), WebAuthn/FIDO2 hardware tokens, SMS/voice OTP, recovery codes, and MFA enrollment. Addresses bypass via account recovery and phishing-resistant authenticator selection. Does not cover first-factor password policy (see password-storage.md).

## Dangerous patterns (regex/AST hints)

### SMS OTP as sole second factor — CWE-308

- Why: SMS is susceptible to SIM-swap, SS7 interception, and real-time phishing; NIST SP 800-63B restricts SMS OTP to AAL1.
- Grep: `sms.*otp|send.*sms.*code|twilio.*verify|nexmo.*verify`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.go`
- Source: https://pages.nist.gov/800-63-3/sp800-63b.html#sec5

### TOTP window too wide — CWE-287

- Why: Accepting TOTP codes across more than ±1 step (30-second windows) dramatically widens the brute-force surface.
- Grep: `valid_window|window.*[3-9]|totp.*window`
- File globs: `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`
- Source: https://datatracker.ietf.org/doc/html/rfc6238#section-5.2

### TOTP code not invalidated after use — CWE-294

- Why: Replay of a used TOTP code within its validity window must be rejected; absence of nonce tracking enables replay.
- Grep: `totp.*verify|pyotp.*verify` (check for cache/nonce tracking of used codes)
- File globs: `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

### MFA bypassed via account recovery — CWE-287

- Why: If account recovery (password reset email) logs the user in without requiring MFA, it is an effective MFA bypass.
- Grep: `password.*reset|account.*recovery|forgot.*password` (check whether MFA is enforced post-reset)
- File globs: `**/*.py`, `**/*.rb`, `**/*.js`, `**/*.ts`, `**/*.go`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

### Recovery codes stored in plaintext — CWE-312

- Why: Recovery codes are equivalent to passwords; they must be hashed at rest.
- Grep: `recovery_code|backup_code` (check for plaintext storage or weak encoding)
- File globs: `**/*.py`, `**/*.rb`, `**/*.go`, `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

## Secure patterns

TOTP verification with replay prevention (pyotp):

```python
import pyotp, time
from django.core.cache import cache

TOTP_VALID_WINDOW = 1   # ±1 step (30s each side) per RFC 6238 recommendation

def verify_totp(user, code: str) -> bool:
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=TOTP_VALID_WINDOW):
        return False
    # Replay prevention: cache the used code for the validity window
    cache_key = f'totp_used:{user.id}:{code}'
    if cache.get(cache_key):
        return False   # already used
    cache.set(cache_key, True, timeout=90)  # 3 windows of 30s
    return True
```

Source: https://datatracker.ietf.org/doc/html/rfc6238#section-5.2

Recovery code generation and hashing:

```python
import secrets, bcrypt

def generate_recovery_codes(n: int = 10) -> list[str]:
    codes = [secrets.token_urlsafe(10) for _ in range(n)]
    hashes = [bcrypt.hashpw(c.encode(), bcrypt.gensalt()).decode() for c in codes]
    # Store hashes in DB; return plaintext codes once to the user
    save_recovery_hashes(hashes)
    return codes

def consume_recovery_code(user, submitted: str) -> bool:
    for stored_hash in user.recovery_code_hashes:
        if bcrypt.checkpw(submitted.encode(), stored_hash.encode()):
            delete_recovery_code(stored_hash)   # single-use
            return True
    return False
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

WebAuthn registration (server-side, py_webauthn):

```python
from webauthn import generate_registration_options, verify_registration_response

options = generate_registration_options(
    rp_id='example.com',
    rp_name='Example',
    user_id=user.id.bytes,
    user_name=user.email,
)
# ... send options to client, receive credential ...
verification = verify_registration_response(
    credential=credential,
    expected_challenge=session['webauthn_challenge'],
    expected_rp_id='example.com',
    expected_origin='https://example.com',
)
```

Source: https://pages.nist.gov/800-63-3/sp800-63b.html#sec5

## Fix recipes

### Recipe: Add replay prevention to TOTP — addresses CWE-294

**Before (dangerous):**

```python
totp = pyotp.TOTP(user.totp_secret)
if totp.verify(submitted_code):
    grant_access()
```

**After (safe):**

```python
if verify_totp(user, submitted_code):   # includes replay cache check
    grant_access()
```

Source: https://datatracker.ietf.org/doc/html/rfc6238#section-5.2

### Recipe: Hash recovery codes at rest — addresses CWE-312

**Before (dangerous):**

```python
user.recovery_codes = json.dumps(recovery_codes)   # plaintext
```

**After (safe):**

```python
user.recovery_code_hashes = json.dumps([
    bcrypt.hashpw(c.encode(), bcrypt.gensalt()).decode() for c in recovery_codes
])
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

### Recipe: Enforce MFA after password reset — addresses CWE-287

**Before (dangerous):**

```python
def password_reset_complete(request, user):
    login(request, user)   # MFA bypassed
    return redirect('/dashboard')
```

**After (safe):**

```python
def password_reset_complete(request, user):
    # Do not log in directly; require MFA step
    request.session['pending_user_id'] = user.id
    request.session['pending_since'] = time.time()
    return redirect('/mfa/challenge')
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

## Version notes

- NIST SP 800-63B (2017, with 2019 and 2024 supplement) classifies SMS OTP as a restricted authenticator at AAL1; use WebAuthn or TOTP for AAL2 requirements.
- FIDO2/WebAuthn is the NIST-preferred phishing-resistant authenticator for AAL3; hardware security keys (e.g. YubiKey) satisfy AAL3 when combined with PIN or biometric.
- RFC 6238 recommends a tolerance of at most one time step (30 seconds) either side of the current time to account for clock skew.

## Common false positives

- `valid_window=1` in TOTP verification — this is the recommended value per RFC 6238; flag only if value is 3 or higher.
- SMS OTP used as a second factor alongside a stronger primary — if the application offers WebAuthn as an alternative and SMS is a fallback, note the weaker path but do not flag as critical.
- Recovery codes not hashed when they are one-time tokens delivered out of band (e.g. printed at enrollment) with no server-side storage — not applicable; flag only when codes are stored server-side.
