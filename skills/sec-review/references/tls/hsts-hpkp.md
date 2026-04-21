# HSTS, HPKP, and Related Transport Security Headers

## Source

- https://datatracker.ietf.org/doc/html/rfc6797 — RFC 6797: HTTP Strict Transport Security (HSTS)
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security — MDN HSTS
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT — MDN Expect-CT (deprecated)
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html — OWASP HSTS Cheat Sheet

## Scope

Covers `Strict-Transport-Security` (HSTS) header configuration, HSTS preload list requirements, and the deprecated HTTP Public Key Pinning (HPKP) and `Expect-CT` headers. Includes CAA DNS record guidance. Does not cover certificate issuance or rotation (see cert-rotation.md) or cipher suite selection (see tls-bcp.md).

## Dangerous patterns (regex/AST hints)

### HSTS max-age too short — CWE-319

- Why: A short `max-age` means the protection window is small; browsers require at least 1 year (31536000s) for preload eligibility; OWASP recommends >= 2 years.
- Grep: `max-age\s*=\s*[0-9]{1,7}(?!\d)` (matches values < 10000000, i.e. < ~115 days)
- File globs: `**/*.conf`, `**/*.nginx`, `**/*.yaml`, `**/*.py`, `**/*.go`, `**/*.rb`
- Source: https://datatracker.ietf.org/doc/html/rfc6797#section-6.1

### HSTS missing includeSubDomains — CWE-319

- Why: Without `includeSubDomains`, cookies and credentials on subdomains can be intercepted by stripping TLS on a subdomain.
- Grep: `Strict-Transport-Security[^;\n]*(?!includeSubDomains)`
- File globs: `**/*.conf`, `**/*.nginx`, `**/*.py`, `**/*.go`, `**/*.rb`
- Source: https://datatracker.ietf.org/doc/html/rfc6797#section-6.1

### HSTS header set over HTTP — CWE-319

- Why: Browsers ignore HSTS headers received over HTTP (RFC 6797 Section 8.1); header must be sent exclusively over HTTPS.
- Grep: `Strict-Transport-Security` in HTTP (non-SSL) server blocks
- File globs: `**/*.conf`, `**/*.nginx`
- Source: https://datatracker.ietf.org/doc/html/rfc6797#section-8.1

### HPKP header in use — CWE-693 (misconfiguration risk)

- Why: HPKP is deprecated in all major browsers and removed from Chrome 68+; misconfiguration permanently bricks a site. Do not recommend or retain.
- Grep: `Public-Key-Pins`
- File globs: `**/*.conf`, `**/*.nginx`, `**/*.py`, `**/*.go`, `**/*.rb`
- Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins

### Missing CAA DNS record — CWE-295

- Why: Without Certification Authority Authorization (CAA) DNS records, any CA can issue certificates for the domain; CAA restricts issuance to named CAs.
- Grep: `CAA` (grep DNS zone files for absence)
- File globs: `**/*.zone`, `**/*.dns`, `**/dns*.yaml`, `**/dns*.json`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

## Secure patterns

HSTS header — production recommended value:

```nginx
# nginx: send only over HTTPS (ssl) server block
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

- `max-age=63072000` = 2 years.
- `includeSubDomains` protects all subdomains.
- `preload` requests inclusion in browser preload lists (submit to hstspreload.org separately).

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

HSTS in Python (Django middleware):

```python
# settings.py
SECURE_HSTS_SECONDS = 63072000        # 2 years
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

CAA DNS record example:

```dns
example.com. 300 IN CAA 0 issue "letsencrypt.org"
example.com. 300 IN CAA 0 issue "pki.goog"
example.com. 300 IN CAA 0 issuewild ";"  ; prohibit wildcard certs
example.com. 300 IN CAA 0 iodef "mailto:security@example.com"
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

## Fix recipes

### Recipe: Increase HSTS max-age and add includeSubDomains — addresses CWE-319

**Before (weak):**

```nginx
add_header Strict-Transport-Security "max-age=86400";
```

**After (safe):**

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

Source: https://datatracker.ietf.org/doc/html/rfc6797#section-6.1

### Recipe: Remove HPKP header — addresses CWE-693

**Before (dangerous — deprecated):**

```nginx
add_header Public-Key-Pins 'pin-sha256="..."; max-age=2592000; includeSubDomains';
```

**After (safe — remove entirely; rely on CAA + CT instead):**

```nginx
# HPKP removed; Certificate Transparency enforced via CAA and browser policy
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins

### Recipe: Move HSTS to HTTPS-only block — addresses CWE-319

**Before (ineffective — in HTTP server block):**

```nginx
server {
    listen 80;
    add_header Strict-Transport-Security "max-age=63072000";  # ignored over HTTP
}
```

**After (safe — only in HTTPS block):**

```nginx
server {
    listen 80;
    return 301 https://$host$request_uri;   # redirect; no HSTS header here
}
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

Source: https://datatracker.ietf.org/doc/html/rfc6797#section-8.1

## Version notes

- HPKP (`Public-Key-Pins`) was removed from Chrome in version 68 (2018) and from Firefox 72+ (2020); it must not be used in new deployments.
- `Expect-CT` was deprecated in Chrome 107 (2022); all browsers now enforce Certificate Transparency natively. Remove `Expect-CT` headers from existing configs.
- HSTS preload requires `max-age >= 31536000`, `includeSubDomains`, and `preload`; submission is at hstspreload.org. Preload removal is slow (months); ensure all subdomains support HTTPS before submitting.

## Common false positives

- Short `max-age` during HSTS rollout phase (staged deployment, e.g. `max-age=300`) — acceptable as a temporary ramp-up; flag if still short after initial deployment window.
- `includeSubDomains` absent when the domain has HTTP-only subdomains that cannot be migrated — document as accepted risk but still flag.
- `Expect-CT` header present but with `max-age=0` (effectively a no-op) — low risk but should be removed to avoid confusion.
