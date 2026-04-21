# TLS Best Current Practices

## Source

- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325: Recommendations for Secure Use of TLS and DTLS (TLS BCP)
- https://ssl-config.mozilla.org/ — Mozilla SSL Configuration Generator
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A02:2021 Cryptographic Failures)
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html — OWASP Transport Layer Protection Cheat Sheet

## Scope

Covers TLS version selection, cipher suite configuration, forward secrecy, and OCSP stapling for servers. Applies to nginx, Apache, HAProxy, and any TLS-terminating component. Does not cover certificate lifecycle (see cert-rotation.md) or HSTS headers (see hsts-hpkp.md).

## Dangerous patterns (regex/AST hints)

### TLS 1.0 or 1.1 enabled — CWE-326

- Why: TLS 1.0 and 1.1 are vulnerable to POODLE, BEAST, and other protocol attacks; both are deprecated per RFC 9325 Section 4.
- Grep: `TLSv1\b|TLSv1\.1|ssl_protocols.*TLSv1[^.]|ssl_protocols.*SSLv`
- File globs: `**/*.conf`, `**/*.cfg`, `**/*.nginx`, `**/*.yaml`, `**/*.py`, `**/*.go`
- Source: https://datatracker.ietf.org/doc/html/rfc9325#section-4

### SSLv2 or SSLv3 enabled — CWE-326

- Why: SSLv2 and SSLv3 are cryptographically broken (DROWN, POODLE); should never be enabled.
- Grep: `SSLv2|SSLv3|ssl_protocols.*SSLv`
- File globs: `**/*.conf`, `**/*.cfg`, `**/*.nginx`
- Source: https://datatracker.ietf.org/doc/html/rfc9325#section-4

### Weak or export cipher suites — CWE-327

- Why: RC4, DES, 3DES, NULL, EXPORT, and ANON cipher suites have known weaknesses; RFC 9325 prohibits their use.
- Grep: `RC4|DES|NULL|EXPORT|ANON|ADH|aNULL|eNULL|3DES`
- File globs: `**/*.conf`, `**/*.cfg`, `**/*.nginx`, `**/*.yaml`
- Source: https://datatracker.ietf.org/doc/html/rfc9325#section-4.2

### TLS certificate verification disabled — CWE-295

- Why: Disabling certificate verification removes authentication of the remote peer; trivially exploitable via MITM.
- Grep: `verify=False|CERT_NONE|InsecureRequestWarning|tls_verify.*false|ssl_verify.*false|InsecureSkipVerify.*true`
- File globs: `**/*.py`, `**/*.go`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

### No forward secrecy (non-ECDHE/DHE key exchange) — CWE-311

- Why: Without forward secrecy, recording encrypted traffic today allows decryption if the server private key is later compromised.
- Grep: `!ECDHE|!DHE|RSA:` (cipher strings that exclude ECDHE/DHE)
- File globs: `**/*.conf`, `**/*.nginx`
- Source: https://datatracker.ietf.org/doc/html/rfc9325#section-4.2

## Secure patterns

Mozilla Intermediate configuration (nginx — TLS 1.2 + 1.3, broad compatibility):

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

Source: https://ssl-config.mozilla.org/

Mozilla Modern configuration (nginx — TLS 1.3 only, highest security):

```nginx
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

Source: https://ssl-config.mozilla.org/

Python requests with enforced TLS and CA verification:

```python
import requests

response = requests.get(
    'https://api.example.com/data',
    verify=True,       # default; never set to False in production
    timeout=10,
)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

## Fix recipes

### Recipe: Remove deprecated TLS versions — addresses CWE-326

**Before (dangerous):**

```nginx
ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
```

**After (safe):**

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

Source: https://datatracker.ietf.org/doc/html/rfc9325#section-4

### Recipe: Remove weak cipher suites — addresses CWE-327

**Before (dangerous):**

```nginx
ssl_ciphers ALL:!aNULL:!eNULL:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP;
```

**After (safe):**

```nginx
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
```

Source: https://ssl-config.mozilla.org/

### Recipe: Re-enable TLS certificate verification — addresses CWE-295

**Before (dangerous):**

```python
import requests
response = requests.get(url, verify=False)
```

**After (safe):**

```python
import requests
response = requests.get(url, verify=True)   # or pass CA bundle path
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

### Recipe: Enable OCSP stapling — addresses CWE-295

**Before (missing):**

```nginx
# No OCSP stapling configured
```

**After (safe):**

```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
```

Source: https://ssl-config.mozilla.org/

## Version notes

- RFC 9325 (published 2022) obsoletes RFC 7525; it formally deprecates TLS 1.0, TLS 1.1, and all DTLS versions prior to 1.2.
- TLS 1.3 removes all non-forward-secret key exchange modes and all CBC cipher suites; use Mozilla Modern config when all clients support TLS 1.3.
- `ssl_session_tickets off` disables TLS session tickets, which can undermine forward secrecy if the ticket key is not rotated frequently; Mozilla recommends disabling them unless ticket key rotation is implemented.

## Common false positives

- `TLSv1.2` appearing in a disable/exclude directive — verify whether TLS 1.2 is being disabled (dangerous) or whether the line is allowlisting only 1.2+ (safe).
- `verify=False` in test fixtures with local self-signed certificates — flag only in production code paths; check for `if settings.DEBUG` guards.
- Old cipher string in a comment or documentation — not an active configuration; confirm it is not imported elsewhere.
