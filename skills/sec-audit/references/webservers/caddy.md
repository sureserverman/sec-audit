# Caddy

## Source

- https://caddyserver.com/docs/caddyfile/directives/tls — Caddy TLS directive reference
- https://caddyserver.com/docs/caddyfile/directives/reverse_proxy — reverse_proxy directive reference
- https://caddyserver.com/docs/caddyfile/directives/file_server — file_server directive reference
- https://caddyserver.com/docs/caddyfile/directives/basicauth — basicauth directive reference
- https://caddyserver.com/docs/caddyfile/directives/header — header directive reference
- https://caddyserver.com/docs/automatic-https — Caddy Automatic HTTPS documentation
- https://ssl-config.mozilla.org/ — Mozilla SSL Configuration Generator
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html — OWASP HTTP Headers Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html — OWASP TLS Cheat Sheet
- https://datatracker.ietf.org/doc/html/rfc6797 — RFC 6797: HTTP Strict Transport Security (HSTS)
- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325: Recommendations for Secure Use of TLS

## Scope

Covers Caddy 2.x (Caddyfile and JSON config API) in web server and reverse-proxy roles. Applies to `Caddyfile`, `*.caddy`, and JSON config files consumed by the Caddy API. Does not cover Caddy 1.x (EOL), xcaddy custom builds, or Caddy's DNS challenge provider plugins beyond basic flags.

## Dangerous patterns (regex/AST hints)

### Pattern 1 — on_demand_tls with unbounded ask endpoint  — CWE-400

- Why: `on_demand` TLS tells Caddy to obtain a certificate for any hostname it receives. Without a restrictive `ask` URL that enforces an allow-list, an attacker can trigger unlimited certificate requests on behalf of arbitrary domains, exhausting ACME rate limits and causing denial-of-service.
- Grep: `on_demand` without adjacent `ask\s+https://`
- File globs: `Caddyfile`, `*.caddy`
- Source: https://caddyserver.com/docs/automatic-https

### Pattern 2 — reverse_proxy trusting all forwarded headers (trusted_proxies)  — CWE-346

- Why: Without `trusted_proxies` configured, Caddy does not validate `X-Forwarded-For` or `X-Real-IP` headers. With an unrestricted or overly broad CIDR in `trusted_proxies`, attacker-controlled headers can spoof client IPs used in logging, rate-limiting, and access-control decisions.
- Grep: `trusted_proxies\s+private_ranges` or `trusted_proxies\s+0\.0\.0\.0/0`
- File globs: `Caddyfile`, `*.caddy`
- Source: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy

### Pattern 3 — file_server with browse (directory listing)  — CWE-548

- Why: `file_server browse` renders an HTML directory index for any path without an index file, exposing filesystem layout and potentially sensitive files.
- Grep: `file_server\s+browse`
- File globs: `Caddyfile`, `*.caddy`
- Source: https://caddyserver.com/docs/caddyfile/directives/file_server

### Pattern 4 — basicauth over a plaintext (HTTP) site  — CWE-319

- Why: If the site block listens on plain HTTP (no TLS directive and no automatic HTTPS because the hostname is an IP or `localhost`) and uses `basicauth`, credentials are transmitted in cleartext Base64.
- Grep: `basicauth` in a block where `tls` directive is absent and the site address is an IP or `http://`
- File globs: `Caddyfile`, `*.caddy`
- Source: https://caddyserver.com/docs/caddyfile/directives/basicauth

### Pattern 5 — disable_redirects suppresses HTTP-to-HTTPS redirect  — CWE-319

- Why: `disable_redirects` in the `tls` block or the global `auto_https` setting prevents Caddy from issuing 301 redirects from HTTP to HTTPS, leaving clients able to use the plaintext endpoint indefinitely.
- Grep: `disable_redirects` or `auto_https\s+disable_redirects`
- File globs: `Caddyfile`, `*.caddy`
- Source: https://caddyserver.com/docs/automatic-https

## Secure patterns

```caddyfile
# TLS with explicit minimum version and Mozilla Intermediate cipher list
example.com {
    tls {
        protocols tls1.2 tls1.3
        ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    }
}
```

Source: https://ssl-config.mozilla.org/

```caddyfile
# Security headers on reverse proxy
example.com {
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Content-Security-Policy "default-src 'self'"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    reverse_proxy localhost:8080
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

```caddyfile
# on_demand TLS with a restrictive ask endpoint
{
    on_demand_tls {
        ask https://internal-allowlist.example.com/check
        interval 2m
        burst 5
    }
}
```

Source: https://caddyserver.com/docs/automatic-https

```caddyfile
# reverse_proxy with explicit trusted proxy CIDR
example.com {
    reverse_proxy backend:8080 {
        trusted_proxies 10.0.0.0/8
        header_up X-Real-IP {remote_host}
    }
}
```

Source: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy

## Fix recipes

### Recipe: Restrict on_demand_tls with an ask URL  — addresses CWE-400

**Before (dangerous):**

```caddyfile
{
    on_demand_tls {
        # No ask URL — any hostname triggers a certificate request
    }
}

:443 {
    tls {
        on_demand
    }
    reverse_proxy localhost:8080
}
```

**After (safe):**

```caddyfile
{
    on_demand_tls {
        ask https://internal-allowlist.example.com/allowed
        interval 1m
        burst 5
    }
}

:443 {
    tls {
        on_demand
    }
    reverse_proxy localhost:8080
}
```

Source: https://caddyserver.com/docs/automatic-https

### Recipe: Add security headers and remove Server header  — addresses CWE-200

**Before (dangerous):**

```caddyfile
example.com {
    reverse_proxy localhost:8080
    # No security headers; Caddy emits "Server: Caddy" by default
}
```

**After (safe):**

```caddyfile
example.com {
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        -Server
    }
    reverse_proxy localhost:8080
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### Recipe: Disable directory browse on file_server  — addresses CWE-548

**Before (dangerous):**

```caddyfile
example.com {
    root * /var/www/html
    file_server browse
}
```

**After (safe):**

```caddyfile
example.com {
    root * /var/www/html
    file_server
    # browse removed; returns 403 or 404 on missing index
}
```

Source: https://caddyserver.com/docs/caddyfile/directives/file_server

### Recipe: Enforce TLS minimum version  — addresses CWE-326

**Before (dangerous):**

```caddyfile
example.com {
    tls cert.pem key.pem
    # protocols not restricted — older Caddy builds default to tls1.0
}
```

**After (safe):**

```caddyfile
example.com {
    tls cert.pem key.pem {
        protocols tls1.2 tls1.3
    }
}
```

Source: https://datatracker.ietf.org/doc/html/rfc9325

## Version notes

- `protocols tls1.2 tls1.3` syntax under the `tls` block applies from Caddy 2.4.0+. Prior 2.x versions use `tls { min_version ... }` in JSON config only.
- Caddy 2.7+ defaults to TLS 1.2 minimum, but explicit configuration is still required for auditability.
- `auto_https disable_redirects` was added in Caddy 2.5; earlier versions have no redirect-suppression option and redirect by default.
- `trusted_proxies private_ranges` is a shorthand added in Caddy 2.7 that expands to RFC 1918 + RFC 4193 ranges — confirm this matches your actual proxy topology before using it.

## Common false positives

- `file_server browse` behind a `basicauth` block where the directory is explicitly meant to be a shared internal file store — access-controlled; lower severity.
- `trusted_proxies private_ranges` is safe when the deployment is entirely within RFC 1918 networks with no public-facing upstream; still confirm the network topology.
- `disable_redirects` in a site block that is HTTP-only by design (e.g., `http://localhost`) — no TLS involved, not a finding.
- `basicauth` without TLS on `localhost` or `127.0.0.1` in a development environment — confirm it is not deployed to production.
