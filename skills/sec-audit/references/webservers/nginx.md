# nginx

## Source

- https://nginx.org/en/docs/http/ngx_http_core_module.html — ngx_http_core_module reference
- https://nginx.org/en/docs/http/ngx_http_ssl_module.html — ngx_http_ssl_module reference
- https://nginx.org/en/docs/http/ngx_http_limit_req_module.html — ngx_http_limit_req_module reference
- https://nginx.org/en/docs/http/ngx_http_proxy_module.html — ngx_http_proxy_module reference
- https://nginx.org/en/docs/http/ngx_http_autoindex_module.html — ngx_http_autoindex_module reference
- https://ssl-config.mozilla.org/ — Mozilla SSL Configuration Generator
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html — OWASP HTTP Headers Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html — OWASP CSP Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — OWASP SSRF Prevention Cheat Sheet
- https://datatracker.ietf.org/doc/html/rfc6797 — RFC 6797: HTTP Strict Transport Security (HSTS)
- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325: Recommendations for Secure Use of TLS

## Scope

Covers nginx stable releases (1.18+) and mainline (1.25+) in HTTP server, reverse-proxy, and load-balancer roles. Applies to `nginx.conf`, virtual-host includes, and `conf.d/*.conf` files. Does not cover nginx Unit, nginx Plus-specific modules, or the Lua/njs scripting layers beyond basic pattern hints.

## Dangerous patterns (regex/AST hints)

### Pattern 1 — Version disclosure via server_tokens  — CWE-200

- Why: Default `server_tokens on` emits nginx version in `Server` response headers and error pages, aiding attacker reconnaissance.
- Grep: `server_tokens\s+on`
- File globs: `*.conf`, `nginx.conf`
- Source: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens

### Pattern 2 — Weak or missing TLS protocol/cipher configuration  — CWE-326

- Why: Omitting `ssl_protocols` allows nginx to negotiate TLS 1.0/1.1 on older builds. Omitting `ssl_ciphers` retains defaults that include 3DES and RC4 on older OpenSSL versions.
- Grep: `ssl_protocols\s+.*TLSv1[^.]` or absence of `ssl_protocols` in an `ssl on` context
- File globs: `*.conf`
- Source: https://datatracker.ietf.org/doc/html/rfc9325

### Pattern 3 — Directory listing enabled (autoindex)  — CWE-548

- Why: `autoindex on` exposes full directory trees to unauthenticated clients when no index file is present.
- Grep: `autoindex\s+on`
- File globs: `*.conf`
- Source: https://nginx.org/en/docs/http/ngx_http_autoindex_module.html

### Pattern 4 — Unbounded request body (client_max_body_size 0)  — CWE-400

- Why: Setting `client_max_body_size 0` disables the upload size limit, enabling denial-of-service via large request bodies.
- Grep: `client_max_body_size\s+0`
- File globs: `*.conf`
- Source: https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size

### Pattern 5 — SSRF via proxy_pass with variable argument  — CWE-918

- Why: `proxy_pass http://$arg_target` or `proxy_pass $scheme://$http_host` lets user-controlled input dictate the upstream, enabling Server-Side Request Forgery to internal services.
- Grep: `proxy_pass\s+[^"]*\$arg_` or `proxy_pass\s+[^"]*\$http_`
- File globs: `*.conf`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Pattern 6 — Missing rate limiting on auth/API endpoints  — CWE-307

- Why: Without `limit_req_zone` + `limit_req`, brute-force and credential-stuffing attacks are unbounded.
- Grep: absence of `limit_req` in a `location` block that handles `/login`, `/auth`, or `/api`
- File globs: `*.conf`
- Source: https://nginx.org/en/docs/http/ngx_http_limit_req_module.html

## Secure patterns

```nginx
# TLS — Mozilla Intermediate profile (nginx 1.18+)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_session_tickets off;
```

Source: https://ssl-config.mozilla.org/

```nginx
# Security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
server_tokens off;
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

```nginx
# Rate limiting on auth endpoint
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

server {
    location /login {
        limit_req zone=login burst=10 nodelay;
        proxy_pass http://backend;
    }
}
```

Source: https://nginx.org/en/docs/http/ngx_http_limit_req_module.html

```nginx
# Proxy pass — fixed upstream (no variable), trailing slash consistent
location /api/ {
    proxy_pass http://backend_upstream/api/;
}
```

Source: https://nginx.org/en/docs/http/ngx_http_proxy_module.html

## Fix recipes

### Recipe: Enable server_tokens off and harden headers  — addresses CWE-200

**Before (dangerous):**

```nginx
http {
    # server_tokens not set — defaults to on
    server {
        listen 443 ssl;
    }
}
```

**After (safe):**

```nginx
http {
    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    server {
        listen 443 ssl;
    }
}
```

Source: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens

### Recipe: Restrict TLS to 1.2 and 1.3 with Mozilla Intermediate ciphers  — addresses CWE-326

**Before (dangerous):**

```nginx
ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers HIGH:!aNULL:!MD5;
```

**After (safe):**

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_tickets off;
```

Source: https://ssl-config.mozilla.org/

### Recipe: Disable autoindex  — addresses CWE-548

**Before (dangerous):**

```nginx
location /files/ {
    root /var/www;
    autoindex on;
}
```

**After (safe):**

```nginx
location /files/ {
    root /var/www;
    autoindex off;
}
```

Source: https://nginx.org/en/docs/http/ngx_http_autoindex_module.html

### Recipe: Fix proxy_pass alias vs root off-by-one (trailing slash)  — addresses CWE-706

**Before (dangerous — double path segment):**

```nginx
location /app {
    proxy_pass http://backend/app;  # /app/foo -> http://backend/app/app/foo
}
```

**After (safe — slash-consistent):**

```nginx
location /app/ {
    proxy_pass http://backend/app/;
}
```

Source: https://nginx.org/en/docs/http/ngx_http_proxy_module.html

## Version notes

- `ssl_session_tickets off` requires nginx >= 1.5.9. On 1.14 and older, omitting the directive leaves tickets enabled with a randomly generated key that rotates on reload — forward secrecy risk at scale.
- TLSv1.3 support requires nginx >= 1.13.0 compiled against OpenSSL 1.1.1+.
- `limit_req_zone` with `$binary_remote_addr` uses 4 bytes per IPv4 entry and 16 bytes per IPv6 entry; size the shared memory zone accordingly (10m ≈ 160 000 IPv4 states).
- `server_tokens build` (nginx 1.11.10+) also hides the build suffix in addition to the version.

## Common false positives

- `autoindex on` inside a `location` block that also has `auth_basic` or `satisfy all` — exposure is limited to authenticated users; still worth noting but lower severity.
- `client_max_body_size 0` under a location dedicated to large file uploads (e.g. `/upload`) where the intent is explicit — verify business justification before flagging.
- `proxy_pass http://$upstream_name` where `$upstream_name` is set by `map` from a fixed allow-list, not from user input — not SSRF, but confirm the map source.
- `ssl_protocols TLSv1.2 TLSv1.3` with no TLSv1.3 cipher list is fine — TLSv1.3 ciphers are not configurable via `ssl_ciphers` in nginx; the directive only affects TLS 1.2.
