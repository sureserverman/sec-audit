# Apache httpd

## Source

- https://httpd.apache.org/docs/2.4/mod/core.html — Apache httpd 2.4 core directives
- https://httpd.apache.org/docs/2.4/mod/mod_ssl.html — mod_ssl reference
- https://httpd.apache.org/docs/2.4/mod/mod_headers.html — mod_headers reference
- https://httpd.apache.org/docs/2.4/mod/mod_status.html — mod_status reference
- https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html — mod_rewrite reference
- https://httpd.apache.org/docs/2.4/mod/mod_proxy.html — mod_proxy reference
- https://ssl-config.mozilla.org/ — Mozilla SSL Configuration Generator
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html — OWASP HTTP Headers Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html — OWASP TLS Cheat Sheet
- https://datatracker.ietf.org/doc/html/rfc6797 — RFC 6797: HTTP Strict Transport Security (HSTS)
- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325: Recommendations for Secure Use of TLS

## Scope

Covers Apache httpd 2.4.x in standalone and reverse-proxy deployments on Linux. Applies to `httpd.conf`, `apache2.conf`, `sites-available/*.conf`, and `.htaccess` files. Does not cover Apache Traffic Server, Apache Tomcat, or httpd 2.2 (EOL).

## Dangerous patterns (regex/AST hints)

### Pattern 1 — Version and OS disclosure (ServerTokens / ServerSignature)  — CWE-200

- Why: `ServerTokens Full` (the default) exposes the httpd version, OS, and loaded module names in every response header and error page, giving attackers free reconnaissance.
- Grep: `ServerTokens\s+(Full|OS|Major|Minor|Prod)` or absence of `ServerTokens Prod`
- File globs: `*.conf`, `httpd.conf`, `apache2.conf`
- Source: https://httpd.apache.org/docs/2.4/mod/core.html#servertokens

### Pattern 2 — Weak TLS protocol or cipher negotiation  — CWE-326

- Why: `SSLProtocol All` or presence of `SSLv3`, `TLSv1`, `TLSv1.1` allows negotiation of broken protocols. `SSLCipherSuite HIGH` retains 3DES and other legacy ciphers.
- Grep: `SSLProtocol\s+[Aa]ll` or `SSLProtocol.*TLSv1[^.]` or `SSLProtocol.*SSLv`
- File globs: `*.conf`
- Source: https://datatracker.ietf.org/doc/html/rfc9325

### Pattern 3 — Directory listing via Options Indexes  — CWE-548

- Why: `Options Indexes` or `Options +Indexes` causes httpd to serve a generated directory listing when no DirectoryIndex file exists, exposing directory contents.
- Grep: `Options\s+.*\+?Indexes`
- File globs: `*.conf`, `.htaccess`
- Source: https://httpd.apache.org/docs/2.4/mod/core.html#options

### Pattern 4 — mod_status exposed without access control  — CWE-200

- Why: `SetHandler server-status` without a `Require` or `Allow from` restriction exposes runtime server metrics and request data to any client.
- Grep: `SetHandler\s+server-status`
- File globs: `*.conf`
- Source: https://httpd.apache.org/docs/2.4/mod/mod_status.html

### Pattern 5 — Path traversal in RewriteRule (unanchored patterns)  — CWE-22

- Why: RewriteRule patterns without `^` anchor or without `[L]` flag can be chained to rewrite request URIs into unintended paths. Unescaped back-references with `$1` passed to `ProxyPass` enable open-proxy traversal (CVE-2021-40438 class).
- Grep: `RewriteRule\s+[^"]*\$[0-9]` combined with `ProxyPass` or `P` flag
- File globs: `*.conf`, `.htaccess`
- Source: https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html

### Pattern 6 — TRACE method enabled  — CWE-16

- Why: HTTP TRACE allows cross-site tracing (XST) attacks that can expose cookies and auth headers even when `HttpOnly` is set, if a browser-level XSS can trigger a TRACE request.
- Grep: `TraceEnable\s+[Oo]n` or absence of `TraceEnable Off`
- File globs: `*.conf`
- Source: https://httpd.apache.org/docs/2.4/mod/core.html#traceenable

## Secure patterns

```apache
# Minimal version disclosure
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

Source: https://httpd.apache.org/docs/2.4/mod/core.html#servertokens

```apache
# TLS — Mozilla Intermediate profile
SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder     off
SSLSessionTickets       off
```

Source: https://ssl-config.mozilla.org/

```apache
# Security headers
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

```apache
# Disable directory listing globally, then allow per-directory
<Directory />
    Options -Indexes
    AllowOverride None
</Directory>
```

Source: https://httpd.apache.org/docs/2.4/mod/core.html#options

```apache
# mod_status locked to localhost
<Location "/server-status">
    SetHandler server-status
    Require local
</Location>
```

Source: https://httpd.apache.org/docs/2.4/mod/mod_status.html

## Fix recipes

### Recipe: Suppress version disclosure  — addresses CWE-200

**Before (dangerous):**

```apache
# Default — ServerTokens not set; emits "Apache/2.4.54 (Ubuntu)"
ServerSignature On
```

**After (safe):**

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

Source: https://httpd.apache.org/docs/2.4/mod/core.html#servertokens

### Recipe: Restrict TLS to 1.2 and 1.3  — addresses CWE-326

**Before (dangerous):**

```apache
SSLProtocol All
SSLCipherSuite HIGH:!aNULL
```

**After (safe):**

```apache
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off
SSLSessionTickets off
```

Source: https://ssl-config.mozilla.org/

### Recipe: Disable directory indexes and tighten AllowOverride  — addresses CWE-548

**Before (dangerous):**

```apache
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride All
</Directory>
```

**After (safe):**

```apache
<Directory "/var/www/html">
    Options -Indexes +FollowSymLinks
    AllowOverride None
</Directory>
```

Source: https://httpd.apache.org/docs/2.4/mod/core.html#options

### Recipe: Close open-proxy RewriteRule (CVE-2021-40438 class)  — addresses CWE-918

**Before (dangerous):**

```apache
RewriteEngine On
RewriteRule "^/proxy/(.*)" "http://$1" [P,L]
```

**After (safe — fixed upstream, no user-controlled host):**

```apache
RewriteEngine On
# Only proxy to known internal backend; user input only supplies the path
RewriteRule "^/api/(.*)" "http://internal-backend.local/$1" [P,L]
ProxyPassReverse "/api/" "http://internal-backend.local/"
```

Source: https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html

## Version notes

- `SSLSessionTickets off` requires mod_ssl built against OpenSSL 0.9.8f+ and httpd >= 2.4.11.
- `Header always set` requires `mod_headers` to be loaded (`LoadModule headers_module`). Verify with `apachectl -M | grep headers`.
- CVE-2021-40438 (mod_proxy SSRF via crafted `uri-path`) affects httpd 2.4.0–2.4.48; patch to 2.4.49+ and restrict RewriteRule back-references.
- `.htaccess` overrides are evaluated per-request and can negate server-level `Options -Indexes` if `AllowOverride Options` or `AllowOverride All` is set in the parent `Directory` block.

## Common false positives

- `Options Indexes` inside a `<Directory>` block protected by `Require valid-user` — listing is access-controlled; still worth noting but lower severity.
- `SetHandler server-status` with `Require ip 127.0.0.1 ::1` — properly restricted; not a finding.
- `SSLProtocol TLSv1` in a legacy internal-only vhost serving non-browser TLS clients with known constraints — document the exception, but do not auto-flag without context.
- `AllowOverride All` in development-environment configs clearly scoped to `localhost` — flag with low confidence.
