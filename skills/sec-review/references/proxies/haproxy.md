# HAProxy

## Source

- https://docs.haproxy.org/2.8/configuration.html — HAProxy 2.8 Configuration Manual
- https://www.haproxy.org/download/2.8/doc/configuration.txt — HAProxy 2.8 configuration.txt (authoritative)
- https://ssl-config.mozilla.org/ — Mozilla SSL Configuration Generator
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html — OWASP HTTP Headers Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html — OWASP TLS Cheat Sheet
- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325: Recommendations for Secure Use of TLS

## Scope

Covers HAProxy 2.4 LTS through 2.8 LTS in HTTP reverse-proxy and TCP load-balancer roles. Applies to `haproxy.cfg` and any included configuration fragments. Does not cover HAProxy Data Plane API, HAProxy Kubernetes Ingress Controller specifics, or the HAPEE commercial variant beyond standard directives.

## Dangerous patterns (regex/AST hints)

### Pattern 1 — Weak bind ciphers or missing ssl-min-ver on frontend  — CWE-326

- Why: Without `ssl-min-ver TLSv1.2` on `bind` lines, HAProxy may negotiate TLS 1.0/1.1 with clients. Without a restricted `ciphers` (TLS 1.2) and `ciphersuites` (TLS 1.3) list, weak ciphers remain available.
- Grep: `bind\s+.*ssl` without `ssl-min-ver` or `ciphers` on the same or following line
- File globs: `haproxy.cfg`, `*.cfg`
- Source: https://datatracker.ietf.org/doc/html/rfc9325

### Pattern 2 — stats socket with world-readable permissions  — CWE-732

- Why: `stats socket /run/haproxy/admin.sock mode 666` allows any local user to issue admin commands (disable servers, drain connections, change weights), equivalent to unauthenticated admin access.
- Grep: `stats\s+socket.*mode\s+6[67][67]`
- File globs: `haproxy.cfg`, `*.cfg`
- Source: https://docs.haproxy.org/2.8/configuration.html#3.1-stats%20socket

### Pattern 3 — Admin ACL based solely on src IP without ssl client cert  — CWE-284

- Why: `acl is_admin src 10.0.0.0/8` used as the sole guard on an admin backend is bypassable via IP spoofing on L3 or when HAProxy sits behind another load balancer that rewrites the source IP. Should be combined with mTLS or an explicit trusted-proxy header check.
- Grep: `acl\s+\w+\s+src\s+` combined with `use_backend.*admin`
- File globs: `haproxy.cfg`, `*.cfg`
- Source: https://docs.haproxy.org/2.8/configuration.html#7.1-acl

### Pattern 4 — HTTP smuggling risk: missing http-request reject on bad framing  — CWE-444

- Why: Without `option http-server-close` (or `option httpclose`) and reject rules for ambiguous `Content-Length`/`Transfer-Encoding` headers, HAProxy may forward malformed requests that desync a keep-alive backend, enabling request smuggling.
- Grep: absence of `option http-server-close` or `option httpclose` in `defaults` or `frontend` sections
- File globs: `haproxy.cfg`, `*.cfg`
- Source: https://docs.haproxy.org/2.8/configuration.html#4-option%20http-server-close

### Pattern 5 — Peers replication over plaintext TCP  — CWE-319

- Why: `peers` blocks used for stick-table replication send session data (client IPs, counters) in cleartext if `shards` or `bind` lines lack `ssl` qualifier, allowing eavesdropping in multi-node deployments.
- Grep: `bind\s+\S+\s*$` inside a `peers` block (no `ssl` on the line)
- File globs: `haproxy.cfg`, `*.cfg`
- Source: https://docs.haproxy.org/2.8/configuration.html#3.5

## Secure patterns

```haproxy
# TLS bind — Mozilla Intermediate profile
frontend https_in
    bind :443 ssl crt /etc/haproxy/certs/ \
        ssl-min-ver TLSv1.2 \
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384 \
        ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 \
        no-sslv3 no-tlsv10 no-tlsv11
```

Source: https://ssl-config.mozilla.org/

```haproxy
# stats socket — restricted to haproxy group only
global
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
```

Source: https://docs.haproxy.org/2.8/configuration.html#3.1-stats%20socket

```haproxy
# Stick-table rate limiting (brute force mitigation)
frontend http_in
    stick-table type ip size 200k expire 30s store conn_cur,http_req_rate(10s),http_err_rate(10s)
    acl too_many_req sc_http_req_rate(0) gt 100
    http-request deny deny_status 429 if too_many_req
```

Source: https://docs.haproxy.org/2.8/configuration.html#7.3.2-sc_http_req_rate

```haproxy
# Enforce HTTP/1.1 connection close and reject smuggling-prone headers
defaults
    option http-server-close
    option forwardfor
    http-request deny if { req.hdr_cnt(content-length) gt 1 }
    http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
```

Source: https://docs.haproxy.org/2.8/configuration.html#4-option%20http-server-close

## Fix recipes

### Recipe: Harden bind TLS to TLS 1.2+  — addresses CWE-326

**Before (dangerous):**

```haproxy
frontend https_in
    bind :443 ssl crt /etc/haproxy/certs/site.pem
    # No ssl-min-ver — TLSv1.0 and TLSv1.1 may be negotiated
```

**After (safe):**

```haproxy
frontend https_in
    bind :443 ssl crt /etc/haproxy/certs/site.pem \
        ssl-min-ver TLSv1.2 \
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384 \
        ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
```

Source: https://datatracker.ietf.org/doc/html/rfc9325

### Recipe: Restrict stats socket permissions  — addresses CWE-732

**Before (dangerous):**

```haproxy
global
    stats socket /run/haproxy/admin.sock mode 666 level admin
```

**After (safe):**

```haproxy
global
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    # Ensure haproxy process runs as haproxy:haproxy; add operator to haproxy group
```

Source: https://docs.haproxy.org/2.8/configuration.html#3.1-stats%20socket

### Recipe: Add HTTP smuggling defenses  — addresses CWE-444

**Before (dangerous):**

```haproxy
defaults
    mode http
    option http-keep-alive
    # No duplicate-header rejection
```

**After (safe):**

```haproxy
defaults
    mode http
    option http-server-close
    http-request deny if { req.hdr_cnt(content-length) gt 1 }
    http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
```

Source: https://docs.haproxy.org/2.8/configuration.html#4-option%20http-server-close

### Recipe: Enable stick-table rate limiting  — addresses CWE-307

**Before (dangerous):**

```haproxy
frontend http_in
    bind :80
    default_backend servers
    # No rate limiting
```

**After (safe):**

```haproxy
frontend http_in
    bind :80
    stick-table type ip size 100k expire 60s store http_req_rate(10s)
    acl abuse sc0_http_req_rate gt 200
    http-request track-sc0 src
    http-request deny deny_status 429 if abuse
    default_backend servers
```

Source: https://docs.haproxy.org/2.8/configuration.html#7.3.2-sc_http_req_rate

## Version notes

- `ssl-min-ver TLSv1.2` is available from HAProxy 1.8+. On 1.6/1.7, use `no-tlsv10 no-tlsv11 no-sslv3` bind options instead.
- `ciphersuites` (TLS 1.3 cipher list) is available from HAProxy 2.0+ compiled against OpenSSL 1.1.1+.
- `http-request deny if { req.hdr_cnt(...) gt 1 }` requires HAProxy 2.2+ for the `hdr_cnt` fetch with `gt` comparator; use `http-request deny if { req.hdr_cnt(...) -m int gt 1 }` on 2.0.
- HAProxy 2.6+ introduces `http-request set-header` with `if { ssl_fc }` for inserting `Strict-Transport-Security` headers at the proxy layer without application changes.

## Common false positives

- `stats socket ... mode 666` on a host where the only local users are container processes running as the same UID — risk is reduced but not eliminated; flag with medium confidence.
- `acl is_admin src` patterns that are ANDed with a second condition (e.g., `acl has_cert ssl_c_used`) — combined check may be adequate; review the full ACL chain before flagging.
- `option http-keep-alive` in backends rather than frontends — keep-alive to backends is not the smuggling vector; the risk is on the frontend-to-HAProxy leg with a downstream load balancer.
