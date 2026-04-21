# Traefik

## Source

- https://doc.traefik.io/traefik/operations/dashboard/ — Traefik Dashboard documentation
- https://doc.traefik.io/traefik/routing/entrypoints/ — EntryPoints reference
- https://doc.traefik.io/traefik/https/tls/ — TLS configuration reference
- https://doc.traefik.io/traefik/middlewares/http/headers/ — Headers middleware reference
- https://doc.traefik.io/traefik/middlewares/http/ipwhitelist/ — IPWhiteList middleware reference
- https://doc.traefik.io/traefik/middlewares/http/ratelimit/ — RateLimit middleware reference
- https://doc.traefik.io/traefik/middlewares/http/forwardauth/ — ForwardAuth middleware reference
- https://doc.traefik.io/traefik/providers/docker/ — Docker provider reference
- https://doc.traefik.io/traefik/providers/file/ — File provider reference
- https://ssl-config.mozilla.org/ — Mozilla SSL Configuration Generator
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html — OWASP HTTP Headers Cheat Sheet
- https://datatracker.ietf.org/doc/html/rfc6797 — RFC 6797: HTTP Strict Transport Security (HSTS)
- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325: Recommendations for Secure Use of TLS

## Scope

Covers Traefik v2.x and v3.x in reverse-proxy and edge-router roles using the Docker provider, file provider, and static configuration (YAML/TOML). Applies to `traefik.yml`, `traefik.toml`, dynamic configuration files, and Docker label sets. Does not cover Traefik Enterprise, Traefik Mesh (Maesh), or Kubernetes IngressRoute CRDs in depth.

## Dangerous patterns (regex/AST hints)

### Pattern 1 — Dashboard exposed with insecure: true  — CWE-306

- Why: `api.insecure: true` binds the Traefik API and dashboard on a separate entryPoint (default `:8080`) with no authentication, exposing full router/service/middleware topology to any network-reachable client.
- Grep: `insecure:\s*true` under an `api:` key, or `--api.insecure=true` in CLI args
- File globs: `traefik.yml`, `traefik.yaml`, `traefik.toml`, `docker-compose*.yml`
- Source: https://doc.traefik.io/traefik/operations/dashboard/

### Pattern 2 — entryPoints trustedIPs set to 0.0.0.0/0 (trust all forwarders)  — CWE-346

- Why: Setting `forwardedHeaders.trustedIPs: ["0.0.0.0/0"]` causes Traefik to accept `X-Forwarded-For` and `X-Real-IP` from any source, allowing IP spoofing in access-control and rate-limiting logic.
- Grep: `trustedIPs.*0\.0\.0\.0/0` or `insecure:\s*true` under `forwardedHeaders`
- File globs: `traefik.yml`, `traefik.yaml`, `traefik.toml`
- Source: https://doc.traefik.io/traefik/routing/entrypoints/

### Pattern 3 — TLS minimum version below TLS 1.2  — CWE-326

- Why: A `tlsOptions` block with `minVersion: VersionTLS10` or `VersionTLS11`, or with no `minVersion` set (Traefik v2 defaults to TLS 1.0 for compatibility), allows negotiation of deprecated protocols.
- Grep: `minVersion:\s*VersionTLS1[01]` or absence of `minVersion` in a `tls:` options block
- File globs: `traefik.yml`, `traefik.yaml`, `*.yml`, `*.yaml`
- Source: https://datatracker.ietf.org/doc/html/rfc9325

### Pattern 4 — Docker provider with exposedByDefault: true  — CWE-16

- Why: `exposedByDefault: true` (the default) makes every Docker container reachable via Traefik without an explicit `traefik.enable=true` label. Newly deployed containers are automatically exposed before labels are applied.
- Grep: `exposedByDefault:\s*true` or absence of `exposedByDefault: false` in `docker:` provider config
- File globs: `traefik.yml`, `traefik.yaml`, `traefik.toml`
- Source: https://doc.traefik.io/traefik/providers/docker/

### Pattern 5 — Missing HSTS and security headers on HTTPS entryPoint  — CWE-523

- Why: Without the `headers` middleware applying `stsSeconds`, `framedeny`, `contentTypeNosniff`, and `contentSecurityPolicy`, responses from Traefik-proxied services lack transport-security and click-jacking protections.
- Grep: absence of `stsSeconds` or `forceSTSHeader` in any `headers` middleware definition
- File globs: `traefik.yml`, `traefik.yaml`, `*.yml`, `*.yaml`
- Source: https://datatracker.ietf.org/doc/html/rfc6797

## Secure patterns

```yaml
# Static config — secure defaults
api:
  insecure: false
  dashboard: true

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    forwardedHeaders:
      trustedIPs:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"

providers:
  docker:
    exposedByDefault: false
```

Source: https://doc.traefik.io/traefik/routing/entrypoints/

```yaml
# TLS options — Mozilla Intermediate profile
tls:
  options:
    default:
      minVersion: VersionTLS12
      cipherSuites:
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
        - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
      sniStrict: true
```

Source: https://ssl-config.mozilla.org/

```yaml
# Security headers middleware
http:
  middlewares:
    secure-headers:
      headers:
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        forceSTSHeader: true
        frameDeny: true
        contentTypeNosniff: true
        browserXssFilter: true
        referrerPolicy: "strict-origin-when-cross-origin"
        contentSecurityPolicy: "default-src 'self'"
        customResponseHeaders:
          X-Powered-By: ""
          Server: ""
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

## Fix recipes

### Recipe: Disable insecure dashboard and protect with middleware  — addresses CWE-306

**Before (dangerous):**

```yaml
api:
  insecure: true
```

**After (safe — dashboard behind IPWhiteList + basicAuth):**

```yaml
api:
  insecure: false
  dashboard: true

# In dynamic config: expose dashboard router with auth middleware
http:
  routers:
    dashboard:
      rule: "Host(`traefik.example.com`) && (PathPrefix(`/api`) || PathPrefix(`/dashboard`))"
      service: api@internal
      middlewares:
        - dashboard-auth
        - dashboard-ipwl
      tls: {}

  middlewares:
    dashboard-ipwl:
      ipWhiteList:
        sourceRange:
          - "10.0.0.0/8"
    dashboard-auth:
      basicAuth:
        users:
          - "admin:$apr1$..."
```

Source: https://doc.traefik.io/traefik/operations/dashboard/

### Recipe: Set TLS minimum version to 1.2  — addresses CWE-326

**Before (dangerous):**

```yaml
tls:
  options:
    default:
      # minVersion absent — Traefik v2 defaults to VersionTLS10
      cipherSuites:
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

**After (safe):**

```yaml
tls:
  options:
    default:
      minVersion: VersionTLS12
      cipherSuites:
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
        - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
      sniStrict: true
```

Source: https://datatracker.ietf.org/doc/html/rfc9325

### Recipe: Disable Docker exposedByDefault  — addresses CWE-16

**Before (dangerous):**

```yaml
providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    # exposedByDefault not set — defaults to true
```

**After (safe):**

```yaml
providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    # Containers must have traefik.enable=true label to be routed
```

Source: https://doc.traefik.io/traefik/providers/docker/

## Version notes

- Traefik v3.0 changed the default `minVersion` to `VersionTLS12`; v2.x defaults to `VersionTLS10`. Explicitly set `minVersion` for portability across versions.
- `IPWhiteList` middleware was renamed to `IPAllowList` in Traefik v3.0. Both names function in v2.11 (with deprecation warning). Use `IPAllowList` for v3-forward-compatible configs.
- `forwardedHeaders.insecure: true` (trust all forwarders, no IP check) is distinct from the API `insecure` flag — both must be audited separately.
- File provider `watch: true` reloads dynamic config on filesystem changes; ensure the config directory is not world-writable or the config becomes an escalation path.

## Common false positives

- `insecure: true` in a `docker-compose.yml` that is clearly labeled for local development (`profiles: [dev]` or similar) — flag at low severity only.
- `exposedByDefault: false` missing but all containers in the compose file already have `traefik.enable=true` — no current exposure, but future containers would be auto-exposed; flag as informational.
- `trustedIPs: ["0.0.0.0/0"]` when Traefik sits behind a known CDN/WAF that strips and re-injects `X-Forwarded-For` — still a finding unless the CDN is the only network path; document the assumption.
- `sniStrict: false` (the default) is acceptable when a single wildcard certificate covers all routed hostnames — confirm the cert scope before flagging.
