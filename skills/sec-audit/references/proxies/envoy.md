# Envoy Proxy

## Source

- https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto — TLS common proto reference
- https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/http_connection_manager — HTTP Connection Manager filter
- https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter — ext_authz HTTP filter
- https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter — RBAC HTTP filter
- https://www.envoyproxy.io/docs/envoy/latest/operations/admin — Admin interface documentation
- https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge — Envoy edge proxy best practices
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html — OWASP TLS Cheat Sheet
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — OWASP SSRF Prevention Cheat Sheet
- https://datatracker.ietf.org/doc/html/rfc9325 — RFC 9325: Recommendations for Secure Use of TLS

## Scope

Covers Envoy Proxy 1.26+ in edge-proxy and sidecar roles, configured via static bootstrap YAML or xDS/gRPC management plane. Applies to bootstrap YAML files and Envoy-generated configs from control planes (Istio, Consul Connect). Does not cover Envoy Mobile or the Envoy gRPC transcoder in depth; does not cover Istio-specific `VirtualService`/`DestinationRule` CRDs beyond noting their xDS relationship.

## Dangerous patterns (regex/AST hints)

### Pattern 1 — TLS minimum version below TLS 1.2 in common_tls_context  — CWE-326

- Why: Setting `tls_minimum_protocol_version: TLSv1_0` or `TLSv1_1` in `DownstreamTlsContext` or `UpstreamTlsContext` allows negotiation of deprecated, broken protocols.
- Grep: `tls_minimum_protocol_version:\s*TLSv1_[01]` or absence of `tls_minimum_protocol_version` with a `tls_params` block
- File globs: `*.yaml`, `*.yml`, `envoy.yaml`, `bootstrap.yaml`
- Source: https://datatracker.ietf.org/doc/html/rfc9325

### Pattern 2 — ext_authz with failure_mode_allow: true  — CWE-285

- Why: `failure_mode_allow: true` in the `ext_authz` filter configuration causes Envoy to allow all requests when the authorization service is unavailable. This is a fail-open posture: an outage of the auth backend becomes a complete authentication bypass.
- Grep: `failure_mode_allow:\s*true`
- File globs: `*.yaml`, `*.yml`
- Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter

### Pattern 3 — Admin interface bound to 0.0.0.0  — CWE-16

- Why: `address: 0.0.0.0` in the `admin:` block exposes the Envoy admin API (stats, config dump, health controls, log-level changes) to all network interfaces, including public ones. The admin interface has no authentication.
- Grep: `admin:` block with `address:\s*0\.0\.0\.0` or `socket_address.*0\.0\.0\.0` under `admin`
- File globs: `*.yaml`, `*.yml`, `envoy.yaml`
- Source: https://www.envoyproxy.io/docs/envoy/latest/operations/admin

### Pattern 4 — xff_num_trusted_hops set to 0 or absent at edge  — CWE-346

- Why: At an edge (internet-facing) proxy, `xff_num_trusted_hops: 0` (or the field absent, which defaults to 0) tells the HTTP connection manager not to pop any `X-Forwarded-For` entries, so the full untrusted XFF chain is passed to upstreams. Upstreams that consume `X-Forwarded-For` for access control or logging will see attacker-controlled IPs.
- Grep: `xff_num_trusted_hops:\s*0` or absence of `xff_num_trusted_hops` in a listener serving external traffic
- File globs: `*.yaml`, `*.yml`
- Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/http_connection_manager

### Pattern 5 — HTTP/2 without concurrent-stream or reset-stream limits (CVE-2023-44487)  — CWE-400

- Why: Envoy versions prior to 1.27.1 / 1.26.5 are vulnerable to the Rapid Reset HTTP/2 DDoS (CVE-2023-44487). Even on patched versions, absence of `max_concurrent_streams` and `max_requests_per_io_cycle` in `http2_protocol_options` leaves resource consumption unbounded.
- Grep: `http2_protocol_options:` without `max_concurrent_streams` or `max_requests_per_io_cycle`
- File globs: `*.yaml`, `*.yml`
- Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/http_connection_manager

### Pattern 6 — Router debug headers not stripped on edge listener  — CWE-200

- Why: The Envoy router filter by default passes `x-envoy-*` internal headers to upstream services and may reflect them to downstream clients. `x-envoy-upstream-service-time` leaks backend latency; `x-envoy-overloaded` leaks capacity signals. On edge listeners, these should be suppressed.
- Grep: absence of `suppress_envoy_headers: true` in the `router` HTTP filter config on an edge listener
- File globs: `*.yaml`, `*.yml`
- Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge

## Secure patterns

```yaml
# DownstreamTlsContext — TLS 1.2+ minimum, strong ciphers
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
    common_tls_context:
      tls_params:
        tls_minimum_protocol_version: TLSv1_2
        tls_maximum_protocol_version: TLSv1_3
        cipher_suites:
          - ECDHE-ECDSA-AES128-GCM-SHA256
          - ECDHE-RSA-AES128-GCM-SHA256
          - ECDHE-ECDSA-AES256-GCM-SHA384
          - ECDHE-RSA-AES256-GCM-SHA384
          - ECDHE-ECDSA-CHACHA20-POLY1305
          - ECDHE-RSA-CHACHA20-POLY1305
```

Source: https://datatracker.ietf.org/doc/html/rfc9325

```yaml
# Admin bound to loopback only
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
```

Source: https://www.envoyproxy.io/docs/envoy/latest/operations/admin

```yaml
# ext_authz — fail-closed
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      failure_mode_allow: false
      grpc_service:
        envoy_grpc:
          cluster_name: ext_authz_cluster
```

Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter

```yaml
# HTTP/2 stream limits (CVE-2023-44487 mitigation)
http2_protocol_options:
  max_concurrent_streams: 100
  max_requests_per_io_cycle: 1
```

Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/http_connection_manager

```yaml
# Edge router — strip internal headers
http_filters:
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
      suppress_envoy_headers: true
```

Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge

## Fix recipes

### Recipe: Set TLS minimum version to TLS 1.2  — addresses CWE-326

**Before (dangerous):**

```yaml
common_tls_context:
  tls_params:
    tls_minimum_protocol_version: TLSv1_0
```

**After (safe):**

```yaml
common_tls_context:
  tls_params:
    tls_minimum_protocol_version: TLSv1_2
    tls_maximum_protocol_version: TLSv1_3
```

Source: https://datatracker.ietf.org/doc/html/rfc9325

### Recipe: Harden ext_authz to fail-closed  — addresses CWE-285

**Before (dangerous):**

```yaml
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    failure_mode_allow: true
```

**After (safe):**

```yaml
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    failure_mode_allow: false
```

Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter

### Recipe: Bind admin to loopback  — addresses CWE-16

**Before (dangerous):**

```yaml
admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 9901
```

**After (safe):**

```yaml
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
```

Source: https://www.envoyproxy.io/docs/envoy/latest/operations/admin

### Recipe: Add HTTP/2 stream limits for Rapid Reset mitigation  — addresses CWE-400

**Before (dangerous):**

```yaml
http_filters:
  - name: envoy.filters.http.router
# http2_protocol_options absent — no stream concurrency cap
```

**After (safe):**

```yaml
http2_protocol_options:
  max_concurrent_streams: 100
  max_requests_per_io_cycle: 1
  initial_stream_window_size: 65536
  initial_connection_window_size: 1048576

http_filters:
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
      suppress_envoy_headers: true
```

Source: https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/http_connection_manager

## Version notes

- CVE-2023-44487 (Rapid Reset): patched in Envoy 1.27.1, 1.26.5, 1.25.9, 1.24.10. On older versions, `max_requests_per_io_cycle: 1` is a workaround but impacts throughput; upgrade is the definitive fix.
- `suppress_envoy_headers` is available from Envoy 1.9.0+.
- `tls_minimum_protocol_version` field was present in the v2 API as `TlsParameters.tls_minimum_protocol_version`; the v3 API path is `envoy.extensions.transport_sockets.tls.v3.TlsParameters`.
- `max_requests_per_io_cycle` was introduced in Envoy 1.26 specifically to mitigate HTTP/2 flood patterns; it is not available in earlier releases.
- Istio-managed sidecars expose the admin interface on `127.0.0.1:15000` by default — check that istio-proxy containers do not have a `hostPort` mapping that re-exposes it.

## Common false positives

- `failure_mode_allow: true` in a development or canary deployment where the ext_authz service is not yet available — valid short-term, but must not reach production; flag with high severity if found outside dev context.
- `address: 0.0.0.0` for the admin interface inside a Kubernetes pod with no `hostPort` and no `NodePort` service — reachable only within the pod network; still flag as a defense-in-depth gap.
- `xff_num_trusted_hops: 0` on an internal sidecar that is not internet-facing and where upstream services do their own XFF handling — not a finding in that topology.
- `http2_protocol_options` absent on a listener that is HTTP/1.1-only (no `h2` in ALPN) — not applicable; confirm protocol negotiation before flagging.
