# sing-box — Configuration Hardening

## Source

- https://sing-box.sagernet.org/ — sing-box documentation (canonical)
- https://sing-box.sagernet.org/configuration/ — sing-box config schema reference
- https://sing-box.sagernet.org/configuration/inbound/ — inbound types
- https://sing-box.sagernet.org/configuration/outbound/ — outbound types
- https://sing-box.sagernet.org/configuration/dns/ — DNS configuration
- https://github.com/SagerNet/sing-box — source repo
- https://www.rfc-editor.org/rfc/rfc8484 — DNS-over-HTTPS (DoH)
- https://www.rfc-editor.org/rfc/rfc7858 — DNS-over-TLS (DoT)
- https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final — NIST SP 800-52 r2 (TLS guidelines)

## Scope

Covers sing-box JSON configuration files: inbound listeners
(SOCKS, HTTP, mixed, VLESS, Trojan, Hysteria, Reality, etc.)
and their TLS / authentication settings; outbound rules
(direct, block, dns, selector, urltest, proxy chains);
DNS configuration (DoH / DoT / fallback resolvers); routing
geosite / geoip rules; transport configuration (uTLS,
Reality, gRPC, WebSocket fallbacks); experimental
clash-API exposure. Out of scope: Sing-box Android client
internals (UI / lifecycle); node-deployment infrastructure
(VPS provisioning, certbot integration); Reality SNI target
selection (handled by sec-expert via the existing
`reality-domain-scanner` skill).

## Dangerous patterns (regex/AST hints)

### `inbounds[].listen` bound to `0.0.0.0` for SOCKS / HTTP / mixed inbound — CWE-200

- Why: A SOCKS / HTTP / mixed inbound listener bound to
  `0.0.0.0` (or `::`) on a publicly-routable host is an
  open proxy — any internet user can route their traffic
  through it. Without authentication (the default for SOCKS
  in sing-box), the operator pays the bandwidth bill and
  attracts abuse traffic. The hardened pattern is to bind
  the SOCKS / HTTP / mixed inbound to `127.0.0.1` (loopback,
  for local applications only), expose ONLY the protocol-
  proxy inbounds (VLESS, Trojan, Hysteria, Reality —
  authenticated by design) on the public interface.
- Grep: `"listen"\s*:\s*"(0\.0\.0\.0|::)"` AND the same
  inbound block has `"type"\s*:\s*"(socks|http|mixed)"`.
- File globs: `*.json` under `sing-box/`, `singbox/`,
  `/etc/sing-box/**`.
- Source: https://sing-box.sagernet.org/configuration/inbound/

### Authentication-less SOCKS / HTTP inbound on non-loopback — CWE-306

- Why: sing-box's SOCKS / HTTP / mixed inbounds support
  per-user authentication via `users` array. Default is no
  auth. Combined with a non-loopback listen, this is an open
  proxy. Even with loopback, in multi-user / containerised
  hosts, missing auth means any local process can use the
  proxy.
- Grep: SOCKS / HTTP / mixed inbound block on a non-loopback
  listen with no `"users"` array OR an empty `"users": []`.
- File globs: `*.json`.
- Source: https://sing-box.sagernet.org/configuration/inbound/

### TLS inbound with `insecure: true` — CWE-295

- Why: sing-box's TLS configuration includes an `insecure`
  flag that disables certificate validation. On an outbound
  (client-side) it's the canonical "ignore TLS errors"
  flag — disabling MITM protection. On an inbound, `insecure`
  affects ALPN handling and is occasionally misused. Either
  way, `insecure: true` is the structural disabler of TLS
  guarantees.
- Grep: `"insecure"\s*:\s*true` in any block.
- File globs: `*.json`.
- Source: https://sing-box.sagernet.org/configuration/

### `experimental.clash_api` exposed on non-loopback — CWE-306

- Why: sing-box's clash-compatible API (controllable via
  `experimental.clash_api`) lets a connected client switch
  outbounds, modify routing rules, fetch traffic stats, and
  reload configuration. Bound to a public interface it gives
  any network peer full control over the sing-box instance.
  The hardened pattern is `external_controller:
  "127.0.0.1:9090"` and a strong `secret` value (or no API
  exposure at all in production — set
  `experimental.clash_api: null`).
- Grep: `"external_controller"\s*:\s*"[^"]*(?<!127\.0\.0\.1):` /
  `"external_controller"\s*:\s*":\d+"` (binding to all
  interfaces).
- File globs: `*.json`.
- Source: https://sing-box.sagernet.org/configuration/experimental/

### Plaintext DNS resolver as primary — CWE-319

- Why: sing-box's `dns.servers` array specifies upstream
  resolvers. A plaintext DNS resolver (`8.8.8.8`,
  `1.1.1.1` without `https://` or `tls://` prefix) sends
  queries in cleartext over UDP — observable to any
  on-path observer (ISP, transit provider, Wi-Fi
  eavesdropper). For a privacy tool like sing-box, this
  defeats the whole point. The hardened pattern is
  `https://1.1.1.1/dns-query` (DoH) or
  `tls://1.1.1.1` (DoT), with a non-DoH bootstrap
  resolver only for the initial DoH-server hostname
  resolution.
- Grep: `"address"\s*:\s*"(?!https?://|tls://|quic://|h3://|local|fakeip)\d+\.\d+\.\d+\.\d+"`
  in `dns.servers[]`.
- File globs: `*.json`.
- Source: https://sing-box.sagernet.org/configuration/dns/

### Reality TLS with `short_id` array including `""` (empty short_id) — CWE-326

- Why: sing-box's Reality protocol accepts an array of
  `short_id` values. Including the empty string `""` allows
  clients to connect without a short_id — defeating the
  per-client identification mechanism Reality provides.
  Operationally an empty short_id is sometimes used during
  initial setup / debugging; in production, every client
  should have its own non-empty short_id.
- Grep: `"short_id"\s*:\s*\[[^\]]*""[^\]]*\]` or
  `"short_id"\s*:\s*""` in Reality TLS blocks.
- File globs: `*.json`.
- Source: https://sing-box.sagernet.org/configuration/

### Outbound `direct` rule that bypasses the proxy for sensitive destinations — CWE-200

- Why: sing-box routing rules with `outbound: "direct"`
  send matching traffic outside the proxy tunnel. A common
  misconfiguration is a route like `domain_suffix:
  ["company.com"]` → `direct` intended to keep
  corporate-network traffic local — but this leaks the
  user's actual public IP to the company's servers, and a
  network observer sees the unencrypted query. For
  privacy-tool deployments (Tor-like usage), every direct
  rule should be examined for whether the leak is
  intentional.
- Grep: `"outbound"\s*:\s*"direct"` paired with
  `"domain"` / `"domain_suffix"` / `"domain_keyword"` rules.
- File globs: `*.json`.
- Source: https://sing-box.sagernet.org/configuration/route/

## Secure patterns

Hardened sing-box config skeleton (server side):

```json
{
  "log": { "level": "info", "timestamp": true },

  "dns": {
    "servers": [
      { "tag": "doh", "address": "https://1.1.1.1/dns-query", "detour": "direct" },
      { "tag": "bootstrap", "address": "1.1.1.1", "detour": "direct" }
    ],
    "rules": [
      { "outbound": "any", "server": "doh" }
    ],
    "strategy": "ipv4_only"
  },

  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "uuid": "<uuid>", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "www.cloudflare.com",
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.cloudflare.com", "server_port": 443 },
          "private_key": "<from file at deploy time>",
          "short_id": ["<per-client>"]
        }
      }
    }
  ],

  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ],

  "experimental": {
    "clash_api": null
  }
}
```

Source: https://sing-box.sagernet.org/configuration/

## Fix recipes

### Recipe: bind SOCKS inbound to loopback only — addresses CWE-200

**Before (dangerous):**

```json
{
  "type": "socks",
  "listen": "0.0.0.0",
  "listen_port": 1080
}
```

**After (safe):**

```json
{
  "type": "socks",
  "listen": "127.0.0.1",
  "listen_port": 1080,
  "users": [
    { "username": "alice", "password": "<from secret store>" }
  ]
}
```

Source: https://sing-box.sagernet.org/configuration/inbound/

### Recipe: replace plaintext DNS with DoH — addresses CWE-319

**Before (dangerous):**

```json
{
  "dns": {
    "servers": [{ "address": "8.8.8.8" }]
  }
}
```

**After (safe):**

```json
{
  "dns": {
    "servers": [
      { "tag": "doh", "address": "https://1.1.1.1/dns-query", "detour": "direct" },
      { "tag": "bootstrap", "address": "1.1.1.1", "detour": "direct" }
    ],
    "rules": [{ "outbound": "any", "server": "doh" }]
  }
}
```

Source: https://www.rfc-editor.org/rfc/rfc8484

### Recipe: disable clash_api in production — addresses CWE-306

**Before (dangerous):**

```json
{
  "experimental": {
    "clash_api": { "external_controller": ":9090" }
  }
}
```

**After (safe):**

```json
{
  "experimental": {
    "clash_api": null
  }
}
```

Source: https://sing-box.sagernet.org/configuration/experimental/

## Version notes

- sing-box 1.8+ stabilised the Reality protocol fields;
  pre-1.8 configs use slightly different field names. Pin
  the runner's tooling to the version of sing-box deployed.
- The `experimental` config namespace is exactly what it
  says — fields move in/out of it across releases. Audit
  per release notes; do not assume `experimental.clash_api`
  is the canonical location across versions.
- sing-box 1.10+ adds `endpoints` for direct-WireGuard /
  Tailscale integration. WireGuard configuration semantics
  in sing-box's endpoint blocks follow the patterns in
  `netcfg/wireguard.md`.

## Common false positives

- SOCKS / HTTP / mixed inbound on `127.0.0.1` (loopback) —
  always safe; flag only when bound to non-loopback.
- `insecure: true` in dev / test / lab configs explicitly
  scoped via comments — annotate.
- `experimental.clash_api` with `external_controller:
  "127.0.0.1:9090"` and a strong `secret` — annotate; the
  loopback binding contains the exposure.
- DNS resolvers set to `local` (sing-box's local-resolver
  abstraction) — safe; flag only literal IP without
  scheme.
