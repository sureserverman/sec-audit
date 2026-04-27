# Xray — Configuration Hardening

## Source

- https://xtls.github.io/ — Xray-core documentation (canonical)
- https://xtls.github.io/config/ — Xray config reference
- https://xtls.github.io/config/inbounds/ — Xray inbound types
- https://xtls.github.io/config/outbounds/ — Xray outbound types
- https://xtls.github.io/config/transport.html — transport layer
- https://github.com/XTLS/Xray-core — source repo
- https://www.v2ray.com/ — v2ray (Xray's predecessor; some patterns shared)
- https://datatracker.ietf.org/doc/html/rfc8446 — TLS 1.3 (RFC 8446)

## Scope

Covers Xray-core JSON configuration files: inbound listeners
(SOCKS, HTTP, dokodemo-door, VMess, VLESS, Trojan, Shadowsocks,
WireGuard) and their TLS / Reality / authentication settings;
outbound rules; routing rules with geosite / geoip;
streamSettings (network, security, fallbacks); the `api`
inbound for Xray-API control; stats and policy. Out of scope:
client-side Xray app configurations (these are downstream
consumers); Xray cluster orchestration (Xray-Manager and
similar — separate concern); Reality SNI target selection
(covered by the `reality-domain-scanner` skill).

## Dangerous patterns (regex/AST hints)

### `inbounds[].listen` bound to `0.0.0.0` for SOCKS / HTTP / dokodemo — CWE-200

- Why: Same class as sing-box's SOCKS-on-public pattern. An
  authenticated SOCKS / HTTP / dokodemo-door inbound bound
  to a public interface is an open proxy. Xray's protocol
  inbounds (VLESS, Trojan, Shadowsocks, VMess) are
  authenticated by design and can safely bind public; the
  utility-protocol inbounds should be loopback-only.
- Grep: `"listen"\s*:\s*"(0\.0\.0\.0|::)"` AND the same
  inbound has `"protocol"\s*:\s*"(socks|http|dokodemo-door)"`.
- File globs: `*.json` under `xray/`, `xray-config/`,
  `/usr/local/etc/xray/**`.
- Source: https://xtls.github.io/config/inbounds/

### `streamSettings.security: "none"` on an inbound carrying credentials — CWE-319

- Why: Xray's streamSettings supports `security:
  "none"`/`"tls"`/`"reality"`/`"xtls"`. With `"none"`, the
  inbound accepts plain TCP — credentials (VMess UUIDs,
  Trojan passwords, Shadowsocks keys) traverse the network
  unencrypted. The hardened pattern is `security: "tls"` (or
  `"reality"` for high-censorship environments) on every
  public-facing inbound. The exception is inbounds behind a
  TLS-terminating reverse proxy (nginx, HAProxy), which is
  defensible if the proxy-to-Xray hop is loopback.
- Grep: `"security"\s*:\s*"none"` in inbound `streamSettings`.
- File globs: `*.json`.
- Source: https://xtls.github.io/config/transport.html

### `tls.allowInsecure: true` on outbound — CWE-295

- Why: Xray's outbound TLS settings include `allowInsecure`
  (boolean, default false). Setting it true disables
  certificate-chain validation — the outbound TLS handshake
  completes with any cert, including attacker MITM. Common
  on dev configs that copy-paste into production. The
  hardened pattern is `allowInsecure: false` (default) plus
  proper cert pinning if needed.
- Grep: `"allowInsecure"\s*:\s*true`.
- File globs: `*.json`.
- Source: https://xtls.github.io/config/transport.html

### `api` inbound exposed on non-loopback — CWE-306

- Why: Xray's `api` inbound (gRPC service for Xray-API
  control) lets a connected client query traffic stats,
  reload routing rules, and modify outbound configurations.
  When the api-inbound's `listen` is non-loopback,
  any network peer can issue control commands. The
  hardened pattern is `"listen": "127.0.0.1"` + a routing
  rule that restricts the API tag to inbound-loopback only.
- Grep: `"protocol"\s*:\s*"dokodemo-door"` paired with
  `"tag"\s*:\s*"api"` in an inbound whose `listen` is
  non-loopback.
- File globs: `*.json`.
- Source: https://xtls.github.io/config/inbounds/dokodemo.html

### VMess inbound without `alterId: 0` (legacy AEAD-disabled mode) — CWE-327

- Why: Xray's VMess protocol has two modes: legacy
  (`alterId > 0`, MD5+AES-CFB) and AEAD-only (`alterId: 0`,
  AEAD ciphersuite). Legacy mode uses MD5-based key
  derivation that has known weaknesses. Xray-core
  deprecated legacy VMess in 2022 and emits warnings; new
  configs should always use `alterId: 0`. Better still,
  migrate to VLESS (no encryption layer at all — TLS does
  the work).
- Grep: `"alterId"\s*:\s*[1-9]\d*` in VMess inbounds.
- File globs: `*.json`.
- Source: https://xtls.github.io/config/inbounds/vmess.html

### Shadowsocks with deprecated cipher — CWE-327

- Why: Xray's Shadowsocks supports many ciphers; the
  hardened set is `2022-blake3-aes-128-gcm`,
  `2022-blake3-aes-256-gcm`, or `2022-blake3-chacha20-poly1305`.
  Legacy ciphers (`aes-256-cfb`, `aes-128-cfb`,
  `chacha20`, `chacha20-ietf`, `rc4-md5`, `salsa20`) are
  vulnerable to known attacks (replay, partition oracles,
  weak streams). Pre-2022 SS configs commonly use legacy
  ciphers; migrate to the SS2022 family.
- Grep: `"method"\s*:\s*"(aes-256-cfb|aes-128-cfb|chacha20(-ietf)?|rc4-md5|salsa20|none|table)"`
  in Shadowsocks inbound/outbound blocks.
- File globs: `*.json`.
- Source: https://xtls.github.io/config/inbounds/shadowsocks.html

### Reality TLS without `serverNames` enumeration — CWE-345

- Why: Xray's Reality TLS expects a `serverNames` array
  enumerating the SNI values the inbound accepts. With an
  empty or missing serverNames, the inbound accepts any
  SNI — losing the per-target-domain pretense Reality
  provides for censorship resistance. The hardened pattern
  is to populate serverNames with the same SNI used in the
  `dest` handshake target (and only that SNI).
- Grep: Reality TLS block with `"serverNames"\s*:\s*\[\s*\]`
  or missing serverNames key.
- File globs: `*.json`.
- Source: https://xtls.github.io/config/transport.html

## Secure patterns

Hardened Xray VLESS + Reality config (server):

```json
{
  "log": { "loglevel": "warning" },

  "inbounds": [
    {
      "tag": "vless-reality",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "<uuid>", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.cloudflare.com:443",
          "xver": 0,
          "serverNames": ["www.cloudflare.com"],
          "privateKey": "<from file at deploy time>",
          "shortIds": ["<per-client>"]
        }
      }
    },
    {
      "tag": "api",
      "port": 10085,
      "listen": "127.0.0.1",
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    }
  ],

  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block",  "protocol": "blackhole" }
  ],

  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["api"], "outboundTag": "direct" }
    ]
  }
}
```

Source: https://xtls.github.io/config/

## Fix recipes

### Recipe: bind dokodemo / SOCKS inbounds to loopback — addresses CWE-200

**Before (dangerous):**

```json
{
  "tag": "api",
  "listen": "0.0.0.0",
  "port": 10085,
  "protocol": "dokodemo-door"
}
```

**After (safe):**

```json
{
  "tag": "api",
  "listen": "127.0.0.1",
  "port": 10085,
  "protocol": "dokodemo-door"
}
```

Source: https://xtls.github.io/config/inbounds/dokodemo.html

### Recipe: replace legacy VMess with AEAD-only — addresses CWE-327

**Before (dangerous):**

```json
{
  "protocol": "vmess",
  "settings": {
    "clients": [{ "id": "<uuid>", "alterId": 64 }]
  }
}
```

**After (safe):**

```json
{
  "protocol": "vmess",
  "settings": {
    "clients": [{ "id": "<uuid>", "alterId": 0 }]
  }
}
```

Source: https://xtls.github.io/config/inbounds/vmess.html

### Recipe: migrate legacy SS cipher to SS-2022 — addresses CWE-327

**Before (dangerous):**

```json
{
  "protocol": "shadowsocks",
  "settings": {
    "method": "aes-256-cfb",
    "password": "<...>"
  }
}
```

**After (safe):**

```json
{
  "protocol": "shadowsocks",
  "settings": {
    "method": "2022-blake3-aes-256-gcm",
    "password": "<base64 32-byte key from openssl rand -base64 32>"
  }
}
```

Source: https://xtls.github.io/config/inbounds/shadowsocks.html

## Version notes

- Xray-core 1.7+ adopted SS-2022 ciphers (Blake3-AEAD); pre-
  1.7 configs are stuck on legacy ciphers. Pin the deployed
  version.
- Xray-core 1.8+ added the `xtls-rprx-vision` flow as the
  canonical anti-detection flow control for VLESS+Reality.
  Pre-1.8 configs may use deprecated `xtls-rprx-direct` or
  `xtls-rprx-origin` flows.
- The Reality protocol's serverNames enumeration was loosened
  in some 1.9.x releases — verify against current docs.

## Common false positives

- SOCKS / HTTP inbounds on `127.0.0.1` for local-app
  consumption — safe; flag only when public.
- `allowInsecure: true` in lab / dev configs scoped via
  comments — annotate.
- Legacy VMess (`alterId > 0`) on a service explicitly
  documented as "legacy client compatibility" — annotate
  with deprecation warning rather than HIGH severity.
- Reality `serverNames` containing only the SNI of the
  upstream `dest` target — the canonical pattern; no flag.
