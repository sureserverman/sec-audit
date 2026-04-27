# WireGuard — Configuration Hardening

## Source

- https://www.wireguard.com/quickstart/ — WireGuard quickstart (canonical)
- https://man7.org/linux/man-pages/man8/wg.8.html — `wg(8)` man page
- https://man7.org/linux/man-pages/man8/wg-quick.8.html — `wg-quick(8)` man page
- https://www.wireguard.com/papers/wireguard.pdf — WireGuard paper (Donenfeld 2020)
- https://datatracker.ietf.org/doc/html/rfc1918 — RFC 1918 private address space
- https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final — NIST SP 800-77 r1 (IPsec VPNs — applicable principles)
- https://cwe.mitre.org/

## Scope

Covers WireGuard configuration files for both Linux
(`/etc/wireguard/*.conf` consumed by `wg-quick`) and the
underlying `wg setconf` interface. Patterns covered:
private-key handling and file permissions, `AllowedIPs`
scoping (the canonical WG access-control mechanism),
`ListenPort` exposure, `Endpoint` IP-vs-hostname tradeoffs,
`PreSharedKey` for post-quantum hybrid, `PersistentKeepalive`
for NAT traversal, `PostUp` / `PostDown` hooks (shell-injection
surface). Out of scope: Tailscale / Headscale (built atop
WireGuard but with their own coordination plane — separate
concern); WireGuard-go userspace implementation specifics;
WG mesh-VPN orchestrators (Netbird, Innernet, etc.).

## Dangerous patterns (regex/AST hints)

### `PrivateKey` embedded in committed config — CWE-798

- Why: WireGuard's `PrivateKey` is a 32-byte Curve25519
  key; possession of it is full peer authentication. Any
  config file committed to git with a `PrivateKey =
  <base64>` line is a published key. The hardened patterns
  are: (a) generate the key at deploy time on the host
  (`wg genkey | tee /etc/wireguard/private.key | wg pubkey >
  /etc/wireguard/public.key`) and reference via
  `PostUp = wg set %i private-key /etc/wireguard/private.key`
  in the conf file, OR (b) keep the conf file out of git and
  populate via a secret-management system (Ansible Vault,
  HashiCorp Vault, sops-encrypted file).
- Grep: `^PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=` in any conf
  file under a git-tracked directory.
- File globs: `*.conf` under `wireguard/`, `wg-quick/`,
  `/etc/wireguard/**`, OR `*.conf` whose first line matches
  WG conf shape (`[Interface]` heading).
- Source: https://www.wireguard.com/quickstart/

### `[Interface]` conf file mode > 0600 — CWE-732

- Why: WireGuard configs contain the PrivateKey. The conf
  file MUST be 0600 (owner-rw only); 0644 (the default for
  most file-creation patterns) means any local user can read
  the private key. `wg-quick(8)` documents this requirement
  but does not enforce it on Linux. The hardened pattern in
  deployment is `chmod 600 /etc/wireguard/wg0.conf` plus
  `chown root:root` ownership.
- Grep: not source-detectable; this is a deployment-time
  property. The runner flags conf files with mode != 0600
  if filesystem metadata is available; otherwise reference
  pack annotates that the operator must verify.
- File globs: `*.conf` under `wireguard/`.
- Source: https://man7.org/linux/man-pages/man8/wg-quick.8.html

### `AllowedIPs = 0.0.0.0/0` on a peer that is NOT a full-tunnel gateway — CWE-863

- Why: `AllowedIPs` is WireGuard's per-peer access-control
  list AND its outbound routing policy: a peer with
  `AllowedIPs = 0.0.0.0/0` is granted permission to send
  packets sourced from any IP, AND the local interface
  routes all outbound traffic to that peer. For full-tunnel
  VPN clients (laptop → cloud gateway), this is correct.
  For point-to-point peer relationships (server-to-server
  VPN, mesh peer), it grants the peer impersonation rights
  on every IP — a compromised peer can spoof traffic from
  any source. The hardened pattern is `AllowedIPs = <peer
  WG IP>/32` (single host) for point-to-point, and explicit
  subnets for routed peers.
- Grep: `^AllowedIPs\s*=\s*0\.0\.0\.0/0` AND the peer's
  config does NOT also contain "gateway" / "exit" / "full-tunnel"
  in `# Description` comments.
- File globs: `*.conf` (WG configs).
- Source: https://www.wireguard.com/quickstart/

### `Endpoint` pointing at an IP literal vs a DNS name — CWE-1188

- Why: The tradeoff: `Endpoint = 198.51.100.7:51820`
  pins the peer to a specific IP and prevents DNS-rebinding
  / DNS-MITM attacks against the WG handshake. But it
  brittles deployment — when the cloud provider re-assigns
  the peer's IP, the config breaks silently (handshake
  retries land at the wrong host). `Endpoint =
  vpn.example.com:51820` resolves at handshake time, which
  is portable but trusts the resolver. The hardened pattern
  for production is to (a) use a DNS name, (b) DNSSEC-sign
  the zone, and (c) pin via the resolver's local cache for
  the handshake duration. For high-stakes deployments,
  prefer IP literals plus a deployment-time IP-update job.
- Grep: not directly flag-able — this is a tradeoff
  decision; the runner documents both forms and lets
  sec-expert reason about the deployment context.
- File globs: `*.conf`.
- Source: https://www.wireguard.com/quickstart/

### Missing `PreSharedKey` in mixed-trust mesh — CWE-326

- Why: Vanilla WireGuard uses Curve25519 + ChaCha20-Poly1305
  + Blake2s — strong against current attacks but
  hypothetically vulnerable to a future cryptographically-
  relevant quantum computer ("harvest now, decrypt later").
  WG's `PreSharedKey` mode adds a symmetric secret to the
  handshake, providing post-quantum hybrid security: even
  if the asymmetric key exchange is broken, the PSK still
  protects the session. Mandatory for high-stakes deployments
  (government, financial, multi-decade secret confidentiality
  requirements). Optional for low-stakes mesh.
- Grep: `\[Peer\]` blocks WITHOUT a corresponding
  `PreSharedKey` line in deployments tagged "high-stakes" /
  "compliance" / "long-term-confidential".
- File globs: `*.conf`.
- Source: https://www.wireguard.com/papers/wireguard.pdf

### `PostUp` / `PostDown` shell hooks with `wg-quick` interpolation — CWE-78

- Why: `wg-quick(8)` runs `PostUp` / `PostDown` commands
  through the user's shell with `%i` substitution for the
  interface name. If `%i` flows into a command without
  quoting (e.g. `PostUp = iptables -t nat -A POSTROUTING -o
  %i -j MASQUERADE`), an attacker who controls the
  interface name (rare, but possible via creative
  configuration) gets shell injection. More commonly: the
  hooks reference attacker-controllable variables (e.g.
  client IP from a deployment script). Audit hooks for
  unquoted variables; prefer `iptables` / `nft` direct
  invocation over shell-interpolated wrappers.
- Grep: `^(PostUp|PostDown|PreUp|PreDown)\s*=\s*[^"']*\$\{?[a-zA-Z_]`
  in WG conf files.
- File globs: `*.conf`.
- Source: https://man7.org/linux/man-pages/man8/wg-quick.8.html

## Secure patterns

Hardened point-to-point WG conf:

```ini
# /etc/wireguard/wg0.conf — mode 0600, root:root
[Interface]
# PrivateKey populated at deploy time, NOT committed:
PostUp = wg set %i private-key /etc/wireguard/wg0.key
ListenPort = 51820
Address = 10.42.0.1/24
SaveConfig = false

# Default-deny on hardware interfaces:
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s 10.42.0.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.42.0.0/24 -o eth0 -j MASQUERADE

[Peer]
# Peer "alice"
PublicKey = AbCdEf...=
PresharedKey = wxYZ12...=          # post-quantum hybrid
AllowedIPs = 10.42.0.2/32          # peer's WG IP only — no spoofing surface
PersistentKeepalive = 25
```

Source: https://www.wireguard.com/quickstart/

Full-tunnel client conf (laptop → gateway):

```ini
[Interface]
PrivateKey = <generated at install>
Address = 10.42.0.99/32
DNS = 10.42.0.1                    # gateway's DNS to prevent DNS leaks

[Peer]
PublicKey = <gateway pub>
PresharedKey = <psk>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0       # full tunnel — INTENTIONAL on this client
PersistentKeepalive = 25
```

Source: https://www.wireguard.com/quickstart/

## Fix recipes

### Recipe: remove inline PrivateKey, populate at deploy — addresses CWE-798

**Before (dangerous):**

```ini
[Interface]
PrivateKey = ABCDEF1234567890...=    # committed to git
ListenPort = 51820
```

**After (safe):**

```ini
[Interface]
# PrivateKey populated by PostUp at deploy time:
PostUp = wg set %i private-key /etc/wireguard/wg0.key
ListenPort = 51820
```

Source: https://www.wireguard.com/quickstart/

### Recipe: scope AllowedIPs to single host for point-to-point — addresses CWE-863

**Before (dangerous):**

```ini
[Peer]
PublicKey = ABC...=
AllowedIPs = 0.0.0.0/0    # peer can spoof any source IP
```

**After (safe):**

```ini
[Peer]
PublicKey = ABC...=
AllowedIPs = 10.42.0.2/32 # peer's WG IP only
```

Source: https://www.wireguard.com/quickstart/

### Recipe: add PSK for post-quantum hybrid — addresses CWE-326

**Before (dangerous):**

```ini
[Peer]
PublicKey = ABC...=
AllowedIPs = 10.42.0.2/32
```

**After (safe):**

```ini
[Peer]
PublicKey = ABC...=
PresharedKey = XYZ...=       # generated via `wg genpsk`
AllowedIPs = 10.42.0.2/32
```

Source: https://www.wireguard.com/papers/wireguard.pdf

## Version notes

- WireGuard 1.0 was upstreamed into Linux kernel 5.6 (March
  2020); userspace `wg-quick` is a separate `wireguard-tools`
  package. The kernel module is the canonical implementation;
  userspace `wireguard-go` is for non-Linux hosts.
- `PreSharedKey` was in WG from day one (paper Section 5.4)
  but is rarely deployed — operators viewed it as overkill.
  Post-2023 NIST PQC signaling has shifted defaults; new
  high-stakes deployments should use it.
- `wg-quick(8)` `SaveConfig = true` causes wg-quick to
  PERSIST runtime changes (added peers, etc.) back to the
  conf file on shutdown — flag as a structural risk for
  production (config drifts silently from the version-
  controlled file).

## Common false positives

- `AllowedIPs = 0.0.0.0/0` on the peer entry of a laptop /
  phone client conf where the peer IS a full-tunnel gateway —
  intentional; flag with INFO unless deployment context
  contradicts.
- Inline `PrivateKey` in conf files explicitly under
  `tests/fixtures/` or generated for ephemeral test
  scenarios — annotate.
- `PostUp = iptables ... %i ...` where `%i` is the only
  interpolation — `%i` is a wg-quick built-in not user input;
  flag only when additional shell-variable references appear.
- Missing `PresharedKey` on low-stakes mesh networks
  (home Tailscale-equivalent, dev environment) — annotate.
