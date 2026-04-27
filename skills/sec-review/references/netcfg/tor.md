# Tor — torrc and Onion Service Configuration

## Source

- https://2019.www.torproject.org/docs/tor-manual.html.en — `tor` man page (canonical, mirrored from upstream)
- https://community.torproject.org/onion-services/setup/ — Tor Project onion service setup guide
- https://gitlab.torproject.org/legacy/trac/-/wikis/doc/EntryGuards — Tor entry guards / GuardLifetime
- https://spec.torproject.org/rend-spec — Tor v3 rendezvous specification (onion v3)
- https://blog.torproject.org/v2-deprecation-timeline/ — v2 onion address deprecation (2021)
- https://2019.www.torproject.org/docs/faq.html.en#BetterAnonymity — anonymity vs entry-guard rotation
- https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final — NIST SP 800-53 r5 (relevant network controls)

## Scope

Covers Tor configuration files (`torrc`, `torrc-defaults`,
fragments under `torrc.d/`) for both Tor clients and Tor
hidden-service servers: ControlPort exposure, HiddenServiceDir
key-material protection, ExitPolicy / RelayBandwidthRate for
relays, v2 onion addresses (deprecated), `SOCKSPort`
binding scope, MaxCircuitDirtiness / GuardLifetime, and
`NumEntryGuards` overrides. Out of scope: Tor as a software
dependency (handled at the package-manager layer); browser-
side Tor patterns (Tor Browser configs are Firefox-prefs,
covered by browser-extension and frontend lanes); Onion
Browser / iOS-specific Tor builds.

## Dangerous patterns (regex/AST hints)

### `ControlPort` bound to public interface — CWE-306

- Why: Tor's `ControlPort` exposes a privileged
  control-channel API — a connected client can request
  circuit creation, retrieve the current entry guards, dump
  configuration including `HiddenServiceDir` paths, and
  potentially cause SIGSHUTDOWN. Default Tor configurations
  bind the ControlPort to localhost only (`127.0.0.1`), but
  `ControlPort 9051` (no IP qualifier) binds to all
  interfaces on some Tor builds. Combined with no
  authentication (default), this gives any network peer
  full Tor control. The hardened pattern is
  `ControlPort 127.0.0.1:9051` PLUS one of `HashedControlPassword`
  / `CookieAuthentication 1`.
- Grep: `^ControlPort\s+(?!127\.0\.0\.1|::1|unix:)\d+`
- File globs: `torrc`, `torrc-*`, `*.torrc`, `/etc/tor/**`.
- Source: https://2019.www.torproject.org/docs/tor-manual.html.en

### `ControlPort` without `HashedControlPassword` / `CookieAuthentication` — CWE-306

- Why: ControlPort with no authentication accepts any
  client's commands. Even bound to `127.0.0.1`, any local
  user (multi-tenant host, container escape, debug shell
  via web app) can issue control commands. The hardened
  pattern is `CookieAuthentication 1` (file-based auth, the
  cookie file lives at `/var/run/tor/control.authcookie`
  with 0600 perms) for production daemons; for interactive
  use, `HashedControlPassword <hash>` (generated via
  `tor --hash-password`).
- Grep: `^ControlPort\b` AND no `HashedControlPassword` or
  `CookieAuthentication` in the same file.
- File globs: `torrc`, `torrc-*`, `*.torrc`.
- Source: https://2019.www.torproject.org/docs/tor-manual.html.en

### `HiddenServiceDir` with mode 0755 / world-traversable parent — CWE-732

- Why: The `HiddenServiceDir` contains the onion service's
  private key (`hs_ed25519_secret_key` for v3). Tor
  requires the directory to be 0700 (owner-rwx-only) and
  refuses to start otherwise. But common deployment errors
  put the directory under a world-readable parent
  (`/srv/onion/` mode 0755) where another local user can
  `ls /srv/onion/` to enumerate every onion service hosted
  on the box. The hardened pattern is to put HiddenServiceDir
  under `/var/lib/tor/<service>/` (the canonical Tor data
  dir, owned by the `tor` user) with parent dir mode 0700.
- Grep: `^HiddenServiceDir\s+([^\s]+)` and verify the parent
  directory's permissions out-of-band; flag any path NOT
  under `/var/lib/tor/`.
- File globs: `torrc`, `torrc-*`, `*.torrc`.
- Source: https://community.torproject.org/onion-services/setup/

### v2 onion address (16-char `.onion`) — CWE-326

- Why: Tor v2 onion addresses (16 base32 chars) were
  deprecated in 2021 — Tor 0.4.6+ no longer creates them
  and Tor 0.4.7+ removes client-side support entirely. v2
  addresses use 80-bit truncated SHA1 hashes that have
  publicly-documented enumeration weaknesses, and the
  protocol leaks the full public key during the descriptor-
  upload phase. Any `torrc` referencing v2-style hidden
  service paths or v2 client authorization is operating on
  a deprecated, weakened protocol.
- Grep: `\b[a-z2-7]{16}\.onion\b` in torrc files (v3 onions
  are 56 chars).
- File globs: `torrc`, `torrc-*`, `*.torrc`, `*.conf`.
- Source: https://blog.torproject.org/v2-deprecation-timeline/

### `ExitRelay 1` on a relay without explicit `ExitPolicy` — CWE-693

- Why: A Tor relay with `ExitRelay 1` and a default
  ExitPolicy advertises permissive exit policies, attracting
  exit traffic. Operators rarely intend to be a public exit
  node — operating one has legal exposure. The hardened
  pattern is to declare an explicit `ExitPolicy reject *:*`
  for non-exit relays (or an explicit narrow exit policy for
  intentional exits), AND `ExitPolicyRejectPrivate 1`
  (rejects RFC 1918 + link-local + loopback as exit
  destinations to avoid accidentally exiting into the relay
  operator's LAN).
- Grep: `^ExitRelay\s+1` AND no explicit `ExitPolicy` AND
  no `ExitPolicyRejectPrivate`.
- File globs: `torrc`, `torrc-*`.
- Source: https://2019.www.torproject.org/docs/tor-manual.html.en

### `SOCKSPort` bound to non-loopback / no isolation flags — CWE-200

- Why: `SOCKSPort 9050` (no IP qualifier) on some Tor
  builds binds to all interfaces. A network peer can then
  use the local Tor daemon as a SOCKS proxy, gaining
  free-tier anonymity at the operator's expense (and
  potentially incurring bandwidth charges). Even on
  loopback, missing isolation flags
  (`IsolateClientAddr`, `IsolateDestAddr`,
  `IsolateClientProtocol`) means a single Tor circuit
  carries traffic from multiple local clients — a
  side-channel that lets co-located attackers observe each
  other's traffic patterns. The hardened pattern is
  `SOCKSPort 127.0.0.1:9050 IsolateClientAddr
  IsolateDestAddr IsolateClientProtocol`.
- Grep: `^SOCKSPort\s+(?!127\.0\.0\.1|::1|unix:)\d+` OR
  `^SOCKSPort\s+\S+` (any) AND no `IsolateClientAddr` flag.
- File globs: `torrc`, `torrc-*`.
- Source: https://2019.www.torproject.org/docs/tor-manual.html.en

### `DataDirectory` outside `/var/lib/tor/` — CWE-732

- Why: Tor's data directory holds entry-guard state, cached
  consensus documents, and (for hidden services) keys.
  Default is `/var/lib/tor/` (owned by the `tor` user).
  Operators sometimes set `DataDirectory /home/me/tor-data/`
  for convenience — but this puts Tor state under a path
  managed by the user shell, with permissions vulnerable to
  user-level attacks (other processes the user runs can
  read entry-guard state, fingerprinting the user's Tor
  usage patterns).
- Grep: `^DataDirectory\s+(?!/var/lib/tor)`.
- File globs: `torrc`, `torrc-*`.
- Source: https://2019.www.torproject.org/docs/tor-manual.html.en

## Secure patterns

Hardened `torrc` for a hidden-service server:

```
# Logging — journald (preferred over flat files)
Log notice syslog

# Data directory — Tor-user-owned only.
DataDirectory /var/lib/tor

# Control channel — local only, cookie-auth.
ControlPort 127.0.0.1:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1

# SOCKS — local clients only, full isolation.
SOCKSPort 127.0.0.1:9050 IsolateClientAddr IsolateDestAddr IsolateClientProtocol

# Hidden service v3 (the only kind Tor 0.4.7+ supports).
HiddenServiceDir /var/lib/tor/myonion/
HiddenServicePort 80 unix:/run/myapp/myapp.sock
HiddenServiceVersion 3
HiddenServiceMaxStreams 100
HiddenServiceMaxStreamsCloseCircuit 1

# Not a relay — be explicit.
ExitRelay 0
ORPort 0
DirPort 0
```

Source: https://community.torproject.org/onion-services/setup/

Hardened `torrc` for a Tor relay (NOT exit):

```
Nickname myrelay
ContactInfo abuse@example.com
ORPort 9001
DirPort 9030

# Relay — no exit traffic at all.
ExitRelay 0
ExitPolicy reject *:*
ExitPolicyRejectPrivate 1

RelayBandwidthRate 10 MB
RelayBandwidthBurst 20 MB
AccountingMax 1 TB
AccountingStart month 1 00:00
```

Source: https://2019.www.torproject.org/docs/tor-manual.html.en

## Fix recipes

### Recipe: bind ControlPort to localhost + add cookie auth — addresses CWE-306

**Before (dangerous):**

```
ControlPort 9051
```

**After (safe):**

```
ControlPort 127.0.0.1:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```

Source: https://2019.www.torproject.org/docs/tor-manual.html.en

### Recipe: explicit ExitPolicy reject for non-exit relay — addresses CWE-693

**Before (dangerous):**

```
ExitRelay 1
```

**After (safe):**

```
ExitRelay 0
ExitPolicy reject *:*
ExitPolicyRejectPrivate 1
```

Source: https://2019.www.torproject.org/docs/tor-manual.html.en

### Recipe: add SOCKSPort isolation flags — addresses CWE-200

**Before (dangerous):**

```
SOCKSPort 9050
```

**After (safe):**

```
SOCKSPort 127.0.0.1:9050 IsolateClientAddr IsolateDestAddr IsolateClientProtocol
```

Source: https://2019.www.torproject.org/docs/tor-manual.html.en

## Version notes

- Tor 0.4.7 (Sep 2022) removes v2 onion address support
  entirely — both server-side hosting and client-side
  resolution. Any `*.onion` reference in torrc that is 16
  chars instead of 56 is structurally unusable post-0.4.7.
- Tor 0.4.8 / 0.4.9 introduced `HiddenServiceMaxStreamsCloseCircuit`
  hardening — set to 1 to defend against onion-service DoS
  via stream flooding.
- `CookieAuthFileGroupReadable 1` is needed for non-root
  control-channel clients (e.g. `nyx` running as a
  monitoring user) — without it, only root can read the
  cookie. Pair with strict `tor` group membership.

## Common false positives

- `ControlPort 0` (explicitly disabled — Tor 0.4.0+) — safe;
  this is the most-restrictive form.
- `SOCKSPort` bound to a Unix socket (`unix:/var/run/tor/socks`) —
  isolation is via socket-permissions; do not flag.
- `ExitRelay 1` on a node explicitly tagged as a public exit
  in operator-provided documentation — annotate, not flag.
- Test-fixture torrc files with intentionally insecure
  patterns under `tests/fixtures/` — annotate.
