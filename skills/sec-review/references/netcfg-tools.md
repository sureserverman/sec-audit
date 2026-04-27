# netcfg-tools

<!--
    Tool-lane reference for sec-review's netcfg lane (v1.9.0+).
    Consumed by the `netcfg-runner` sub-agent. Documents
    sing-box check + xray test (self-validation subcommands).
-->

## Source

- https://sing-box.sagernet.org/configuration/ — sing-box `check` subcommand (canonical)
- https://xtls.github.io/config/ — Xray-core `test` subcommand (canonical)
- https://github.com/SagerNet/sing-box/blob/main/cmd/sing-box/cmd_check.go — sing-box check implementation
- https://github.com/XTLS/Xray-core — Xray-core source
- https://cwe.mitre.org/

## Scope

In-scope: the two tools invoked by `netcfg-runner` —
`sing-box check` (sing-box's self-validation subcommand;
parses the JSON config and validates schema + cross-field
constraints without starting any listeners or network
activity) and `xray test` (Xray-core's self-validation
subcommand; same shape — schema + structural validation,
no network activity).

Both are **structural validators** rather than security
scanners — they catch typos, missing required fields, type
mismatches, and impossible cross-field constraints (e.g. a
Reality block referencing a serverName not in the
serverNames array). Security-pattern detection (the
patterns documented in `netcfg/sing-box.md` and
`netcfg/xray.md`) is handled by sec-expert reading the
reference packs; the validators complement sec-expert by
catching configs that won't even start.

The Tor (`torrc`) and WireGuard (`*.conf`) configurations
have no runner-invoked validator. `tor --verify-config -f
torrc` exists but starts background processes; `wg-quick`
config check (`wg-quick strip`) is parsing-only but
mixed-distro support is uneven. Tor and WireGuard
patterns are covered by sec-expert reasoning over
`netcfg/tor.md` and `netcfg/wireguard.md` reference packs.

Out of scope: live testing (the runner never starts
sing-box or xray; only `--check` / `test -confdir` parse
phases run); cluster-level testing (multi-node sing-box /
Xray deployments require their own integration tests).

## Canonical invocations

### sing-box check

- Install: `apt install sing-box` / `brew install sing-box` / pre-built binaries from GitHub Releases. Cross-platform; Go binary.
- Invocation:
  ```bash
  sing-box check -c "$config_file" \
      > "$TMPDIR/netcfg-runner-singbox.txt" \
      2> "$TMPDIR/netcfg-runner-singbox.stderr"
  rc_sb=$?
  ```
  Run per file. The check subcommand reads the JSON config,
  validates against the schema, and exits 0 (valid) or
  non-zero (invalid). Error messages on stderr include the
  field path of the violation.
- Output: text (not JSON). The runner parses the text into
  per-file findings: 0-rc → no finding emitted (the file is
  structurally valid; security findings come from sec-expert);
  non-zero rc → one MEDIUM finding per file with the error
  text as evidence.
- Tool behaviour: never starts listeners, never connects to
  the network. Pure parse + validate.
- Primary source: https://sing-box.sagernet.org/

Source: https://sing-box.sagernet.org/

### xray test

- Install: `apt install xray` / pre-built binaries from GitHub Releases (XTLS/Xray-core). Cross-platform; Go binary.
- Invocation:
  ```bash
  xray test -confdir "$config_dir" \
      > "$TMPDIR/netcfg-runner-xray.txt" \
      2> "$TMPDIR/netcfg-runner-xray.stderr"
  rc_xr=$?
  ```
  Run per directory containing one or more JSON configs.
  The test subcommand parses every JSON in the dir, merges
  them, and validates the result. Exits 0 (valid) or non-zero
  (invalid).
- Output: text. Same handling as sing-box: 0-rc emits nothing,
  non-zero emits a MEDIUM finding per directory with the
  error text as evidence.
- Tool behaviour: never starts listeners. Pure parse +
  validate. (`xray run -test` is a separate subcommand that
  attempts to bind ports — DO NOT use that.)
- Primary source: https://xtls.github.io/

Source: https://xtls.github.io/

## Output-field mapping

Every finding carries `origin: "netcfg"`,
`tool: "sing-box" | "xray"`, `reference: "netcfg-tools.md"`.

### sing-box check → sec-review finding (when rc != 0)

| sec-review field             | value                                                         |
|------------------------------|---------------------------------------------------------------|
| `id`                         | `"sing-box:invalid-config"`                                   |
| `severity`                   | `MEDIUM` (structural; will not start)                         |
| `cwe`                        | `CWE-1284` (Improper Validation of Specified Quantity in Input) |
| `title`                      | First line of stderr text (truncated to 200 chars)            |
| `file`                       | The config file path (relative to target_path)                |
| `line`                       | Line number extracted from error text via regex `line\s+(\d+)`; 0 if absent |
| `evidence`                   | Stderr text (truncated to 200 chars)                          |
| `reference_url`              | `https://sing-box.sagernet.org/configuration/`                |
| `fix_recipe`                 | null                                                          |
| `confidence`                 | `"high"` (deterministic validator)                            |

### xray test → sec-review finding (when rc != 0)

| sec-review field             | value                                                         |
|------------------------------|---------------------------------------------------------------|
| `id`                         | `"xray:invalid-config"`                                       |
| `severity`                   | `MEDIUM`                                                      |
| `cwe`                        | `CWE-1284`                                                    |
| `title`                      | First line of stderr text (truncated to 200 chars)            |
| `file`                       | Config dir path (or specific file mentioned in error)         |
| `line`                       | Line number from error text; 0 if absent                      |
| `evidence`                   | Stderr text (truncated to 200 chars)                          |
| `reference_url`              | `https://xtls.github.io/config/`                              |
| `fix_recipe`                 | null                                                          |
| `confidence`                 | `"high"`                                                      |

## Degrade rules

`__netcfg_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary (v1.9.0):

- `tool-missing` — the tool's binary is absent from PATH.
- `no-singbox-config` — sing-box on PATH but no
  sing-box-shaped JSON files (top-level `inbounds:` /
  `outbounds:` keys characteristic of sing-box) under
  target. Target-shape clean-skip.
- `no-xray-config` — xray on PATH but no Xray-shaped JSON
  files (top-level `inbounds:` / `outbounds:` with
  Xray-specific protocol values like `vless` / `vmess` /
  `trojan`) under target. Target-shape clean-skip.

The runner emits findings ONLY for sing-box / Xray
config validation. Tor (`torrc`) and WireGuard (`*.conf`)
patterns are covered by sec-expert reading the
`netcfg/tor.md` and `netcfg/wireguard.md` reference packs;
no tool runs against them in the v1.9 lane (mature
validators that fit the source-only / network-free contract
do not exist for these formats).

No host-OS gate.

## Version pins

- `sing-box` ≥ 1.8 (stable Reality field schema, stable
  experimental.clash_api). Pinned 2026-04.
- `xray` ≥ 1.8 (xtls-rprx-vision flow stable). Pinned 2026-04.
