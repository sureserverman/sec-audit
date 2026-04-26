# go-tools

<!--
    Tool-lane reference for sec-review's Go lane (v1.5.0+).
    Consumed by the `go-runner` sub-agent. Documents
    gosec + staticcheck.
-->

## Source

- https://github.com/securego/gosec — gosec canonical (Go binary; security-focused linter with `Gxxx` rule IDs)
- https://github.com/securego/gosec/blob/master/README.md#available-rules — gosec rule reference (`G101` … `G505`)
- https://staticcheck.dev/ — staticcheck canonical (Go binary; bug-finding + simplifications + style)
- https://staticcheck.dev/docs/checks/ — staticcheck check reference (`SAxxxx` / `Sxxxx` / `STxxxx` / `Uxxxx` / `QFxxxx`)
- https://cwe.mitre.org/

## Scope

In-scope: the two tools invoked by `go-runner` — `gosec` (Go
binary; security-focused linter with mature `Gxxx` rule IDs
covering hardcoded credentials, SQL injection, weak crypto,
file permissions, command injection, integer overflow, TLS
config, HTTP servers without timeouts) and `staticcheck` (Go
binary; comprehensive static analyzer covering bug-finding
SA-rules, simplification S/QF-rules, style ST-rules,
unused-code U-rules). Both cross-platform; both run as pure
source-tree static scanners; neither contacts a Go module
proxy or any registry. Out of scope: `govulncheck`
(reachability-based vulnerability scanner — overlaps with
sec-review's cve-enricher OSV pass against the `Go` ecosystem;
may be added in a future v1.5.x as a third tool); `go vet` (a
narrower stdlib-shipped subset of staticcheck — staticcheck
supersedes); `golangci-lint` (an aggregator that includes both
gosec and staticcheck — running them directly is more
deterministic for this lane).

## Canonical invocations

### gosec

- Install: `go install github.com/securego/gosec/v2/cmd/gosec@latest` OR pre-built binaries from GitHub Releases (Linux/macOS/Windows amd64+arm64).
- Invocation:
  ```bash
  gosec -fmt=json -quiet ./... \
      > "$TMPDIR/go-runner-gosec.json" \
      2> "$TMPDIR/go-runner-gosec.stderr"
  rc_gs=$?
  ```
  Run with the Go module root as cwd. The `./...` pattern
  walks the package tree; `-quiet` suppresses progress output
  on stderr; `-fmt=json` is the canonical machine-readable
  output.
- Output: JSON object with top-level `Issues: [...]` array.
  Each issue has `file`, `line` (string, may be a range like
  `"42-44"`), `column`, `severity` (`HIGH` / `MEDIUM` /
  `LOW`), `confidence` (`HIGH` / `MEDIUM` / `LOW`), `cwe`
  object with `ID` and `URL` fields, `rule_id` (e.g. `G101`,
  `G201`, `G304`, `G402`, `G404`, `G501`), and `details`
  (the human-readable message + code snippet).
- Tool behaviour: exits non-zero when any issue fires. NOT a
  crash — parse JSON regardless. Empty result is `Issues: []`.
- Primary source: https://github.com/securego/gosec

Source: https://github.com/securego/gosec

### staticcheck

- Install: `go install honnef.co/go/tools/cmd/staticcheck@latest` OR pre-built binaries from GitHub Releases.
- Invocation:
  ```bash
  staticcheck -f=json ./... \
      > "$TMPDIR/go-runner-staticcheck.json" \
      2> "$TMPDIR/go-runner-staticcheck.stderr"
  rc_sc=$?
  ```
  Run with the Go module root as cwd. `-f=json` emits one
  JSON object per line (NDJSON), not a single top-level
  array. Each line is a finding.
- Output: NDJSON. Each line has `code` (rule ID — `SA1000`,
  `SA1019`, `SA4006`, `SA5007`, etc.), `severity` (`error` /
  `warning` / `ignored`), `message`, `location` (with
  `file`, `line`, `column`), and `end` (location of the end
  of the diagnostic span).
- Tool behaviour: exits non-zero when any finding fires.
  NOT a crash — parse line-by-line regardless. Empty result
  is no output.
- Primary source: https://staticcheck.dev/

Source: https://staticcheck.dev/

## Output-field mapping

Every finding carries `origin: "go"`,
`tool: "gosec" | "staticcheck"`, `reference: "go-tools.md"`.

### gosec → sec-review finding

| upstream                                              | sec-review field             |
|-------------------------------------------------------|------------------------------|
| `"gosec:" + .rule_id`                                 | `id`                         |
| `.severity` remap: `HIGH` → HIGH, `MEDIUM` → MEDIUM, `LOW` → LOW | `severity`        |
| `.cwe.ID` formatted as `"CWE-" + ID` (gosec ships the CWE inline) | `cwe`            |
| `.details` (first line — the rule description)        | `title`                      |
| `.file`                                               | `file`                       |
| `.line` parsed to int (range `"42-44"` → 42)          | `line`                       |
| `.code` (the snippet gosec captures) truncated to 200 | `evidence`                   |
| `.cwe.URL` if present, else `https://github.com/securego/gosec/blob/master/README.md#` + rule_id | `reference_url` |
| null (gosec does not ship inline fix recipes)         | `fix_recipe`                 |
| `.confidence` remap: `HIGH` → high, `MEDIUM` → medium, `LOW` → low | `confidence`    |

### staticcheck → sec-review finding

| upstream                                              | sec-review field             |
|-------------------------------------------------------|------------------------------|
| `"staticcheck:" + .code`                              | `id`                         |
| `.severity` remap: `error` → MEDIUM, `warning` → LOW, `ignored` → LOW | `severity` |
| Per-`code` CWE table — `SA1019` (deprecated symbol use) → CWE-477, `SA1015` (`time.Tick` leaks) → CWE-401, `SA4006` (unused value) → null, `SA5007` (infinite recursive call) → CWE-674, `SA1023` (missing http.Hijacker close) → CWE-404, `SA9003` (empty branch) → null, `SA1000`/`SA1006` (unsafe printf) → CWE-134, all other SA-rules → null, all S/ST/U/QF-rules → null (style/refactor only) | `cwe` |
| `.message`                                            | `title`                      |
| `.location.file`                                      | `file`                       |
| `.location.line`                                      | `line`                       |
| `.message` (truncated to 200 chars)                   | `evidence`                   |
| `https://staticcheck.dev/docs/checks/#` + code        | `reference_url`              |
| null (staticcheck does not ship inline fix recipes)   | `fix_recipe`                 |
| `"high"` (staticcheck is deterministic — no FP rate)  | `confidence`                 |

## Degrade rules

`__go_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary (v1.5.0):

- `tool-missing` — the tool's binary is absent from PATH.

No host-OS gate — both tools are cross-platform Go binaries
with no `requires-<host>-host` precondition. No target-shape
skip reasons — when the inventory detects `go` (`go.mod`
presence with at least one `*.go` file), both tools always
have something to scan; an empty package set yields empty
results, not a skip.

## Version pins

- `gosec` ≥ 2.20 (stable JSON schema; CWE inlining via
  `.cwe.ID`/`.cwe.URL`; rule set covers G101 … G505 with
  consistent severity mapping). Pinned 2026-04.
- `staticcheck` ≥ 2024.1 (stable NDJSON output; SA-rule
  vocabulary fixed; deprecation-tracking SA1019 covers Go
  1.21+ stdlib). Pinned 2026-04.
