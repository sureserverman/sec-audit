# Rust Tools

## Source

- https://github.com/rustsec/rustsec — RustSec advisory database and cargo-audit source (README + `cargo-audit/README.md`)
- https://github.com/EmbarkStudios/cargo-deny — cargo-deny source and book (README + `book/`)
- https://github.com/geiger-rs/cargo-geiger — cargo-geiger source repo (README)
- https://mozilla.github.io/cargo-vet/ — Mozilla's cargo-vet book (official)
- https://github.com/mozilla/cargo-vet — cargo-vet source repo
- https://rustsec.org/ — RustSec advisory index and categorization context
- https://cwe.mitre.org/ — CWE index (for mapping advisory CWE arrays and per-tool defaults)

## Scope

This reference pack documents the four Rust-lane binaries invoked by the
`rust-runner` sub-agent (cargo-audit, cargo-deny, cargo-geiger, and
cargo-vet). It specifies canonical CLI invocations, JSON output schemas,
field mappings to sec-audit's finding schema, and offline-degrade rules.
Out of scope: cargo-semver-checks (API compatibility, not security),
custom advisory authoring, cargo-crev (deferred), and non-Cargo Rust
build systems — all deferred to future versions. This pack documents how
the `rust-runner` sub-agent invokes each tool, not anti-patterns in user
code.

All four tools are Cargo subcommands. They require a working `cargo`
installation and a `Cargo.lock` (or `Cargo.toml`) at the target project
root.

## Canonical invocations

### cargo-audit

**Install:** `cargo install cargo-audit --locked`

**Run command:**

```bash
cargo audit --json
```

Emits a single JSON object to stdout. Exits 0 when no vulnerabilities are
found and non-zero when vulnerabilities are present. Both exit codes
produce valid JSON. A non-zero exit because vulnerabilities were found is
NOT a crash — parse the JSON and emit findings regardless.

**Expected JSON output shape:**

```json
{
  "database": {
    "advisory-count": 412,
    "last-commit": "abc123",
    "last-updated": "2026-04-20T00:00:00Z"
  },
  "lockfile": {
    "dependency-count": 87
  },
  "vulnerabilities": {
    "found": true,
    "count": 2,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2024-0001",
          "package": "openssl",
          "title": "Use-after-free in SSL_free_buffers",
          "description": "A use-after-free vulnerability exists...",
          "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "aliases": ["CVE-2024-12345"],
          "url": "https://rustsec.org/advisories/RUSTSEC-2024-0001.html",
          "categories": ["memory-corruption"],
          "cwe": [416]
        },
        "package": {
          "name": "openssl",
          "version": "0.10.55"
        }
      }
    ]
  },
  "warnings": {}
}
```

Top-level keys: `database`, `lockfile`, `vulnerabilities`, `warnings`.
The `vulnerabilities.list[]` array contains the security findings; each
entry has an `advisory` sub-object and a `package` sub-object.

**Worked example:**

```bash
# Run from the project root (where Cargo.lock resides)
cargo audit --json

# Scope to a specific package tree (monorepo)
cargo audit --json --file path/to/Cargo.lock
```

Source: https://github.com/rustsec/rustsec

### cargo-deny

**Install:** `cargo install cargo-deny --locked`

**Run command:**

```bash
cargo deny --format json check all
```

Emits JSON diagnostic objects to stdout (one per line, or a combined
array depending on the version). Exits non-zero when any enabled check
produces an error. A non-zero exit because checks failed is NOT a crash —
parse the JSON diagnostics and emit findings regardless. Only treat as
tool failure when stdout is empty or not valid JSON, or when the process
exits >= 127.

**Expected JSON output shape (one diagnostic per line):**

```json
{
  "type": "diagnostic",
  "severity": "error",
  "code": "A001",
  "message": "vulnerable crate 'openssl 0.10.55' (RUSTSEC-2024-0001)",
  "labels": [
    {
      "span": {
        "path": "Cargo.lock",
        "line": 42,
        "column": 1
      },
      "message": "this crate"
    }
  ],
  "graphs": []
}
```

Each diagnostic object carries: `type`, `severity` (`"error"` /
`"warning"` / `"note"` / `"help"`), `code`, `message`, `labels[]`
(file/line spans), and `graphs` (dependency graph slices). The `code`
field identifies which cargo-deny check produced the diagnostic:
advisory-related codes begin with `A`, ban-related with `B`, license-
related with `L`, and source-related with `S`.

Check categories exposed by `check all`:
- `advisories` — cross-references Cargo.lock against the RustSec DB.
- `bans` — detects disallowed crates and duplicate dependency versions.
- `licenses` — flags unacceptable license expressions.
- `sources` — validates crate source registries and git references.

**Worked example:**

```bash
# Run all checks, JSON diagnostics to stdout
cargo deny --format json check all

# Run only the advisory and bans checks
cargo deny --format json check advisories bans

# With a deny.toml config in a non-standard location
cargo deny --config path/to/deny.toml --format json check all
```

Source: https://github.com/EmbarkStudios/cargo-deny

### cargo-geiger

**Install:** `cargo install cargo-geiger --locked`

Requires cargo-geiger >= 0.11.5 for the `Json` output format flag.

**Run command:**

```bash
cargo geiger --output-format Json --all-targets
```

Emits a JSON object to stdout. Exits 0 on success. The scan walks the
full dependency tree and counts safe and unsafe usages per crate.

**Expected JSON output shape:**

```json
{
  "packages": [
    {
      "package": {
        "id": {
          "name": "libc",
          "version": "0.2.147"
        }
      },
      "unsafety": {
        "used": {
          "functions": {"safe": 12, "unsafe_": 4},
          "exprs":     {"safe": 89, "unsafe_": 22},
          "item_impls":{"safe": 3,  "unsafe_": 1},
          "item_traits":{"safe": 0, "unsafe_": 0},
          "methods":   {"safe": 6,  "unsafe_": 2}
        },
        "unused": {
          "functions": {"safe": 0, "unsafe_": 1},
          "exprs":     {"safe": 0, "unsafe_": 3},
          "item_impls":{"safe": 0, "unsafe_": 0},
          "item_traits":{"safe": 0, "unsafe_": 0},
          "methods":   {"safe": 0, "unsafe_": 0}
        },
        "forbids_unsafe": false
      }
    }
  ]
}
```

Top-level key: `packages[]`. Each entry carries a `package.id` object
(`name`, `version`) and an `unsafety` object with `used`, `unused`, and
`forbids_unsafe`. The `used` and `unused` sub-objects contain per-
category counters (`functions`, `exprs`, `item_impls`, `item_traits`,
`methods`), each with `safe` and `unsafe_` integer counts.

**Worked example:**

```bash
# Scan all targets in the workspace
cargo geiger --output-format Json --all-targets

# Scope to one package in a workspace
cargo geiger --output-format Json --all-targets -p my-crate
```

Source: https://github.com/geiger-rs/cargo-geiger

### cargo-vet

**Install:** `cargo install cargo-vet --locked`

**Run command:**

```bash
cargo vet suggest --output-format json
```

The `suggest` subcommand lists unaudited dependencies that need review.
`cargo vet check` exits non-zero when unaudited dependencies exist; use
`suggest` to enumerate them with structured output. Exits 0 when all
dependencies are audited or exempted.

**Expected JSON output shape:**

```json
{
  "suggestions": [
    {
      "crate": "serde",
      "version": "1.0.195",
      "diff_from": "1.0.190",
      "suggested_criteria": ["safe-to-deploy"],
      "notable_parents": ["my-crate"]
    }
  ]
}
```

Top-level key: `suggestions[]`. Each entry carries `crate`, `version`,
`diff_from` (the last audited version, if any), `suggested_criteria`
(what the auditor should certify), and `notable_parents` (direct
dependents of this unaudited crate).

**Worked example:**

```bash
# List all unaudited crates requiring review
cargo vet suggest --output-format json

# Check that all deps are covered (non-zero exit when any are unaudited)
cargo vet check
```

Source: https://mozilla.github.io/cargo-vet/, https://github.com/mozilla/cargo-vet

## Output-field mapping

### cargo-audit → sec-audit finding

| cargo-audit JSON field                        | sec-audit finding field | Notes                                                                                                                                                                                     |
|-----------------------------------------------|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `advisory.aliases[0]` or `advisory.id`        | `id`                     | Prefer `aliases[0]` when it starts with `"CVE-"`, so the downstream cve-enricher picks it up; fall back to the `RUSTSEC-YYYY-NNNN` id otherwise                                          |
| (derived from `advisory.cvss`)                | `severity`               | Parse CVSS base score: >= 9.0 → CRITICAL; 7.0–8.9 → HIGH; 4.0–6.9 → MEDIUM; 0.1–3.9 → LOW; missing or unparseable → MEDIUM (safe default). CVSS string is the ONLY source of severity. |
| `advisory.cwe[0]`                             | `cwe`                    | Pull first entry of the `cwe` integer array (e.g. `[416]` → `"CWE-416"`). If `cwe` is absent or empty, fall back to `"CWE-1104"` — document this fallback; never invent a CWE           |
| `advisory.title`                              | `title`                  | Short advisory title, verbatim                                                                                                                                                            |
| `advisory.description`                        | `evidence`               | Full advisory description, verbatim                                                                                                                                                       |
| `package.name` (synthesised as crate path)    | `file`                   | cargo-audit is lock-file analysis — no source file. Emit `"Cargo.lock"` as the `file` value.                                                                                             |
| (constant)                                    | `line`                   | `0` — no source line; cargo-audit reports at lock-file level                                                                                                                              |
| `advisory.url`                                | `reference_url`          | Advisory page URL; `null` if absent                                                                                                                                                       |
| (synthesised)                                 | `fix_recipe`             | `"Upgrade \`<package.name>\` to the version(s) listed in the advisory (see reference_url)."` — the cve-enricher will overwrite with CVSS/KEV details at merge                            |

Constants on every cargo-audit finding:

- `origin: "rust"`
- `tool: "cargo-audit"`
- `reference: "rust-tools.md"`
- `confidence: "high"` — advisory matches are deterministic version comparisons against a maintained DB

**Severity derivation note:** Severity comes from the advisory's CVSS
string parsed to a numeric base score. The mapping is honest — if the
advisory has no CVSS, the runner MUST default to MEDIUM (not guess a
higher tier). Never derive severity from the advisory title or category.

**CWE fallback note:** `advisory.cwe` is an integer array in cargo-audit
JSON (e.g. `[95, 20]`). Take the first element and format as `"CWE-95"`.
When the array is absent or empty, use `"CWE-1104"` ("Use of Unmaintained
Third-Party Components") as the documented safe default. This fallback MUST
be recorded in the finding's `evidence` or `notes` field so reviewers know
it was derived, not from the advisory itself.

Source: https://github.com/rustsec/rustsec, https://cwe.mitre.org/

### cargo-deny → sec-audit finding

cargo-deny emits one diagnostic object per issue. Each diagnostic maps to
exactly one sec-audit finding.

| cargo-deny JSON field | sec-audit finding field | Notes                                                                                                                                                                              |
|-----------------------|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `code`                | `id`                     | Tool-assigned diagnostic code string (e.g. `"A001"`, `"B003"`, `"L001"`, `"S002"`)                                                                                               |
| `severity`            | `severity`               | `"error"` → HIGH; `"warning"` → MEDIUM; `"note"` or `"help"` → LOW                                                                                                               |
| (per-check-type rule) | `cwe`                    | See per-check-type CWE table below — mapping depends on which check produced the diagnostic                                                                                        |
| `message`             | `title`                  | Diagnostic message string, verbatim                                                                                                                                                |
| `message`             | `evidence`               | Same string as `title`; keep both for schema consistency                                                                                                                           |
| `labels[0].span.path` | `file`                   | Path from the first label span (typically `"Cargo.lock"` or `"Cargo.toml"`); `null` when `labels` is empty                                                                        |
| `labels[0].span.line` | `line`                   | Line from the first label span; `0` when absent                                                                                                                                    |
| (constant)            | `reference_url`          | `null` — cargo-deny diagnostics do not carry per-finding URLs in the JSON output                                                                                                   |
| (constant)            | `fix_recipe`             | `null` — fix action depends on which check fired; the runner does not synthesise one                                                                                               |

Constants on every cargo-deny finding:

- `origin: "rust"`
- `tool: "cargo-deny"`
- `reference: "rust-tools.md"`
- `confidence: "medium"`

**Per-check-type CWE mapping:**

| cargo-deny check | Diagnostic type           | CWE        | Rationale                                                     |
|------------------|---------------------------|------------|---------------------------------------------------------------|
| `advisories`     | advisory match            | From embedded advisory `cwe[0]`; fall back to `"CWE-1104"` when absent | Same derivation as cargo-audit        |
| `bans`           | disallowed crate          | `"CWE-1104"` | Use of unmaintained or prohibited third-party component       |
| `licenses`       | license violation         | `null`     | License compliance is not a CWE-classified vulnerability class |
| `sources`        | disallowed registry/git   | `"CWE-494"` | Download of code without integrity check (supply-chain source) |

Do not emit a CWE for a diagnostic type not in this table — emit `null`.

Source: https://github.com/EmbarkStudios/cargo-deny, https://cwe.mitre.org/

### cargo-geiger → sec-audit finding

cargo-geiger reports unsafe-code presence per package. Every package
whose `unsafety.used.functions.unsafe_` counter is > 0 produces exactly
ONE finding.

| cargo-geiger JSON field                             | sec-audit finding field | Notes                                                                                                         |
|-----------------------------------------------------|--------------------------|---------------------------------------------------------------------------------------------------------------|
| `package.id.name` + `"@"` + `package.id.version`   | `id`                     | Synthesised, e.g. `"libc@0.2.147"`                                                                           |
| (constant)                                          | `severity`               | Always `INFO`. Geiger findings MUST NOT be elevated above INFO without explicit human triage.                 |
| (constant)                                          | `cwe`                    | `null` — unsafe code is not inherently a defect; it is a signal requiring triage, not a classified weakness  |
| (synthesised)                                       | `title`                  | `"Unsafe code in <name>"` e.g. `"Unsafe code in libc"`                                                       |
| (constant)                                          | `file`                   | `"Cargo.lock"` — geiger reports at crate level, not source file level                                        |
| (constant)                                          | `line`                   | `0` — no source line                                                                                          |
| (synthesised from counters)                         | `evidence`               | `"<name>@<version>: used unsafe functions=N, exprs=N; forbids_unsafe=<bool>"` — verbatim counter values      |
| (constant)                                          | `reference_url`          | `null`                                                                                                        |
| (constant)                                          | `fix_recipe`             | `null` — whether unsafe usage is acceptable is a design decision, not a mechanical fix                        |

Constants on every cargo-geiger finding:

- `origin: "rust"`
- `tool: "cargo-geiger"`
- `reference: "rust-tools.md"`
- `confidence: "low"` — presence of unsafe code is a signal, not a confirmed vulnerability; confidence is low until human review

**INFO ceiling:** cargo-geiger findings MUST NOT be escalated above INFO
severity by the runner. The runner emits them at INFO so the triage step
can decide whether any given unsafe block represents an actual risk (e.g.
an FFI boundary into a known-buggy C library) versus an audited, necessary
use of unsafe (e.g. a handwritten allocator). The triage step, not the
runner, makes that judgment.

Source: https://github.com/geiger-rs/cargo-geiger

### cargo-vet → sec-audit finding

Every entry in `suggestions[]` produces exactly ONE finding.

| cargo-vet JSON field    | sec-audit finding field | Notes                                                                                                       |
|-------------------------|--------------------------|-------------------------------------------------------------------------------------------------------------|
| `crate` + `"@"` + `version` | `id`               | Synthesised, e.g. `"serde@1.0.195"`                                                                        |
| (constant)              | `severity`               | Always `LOW` — unaudited status is a supply-chain hygiene gap, not a confirmed vulnerability                |
| (constant)              | `cwe`                    | `null` — absence of audit is not a classified CWE weakness                                                  |
| (synthesised)           | `title`                  | `"Unaudited supply-chain entry: <crate> <version>"`                                                         |
| (constant)              | `file`                   | `"Cargo.lock"`                                                                                              |
| (constant)              | `line`                   | `0`                                                                                                         |
| (synthesised)           | `evidence`               | `"Suggested criteria: <suggested_criteria[]>. Notable parents: <notable_parents[]>. Diff from: <diff_from>."` |
| (constant)              | `reference_url`          | `null`                                                                                                      |
| (synthesised)           | `fix_recipe`             | `"Run \`cargo vet diff <crate> <diff_from> <version>\` and certify, or add an exemption with justification."` |

Constants on every cargo-vet finding:

- `origin: "rust"`
- `tool: "cargo-vet"`
- `reference: "rust-tools.md"`
- `confidence: "medium"`

Source: https://mozilla.github.io/cargo-vet/, https://github.com/mozilla/cargo-vet

## Degrade rules

The `rust-runner` agent follows a three-state sentinel contract identical
to the one used by `webext-runner` (`__webext_status__`), `sast-runner`
(`__sast_status__`), and `dast-runner` (`__dast_status__`).

All four Cargo tools are subcommands of the `cargo` binary. When `cargo`
itself is absent, none of the four tools can run.

**State 1 — NONE available:**

If `cargo` is NOT on `PATH` at all, OR if `cargo` is present but none of
the four subcommands (`audit`, `deny`, `geiger`, `vet`) responds to
`--version`, emit exactly one sentinel line and exit 0:

```json
{"__rust_status__": "unavailable", "tools": []}
```

No findings are emitted. No fabricated results. The sentinel tells the
downstream aggregator that the Rust lane did not run, so its absence of
findings cannot be misread as a clean pass.

**State 2 — SOME available:**

If at least one subcommand is available and functional but not all four,
run the available ones, emit their findings, and then emit a partial-
status summary line listing only the tools that actually ran:

```json
{"__rust_status__": "partial", "tools": ["cargo-audit", "cargo-deny"], "runs": 2, "findings": 7}
```

The `partial` status tells the downstream aggregator that the Rust lane
ran with reduced coverage — findings from the missing tools are simply
absent, not "clean."

**State 3 — ALL available and successful:**

If all four tools ran and each exited with a documented success or
findings-present code, emit the standard status line:

```json
{"__rust_status__": "ok", "tools": ["cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet"], "runs": 4, "findings": 23}
```

**Exit-code semantics per tool:**

| Tool          | Success / findings-present codes      | Tool failure (not a findings event)                                              |
|---------------|---------------------------------------|----------------------------------------------------------------------------------|
| cargo-audit   | `0` (clean), `1` (vulns found)        | Exit >= 127, or stdout is empty / not valid JSON                                 |
| cargo-deny    | `0` (all checks pass), non-zero (checks failed) | Exit >= 127, or stdout is empty / not valid JSON                        |
| cargo-geiger  | `0`                                   | Any non-zero, or stdout is empty / not valid JSON                                |
| cargo-vet     | `0` (all audited), non-zero (unaudited exist) | Exit >= 127, or stdout is empty / not valid JSON                          |

A subcommand exiting non-zero because it FOUND findings (cargo-audit when
vulns are present, cargo-deny when a check fails, cargo-vet when unaudited
deps exist) is NOT a crash — parse its JSON and emit findings. Only treat
as tool failure when JSON is missing/malformed OR exit >= 127.

When a tool was on PATH but its run failed (exit code indicating tool
error, or its JSON could not be parsed), omit it from the `tools[]` list
and do not emit findings for it. If this exhausts all available tools,
emit the `unavailable` sentinel instead of an `ok` or `partial` line.

Source: https://github.com/rustsec/rustsec,
https://github.com/EmbarkStudios/cargo-deny,
https://github.com/geiger-rs/cargo-geiger,
https://mozilla.github.io/cargo-vet/

## Version pins

Minimum tested versions (pinned 2026-04 against upstream stable releases;
later upgrades should update this line):

| Tool          | Minimum version | Key constraint                                                              |
|---------------|-----------------|-----------------------------------------------------------------------------|
| cargo-audit   | 0.20.0          | JSON output schema stable at this version                                   |
| cargo-deny    | 0.16.0          | `--format json` flag stable at this version                                 |
| cargo-geiger  | 0.11.5          | `--output-format Json` flag added in 0.11; 0.11.5 is the minimum safe pin  |
| cargo-vet     | 0.10.0          | `--output-format json` flag stable at this version                          |

All four install via `cargo install <tool> --locked`. The `rust-runner`
agent SHOULD verify each subcommand's version before use:

```bash
cargo audit --version   2>/dev/null  # expect 0.20.x or higher
cargo deny --version    2>/dev/null  # expect 0.16.x or higher
cargo geiger --version  2>/dev/null  # expect 0.11.5 or higher
cargo vet --version     2>/dev/null  # expect 0.10.x or higher
```

If a subcommand is present but reports a version below the minimum, the
runner SHOULD log a warning to stderr (e.g. `rust-runner: cargo-geiger
0.10.3 is below minimum 0.11.5 — Json output format unavailable, skipping`)
and mark the tool as unavailable rather than proceeding, because the JSON
output format may be absent or structurally different. Unlike the WebExt
tools, where older versions still emit parseable JSON, cargo-geiger's JSON
flag did not exist before 0.11 and older versions would fail at invocation.

Source: https://github.com/rustsec/rustsec,
https://github.com/EmbarkStudios/cargo-deny,
https://github.com/geiger-rs/cargo-geiger,
https://mozilla.github.io/cargo-vet/

## Common false positives

The `rust-runner` agent emits these findings at their tool-declared
severity, but the triage step SHOULD downgrade or suppress them when the
listed context applies.

- **cargo-audit findings on crates in `[dev-dependencies]`** that are
  never compiled into production artifacts — a vulnerable test helper or
  benchmark harness does not expose the binary's attack surface. Downgrade
  to `info` when the affected crate appears exclusively in
  `[dev-dependencies]` in every member's `Cargo.toml` and is not
  transitively required by a `[dependencies]` entry.

- **cargo-deny `bans` diagnostics on intentional duplicate versions** in
  workspaces where two subsystems pin different major versions of the same
  crate (e.g. `tokio 0.2` and `tokio 1.x` side by side during a
  migration) — the ban is real but the duplicate is acknowledged. Suppress
  when the workspace `deny.toml` already carries a `skip` or
  `skip-tree` directive for the pair, indicating the team has accepted the
  duplicate during the migration window.

- **cargo-deny `licenses` diagnostics** are packaging/legal findings, not
  security findings. They MUST NOT appear in a security-focused report
  unless the caller has explicitly asked for licence-compliance findings.
  The runner emits them at LOW per the severity mapping; the triage step
  should route them to a separate compliance track rather than the
  security finding list.

- **cargo-geiger INFO findings on `libc`, `cfg-if`, or `std`-facade
  crates** — these crates contain well-audited unsafe blocks that provide
  the safe abstractions the rest of the Rust ecosystem depends on. They
  are routinely reviewed by the Rust library team. Downgrade or suppress
  when the crate name and version are in a maintained allowlist; do not
  suppress wholesale without verifying the version matches the allowlist
  entry.

- **cargo-vet LOW findings on crates that have been audited by a trusted
  third party** (e.g. a crate in the `crates.io-index` that carries a
  `safe-to-deploy` certification from a recognised auditor in the
  `cargo-vet` registry) — if the project's `audits.toml` simply hasn't
  been updated to import that external audit yet, the finding is a
  paperwork gap rather than a genuine supply-chain risk. Flag as
  housekeeping rather than a security finding.

- **cargo-audit MEDIUM-default findings** (where CVSS was absent and the
  runner defaulted to MEDIUM) on advisory categories `unmaintained` or
  `unsound` that have a documented safe workaround and no CVE alias —
  these advisories represent hygiene concerns rather than exploitable
  vulnerabilities. Downgrade to LOW when the advisory category is
  `unmaintained` and no CVE alias exists in `advisory.aliases[]`.

Source: https://github.com/rustsec/rustsec,
https://github.com/EmbarkStudios/cargo-deny,
https://github.com/geiger-rs/cargo-geiger,
https://mozilla.github.io/cargo-vet/,
https://cwe.mitre.org/

## CI notes

These notes apply when the Rust lane runs inside a GitHub Actions workflow
or equivalent CI system.

- **Rust toolchain**: pin the runner's `actions-rs/toolchain` or
  `dtolnay/rust-toolchain` step to a stable channel (e.g. `stable` or a
  pinned `1.77.x`). `cargo install` behaviour and lockfile resolution can
  differ between toolchain versions; a floating `nightly` channel will
  produce non-deterministic scan results.

- **`cargo install` caching**: the four tools can take several minutes to
  compile on first install. Cache `~/.cargo/bin/` and `~/.cargo/registry/`
  between CI runs (e.g. with `actions/cache` keyed on the tool version
  pins in this file). Stale caches that predate a minimum version bump
  MUST be invalidated; key on the version string as well as the runner
  platform.

- **Advisory database freshness**: cargo-audit fetches the RustSec
  advisory DB on each run (to `~/.cargo/advisory-db/` by default).
  Cache this directory between CI runs, but set a max-age of 24 hours —
  stale advisory data misses newly disclosed vulnerabilities. Pass
  `--no-fetch` only when the cache is confirmed fresh to avoid needless
  network fetches on every job step.

- **Exit-code handling**: cargo-audit exits 1 when vulnerabilities are
  found, cargo-deny exits non-zero when a check fails, and cargo-vet exits
  non-zero when unaudited deps exist. A naive `if [ $? -ne 0 ]` guard
  that treats any non-zero as "tool crashed" will silently suppress all
  findings. The runner MUST inspect stdout JSON before deciding whether
  a non-zero exit represents findings or a genuine tool failure.

- **Workspace support**: in a Cargo workspace, run each tool from the
  workspace root so that all member crates are covered. `cargo audit`
  reads the workspace `Cargo.lock`; `cargo deny` reads the workspace
  `Cargo.toml` and the `deny.toml` config; `cargo geiger` traverses the
  full workspace member graph; `cargo vet` reads the workspace
  `supply-chain/` directory.

- **Parallel invocation**: cargo-audit, cargo-geiger, and cargo-vet are
  read-only and safe to run in parallel. cargo-deny is also read-only
  but shares the advisory DB fetch path with cargo-audit — when caching
  is in use, run cargo-audit first (which populates the cache) and then
  launch the remaining three in parallel to avoid cache write contention.

Source: https://github.com/rustsec/rustsec,
https://github.com/EmbarkStudios/cargo-deny,
https://github.com/geiger-rs/cargo-geiger,
https://mozilla.github.io/cargo-vet/
