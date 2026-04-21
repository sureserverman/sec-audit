# SAST Tools

## Source

- https://semgrep.dev/docs/cli-reference — Semgrep CLI reference (official)
- https://semgrep.dev/docs/semgrep-appsec-platform/json-and-sarif — Semgrep JSON schema
- https://semgrep.dev/explore — Semgrep Registry (p/owasp-top-ten, p/ci, etc.)
- https://bandit.readthedocs.io/en/latest/ — Bandit documentation (official)
- https://bandit.readthedocs.io/en/latest/plugins/index.html — Bandit test plugin catalog
- https://github.com/PyCQA/bandit — Bandit source repo
- https://cwe.mitre.org/ — CWE index (for mapping tool rules to CWEs)

## Scope

This reference pack documents the two SAST binaries invoked by the
`sast-runner` sub-agent (Semgrep and Bandit). It specifies canonical CLI
invocations, JSON output schemas, field mappings to sec-review's finding
schema, and offline-degrade rules. Out of scope: SARIF output format
(sec-review uses Semgrep JSON not SARIF), custom rule authoring, and other
SAST tools (gosec, brakeman, spotbugs-security — deferred to future
versions).

## Dangerous patterns (regex/AST hints)

> **Operational sentinel:** This file describes how to invoke external SAST
> binaries, not source code under review. Suppress grep/AST matches for the
> invocation strings below when the enclosing file path is
> `references/sast-tools.md`. This section lists "invocations that go wrong"
> — the anti-patterns apply to scripts and CI config that shell out to
> semgrep or bandit, not to product code.

### Running semgrep without --metrics=off — CWE-359

- Why: Semgrep's default behaviour sends scan telemetry (rule IDs, file
  hashes, environment metadata) to semgrep.dev. In a security review
  context this leaks the shape of the audited codebase to a third party.
  The `sast-runner` agent MUST disable metrics on every invocation.
- Grep: `semgrep\s+(scan|ci|--config)(?!.*--metrics)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`, `**/*.py`
- Source: https://semgrep.dev/docs/cli-reference

### Running bandit or semgrep without JSON output — CWE-1188

- Why: The default human-readable text output is not a stable contract;
  columns, colour codes, and wording change across versions. Parsing it
  with regex breaks silently on upgrade and produces empty finding sets
  that look like "clean scan." The runner MUST request structured output
  (`--json` for semgrep, `-f json` for bandit).
- Grep: `semgrep\s+scan(?!.*--json)|bandit\s+(?!.*-f\s+json)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`
- Source: https://semgrep.dev/docs/cli-reference,
  https://bandit.readthedocs.io/en/latest/

### Running bandit without -r — CWE-754

- Why: Without `-r` (recursive), bandit scans only the files or top-level
  directory contents passed on the command line and silently skips
  subdirectories. A repo root invocation without `-r` will miss the entire
  `src/` tree and report zero issues, which callers misread as a clean
  codebase.
- Grep: `bandit\s+(?!-r|.*\s+-r\b)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`
- Source: https://bandit.readthedocs.io/en/latest/

### Ignoring semgrep exit codes 3/4/5/7 — CWE-755

- Why: Semgrep distinguishes "scan completed, no findings" (exit 0),
  "findings present with --error" (exit 1), "invalid configuration" (exit
  3), "unparseable rule file" (exit 4), "unknown language" (exit 5), and
  "registry fetch failed" (exit 7). Scripts that treat anything non-zero
  as "findings" (or worse, only check `exit == 0`) hide broken scanner
  configuration as a false-clean result. The runner MUST branch on the
  specific code and surface 3/4/5/7 as a tool failure, not a finding
  count.
- Grep: `semgrep.*\|\|\s*true|semgrep.*;\s*exit\s*0`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`
- Source: https://semgrep.dev/docs/cli-reference

### Running semgrep without --error in gating CI — CWE-703

- Why: Without `--error`, semgrep exits 0 even when findings are present,
  so a CI job that only checks the exit code will merge code with known
  HIGH findings. In a gating context the runner MUST pass `--error`; in a
  non-gating context it MUST still parse the JSON findings array.
- Grep: `semgrep\s+scan(?!.*--error)` (only in gating CI steps)
- File globs: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `**/*.sh`
- Source: https://semgrep.dev/docs/cli-reference

## Secure patterns

Canonical invocations for the `sast-runner` agent. Each is the minimum
correct form — callers may add `--exclude`, `--timeout`, or targeting
flags, but MUST NOT drop any flag shown here.

```bash
# Semgrep baseline — OWASP Top Ten ruleset, JSON to stdout, telemetry off,
# non-zero exit on any finding (gating mode).
semgrep scan \
  --config=p/owasp-top-ten \
  --json \
  --metrics=off \
  --error \
  <target>
```

Source: https://semgrep.dev/docs/cli-reference

```bash
# Bandit baseline — recursive scan, JSON output to a file for later
# parsing. Bandit writes progress to stderr, findings to the output file.
bandit -r <target> -f json -o <out.json>
```

Source: https://bandit.readthedocs.io/en/latest/

```bash
# Non-gating CI — run both tools, always exit 0, let the parser decide
# severity. For semgrep, drop --error. For bandit, add --exit-zero so the
# job does not fail when findings exist; the runner still parses the JSON
# and emits findings into sec-review's pipeline.
semgrep scan --config=p/owasp-top-ten --json --metrics=off <target>
bandit -r <target> -f json -o <out.json> --exit-zero
```

Source: https://semgrep.dev/docs/cli-reference,
https://bandit.readthedocs.io/en/latest/

```bash
# Semgrep Registry configs that pair well with sec-review reviews:
#   p/owasp-top-ten  — broad OWASP coverage (default for sec-review)
#   p/ci             — curated, low-noise CI ruleset
#   p/security-audit — deeper audit ruleset, higher noise
# Use --config multiple times to stack packs; duplicates are de-duped by
# rule ID.
semgrep scan \
  --config=p/owasp-top-ten \
  --config=p/ci \
  --json --metrics=off --error <target>
```

Source: https://semgrep.dev/explore

## Fix recipes

These recipes document the contract between the `sast-runner` sub-agent
and the rest of the sec-review pipeline. They are NOT fix recipes in the
user-code sense; each recipe specifies how a tool's native JSON maps into
sec-review's canonical finding schema.

### Recipe: Semgrep result → sec-review finding

Semgrep `--json` emits `{"results": [...], "errors": [...], ...}`. Each
element of `results` maps to exactly one sec-review finding as follows:

| Semgrep JSON field                   | sec-review finding field | Notes                                                                      |
|--------------------------------------|--------------------------|----------------------------------------------------------------------------|
| `check_id`                           | `id`                     | e.g. `python.lang.security.audit.exec-use`                                 |
| `extra.severity`                     | `severity`               | Map `ERROR` → `HIGH`, `WARNING` → `MEDIUM`, `INFO` → `LOW` (per JSON schema docs) |
| `extra.metadata.cwe[0]`              | `cwe`                    | Semgrep stores CWE as a list of strings; take index 0. If absent, emit `null` |
| `extra.message`                      | `title`                  | Also duplicated into `evidence`                                            |
| `extra.message`                      | `evidence`               | Same string as `title`; keep both for schema consistency                   |
| `path`                               | `file`                   | Path as semgrep reports it, relative to the scan target                    |
| `start.line`                         | `line`                   | 1-indexed                                                                  |
| `extra.metadata.references[0]`       | `reference_url`          | First element of the list; emit `null` if the list is empty or absent      |

Plus these constant fields on every semgrep-sourced finding:

- `origin: "sast"`
- `tool: "semgrep"`
- `reference: "sast-tools.md"`
- `fix_recipe: null`
- `confidence: "medium"`

The `extra.severity` → `severity` mapping is the one documented in the
Semgrep JSON schema: ERROR is the highest rule-author-declared level,
WARNING is middle, INFO is lowest. sec-review's HIGH/MEDIUM/LOW tiers
match one-to-one.

Source: https://semgrep.dev/docs/semgrep-appsec-platform/json-and-sarif

### Recipe: Bandit result → sec-review finding

Bandit `-f json` emits `{"results": [...], "metrics": {...}, ...}`. Each
element of `results` maps to exactly one sec-review finding:

| Bandit JSON field   | sec-review finding field | Notes                                                          |
|---------------------|--------------------------|----------------------------------------------------------------|
| `test_id`           | `id`                     | e.g. `B602`                                                    |
| `issue_severity`    | `severity`               | Verbatim — bandit already uses `HIGH`/`MEDIUM`/`LOW`           |
| `test_id`           | `cwe`                    | Looked up in the plugin-to-CWE table below; `null` if unmapped |
| `issue_text`        | `title`                  | Also duplicated into `evidence`                                |
| `issue_text`        | `evidence`               | Same string as `title`                                         |
| `filename`          | `file`                   | Absolute path as bandit reports it                             |
| `line_number`       | `line`                   | 1-indexed                                                      |
| `more_info`         | `reference_url`          | May be absent or empty; emit `null` in that case               |
| `issue_confidence`  | `confidence`             | `HIGH` → `high`, `MEDIUM` → `medium`, `LOW` → `low`            |

Plus constants on every bandit-sourced finding:

- `origin: "sast"`
- `tool: "bandit"`
- `reference: "sast-tools.md"`
- `fix_recipe: null`

Plugin-to-CWE mapping table (sec-review v0 — extend as new rules are
adopted):

| Bandit test ID | Short name              | CWE     |
|----------------|-------------------------|---------|
| `B602`         | subprocess `shell=True` | CWE-78  |
| `B303`         | Weak hash (md5/sha1)    | CWE-327 |
| `B105`         | Hardcoded password      | CWE-798 |
| `B201`         | Flask `debug=True`      | CWE-94  |
| `B608`         | SQL via string format   | CWE-89  |

If `test_id` is not present in the table, emit `cwe: null` — do not guess.

Source: https://bandit.readthedocs.io/en/latest/,
https://bandit.readthedocs.io/en/latest/plugins/index.html,
https://cwe.mitre.org/

### Recipe: Unavailable-tool sentinel

When neither `semgrep` nor `bandit` is installed on `PATH`, the
`sast-runner` agent MUST NOT emit any findings and MUST NOT guess. It
emits exactly one line to stdout:

```json
{"__sast_status__": "unavailable", "tools": []}
```

Exit code 0. No findings, no partial results. The downstream aggregator
reads this sentinel and propagates it into the top-level review summary so
that the absence of SAST findings cannot be misread as a clean SAST pass.

Source: https://semgrep.dev/docs/cli-reference,
https://bandit.readthedocs.io/en/latest/

### Recipe: Status summary line

After all available tools have run and all findings have been emitted, the
`sast-runner` agent emits exactly one final JSON line at the END of stdout
(after every finding):

```json
{"__sast_status__": "ok", "tools": ["semgrep","bandit"], "runs": 2, "findings": 17}
```

- `tools` is the list of tools that actually executed (omit any that were
  not on `PATH`).
- `runs` is the number of successful tool invocations.
- `findings` is the total count of findings emitted this run (across all
  tools).

This line is mandatory — its absence means the agent crashed mid-run and
the finding set is untrusted.

Source: https://semgrep.dev/docs/semgrep-appsec-platform/json-and-sarif,
https://bandit.readthedocs.io/en/latest/

## Common false positives

The `sast-runner` agent emits these findings with normal confidence, but
the triage step SHOULD downgrade or suppress them when the listed context
applies.

- **Bandit B101 (`assert_used`)** in files under `tests/`, `test_*.py`, or
  `*_test.py` — asserts in a test suite are the correct pytest idiom, not
  a security issue. Downgrade to `info` or suppress entirely when the path
  matches a test glob.
- **Bandit B404 (`import subprocess`)** — flagging an import is not a
  vulnerability on its own; only the unsafe *use* of `subprocess` (captured
  separately by B602/B603/B605) is a sink. B404 is often a low-confidence
  noise entry and should be dropped unless paired with a use-site finding
  in the same file.
- **Semgrep `generic.secrets.security.detected-*`** on fixture files under
  `tests/fixtures/`, `testdata/`, or `**/__fixtures__/` — these are
  placeholder tokens for test inputs, not real credentials. Downgrade to
  `info` when the path clearly marks a fixture directory.
- **Semgrep `python.lang.security.audit.exec-use`** on code-generator or
  scaffolding scripts under `scripts/`, `tools/`, or `codegen/` — `exec()`
  in a build-time generator that never runs in production is a different
  risk class than `exec()` in a request handler. Downgrade confidence
  unless the file is imported from production code paths.
- **Bandit B311 (`random` module)** in files that clearly use it for
  non-cryptographic purposes (fuzzing seeds, sampling, jitter) — the real
  risk is `random` for tokens/keys, which is covered by other rules.
  Downgrade when no key/token/secret lexeme is near the call site.
