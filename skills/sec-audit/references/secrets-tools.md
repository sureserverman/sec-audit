# secrets-tools

<!--
    Tool-lane reference for sec-audit's secrets lane (v1.21.0+).
    Consumed by the `secrets-runner` sub-agent. Documents
    gitleaks (working-tree scan) + trufflehog (git-history scan).
-->

## Source

- https://github.com/gitleaks/gitleaks — gitleaks canonical (Go binary; secret scanner for files and git history)
- https://github.com/trufflesecurity/trufflehog — trufflehog canonical (Go binary; secret scanner with optional live verification)
- https://cwe.mitre.org/data/definitions/798.html — CWE-798 Use of Hard-coded Credentials

## Scope

In-scope:

- **`gitleaks`** — Go binary; regex + entropy secret detector. Scans the
  **working tree** (`gitleaks dir`) — every file under target, committed or
  not. Feature-complete upstream (v8.x); stable JSON report schema. Runs with
  `--redact` so the raw secret never enters the report.
- **`trufflehog`** — Go binary; detector-based secret scanner with 700+
  credential detectors. Scans the **full git history** (`trufflehog git`) —
  every commit, catching secrets that were committed and later deleted from
  HEAD but remain recoverable from history. Runs with `--no-verification` so
  it makes NO network calls to test whether a credential is live.

Out of scope: `detect-secrets` (Yelp; overlaps gitleaks with a weaker default
ruleset and a baseline-file workflow that does not fit the stateless lane
model), `git-secrets` (AWS; narrow AWS-key regex, subsumed by gitleaks),
`ggshield` (GitGuardian; requires an API key and sends candidate secrets to a
SaaS backend — violates sec-audit's nothing-leaves-the-machine stance).

**Two tools, two surfaces, no redundancy.** gitleaks covers the working tree;
trufflehog covers history. A secret that only ever existed in a deleted commit
is invisible to a working-tree scan and is precisely trufflehog's contribution.

## Canonical invocations

### gitleaks (working-tree scan — always applicable)

- Install: pre-built binaries from GitHub Releases (Linux/macOS/Windows,
  amd64+arm64) / `brew install gitleaks` / `apt install gitleaks` (recent
  Debian/Ubuntu).
- Invocation:
  ```bash
  gitleaks dir "$target_path" \
      --report-format json \
      --report-path "$TMPDIR/gitleaks.json" \
      --exit-code 0 \
      --redact \
      --no-banner
  ```
- **`--redact` is MANDATORY.** It masks the secret substring in both the
  `Secret` and `Match` fields of the report, so the raw credential never
  reaches sec-audit's output. Never invoke gitleaks without it.
- **`--exit-code 0` is MANDATORY.** gitleaks conflates "leaks found" and
  "runtime error" in its default exit code (`1` for both). Forcing the
  leaks-found code to `0` lets the runner distinguish a successful scan (parse
  the report) from a crash (no report file) by the report file's existence, not
  the exit code.
- Subcommand note: `gitleaks dir` is the v8.19+ spelling. Older v8 releases use
  `gitleaks detect --no-git --source <path>`. The runner targets the `dir`
  spelling; on an older gitleaks the probe still succeeds but the invocation may
  need the legacy form — pin ≥ v8.19 (see Version pins).
- Output: JSON array written to `--report-path`. Each element: `RuleID`,
  `Description`, `StartLine`, `EndLine`, `StartColumn`, `EndColumn`, `Match`
  (redacted), `Secret` (redacted — do NOT map), `File`, `Fingerprint`, plus
  `Commit`/`Author`/`Email`/`Date` when scanning a repo.
- Primary source: https://github.com/gitleaks/gitleaks

### trufflehog (git-history scan — git repos only)

- Install: pre-built binaries from GitHub Releases / `brew install trufflehog`.
- Invocation:
  ```bash
  trufflehog git "file://$target_path" \
      --json \
      --no-verification
  ```
- **`--no-verification` is MANDATORY.** Without it, trufflehog makes live
  network calls to each detected credential's service (AWS, GitHub, Stripe, …)
  to test whether it authenticates. sec-audit sends nothing off the machine —
  the flag disables all such calls, yielding unverified findings only.
- Applicable only when the target is a git repository. On a non-git target the
  runner cleanly skips trufflehog with `no-git-history` (the gitleaks
  working-tree scan still runs).
- Output: newline-delimited JSON (one object per finding). Key fields:
  `DetectorName`, `DecoderName`, `Verified` (always `false` under
  `--no-verification`), `Raw` (the PLAINTEXT secret — NEVER map), `Redacted`
  (the masked form — map this), and `SourceMetadata.Data.Git.{file,line,commit}`.
- Tool behaviour: exits `0` on a clean run even with findings (the `--fail`
  flag, which would return `183`, is deliberately NOT passed — the runner reads
  findings from stdout, not the exit code).
- Primary source: https://github.com/trufflesecurity/trufflehog

## Output-field mapping

Every finding carries `origin: "secrets"`, `reference: "secrets-tools.md"`,
`cwe: "CWE-798"`, `severity: "HIGH"`, `confidence: "high"`, `fix_recipe: null`.

### gitleaks → sec-audit finding

| upstream                              | sec-audit field  |
|---------------------------------------|------------------|
| `"gitleaks:" + .RuleID`               | `id`             |
| `.Description`                        | `title`          |
| `.File`                               | `file`           |
| `.StartLine`                          | `line`           |
| `.Match` (redacted, truncated 200)    | `evidence`       |
| `https://github.com/gitleaks/gitleaks`| `reference_url`  |

### trufflehog → sec-audit finding

| upstream                                          | sec-audit field  |
|---------------------------------------------------|------------------|
| `"trufflehog:" + .DetectorName`                   | `id`             |
| `.DetectorName + " secret detected"`              | `title`          |
| `.SourceMetadata.Data.Git.file`                   | `file`           |
| `.SourceMetadata.Data.Git.line`                   | `line`           |
| `.Redacted` (NEVER `.Raw`)                         | `evidence`       |
| null                                              | `reference_url`  |

**Redaction invariant.** `evidence` is ALWAYS the redacted field — gitleaks
`Match` (masked by `--redact`) or trufflehog `Redacted`. The plaintext secret
(gitleaks `Secret`, trufflehog `Raw`) is NEVER mapped into any emitted field.
`tests/secrets-e2e.sh` plants a canary in the recorded fixture's `Raw` field and
asserts it never appears in the golden.

`fix_recipe` is null for every secrets finding: the report's quoted recipe comes
from sec-expert reading `secrets/{env-var-leaks,secret-sprawl,vault-patterns}.md`
(rotate the exposed credential, move it to a secrets manager, purge it from git
history with `git filter-repo`).

## Degrade rules

`__secrets_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary (v1.21.0):

- `tool-missing` — a binary is absent from PATH.
- `no-git-history` — trufflehog is on PATH but the target is not a git
  repository (no `.git`), so there is no history to scan. Target-shape
  clean-skip; gitleaks' working-tree scan still runs, so the lane is `partial`,
  not `unavailable`.

`partial` is the common shape on a non-git target (gitleaks ran, trufflehog
skipped `no-git-history`) or when only one binary is installed. `unavailable`
means neither tool could run. Absence is never a clean scan.

## Version pins

- `gitleaks` ≥ 8.19.0 (the `dir` / `git` subcommand spelling; `--redact`
  percentage form; stable JSON report schema). Pinned 2026-07.
- `trufflehog` ≥ 3.63.0 (stable `--json` NDJSON schema with the
  `Redacted` field; `--no-verification` flag). Pinned 2026-07.
