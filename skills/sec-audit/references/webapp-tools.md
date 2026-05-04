# webapp-tools

<!--
    Tool-lane reference for sec-audit's Webapp lane (v1.14.0+).
    Consumed by the `webapp-runner` sub-agent. Documents
    bearer + njsscan + brakeman.
-->

## Source

- https://github.com/Bearer/bearer — bearer canonical (Apache-2.0; cross-language SAST tuned for OWASP Top 10 + sensitive data flow)
- https://docs.bearer.com/reference/rules/ — bearer rule index
- https://docs.bearer.com/reference/commands/ — bearer CLI reference (incl. `--format json`)
- https://github.com/ajinabraham/njsscan — njsscan canonical (MIT; MobSF-family Node.js static analyzer)
- https://opensecurity.in/njsscan/ — njsscan rule docs
- https://brakemanscanner.org/docs/ — brakeman canonical (MIT; Rails-only SAST)
- https://brakemanscanner.org/docs/options/ — brakeman CLI / output options
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (2021)
- https://cheatsheetseries.owasp.org/ — OWASP Cheat Sheet Series
- https://cwe.mitre.org/

## Scope

In-scope: the three tools invoked by `webapp-runner` —

- **bearer** — cross-language web-app SAST. Supports JavaScript /
  TypeScript, Java, Ruby, PHP, Go, Python. Rule set covers OWASP
  Top 10 (A01 broken access, A03 injection / SQLi / cmd-injection,
  A05 misconfig, A07 auth, A08 deserialization, A10 SSRF) plus
  PII / sensitive-data flow. Emits JSON via `bearer scan --format
  json --report security`. Exit code 0 = clean / no high-severity;
  non-zero = findings present (NOT a crash). Cross-platform.

- **njsscan** — Node.js-specific SAST. Rule set targets Express,
  Hapi, Koa, Fastify, Sails, generic Node patterns. Emits JSON
  via `njsscan --json -o <out.json>`. Cross-platform (pure
  Python, scans `*.js` / `*.ts` / `*.jsx` / `*.tsx`).

- **brakeman** — Ruby-on-Rails-only SAST. Knows Rails idioms
  deeply (strong_parameters bypass, `params.permit` antipatterns,
  `find_by_sql` / `where("...#{x}")` SQLi, ERB SSTI,
  `render file:` path traversal, `redirect_to params[:next]`).
  Emits JSON via `brakeman --format json --no-progress`.
  Cross-platform (pure Ruby).

All three run as pure source-tree static scanners; none execute
target code; none make network calls (bearer's optional
`--external-rule-source` is disabled in our invocation).

**Delineation from existing SAST lane (§3.6):** the SAST lane
runs `semgrep` (`p/owasp-top-ten`) + `bandit` (Python). Why a
separate webapp lane?

1. **bearer adds data-flow tracking** — semgrep's `p/owasp-top-
   ten` is largely syntactic (regex / AST sink-only). bearer
   tracks tainted data from sources (HTTP request body, query
   params, headers) to sinks (SQL exec, subprocess, file system,
   redirect, render-with-html) across function boundaries.
   Findings carry both `source.location` and `sink.location`
   spans.
2. **njsscan covers Node-specific idioms semgrep misses** —
   prototype-pollution sinks, `eval(req.body)`, `child_process.
   exec` with template-string interpolation, regex-DoS in
   request handlers, hardcoded JWT secrets, missing `helmet`
   middleware. semgrep's Node rules in `p/owasp-top-ten` are
   thin.
3. **brakeman is Rails-only and irreplaceable** — Rails idioms
   (`params[:user]`, `respond_to`, `before_action`, `acts_as_*`)
   require parser-aware analysis. semgrep cannot match
   `params.permit(:role)` correctness against the model's
   attribute list; brakeman can.
4. **Reference-pack deepening** — the webapp lane ships
   `webapp/sql-injection.md`, `webapp/ssrf.md`, `webapp/xxe.md`,
   `webapp/path-traversal.md`, `webapp/file-upload.md`,
   `webapp/open-redirect.md`, `webapp/ssti.md`,
   `webapp/mass-assignment.md`, `webapp/idor-bac.md`,
   `webapp/prototype-pollution.md`, `webapp/command-injection-
   web.md`, `webapp/http-header-misuse.md`,
   `webapp/deserialization-web.md` for sec-expert reasoning
   beyond what tool rule-sets cover.

Out of scope: `sqlmap` / `dalfox` / `nuclei` (active fuzzing
— belongs in DAST, not webapp); `phpcs-security-audit` /
`Psalm-Taint` (PHP-specific; deferred); `find-sec-bugs` /
`spotbugs-security` (Java-specific; deferred to a future
java-runner lane).

## Dangerous patterns (regex/AST hints)

> **Operational sentinel:** This file describes how to invoke
> external SAST binaries, not source code under review. Suppress
> grep/AST matches for the invocation strings below when the
> enclosing file path is `references/webapp-tools.md`.

### Running bearer without `--report security` — CWE-1188

- Why: `bearer scan` defaults to a privacy/PII report
  (`--report privacy`) that surfaces sensitive-data findings
  rather than security-class vulnerabilities. The webapp
  lane MUST request `--report security` to get OWASP-Top-10
  findings; the privacy report is a different rule set and is
  not what the lane advertises.
- Grep: `bearer\s+scan(?!.*--report\s+security)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`
- Source: https://docs.bearer.com/reference/commands/

### Running njsscan without `--json` — CWE-1188

- Why: njsscan's default output is human-readable text; the
  format is not a stable contract and shifts between
  versions. Parse JSON only.
- Grep: `njsscan(?!.*--json)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`
- Source: https://github.com/ajinabraham/njsscan

### Running brakeman without `--no-progress` — CWE-1188

- Why: brakeman writes ANSI progress bars to stderr that
  interleave with the JSON on stdout in some shells. Disable
  progress to keep the JSON parser-clean.
- Grep: `brakeman\s+(?!.*--no-progress)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`
- Source: https://brakemanscanner.org/docs/options/

### Bearer / njsscan / brakeman without scope arg — CWE-754

- Why: All three bind to the current working directory when
  no path arg is supplied. The runner MUST pass an explicit
  `target_path` so a CI invocation in the wrong cwd doesn't
  silently scan an empty tree (which produces zero findings
  and looks like a clean scan).
- Grep: `(bearer\s+scan|njsscan|brakeman)\s+--?[a-z]+\s+\S+\s*$`
  (matches invocations that end on a flag value rather than
  a path)
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`
- Source: https://docs.bearer.com/reference/commands/

## Canonical invocations

### bearer

- Install: pre-built binaries from
  https://github.com/Bearer/bearer/releases (Linux/macOS amd64
  +arm64), `brew install bearer/tap/bearer`, or via Docker.
- Invocation:
  ```bash
  bearer scan "$target_path" \
      --report security \
      --format json \
      --output "$TMPDIR/webapp-runner-bearer.json" \
      --quiet \
      2> "$TMPDIR/webapp-runner-bearer.stderr"
  rc_be=$?
  ```
  `--report security` selects the OWASP-Top-10 rule set
  (versus `--report privacy` which surfaces sensitive-data
  findings). `--format json` is the parser-stable contract.
  `--quiet` suppresses progress bars.
- Output: JSON object with top-level keys `critical`, `high`,
  `medium`, `low`, `warning` — each an array of finding
  objects. Each finding has `cwe_ids` (array of `"<n>"`
  strings, no `CWE-` prefix), `id` (rule slug), `title`,
  `description`, `documentation_url`, `line_number`,
  `filename`, `code_extract`.
- Tool behaviour: exit 0 = scan completed (with or without
  findings); non-zero only on configuration / parse error.
  Parse JSON regardless of exit code — clean scans emit
  `{}` or empty severity arrays.
- Primary source: https://docs.bearer.com/reference/commands/

Source: https://github.com/Bearer/bearer

### njsscan

- Install: `pip install njsscan` (Python 3.8+) OR pipx.
  Cross-platform.
- Invocation:
  ```bash
  njsscan --json \
          -o "$TMPDIR/webapp-runner-njsscan.json" \
          "$target_path" \
          2> "$TMPDIR/webapp-runner-njsscan.stderr"
  rc_nj=$?
  ```
- Output: JSON object with top-level keys `nodejs` and
  `templates`, each mapping rule-id → `{ files: [{ file_path,
  match_lines: [...], match_position: [...], match_string }],
  metadata: { cwe, owasp-web, severity, description, ... } }`.
- Tool behaviour: exit 0 = clean; exit 1 = findings; exit ≥2
  = crash. Parse JSON for both 0 and 1.
- Primary source: https://github.com/ajinabraham/njsscan

Source: https://github.com/ajinabraham/njsscan

### brakeman

- Install: `gem install brakeman` (Ruby 2.7+) OR system
  package.
- Invocation:
  ```bash
  brakeman --format json \
           --no-progress \
           --quiet \
           --no-exit-on-warn \
           -o "$TMPDIR/webapp-runner-brakeman.json" \
           "$target_path" \
           2> "$TMPDIR/webapp-runner-brakeman.stderr"
  rc_br=$?
  ```
  `--no-exit-on-warn` keeps exit 0 even when warnings fire
  (we parse JSON, exit code is informational).
- Output: JSON with top-level `warnings: [...]`. Each warning
  has `warning_type`, `warning_code`, `check_name`, `message`,
  `file`, `line`, `link` (URL to brakeman docs),
  `confidence` (`"High" | "Medium" | "Weak"`), `cwe_id`
  (array of integers).
- Tool behaviour: exit 0 = scan ran (with our flag); non-zero
  = parse error or rails-app-not-detected.
- Primary source: https://brakemanscanner.org/docs/options/

Source: https://brakemanscanner.org/docs/options/

## Output-field mapping

Every finding carries `origin: "webapp"`,
`tool: "bearer" | "njsscan" | "brakeman"`,
`reference: "webapp-tools.md"`.

### bearer → sec-audit finding

| upstream                                               | sec-audit field           |
|--------------------------------------------------------|---------------------------|
| `"bearer:" + .id`                                      | `id`                      |
| Top-level severity bucket (`critical` → `CRITICAL`, `high` → `HIGH`, `medium` → `MEDIUM`, `low` → `LOW`, `warning` → `INFO`) | `severity` |
| `"CWE-" + .cwe_ids[0]` (first CWE), null if absent     | `cwe`                     |
| `.title`                                               | `title`                   |
| `.filename` (relative to target_path)                  | `file`                    |
| `.line_number`                                         | `line`                    |
| `.code_extract` (truncated to 200 chars)               | `evidence`                |
| `.documentation_url`                                   | `reference_url`           |
| null (bearer rule docs are advisory; not verbatim-quotable) | `fix_recipe`         |
| `"high"` for `critical`/`high` buckets, `"medium"` for `medium`, `"low"` for `low`/`warning` | `confidence` |

### njsscan → sec-audit finding

| upstream                                               | sec-audit field           |
|--------------------------------------------------------|---------------------------|
| `"njsscan:" + <rule_id>` (the rule key)                | `id`                      |
| `metadata.severity` (`"ERROR" → HIGH`, `"WARNING" → MEDIUM`, `"INFO" → LOW`) | `severity` |
| `"CWE-" + (metadata.cwe \| split(":")[0] \| ltrimstr("CWE-"))` (extract numeric CWE) | `cwe` |
| `metadata.description`                                 | `title`                   |
| `files[0].file_path`                                   | `file`                    |
| `files[0].match_lines[0]`                              | `line`                    |
| `files[0].match_string` (truncated to 200 chars)       | `evidence`                |
| `metadata.owasp-web` (URL when present) else null      | `reference_url`           |
| null                                                   | `fix_recipe`              |
| `"high"` for ERROR, `"medium"` for WARNING, `"low"` for INFO | `confidence`        |

### brakeman → sec-audit finding

| upstream                                               | sec-audit field           |
|--------------------------------------------------------|---------------------------|
| `"brakeman:" + (.warning_code\|tostring) + ":" + .check_name` | `id`               |
| `.confidence` mapped to severity — `"High"` → `HIGH`, `"Medium"` → `MEDIUM`, `"Weak"` → `LOW` (brakeman's confidence IS its severity proxy) | `severity` |
| `"CWE-" + (.cwe_id[0] \| tostring)` (first CWE, null if `cwe_id` is empty) | `cwe`     |
| `.message` (truncated to 200 chars)                    | `title`                   |
| `.file` (relative to target_path)                      | `file`                    |
| `.line` (integer; 0 when brakeman could not localise)  | `line`                    |
| `.message` (verbatim)                                  | `evidence`                |
| `.link`                                                | `reference_url`           |
| null                                                   | `fix_recipe`              |
| `"high"` for `High`-confidence, `"medium"` for `Medium`, `"low"` for `Weak` | `confidence` |

## Degrade rules

`__webapp_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary (v1.14.0):

- `tool-missing` — the tool's binary is absent from PATH.
- `no-webapp-source` — bearer is on PATH but the target has
  no recognised web-framework signal (no Django / Flask /
  FastAPI / Express / Next.js / Rails / Spring source).
  Target-shape clean-skip.
- `no-node-source` — njsscan is on PATH but no `*.js` / `*.ts`
  / `*.jsx` / `*.tsx` files exist under target.
- `no-rails-source` — brakeman is on PATH but the target is
  not a Rails app (no `Gemfile` mentioning `rails` AND no
  `config/application.rb`).

No host-OS gate — all three tools are cross-platform.

## Version pins

- `bearer` ≥ 1.41 (stable `--report security` semantics, JSON
  schema with `cwe_ids[]` array, `--quiet` flag). Pinned
  2026-04.
- `njsscan` ≥ 0.4 (stable JSON schema with `metadata.cwe`,
  `metadata.owasp-web`, `metadata.severity`). Pinned 2026-04.
- `brakeman` ≥ 6.0 (`cwe_id` array on every warning;
  `--no-exit-on-warn` flag stable). Pinned 2026-04.

## Sentinel recipes

### Unavailable (all three missing)

```json
{"__webapp_status__": "unavailable", "tools": [], "skipped": [{"tool": "bearer", "reason": "tool-missing"}, {"tool": "njsscan", "reason": "tool-missing"}, {"tool": "brakeman", "reason": "tool-missing"}]}
```

### Partial (some tools ran, others missing or skipped)

```json
{"__webapp_status__": "partial", "tools": ["bearer"], "skipped": [{"tool": "njsscan", "reason": "no-node-source"}, {"tool": "brakeman", "reason": "no-rails-source"}]}
```

### OK (all available tools ran successfully)

```json
{"__webapp_status__": "ok", "tools": ["bearer", "njsscan"], "skipped": [{"tool": "brakeman", "reason": "no-rails-source"}]}
```

The status line is emitted on its own JSONL line AFTER all
finding lines, exactly once per run. The runner exits 0 in
all three cases — sentinel-on-unavailable, never crash.

## Common false positives

- **bearer `javascript_lang_logger`** — flags every `console.
  log` call as PII risk; downgrade unless the logger
  argument is a tainted-flow source.
- **njsscan `node_loglevel`** — flags `console.log` similarly;
  same downgrade.
- **brakeman `Cross-Site Scripting`** with confidence `Weak`
  — Rails ERB auto-escapes; downgrade unless `raw()` /
  `html_safe` / `<%==` is in the same template.
- **bearer `ruby_rails_render_inline`** on test fixtures — the
  `render inline:` antipattern is real but tests often render
  fixture HTML; downgrade when `file:` is under `spec/` or
  `test/`.
- **njsscan `node_express_csurf`** — flags missing `csurf`
  middleware. csurf was deprecated in 2022; modern Express
  apps use SameSite=Strict cookies + Origin header check.
  Downgrade when the app sets `Origin`-allowlist middleware.
