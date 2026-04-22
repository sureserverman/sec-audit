---
name: sec-review
description: Run a citation-grounded cybersecurity review of a web service, server, or web application. Use when the user asks for a "security review", "CVE scan", "audit dependencies", "harden this service", "check for vulnerabilities", "OWASP review", "scan for secrets", or wants a prioritized list of security fixes for a project. Scopes the target, inventories its tech stack (databases, frameworks, webservers, proxies, frontend, auth, TLS, containers, secrets, supply chain), dispatches the sec-expert subagent to produce structured findings, enriches with live CVE data from NVD 2.0 + OSV.dev + GitHub GHSA, prioritizes by CVSS / exposure / exploit-in-wild / auth-required, and writes a dated markdown report with quoted fixes from primary-source references. Degrades cleanly when CVE feeds are offline.
---

# sec-review — orchestrator skill

Drive a full, citation-grounded security review of a target project. The
skill's job is to coordinate: scope → inventory → dispatch sec-expert →
CVE-enrich → prioritize → report. The sec-expert subagent does the actual
code analysis; this skill orchestrates and enriches.

## Inputs

- `target_path` (required) — absolute path of the project to review.
  The slash command passes `$ARGUMENTS` here.
- `target_url` (optional) — HTTP(S) URL of a running instance of the
  same project, for the DAST lane (§3.7). When absent, DAST is
  skipped; static code analysis and CVE enrichment still run. Read
  from `$DAST_TARGET_URL` env var if unset.
- `github_token` (optional) — used to raise the GHSA rate limit from 60/hr
  to 5000/hr. Read from `$GITHUB_TOKEN` env var if unset.
- `nvd_api_key` (optional) — raises NVD rate limit from ~5/30s to 50/30s.
  Read from `$NVD_API_KEY` env var if unset.

## Output

A markdown report written to
`<target_path>/sec-review-report-YYYYMMDD-HHMM.md`. The report is the
single user-facing deliverable — everything else (JSONL, CVE JSON blobs)
is internal working state.

---

## 1. Scope

Before touching anything, fix the scope and confirm it out loud.

- Confirm `target_path` is readable and is NOT the `sec-review` plugin
  itself. If the user points at the plugin directory, refuse and ask for
  the actual target.
- If `target_path` is a monorepo, ask whether to scope to a subdir
  (`services/api/`, `apps/web/`) or review the whole tree.
- Honor `.gitignore` — skip `node_modules/`, `.venv/`, `dist/`, `build/`,
  `target/`, vendored deps. These will be covered by dependency-pinning
  analysis, not code-pattern analysis.
- Respect project boundaries: if `target_path` contains multiple apps
  with independent stacks, dispatch one sec-expert per stack rather than
  one giant run.

State the final scope (paths included, paths excluded) in the report's
header block so the review is reproducible.

## 2. Inventory

Detect the technology stack. Read only — do not install or execute.

- **Manifests**: `package.json`, `requirements.txt`, `pyproject.toml`,
  `poetry.lock`, `Gemfile(.lock)`, `go.mod`/`go.sum`, `pom.xml`,
  `build.gradle(.kts)`, `Cargo.toml`/`Cargo.lock`, `composer.json`,
  `mix.exs`, `pubspec.yaml`.
- **Infra configs**: `Dockerfile`, `docker-compose.yml`, `kubernetes/*.yml`,
  `nginx.conf` (and `/etc/nginx/conf.d/*.conf`), `httpd.conf`, `Caddyfile`,
  `haproxy.cfg`, `traefik.yml`/`traefik.toml`, `envoy.yaml`.
- **Framework signals**: `settings.py`/`manage.py` (Django), `app.py`
  (Flask/FastAPI), `server.js`/`next.config.js` (Node), `config/routes.rb`
  (Rails), `pom.xml` with `spring-boot-starter-*` (Spring).
- **Frontend signals**: `src/**/*.{tsx,jsx,vue,svelte}`, templates
  (`templates/**/*.html`, `app/views/**/*.erb`, `resources/views/**/*.blade.php`).
- **Browser-extension signals**: `manifest.json` at project root AND the
  file contains a `"manifest_version"` key (2 or 3). Distinguish platform
  by `browser_specific_settings.gecko` (Firefox / AMO) vs absence
  (Chrome / Edge / Chromium). When detected, add `"webext"` to the
  inventory and load `references/frontend/webext-chrome-mv3.md`,
  `references/frontend/webext-firefox-amo.md`, and
  `references/frontend/webext-shared-patterns.md` as appropriate.
- **Auth / secrets signals**: occurrences of `jwt`, `oauth`, `passport`,
  `django-allauth`, `NextAuth`, `SECRET_KEY`, `.env*` files.

Emit an `inventory.json` record (in-memory only) like:

```json
{
  "frameworks":  ["django"],
  "databases":   ["postgres"],
  "webservers":  ["nginx"],
  "proxies":     [],
  "frontend":    ["django-templates"],
  "webext":      [],
  "auth":        ["django-sessions"],
  "containers":  ["docker"],
  "ecosystems":  [{"ecosystem": "PyPI", "manifest": "requirements.txt"}]
}
```

For a browser-extension target the `webext` key carries the detected
platform(s), e.g. `"webext": ["chrome-mv3"]`, `"webext": ["firefox-amo"]`,
or `"webext": ["chrome-mv3", "firefox-amo"]` for a cross-browser
extension (one whose manifest has both a top-level MV3 shape and a
`browser_specific_settings.gecko.id`).

## 3. Code analysis — dispatch sec-expert subagent(s)

For each detected stack (usually one, multiple for monorepos), dispatch the
`sec-expert` agent defined at `agents/sec-expert.md`. For monorepos with
more than one independent stack, follow the `dispatching-parallel-agents`
skill: dispatch them concurrently as long as they don't share source files.

`sec-expert` is pinned to `model: sonnet` in its frontmatter — caller-model
choice (e.g. an Opus-session invocation of `/sec-review`) does NOT inflate
the agent's cost. The same pinning applies to `finding-triager` and
`report-writer` (both sonnet); `cve-enricher` is pinned to `haiku` because
its work is high-volume JSON extraction over HTTP.

Each `sec-expert` call receives:

- The stack-scoped `target_path` (subdir for monorepos, whole tree otherwise).
- The detected technologies (so the agent loads only relevant reference
  files — don't read `frameworks/rails.md` for a Django project).
- The plugin-root path so it can read `skills/sec-review/references/*.md`.

The agent returns JSONL findings per the schema documented in
`agents/sec-expert.md`. Collect all findings (including the final
`__dep_inventory__` object) into a list called `findings`. The dep
inventory feeds step 4.

### 3.5 Triage findings — dispatch finding-triager

Before CVE enrichment, run the raw findings through the `finding-triager`
agent (`agents/finding-triager.md`, pinned to sonnet). It reads the
surrounding code/config context at each `file:line`, applies the
`## Common false positives` guidance from the matched reference pack, and
annotates each finding with:

- `confidence` — `high` / `medium` / `low`
- `fp_suspected` — boolean
- `triage_notes` — one short sentence of justification

The triager **only annotates** — it never drops findings and never
alters the `fix_recipe` string. The rubric in section 5 is the only
thing that downgrades a finding into the LOW bucket, driven by the
`confidence` field the triager sets here. The `__dep_inventory__` line
passes through unchanged.

Input to finding-triager: the raw JSONL stream from sec-expert plus the
plugin root path. Output: the same JSONL stream with the three extra
fields appended to each finding line.

### 3.6 SAST pass — dispatch sast-runner

After triage, run a separate SAST pass on the same `target_path` by
dispatching the `sast-runner` agent (`agents/sast-runner.md`, pinned
to haiku, tools: Read + Bash). The agent shells out to `semgrep` and
`bandit` using the canonical invocations in `references/sast-tools.md`,
parses their native JSON, and emits sec-expert-compatible JSONL on
stdout — every line carrying `origin: "sast"` and `tool: "semgrep"` or
`tool: "bandit"`.

The SAST stream runs in parallel with the sec-expert stream and is
independent of it: SAST findings are additive signal, not replacements.
Collect the SAST JSONL into a `sast_findings` list alongside the
triaged regex findings.

Skill-level invariants the orchestrator enforces on the SAST stream
(the agent reports these states; the skill decides what to do with
them):

- **`__sast_status__: "unavailable"`** — neither `semgrep` nor `bandit`
  was on PATH (or both failed). Add the `⚠ SAST tools unavailable —
  install semgrep and/or bandit to enable static-analysis pass` banner
  to the Review metadata block. Do NOT fabricate findings. Do NOT treat
  the absence as a clean scan.
- **`__sast_status__: "ok"`** — at least one tool ran successfully.
  Merge the SAST findings into the triaged stream. The triager's
  origin-aware rules (see `agents/finding-triager.md`) govern FP
  annotation for any SAST-origin findings that flow back through
  triage on a subsequent pass; by default the SAST findings carry the
  `confidence` the tool or the mapping table sets and are not
  downgraded.
- **Partial availability** — if `tools` in the status line omits a
  binary that was expected, note it in the Review metadata section
  (`SAST tools run: semgrep; bandit skipped — not on PATH`) so the
  absence is visible rather than silent.

The dep-inventory and CVE-enrichment paths are NOT affected by this
pass — SAST findings are code-pattern signal, not package-version
signal.

### 3.7 DAST pass — dispatch dast-runner

When the caller supplies a `target_url` input (an HTTP or HTTPS URL
of a running instance of the target), dispatch the `dast-runner`
agent (`agents/dast-runner.md`, pinned to haiku, tools: Read + Bash).
The agent shells out to OWASP ZAP baseline via docker
(`zaproxy/zap-stable`) or the local `zap-baseline.py`, parses ZAP's
native JSON output, and emits sec-expert-compatible JSONL on stdout —
every line carrying `origin: "dast"` and `tool: "zap-baseline"`.

DAST runs in parallel with sec-expert, sast-runner, and cve-enricher
— its input is a URL, not a file path or a dep inventory, so it
shares nothing with the other agents. Collect the DAST JSONL into a
`dast_findings` list alongside the other streams.

Skill-level invariants the orchestrator enforces on the DAST stream:

- **No `target_url` supplied** — skip DAST entirely. Do NOT fabricate
  a URL from the repo contents. Add a Review-metadata line
  `DAST: skipped — no target_url supplied` so the absence is visible.
- **`__dast_status__: "unavailable"`** — neither `docker` nor
  `zap-baseline.py` was on PATH, the URL was non-HTTP, or the ZAP
  run failed. Add the `⚠ DAST tools unavailable — install docker or
  zap-baseline to enable dynamic-analysis pass` banner to the Review
  metadata block. Do NOT fabricate findings.
- **`__dast_status__: "ok"`** — ZAP ran successfully. Merge the DAST
  findings into the triaged stream. DAST findings carry `file:
  <site hostname or URI>` and `line: 0` because DAST has no source
  line; the report-writer renders `Target: <method> <uri>` from the
  `notes` field instead of the conventional `file:line` locus.
- **DAST baseline is passive only.** The ZAP baseline profile never
  performs active exploitation. Any finding with CRITICAL severity
  must come from a different agent — DAST's maximum is HIGH
  (`riskcode: "3"`).

DAST findings are additive signal. They do NOT feed the dep-inventory
or CVE-enrichment paths; a live scan surfaces runtime issues that
static analysis cannot (reflected XSS, missing security headers on
rendered pages, mixed-content, server banners).

### 3.8 Browser-extension pass — dispatch webext-runner

When the inventory emitted by §2 contains `webext` (the `manifest.json`
+ `manifest_version` detection rule fired), dispatch the `webext-runner`
agent (`agents/webext-runner.md`, pinned to haiku, tools: Read + Bash).
The agent shells out to three Node-based CLIs — `addons-linter`,
`web-ext lint`, and `retire.js` — against the extension source
directory, parses each tool's native JSON output, and emits
sec-expert-compatible JSONL on stdout — every line carrying
`origin: "webext"` and `tool: "addons-linter" | "web-ext" | "retire"`.

webext-runner runs in parallel with sec-expert, sast-runner,
dast-runner, and cve-enricher — its input is the extension source
tree, which other agents may also read but do not mutate, so they
share nothing observable. Collect the webext JSONL into a
`webext_findings` list alongside the other streams.

Skill-level invariants the orchestrator enforces on the webext stream:

- **No `webext` in inventory** — skip this pass entirely. Do NOT probe
  for browser-extension tools on an unrelated project; the tools are
  node-based and noisy on server/backend trees.
- **`__webext_status__: "unavailable"`** — none of `addons-linter`,
  `web-ext`, or `retire` was on PATH, the target directory had no
  `manifest.json`, or every tool crashed. Add the `⚠ Browser-extension
  tools unavailable — install addons-linter, web-ext, or retire to
  enable WebExtension analysis pass` banner to the Review metadata
  block. Do NOT fabricate findings.
- **`__webext_status__: "partial"`** — some tools ran successfully
  and others were missing or crashed. Merge the findings from the
  tools that ran; note the missing/failed tools in the Review-metadata
  section (`WebExt tools run: addons-linter, retire; web-ext skipped —
  not on PATH`).
- **`__webext_status__: "ok"`** — every available tool ran. Merge the
  webext findings into the triaged stream. Webext findings carry
  `file: <relative path>` (e.g. `manifest.json`, `background/sw.js`)
  and `line: <integer>` when the tool supplied one; retire findings
  carry `line: 0` because the upstream advisory has no line.
- **Retire findings with a CVE** — when a retire finding's `id` is a
  `CVE-YYYY-NNNN` string, the cve-enricher MUST pick it up and attach
  CVSS / KEV / fix-version metadata just as it does for manifest-
  derived CVEs. The dep-inventory path in §4 is extended to include
  retire's `{component, version}` pairs.

Webext findings combine code-pattern signal (addons-linter rules) with
package-version signal (retire.js). The dep-inventory path IS affected:
retire's `{component, version}` pairs feed the cve-enricher as an
additional ecosystem entry with `ecosystem: "retire"` so OSV/NVD/GHSA
lookups run against them.

## 4. CVE enrichment — dispatch cve-enricher

Dispatch the `cve-enricher` agent (`agents/cve-enricher.md`, pinned to
haiku). It consumes the dep inventory emitted by sec-expert and returns a
structured JSON document — one object per package with its CVEs and a
`status` field (`ok` / `offline` / `capped`). Moving CVE enrichment into a
haiku-pinned agent keeps the main skill context small and makes the
per-package I/O loop cheap.

The agent uses the OSV `querybatch` endpoint for the primary lookup (up
to 1000 queries per call, returning vuln IDs only), follows up with
per-id detail fetches, and falls back to NVD 2.0 and GHSA for packages
OSV doesn't cover. Endpoint URLs live in `references/cve-feeds.md` —
`cve-enricher` reads them at runtime; they are NOT inlined here or in
the agent body. That file is the single choke-point when feed schemas
change.

Skill-level invariants the orchestrator still enforces (the agent
reports these states; the skill decides what to do with them):

- **Per-package `status: "offline"`** — keep the package in the report,
  but mark `CVE(s): Unknown — feed offline` in its finding block.
- **Per-package `status: "capped"`** — we hit the 500-lookup cap; emit a
  `Limits hit: cve_lookup_cap_500` entry in the Review metadata section
  and ask the user to narrow scope on re-run.
- **All-feeds-offline run** — when every package has `status: "offline"`,
  add the `⚠ CVE enrichment offline — re-run with network to populate`
  banner at the top of the report. The report still lists the full
  finding set from sec-expert. Never fabricate CVE IDs from training
  data under any circumstance.
- **Retry and cap** — the agent enforces retry-once-with-2s-backoff and
  the 500 cap itself; the skill just validates the shape of what comes
  back.

Attach each CVE entry to the corresponding dep-level finding, and
promote HIGH/CRITICAL CVSS CVEs to top-level findings (not just footnotes
on the dep inventory).

## 5. Prioritize

Compute a numeric score 0–100 per finding and bucket it.

**Scoring rubric** (deterministic — show the math in the report):

- **CVSS** (0–40 pts): `min(40, cvss_base * 4)` if CVE-enriched; else use
  the sec-expert severity mapped to `CRITICAL=36 / HIGH=28 / MEDIUM=16 /
  LOW=6 / INFO=0`.
- **Exposure** (0–25 pts): `+25` if the affected file is reachable from an
  unauthenticated HTTP path, `+15` if authenticated, `+5` if internal-only
  (admin, cron, worker), `0` if test/fixture code.
- **Exploit-in-wild** (0–20 pts): `+20` if `cve.kev == true` (CISA KEV
  catalog, cross-referenced by `cve-enricher`); `+10` if there's a public
  PoC reference; `0` otherwise. Note: `cve.kev == null` means the KEV feed
  was offline — unknown is unknown, no points awarded.
- **Auth-required** (0–15 pts): `+15` if exploit requires no auth; `+8`
  if auth but no elevated privileges; `+2` if admin-only; `0` if attacker
  must already control the host.

Downgrade confidence one step if `cve_enrichment: "offline"` — an unknown
CVSS can't count against the user. Note: the base `confidence` field this
rubric reads is set by the `finding-triager` agent (section 3.5), not by
this skill. This skill's only confidence adjustment is the offline
downgrade above; all other confidence decisions belong to the triager.

**Buckets**:

| Score  | Bucket   |
|--------|----------|
| 90–100 | CRITICAL |
| 70–89  | HIGH     |
| 40–69  | MEDIUM   |
| 0–39   | LOW      |

Order the report by descending score, CRITICAL first.

## 6. Report — dispatch report-writer

Dispatch the `report-writer` agent (`agents/report-writer.md`, pinned to
sonnet) with the triaged findings, the cve-enricher output, and the
inventory. The agent writes
`<target_path>/sec-review-report-YYYYMMDD-HHMM.md` (timestamp in UTC) and
returns the absolute path to stdout so the orchestrator can confirm
placement.

This section documents the report template so it remains readable in the
skill source — but generation is **delegated** to the agent. Keeping the
template here is for humans reading the skill; the agent is the single
source of truth for actual report shape. Do not inline the markdown build
into this skill's context.

Template (the agent follows this exactly):

```markdown
# Security Review — <target_basename>

**Date (UTC):** 2026-04-21 14:32
**Scope:** <paths included>
**Excluded:** <paths excluded>
**Inventory:** <terse stack summary>
**CVE feeds:** OSV (ok), NVD (ok), GHSA (ok)   <!-- or "offline" -->
**Findings:** 1 CRITICAL, 4 HIGH, 7 MEDIUM, 3 LOW

---

## CRITICAL

### <title>
- **File:** `<path>:<line>`
- **CWE:** CWE-<n>
- **CVE(s):** CVE-YYYY-NNNNN (CVSS 9.8, source: OSV, fetched 2026-04-21T14:30Z)
- **Score:** 94 / 100 (CVSS 40 + Exposure 25 + Exploit 20 + NoAuth 15, confidence: high)
- **Evidence:**
  ```
  <exact line from sec-expert>
  ```
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > <verbatim Fix recipe from the reference file>
- **Sources:**
  - <primary-source URL from reference>
  - <CVE advisory URL(s)>

## HIGH
<...same shape...>

## MEDIUM
<...>

## LOW
<...>

---

## Dependency CVE summary

| Package | Version | CVEs | Max CVSS | Fixed in |
|---------|---------|------|----------|----------|
| django  | 2.2.0   | 7    | 9.8      | 3.2.25+  |

## Review metadata

- Plugin version: `sec-review 0.1.0`
- Reference packs loaded: <list>
- sec-expert runs: <n>
- Total CVE lookups: <n>
- Limits hit: <list or "none">
```

Each finding block MUST include `file:line`, the CWE, any matched CVE
IDs, the numeric score (with the breakdown), the evidence snippet, the
recommended fix (quoted verbatim from a reference file's `## Fix
recipes`), and primary-source URLs. The report is the only user-facing
deliverable — make it the thing a reviewer could hand to an engineer.
