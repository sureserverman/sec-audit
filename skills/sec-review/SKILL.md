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
  "auth":        ["django-sessions"],
  "containers":  ["docker"],
  "ecosystems":  [{"ecosystem": "PyPI", "manifest": "requirements.txt"}]
}
```

## 3. Code analysis — dispatch sec-expert subagent(s)

For each detected stack (usually one, multiple for monorepos), dispatch the
`sec-expert` agent defined at `agents/sec-expert.md`. For monorepos with
more than one independent stack, follow the `dispatching-parallel-agents`
skill: dispatch them concurrently as long as they don't share source files.

Each `sec-expert` call receives:

- The stack-scoped `target_path` (subdir for monorepos, whole tree otherwise).
- The detected technologies (so the agent loads only relevant reference
  files — don't read `frameworks/rails.md` for a Django project).
- The plugin-root path so it can read `skills/sec-review/references/*.md`.

The agent returns JSONL findings per the schema documented in
`agents/sec-expert.md`. Collect all findings (including the final
`__dep_inventory__` object) into a list called `findings`. The dep
inventory feeds step 4.

## 4. CVE enrichment — NVD 2.0 + OSV.dev + GitHub GHSA

Read endpoint details from `references/cve-feeds.md` — **do not inline the
URLs here**. That file is the single choke-point when feed schemas change.

Algorithm for each `(ecosystem, package, version)` tuple in the dep
inventory:

1. **Primary: OSV.dev** — `POST https://api.osv.dev/v1/query` with the
   package/version. OSV covers ~15 ecosystems (PyPI, npm, Maven, Go,
   RubyGems, NuGet, crates.io, Packagist, Debian, Alpine, Ubuntu, ...) in
   one endpoint. No auth, no per-request rate limit to worry about at
   typical review volumes. If `.vulns` is non-empty, capture each vuln's
   `id`, `summary`, `severity`, `references`, and `affected.ranges`.
2. **Fallback: NVD 2.0** — `GET
   https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<pkg>&virtualMatchString=cpe:2.3:a:*:<pkg>:<version>`.
   Used when OSV returns empty for an ecosystem it doesn't cover, or when
   cross-referencing is warranted. Unauth rate limit ~5 req / 30s — use
   `nvd_api_key` if available.
3. **Fallback: GHSA REST** — `GET
   https://api.github.com/advisories?ecosystem=<eco>&affects=<pkg>@<version>`
   for repo-native advisories (including GitHub-only issues not yet in
   NVD). Pass `Authorization: Bearer $GITHUB_TOKEN` if available.
4. **Record source and fetched_at** per CVE so the report is reproducible.
   Structure each enriched finding as `{id, source: "OSV|NVD|GHSA", cvss,
   summary, fixed_versions, references, fetched_at}`.
5. **Degradation on HTTP error / rate-limit**:
   - On 429 or 5xx: retry ONCE with 2-second backoff.
   - On second failure: mark that specific package `cve_enrichment:
     "offline"` and continue — do NOT fail the whole review.
   - If ALL three feeds fail for the entire run, write the report with
     an "⚠ CVE enrichment offline — re-run with network to populate"
     banner at the top. Do NOT fabricate CVE IDs from training data.
6. **Cap lookups at 500 per review**. If the cap is exceeded, warn the
   user and ask them to narrow scope (e.g. review one service at a time).

Attach any matching CVE entries to the corresponding dep-level finding in
the `findings` list. Also promote HIGH/CRITICAL CVSS CVEs to top-level
findings (not just footnotes on the dep inventory).

## 5. Prioritize

Compute a numeric score 0–100 per finding and bucket it.

**Scoring rubric** (deterministic — show the math in the report):

- **CVSS** (0–40 pts): `min(40, cvss_base * 4)` if CVE-enriched; else use
  the sec-expert severity mapped to `CRITICAL=36 / HIGH=28 / MEDIUM=16 /
  LOW=6 / INFO=0`.
- **Exposure** (0–25 pts): `+25` if the affected file is reachable from an
  unauthenticated HTTP path, `+15` if authenticated, `+5` if internal-only
  (admin, cron, worker), `0` if test/fixture code.
- **Exploit-in-wild** (0–20 pts): `+20` if CVE references include "CISA
  KEV", "exploit-db", or "metasploit"; `+10` if there's a public PoC;
  `0` otherwise.
- **Auth-required** (0–15 pts): `+15` if exploit requires no auth; `+8`
  if auth but no elevated privileges; `+2` if admin-only; `0` if attacker
  must already control the host.

Downgrade confidence one step if `cve_enrichment: "offline"` — an unknown
CVSS can't count against the user.

**Buckets**:

| Score  | Bucket   |
|--------|----------|
| 90–100 | CRITICAL |
| 70–89  | HIGH     |
| 40–69  | MEDIUM   |
| 0–39   | LOW      |

Order the report by descending score, CRITICAL first.

## 6. Report

Write `<target_path>/sec-review-report-YYYYMMDD-HHMM.md` (timestamp in
UTC). Structure:

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
