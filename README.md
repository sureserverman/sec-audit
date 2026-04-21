# sec-review

A Claude Code plugin that performs **citation-grounded cybersecurity reviews** of web services and servers. It pairs a **four-agent pipeline** (domain-expert + triager + CVE enricher + report-writer, each model-pinned for cost efficiency) with **live CVE feeds** (NVD 2.0, OSV.dev, GitHub GHSA) to produce a prioritized markdown report of reliable, primary-source-cited fixes.

The plugin is arranged as its own single-plugin marketplace — one `/plugin marketplace add` makes it installable.

---

## Install

From a Claude Code session:

```text
/plugin marketplace add https://github.com/<you>/sec-review.git
/plugin install sec-review
```

Or for a local clone:

```text
/plugin marketplace add /home/user/dev/sec-review
/plugin install sec-review
```

After install, two things become available:

- `/sec-review <path-to-project>` — slash command, the primary entry point.
- `Skill sec-review` — the same behavior as a skill invocation (natural-language triggers: "do a security review", "CVE scan this repo", "audit dependencies", "harden this service").

Optional env vars (not required):

- `GITHUB_TOKEN` — raises GHSA rate limit from 60/hr to 5000/hr.
- `NVD_API_KEY` — raises NVD rate limit from ~5 req / 30s to 50 req / 30s.

## Quick start

```text
/sec-review /abs/path/to/my-web-app
```

The review writes its report to `<target>/sec-review-report-YYYYMMDD-HHMM.md` (UTC timestamp). Open it when the run finishes — it's the only user-facing deliverable.

A CRITICAL finding block from a real run against the sample fixture looks like:

```markdown
### Django 2.2.0 — SQL injection via QuerySet.annotate()/aggregate()/extra() (CVE-2022-28346)
- **File:** `requirements.txt:1` (dep); reachable sink at `app/views/search.py:9`
- **CWE:** CWE-89
- **CVE(s):** CVE-2022-28346 (CVSS 9.8, source: OSV, fetched 2026-04-21T11:01Z)
- **Score:** 90 / 100 (CVSS 40 + Exposure 25 + Exploit 10 + NoAuth 15, confidence: high)
- **Evidence:** `cursor.execute("SELECT … WHERE name = '" + q + "'")`
- **Recommended fix** (quoted from `references/frameworks/django.md`):
  > cursor.execute("SELECT … WHERE user_id = %s", [user_id])
```

## What it checks

Static analysis plus live CVE enrichment across ten security domains. Each reference pack in `skills/sec-review/references/` carries dangerous-pattern regexes, secure-pattern snippets, and verbatim fix recipes — all cited to primary sources (OWASP, RFC, CIS, vendor docs, NIST):

| Domain | Covered |
|---|---|
| Web frameworks | Django, Flask, FastAPI, Express, Next.js, Rails, Spring |
| Databases | PostgreSQL, MySQL, MongoDB, Redis, SQLite |
| Webservers | nginx, Apache, Caddy |
| Proxies / LB | HAProxy, Traefik, Envoy |
| Frontend | XSS, CSP, CSRF, SameSite cookies |
| Auth | OAuth 2.0/2.1, OIDC, JWT, sessions, MFA, password storage |
| TLS | TLS BCP (RFC 9325), HSTS (RFC 6797), cert rotation |
| Containers | Docker daemon, Kubernetes PSS/RBAC, Dockerfile hardening |
| Secrets | Secret sprawl, Vault patterns, env-var leaks |
| Supply chain | Dep pinning, SLSA, Sigstore, SBOM |

The full reference list is in `skills/sec-review/references/` — 43 files, each citation-grounded.

## CVE feeds & privacy

Reviews query live CVE data from three sources (documented in `skills/sec-review/references/cve-feeds.md`):

1. **OSV.dev** — primary feed (covers ~15 ecosystems). No auth, no data sent beyond `{ecosystem, package, version}` tuples.
2. **NVD 2.0** — fallback by CPE or keyword. No auth required; API key optional for higher rate limit.
3. **GHSA REST** — GitHub Security Advisories. Anonymous by default; optional `GITHUB_TOKEN` for higher rate limit.

No source code from the target project is ever sent to external services. Only package name, ecosystem, and version strings leave the machine, and only toward the three endpoints above.

If all three feeds fail (rate limit, network, outage), the review still completes with a `⚠ CVE enrichment offline` banner. The plugin will **never** fabricate CVE IDs from training data — when offline, the dep inventory is surfaced without enrichment, and the user can re-run with network later.

## Rigor (v0.3.0)

Three quality-of-review improvements landed in v0.3.0 without architectural change:

- **CISA KEV cross-reference.** The `cve-enricher` agent fetches the CISA Known Exploited Vulnerabilities catalog once per run, indexes it by CVE ID, and attaches `kev: true|false|null` plus `kev_date_added` / `kev_due_date` to every CVE. The scoring rubric's Exploit-in-wild sub-score is now a direct `kev == true` check instead of fuzzy substring matching on reference text. `kev: null` (KEV feed offline) awards zero points — unknown is unknown; the agent never fabricates a KEV hit.
- **Per-agent token-cost accounting.** `tests/measure-pipeline.sh <tokens.json>` converts a per-agent tokens JSON into a blended-rate cost figure, using rates pinned in `tests/model-costs.json`. The v0.2.0 baseline (on the sample-stack fixture) landed at **$0.5575 / 112K tokens**; the v0.3.0 Stage 3 baseline with KEV added captured **$1.2644 / 244K tokens** — most of the spread is sub-agent dispatch variance across runs, not the KEV adapter (which is one extra HTTP fetch + index). Runtime only exposes `total_tokens`, so costing is blended at an assumed 3:1 input:output ratio; when per-token-type fields become visible, `model-costs.json` already carries `input_per_mtok` and `output_per_mtok` for a one-line upgrade.
- **Offline-degradation drill.** `tests/offline-drill.sh` stands up a local 503 mock (`tests/offline-mock.py`), proves every override URL routes to it, and asserts the pipeline's offline path produces the ⚠ banner and zero fabricated CVE IDs. The `cve-enricher` agent now honors four env-var overrides (`OSV_BASE_URL`, `NVD_BASE_URL`, `GHSA_BASE_URL`, `KEV_URL`) with a stderr audit log on each active override — reviews run against an internal mirror or air-gapped cache are visibly distinguishable from live-feed runs.

## Windows/IIS coverage (v0.4.0)

A new reference pack `skills/sec-review/references/webservers/iis.md`
extends sec-review to **Microsoft IIS 10** configuration audits. The
pack covers eight hardening patterns grounded in primary sources:

- **TLS policy** — TLS 1.0 / 1.1 enablement on `sslProtocols`; `ssl3`
  surface.
- **Directory browsing** — `<directoryBrowse enabled="true">` leaking
  directory contents.
- **Server / X-Powered-By headers** — missing `remove` rules in
  `<customHeaders>` revealing IIS + ASP.NET version to attackers.
- **Error disclosure** — `<customErrors mode="Off">` and
  `<httpErrors errorMode="Detailed">` leaking stack traces.
- **Anonymous IUSR authentication** — enabled in
  `applicationHost.config` without explicit ACLs.
- **machineKey AutoGenerate with IsolateApps** — breaks session state
  and view-state validation across the farm.
- **`maxAllowedContentLength` unset or huge** — enabling DoS via body
  size.
- **Missing security headers** — HSTS, X-Content-Type-Options,
  X-Frame-Options absent from `<customHeaders>`.

Primary sources cited in the pack: **CIS Microsoft IIS 10 Benchmark**,
**NIST NCP / DISA STIG for IIS 10**, Microsoft Learn
(`system.webServer` / `system.applicationHost` schema), OWASP Secure
Headers, Mozilla SSL Configuration, **RFC 9325** (TLS BCP), and
**RFC 6797** (HSTS). Fixture `tests/fixtures/iis-stack/` ships the full
set of vulnerable patterns so regression tests fail loudly if the pack
drifts.

Windows OS hardening (registry policy, WinRM, SMB signing, Defender
exclusions) remains out of scope — that territory needs live-host
interaction rather than code/config review.

## SAST adapter (v0.4.0)

A fifth agent, **`sast-runner`** (haiku-pinned, `Read` + `Bash`
tools), joins the pipeline as an opt-in static-analysis pass dispatched
in parallel with `sec-expert`. It shells out to two tools when they are
on `PATH`:

- **Semgrep** (`semgrep scan --config=p/owasp-top-ten --json
  --metrics=off`) — OWASP Top Ten ruleset with telemetry suppressed so
  the shape of the audited codebase never leaves the machine.
- **Bandit** (`bandit -r <target> -f json --exit-zero`) — Python-only,
  run recursively with structured JSON output.

Output is sec-expert-compatible JSONL: every finding carries
`origin: "sast"` and `tool: "semgrep" | "bandit"`, mapped per the
field-mapping recipes in `skills/sec-review/references/sast-tools.md`.
The `finding-triager` agent is origin-aware — SAST findings consult
the SAST pack's `## Common false positives` in addition to the matched
domain pack and are never dropped.

**Fixes still come from the regex packs, not from the SAST tools.**
Semgrep and bandit surface a signal and a rule ID — they don't ship
quoted, verbatim fix recipes in the sec-review sense, so every SAST
finding lands with `fix_recipe: null`. The regex-based domain packs
remain the single source of truth for the `> Recommended fix` block in
the final report.

**Degrade path.** When neither binary is on `PATH`, the agent emits a
single sentinel line `{"__sast_status__": "unavailable", "tools": []}`
and exits clean. The orchestrator adds a `⚠ SAST tools unavailable`
banner to the Review metadata section — absence of SAST findings is
visibly distinguishable from a clean SAST scan. `tests/sast-drill.sh`
enforces this contract by scrubbing PATH and asserting the unavailable
output shape. No SAST finding is ever fabricated.

## DAST lane (v0.5.0)

A sixth agent, **`dast-runner`** (haiku-pinned, `Read` + `Bash`
tools), joins the pipeline as an opt-in dynamic-analysis pass
dispatched in parallel with `sec-expert` and `sast-runner`. Unlike
SAST, DAST needs a running target — the agent is a no-op unless the
orchestrator is passed a `target_url` (or the agent is invoked with
`$DAST_TARGET_URL` set). It shells out to OWASP ZAP baseline when
available:

- **Docker** (preferred): `docker run --rm -v <tmp>:/zap/wrk/:rw
  --user $(id -u):$(id -g) zaproxy/zap-stable zap-baseline.py -t
  <URL> -J report.json -I -m <max-minutes>` — passive-only scan,
  exits cleanly on warnings/failures via `-I`.
- **Local** `zap-baseline.py` when docker is absent: same flags,
  writing the JSON report to a tempdir.

Output is sec-expert-compatible JSONL: every finding carries
`origin: "dast"`, `tool: "zap-baseline"`, `file: <URI>`, and
`line: 0` (there is no source line for a live scan — the URI and
request method live in `notes`). ZAP's `riskcode` ("0"–"3") maps to
INFO/LOW/MEDIUM/HIGH. Baseline never emits CRITICAL — it is a
passive scan, not exploitation. `cweid` maps to `CWE-<n>` when
present. Field-mapping recipes live in
`skills/sec-review/references/dast-tools.md`.

**Fixes still come from the regex packs and reference files, not
from ZAP.** DAST findings land with `fix_recipe: null`; the
triager's domain-pack lookup is what supplies the quoted fix in the
final report.

**Degrade path.** When the orchestrator runs without a
`target_url`, the DAST pass is skipped entirely and a
`dast skipped (no target_url)` metadata line appears in the report.
When a URL is supplied but neither docker nor `zap-baseline.py` is
on `PATH`, the agent emits a single sentinel line
`{"__dast_status__": "unavailable", "tools": []}` and exits clean.
The orchestrator adds a `⚠ DAST tools unavailable` banner.
`tests/dast-drill.sh` enforces this contract by scrubbing PATH and
asserting the unavailable output shape. No DAST finding is ever
fabricated.

## Known limits & false positives

- **No exploitation, no fuzzing.** The plugin does not fuzz endpoints, brute-force credentials, or exploit findings. SAST invokes semgrep/bandit when available; DAST invokes ZAP baseline (passive-only) against a supplied `target_url`. Everything else is grep + CVE-feed enrichment.
- **Regex hints over-match.** Every reference file has a `## Common false positives` section. Findings the sec-expert flags as likely FP are emitted with `confidence: low` and a note; review with judgment.
- **Transitive deps are covered by OSV** but only when the manifest exposes them (e.g. `poetry.lock`, `package-lock.json`, `go.sum`). Unlocked `requirements.txt` only lists direct deps.
- **Platform coverage.** Deep CIS-benchmark coverage is strongest for Linux hosts. **IIS webserver configuration** (`web.config`, `applicationHost.config`) is covered as of v0.4.0 via `references/webservers/iis.md`. Windows OS hardening (registry, WinRM, SMB, Defender policy) remains out of scope — that territory needs live-host interaction rather than code/config review.
- **Per-review lookup cap** of 500 CVE queries. Monorepos with many services should be scoped to one service at a time.
- **Secrets detection** is pattern-based (it won't beat a dedicated scanner like gitleaks/trufflehog for history). Consider those as a complement.

## Updating the reference packs

When a primary source changes shape (OWASP cheat-sheet URLs, RFC revisions, feed schema updates), reference files under `skills/sec-review/references/` are the single point of update. The orchestrator skill reads URLs from `cve-feeds.md` — no endpoint strings are inlined in `SKILL.md`.

To contribute a new reference pack:

1. Copy `skills/sec-review/references/_TEMPLATE.md` to a new file.
2. Fill in `## Source` with primary-source URLs only (no blogs, no StackOverflow).
3. Add 3–6 `### <Pattern> — CWE-XXX` entries and 2–4 `### Recipe:` entries.
4. Run the header-presence check from the plan document.

## Architecture

v0.2.0 splits the review into four specialist agents, each pinned to the
right model class, glued together by the `sec-review` orchestrator skill:

```
   /sec-review <path>
          │
          ▼
  ┌───────────────────────┐
  │  skills/sec-review    │    orchestrator: scope, inventory,
  │     SKILL.md          │    rubric, dispatch — stays lean
  └───┬────────┬──────┬───┘
      │        │      │
      ▼        │      │
  ┌────────────┴──┐   │
  │  sec-expert   │   │    sonnet · inventory + grep + raw findings
  │  (sonnet)     │   │                (no triage, no CVE I/O)
  └──────┬────────┘   │
         │ JSONL      │
         ▼            │
  ┌───────────────┐   │
  │ finding-      │   │    sonnet · context-aware FP annotation;
  │ triager       │   │                never drops findings
  │ (sonnet)      │   │
  └──────┬────────┘   │
         │ JSONL      │
         │        ┌───▼──────────┐
         │        │ cve-enricher │  haiku · OSV querybatch + NVD +
         │        │ (haiku)      │          GHSA fallback, retry+cap
         │        └──────┬───────┘
         │               │ JSON
         ▼               ▼
       ┌───────────────────┐
       │   report-writer   │   sonnet · composes final markdown
       │   (sonnet)        │             from triaged + enriched
       └───────┬───────────┘
               ▼
      sec-review-report-YYYYMMDD-HHMM.md
```

| Agent             | Model (pinned) | Role                                                 |
|-------------------|----------------|------------------------------------------------------|
| `sec-expert`      | `sonnet`       | Inventory + grep + raw JSONL findings. No triage.   |
| `finding-triager` | `sonnet`       | Context-aware FP annotation; sets `confidence`.     |
| `cve-enricher`    | `haiku`        | OSV querybatch + NVD/GHSA fallback; retry + 500 cap.|
| `report-writer`   | `sonnet`       | Composes final markdown from all upstream outputs.  |

Model pinning makes sub-agent cost independent of caller model — invoking
`/sec-review` from an Opus session does not upgrade any sub-agent to Opus.

## Layout

```
.claude-plugin/
  plugin.json
  marketplace.json
agents/
  sec-expert.md            — inventory + grep + raw findings (sonnet)
  finding-triager.md       — context-aware FP annotation (sonnet)
  cve-enricher.md          — OSV querybatch + NVD/GHSA fallback (haiku)
  report-writer.md         — final markdown composition (sonnet)
skills/
  sec-review/
    SKILL.md               — orchestrator
    references/
      _TEMPLATE.md
      frameworks/          — Django, Flask, FastAPI, Express, Next.js, Rails, Spring
      databases/           — Postgres, MySQL, MongoDB, Redis, SQLite
      webservers/          — nginx, Apache, Caddy
      proxies/             — HAProxy, Traefik, Envoy
      frontend/            — XSS, CSP, CSRF, cookies
      auth/                — OAuth2, OIDC, JWT, sessions, MFA, passwords
      tls/                 — TLS BCP, HSTS, cert rotation
      containers/          — Docker, Kubernetes, Dockerfile hardening
      secrets/             — sprawl, Vault, env leaks
      supply-chain/        — pinning, SLSA, Sigstore, SBOM
      cve-feeds.md         — NVD 2.0 / OSV / GHSA adapter spec
commands/
  sec-review.md            — /sec-review slash command
tests/fixtures/
  tiny-django/             — minimal Django SQLi+XSS fixture
  sample-stack/            — Django + nginx + Docker + vulnerable deps
```

## License

MIT. See `LICENSE`.
