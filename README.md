# sec-review

A Claude Code plugin that performs **citation-grounded cybersecurity reviews** of web services and servers. It pairs a domain-expert subagent with **live CVE feeds** (NVD 2.0, OSV.dev, GitHub GHSA) to produce a prioritized markdown report of reliable, primary-source-cited fixes.

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

## Known limits & false positives

- **Static analysis only.** This plugin does not execute your code, run SAST binaries, or fuzz endpoints. It greps for dangerous patterns and enriches with CVE feeds.
- **Regex hints over-match.** Every reference file has a `## Common false positives` section. Findings the sec-expert flags as likely FP are emitted with `confidence: low` and a note; review with judgment.
- **Transitive deps are covered by OSV** but only when the manifest exposes them (e.g. `poetry.lock`, `package-lock.json`, `go.sum`). Unlocked `requirements.txt` only lists direct deps.
- **Platform coverage.** Deep CIS-benchmark coverage is strongest for Linux hosts; Windows/IIS targets are out of scope in v0.1.
- **Per-review lookup cap** of 500 CVE queries. Monorepos with many services should be scoped to one service at a time.
- **Secrets detection** is pattern-based (it won't beat a dedicated scanner like gitleaks/trufflehog for history). Consider those as a complement.

## Updating the reference packs

When a primary source changes shape (OWASP cheat-sheet URLs, RFC revisions, feed schema updates), reference files under `skills/sec-review/references/` are the single point of update. The orchestrator skill reads URLs from `cve-feeds.md` — no endpoint strings are inlined in `SKILL.md`.

To contribute a new reference pack:

1. Copy `skills/sec-review/references/_TEMPLATE.md` to a new file.
2. Fill in `## Source` with primary-source URLs only (no blogs, no StackOverflow).
3. Add 3–6 `### <Pattern> — CWE-XXX` entries and 2–4 `### Recipe:` entries.
4. Run the header-presence check from the plan document.

## Layout

```
.claude-plugin/
  plugin.json
  marketplace.json
agents/
  sec-expert.md            — domain-expert subagent
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
