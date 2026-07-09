# Security Review — sec-audit

> ⚠ **SELF-AUDIT NOTICE** — this report is sec-audit auditing its own source
> tree (commit `3bca41c`, plugin version 1.27.0). The §1 scope guard that
> normally prevents sec-audit from reviewing its own repository was
> deliberately overridden at the user's explicit request for this run.

**Date (UTC):** 2026-07-09 17:38
**Scope:** `scripts/secaudit/*.py` (stdlib-only Python, 9 modules), `push-purged-history.sh` + `tests/*.sh` harness, AI-tool config surface (`.claude-plugin/`, `commands/`, `agents/` [30 files], `skills/sec-audit/SKILL.md`), `.github/workflows/ci.yml`
**Excluded:** `tests/fixtures/**` (intentionally-vulnerable fixtures that exist to prove lanes fire — all rust/go/c-cpp/php/k8s/iac/virt/webext/supply-chain/image inventory signals and all 5 dependency-ecosystem manifests live only there), `docs/`, the prior report `sec-audit-report-20260527-2055.md`
**Inventory:** ai-tools (claude-code), python (scripts, stdlib-only), shell (scripts), gh-actions (push/pull_request) — no web framework, no database, no containers, no third-party dependencies
**CVE feeds:** not applicable (no third-party dependencies)
**Findings:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 54 LOW (+2 INFO informational, not counted in this tally)

## Per-lane summary

| Lane       | Status  | Tools run                                      | Findings | Skipped                                                  |
|------------|---------|-------------------------------------------------|---------:|-----------------------------------------------------------|
| sec-expert | ok      | (code reasoning)                                | 32       | —                                                           |
| sast       | partial | semgrep                                         | 4        | bandit (tool-missing)                                      |
| shell      | ok      | shellcheck                                      | 15       | —                                                           |
| gh-actions | ok      | actionlint, zizmor                              | 5        | —                                                           |
| ai-tools   | partial | jq                                              | 0        | mcp-scan (tool-missing)                                     |

Lanes not present in this table were out of scope for the self-audit (see
`Review metadata` → `Lane filter applied`) or had no dispatch trigger
(dast — no `target_url`; python — pip-audit/ruff not on PATH; secrets —
gitleaks/trufflehog not on PATH).

## LOW

The findings below fall into four clusters. The first — 30 near-identical
`CWE-693` unscoped-`Bash`-grant findings, one per `agents/*.md` runner
adapter plus `commands/sec-audit.md` — form a single systemic pattern and
are consolidated into one entry with a file list rather than rendered as 30
near-identical blocks. sec-expert flagged the pattern **FP-suspected**
(reasoning: runner adapters legitimately invoke a varying set of external
CLI scanners), but the finding-triager **rejected** the FP claim
(`confidence: high`, `fp_suspected: false`) because the reference pack's
runner-adapter exemption requires explicit `Bash(toolname:*)` scoping per
invoked binary, which is absent from every one of these files. All 30
score LOW (21/100) only because exposure is internal (host-run plugin, not
network-facing) and exploitation would require indirect prompt injection
from content read out of an audited target tree — not because the
underlying pattern is disputed.

The second cluster is 4 `zizmor` findings on `.github/workflows/ci.yml`
(one `zizmor:template-injection` duplicate at the identical `file:line`
was deduplicated from the raw 5-finding scan output — noted at that
entry below). The third cluster is 4 `semgrep` findings, all matched
inside reference-pack **documentation prose** (`skills/sec-audit/references/**.md`)
rather than executable code and triaged `fp_suspected: true`. The fourth
cluster is 15 `shellcheck` hygiene findings across `tests/*.sh`, none of
which carry a security CWE mapping.

### Unscoped `Bash` tool grant across 30 agent/command frontmatter files (no argument filter)

- **Files:**
  - `agents/android-runner.md:5` — `tools: Read, Bash`
  - `agents/k8s-runner.md:5` — `tools: Read, Bash`
  - `agents/supply-chain-runner.md:5` — `tools: Read, Bash`
  - `agents/go-runner.md:5` — `tools: Read, Bash`
  - `agents/ios-runner.md:5` — `tools: Read, Bash`
  - `agents/sast-runner.md:5` — `tools: Read, Bash`
  - `agents/ai-tools-runner.md:5` — `tools: Read, Bash`
  - `agents/c-cpp-runner.md:5` — `tools: Read, Bash`
  - `agents/linux-runner.md:5` — `tools: Read, Bash`
  - `agents/iac-runner.md:5` — `tools: Read, Bash`
  - `agents/dep-diff-analyst.md:5` — `tools: Read, Bash, WebFetch`
  - `agents/gh-actions-runner.md:5` — `tools: Read, Bash`
  - `agents/ansible-runner.md:5` — `tools: Read, Bash`
  - `agents/webapp-runner.md:5` — `tools: Read, Bash`
  - `agents/netcfg-runner.md:5` — `tools: Read, Bash`
  - `agents/cve-enricher.md:6` — `tools: Read, WebFetch, Bash`
  - `agents/python-runner.md:5` — `tools: Read, Bash`
  - `agents/sec-expert.md:5` — `tools: Read, Grep, Glob, Bash, WebFetch`
  - `agents/php-runner.md:5` — `tools: Read, Bash`
  - `agents/virt-runner.md:5` — `tools: Read, Bash`
  - `agents/dast-runner.md:5` — `tools: Read, Bash`
  - `agents/webext-runner.md:5` — `tools: Read, Bash`
  - `agents/report-writer.md:5` — `tools: Read, Write, Bash`
  - `agents/image-runner.md:5` — `tools: Read, Bash`
  - `agents/rust-runner.md:5` — `tools: Read, Bash`
  - `agents/macos-runner.md:5` — `tools: Read, Bash`
  - `agents/shell-runner.md:5` — `tools: Read, Bash`
  - `agents/secrets-runner.md:5` — `tools: Read, Bash`
  - `agents/windows-runner.md:5` — `tools: Read, Bash`
  - `commands/sec-audit.md:3` — `allowed-tools: Read, Grep, Glob, Bash, WebFetch, Agent`
- **CWE:** CWE-693
- **Origin:** sec-expert (code reasoning)
- **CVE(s):** None detected by configured feeds.
- **Score:** 21 / 100 (CVSS 16 + Exposure 5 + Exploit 0 + NoAuth 0, confidence: high — triage_notes: "Frontmatter shows `tools: Read, Bash` [or the file's specific tool list] with no argument filter on Bash; no FP bullet in the pack exempts runner-adapter design intent.")
- **Evidence:**
  ```
  tools: Read, Bash
  ```
  (per-file evidence strings shown in the file list above; three files —
  `dep-diff-analyst.md`, `cve-enricher.md`, `sec-expert.md`, `report-writer.md` —
  carry additional non-Bash tools alongside the unscoped `Bash` grant)
- **Recommended fix** (quoted from `references/ai-tools/claude-code-plugin.md`):
  > ---
  > name: run-tests
  > description: Run the project test suite using pytest.
  > allowed-tools:
  >   - Bash(pytest:*)
  >   - Bash(python -m pytest:*)
  >   - Read
  > ---
- **Sources:**
  - https://docs.claude.com/en/docs/claude-code/agents

### `zizmor:artipacked` — credential persistence through GitHub Actions artifacts

- **File:** `.github/workflows/ci.yml:17`
- **CWE:** CWE-522
- **Origin:** gh-actions (zizmor)
- **CVE(s):** None detected by configured feeds.
- **Score:** 19 / 100 (CVSS 6 + Exposure 5 + Exploit 0 + NoAuth 8, confidence: medium)
- **Evidence:**
  ```
  credential persistence through GitHub Actions artifacts
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://woodruffw.github.io/zizmor/audits/#artipacked

### `zizmor:dangerous-triggers` — use of fundamentally insecure workflow trigger

- **File:** `.github/workflows/ci.yml:4`
- **CWE:** CWE-94
- **Origin:** gh-actions (zizmor)
- **CVE(s):** None detected by configured feeds.
- **Score:** 19 / 100 (CVSS 6 + Exposure 5 + Exploit 0 + NoAuth 8, confidence: medium)
- **Evidence:**
  ```
  use of fundamentally insecure workflow trigger
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://woodruffw.github.io/zizmor/audits/#dangerous-triggers

### `zizmor:template-injection` — code injection via template expansion

> Note: the raw zizmor scan reported this finding twice at the identical
> `file:line` (`.github/workflows/ci.yml:29`); the duplicate report has
> been deduplicated to a single entry below.

- **File:** `.github/workflows/ci.yml:29`
- **CWE:** CWE-94
- **Origin:** gh-actions (zizmor)
- **CVE(s):** None detected by configured feeds.
- **Score:** 19 / 100 (CVSS 6 + Exposure 5 + Exploit 0 + NoAuth 8, confidence: medium)
- **Evidence:**
  ```
  code injection via template expansion
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://woodruffw.github.io/zizmor/audits/#template-injection

### `zizmor:unpinned-uses` — unpinned action reference

- **File:** `.github/workflows/ci.yml:17`
- **CWE:** CWE-829
- **Origin:** gh-actions (zizmor)
- **CVE(s):** None detected by configured feeds.
- **Score:** 19 / 100 (CVSS 6 + Exposure 5 + Exploit 0 + NoAuth 8, confidence: medium)
- **Evidence:**
  ```
  unpinned action reference
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://woodruffw.github.io/zizmor/audits/#unpinned-uses

### `generic.nginx.security.request-host-used.request-host-used` — '$http_host'/'$host' may contain attacker-controlled Host header (matched inside reference documentation)

- **File:** `skills/sec-audit/references/webservers/nginx.md:53`
- **CWE:** CWE-290
- **Origin:** sast (semgrep)
- **CVE(s):** None detected by configured feeds.
- **Score:** 16 / 100 (CVSS 16 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: medium — triage_notes: "semgrep rule matched inside reference-pack documentation prose, not executable code — FP.")
- **Evidence:**
  ```
  '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header.
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://github.com/yandex/gixy/blob/master/docs/en/plugins/hostspoofing.md

### `java.spring.security.audit.spring-actuator-non-health-enabled.spring-actuator-dangerous-endpoints-enabled` — Spring Boot Actuators "health,info" are enabled (matched inside reference documentation)

- **File:** `skills/sec-audit/references/frameworks/spring.md:154`
- **CWE:** CWE-200
- **Origin:** sast (semgrep)
- **CVE(s):** None detected by configured feeds.
- **Score:** 16 / 100 (CVSS 16 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: medium — triage_notes: "semgrep rule matched inside reference-pack documentation prose, not executable code — FP.")
- **Evidence:**
  ```
  Spring Boot Actuators "health,info" are enabled. Depending on the actuators, this can pose a significant security risk.
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-endpoints-exposing-endpoints

### `java.spring.security.audit.spring-actuator-non-health-enabled.spring-actuator-dangerous-endpoints-enabled` — Spring Boot Actuators enabled (matched inside reference documentation)

- **File:** `skills/sec-audit/references/frameworks/spring.md:189`
- **CWE:** CWE-200
- **Origin:** sast (semgrep)
- **CVE(s):** None detected by configured feeds.
- **Score:** 16 / 100 (CVSS 16 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: medium — triage_notes: "semgrep rule matched inside reference-pack documentation prose, not executable code — FP.")
- **Evidence:**
  ```
  Spring Boot Actuators pattern matched in doc prose.
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-endpoints-exposing-endpoints

### `java.spring.security.audit.spring-actuator-non-health-enabled.spring-actuator-dangerous-endpoints-enabled` — Spring Boot Actuators enabled (matched inside reference documentation)

- **File:** `skills/sec-audit/references/secrets/env-var-leaks.md:218`
- **CWE:** CWE-200
- **Origin:** sast (semgrep)
- **CVE(s):** None detected by configured feeds.
- **Score:** 16 / 100 (CVSS 16 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: medium — triage_notes: "semgrep rule matched inside reference-pack documentation prose, not executable code — FP.")
- **Evidence:**
  ```
  Spring Boot Actuators pattern matched in doc prose.
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-endpoints-exposing-endpoints

### `shellcheck:SC2034` — target_path appears unused. Verify use (or export if used externally).

- **File:** `tests/k8s-drill.sh:8`
- **CWE:** —
- **Origin:** shell (shellcheck)
- **CVE(s):** None detected by configured feeds.
- **Score:** 16 / 100 (CVSS 16 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: high)
- **Evidence:**
  ```
  target_path appears unused. Verify use (or export if used externally).
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://www.shellcheck.net/wiki/SC2034

### `shellcheck:SC2034` — target appears unused. Verify use (or export if used externally).

- **File:** `tests/deep-deps-drill.sh:24`
- **CWE:** —
- **Origin:** shell (shellcheck)
- **CVE(s):** None detected by configured feeds.
- **Score:** 16 / 100 (CVSS 16 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: high)
- **Evidence:**
  ```
  target appears unused. Verify use (or export if used externally).
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://www.shellcheck.net/wiki/SC2034

### `shellcheck:SC2088` — Tilde does not expand in quotes. Use $HOME.

- **File:** `tests/ai-tools-e2e.sh:99`
- **CWE:** —
- **Origin:** shell (shellcheck)
- **CVE(s):** None detected by configured feeds.
- **Score:** 16 / 100 (CVSS 16 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: high)
- **Evidence:**
  ```
  Tilde does not expand in quotes. Use $HOME.
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://www.shellcheck.net/wiki/SC2088

### `shellcheck:SC2164` — Use 'cd ... || exit' or 'cd ... || return' in case cd fails.

- **File:** `tests/ci-local.sh:14`
- **CWE:** —
- **Origin:** shell (shellcheck)
- **CVE(s):** None detected by configured feeds.
- **Score:** 16 / 100 (CVSS 16 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: high)
- **Evidence:**
  ```
  Use 'cd ... || exit' or 'cd ... || return' in case cd fails.
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://www.shellcheck.net/wiki/SC2164

### `shellcheck:SC2016` — Expressions don't expand in single quotes, use double quotes for that. (11 occurrences)

- **Files:**
  - `tests/diff-e2e.sh:34`
  - `tests/diff-e2e.sh:35`
  - `tests/diff-e2e.sh:40`
  - `tests/diff-e2e.sh:80`
  - `tests/diff-e2e.sh:81`
  - `tests/diff-e2e.sh:83`
  - `tests/contract-check.sh:1469`
  - `tests/ai-tools-e2e.sh:55`
  - `tests/ai-tools-drill.sh:99`
  - `tests/ai-tools-drill.sh:103`
  - `tests/ai-tools-drill.sh:109`
- **CWE:** —
- **Origin:** shell (shellcheck)
- **CVE(s):** None detected by configured feeds.
- **Score:** 6 / 100 (CVSS 6 + Exposure 0 + Exploit 0 + NoAuth 0, confidence: high)
- **Evidence:**
  ```
  Expressions don't expand in single quotes, use double quotes for that.
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://www.shellcheck.net/wiki/SC2016

## Informational (INFO — not counted in severity tally)

### Detected stack: Claude Code plugin (30 agents, SKILL.md, commands), stdlib-only Python 9 modules (scripts/secaudit/), bash test/drill harness (tests/*.sh), GitHub Actions CI (.github/workflows/ci.yml)

- **File:** `.claude-plugin/plugin.json:1`
- **CWE:** CWE-1006
- **Origin:** sec-expert (code reasoning)
- **CVE(s):** None detected by configured feeds.
- **Score:** 5 / 100 (CVSS 0 + Exposure 5 + Exploit 0 + NoAuth 0, confidence: high — triage_notes: "Informational stack-detection summary, not a vulnerability claim; no FP lookup applicable.")
- **Evidence:**
  ```
  "name": "sec-audit", "version": "1.27.0"
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://docs.claude.com/en/docs/claude-code/plugins

### net.py restricts outbound requests to http/https scheme only; no per-request destination allow-list beyond env-configured feed bases

- **File:** `scripts/secaudit/net.py:17`
- **CWE:** CWE-918
- **Origin:** sec-expert (code reasoning)
- **CVE(s):** None detected by configured feeds.
- **Score:** 5 / 100 (CVSS 0 + Exposure 5 + Exploit 0 + NoAuth 0, confidence: low — triage_notes: "INFO note only; SSRF assessed as FP class per webapp/ssrf.md (operator-configured base URLs).")
- **Evidence:**
  ```
  return urllib.parse.urlparse(url).scheme not in ("http", "https")
  ```
- **Recommended fix:** (no reference recipe available — confidence: low)
- **Sources:**
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

## Dependency CVE summary

| Package | Version | CVEs | Max CVSS | Max EPSS | Fixed in |
|---------|---------|------|----------|----------|----------|
| (no CVE data — feed offline or no dependencies found) | — | — | — | — | — |

Rendered per instructions as "none — no third-party dependencies": sec-audit
ships stdlib-only Python and has no manifest-declared or bundled
third-party dependency ecosystems in the reviewed scope (the five
dependency-ecosystem manifests that exist in this repository live only
under the excluded `tests/fixtures/**` tree). CVE enrichment was therefore
a structural no-op for this run, not a feed outage.

## Review metadata

- Plugin version: sec-audit 1.27.0
- Reference packs loaded: ai-tools/claude-code-plugin.md, ai-tools/prompt-injection.md, python/subprocess-and-async.md, shell/command-injection.md, shell/file-handling.md, shell/script-hardening.md, webapp/ssrf.md, webapp/path-traversal.md, infra/gh-actions-permissions.md, infra/gh-actions-secrets.md
- sec-expert runs: 1
- Lanes dispatched: sec-expert, sast, shell, gh-actions, ai-tools
- Lane filter applied: none
- SAST tools run: semgrep (bandit — skipped, not on PATH)
- DAST tools run: skipped — no target_url supplied
- WebExt tools run: skipped — no webext detected in reviewed scope (real webext manifest only present under excluded tests/fixtures/**)
- Rust tools run: skipped — no Rust inventory signal in reviewed scope (fixtures only, excluded)
- Android tools run: skipped — no Android inventory signal in reviewed scope (fixtures only, excluded)
- iOS tools run: skipped — no iOS inventory signal in reviewed scope (fixtures only, excluded)
- Linux tools run: skipped — no Linux-daemon inventory signal in reviewed scope (fixtures only, excluded)
- macOS tools run: skipped — no macOS inventory signal in reviewed scope (fixtures only, excluded)
- Windows tools run: skipped — no Windows inventory signal in reviewed scope (fixtures only, excluded)
- Total CVE lookups: 0
- Limits hit: none

Additional scoped-out lanes for this self-audit (inputs live only under
the excluded `tests/fixtures/**` tree): go, c-cpp, php, k8s, iac, virt,
supply-chain, image, netcfg, ansible, webapp.

ai-tools lane: jq validated `.claude-plugin/plugin.json`,
`.claude-plugin/marketplace.json`, and `.claude/settings.local.json` —
all structurally valid, 0 findings; mcp-scan skipped (not on PATH).
