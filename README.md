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

## Browser-extension lane (v0.6.0)

A seventh agent, **`webext-runner`** (haiku-pinned, `Read` + `Bash`
tools), joins the pipeline whenever the §2 inventory detects a
browser extension — a `manifest.json` at project root containing a
`"manifest_version"` key (2 or 3). The runner is dispatched in
parallel with `sec-expert`, `sast-runner`, `dast-runner`, and
`cve-enricher`. It shells out to three Node-based CLIs when available:

- **`addons-linter`** (Mozilla's official AMO validator) — emits
  rule-coded errors / warnings / notices, with security-rule codes
  (e.g. `MANIFEST_CSP_UNSAFE_DIRECTIVE`, `DANGEROUS_EVAL`) mapped to
  CWE via the table in `references/webext-tools.md`.
- **`web-ext lint`** — Mozilla's developer-tool linter; same JSON
  schema as addons-linter (it wraps it), separate `tool` tag so the
  origin-tag isolation check can distinguish which runner flagged
  each finding.
- **`retire.js`** — flags bundled vulnerable JavaScript libraries in
  the extension source tree. CVE-carrying findings flow into the
  `cve-enricher` step via the `retire` ecosystem and appear as rows in
  the final report's Dependency CVE summary table alongside manifest-
  declared dependencies.

Output is sec-expert-compatible JSONL: every finding carries
`origin: "webext"` and one of
`tool: "addons-linter" | "web-ext" | "retire"`. `file` is the
relative path inside the extension (e.g. `manifest.json`,
`background/sw.js`, `lib/jquery-1.12.4.min.js`); `line` is the integer
line number the tool supplied, or `0` when it did not (retire.js has
no line; addons-linter `notice` type often omits it). Field-mapping
recipes live in `skills/sec-review/references/webext-tools.md`; the
code-pattern reference packs (MV3, AMO, shared) live in
`skills/sec-review/references/frontend/webext-*.md`.

**Fixes for code-pattern findings come from the `frontend/webext-*`
packs**, not from addons-linter's one-liner messages; the triager's
domain-pack lookup supplies the quoted before/after recipe in the
final report. **Retire.js findings are upgrade-only**: the
recommended fix is synthesised from the advisory's `below` field
("Upgrade `jquery` beyond 3.0.0"), never invented.

**Three-state sentinel.** Unlike SAST and DAST, which have two states
(ok / unavailable), the webext lane adds `partial` for the common case
where some of the three tools are installed and others are not.
`__webext_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}. The
orchestrator adds `⚠ Browser-extension tools unavailable` or a
`WebExt tools run: addons-linter, retire; web-ext skipped — not on
PATH` metadata line so the absence is always visible.

**Degrade path.** When the inventory does NOT contain `webext`, the
pass is skipped entirely — the tools are not probed. When webext is
detected but no tool is on PATH, the agent emits a single sentinel
line `{"__webext_status__": "unavailable", "tools": []}` and exits
clean. `tests/webext-drill.sh` enforces this contract by scrubbing
PATH and asserting the unavailable output shape. `tests/webext-e2e.sh`
validates the `vulnerable-webext` fixture produces addons-linter
findings, retire findings, origin-tag isolation, and the trailing
status line. No webext finding is ever fabricated.

## Rust toolchain lane (v0.7.0)

An eighth agent, **`rust-runner`** (haiku-pinned, `Read` + `Bash`
tools), joins the pipeline whenever the §2 inventory detects a
Rust/Cargo project — a `Cargo.toml` at project root containing
`[package]` or `[workspace]`. The runner is dispatched in parallel
with `sec-expert`, `sast-runner`, `dast-runner`, `webext-runner`, and
`cve-enricher`. It shells out to four cargo subcommands when available:

- **`cargo-audit`** (RustSec advisory DB) — scans `Cargo.lock`
  against the RustSec DB; findings with a CVE alias flow through
  `cve-enricher` via the `crates.io` OSV-native ecosystem. CVSS →
  severity mapping and `advisory.cwe[0]` → `CWE-<n>` (with `CWE-1104`
  fallback) are documented in `references/rust-tools.md`.
- **`cargo-deny`** (Embark's multi-check gate) — emits per-line JSON
  diagnostics for `advisories`, `bans`, `licenses`, and `sources`
  checks. Per-check CWE mapping: advisories → embedded advisory CWE
  or CWE-1104; bans → CWE-1104; licenses → `null` (compliance, not
  security); sources → CWE-494.
- **`cargo-geiger`** (unsafe-surface counter) — one INFO-severity
  finding per dependency with `unsafety.used.functions.unsafe_ > 0`.
  **Geiger findings are hard-capped at INFO by both the runner and the
  contract-check validator** — unsafe presence is a signal, not a
  defect; human triage decides whether a specific crate is concerning.
- **`cargo-vet`** (Mozilla's supply-chain attestation) — one LOW
  finding per unaudited dep from `cargo vet suggest`, with a
  `fix_recipe` instructing the developer to run `cargo vet diff` and
  either certify or add a justified exemption.

Output is sec-expert-compatible JSONL: every finding carries
`origin: "rust"` and one of
`tool: "cargo-audit" | "cargo-deny" | "cargo-geiger" | "cargo-vet"`.
`file` is `Cargo.toml` / `Cargo.lock` / a crate name; `line` is an
integer span when the tool supplies one, otherwise `0`. Field-mapping
recipes live in `skills/sec-review/references/rust-tools.md`; the
code-pattern reference packs (Cargo ecosystem, unsafe surface) live
in `skills/sec-review/references/rust/`.

**Fixes for advisory findings come from the advisory** (patched-
versions range); fixes for ecosystem findings come from
`rust/cargo-ecosystem.md` and `rust/unsafe-surface.md`. Retire.js-
style bundled-library flagging has no direct equivalent in Rust —
cargo-audit plays that role against `Cargo.lock`, and the results
appear in the Dependency CVE summary table as `crates.io` ecosystem
rows.

**Three-state sentinel.** Like the webext lane,
`__rust_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}. `cargo`
missing entirely is unavailable; some subcommands installed and
others missing is partial; all four running cleanly is ok. cargo-
audit and cargo-deny exit non-zero when they FIND findings — the
runner correctly treats this as success with findings, not as a
crash.

**Degrade path.** When the inventory does NOT contain `rust`, the
pass is skipped entirely (no cargo probe). When rust is detected but
cargo is not on PATH, the agent emits a single sentinel line
`{"__rust_status__": "unavailable", "tools": []}` and exits clean.
`tests/rust-drill.sh` enforces this contract by scrubbing PATH and
asserting the unavailable output shape. `tests/rust-e2e.sh` validates
the `vulnerable-rust` fixture produces cargo-audit CVE findings,
cargo-geiger INFO-ceiling findings, origin-tag isolation across all
six other lanes, and the trailing status line. No Rust finding is
ever fabricated.

## Android lane (v0.8.0)

A ninth agent, **`android-runner`** (haiku-pinned, `Read` + `Bash`
tools), joins the pipeline whenever the §2 inventory detects an
Android project — an `AndroidManifest.xml` anywhere in the tree OR a
`build.gradle(.kts)` applying the `com.android.application` or
`com.android.library` plugin. The runner is dispatched in parallel
with the other seven pass agents. It shells out to three Android
static-analysis tools when available:

- **`mobsfscan`** (the pip-installable MobSF static-analyzer
  component) — regex/semgrep-rule engine mapped to OWASP MASVS
  categories. Runs against the source tree. Emits per-rule findings
  with CWE and `reference_url` pointing to MobSF docs.
- **`apkleaks`** (compiled-APK secret + endpoint scanner) — runs
  against any `*.apk` / `*.aab` found under the target tree. When
  no APK is present (the common case for source-only checkouts),
  the runner CLEANLY SKIPS apkleaks and records that in the status
  line's `"skipped"` list with `reason: "no-apk"`. Clean-skip is
  distinct from failure (on PATH but crashed). This distinction is
  new in v0.8 and may be reused by future lanes where tool
  applicability depends on target artifacts.
- **`android-lint`** (via `./gradlew :app:lintDebug` when a gradle
  wrapper is present, else standalone `lint`) — emits Security-
  category issues like `HardcodedDebugMode`, `AllowBackup`,
  `ExportedReceiver`, `SetJavaScriptEnabled`, with a hand-curated
  CWE lookup table in `references/mobile-tools.md`.

Output is sec-expert-compatible JSONL: every finding carries
`origin: "android"` and one of
`tool: "mobsfscan" | "apkleaks" | "android-lint"`. `file` is the
relative path under the target root (e.g.
`app/src/main/AndroidManifest.xml`, `app/src/main/java/com/example/MainActivity.java`)
or the APK basename for apkleaks findings. Field-mapping recipes and
the lint-rule → CWE lookup table live in
`skills/sec-review/references/mobile-tools.md`; the code-pattern
reference packs (manifest, data, runtime) live in
`skills/sec-review/references/mobile/`.

**Dependencies feed cve-enricher** via the `Maven` OSV-native
ecosystem entry; transitive coverage depends on whether a
`gradle.lockfile` is committed.

**Four-state status.** `__android_status__` ∈ {`"ok"`, `"partial"`,
`"unavailable"`} and the trailing line may include a structured
`"skipped"` list (each entry `{"tool": "...", "reason": "..."}`).
A common shape is `"ok"` with `skipped: [{"tool": "apkleaks",
"reason": "no-apk"}]` for source-only reviews where mobsfscan and
android-lint ran cleanly.

**Degrade path.** When the inventory does NOT contain `android`, the
pass is skipped entirely. When Android is detected but no tool is on
PATH, the agent emits the unavailable sentinel and exits 0.
`tests/android-drill.sh` scrubs PATH and asserts the spec's probe +
sentinel + clean-skip contract. `tests/android-e2e.sh` validates the
`vulnerable-android` fixture produces mobsfscan + android-lint
findings, 7-lane origin-tag isolation, the trailing status line, and
the apkleaks clean-skip. No Android finding is ever fabricated.

## iOS lane (v0.9.0)

A tenth agent, **`ios-runner`** (haiku-pinned, `Read` + `Bash`
tools), joins the pipeline whenever the §2 inventory detects an iOS /
Apple-platform project — any of `Info.plist`, `*.xcodeproj`,
`Package.swift`, or `Podfile`. The runner is dispatched in parallel
with every other pass agent. It shells out to up to four tools:

- **`mobsfscan`** — the same pip-installable tool used by the
  Android lane; its rule set covers both Android and iOS, so the
  runner does not need a separate binary. The only lane-specific
  difference is `origin: "ios"` vs `"android"`.
- **`codesign`** (macOS-only) — dumps entitlements and hardened-
  runtime state from a `.app` / `.framework` / `.xcarchive` bundle.
  Findings map per the `mobile/ios-codesign.md` pack.
- **`spctl`** (macOS-only) — runs a Gatekeeper assessment; a
  rejected assessment produces one HIGH finding.
- **`xcrun notarytool history`** (macOS-only, needs `$NOTARY_PROFILE`)
  — one MEDIUM finding per `Invalid` or `Rejected` notarization in
  the developer team's history.

Output is sec-expert-compatible JSONL: every finding carries
`origin: "ios"` and one of
`tool: "mobsfscan" | "codesign" | "spctl" | "notarytool"`. Field-
mapping recipes live in `skills/sec-review/references/mobile-tools.md`
(iOS subsection); code-pattern reference packs live in
`skills/sec-review/references/mobile/ios-*.md`.

**Dependencies feed cve-enricher** via CocoaPods and SwiftPM ecosystem
entries (OSV best-effort — CocoaPods through GHSA fallback, SwiftPM
partial). Coverage gaps are tolerated rather than failed.

**NEW in v0.9 — host-OS-gated clean-skip.** The three Apple binaries
are macOS-only. When the runner is on Linux or Windows (the common CI
case), they are CLEANLY SKIPPED with
`reason: "requires-macos-host"` — not failed, not fabricated. This
extends v0.8's skipped-list primitive (apkleaks-no-apk was "target
lacks artifact"; ios now adds "host lacks capability"). The
report-writer surfaces both as informational metadata rather than
reviewer-fixable gaps. The iOS lane's total skip vocabulary:

- `reason: "requires-macos-host"` (codesign / spctl / notarytool on Linux/Windows)
- `reason: "no-bundle"` (codesign / spctl need a built `.app` / `.framework` / `.xcarchive`)
- `reason: "no-notary-profile"` (notarytool needs `$NOTARY_PROFILE`)
- `reason: "tool-missing"` (the binary is absent when its preconditions held)

**Degrade path.** No `ios` in inventory → skip entirely. Target has
no iOS signals → unavailable sentinel. All tools skipped on a Linux
host with no bundle → unavailable sentinel with a populated `skipped`
list (so the reviewer learns that the review was partial by design).
`tests/ios-drill.sh` enforces the spec's probe + sentinel + host-OS-
gate + all-four-skip-reasons contracts. `tests/ios-e2e.sh` validates
the `vulnerable-ios` fixture produces mobsfscan findings, a status
line with three `requires-macos-host` skipped entries, and 12-way
origin-tag isolation.

## Desktop Linux lane (v0.10.0)

An eleventh agent, **`linux-runner`** (haiku-pinned, `Read` + `Bash`
tools), joins the pipeline whenever the §2 inventory detects a Linux
desktop target — any of `*.service` / `*.socket` / `*.timer` units,
`debian/control`, `*.spec`, a Flatpak manifest, or `snapcraft.yaml`.
The runner dispatches up to three tools:

- **`systemd-analyze security`** (bundled with systemd; needs a
  systemd host) — scores a `.service` unit's hardening per-directive.
  `--offline=true --profile=strict` on systemd ≥ 252 enables offline
  scoring. macOS/Windows/Alpine-without-systemd CLEANLY SKIP with
  `reason: "requires-systemd-host"`. Absent systemd unit →
  `reason: "no-systemd-unit"`.
- **`lintian`** (apt/brew-installable; Debian source reviewer) —
  emits tag-based findings against `debian/control`, maintainer
  scripts, and packaging metadata. `--output-format=json` (Lintian
  ≥ 2.117). Absent `debian/control` → `reason: "no-debian-source"`.
- **`checksec`** (pip `checksec-py` or apt) — ELF hardening flag
  check (RELRO, canary, NX, PIE, RPATH). Absent ELF under target →
  `reason: "no-elf"` (source-only reviews are the common case).

Output is sec-expert-compatible JSONL: every finding carries
`origin: "linux"` and one of
`tool: "systemd-analyze" | "lintian" | "checksec"`. Field-mapping
recipes live in `skills/sec-review/references/linux-tools.md`; the
three code-pattern reference packs (systemd directives, sandboxing,
packaging) live in `skills/sec-review/references/desktop/linux-*.md`.

**Dependencies feed cve-enricher** via the `Debian` ecosystem
(best-effort via the Debian Security Tracker — OSV partial; same
tolerance model as CocoaPods/SwiftPM in the iOS lane).

**NEW in v0.10 — second host-OS-gated clean-skip.** The `requires-
systemd-host` skip reason extends v0.9's host-OS vocabulary with a
Linux-specific host requirement. Six canonical Linux-lane skip
reasons: `requires-systemd-host` (host-gate), `no-debian-source` /
`no-elf` / `no-systemd-unit` (target-shape gates), `tool-missing`
(binary absent when preconditions hold). All still `{tool, reason}`
structured.

**Degrade path.** No `linux` in inventory → skip entirely. Target
lacks Linux signals → unavailable sentinel. All tools skipped on a
macOS CI with no `.service` unit → unavailable with populated
`skipped` list. `tests/linux-drill.sh` enforces the spec's four
probes + host-systemd check + all four skip reasons. `tests/linux-
e2e.sh` validates the `vulnerable-linux` fixture (systemd unit +
debian/ source + postinst hazards, no ELF) produces systemd-analyze
+ lintian findings with `no-elf` cleanly-skipped.

## Desktop macOS lane (v0.11.0)

A twelfth agent, **`macos-runner`** (haiku-pinned, `Read` + `Bash`
tools), joins the pipeline whenever the §2 inventory detects a macOS
desktop target — `Info.plist` with `LSMinimumSystemVersion`, a
`*.pkg` / `*.dmg` file, a `Sparkle.framework`/`SUFeedURL` marker, or
a `.app` bundle with the macOS deployment-target key. macos-runner
is a **sibling of `ios-runner`** (§3.11); cross-platform SwiftPM
packages can satisfy both inventory signals and dispatch both
runners into separate report sections.

The runner dispatches up to five tools:

- **`mobsfscan`** — cross-platform Swift/Obj-C rule engine, shared
  with the Android and iOS lanes.
- **`codesign`** (macOS-only) — entitlements + hardened-runtime on
  `.app`/`.framework`; same binary as iOS, different target shape.
- **`spctl`** (macOS-only) — Gatekeeper assessment on `.app`.
- **`pkgutil --check-signature`** (macOS-only, NEW in v0.11) —
  verifies `.pkg` installer signatures.
- **`xcrun stapler validate`** (macOS-only, NEW in v0.11) — checks
  notarization-ticket stapling on `.app`/`.pkg`/`.dmg`.

Output is sec-expert-compatible JSONL: every finding carries
`origin: "macos"` and one of
`tool: "mobsfscan" | "codesign" | "spctl" | "pkgutil" | "stapler"`.
Field-mapping recipes live in
`skills/sec-review/references/mobile-tools.md` (iOS + macOS
subsections); code-pattern reference packs live in
`skills/sec-review/references/desktop/macos-*.md`.

Three desktop-macOS-specific reference packs cover concerns iOS
doesn't share: **hardened runtime** flags on GUI apps
(`cs.allow-jit`, `disable-library-validation`, etc.), **TCC
entitlements** + paired `NS*UsageDescription` discipline, and
**`.pkg`/Sparkle packaging** — including the canonical **Sparkle
over HTTP** vulnerability (CVE-2014-9390 class) where auto-update
payloads are delivered without transport integrity.

**NEW in v0.11: `no-pkg` clean-skip reason.** pkgutil requires a
`.pkg` under target; source-only reviews cleanly-skip. Parallel to
Android's `no-apk` and iOS's `no-bundle`. The macOS lane has five
canonical skip reasons: `requires-macos-host` (shared with iOS),
`no-bundle`, `no-pkg` (new), `no-notary-profile`, `tool-missing`.

**Degrade path.** No `macos` in inventory → skip entirely. Linux CI
with Sparkle-using source tree but no Apple binaries → `ok` with
four `requires-macos-host` skipped entries. `tests/macos-drill.sh`
enforces the spec's five-tool probe + host-gate + five-skip-reason
contracts. `tests/macos-e2e.sh` validates the `vulnerable-macos`
fixture (Sparkle HTTP feed + UserDefaults secret + JIT entitlement)
produces mobsfscan findings with all four Apple binaries cleanly-
skipped on Linux.

## Coverage matrix

| Lane                      | Target                                           | Tools                                      | Reference packs                                                                        | Shipped in |
|---------------------------|--------------------------------------------------|--------------------------------------------|----------------------------------------------------------------------------------------|------------|
| Code reasoning            | Source tree (any supported framework)            | `sec-expert` (LLM, grep + context)         | `databases/`, `frameworks/`, `webservers/`, `proxies/`, `frontend/`, `auth/`, `tls/`, `containers/`, `secrets/`, `supply-chain/` | v0.2.0     |
| Windows / IIS             | `web.config`, `applicationHost.config`           | `sec-expert` (code reasoning)              | `references/webservers/iis.md`                                                         | v0.4.0     |
| SAST                      | Source tree                                      | `semgrep` (OWASP Top Ten), `bandit`        | `references/sast-tools.md`                                                             | v0.4.0     |
| DAST                      | Running `http(s)://…` instance                   | `zap-baseline.py` (docker or local)        | `references/dast-tools.md`                                                             | v0.5.0     |
| Browser extensions        | MV3 / AMO extension source tree                  | `addons-linter`, `web-ext lint`, `retire`  | `references/frontend/webext-{chrome-mv3,firefox-amo,shared-patterns}.md`, `references/webext-tools.md` | v0.6.0     |
| Rust toolchain            | Cargo project (`Cargo.toml` + `[package]`/`[workspace]`) | `cargo-audit`, `cargo-deny`, `cargo-geiger`, `cargo-vet` | `references/rust/{cargo-ecosystem,unsafe-surface}.md`, `references/rust-tools.md` | v0.7.0     |
| Android                   | Source tree (`AndroidManifest.xml` + gradle Android plugin) | `mobsfscan`, `apkleaks` (APK-present), `android-lint` (gradle or standalone) | `references/mobile/{android-manifest,android-data,android-runtime}.md`, `references/mobile-tools.md` | v0.8.0     |
| iOS                       | Source tree (`Info.plist` / `*.xcodeproj` / `Package.swift` / `Podfile`) | `mobsfscan`, `codesign` / `spctl` / `xcrun notarytool` (macOS-host + bundle-present) | `references/mobile/{ios-plist,ios-data,ios-codesign}.md`, `references/mobile-tools.md` | v0.9.0     |
| Desktop Linux             | Source tree (`*.service` / `debian/control` / `*.spec` / flatpak-manifest / `snapcraft.yaml`) | `systemd-analyze security` (systemd-host), `lintian` (debian/ source), `checksec` (ELF present) | `references/desktop/{linux-systemd,linux-sandboxing,linux-packaging}.md`, `references/linux-tools.md` | v0.10.0    |
| Desktop macOS             | Source tree (`Info.plist` with `LSMinimumSystemVersion` / `*.pkg` / `*.dmg` / Sparkle) | `mobsfscan`, `codesign` / `spctl` / `pkgutil` / `stapler` (macOS-host + artifact-present) | `references/desktop/{macos-hardened-runtime,macos-tcc,macos-packaging}.md`, `references/mobile-tools.md` | v0.11.0    |
| CVE enrichment            | Manifests + retire + crates.io + Maven + CocoaPods/SwiftPM + Debian (best-effort beyond crates.io/Maven) | OSV `querybatch`, NVD 2.0, GHSA, CISA KEV  | `references/cve-feeds.md`                                                              | v0.2.0     |

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
