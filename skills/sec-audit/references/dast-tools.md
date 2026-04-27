# DAST Tools

## Source

- https://www.zaproxy.org/docs/docker/baseline-scan/ — ZAP baseline scan (Docker, official)
- https://www.zaproxy.org/docs/docker/ — ZAP Docker images and invocation reference
- https://www.zaproxy.org/docs/api/ — ZAP API and report generation reference
- https://cwe.mitre.org/ — CWE index (for mapping ZAP `cweid` integers)

## Scope

This reference pack documents the single DAST tool invoked by the
`dast-runner` sub-agent in sec-audit v0.5.0: OWASP ZAP's `zap-baseline.py`
wrapper, running passive rules only against a live HTTP target. It
specifies canonical CLI invocations, JSON output schema, field mappings to
sec-audit's finding schema, and offline-degrade rules. Out of scope:
ZAP's full active scan (`zap-full-scan.py`), authenticated scans,
OpenAPI/GraphQL-spec-driven scanning, and custom rule authoring — all
deferred to future versions. This pack documents how the `dast-runner`
sub-agent invokes ZAP, not anti-patterns in user code.

## Dangerous patterns

> **Operational sentinel:** This file describes how to invoke the ZAP
> baseline tool, not source code under review. Suppress grep/AST matches
> for the invocation strings below when the enclosing file path is
> `references/dast-tools.md`. This section lists "invocations that go
> wrong" — the anti-patterns apply to scripts and CI config that shell out
> to `zap-baseline.py` or the ZAP docker image, not to product code.

### Running zap-baseline without -J — CWE-1188

- Why: Without `-J <path>`, ZAP writes only the text/HTML summary and no
  machine-readable JSON report. Downstream parsers then have nothing stable
  to ingest and the run looks clean even when ZAP raised alerts. The
  `dast-runner` agent MUST pass `-J` on every invocation.
- Grep: `zap-baseline\.py\s+(?!.*-J\b)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`,
  `.github/workflows/*.yml`
- Source: https://www.zaproxy.org/docs/docker/baseline-scan/

### Running docker ZAP without -I — CWE-703

- Why: `zap-baseline.py` exits non-zero when WARN-level alerts are raised
  (the default). Scripts that do not anticipate this either abort early
  and skip the JSON report step, or mask the exit with `|| true` and lose
  genuine tool errors. Passing `-I` ("do not return failure on warning")
  normalises the exit code to 0 on WARN and preserves non-zero for real
  errors, so the runner can branch on tool failure vs. alerts-present.
- Grep: `docker\s+run.*zap-baseline\.py\s+(?!.*-I\b)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `.github/workflows/*.yml`
- Source: https://www.zaproxy.org/docs/docker/baseline-scan/

### Using deprecated owasp/zap2docker-stable image — CWE-1104

- Why: The `owasp/zap2docker-stable` image is retired; the current image
  is `zaproxy/zap-stable`. Pinning the retired image means the runner
  never receives rule or engine updates, and eventually the image will be
  removed from Docker Hub — at which point the DAST lane silently stops
  producing findings.
- Grep: `owasp/zap2docker-(stable|weekly|bare|live)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Dockerfile`,
  `.github/workflows/*.yml`
- Source: https://www.zaproxy.org/docs/docker/

### Baseline scan against production without explicit auth — CWE-754

- Why: Even the passive-only baseline crawls the target, follows links,
  and issues HEAD/GET requests at a high rate. Pointed at a production
  host without operator sign-off it can trip WAF rate limits, page
  on-call, or pollute analytics. The runner MUST refuse a production
  target unless the caller has passed an explicit authorisation flag.
- Grep: `zap-baseline\.py\s+.*-t\s+https?://(?!localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `.github/workflows/*.yml`
- Source: https://www.zaproxy.org/docs/docker/baseline-scan/

### Parsing ZAP text/HTML output instead of JSON — CWE-1188

- Why: ZAP's text (`-r`-style `.txt`) and HTML report layouts are not a
  stable contract; column order and wording change across releases.
  Regex-parsing them produces empty finding sets on upgrade that look
  like "clean scan." The runner MUST consume the JSON report written by
  `-J`.
- Grep: `zap-baseline\.py\s+.*-r\s+\S+\.html`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `.github/workflows/*.yml`
- Source: https://www.zaproxy.org/docs/api/

## Secure patterns

Canonical invocations for the `dast-runner` agent. Each is the minimum
correct form — callers may add `-c <config>`, `-z <zap-opts>`, or
targeting flags, but MUST NOT drop any flag shown here.

```bash
# Docker baseline — current image, JSON report into the shared volume,
# do-not-fail-on-warning so the script continues to the parser step.
docker run -t zaproxy/zap-stable \
  zap-baseline.py \
    -t <URL> \
    -J /zap/wrk/report.json \
    -I
```

Source: https://www.zaproxy.org/docs/docker/baseline-scan/,
https://www.zaproxy.org/docs/docker/

```bash
# Local python fallback — same flags, used when docker is not on PATH
# but a system ZAP install is. The JSON report is written to the current
# working directory.
zap-baseline.py \
  -t <URL> \
  -J report.json \
  -I
```

Source: https://www.zaproxy.org/docs/docker/baseline-scan/

```bash
# Non-gating with runtime cap — -m <minutes> bounds the passive-rule
# wait after the spider completes. Use this in CI lanes where a slow
# target must not hang the pipeline. The runner still parses the JSON
# and emits findings even when the cap triggers.
docker run -t zaproxy/zap-stable \
  zap-baseline.py \
    -t <URL> \
    -J /zap/wrk/report.json \
    -I \
    -m 5
```

Source: https://www.zaproxy.org/docs/docker/baseline-scan/

## Fix recipes

These recipes document the contract between the `dast-runner` sub-agent
and the rest of the sec-audit pipeline. They are NOT fix recipes in the
user-code sense; each recipe specifies how ZAP's native JSON maps into
sec-audit's canonical finding schema.

### Recipe: ZAP alert → sec-audit finding

The JSON report written by `-J` is a nested object
`{"site": [{"alerts": [...]}]}`. Each element of `alerts` maps to exactly
one sec-audit finding as follows:

| ZAP JSON field                | sec-audit finding field | Notes                                                                                 |
|-------------------------------|--------------------------|---------------------------------------------------------------------------------------|
| `pluginid`                    | `id`                     | Numeric string, e.g. `"10038"`                                                        |
| `alert` / `name`              | `title`                  | `alert` is the short form; fall back to `name` if `alert` is empty                    |
| `riskcode`                    | `severity`               | STRING, not int: `"0"`=INFO, `"1"`=LOW, `"2"`=MEDIUM, `"3"`=HIGH. Map to sec-audit `INFO`/`LOW`/`MEDIUM`/`HIGH` |
| `confidence`                  | (see notes)              | Not mapped to `confidence`; runner uses constant `medium` (see below)                 |
| `cweid`                       | `cwe`                    | Numeric string like `"89"` → `"CWE-89"`. Emit `null` when `cweid` is empty or `"-1"` |
| `desc`                        | `evidence`               | HTML-ish description string; pass through verbatim                                    |
| `instances[0].uri`            | `file`                   | DAST has no source file; the URI is the locus                                         |
| (none)                        | `line`                   | Always `0` — DAST has no source line; the parser sets this explicitly                 |
| `reference`                   | `reference_url`          | ZAP emits a newline-separated string; take the first URL, or `null` if empty          |
| `instances[0].method` + `.uri`| `notes`                  | Synthesised as `"<method> <uri>"` so the report-writer can render `Target: GET /admin (GET)` |
| `instances[0].evidence`       | (appended to `evidence`) | Concatenate onto the ZAP `desc` so the request fragment that triggered the alert survives into the finding |

Plus these constant fields on every ZAP-sourced finding:

- `origin: "dast"`
- `tool: "zap-baseline"`
- `reference: "dast-tools.md"`
- `fix_recipe: null`
- `confidence: "medium"`

The `riskcode` → `severity` mapping is the one documented in the ZAP API
report schema: `3` is the highest rule-author-declared level, `0` is
informational. sec-audit's HIGH/MEDIUM/LOW/INFO tiers match one-to-one.

Source: https://www.zaproxy.org/docs/api/, https://cwe.mitre.org/

### Recipe: Unavailable-tool sentinel

When neither `docker` nor `zap-baseline.py` is on `PATH`, the
`dast-runner` agent MUST NOT emit any findings and MUST NOT guess. It
emits exactly one line to stdout:

```json
{"__dast_status__": "unavailable", "tools": []}
```

Exit code 0. No findings, no partial results. The downstream aggregator
reads this sentinel and propagates it into the top-level review summary
so that the absence of DAST findings cannot be misread as a clean DAST
pass.

Source: https://www.zaproxy.org/docs/docker/baseline-scan/

### Recipe: Status summary line

After the baseline scan has run and all findings have been emitted, the
`dast-runner` agent emits exactly one final JSON line at the END of
stdout (after every finding):

```json
{"__dast_status__": "ok", "tools": ["zap-baseline"], "runs": 1, "findings": N}
```

- `tools` is the list of tools that actually executed (omit any that
  were not available).
- `runs` is the number of successful tool invocations.
- `findings` is the total count of findings emitted this run.

This line is mandatory — its absence means the agent crashed mid-run and
the finding set is untrusted.

Source: https://www.zaproxy.org/docs/api/

## Common false positives

The `dast-runner` agent emits these findings at their ZAP-declared
severity, but the triage step SHOULD downgrade or suppress them when the
listed context applies.

- **CSP header missing (pluginid 10038)** on internal admin tools and
  dashboards served only inside a VPN or onion trust boundary — CSP
  protects against injection from untrusted origins, which do not apply
  when the page cannot be reached from the public web. Downgrade to
  `info` when the target host is clearly marked internal/admin.
- **Cookie No HttpOnly Flag (pluginid 10010)** on a cookie that is
  intentionally readable from JavaScript, e.g. a double-submit CSRF
  token that the frontend must echo into a header. Suppress on the
  specific cookie name when a double-submit pattern is in use;
  HttpOnly would break the mitigation it implements.
- **X-Frame-Options / anti-clickjacking header missing (pluginid 10020)**
  on pure JSON API endpoints — a response that returns
  `Content-Type: application/json` is not framable as UI, so the header
  is moot. Downgrade to `info` when the response content-type is JSON
  (or any other non-`text/html` type).
- **Informational-risk alerts (riskcode `"0"`)** against `localhost`,
  `127.0.0.0/8`, or loopback-only targets — these scans run inside the
  developer's own trust boundary, and INFO-tier findings are noise in
  that context. Downgrade or suppress wholesale when the target host
  resolves to loopback.
- **Strict-Transport-Security missing (pluginid 10035)** on a target
  reached via `http://` — HSTS is only meaningful over HTTPS, and ZAP
  flags its absence on plain-HTTP targets anyway. Suppress when the
  scanned URL scheme is `http`; re-enable when the caller switches to
  `https`.

Source: https://www.zaproxy.org/docs/docker/baseline-scan/,
https://cwe.mitre.org/
