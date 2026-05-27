# Supply-Chain Tools

## Source

- https://github.com/DataDog/guarddog — GuardDog (Datadog, Apache-2.0): heuristic malicious-package scanner for PyPI / npm / GitHub Actions
- https://github.com/DataDog/guarddog#heuristics — GuardDog detector catalogue (source + metadata heuristics)
- https://github.com/google/osv-scanner — OSV-Scanner (Google, Apache-2.0): lockfile + directory vulnerability scanner backed by OSV.dev
- https://google.github.io/osv-scanner/ — OSV-Scanner documentation (output formats, scanning modes)
- https://github.com/ossf/malicious-packages — OpenSSF Malicious Packages dataset (the `MAL-` advisories OSV serves)
- https://cwe.mitre.org/ — CWE index (for mapping detectors to CWEs)

## Scope

This reference pack documents the two binaries invoked by the
`supply-chain-runner` sub-agent: **GuardDog** (heuristic malicious-code
detection) and **OSV-Scanner** (lockfile-level malicious-package advisories).
It specifies canonical CLI invocations, JSON output schemas, detector→CWE
mappings, the sentinel/status recipes, and the division of labour with the
`cve-enricher` agent.

In scope: PyPI and npm dependency sets (GuardDog's supported ecosystems; the
runner also accepts GuardDog's GitHub Actions mode when `.github/workflows/`
is present). Detection of install-time code execution, obfuscation,
download-and-exec, exfiltration, typosquatting / dependency-confusion, and
known-malware (`MAL-`) packages anywhere in the resolved lockfile graph.

Out of scope, by deliberate division of labour:

- **Ordinary CVEs are NOT this lane's job.** `cve-enricher` owns CVE
  enrichment (OSV/NVD/GHSA + KEV) over the dep inventory. To avoid
  double-reporting, the runner emits **only** OSV-Scanner results whose ID is
  prefixed `MAL-` (malicious-package advisories) and **drops** every ordinary
  vuln ID (`CVE-…`, `GHSA-…`, `PYSEC-…`, …) from OSV-Scanner output.
- **Direct-dep `MAL-` hits** are also surfaced by `cve-enricher` (it now
  classifies `MAL-` IDs from its OSV calls — see `cve-feeds.md`). OSV-Scanner
  here adds **transitive-graph** reach that the sec-expert direct-dep
  inventory misses. The report-writer deduplicates by `(ecosystem, name,
  version, id)` across the two sources.

## Dangerous patterns (regex/AST hints)

> **Operational sentinel:** This file describes how to invoke external
> supply-chain binaries, not source code under review. Suppress grep/AST
> matches for the invocation strings below when the enclosing file path is
> `references/supply-chain-tools.md`. The anti-patterns apply to scripts and
> CI that shell out to guarddog or osv-scanner, not to product code.

### Running guarddog `scan` instead of `verify` on a project tree — CWE-1188

- Why: `guarddog <eco> scan <name>` scans a single named package; on a
  project tree it inspects only the top-level files and silently misses the
  installed dependency set. To analyse the dependencies a project actually
  pulls, the runner MUST use `verify <manifest>` (which downloads and scans
  every dependency in the manifest). Using `scan` on a repo root produces a
  near-empty result that callers misread as "clean deps."
- Grep: `guarddog\s+(pypi|npm)\s+scan\s` (in a context that targets a repo, not a package name)
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`
- Source: https://github.com/DataDog/guarddog

### Parsing guarddog/osv-scanner text output instead of JSON — CWE-1188

- Why: the default human-readable output is not a stable contract; it changes
  across versions and breaks regex parsers silently, yielding empty finding
  sets that look like a clean scan. The runner MUST request
  `--output-format json` (guarddog) / `--format json` (osv-scanner).
- Grep: `guarddog\s+(pypi|npm)\s+verify(?!.*--output-format)|osv-scanner(?!.*--format\s+json)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`
- Source: https://github.com/DataDog/guarddog, https://google.github.io/osv-scanner/

### Treating osv-scanner exit 1 as failure — CWE-755

- Why: OSV-Scanner exits **1** when it finds vulnerabilities (not on error);
  it exits 127/128 on actual invocation errors. A script that treats any
  non-zero as "tool broke" discards a successful scan that found malware. The
  runner MUST parse the JSON regardless of a 1 exit and branch only on the
  documented error codes.
- Grep: `osv-scanner.*\|\|\s*(exit|return)\b`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`
- Source: https://google.github.io/osv-scanner/

### Emitting osv-scanner CVE/GHSA IDs from the supply-chain lane — CWE-1188

- Why: ordinary CVE/GHSA enrichment is `cve-enricher`'s job. If the
  supply-chain runner also emits `CVE-…`/`GHSA-…` rows, the same dependency
  CVE appears twice in the report with different provenance. The runner MUST
  keep only `MAL-`-prefixed IDs from OSV-Scanner output.
- Grep: `osv-scanner` (look for absence of a `startswith("MAL-")` / `^MAL-` filter nearby)
- File globs: `**/*.sh`, `**/*.py`, `**/*.yml`
- Source: https://github.com/ossf/malicious-packages

## Secure patterns

Canonical invocations for the `supply-chain-runner` agent. Each is the
minimum correct form.

```bash
# GuardDog — scan every PyPI dependency declared in a manifest by downloading
# and heuristically analysing each one. JSON to stdout. `verify` is the
# project-scoped mode (vs. `scan <name>` for a single package).
guarddog pypi verify <path/to/requirements.txt> --output-format json

# GuardDog — same for an npm project. Point at package.json (it resolves the
# declared deps). package-lock.json gives the fuller set when present.
guarddog npm verify <path/to/package.json> --output-format json
```

Source: https://github.com/DataDog/guarddog

```bash
# OSV-Scanner — recursive scan of the project tree; resolves every lockfile it
# finds (requirements.txt, package-lock.json, poetry.lock, go.sum, …) and
# queries OSV for the full graph, including transitive deps. JSON to stdout.
osv-scanner --format json -r <target>
```

Source: https://google.github.io/osv-scanner/

```bash
# Keep ONLY malicious-package advisories from OSV-Scanner (drop ordinary
# CVEs — cve-enricher owns those). jq filter applied to the JSON above:
osv-scanner --format json -r <target> \
  | jq -c '.results[].packages[]
           | . as $p
           | .vulnerabilities[]
           | select(.id | startswith("MAL-"))
           | {ecosystem: $p.package.ecosystem, name: $p.package.name,
              version: $p.package.version, id: .id, summary: .summary}'
```

Source: https://github.com/ossf/malicious-packages

## Fix recipes

These recipes specify how each tool's native JSON maps into sec-audit's
canonical finding schema — they are NOT user-code fix recipes.

### Recipe: GuardDog result → sec-audit finding

`guarddog <eco> verify --output-format json` emits one record per scanned
dependency. Each triggered detector becomes one sec-audit finding:

| GuardDog field                         | sec-audit field | Notes                                              |
|----------------------------------------|------------------|----------------------------------------------------|
| `<detector name>` (the result key)     | `id`             | e.g. `npm-install-script`, `exec-base64`           |
| `message` / per-finding description    | `title`          | Also duplicated into `evidence`                    |
| `<package being verified>`             | `file`           | The dependency name (+ version when present); GuardDog reports the package, not a file/line |
| —                                      | `line`           | `1` (GuardDog findings are package-level, not line-level) |
| detector → CWE (table below)           | `cwe`            | `null` if the detector is not in the table — do NOT guess |

Constants on every guarddog finding: `origin: "supply-chain"`,
`tool: "guarddog"`, `reference: "supply-chain-tools.md"`,
`fix_recipe: null`, `confidence: "medium"`.

Severity: GuardDog's malware-class detectors (`exec-base64`,
`download-executable`, `obfuscation`, `npm-install-script`, `cmd-overwrite`,
`shady-links`, `bidirectional-characters`, `steganography`, `code-execution`)
are **HIGH**; metadata/heuristic detectors (`typosquatting`,
`potentially-compromised-email-domain`, `single-python-file`,
`empty-information`, `release-zero`) are **MEDIUM** (signal, not proof).

Detector → CWE table (sec-audit v1; extend as GuardDog adds detectors):

| GuardDog detector                         | CWE      | Class                                   |
|-------------------------------------------|----------|------------------------------------------|
| `exec-base64`, `code-execution`           | CWE-94   | Code injection / dynamic eval            |
| `npm-install-script`, `cmd-overwrite`     | CWE-506  | Embedded malicious code (install hook)   |
| `download-executable`, `download-*`       | CWE-494  | Download of code without integrity check |
| `obfuscation`, `steganography`            | CWE-506  | Embedded malicious code                  |
| `shady-links`, `exfiltrate-*`             | CWE-200  | Exfiltration / info exposure             |
| `typosquatting`, `dependency-confusion`   | CWE-1357 | Reliance on insufficiently trustworthy component |
| `bidirectional-characters`                | CWE-1007 | Trojan-source / non-rendered code        |

If a detector is not in the table, emit `cwe: null`. Do not guess.

Source: https://github.com/DataDog/guarddog#heuristics, https://cwe.mitre.org/

### Recipe: OSV-Scanner malicious-package result → sec-audit finding

From the `--format json` output, keep **only** vulnerabilities whose `id`
starts with `MAL-`. Each becomes one finding:

| OSV-Scanner field                                   | sec-audit field | Notes                          |
|-----------------------------------------------------|------------------|--------------------------------|
| `…vulnerabilities[].id` (`MAL-…`)                   | `id`             | Verbatim; never relabel as CVE |
| `…vulnerabilities[].summary`                        | `title`          | Also into `evidence`           |
| `…packages[].package.name` (+ `version`)            | `file`           | The package coordinate         |
| —                                                   | `line`           | `1`                            |
| —                                                   | `cwe`            | `CWE-506` (embedded malicious code) |

Constants: `origin: "supply-chain"`, `tool: "osv-scanner"`,
`reference: "supply-chain-tools.md"`, `fix_recipe: null`,
`confidence: "high"` (a `MAL-` advisory is a curated, confirmed hit),
`severity: "CRITICAL"`.

Drop every non-`MAL-` OSV-Scanner result silently — those are `cve-enricher`'s
responsibility.

Source: https://github.com/google/osv-scanner, https://github.com/ossf/malicious-packages

### Recipe: Unavailable-tool sentinel

When neither `guarddog` nor `osv-scanner` is on `PATH`, OR the target has no
PyPI/npm dependency manifest, the runner emits exactly one line to stdout and
exits 0:

```json
{"__supply_chain_status__": "unavailable", "tools": []}
```

No findings, no partial results.

Source: https://github.com/DataDog/guarddog, https://google.github.io/osv-scanner/

### Recipe: Status summary line

After all available tools have run and all findings are on stdout, emit
exactly one final line:

```json
{"__supply_chain_status__": "ok", "tools": ["guarddog","osv-scanner"], "runs": 2, "findings": 3, "skipped": []}
```

- `tools` — tools that actually executed successfully (omit missing ones).
- `runs` — length of `tools`.
- `findings` — total finding lines emitted this run.
- `skipped` — list of `{"tool": "<name>", "reason": "<reason>"}`. Reasons:
  `tool-missing` (binary absent), `no-supply-chain-source` (guarddog/osv-scanner
  on PATH but no PyPI/npm manifest under target).

Use `"partial"` when some tools ran and others were missing or cleanly
inapplicable; `"unavailable"` when none could run (same sentinel as above).

Source: https://github.com/DataDog/guarddog, https://google.github.io/osv-scanner/

## Version notes

- **GuardDog** ≥ 1.0 uses `--output-format json`; older 0.x used
  `--output-format=json` (equals form). The runner accepts either by passing
  `--output-format json`. The `verify` subcommand (manifest-scoped) was
  stabilised in 1.x — prefer it over `scan` for project audits.
- **OSV-Scanner** ≥ 1.7 introduced the `osv-scanner scan` subcommand form;
  the flat `osv-scanner --format json -r <dir>` form remains supported.
  Exit code 1 means "vulnerabilities found," not an error.

## Common false positives

The runner emits these with normal confidence; the triage step SHOULD
downgrade them when the listed context applies.

- **GuardDog `typosquatting`** on an internal/private package whose name is
  legitimately close to a popular one (e.g. a company's `requests-internal`)
  — MEDIUM heuristic, not proof. Downgrade when the package resolves from a
  private registry/scope configured in the project.
- **GuardDog `single-python-file` / `empty-information` / `release-zero`** on
  small first-party utilities vendored into the tree — these metadata
  heuristics fire on benign minimal packages. Downgrade unless paired with a
  malware-class detector on the same package.
- **GuardDog `npm-install-script`** on a package with a legitimate, well-known
  native-build `postinstall` (e.g. `node-gyp` rebuilds) — the hook is
  expected; downgrade unless the script body also triggers `exec-base64` /
  `download-executable` / `shady-links`.
- **OSV-Scanner dev-only `MAL-` in a path that never ships** — a malicious
  package in a dev/test-only dependency is still serious (it runs on
  developer machines and CI), so do NOT suppress; at most annotate scope.
