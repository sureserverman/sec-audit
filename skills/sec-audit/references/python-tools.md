# python-tools

<!--
    Tool-lane reference for sec-audit's Python lane (v1.7.0+).
    Consumed by the `python-runner` sub-agent. Documents
    pip-audit + ruff.
-->

## Source

- https://github.com/pypa/pip-audit — pip-audit canonical (PyPA-maintained; OSV-backed PyPI vulnerability scanner)
- https://docs.astral.sh/ruff/ — ruff canonical (Rust-implemented Python linter; fastest mature option)
- https://docs.astral.sh/ruff/rules/#flake8-bandit-s — ruff's flake8-bandit `S`-rule subset (security)
- https://docs.astral.sh/ruff/rules/#flake8-bugbear-b — ruff's flake8-bugbear `B`-rules (bug-prone patterns)
- https://github.com/PyCQA/bandit — bandit (already in SAST lane; documented here for delineation)
- https://cwe.mitre.org/

## Scope

In-scope: the two tools invoked by `python-runner` —
`pip-audit` (PyPA-maintained Python-package vulnerability
scanner that consumes the project's resolved environment or
requirements file and queries OSV.dev for known CVEs;
complements sec-audit's cve-enricher with reachability-
hint metadata that the OSV bulk-query path lacks) and
`ruff` (Rust-implemented Python linter; runs the `S`-prefix
flake8-bandit security ruleset and the `B`-prefix
flake8-bugbear bug-prone-pattern ruleset, faster than
running bandit alone with finer-grained rule selection).
Both cross-platform; no host-OS gate; both run as pure
source-tree static scanners (pip-audit's network calls go
to OSV/PyPI for vulnerability metadata only — same trust
boundary as sec-audit's cve-enricher uses).

**Delineation from existing SAST lane:** the SAST lane (§3.6)
runs `bandit` and `semgrep` against every project. Why a
dedicated Python lane in addition? Three reasons:

1. **`pip-audit` adds reachability-hint metadata** — when a
   vulnerable package is installed but the vulnerable
   function is never imported, pip-audit reports the
   advisory but downgrades severity. cve-enricher's bulk
   OSV pass is version-only.
2. **`ruff` is faster + has more recent rules** — ruff's
   flake8-bandit port adds rules that landed in upstream
   bandit after the last pinned version; running ruff
   alongside catches the gap.
3. **Reference-pack deepening** — the Python lane ships
   `python/deserialization.md`, `python/subprocess-and-async.md`,
   `python/framework-deepening.md` for sec-expert reasoning
   beyond what bandit's rule set covers (Pickle/YAML XXE
   class, asyncio task swallowing, FastAPI dependency-
   injection bypass, Django ORM `.extra()` injection).

Out of scope: `mypy` / `pyright` (type-checkers, not
security tools); `flake8` (style-only, no security depth);
`safety` (commercial fork of pip-audit's domain — pip-audit
is canonical and PyPA-maintained); `vulture` (dead-code
detection, not security signal).

## Canonical invocations

### pip-audit

- Install: `pip install pip-audit` (Python 3.8+) OR `pipx install pip-audit`. Cross-platform (pure Python).
- Invocation:
  ```bash
  # Mode A: scan a requirements file (preferred — deterministic, no env activation):
  pip-audit -r "$target_path/requirements.txt" --format json \
      > "$TMPDIR/python-runner-pip-audit.json" \
      2> "$TMPDIR/python-runner-pip-audit.stderr"
  rc_pa=$?

  # Mode B: scan the active environment (when no requirements.txt is present):
  pip-audit --format json \
      > "$TMPDIR/python-runner-pip-audit.json" \
      2> "$TMPDIR/python-runner-pip-audit.stderr"
  ```
  Prefer Mode A; fall back to Mode B only when no
  `requirements.txt` / `requirements-*.txt` /
  `pyproject.toml` is present and an active venv contains
  the dependencies. Skip pip-audit entirely if neither
  manifest nor active env is available.
- Output: JSON object with `dependencies: [{name, version, vulns: [...]}]`. Each vuln has `id` (e.g. `GHSA-xxxx-xxxx-xxxx` or `CVE-YYYY-NNNNN`), `description`, `fix_versions`, `aliases`.
- Tool behaviour: exits non-zero when any vulnerability fires (1 = vulns found, 2 = error). Parse JSON for both 0 and 1 exit codes.
- Primary source: https://github.com/pypa/pip-audit

Source: https://github.com/pypa/pip-audit

### ruff

- Install: `pip install ruff` (Python 3.7+) OR pre-built binaries from GitHub Releases (Linux/macOS/Windows amd64+arm64). Cross-platform.
- Invocation:
  ```bash
  ruff check --select=S,B \
             --output-format=json \
             "$target_path" \
      > "$TMPDIR/python-runner-ruff.json" \
      2> "$TMPDIR/python-runner-ruff.stderr"
  rc_ru=$?
  ```
  `--select=S,B` enables the `S` (flake8-bandit) and `B`
  (flake8-bugbear) rule families — the security-relevant
  subset. Other ruff rule families are style/formatting and
  out of scope for sec-audit.
- Output: JSON array. Each element has `code` (e.g. `S101`,
  `S301`, `S506`, `S608`, `B007`, `B902`), `message`,
  `filename`, `location` (with `row`, `column`),
  `end_location`, `fix` (optional structured fix), `url`
  (link to the rule doc).
- Tool behaviour: exits non-zero when any rule fires.
  NOT a crash — parse JSON regardless. Empty result is `[]`.
- Primary source: https://docs.astral.sh/ruff/

Source: https://docs.astral.sh/ruff/

## Output-field mapping

Every finding carries `origin: "python"`,
`tool: "pip-audit" | "ruff"`,
`reference: "python-tools.md"`.

### pip-audit → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"pip-audit:" + .vulns[].id` (GHSA-… or CVE-…)        | `id`                         |
| Severity derived from CVSS in vuln record (HIGH/MEDIUM/LOW) — when absent, default to MEDIUM | `severity` |
| `"CWE-1395"` (vulnerable third-party component) — pip-audit does not ship per-vuln CWE | `cwe` |
| `.vulns[].description` (first 200 chars)              | `title`                      |
| The dep manifest path (`requirements.txt` / `pyproject.toml`) | `file`               |
| 0 (no source line for dep findings)                   | `line`                       |
| `.name + " " + .version + " — " + (.vulns[].id)`      | `evidence`                   |
| `https://osv.dev/vulnerability/` + (.vulns[].id)      | `reference_url`              |
| `.vulns[].fix_versions[0]` formatted as "upgrade to >=X" | `fix_recipe`              |
| `"high"` (pip-audit cross-references OSV — high precision) | `confidence`            |

### ruff → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"ruff:" + .code`                                     | `id`                         |
| Per-`code` severity table — `S102` (exec) HIGH, `S301`/`S506` (pickle/yaml load) HIGH, `S608` (SQL via fstring) HIGH, `S605`/`S606` (process call with shell-tainted) HIGH, `S105`/`S106` (hardcoded password) MEDIUM, `S307` (eval) HIGH, `S311` (random for security) MEDIUM, `S324` (weak hash) MEDIUM, `S501` (verify=False) HIGH, `S701` (Jinja2 autoescape disabled) HIGH, all other `S*` MEDIUM, all `B*` LOW | `severity` |
| Per-`code` CWE table — `S102`/`S307` (exec/eval) → CWE-95, `S301` (pickle) → CWE-502, `S506` (yaml.load) → CWE-502, `S608` (fstring SQL) → CWE-89, `S605`/`S606` (subprocess shell) → CWE-78, `S105`/`S106` (hardcoded password) → CWE-798, `S311` (random) → CWE-338, `S324` (md5/sha1) → CWE-327, `S501` (verify=False) → CWE-295, `S313`-`S320` (XML XXE class) → CWE-611, `S701` (Jinja2 autoescape) → CWE-79, all other → null | `cwe` |
| `.message`                                            | `title`                      |
| `.filename`                                           | `file`                       |
| `.location.row`                                       | `line`                       |
| `.message` (truncated to 200 chars)                   | `evidence`                   |
| `.url` if present, else `https://docs.astral.sh/ruff/rules/#` + code | `reference_url` |
| null (ruff's `fix` is structured patch data, not a citation-grade recipe) | `fix_recipe` |
| `"high"` (ruff is deterministic; no FP rate above the per-code severity remap) | `confidence` |

## Degrade rules

`__python_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary (v1.7.0):

- `tool-missing` — the tool's binary is absent from PATH.
- `no-requirements` — pip-audit is on PATH but the target
  has no `requirements.txt` / `requirements-*.txt` /
  `pyproject.toml` AND no active virtualenv to scan.
  Target-shape clean-skip; parallel to v0.10–v1.6
  target-shape primitives.

No host-OS gate — both tools are cross-platform.

## Version pins

- `pip-audit` ≥ 2.7 (stable JSON schema; `aliases[]`
  populated from OSV; `--strict` flag for fail-on-vuln
  semantics finalised). Pinned 2026-04.
- `ruff` ≥ 0.5 (stable JSON output schema; `S`-rule subset
  vocabulary tracking upstream bandit ≥ 1.7.5;
  `B`-rule subset stable). Pinned 2026-04.
