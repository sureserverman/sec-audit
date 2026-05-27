# sec-audit report — sec-audit (self-audit)

**Findings:** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 3 LOW
**Target:** `/home/user/dev/ai-tools/sec-audit` @ `3f0e38a` (v1.20.0)
**Generated:** 2026-05-27 20:55 UTC
**Plus:** 2 INFO (informational — not counted in the severity tally)

> ⚠ **Self-review.** This is the sec-audit plugin auditing its own source
> tree. The skill's §1 scope guard normally refuses this; it was overridden
> at the user's explicit request. Read the **Scope & methodology** section
> before acting on these findings — the analysis was deliberately narrowed
> to the plugin's *real shipped surface* and the standard multi-agent
> pipeline was **not** dispatched (rationale below).

---

## Scope & methodology

### In scope (real shipped surface)
- **Python — 883 LOC, stdlib-only**, under `scripts/secaudit/`:
  `net.py` (HTTP), `cve_enricher.py` (OSV/KEV feed enrichment),
  `runner.py` (config-driven external-tool engine), `inventory.py`
  (file-glob detection), `score.py` (prioritisation rubric).
- **Shell** — `push-purged-history.sh` (root, shipped) + the `tests/*.sh`
  drill/e2e harness.
- **AI-tools config** — the plugin definition itself: `commands/sec-audit.md`,
  27 `agents/*.md`, `skills/sec-audit/SKILL.md`, `.claude-plugin/`,
  `.claude/settings.local.json`.

### Out of scope (deliberately excluded)
- **`tests/fixtures/**`** — the inventory pre-pass detected ~10 lanes
  (rust, go, android, k8s, iac, virt, webext, supply-chain, python, shell)
  and 5 dependency ecosystems (PyPI, npm, Go, crates.io, Maven). **Every one
  of those manifests is an intentionally-vulnerable test fixture**
  (`vulnerable-python/`, `vulnerable-rust/`, `vulnerable-supply-chain/`, …)
  whose purpose is to prove the lanes fire. Auditing them would emit a flood
  of by-design findings — pure noise. They are excluded from all
  dependency/lane analysis.
- **CVE enrichment** — no-op. The plugin has **no real third-party
  dependencies** (no root `requirements.txt`/`package.json`/etc.; the Python
  is stdlib-only by design). The only manifests in the tree are the fixtures
  above.

### How the analysis was run (deviation from the standard pipeline)
The normal pipeline dispatches `sec-expert` + per-lane runners + `cve-enricher`.
For this self-audit that was **not** done, for three reasons:
1. The lane runners' tools are **not installed** — `semgrep`, `bandit`,
   `ruff`, `pip-audit`, `mcp-scan` are all absent (`shellcheck`, `jq`,
   `node`, `python3` are present). The SAST/python/ai-tools tool passes would
   report `unavailable`; fabricating their output is forbidden.
2. The real surface is small (883 LOC + a handful of scripts + config),
   so sec-expert-grade manual review was performed **directly** by the
   orchestrator (Opus) — more reliable here than dispatching sonnet runners
   against missing tools.
3. The fixture exclusion above removes the inputs the other ~8 lanes would
   consume.

**Deterministic tool that DID run:** `shellcheck` (real, on PATH) against all
non-fixture shell scripts.

### Per-lane summary
| Lane | Status | Notes |
|---|---|---|
| python (manual) | ✅ reviewed | 883 LOC, stdlib core — see findings |
| shell (shellcheck) | ✅ ran | `push-purged-history.sh` clean; 3 LOW warnings in `tests/*.sh` |
| ai-tools (manual) | ✅ reviewed | command/agents/settings — least-privilege confirmed |
| sast / webapp | ⚠ unavailable | semgrep + bandit not on PATH |
| ai-tools (mcp-scan) | ⚠ unavailable | mcp-scan not on PATH (no `.mcp.json` anyway) |
| rust, go, android, k8s, iac, virt, webext, supply-chain | ⏭ skipped | inputs are `tests/fixtures/**` only (out of scope) |
| cve-enricher | ⏭ no-op | no real third-party dependencies |

---

## Findings

### LOW-1 — Unhardened XML parsing of tool output (entity-expansion DoS class)
- **File:** `scripts/secaudit/runner.py:166` (`_xml_items` → `ET.fromstring`)
- **CWE:** CWE-776 (XML entity expansion) / CWE-611-adjacent
- **Detail:** Tool XML output (android-lint, virt-xml-validate via the
  validator mode) is parsed with `xml.etree.ElementTree.fromstring()`. The
  Python stdlib docs explicitly flag ElementTree against untrusted XML for
  entity-expansion ("billion laughs" / quadratic blowup) and recommend
  `defusedxml`. External-entity *resolution* is already safe in ElementTree,
  and modern libexpat (≥2.4.0, bundled in recent CPython) mitigates billion
  laughs by default — and the XML here is tool-*generated*, not raw target
  content — so this is **defense-in-depth**, hence LOW.
- **Fix:** parse via `defusedxml.ElementTree` *(adds a dependency — against
  the stdlib-only design)*, **or** keep stdlib and harden the expat parser:
  ```python
  parser = ET.XMLParser()
  parser.parser.DefaultHandler = lambda data: None   # no entity expansion
  # or guard input size and reject DOCTYPE/<!ENTITY before parse
  ```
  Simplest stdlib-only mitigation: reject inputs containing `<!DOCTYPE`/`<!ENTITY`
  before `fromstring`, since legitimate tool output never declares a DTD.

### LOW-2 — Feed-supplied vuln ID interpolated into URL path without encoding
- **File:** `scripts/secaudit/cve_enricher.py:95`
  (`net.get(f"{OSV}/v1/vulns/{vid}")`)
- **CWE:** CWE-20 (improper input validation) — SSRF/path-confusion class
- **Detail:** `vid` is taken from the OSV `querybatch` response
  (`v.get("id", "")`) and interpolated directly into the request path. A
  compromised or spoofed feed response containing path-control characters
  (`/`, `?`, `#`, `..`) could alter the request target. Risk is low: OSV IDs
  are a constrained charset (`CVE-…`, `GHSA-…`, `MAL-…`), the base URL is a
  hard-coded HTTPS origin, and a man-in-the-middle is already excluded by
  TLS verification (intact — see note below).
- **Fix:** `from urllib.parse import quote` then
  `net.get(f"{OSV}/v1/vulns/{quote(vid, safe='')}")`. Optionally validate
  `vid` against `^[A-Za-z0-9.\-]+$` and skip non-conforming IDs.

### LOW-3 — No URL-scheme allowlist on the HTTP seam
- **File:** `scripts/secaudit/net.py:43,63` (`urllib.request.urlopen`)
- **CWE:** CWE-918 (SSRF) / CWE-749 — via env-controlled endpoint base
- **Detail:** `urllib.request.urlopen` will service `file://`, `ftp://`, and
  `data:` schemes. The feed base URLs are env-overridable
  (`OSV_BASE_URL`, `NVD_BASE_URL`, `GHSA_BASE_URL`, `KEV_URL` —
  the documented offline-degrade seam). An operator (or a poisoned process
  environment) that points one of these at `file:///etc/...` would cause
  `net.get` to read local files into the enrichment output. Exploitation
  requires control of the process environment, which is already a
  high-privilege position — hence LOW, but a security tool should pin its
  own egress.
- **Fix:** in `get`/`post`, assert the scheme up front:
  ```python
  from urllib.parse import urlparse
  if urlparse(url).scheme not in ("http", "https"):
      return 0, ""
  ```

---

## Informational (not scored)

### INFO-1 — `tempfile.mkdtemp()` directories are never removed
- **File:** `scripts/secaudit/runner.py:313`
- Each `run_live` call creates a temp dir and never cleans it up. `mkdtemp`
  is `0700` so this is not a disclosure issue — just leaked scratch dirs
  across runs. Wrap in `try/finally: shutil.rmtree(tmp, ignore_errors=True)`
  or use `tempfile.TemporaryDirectory()`.

### INFO-2 — Minor shellcheck warnings in the test harness
- `tests/ai-tools-e2e.sh:99` — **SC2088**: `~` in quotes won't expand
  (use `$HOME`). Functional bug in a test path, not a security issue.
- `tests/deep-deps-drill.sh:24`, `tests/k8s-drill.sh:8` — **SC2034**:
  unused variable (`target` / `target_path`).
- The **shipped** `push-purged-history.sh` is shellcheck-clean.

---

## What was checked and found sound (no findings)

- **No command injection.** `runner.py` invokes every external tool with
  **list-form `argv`** to `subprocess.run` — never `shell=True` — so
  attacker-influenced filenames passed as arguments cannot break out into a
  shell.
- **TLS verification intact.** `net.py` uses urllib's default context; no
  `ssl._create_unverified_context`, no `verify=False`.
- **No `eval`/`exec`/`pickle`/`yaml.load`** anywhere in the Python.
- **Request budget cap** (500/run) in `cve_enricher.py` bounds runaway
  network use; all feed parsing is exception-guarded and degrades to
  `status: offline`.
- **No real secrets.** Every secret-pattern match is example/pedagogical
  content inside `skills/sec-audit/references/**` (e.g. a base64 `supersecret`
  k8s sample, CSRF-token example functions, OAuth grep patterns).
- **AI-tools least-privilege.** The command declares an explicit
  `allowed-tools` list (no `Bash(*)` wildcard); 26 of 27 agents are granted
  only `Read, Bash`, with `Write` reserved to `report-writer`; models are
  pinned (haiku for I/O runners, sonnet for reasoning) with no Opus inflation;
  no `.mcp.json`, no hooks, no over-granted tools. `settings.local.json` holds
  only plugin on/off flags and is **not** git-tracked.

---

## Residual risk note (inherent to any LLM code-review tool)

The `sec-expert` and `report-writer` agents read untrusted target source and
tool output; a malicious target could embed prompt-injection in comments or
filenames. The v1.17+ hybrid design — moving the deterministic lanes into
`runner.py` script-backed mappers so the LLM no longer fabricates the
finding fields — materially narrows this class, but it cannot be eliminated
for the agents that still reason over target content. This is a property of
the architecture, not a defect in this tree.

---

*Self-audit performed directly by the orchestrator (manual sec-expert review +
shellcheck) rather than the standard agent pipeline; see Scope & methodology.
0 CRITICAL / 0 HIGH means a subsequent `project-maturity audit` will auto-tick
the Security axis from this report.*
