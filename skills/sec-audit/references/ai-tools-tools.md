# ai-tools-tools

<!--
    Tool-lane reference for sec-audit's ai-tools lane.
    Consumed by the `ai-tools-runner` sub-agent. Documents the
    two tools the runner invokes:

      - jq: structural JSON validation for AI-tool-config files.
      - mcp-scan (Invariant Labs; rebranded `snyk-agent-scan`
        after the Snyk acquisition): tool-poisoning + malicious-
        description scanner for `.mcp.json` and skill files,
        run in `inspect` mode (static, never launches MCP
        servers).

    Lane shape: jq + mcp-scan. Status states: `ok` / `partial`
    / `unavailable` (matches the SAST and webext lanes).
-->

## Source

- https://jqlang.org/ — jq reference (canonical)
- https://stedolan.github.io/jq/manual/ — jq manual (widely mirrored)
- https://github.com/invariantlabs-ai/mcp-scan — mcp-scan (Invariant Labs; Apache-2.0)
- https://invariantlabs.ai/blog/mcp-scan — mcp-scan announcement and threat model writeup
- https://github.com/slowmist/MCP-Security-Checklist — SlowMist MCP Security Checklist (cross-reference for tool-poisoning, name-shadowing, sampling, multi-MCP risks)
- https://genai.owasp.org/llm-top-10/ — OWASP LLM Top 10 v2025 (LLM01 indirect prompt injection)
- https://cwe.mitre.org/data/definitions/1284.html — CWE-1284: Improper Validation of Specified Quantity in Input
- https://cwe.mitre.org/data/definitions/94.html — CWE-94: Improper Control of Generation of Code (used for tool-poisoning findings)
- https://docs.claude.com/en/docs/claude-code/plugins — Claude Code plugin authoring (plugin.json / marketplace.json shapes)
- https://docs.claude.com/en/docs/claude-code/mcp — Claude Code MCP config (.mcp.json shape)
- https://docs.claude.com/en/docs/claude-code/settings — Claude Code settings.json shape
- https://opencode.ai/docs/ — OpenCode (opencode.json shape)

## Scope

In-scope: the two tools invoked by `ai-tools-runner` —

1. **`jq`** as a JSON structural validator. The runner invokes
   `jq` once per JSON config file that belongs to the AI-tool-
   config shapes listed below. Its role is parse validation
   only: it confirms the file is well-formed JSON and emits a
   MEDIUM finding when it is not.

2. **`mcp-scan inspect`** (or `snyk-agent-scan inspect` when the
   legacy package name is unavailable) as a tool-poisoning and
   malicious-description scanner. The runner invokes it on each
   `.mcp.json` config and on the project's skill / agent
   markdown trees. The `inspect` subcommand is **static-only** —
   it reads tool descriptions WITHOUT launching any MCP server
   process. The runner MUST NEVER invoke the `scan` subcommand,
   which would launch stdio servers locally; that violates
   sec-audit's no-execution guarantee.

JSON files in scope (the only ones the runner passes to jq):

- `.claude-plugin/plugin.json`
- `.claude-plugin/marketplace.json`
- `.mcp.json` (at any depth under target)
- `.claude/settings.json`
- `.claude/settings.local.json`
- `opencode.json`

Files in scope for mcp-scan:

- All `.mcp.json` discovered above.
- `claude_desktop_config.json` if present anywhere under target.
- Skill / agent markdown trees: `skills/**/SKILL.md`,
  `agents/*.md`, `.claude/agents/*.md`, `.claude/skills/**/SKILL.md`
  (mcp-scan reads these via its `--skills` flag).

Not every JSON file in the target tree — only the six AI-tool-
config shapes above. YAML-fronted Markdown files (`.mdc`,
`SKILL.md`, `agents/*.md`) are plain text and are not validated
by `jq`; they ARE handed to mcp-scan when its `--skills` mode is
applicable. TOML files (`.codex/config.toml`) are out of scope
for both tools (sec-expert text analysis only).

Out of scope: live testing (the runner never starts any AI tool,
model, or MCP server — `mcp-scan inspect` is static, never
`mcp-scan scan`); network-level validation; semantic schema
validation beyond parse correctness; OAuth token introspection.

## Canonical invocations

### jq

- Install: `apt install jq` / `brew install jq` / pre-built
  binaries at https://jqlang.org/download/. Cross-platform; C
  binary with no runtime dependencies.
- Invocation:
  ```bash
  jq --exit-status . "$config_file" > /dev/null \
      2> "$TMPDIR/ai-tools-runner-jq.stderr"
  rc_jq=$?
  ```
  Run once per in-scope JSON file. The `--exit-status` flag
  causes `jq` to exit non-zero if the output is `false` or
  `null` (which also catches empty-document edge cases), in
  addition to the standard non-zero exit on parse failure.
  Stdout is discarded; only the exit code and stderr are used.
  stderr contains the parse error message when rc != 0.
- Output: exit code only (stdout discarded). rc=0 → file is
  well-formed JSON; no finding emitted from `jq` (security
  findings come from sec-expert and mcp-scan). rc!=0 → one
  MEDIUM finding per file with the stderr text as evidence.
- Tool behaviour: reads the file and parses it entirely in
  memory. No network activity, no file writes, no side effects.
  Pure parse validation.
- Primary source: https://jqlang.org/

Source: https://jqlang.org/

### mcp-scan (or snyk-agent-scan)

- Install (legacy / preferred): `pipx install mcp-scan` or
  `pip install --user mcp-scan`. The original Invariant Labs
  package; Apache-2.0; cross-platform Python.
- Install (post-acquisition fork): `uvx snyk-agent-scan@latest`
  or `pipx install snyk-agent-scan`. Same `inspect` subcommand,
  same `--json` flag. Use this name when `mcp-scan` is not
  available on PATH.
- Probe order — try `mcp-scan` first, then `snyk-agent-scan`:
  ```bash
  mcp_scan_bin=""
  if command -v mcp-scan >/dev/null 2>&1; then
      mcp_scan_bin="mcp-scan"
  elif command -v snyk-agent-scan >/dev/null 2>&1; then
      mcp_scan_bin="snyk-agent-scan"
  fi
  ```
- Invocation (per `.mcp.json` / `claude_desktop_config.json`):
  ```bash
  "$mcp_scan_bin" inspect "$config_file" --json \
      > "$TMPDIR/ai-tools-runner-mcpscan-$nonce.json" \
      2> "$TMPDIR/ai-tools-runner-mcpscan-$nonce.stderr"
  rc_mcpscan=$?
  ```
  `inspect` is the **static** subcommand: it reads tool
  descriptions from the config file and any servers it
  references WITHOUT launching the servers themselves. The
  `--json` flag emits machine-readable output on stdout.
- Invocation (per skills tree, when present):
  ```bash
  "$mcp_scan_bin" --skills "$target_path/skills" --json \
      > "$TMPDIR/ai-tools-runner-mcpscan-skills.json" \
      2> "$TMPDIR/ai-tools-runner-mcpscan-skills.stderr"
  ```
- Output schema (best-effort permissive parser): mcp-scan
  emits a JSON document. The runner extracts an array of
  issues by trying these top-level keys in order: `issues`,
  `findings`, `results`. If none is present and the document
  is itself a JSON array, treat that array as the issues list.
  Each issue object is mapped per the table below; missing
  fields default to `null` and never crash the parser.
- Tool behaviour: reads files only. Network activity is
  bounded to fetching the latest signature pack the first
  time the tool runs, which the runner suppresses by setting
  `MCP_SCAN_OFFLINE=1` (or by using the cached pack at
  `~/.cache/mcp-scan/`). When suppression fails, mcp-scan
  still degrades gracefully — outdated signatures still
  detect the most common patterns.
- Forbidden flags — the runner MUST NOT pass any of:
  - `scan` subcommand (launches MCP servers locally)
  - `--dangerously-run-mcp-servers` (forces non-interactive
    server launch in the Snyk fork)
  Setting either violates sec-audit's no-execution guarantee.
- Primary source: https://github.com/invariantlabs-ai/mcp-scan

Source: https://github.com/invariantlabs-ai/mcp-scan

## Output-field mapping

### jq parse failure → sec-audit finding (when rc != 0)

Every finding carries `origin: "ai-tools"`,
`tool: "jq"`, `reference: "ai-tools-tools.md"`.

| sec-audit field             | value                                                         |
|------------------------------|---------------------------------------------------------------|
| `id`                         | `"jq:invalid-json"`                                           |
| `severity`                   | `MEDIUM` (structural; config will be silently ignored or crash the tool) |
| `cwe`                        | `CWE-1284` (Improper Validation of Specified Quantity in Input) |
| `title`                      | First line of stderr text (truncated to 200 chars)            |
| `file`                       | The config file path (relative to target_path)                |
| `line`                       | Line number extracted from stderr via regex `line\s+(\d+)`; 0 if absent |
| `evidence`                   | Stderr text (truncated to 200 chars)                          |
| `reference_url`              | `https://jqlang.org/`                                         |
| `fix_recipe`                 | null                                                          |
| `confidence`                 | `"high"` (deterministic parser)                              |

### mcp-scan issue → sec-audit finding

Every finding carries `origin: "ai-tools"`,
`tool: "mcp-scan"`, `reference: "ai-tools-tools.md"`. The
`tool` value is always literally `mcp-scan` regardless of
which binary actually ran (legacy `mcp-scan` or `snyk-agent-
scan`); this keeps the lane allowlist single-entry and stable.

The runner extracts the issue list from the top-level
document by trying keys `issues` / `findings` / `results`
in that order, then falling back to a top-level array. Per-
issue fields are pulled with this preference (first present
wins); missing values default to `null` or the listed
default.

| sec-audit field   | mcp-scan field preference                                       | Notes                                                             |
|-------------------|------------------------------------------------------------------|-------------------------------------------------------------------|
| `id`              | `id` ‖ `rule_id` ‖ `check_id` ‖ `"mcp-scan:unknown"`             | Verbatim if present                                              |
| `severity`        | `severity` (uppercase, mapped: CRITICAL/HIGH→`HIGH`, MEDIUM/MODERATE→`MEDIUM`, LOW/INFO→`LOW`) | Default `MEDIUM` when absent or unrecognized |
| `cwe`             | `cwe` ‖ `cwe_id` ‖ `"CWE-94"`                                    | CWE-94 (code injection) is the canonical fallback for tool poisoning |
| `title`           | `title` ‖ `name` ‖ `description` (first 200 chars)               | Truncated                                                         |
| `file`            | `file` ‖ `path` ‖ `config_file` (made relative to `target_path`) | Path normalization                                                |
| `line`            | `line` ‖ `line_number` ‖ `0`                                     | 1-indexed when known                                              |
| `evidence`        | `evidence` ‖ `description` ‖ `message` ‖ `title` (truncated 200) | Verbatim                                                          |
| `reference_url`   | `url` ‖ `reference` ‖ `https://github.com/invariantlabs-ai/mcp-scan` | Fallback to project URL when issue has none |
| `fix_recipe`      | `null`                                                            | Sec-expert provides fix_recipe; the runner never invents one      |
| `confidence`      | `"medium"`                                                        | mcp-scan signatures are heuristic, not deterministic              |

If the JSON document does not contain any of the recognized
issue-list keys AND is not a top-level array, the runner
treats this as a tool failure (not a clean scan): no findings
are emitted and mcp-scan is reported in the status sentinel
with `reason: "parse-failed"`.

## Degrade rules

`__ai_tools_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

State semantics:

- `ok`: BOTH jq and mcp-scan ran successfully (or had no
  applicable inputs). Findings count may be zero.
- `partial`: at least one tool ran, at least one was missing
  or failed. Findings (if any) come only from the tool(s)
  that ran.
- `unavailable`: jq is missing AND mcp-scan is missing,
  OR jq is on PATH but no in-scope JSON exists AND no
  skills/MCP files exist for mcp-scan to inspect. No
  findings emitted.

Skip vocabulary (v1.13):

- `tool-missing` — the named binary is absent from PATH.
  Emit per-tool, e.g. `{"tool": "mcp-scan", "reason":
  "tool-missing"}`.
- `no-ai-tool-config` — the binary is on PATH but no
  in-scope file exists for it (jq: no JSON shape found;
  mcp-scan: no `.mcp.json` and no skills tree). Emit per-
  tool with the same shape.
- `parse-failed` — mcp-scan ran but its output JSON could
  not be parsed (no recognized issue list, malformed
  document). Emit `{"tool": "mcp-scan", "reason":
  "parse-failed"}`. No findings; mcp-scan is treated as
  unavailable for that run.

No host-OS gate. Both tools are available on Linux, macOS,
and Windows (jq via native binary or WSL; mcp-scan via
Python and pipx/uvx).

## Version pins

- `jq` ≥ 1.6 (stable `--exit-status` flag; bignum support).
  Pinned 2026-04.
- `mcp-scan` ≥ 0.2 (legacy Invariant Labs package; first
  public release with the `inspect` subcommand). Pinned
  2026-05.
- `snyk-agent-scan` ≥ 0.1 (post-acquisition fork; accepts
  same `inspect`/`--json`/`--skills` flags). Pinned 2026-05.
  When both binaries are present, prefer `mcp-scan` for the
  more permissive license terms and the simpler invocation
  surface (no `SNYK_TOKEN` required for inspect mode).

## Common false positives

- mcp-scan flagging a skill description that legitimately
  cites prompt-injection example strings inside fenced code
  blocks for documentation purposes (e.g. the very pack
  `prompt-injection.md` itself, or sec-audit's own fixture
  trees). The runner does not suppress these — sec-expert's
  `finding-triager` annotates them with `fp_suspected`
  during triage. Do NOT add suppression in the runner.
- jq flagging a JSON file that contains JSONC-style comments
  (e.g. `claude_desktop_config.json` historically allowed
  `//` comments). When this is observed, file the finding —
  Claude Code's strict parser also rejects JSONC, so the
  finding is genuine, not a false positive.
