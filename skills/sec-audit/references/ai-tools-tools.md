# ai-tools-tools

<!--
    Tool-lane reference for sec-audit's ai-tools lane.
    Consumed by the `ai-tools-runner` sub-agent. Documents
    jq as the only runner-invoked tool (JSON structural
    validation for AI-tool-config-shaped files).
-->

## Source

- https://jqlang.org/ — jq reference (canonical)
- https://stedolan.github.io/jq/manual/ — jq manual (widely mirrored)
- https://cwe.mitre.org/data/definitions/1284.html — CWE-1284: Improper Validation of Specified Quantity in Input
- https://docs.claude.com/en/docs/claude-code/plugins — Claude Code plugin authoring (plugin.json / marketplace.json shapes)
- https://docs.claude.com/en/docs/claude-code/mcp — Claude Code MCP config (.mcp.json shape)
- https://docs.claude.com/en/docs/claude-code/settings — Claude Code settings.json shape
- https://opencode.ai/docs/ — OpenCode (opencode.json shape)

## Scope

In-scope: the single tool invoked by `ai-tools-runner` — `jq`
used as a JSON structural validator. The runner invokes `jq` once
per JSON config file that belongs to the AI-tool-config shapes
listed below. Its role is parse validation only: it confirms the
file is well-formed JSON and emits a MEDIUM finding when it is not.
Security-pattern detection (the patterns documented in
`ai-tools/claude-code-plugin.md`, `ai-tools/claude-code-mcp.md`,
`ai-tools/prompt-injection.md`, `ai-tools/cursor-rules.md`, and
`ai-tools/codex-opencode.md`) is handled by sec-expert reading
the reference packs; `jq` only catches parse failures.

JSON files in scope (the only ones the runner passes to jq):

- `.claude-plugin/plugin.json`
- `.claude-plugin/marketplace.json`
- `.mcp.json` (at any depth under target)
- `.claude/settings.json`
- `.claude/settings.local.json`
- `opencode.json`

Not every JSON file in the target tree — only the six AI-tool-config
shapes above. YAML-fronted Markdown files (`.mdc`, `SKILL.md`,
`agents/*.md`) are plain text and are not validated by `jq`; they
are covered by sec-expert text analysis only. TOML files
(`.codex/config.toml`) are also out of scope for `jq`.

Out of scope: live testing (the runner never starts any AI tool,
model, or MCP server); network-level validation; semantic schema
validation beyond parse correctness.

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
  findings come from sec-expert). rc!=0 → one MEDIUM finding
  per file with the stderr text as evidence.
- Tool behaviour: reads the file and parses it entirely in
  memory. No network activity, no file writes, no side effects.
  Pure parse validation.
- Primary source: https://jqlang.org/

Source: https://jqlang.org/

## Output-field mapping

Every finding carries `origin: "ai-tools"`,
`tool: "jq"`, `reference: "ai-tools-tools.md"`.

### jq parse failure → sec-audit finding (when rc != 0)

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

## Degrade rules

`__ai_tools_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary (v1.0):

- `tool-missing` — `jq` binary is absent from PATH. The runner
  degrades to sec-expert-only mode; all JSON files are still
  analyzed by sec-expert for pattern findings, but parse
  validation is skipped. Set status `"partial"`.
- `no-ai-tool-config` — `jq` is on PATH but none of the six
  in-scope JSON file paths exist anywhere under target. Target-
  shape clean-skip. Set status `"ok"` (no findings emitted,
  no degradation).

No host-OS gate. `jq` is available on Linux, macOS, and Windows
(via WSL or the native binary).

## Version pins

- `jq` ≥ 1.6 (stable `--exit-status` flag; bignum support).
  Pinned 2026-04.
