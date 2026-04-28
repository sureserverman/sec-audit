# Claude Code Plugin — Plugin and Agent Configuration Security

## Source

- https://docs.claude.com/en/docs/claude-code/plugins — Claude Code plugin authoring guide
- https://docs.claude.com/en/docs/claude-code/settings — Claude Code settings reference (settings.json / settings.local.json)
- https://docs.claude.com/en/docs/claude-code/hooks — Claude Code hooks reference (hooks.json)
- https://docs.claude.com/en/docs/claude-code/skills — Claude Code skills reference (SKILL.md)
- https://docs.claude.com/en/docs/claude-code/agents — Claude Code sub-agents reference
- https://cwe.mitre.org/data/definitions/77.html — CWE-77: Improper Neutralization of Special Elements used in a Command
- https://cwe.mitre.org/data/definitions/78.html — CWE-78: OS Command Injection
- https://cwe.mitre.org/data/definitions/94.html — CWE-94: Improper Control of Generation of Code
- https://cwe.mitre.org/data/definitions/200.html — CWE-200: Exposure of Sensitive Information
- https://cwe.mitre.org/data/definitions/269.html — CWE-269: Improper Privilege Management
- https://cwe.mitre.org/data/definitions/693.html — CWE-693: Protection Mechanism Failure
- https://cwe.mitre.org/data/definitions/749.html — CWE-749: Exposed Dangerous Method or Function
- https://cwe.mitre.org/data/definitions/798.html — CWE-798: Use of Hard-coded Credentials
- https://genai.owasp.org/llm-top-10/ — OWASP LLM Top 10 (LLM01 Prompt Injection, LLM06 Sensitive Information Disclosure)

## Scope

Covers security-relevant configuration in Claude Code plugin
repositories: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`,
agent definition files (`agents/*.md`), skill definition files
(`skills/**/SKILL.md`), slash-command files (`commands/*.md`),
hook configuration (`hooks.json`, top-level or under `.claude/`),
and user/project settings files (`.claude/settings.json`,
`.claude/settings.local.json`). Out of scope: runtime behavior of
Claude models themselves; network-level MCP server security (covered
in `ai-tools/claude-code-mcp.md`); prompt injection in skill bodies
(covered in `ai-tools/prompt-injection.md`).

## Dangerous patterns (regex/AST hints)

### `Bash` or `Bash(*)` blanket allowlist in command/agent frontmatter — CWE-77 / CWE-693

- Why: Command and agent markdown files carry a YAML frontmatter
  block whose `allowed-tools:` field controls which Claude Code tools
  the model may invoke when running that command or agent. A value of
  `Bash` (no argument filter) or `Bash(*)` (explicit wildcard) grants
  the model permission to execute any shell command on the host
  without restriction. An attacker who achieves indirect prompt
  injection in any data the agent reads can leverage this to run
  arbitrary commands. The safe pattern is to use tool-scoped
  allowances such as `Bash(git log:*)` or `Bash(make test)`.
- Grep: `^\s*-\s*Bash(\(\*\))?\s*$`
- File globs: `agents/*.md`, `commands/*.md`, `skills/**/SKILL.md`,
  `.claude/agents/*.md`, `.claude/commands/*.md`.
- Source: https://docs.claude.com/en/docs/claude-code/agents

### Shell hooks interpolating `$TOOL_INPUT` / `$CLAUDE_*` unquoted — CWE-78

- Why: `hooks.json` (and the hooks section of `settings.json`) lets
  operators run shell commands before and after Claude tool calls. If
  the hook command string concatenates environment variables such as
  `$TOOL_INPUT` or `$CLAUDE_FILE_PATHS` directly into a bash
  one-liner without quoting, any tool input that contains shell
  metacharacters (`;`, `|`, `$(`, backtick) can break out of the
  intended command and execute arbitrary shell code. Claude Code
  populates `$TOOL_INPUT` from the raw tool argument — values that
  originate from user-supplied or external content.
- Grep: `\$(TOOL_INPUT|CLAUDE_[A-Z_]+)` inside a `command` string
  that is not wrapped in double quotes followed by a quoted reference.
  Practical regex: `"command":\s*"[^"]*\$(TOOL_INPUT|CLAUDE_)[^"]*"`
- File globs: `hooks.json`, `.claude/hooks.json`,
  `.claude/settings.json`, `.claude/settings.local.json`.
- Source: https://docs.claude.com/en/docs/claude-code/hooks

### `dangerouslyDisableSandbox: true` in settings — CWE-749

- Why: Claude Code runs Bash tool calls inside a sandbox that
  restricts network access and file-system scope by default.
  Setting `dangerouslyDisableSandbox: true` in `settings.json` or
  `settings.local.json` removes all sandbox restrictions, allowing
  any model-executed command to reach the network, write anywhere on
  disk, and interact with system daemons. This field is intentionally
  named to signal danger; its presence in a checked-in config file
  means every contributor who clones the repo runs without the
  sandbox.
- Grep: `"dangerouslyDisableSandbox"\s*:\s*true`
- File globs: `.claude/settings.json`, `.claude/settings.local.json`,
  `.claude-plugin/*.json`.
- Source: https://docs.claude.com/en/docs/claude-code/settings

### `--dangerously-skip-permissions` in hook commands — CWE-269

- Why: The `--dangerously-skip-permissions` flag, when passed to a
  nested `claude` invocation inside a hook command, bypasses all
  permission prompts for that sub-process. A hook that spawns Claude
  with this flag grants the sub-agent unrestricted tool access
  without any interactive approval, even for destructive operations
  (file deletion, remote pushes, package publishes). This is a
  privilege escalation path: the outer session may be scoped, but the
  inner invocation is not.
- Grep: `--dangerously-skip-permissions`
- File globs: `hooks.json`, `.claude/hooks.json`,
  `.claude/settings.json`, `.claude/settings.local.json`.
- Source: https://docs.claude.com/en/docs/claude-code/settings

### Hardcoded API keys or tokens in any plugin file — CWE-798

- Why: Plugin files (`plugin.json`, `marketplace.json`, agent
  markdown, skill files, hooks.json) are typically version-controlled
  and distributed to consumers via a marketplace or repository.
  Hardcoded Anthropic API keys (`sk-ant-...`), OpenAI keys
  (`sk-proj-...`), GitHub tokens (`ghp_...`, `gho_...`), or AWS
  access key IDs embedded in these files are exposed to every user
  who installs the plugin or clones the repo. Keys committed to git
  history persist even after deletion from HEAD.
- Grep: `(sk-ant-[A-Za-z0-9\-_]{20,}|sk-proj-[A-Za-z0-9\-_]{20,}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16})`
- File globs: `**/*.json`, `**/*.md`, `**/*.yaml`, `**/*.toml`.
- Source: https://cwe.mitre.org/data/definitions/798.html

### `permissions.allow: ["Bash(*)"]` blanket allowlist in settings — CWE-693

- Why: The `permissions` block in `settings.json` and
  `settings.local.json` controls which tools Claude may use in the
  project session without prompting. An `allow` entry of `"Bash(*)"` is
  functionally identical to granting the model unrestricted shell
  access for the duration of any session in that project directory.
  Combined with indirect prompt injection from files in the project
  tree, this allows a single malicious file to achieve arbitrary code
  execution silently.
- Grep: `"Bash\(\*\)"`
- File globs: `.claude/settings.json`, `.claude/settings.local.json`.
- Source: https://docs.claude.com/en/docs/claude-code/settings

### Agent `model:` pinned to Opus with destructive tools and no `description:` scoping — informational

- Why: An agent frontmatter that pins `model: claude-opus-4-5` (or
  any high-capability model) while listing Write, Edit, and Bash in
  `tools:` but omits a `description:` field is unscoped — Claude Code
  cannot decide when to invoke it from context alone. Without a
  `description:`, the agent is either never triggered automatically or
  is triggered incorrectly, and the combination of Opus-class
  reasoning with blanket destructive tools in an improperly triggered
  agent is a latent risk. This is informational; review intent.
- Grep: `^model:\s*claude-opus` in agent files that also contain
  `tools:` with `Write|Edit|Bash` and no `description:` key.
- File globs: `agents/*.md`, `.claude/agents/*.md`.
- Source: https://docs.claude.com/en/docs/claude-code/agents

### Skill `description:` containing hidden Unicode tag characters — CWE-94 / OWASP LLM01

- Why: Unicode tag characters (U+E0000–U+E007F) are invisible in
  most editors and terminals but are passed intact to the language
  model. A skill whose `description:` field embeds these characters
  can carry covert instructions that redirect the model's behavior
  during skill selection. This is an indirect prompt injection vector
  embedded at the configuration layer, not the user-input layer. See
  `ai-tools/prompt-injection.md` for full treatment.
- Grep: `[\xF3\xA0\x80\x80-\xF3\xA0\x81\xBF]` (UTF-8 encoding of
  U+E0000–U+E007F, PCRE: `\x{E0000}-\x{E007F}` with `-P` flag).
  Practical: `grep -P "[\x{E0000}-\x{E007F}]"`.
- File globs: `skills/**/SKILL.md`, `agents/*.md`, `commands/*.md`.
- Source: https://genai.owasp.org/llm-top-10/

### Skill `description:` exceeding 1024 characters — informational

- Why: Anthropic's Claude Code skill-selection mechanism uses the
  `description:` field to decide which skill matches a user's intent.
  Descriptions longer than ~1024 characters or spanning multiple
  paragraphs are truncated or poorly represented in the selection
  prompt, causing the skill to fail to trigger reliably. This is not
  a security finding but signals a misconfigured skill that may
  behave unexpectedly. Flag for review.
- Grep: Match the YAML frontmatter `description:` value and check
  byte length. Shell: `awk '/^description:/{found=1;buf=""} found{buf=buf$0} /^[a-z]/{if(found&&length(buf)>1024) print FILENAME; found=0}' SKILL.md`
- File globs: `skills/**/SKILL.md`.
- Source: https://docs.claude.com/en/docs/claude-code/skills

## Fix recipes

### Recipe: replace blanket Bash allowlist with scoped tool calls — addresses CWE-77 / CWE-693

**Before (dangerous):**

```yaml
---
name: run-tests
description: Run the test suite.
allowed-tools:
  - Bash
  - Read
---
```

**After (safe):**

```yaml
---
name: run-tests
description: Run the project test suite using pytest.
allowed-tools:
  - Bash(pytest:*)
  - Bash(python -m pytest:*)
  - Read
---
```

Source: https://docs.claude.com/en/docs/claude-code/agents

### Recipe: quote env-var references in hook commands — addresses CWE-78

**Before (dangerous):**

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "logger -t claude-hook Written file: $TOOL_INPUT"
          }
        ]
      }
    ]
  }
}
```

**After (safe):**

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "logger -t claude-hook \"Written file: ${TOOL_INPUT}\""
          }
        ]
      }
    ]
  }
}
```

Note: even with quoting, `$TOOL_INPUT` in a shell command is
risky if the value can contain newlines or NUL bytes. Prefer
hook scripts that receive the value over stdin or as a
positional argument from a wrapper script, never via
inline string interpolation.

Source: https://docs.claude.com/en/docs/claude-code/hooks

### Recipe: remove dangerouslyDisableSandbox — addresses CWE-749

**Before (dangerous):**

```json
{
  "dangerouslyDisableSandbox": true,
  "permissions": {
    "allow": ["Bash(*)", "Write", "Edit"]
  }
}
```

**After (safe):**

```json
{
  "permissions": {
    "allow": ["Bash(make:*)", "Bash(pytest:*)", "Write", "Edit"]
  }
}
```

Source: https://docs.claude.com/en/docs/claude-code/settings

### Recipe: replace hardcoded API key with environment variable reference — addresses CWE-798

**Before (dangerous):**

```json
{
  "name": "my-plugin",
  "env": {
    "ANTHROPIC_API_KEY": "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXX"
  }
}
```

**After (safe):**

```json
{
  "name": "my-plugin",
  "env": {}
}
```

Set `ANTHROPIC_API_KEY` in the shell environment or in an
untracked `.env` file loaded at session start, never in a
checked-in config.

Source: https://cwe.mitre.org/data/definitions/798.html

## Version notes

- Claude Code 1.x introduced `permissions.allow` / `permissions.deny`
  in `settings.json`; the `dangerouslyDisableSandbox` field exists
  from initial release. Pinned 2026-04.
- Agent `tools:` frontmatter was stabilized in the agent SDK; older
  plugin formats used `allowed-tools:` only in command files. Both
  fields are in scope.
- `hooks.json` as a standalone top-level file is supported alongside
  the `hooks:` key inside `settings.json`; both must be checked.

## Common false positives

- `allowed-tools: [Bash(git log:*)]` — scoped Bash; safe. Do not
  flag unless the argument filter is `(*)` or absent.
- Test fixture files under `tests/fixtures/` or `testdata/` that
  contain intentionally dangerous patterns to exercise the auditor —
  annotate as fixture, do not flag as live risk.
- `sk-ant-` prefix inside a comment block or documentation string
  that shows a redacted example (e.g. `sk-ant-...REDACTED...`) —
  verify the value does not match a real key pattern before flagging.
- `--dangerously-skip-permissions` in README or documentation code
  fences that describe CLI usage — flag only when inside an actual
  executable hook command string.
