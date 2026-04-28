# Claude Code MCP — Model Context Protocol Server Configuration Security

## Source

- https://modelcontextprotocol.io/ — Model Context Protocol specification and reference
- https://modelcontextprotocol.io/docs/concepts/transports — MCP transport types (stdio, HTTP/SSE)
- https://docs.claude.com/en/docs/claude-code/mcp — Claude Code MCP configuration guide
- https://cwe.mitre.org/data/definitions/77.html — CWE-77: Improper Neutralization of Special Elements used in a Command
- https://cwe.mitre.org/data/definitions/78.html — CWE-78: OS Command Injection
- https://cwe.mitre.org/data/definitions/200.html — CWE-200: Exposure of Sensitive Information
- https://cwe.mitre.org/data/definitions/319.html — CWE-319: Cleartext Transmission of Sensitive Information
- https://cwe.mitre.org/data/definitions/732.html — CWE-732: Incorrect Permission Assignment for Critical Resource
- https://cwe.mitre.org/data/definitions/798.html — CWE-798: Use of Hard-coded Credentials
- https://cwe.mitre.org/data/definitions/918.html — CWE-918: Server-Side Request Forgery
- https://cwe.mitre.org/data/definitions/1395.html — CWE-1395: Dependency on Vulnerable Third-Party Component

## Scope

Covers `.mcp.json` files at any depth in the project tree, as
well as the `mcpServers` block inside `.claude/settings.json` and
`.claude/settings.local.json`. MCP servers come in two transport
shapes: stdio (the `command`/`args`/`env` triple) and HTTP/SSE
(a `url` field). Both are in scope. Out of scope: the MCP server
implementation code itself (covered by the relevant language lane,
e.g. `frameworks/` or `shell/`); OpenCode MCP entries (cross-linked
from `ai-tools/codex-opencode.md`).

## Dangerous patterns (regex/AST hints)

### HTTP MCP server URL without TLS — CWE-319

- Why: An MCP server declared with a plain `http://` URL transmits
  all tool calls, tool results, and any context the model sends over
  an unencrypted channel. MCP sessions can carry secrets (API keys
  passed as tool arguments, file contents the model retrieved), and
  on a shared network the entire exchange is visible to passive
  observers. Claude Code sends the active project's context to the
  MCP server at session start; this context may include environment
  variable names, file paths, and file snippets. The safe pattern
  is `https://` for all remote MCP servers.
- Grep: `"url"\s*:\s*"http://`
- File globs: `.mcp.json`, `**/.mcp.json`, `.claude/settings.json`,
  `.claude/settings.local.json`.
- Source: https://modelcontextprotocol.io/docs/concepts/transports

### `npx` / `uvx` MCP server command without pinned package version — CWE-1395

- Why: Stdio MCP servers launched via `npx <package>` or
  `uvx <package>` resolve to the latest published version of that
  package at the moment of invocation unless the version is pinned.
  A malicious publisher can push a new version of the package that
  includes backdoor code; every developer who restarts Claude Code
  in a project using that MCP server will execute the malicious
  version. The safe form is `npx --package <pkg>@<exact-version>
  --yes <pkg>` or `uvx <pkg>==<exact-version>`, ideally combined
  with a lockfile or integrity check.
- Grep: `"command"\s*:\s*"(npx|uvx)"` AND `args` array that does
  not contain `@[0-9]` or `==[0-9]` in the package specifier.
  Practical: `"command":\s*"(npx|uvx)"` in the same object without
  a version-pinned package argument.
- File globs: `.mcp.json`, `**/.mcp.json`, `.claude/settings.json`,
  `.claude/settings.local.json`.
- Source: https://cwe.mitre.org/data/definitions/1395.html

### Stdio MCP server `command` interpolating env vars into shell — CWE-78

- Why: Some stdio MCP configs pass the `command` field as a shell
  string rather than a plain executable, embedding references to
  environment variables such as `$USER`, `$HOME`, or `$PROJECT_DIR`.
  If this string is later evaluated by a shell (e.g., the parent
  process uses `sh -c "$command"` to launch it), and any part of
  the variable values contains shell metacharacters, this becomes an
  OS command injection sink. Even when the launcher uses `execvp`,
  a variable containing spaces can alter the argv split.
- Grep: `"command"\s*:\s*"[^"]*\$[A-Z_][A-Z0-9_]*`
- File globs: `.mcp.json`, `**/.mcp.json`, `.claude/settings.json`,
  `.claude/settings.local.json`.
- Source: https://cwe.mitre.org/data/definitions/78.html

### MCP server `env` block with hardcoded API key — CWE-798

- Why: The `env` block of a stdio MCP server entry injects
  key-value pairs into the child process's environment. Placing a
  real API key (Anthropic, OpenAI, GitHub, AWS) as a literal value
  in this block and committing it to version control exposes the
  credential to every repository consumer. MCP server credentials
  are particularly sensitive because the server may forward them to
  external services on behalf of every tool call Claude makes.
- Grep: `"env"\s*:\s*\{[^}]*(sk-ant-|sk-proj-|ghp_|gho_|AKIA)[^}]*\}`
  Or more broadly: `(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN)\s*:\s*"[^$][^"]{8,}"`
- File globs: `.mcp.json`, `**/.mcp.json`, `.claude/settings.json`,
  `.claude/settings.local.json`.
- Source: https://cwe.mitre.org/data/definitions/798.html

### MCP server trusting `${input:...}` user prompts as command arguments — CWE-77

- Why: Claude Code supports variable substitution in MCP configs
  using `${input:variable}` syntax, which prompts the user for a
  value at session start. If that user-supplied value is passed
  directly as a command argument (e.g., the server binary path or
  a flag value), a user who controls their own `.mcp.json` can
  supply shell metacharacters or path traversal sequences. In
  multi-user or shared-config scenarios (e.g., a `.mcp.json`
  committed to a monorepo), a developer could override the config
  with a malicious input value to redirect the server invocation.
- Grep: `"\$\{input:[^}]+\}"` appearing inside `command` or `args`
  values.
- File globs: `.mcp.json`, `**/.mcp.json`, `.claude/settings.json`,
  `.claude/settings.local.json`.
- Source: https://docs.claude.com/en/docs/claude-code/mcp

### Local stdio MCP server with unrestricted filesystem access — CWE-732

- Why: A stdio MCP server that exposes a filesystem-browsing or
  file-reading tool (e.g., `@modelcontextprotocol/server-filesystem`)
  runs with the same filesystem permissions as the Claude Code
  process — typically the developer's full home directory. Without
  explicit root-restriction arguments, the server can traverse to
  `~/.ssh/`, `~/.aws/credentials`, `~/.gnupg/`, and any other
  sensitive path the model (or an injected instruction) requests.
  The safe form passes an explicit allowed-path list as arguments
  to the server binary.
- Grep: `"@modelcontextprotocol/server-filesystem"` (or any known
  filesystem MCP package) in `args` without a following path
  restriction argument. Practical: `server-filesystem"` without
  an args entry starting with `/` (the allowed root).
- File globs: `.mcp.json`, `**/.mcp.json`, `.claude/settings.json`,
  `.claude/settings.local.json`.
- Source: https://modelcontextprotocol.io/

## Fix recipes

### Recipe: switch HTTP MCP URL to HTTPS — addresses CWE-319

**Before (dangerous):**

```json
{
  "mcpServers": {
    "my-server": {
      "type": "http",
      "url": "http://mcp.internal.example.com:8080/mcp"
    }
  }
}
```

**After (safe):**

```json
{
  "mcpServers": {
    "my-server": {
      "type": "http",
      "url": "https://mcp.internal.example.com:8443/mcp"
    }
  }
}
```

Source: https://modelcontextprotocol.io/docs/concepts/transports

### Recipe: pin npx package version — addresses CWE-1395

**Before (dangerous):**

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

**After (safe):**

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "--package", "@modelcontextprotocol/server-github@0.6.2",
        "--yes",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

Source: https://cwe.mitre.org/data/definitions/1395.html

### Recipe: move API key out of env block — addresses CWE-798

**Before (dangerous):**

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["--yes", "@modelcontextprotocol/server-github@0.6.2"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_XXXXXXXXXXXXXXXXXXXX"
      }
    }
  }
}
```

**After (safe):**

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["--yes", "@modelcontextprotocol/server-github@0.6.2"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"
      }
    }
  }
}
```

Set `GITHUB_PERSONAL_ACCESS_TOKEN` in the shell environment or a
`.env` file that is listed in `.gitignore`.

Source: https://cwe.mitre.org/data/definitions/798.html

### Recipe: restrict filesystem MCP server to a named root — addresses CWE-732

**Before (dangerous):**

```json
{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["--yes", "@modelcontextprotocol/server-filesystem@0.6.2"]
    }
  }
}
```

**After (safe):**

```json
{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": [
        "--yes",
        "@modelcontextprotocol/server-filesystem@0.6.2",
        "/home/user/projects/myproject"
      ]
    }
  }
}
```

Source: https://modelcontextprotocol.io/

## Version notes

- `.mcp.json` as a project-scoped config file was introduced in
  Claude Code 1.x; earlier versions used only the `mcpServers` key
  inside `settings.json`. Both shapes must be checked.
- The `${input:...}` variable substitution syntax for MCP configs
  is documented in the Claude Code 1.x MCP guide; flag this pattern
  in `command` and `args` positions only, not in `env` values where
  it is the recommended pattern for credential injection.
- `npx --package pkg@version --yes pkg` is the safe invocation form
  introduced after supply-chain incidents in the npm ecosystem; older
  docs showed `npx -y pkg` without version pinning.

## Common false positives

- `http://localhost:...` or `http://127.0.0.1:...` MCP URLs — a
  local-only server has no TLS exposure; do not flag CWE-319 for
  loopback-only URLs. Annotate if the port is world-accessible.
- `${input:variable}` in the `env` block (not in `command`/`args`)
  — this is the recommended pattern for credential injection; safe.
- `npx --yes` with a version-pinned package (contains `@x.y.z` in
  the package specifier) — not a supply-chain risk; do not flag.
- MCP server entries that reference a local path binary
  (`"command": "/usr/local/bin/my-mcp-server"`) — no package
  resolution risk; review only for env-var interpolation.
