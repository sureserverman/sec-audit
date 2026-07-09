# Scoped-Bash semantics (Task 1.1 ground truth)

Source of truth for the CWE-693 scoped-Bash fix (plan
`2026-07-09-scoped-bash-allowlists-plan.md`). Established 2026-07-09.

## Method note

The plan's Task 1.1 called for a **live probe agent** dispatched in-session to
observe a hard deny. This was not feasible: subagent types resolve from a
registry built at session start, and this repo has no local `.claude/agents/`
registry, so a freshly-written probe agent is not dispatchable via the Agent
tool mid-session. Substituted evidence (recorded here honestly, not a live probe
result):

1. **A real installed agent proves the syntax loads and runs.** The shipped
   `i18n:translator` agent
   (`~/.claude/plugins/marketplaces/coder-plugins/i18n/agents/translator.md`)
   declares:
   `tools: Read, Grep, Glob, Edit, Write, Bash(python3:*), Bash(git status:*), Bash(git diff:*), WebFetch`
   — confirming `Bash(cmd:*)` scoping AND multi-word prefixes like
   `Bash(git status:*)` are accepted in a working agent's `tools:` frontmatter.
2. **Official docs** (code.claude.com/docs/en/settings §permissions example;
   permissions.md §"Compound commands") + the `claude-code-guide` agent's
   documented answers supplied the matching semantics below.

## Established semantics

### Syntax
- `Bash(python3:*)` / `Bash(python3 *)` — the `:*` is equivalent to trailing
  ` *` and is only special at the **end** of the pattern. Matches any command
  whose first token is `python3`.
- **Multi-word prefixes scope to a subcommand**: `Bash(git status:*)` matches
  `git status --porcelain` but NOT `git commit`. The space/`:` before `*`
  enforces a word boundary, so `Bash(ls:*)` matches `ls -la` but not `lsof`.

### Compound commands — the operative constraint
The matcher is shell-operator-aware. **A rule must match each sub-command
independently.** Recognized separators: `&&  ||  ;  |  |&  &` and newlines.

| Construct | Consequence for scoping |
|---|---|
| `a \| b` (pipe) | BOTH `a` and `b` must be scoped. `codesign … \| head` needs `Bash(codesign:*)` AND `Bash(head:*)`. |
| `a && b`, `a; b` | each side scoped independently |
| `find … -exec tool {} \;` | **`find -exec` is NOT auto-stripped and always prompts → FAILS in a headless subagent.** A `Bash(find:*)` rule does not cover the exec'd command. Avoid `-exec` in agent-body Bash, or the lane must keep unscoped Bash (documented exception). |
| `$(subcmd)` | the substituted command is evaluated independently |
| wrappers `timeout/time/nice/nohup/stdbuf/xargs` (bare) | auto-stripped BEFORE matching → `Bash(grep:*)` covers `timeout 30 grep …` |
| wrappers `watch/setsid/ionice/flock` | NOT stripped → always prompt |

### Env vars & quoted paths — no effect on matching
Matching is literal on the raw command string, before expansion. All of these
match `Bash(python3:*)`:
- `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/secaudit/runner.py" shell /t`
- `TMPDIR=/x python3 foo.py`
- `python3 /abs/path/script.py`

→ **Every engine-backed runner (body = `python3 "${CLAUDE_PLUGIN_ROOT}/…/runner.py"`)
is fully covered by `Bash(python3:*)` alone.**

### Enforcement in subagent `tools:`
- The `tools:` list is a **hard allowlist** — unlisted tools are removed from the
  subagent's context; it never sees or attempts them.
- A **scoped** Bash entry (`Bash(python3:*)`) admits only matching commands; an
  out-of-scope Bash command in a headless subagent is **denied outright, no
  interactive prompt** (a prompt with no callback == denial). So an
  under-scoped allowlist doesn't degrade gracefully — the lane's tool call
  fails. Scope sets must therefore be a **superset of every binary the agent
  BODY invokes**, including pipe targets and loop bodies.

## Design rules for the rewrite
1. **Engine-backed lane** (body only runs `runner.py`): `Read, Bash(python3:*)`.
   Add `Bash(command -v:*)` only if the agent body itself runs a probe (most
   don't — the probe is inside `runner.py`, i.e. python subprocess, NOT a Claude
   Bash call and NOT subject to these rules).
2. **Direct-invocation lane** (agent body runs real binaries): scope EVERY
   binary the body invokes, plus every pipe target. Audit for `find -exec` — if
   present in agent-body Bash, it cannot be scoped (headless prompt = fail);
   resolve by refactor or document the lane as a justified unscoped-Bash
   exception.
3. Distinguish agent-BODY Bash (subject to these rules) from engine-INTERNAL
   subprocess calls in `runner.py` (Python subprocess, not gated by Claude Code
   permissions). Only the former drives the scope set.
