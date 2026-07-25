# Per-agent Bash-surface inventory (Task 1.2)

For each of the 30 Bash-granting files (29 `agents/*.md` + `commands/sec-audit.md`;
`finding-triager` grants no Bash → excluded), the commands the **agent body itself**
invokes (engine-internal `runner.py` subprocess calls are NOT Claude Bash and don't
count) and the proposed scoped `Bash(...)` set. Derived by scanning ```bash fences and
splitting on shell operators; see `scoped-bash-semantics.md` for the matching rules.

## Class A — engine-backed runners (body runs only `python3 …/runner.py`)

19 files. `command -v <tool>` probes live inside `runner.py` (Python subprocess), not
agent-body Bash. Proposed scope: **`Read, Bash(python3:*)`**.

android, ansible, c-cpp, dast, gh-actions, go, iac, image, k8s, php, python, rust,
sast, secrets, shell, supply-chain, virt, webapp, webext

## Class B — pipeline / orchestrator (scopeable, no `-exec`)

| File | Body commands (agent-run) | Proposed `tools:` |
|---|---|---|
| `cve-enricher` | `python3` (cve_enricher.py) | `Read, WebFetch, Bash(python3:*)` |
| `report-writer` | `date` | `Read, Write, Bash(date:*)` |
| `sec-expert` | none but a documented `Bash(rg)` regex fallback | `Read, Grep, Glob, WebFetch, Bash(rg:*)` |
| `dep-diff-analyst` | `curl`, `jq`, `tar`, `unzip`, `diff`, `head`, `mkdir` | `Read, WebFetch, Bash(curl:*), Bash(jq:*), Bash(tar:*), Bash(unzip:*), Bash(diff:*), Bash(head:*), Bash(mkdir:*)` |
| `commands/sec-audit.md` | `python3` (inventory/diffscope/score/sarif) | `Read, Grep, Glob, WebFetch, Agent, Bash(python3:*)` |

## Class C — host-OS-gated direct-invocation (scopeable, no `-exec`)

`find` here uses `-name` filters piped to `head`/loops — no `-exec`, so `Bash(find:*)`
is safe.

| File | Body commands | Proposed `Bash(...)` set (+ `Read`) |
|---|---|---|
| `ios-runner` | codesign, spctl, mobsfscan, xcrun, find, head, command -v, basename, uname, echo | `Bash(codesign:*), Bash(spctl:*), Bash(mobsfscan:*), Bash(xcrun:*), Bash(find:*), Bash(head:*), Bash(command -v:*), Bash(basename:*), Bash(uname:*), Bash(echo:*)` |
| `macos-runner` | codesign, spctl, pkgutil, mobsfscan, xcrun, find, command -v, basename, uname, echo | `Bash(codesign:*), Bash(spctl:*), Bash(pkgutil:*), Bash(mobsfscan:*), Bash(xcrun:*), Bash(find:*), Bash(command -v:*), Bash(basename:*), Bash(uname:*), Bash(echo:*)` |
| `windows-runner` | binskim, osslsigncode, sigcheck.exe, jq, find, tr, wc, command -v, basename, uname, echo | `Bash(binskim:*), Bash(osslsigncode:*), Bash(sigcheck.exe:*), Bash(jq:*), Bash(find:*), Bash(tr:*), Bash(wc:*), Bash(command -v:*), Bash(basename:*), Bash(uname:*), Bash(echo:*)` |
| `ai-tools-runner` | jq, mcp-scan, find, sed, printf, command -v, basename | `Bash(jq:*), Bash(mcp-scan:*), Bash(find:*), Bash(sed:*), Bash(printf:*), Bash(command -v:*), Bash(basename:*)` |

## Class D — BLOCKED: agent-body `find -exec` (cannot be expressed as a scoped allowlist)

Per `scoped-bash-semantics.md`, `find … -exec <cmd>` always prompts → **fails in a
headless subagent** under any scope. These two are the only real `find -exec` uses
(the ios/macos/dep-diff `-exec` grep-hits were the word "exec" in prose/entitlement
keys).

| File | Blocking line | Other body commands |
|---|---|---|
| `linux-runner` | `find "$target_path" … -exec file {} + \| grep -l 'ELF'` (line 111-112) | systemd-analyze, lintian, checksec, systemctl, find, grep, command -v, echo, cd |
| `netcfg-runner` | `find "$target_path" -name '*.json' -exec grep -l '"inbounds"' {} +` (lines 89-90, 103-104) | sing-box, xray, find, grep, awk, printf, sort, dirname, command -v |

**Decision (2026-07-09): Option A chosen** — rewrite `find … -exec <cmd> {} +` to
`find … -print0 | xargs -0 <cmd>` (bare `xargs` auto-stripped → inner cmd matched).
Closes all 30 findings. `linux` verifiable on this host; `netcfg` rewrite ships
verified-by-inspection, live verification deferred to a sing-box/xray host (recorded
in the Stage 3 handoff + mac-handoff-style runbook note). Resolved scopes:

| File | Final `tools:` (after xargs rewrite) |
|---|---|
| `linux-runner` | `Read, Bash(systemd-analyze:*), Bash(lintian:*), Bash(checksec:*), Bash(systemctl:*), Bash(find:*), Bash(file:*), Bash(grep:*), Bash(command -v:*), Bash(echo:*), Bash(cd:*), Bash(true:*)` |
| `netcfg-runner` | `Read, Bash(sing-box:*), Bash(xray:*), Bash(find:*), Bash(grep:*), Bash(awk:*), Bash(printf:*), Bash(sort:*), Bash(dirname:*), Bash(command -v:*)` |

## Coverage check
All 30 Bash-granting files accounted for: 19 (Class A) + 5 (Class B) + 4 (Class C) +
2 (Class D) = 30. ✓

---

## Matcher behavior (LIVE-VERIFIED 2026-07-25)

The three questions that forced the 2026-07-09 revert (commit `7718c0a`) are
answered here by observation, not inference. Harness:
`docs/plans-notes/matcher-probe.sh`; raw transcripts:
`docs/plans-notes/matcher-probe-transcripts.txt`.

**Environment:** Claude Code **2.1.220**, Linux 7.0.0-28-generic, headless
`claude -p` with `--permission-mode default` and a harness-owned settings file
pinning `permissions.defaultMode: "default"`, `allow: []`, `deny: []`.

**Every run is bracketed by two controls** — a command inside the allowlist
(must be ALLOWED) and one outside it (must be DENIED). Verdicts are read from a
marker file on disk, never from the model's prose. The run below is the first in
which both controls behaved; two earlier runs were discarded, and *why* they were
discarded matters as much as the results:

| Discarded run | What it reported | Actual cause |
|---|---|---|
| #1 | everything ALLOWED | `~/.claude/settings.json` sets `permissions.defaultMode: "auto"` — a safety classifier, not the allowlist, decided each command. A `touch` ran under an allowlist of only `Bash(echo:*)`. |
| #2 | everything DENIED | (a) the sandbox restricts writes to the project dir, so `/tmp` markers were blocked by the **sandbox**, indistinguishable from a matcher denial; (b) the prompt demanded an unexplained `touch` of a file named `*_deny`, which the model correctly refused as an unverifiable sentinel — a **refusal**, not a denial. |

Both would have been recorded as enforcement facts. That is exactly the failure
mode BL-002's "needs-live-verification" tag exists to prevent.

### Results

| Q | Construct | Allowlist | Verdict |
|---|---|---|---|
| 1 | `[ -f X ] && touch M` | `Bash(touch:*)` | **ALLOWED** |
| 2 | `diff <(cat X) X && touch M` | `Bash(diff:*),Bash(touch:*)` | **DENIED** |
| 2b | same, with `cat` granted | `+ Bash(cat:*)` | **DENIED** |
| 3 | `cmd=touch; "$cmd" M` | `Bash(touch:*)` | **ALLOWED** |
| 3b | same, resolved cmd NOT granted | `Bash(echo:*)` | **DENIED** |
| 3c | literal `touch M` (control) | `Bash(touch:*)` | **ALLOWED** |

### What this means for the six runners

1. **`[ … ] && …` precondition gates need no grant.** `[` is not separately
   matched — Q1 passed with only `Bash(touch:*)` allowed. **No `Bash([:*)` is
   required anywhere.** (Original assumption: possibly needed. Disproven.)

2. **Process substitution is rejected outright, and no grant fixes it.** The Bash
   tool refuses the call before execution with a literal
   `Error: Contains process_substitution` — *even when the inner command is
   explicitly allowed* (Q2b). This is stronger than the question assumed: the
   macOS runner's `< <(cat …)` is not a scoping problem needing `Bash(cat:*)`, it
   **cannot run under the Bash tool at all**. It must be rewritten to a pipe or a
   temp file. Note this is independent of scoping — the construct is already
   broken today under the *unscoped* `Bash` grant.

3. **Variable command names resolve and match correctly — they do not bypass.**
   `cmd=touch; "$cmd" …` was ALLOWED under `Bash(touch:*)` and DENIED under
   `Bash(echo:*)`, same command, same target directory: the only variable was the
   allowlist. The matcher resolves the indirection (one transcript states it
   matched "variable-indirected command name" explicitly). So ai-tools-runner's
   `"$mcp_scan_bin"` **can** be scoped; the blocker recorded in BL-002 — "no
   `Bash(...)` rule matches a variable command name" — is **disproven**.

### Residual uncertainty (do not overstate these results)

- Probes drove `claude -p --allowedTools`. The runners are dispatched as
  **sub-agents whose grants come from `tools:` frontmatter**. Both are believed to
  feed the same permission engine, but that equivalence was **not** separately
  proven here.
- Verified on Linux only. The macOS-specific runners (`ios`, `macos`) were not
  dispatched against real signing tools; finding 2 above applies to them by
  construction (it is a Bash-tool rule, not a platform one), but their remaining
  command surface is still verified-by-inspection.

## Stage 3 outcome (2026-07-25): scoping BLOCKED, and not by grants

Stage 3 reapplied the drafted scopes (`git revert` of the revert), then probed
each lane's own commands against its own allowlist under strict enforcement.
**The scopes were reverted again.** What stops them is structural:

| Construct | Verdict under a scoped allowlist | Rejection message |
|---|---|---|
| `while … done` (any form) | **REFUSED** | `Contains while_statement` |
| `for x in $(cat f)` | **REFUSED** | `Contains simple_expansion` |
| `while IFS= read …` | **REFUSED** | `IFS assignment changes word-splitting — cannot model statically` |
| `<(…)` process substitution | **REFUSED** | `Contains process_substitution` |
| `find … -exec c {} +` | **REFUSED** | `find with '-exec' executes commands … cannot be auto-allowed by a Bash(find:*) prefix rule` |
| `find … -print0 \| xargs -0 grep` | **ALLOWED** | — (validates the 886a60a rewrite) |
| `command -v tool && …` | **ALLOWED** under each lane's real scope | — |
| `xargs -I{} cmd` | **ALLOWED** | — |

**The blocker is not a missing grant.** Under a per-tool allowlist the matcher
must statically model the command; anything it cannot model is refused *no matter
what is granted*. Adding `Bash(cat:*)` does not help a `while` loop.

**Why these six and not the other 24.** The already-scoped runners
(`sast`, `python`, `rust`, `go`, `shell`, …) contain **zero** `while`/`for` loops
and **zero** command substitutions — plain one-command-per-line bodies, which is
exactly why they scoped cleanly. The six host-OS runners are the loop-heavy ones:

| Runner | `while` | `for` | `$( … )` |
|---|---:|---:|---:|
| macos | 4 | 0 | 6 |
| windows | 3 | 0 | 7 |
| ai-tools | 3 | 2 | 8 |
| linux | 2 | 0 | 5 |
| netcfg | 0 | 2 | 5 |
| ios | 0 | 0 | 4 |

**What scoping these actually costs.** Each runner body must be rewritten so every
Bash call is a single statically-modellable command: per-artifact loops become
`xargs -I{}` (verified ALLOWED), `$(…)`-captured values must be replaced by files
or by the orchestrator passing values in, and macos' stapler/codesign/spctl/pkgutil
per-artifact loops each need redesign while preserving per-artifact stderr
attribution (the parser at Step 6 depends on it). That is a runner-body redesign,
not a frontmatter edit — and it must be done per lane with the lane's tools
present to re-verify behaviour.

**Note the constructs already fail today under a scoped grant — but the runners
ship UNSCOPED, and under the permissive/`auto` modes users actually run, loops and
process substitution execute normally.** So this is not a live outage; it is the
reason the lanes cannot simply be scoped.
