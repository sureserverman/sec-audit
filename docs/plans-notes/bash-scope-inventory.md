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
