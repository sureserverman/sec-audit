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
| `ai-tools-runner` | ~~jq, mcp-scan, find, sed, printf, command -v, basename~~ **SUPERSEDED 2026-08-27** — migrated to the engine; now `python3` only | `Bash(python3:*)` |

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

## Second probe round (2026-08-27): the blocker is `>`, and the remedy on file is wrong

Pilot scoping of **one** lane (`ios` — the cheapest of the six: zero loops) to
test whether the six could be taken one at a time. It cannot be, but not for the
reason recorded above. Harness: `docs/plans-notes/ios-scope-probe.sh`; raw
transcripts: `docs/plans-notes/ios-scope-probe-transcripts.txt`.

**Environment:** Claude Code **2.1.247**, Linux 7.0.0-28-generic, same
harness-owned strict settings and marker-file method as the 2026-07-25 run.
Controls behaved on every round reported here.

**Two verdicts from the first round were discarded, and why matters:**

| Discarded verdict | What it reported | Actual cause |
|---|---|---|
| `$(basename …)` in a redirect target | DENIED | `Error: Reached max turns (3)` — the probe never got a verdict. No marker, so it read as a denial. The harness now reports INCONCLUSIVE on max-turns. |
| `find … \| head > f` | DENIED "for security, Claude Code may only write to files in the allowed working directories" | The path *was* inside the allowed root. The message is misleading; re-probing under a bare `Bash` grant showed it ALLOWED, so it is a scoped-allowlist refusal, not a sandbox one. |

### Results

| # | Construct | Allowlist | Verdict |
|---|---|---|---|
| A1 | `[ -f X ] && touch M` | `Bash(touch:*)` | **ALLOWED** (replicates 2026-07-25 Q1 on 2.1.247) |
| A2 | `[ "$VAR" != "" ] && touch M` | `Bash(touch:*)` | **DENIED** |
| A3 | same as A2 | `+ Bash([:*)` | **ALLOWED** |
| B1 | `echo hi > f && touch M` | `Bash(echo:*),Bash(touch:*)` | **DENIED** |
| B2 | same as B1 | `Bash` (bare) | **ALLOWED** |
| B3 | `echo ok > "f-$(basename P).txt"` | `Bash(echo:*),Bash(basename:*),Bash(touch:*)` | **DENIED** |
| B4 | same as B3 | `Bash` (bare) | **ALLOWED** |
| C1 | `find … \| head -n 10 && touch M` | `Bash(find:*),Bash(head:*),Bash(touch:*)` | **ALLOWED** |
| C2 | same as C1 **plus `> f`** | same | **DENIED** |
| D1 | `host_os=$(uname -s … \|\| echo Unknown) && touch M` | `Bash(uname:*),Bash(echo:*),Bash(touch:*)` | **ALLOWED** |

### What this corrects and what it adds

1. **Conclusion 1 above is wrong for the form the runners actually use.**
   "`[ … ] && …` needs no grant … no `Bash([:*)` is required anywhere" holds only
   for a test with no variable expansion (A1). Every real gate is
   `[ "$host_os" = "Darwin" ] && …`, which is **DENIED** (A2) and fixed by
   granting `Bash([:*)` (A3). That is a frontmatter addition, not a rewrite —
   and it is missing from all six drafted scopes in `886a60a`.

2. **Output redirection is the blocker, and it is unconditional.** A bare
   `echo hi > f` is refused under a scoped allowlist with `echo` itself granted
   (B1) and allowed under bare `Bash` (B2). The pipe is innocent: the same
   pipeline passes without a redirect (C1) and fails with one (C2).
   `$(…)` inside a redirect target is a refused sub-case with its own message
   (`Redirect target contains $(cmd) output — path is runtime-determined`, B3).
   Command substitution *on its own* is fine (D1).

3. **This — not loops — is why 24 scoped cleanly and 6 did not.** Of the 25
   runners, the 19 scoped ones all carry `Bash(python3:*)` and their entire bash
   surface is one line:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/secaudit/runner.py" <lane> <target>`.
   **Zero** of them contain a `>` redirect — the engine does the file writing.
   The six exempt runners are exactly the six that still shell out directly and
   redirect each tool's stdout/stderr to `$TMPDIR/…`.

4. **BL-002's recorded remedy is therefore the wrong one.** "Per-artifact loops
   become `xargs -I{}`, `$(…)` captures become files" cannot work: *writing those
   files is itself the unscopeable act*. Rewriting the loops would leave every
   lane still refused at its first `>`.

5. **The right remedy is the migration this repo already performs 19 times:**
   give each of the six a `scripts/secaudit/lanes/<lane>` definition and reduce
   its agent body to the one-line engine invocation. `ai-tools` is **already
   half-migrated** — `scripts/secaudit/lanes/ai-tools` exists (commit `b91a43c`)
   but `agents/ai-tools-runner.md` still shells out directly (7 loops, 3
   redirects) and still carries a bare `Bash` grant. Lanes missing entirely:
   `ios`, `macos`, `windows`, `linux`, `netcfg`.

### Residual uncertainty (do not overstate these results)

- Probes drove `claude -p --allowedTools`; the runners are dispatched as
  sub-agents granted through `tools:` frontmatter. Same caveat as the 2026-07-25
  run — the two are believed to share a permission engine, still not proven here.
- Verified on Linux, one Claude Code version (2.1.247). A1 replicating the
  2026-07-25 Q1 result is evidence the matcher did not drift between 2.1.220 and
  2.1.247, but only for that one construct.
- No lane was scoped or dispatched as part of this round. The migration in
  finding 5 is a *proposal* sized from the existing pattern, not a measured one.

### Outcome: ai-tools migrated (2026-08-27)

`ai-tools` was taken through the finding-5 migration as the pilot, and left the
exemption list. What it took:

- **`scripts/secaudit/mcpscan.py`** (new, bundled) — the one thing that had kept
  this lane agent-driven. It does the skill-directory discovery the lane schema
  cannot express, normalises mcp-scan's path-keyed output, and closes stdin so
  the server-launch consent prompt is always declined.
- **`scripts/secaudit/runner.py`** — two small general additions: `probe` may be
  a LIST of interchangeable binary names (mcp-scan also ships as
  snyk-agent-scan) with the resolved name available as `{probe}`; and
  `fail_on_rc` lets a bundled wrapper degrade its lane to `partial` instead of
  reporting a clean `ok` over a target it did not finish reading.
- **`agents/ai-tools-runner.md`** — 415 lines to 207, all shell replaced by the
  one-line engine call, grant `Bash` → `Bash(python3:*)`.
- **`tests/ai-tools-drill.sh`** — the mcp-scan safety assertions follow the
  invocation into the wrapper (inspect-only, no `scan`, no
  `--dangerously-run-mcp-servers`, stdin closed); the prose prohibitions stay
  asserted on the agent markdown.
- **`tests/contract-check.sh`** — exempt list 6 → 5.

**Verified under real enforcement, not by inspection.** Paired probe of the
agent's exact command: ALLOWED under `Bash(python3:*)`, emitting
`{"__ai_tools_status__": "ok", "tools": ["agentscan", "jq", "mcp-scan"], ...}`;
DENIED (`requires approval`) under a deliberately wrong `Bash(echo:*)`. Full
suite `ci-local.sh` 75/75.

**Two pre-existing bugs surfaced while porting, both now fixed in the wrapper:**

1. The old runner invoked `"$mcp_scan_bin" --skills "$dir"`. `--skills` is a
   BOOLEAN toggle on this CLI, not a path-taking option — that call exits
   non-zero and scans nothing. Skills were never actually scanned by mcp-scan.
   The correct form is `inspect <dir>` positionally.
2. `inspect` reports **without security verification** — its `issues` array is
   empty by construction, confirmed against the deliberately poisoned fixture.
   Verification is `mcp-scan scan`, which launches MCP servers and posts to a
   remote analysis endpoint, both forbidden by this lane. So mcp-scan can only
   ever contribute coverage here, never findings; `agentscan` is what actually
   finds poisoned agents and skills. **This is a product decision left open, not
   something the migration settled** — see BL-002.

### Outcome: netcfg migrated (2026-08-27)

Second lane through the finding-5 migration; exemption list 5 → 4. Cheaper than
ai-tools — both tools are pass/fail self-validators, which is exactly the
engine's existing `validator` mode (as used by jq and virt-xml-validate), so
`scripts/secaudit/lanes/netcfg.json` needed no bundled wrapper at all.

Shape detection is a two-clause lookahead rather than a filename glob, because
both tools eat `*.json`: a file qualifies only if it carries an `inbounds` array
AND that dialect's protocol vocabulary. Without that, `-confdir`-style
invocation hands a sing-box config to xray and reports the dialect mismatch as
an xray error.

**Three engine additions, all general:**

- ANSI SGR stripping on validator output — sing-box colourises its diagnostics
  and the raw escapes were landing in finding titles.
- `message_regex` narrows a chatty validator's output to the actual diagnostic.
  xray prints a version banner and a run of `[Info]` lines before its error;
  without this the finding's title was the banner. No match leaves the message
  untouched, so a changed output format degrades to noisy, never to empty.
- (A `parent-dirs` validator selector was added and then reverted — see below.)

**A third pre-existing bug, same class as the other two.** The runner documented
`xray test -confdir <dir>`. **There is no `xray test` subcommand** — it exits
`unknown command`, and the faithful port dutifully turned the tool's own usage
error into a finding claiming the caller's config was malformed. Worse,
`tests/netcfg-drill.sh` asserted `grep -q "xray test"`, so the test suite was
actively holding the bug in place. The validation form is `xray run -test -c
<file>`: it loads and checks the config and exits without launching the server,
0 with `Configuration OK.` when valid and 23 with a `Failed to start:`
diagnostic when not. Per-FILE, not per-directory — which is why the
`parent-dirs` selector written for `-confdir` was reverted rather than kept.

That invocation required amending Hard rule 5, which read "NEVER use `sing-box
run` or `xray run`". The rule's intent is *never start a listener*; `run -test`
satisfies it. The rule now states the intent precisely — `-test` is mandatory
whenever `xray run` appears — and the drill asserts the lane's argv directly,
including that no tool invokes `run` without `-test`.

**Verified under real enforcement:** ALLOWED under `Bash(python3:*)` emitting
`{"__netcfg_status__": "ok", "tools": ["sing-box", "xray"], "runs": 2,
"findings": 2}`; DENIED under a wrong `Bash(echo:*)`. `ci-local.sh` 75/75.

**Running total: 2 of 6 migrated. Three lanes ported, three latent invocation
bugs found** — each one a documented command that silently did nothing or
reported the tool's own error as the caller's fault. Whatever else BL-002 is
worth, porting a lane to the engine is proving to be the thing that finds them.
