---
description: Run a full cybersecurity review of a project (code + deps + CVE feeds) and write a prioritized markdown report.
allowed-tools: Read, Grep, Glob, Bash, WebFetch, Agent
---

Run the `sec-audit` skill against the target path the user provided.

**Raw arguments:** `$ARGUMENTS`

## Argument parsing (v1.0.0+)

Parse `$ARGUMENTS` into:

1. **Target path** (required, positional) — the first non-flag token.
   Must be an absolute or tilde-expanded path to a readable directory.
2. **`--only=<lanes>`** (optional) — comma-separated lane names to
   restrict dispatch to.
3. **`--skip=<lanes>`** (optional) — comma-separated lane names to
   exclude from dispatch.

**Canonical lane names (21 total):** `sec-expert`, `sast`, `dast`,
`webext`, `rust`, `android`, `ios`, `linux`, `macos`, `windows`,
`k8s`, `iac`, `gh-actions`, `virt`, `go`, `shell`, `python`,
`ansible`, `netcfg`, `image`, `ai-tools`. Reject any invocation
that names a lane outside this list.

**Mutual exclusion:** `--only` and `--skip` MUST NOT both be set. The
two flags are mutually exclusive. If the caller passed both, refuse
with this user-visible error BEFORE invoking the skill:

> Error: `--only=` and `--skip=` are mutually exclusive. Use one or
> the other, not both.

Example valid invocations:

```
/sec-audit /path/to/repo
/sec-audit /path/to/repo --only=webext,rust
/sec-audit /path/to/repo --skip=dast,windows
/sec-audit ~/projects/myapp --only=sec-expert,sast,rust
```

## Default-target behaviour (v1.10.0+)

If `$ARGUMENTS` is empty (no positional path was supplied), default
`target_path` to the current working directory (`$PWD`). Do NOT
prompt the user for a path — the natural intent of `/sec-audit` with
no argument is "review the project I'm currently in." Only prompt
in these explicit failure cases:

1. `$PWD` resolves to the `sec-audit` plugin's own directory (per
   the §1 Scope guard — refusing self-review). In that case, ask
   the user for the actual target.
2. `$PWD` is not a readable directory (extremely rare — almost
   always indicates the shell environment is broken). Surface the
   error and ask.

Echo the resolved `target_path` back to the user as part of the
§1 Scope confirmation so the resolved default is visible:

> Reviewing `$PWD` (current directory). Pass an explicit path to
> review elsewhere.

Only when the user passes `--only=` / `--skip=` flags AND no
positional path, the same default-to-cwd rule applies — the flags
filter the lane set; the target is still the cwd.

If `$ARGUMENTS` contains flags but no parseable positional token,
treat the positional as missing and apply the default-to-cwd rule.
Do NOT silently treat a flag value as a path.

## Dispatch

Invoke the `sec-audit` skill (see `skills/sec-audit/SKILL.md`) with:

- `target_path` — parsed positional argument
- `only_lanes` — parsed `--only=` list, or omit when absent
- `skip_lanes` — parsed `--skip=` list, or omit when absent
- `target_url`, `github_token`, `nvd_api_key` — read from env vars
  as before (see SKILL.md Inputs)

The skill is responsible for:

1. Scoping (confirming what's in / out of scope).
2. Inventorying the tech stack.
3. Filtering the dispatch list by `only_lanes` / `skip_lanes` per
   §3.0 Dispatch discipline.
4. Dispatching the `sec-expert` sub-agent + the applicable tool-
   lane runners in parallel.
5. Enriching findings with live CVE data from NVD 2.0, OSV.dev, and
   GHSA.
6. Prioritizing by the deterministic CVSS + exposure + exploit +
   auth rubric defined in the skill.
7. Writing the report to
   `<target>/sec-audit-report-YYYYMMDD-HHMM.md`.

After the skill completes, print the report's absolute path and a
one-line summary of how many findings were produced per severity
bucket, plus which lanes dispatched and which were filtered out.
