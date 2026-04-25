---
description: Run a full cybersecurity review of a project (code + deps + CVE feeds) and write a prioritized markdown report.
allowed-tools: Read, Grep, Glob, Bash, WebFetch, Agent
---

Run the `sec-review` skill against the target path the user provided.

**Raw arguments:** `$ARGUMENTS`

## Argument parsing (v1.0.0+)

Parse `$ARGUMENTS` into:

1. **Target path** (required, positional) — the first non-flag token.
   Must be an absolute or tilde-expanded path to a readable directory.
2. **`--only=<lanes>`** (optional) — comma-separated lane names to
   restrict dispatch to.
3. **`--skip=<lanes>`** (optional) — comma-separated lane names to
   exclude from dispatch.

**Canonical lane names (13 total):** `sec-expert`, `sast`, `dast`,
`webext`, `rust`, `android`, `ios`, `linux`, `macos`, `windows`,
`k8s`, `iac`, `gh-actions`. Reject any invocation that names a
lane outside this list.

**Mutual exclusion:** `--only` and `--skip` MUST NOT both be set. The
two flags are mutually exclusive. If the caller passed both, refuse
with this user-visible error BEFORE invoking the skill:

> Error: `--only=` and `--skip=` are mutually exclusive. Use one or
> the other, not both.

Example valid invocations:

```
/sec-review /path/to/repo
/sec-review /path/to/repo --only=webext,rust
/sec-review /path/to/repo --skip=dast,windows
/sec-review ~/projects/myapp --only=sec-expert,sast,rust
```

If `$ARGUMENTS` is empty, ask the user for the absolute path of the
project to review before continuing.

## Dispatch

Invoke the `sec-review` skill (see `skills/sec-review/SKILL.md`) with:

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
   `<target>/sec-review-report-YYYYMMDD-HHMM.md`.

After the skill completes, print the report's absolute path and a
one-line summary of how many findings were produced per severity
bucket, plus which lanes dispatched and which were filtered out.
