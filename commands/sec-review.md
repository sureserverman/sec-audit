---
description: Run a full cybersecurity review of a project (code + deps + CVE feeds) and write a prioritized markdown report.
allowed-tools: Read, Grep, Glob, Bash, WebFetch, Agent
---

Run the `sec-review` skill against the target path the user provided.

**Target path:** `$ARGUMENTS`

If `$ARGUMENTS` is empty, ask the user for the absolute path of the project
to review before continuing.

Invoke the `sec-review` skill (see `skills/sec-review/SKILL.md`) with that
target path. The skill is responsible for:

1. Scoping (confirming what's in / out of scope).
2. Inventorying the tech stack.
3. Dispatching the `sec-expert` subagent (`agents/sec-expert.md`).
4. Enriching findings with live CVE data from NVD 2.0, OSV.dev, and GHSA.
5. Prioritizing by the deterministic CVSS + exposure + exploit + auth
   rubric defined in the skill.
6. Writing the report to `<target>/sec-review-report-YYYYMMDD-HHMM.md`.

After the skill completes, print the report's absolute path and a one-line
summary of how many findings were produced per severity bucket.
