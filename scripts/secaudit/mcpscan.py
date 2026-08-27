#!/usr/bin/env python3
"""mcp-scan driver for the ai-tools lane.

Why this exists
---------------
Every other tool in every other lane is a JSON entry in `lanes/<lane>.json`:
probe a binary, run it once, map its output. `mcp-scan` does not fit that shape
for two reasons, and until this module existed it was the single tool keeping
`ai-tools-runner` on a bare `Bash` grant (BL-002).

  1. **It must be aimed, not pointed.** mcp-scan discovers skills only when
     given a directory that DIRECTLY contains skill folders. Aimed at a
     repository root it prints "no mcp servers or skills found" and exits 0 —
     a clean bill of health for a tree it never opened. A lane entry invoking
     it once on `{target}` would manufacture exactly that false all-clear, so
     the discovery has to happen first, and `lanes/*.json` has no placeholder
     that can express "every directory that contains skill folders".
  2. **Its output shape is not fixed.** The current binary returns a document
     keyed by inspected path — `{"<path>": {servers, issues, labels, error}}` —
     while older versions returned a flat `issues`, `findings`, or `results`
     array, or a bare array. The lane mapper needs one known path, so this
     module accepts all of them.

Both problems are mechanical, so they belong in code rather than in an agent's
shell. This module does the discovery, invokes the tool once per discovered
target, normalises whatever shape comes back, and emits sec-audit finding JSONL
— which `lanes/ai-tools.json` then consumes as an ordinary `bundled` tool.

Safety contract (asserted by tests/ai-tools-drill.sh)
-----------------------------------------------------
  * `inspect` is the ONLY subcommand ever invoked.
  * `mcp-scan scan` is never invoked — it launches MCP servers locally and
    posts to a remote verification endpoint.
  * `--dangerously-run-mcp-servers` (or any synonym) is never passed. Because
    `inspect` on a config declaring stdio servers PROMPTS for consent to launch
    them, every invocation also gets stdin from /dev/null, so the prompt is
    always declined rather than inheriting a terminal that might accept.
  * Nothing under the target is written, and no network call is made.

Known limitation — read before trusting this tool's silence
------------------------------------------------------------
`inspect` prints descriptions **without security verification**: its `issues`
array is empty by construction, including for a deliberately poisoned skill.
Only `scan` verifies, and `scan` is forbidden here on both counts above. So
this tool contributes coverage (what tools/skills exist) and not findings.
The deterministic checks that DO produce findings for this lane live in
`agentscan.py`, which exists precisely because this gap was found before.

Output: sec-audit finding JSONL on stdout, one object per line, `origin`
"ai-tools" and `tool` "mcp-scan". A summary goes to stderr. Exit 0 unless the
target is unreadable — findings are data, not an error condition.
"""

import argparse
import json
import os
import subprocess
import sys

REF = "ai-tools-tools.md"
REF_URL = "https://github.com/invariantlabs-ai/mcp-scan"

# Same prune list as agentscan.py — vendored, generated, or VCS internals.
PRUNE = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", "target",
    "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache", "vendor",
    ".tox", "htmlcov", ".cache",
}

# MCP server declarations mcp-scan inspects directly.
CONFIG_NAMES = (".mcp.json", "claude_desktop_config.json")

# Accepted binaries, in preference order. The lane probes the same list.
BINARIES = ("mcp-scan", "snyk-agent-scan")

TIMEOUT = 600


def resolve_bin(preferred=None):
    """First usable mcp-scan binary, or None."""
    import shutil
    names = [preferred] if preferred else list(BINARIES)
    for n in names:
        if n and shutil.which(n):
            return n
    return None


def discover(target):
    """(config_files, skill_parent_dirs) under target.

    `skill_parent_dirs` is the set of directories that DIRECTLY contain skill
    folders — i.e. for every `<d>/<skill>/SKILL.md`, the directory `<d>`. That
    is the only shape mcp-scan's `--skills` recognises, and deriving it from
    the tree (rather than hardcoding `<target>/skills`) is what makes layouts
    like `plugins/<plugin>/skills/` visible. The old shell runner hardcoded
    four paths and silently missed every other layout.
    """
    configs, skill_parents = [], set()
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in PRUNE)
        for name in sorted(files):
            full = os.path.join(root, name)
            if name in CONFIG_NAMES:
                configs.append(full)
            elif name == "SKILL.md":
                # root == <d>/<skill>; its parent is the directory to aim at.
                parent = os.path.dirname(root)
                if parent and parent.startswith(target):
                    skill_parents.add(parent)
    return sorted(configs), sorted(skill_parents)


def _norm_severity(raw):
    s = str(raw or "MEDIUM").upper()
    if s in ("CRITICAL", "HIGH"):
        return "HIGH"
    if s in ("MEDIUM", "MODERATE"):
        return "MEDIUM"
    return "LOW"


def _items(doc):
    """Findings from any shape mcp-scan has emitted.

    Current: `{"<inspected path>": {servers, issues, labels, error}}` — one
    entry per path, findings nested under each entry's `issues`.
    Older: a flat `issues` / `findings` / `results` array, or a bare array.
    """
    if isinstance(doc, list):
        return doc
    if not isinstance(doc, dict):
        return []
    for key in ("issues", "findings", "results"):
        val = doc.get(key)
        if isinstance(val, list):
            return val
    out = []
    for val in doc.values():                       # path-keyed shape
        if isinstance(val, dict):
            for key in ("issues", "findings", "results"):
                nested = val.get(key)
                if isinstance(nested, list):
                    out.extend(nested)
    return out


def _client_errors(doc):
    """Per-path `error` strings in the path-keyed shape. A client that errored
    inspected nothing, so its silence must not read as a clean result."""
    if not isinstance(doc, dict):
        return []
    return [str(v["error"]) for v in doc.values()
            if isinstance(v, dict) and v.get("error")]


def _first(item, *keys, default=None):
    for k in keys:
        v = item.get(k)
        if v not in (None, ""):
            return v
    return default


def to_finding(item, source_rel, target):
    """One normalised sec-audit finding, or None if the entry is unusable."""
    if not isinstance(item, dict):
        return None
    file_val = _first(item, "file", "path", "config_file", default=source_rel)
    file_val = str(file_val)
    if os.path.isabs(file_val):
        try:
            file_val = os.path.relpath(file_val, target)
        except ValueError:
            pass
    try:
        line = int(_first(item, "line", "line_number", default=0) or 0)
    except (TypeError, ValueError):
        line = 0
    return {
        "id": str(_first(item, "id", "rule_id", "check_id",
                         default="mcp-scan:unknown")),
        "severity": _norm_severity(item.get("severity")),
        "cwe": str(_first(item, "cwe", "cwe_id", default="CWE-94")),
        "title": str(_first(item, "title", "name", "description",
                            default=""))[:200],
        "file": file_val,
        "line": line,
        "evidence": str(_first(item, "evidence", "description", "message",
                               "title", default=""))[:200],
        "confidence": "medium",
        "reference": REF,
        "reference_url": str(_first(item, "url", "reference", default=REF_URL)),
        "fix_recipe": None,
        "origin": "ai-tools",
        "tool": "mcp-scan",
    }


def run_one(binary, argv_tail, source, target):
    """Invoke the tool once. Returns (findings, ok). ok=False means the run or
    the parse failed — the caller counts that as a parse/run failure and must
    NOT treat it as a clean result."""
    argv = [binary] + argv_tail + ["--json"]
    try:
        # stdin=DEVNULL: `inspect` on a config declaring stdio servers asks for
        # consent to launch them. Declining is the only acceptable answer here,
        # and EOF declines.
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except Exception as e:                                  # noqa: BLE001
        sys.stderr.write(f"mcpscan: {' '.join(argv)} failed: {e}\n")
        return [], False
    if proc.returncode != 0 or not proc.stdout.strip():
        sys.stderr.write(
            f"mcpscan: {' '.join(argv)} rc={proc.returncode} "
            f"(no usable output)\n")
        return [], False
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"mcpscan: unparseable JSON from {source}: {e}\n")
        return [], False
    errors = _client_errors(doc)
    for e in errors:
        sys.stderr.write(f"mcpscan: {source}: inspect reported error: {e}\n")
    rel = os.path.relpath(source, target)
    out = []
    for item in _items(doc):
        f = to_finding(item, rel, target)
        if f is not None:
            out.append(f)
    return out, not errors


def main(argv):
    ap = argparse.ArgumentParser(prog="mcpscan.py")
    ap.add_argument("target")
    ap.add_argument("--bin", default=None,
                    help="resolved mcp-scan binary (lane passes {probe})")
    args = ap.parse_args(argv[1:])

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        sys.stderr.write(f"mcpscan: not a directory: {target}\n")
        return 2

    binary = resolve_bin(args.bin)
    if binary is None:
        # The lane probes for the binary before dispatching, so reaching here
        # means PATH changed underneath us. Emit nothing rather than a clean
        # all-clear, and say so.
        sys.stderr.write("mcpscan: no mcp-scan binary on PATH; emitted nothing\n")
        return 0

    configs, skill_dirs = discover(target)
    if not configs and not skill_dirs:
        sys.stderr.write("mcpscan: no MCP config or skill folder found\n")
        return 0

    findings, failures = [], 0
    for path in configs + skill_dirs:
        # One form for both: `inspect <path>`. `--skills` is a boolean toggle on
        # this CLI, not a path-taking option — the previous shell runner called
        # `--skills <dir>`, which exits non-zero and scans nothing.
        got, ok = run_one(binary, ["inspect", path], path, target)
        findings.extend(got)
        failures += 0 if ok else 1

    for f in findings:
        sys.stdout.write(json.dumps(f, sort_keys=True) + "\n")
    sys.stderr.write(
        f"mcpscan: {binary} over {len(configs)} config(s) + "
        f"{len(skill_dirs)} skill dir(s), {len(findings)} finding(s), "
        f"{failures} failed run(s)\n")
    # Non-zero on any failed run so the lane degrades to `partial` instead of
    # reporting a clean `ok` over a target it did not finish reading. The lane
    # entry opts into this with `fail_on_rc`; findings already emitted above are
    # still kept.
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
