#!/usr/bin/env python3
"""Deterministic tool-poisoning scan for agent and skill markdown (ai-tools lane).

Why this exists
---------------
`mcp-scan` / `snyk-agent-scan inspect --skills` was documented as covering
`agents/*.md` as well as `skills/**/SKILL.md`. It does not: pointed at a
directory of agent markdown it reports zero entries, because it only recognises
skill-shaped folders. Worse, it discovers skills **only** when pointed at a
directory that directly contains skill folders — aimed at a repository root it
prints "no mcp servers or skills found" and exits 0, which reads as a clean
scan of a tree it never looked at.

So the lane had a hole in two directions: agent files were never scanned by
anything, and skill files were silently skipped in any layout other than
`<target>/skills` (a plugin marketplace keeps them at
`plugins/<plugin>/skills/`, which is the common case for Claude Code plugins).

This module closes both. It finds every agent/skill markdown file under the
target by shape rather than by a fixed path, and applies checks that are
mechanical enough to be deterministic — no model, no network, no execution.

What it checks
--------------
  unscoped-tool-grant   `allowed-tools:` / `tools:` naming bare `Bash` (or
                        `Bash(*)`), which is an unrestricted shell grant
  interpreter-grant     a grant scoped to an interpreter — `Bash(bash:*)`,
                        `Bash(sh:*)`, `Bash(python3:*)`, `Bash(sqlite3:*)` —
                        which the permission matcher cannot constrain, since
                        the interpreter accepts arbitrary code as an argument
  missing-tool-grant    no tool declaration at all, so the component inherits
                        the caller's entire tool set (broader than a bare
                        `Bash`, because Write/Edit come with it)
  hidden-unicode        zero-width or bidi-control characters, the standard way
                        to hide instructions from a human reviewing a diff
  hidden-instruction    an imperative buried in an HTML comment, invisible in
                        rendered markdown
  instruction-override  text steering the agent to disregard its operator or to
                        act without telling the user
  exfiltration-shape    a documented command that pipes local data to a remote
                        host, or pipes a download into a shell

Output: sec-audit finding JSONL on stdout, one object per line, `origin`
"ai-tools" and `tool` "agentscan". A summary line goes to stderr. Exit 0 unless
the target is unreadable — findings are data, not an error condition.

Pure stdlib. Reads files; writes nothing.
"""

from __future__ import annotations

import json
import os
import re
import sys

REF = "ai-tools-tools.md"
REF_URL = "https://genai.owasp.org/llm-top-10/"

# Directories never worth walking — vendored, generated, or VCS internals.
PRUNE = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", "target",
    "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache", "vendor",
    ".tox", "htmlcov", ".cache",
}

FRONTMATTER_TOOL_KEYS = ("allowed-tools", "tools")

# An interpreter accepts arbitrary code as an argument, so scoping a grant to
# one constrains nothing: `Bash(bash:*)` still matches `bash -c '<anything>'`.
# sqlite3 belongs here for its `.shell` / `.system` / `.load` dot-commands,
# which execute regardless of a read-only database URI.
INTERPRETERS = ("bash", "sh", "zsh", "ksh", "python", "python3", "perl", "ruby",
                "node", "sqlite3", "env", "eval", "xargs")

ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
}
BIDI = {
    "‪": "LEFT-TO-RIGHT EMBEDDING", "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING", "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE", "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE", "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}

OVERRIDE_RE = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions"
    r"|disregard\s+(the\s+)?(user|operator|previous|prior)"
    r"|do\s*not\s+(tell|inform|mention\s+to|report\s+to)\s+the\s+user"
    r"|without\s+(telling|informing|asking)\s+the\s+user"
    r"|hide\s+this\s+from\s+the\s+user"
    r"|regardless\s+of\s+what\s+the\s+user)",
    re.I,
)

# curl/wget piped into a shell, or sending local data outward.
EXFIL_RE = re.compile(
    r"(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(ba)?sh"
    r"|\b(curl|wget)\b[^\n]*(--data|--data-binary|-d\s|--upload-file|-T\s)"
    r"|base64\b[^\n|]*\|\s*(curl|wget|nc|ncat)",
    re.I,
)

# Well-written skills document their own hazards, so the phrases above appear
# most often in prose warning against them: "Never <bad thing>", or a bullet
# under a "Common pitfalls" heading. Matching those would make the scanner
# loudest on the most careful authors, so two suppressions apply — the nearest
# preceding heading, and a negative framing on the line itself.
NEGATIVE_SECTION_RE = re.compile(
    r"(pitfall|never\s+to\s+do|anti-?pattern|common\s+mistake|what\s+never|"
    r"don'?t|do\s+not|avoid|failure\s+mode|caveat|warning)", re.I)
NEGATIVE_LINE_RE = re.compile(
    r"^\s*[-*>]?\s*\**\s*(never|do\s*not|don'?t|avoid|silently|no\s+)", re.I)
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.*)$")

# An imperative inside an HTML comment. Comments are invisible in rendered
# markdown, so an instruction there reaches the model but not a human skimming
# the page. Reference/licence banners are the common benign case, so require a
# second-person imperative rather than flagging every comment.
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
IMPERATIVE_RE = re.compile(
    r"\b(you\s+must|you\s+should\s+always|always\s+run|never\s+tell|"
    r"instead\s+of\s+what\s+the\s+user|when\s+asked[^.]{0,40}respond|"
    r"do\s+not\s+mention|silently)\b",
    re.I,
)


def is_agent_or_skill(path: str) -> str | None:
    """Classify a markdown path as 'skill', 'agent', or None.

    By shape, not by a fixed location — `<target>/skills`, `plugins/*/skills`,
    `.claude/agents`, and any nesting of those all qualify.
    """
    base = os.path.basename(path)
    parts = path.replace(os.sep, "/").split("/")
    if base == "SKILL.md":
        return "skill"
    if base.endswith(".md") and "agents" in parts[:-1]:
        return "agent"
    # Commands declare `allowed-tools:` from the same vocabulary and can hold the
    # same grants. Omitting them let a grant "disappear" simply by moving from a
    # skill into its command — a real reduction in reachability, but not the
    # elimination the finding count implied.
    if base.endswith(".md") and "commands" in parts[:-1]:
        return "command"
    return None


def walk(target: str) -> list[tuple[str, str]]:
    out = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in PRUNE)
        for name in sorted(files):
            if not name.endswith(".md"):
                continue
            full = os.path.join(root, name)
            kind = is_agent_or_skill(full)
            if kind:
                out.append((full, kind))
    return sorted(out)


def frontmatter(text: str) -> tuple[dict, int]:
    """Return (frontmatter fields, line offset of the block's first line).

    Deliberately not a YAML parser: only top-level `key: value` lines are read,
    which is all the tool-grant checks need, and it cannot fail on the
    multi-line `description: >` blocks these files use.
    """
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return {}, 0
    fields = {}
    for i, line in enumerate(lines[1:], start=2):
        if line.strip() == "---":
            break
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m:
            fields[m.group(1)] = (m.group(2).strip(), i)
    return fields, 1


def finding(fid, severity, cwe, title, path, line, evidence, target, confidence="high"):
    rel = os.path.relpath(path, target)
    return {
        "id": f"agentscan:{fid}",
        "severity": severity,
        "cwe": cwe,
        "title": title,
        "file": rel,
        "line": line,
        "evidence": (evidence or "")[:200],
        "confidence": confidence,
        "reference": REF,
        "reference_url": REF_URL,
        "fix_recipe": None,
        "origin": "ai-tools",
        "tool": "agentscan",
    }


def check_tool_grant(path, kind, fields, target):
    out = []
    key = next((k for k in FRONTMATTER_TOOL_KEYS if k in fields), None)
    if key is None and kind == "command":
        return out          # commands commonly omit the key; not the skill hazard
    if key is None:
        out.append(finding(
            "missing-tool-grant", "MEDIUM", "CWE-693",
            f"{kind} declares no tool grant, inheriting the caller's full tool set",
            path, 1,
            "no `allowed-tools:` or `tools:` key in frontmatter", target))
        return out

    value, line = fields[key]
    # Strip scoped grants, then look for a surviving bare `Bash`.
    stripped = re.sub(r"Bash\([^)]*\)", "", value)
    if re.search(r"(^|[,\s\[\"'])Bash([,\s\]\"']|$)", stripped) or "Bash(*)" in value:
        out.append(finding(
            "unscoped-tool-grant", "HIGH", "CWE-693",
            f"{kind} grants unrestricted Bash (no argument filter)",
            path, line, f"{key}: {value}", target))
        return out

    for interp in INTERPRETERS:
        if re.search(rf"Bash\(\s*{re.escape(interp)}\s*[:)]", value):
            out.append(finding(
                "interpreter-grant", "HIGH", "CWE-693",
                f"{kind} grants Bash({interp}:*), which an argument filter cannot constrain",
                path, line, f"{key}: {value}", target,
                confidence="medium"))
            break
    return out


def check_text(path, kind, text, target):
    out = []
    lines = text.split("\n")

    heading = ""
    for i, line in enumerate(lines, start=1):
        h = HEADING_RE.match(line)
        if h:
            heading = h.group(1)
        # A hazard documented under a "Common pitfalls" heading, or framed as
        # "Never …", is the author warning against the behaviour, not asking
        # for it. Unicode checks are exempt: an invisible character is never
        # documentation, whatever section it sits in.
        warned = bool(NEGATIVE_SECTION_RE.search(heading)) or bool(NEGATIVE_LINE_RE.match(line))

        for ch, name in ZERO_WIDTH.items():
            if ch in line:
                out.append(finding(
                    "hidden-unicode", "HIGH", "CWE-94",
                    f"{kind} contains a zero-width character ({name})",
                    path, i, line.replace(ch, f"<{name}>").strip(), target))
                break
        for ch, name in BIDI.items():
            if ch in line:
                out.append(finding(
                    "hidden-unicode", "HIGH", "CWE-94",
                    f"{kind} contains a bidirectional control character ({name})",
                    path, i, line.replace(ch, f"<{name}>").strip(), target))
                break

        if not warned and OVERRIDE_RE.search(line):
            out.append(finding(
                "instruction-override", "HIGH", "CWE-94",
                f"{kind} contains text steering the agent to override or conceal from its operator",
                path, i, line.strip(), target, confidence="medium"))

        if not warned and EXFIL_RE.search(line):
            out.append(finding(
                "exfiltration-shape", "HIGH", "CWE-77",
                f"{kind} documents a command that pipes data outward or pipes a download into a shell",
                path, i, line.strip(), target, confidence="medium"))

    for m in COMMENT_RE.finditer(text):
        body = m.group(1)
        hit = IMPERATIVE_RE.search(body)
        if hit:
            line = text[:m.start()].count("\n") + 1
            snippet = " ".join(body.split())[:160]
            out.append(finding(
                "hidden-instruction", "MEDIUM", "CWE-94",
                f"{kind} carries an imperative inside an HTML comment (invisible when rendered)",
                path, line, snippet, target, confidence="medium"))
    return out


def scan(target: str):
    findings, counts = [], {"skill": 0, "agent": 0, "command": 0}
    for path, kind in walk(target):
        counts[kind] += 1
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        fields, _ = frontmatter(text)
        findings.extend(check_tool_grant(path, kind, fields, target))
        findings.extend(check_text(path, kind, text, target))
    return findings, counts


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: agentscan.py <target_path>\n")
        return 2
    target = os.path.abspath(argv[1])
    if not os.path.isdir(target):
        sys.stderr.write(f"agentscan: not a directory: {target}\n")
        return 2

    findings, counts = scan(target)
    for f in findings:
        sys.stdout.write(json.dumps(f, sort_keys=True) + "\n")
    sys.stderr.write(
        f"agentscan: scanned {counts['skill']} skill + {counts['agent']} agent + "
        f"{counts['command']} command file(s), {len(findings)} finding(s)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
