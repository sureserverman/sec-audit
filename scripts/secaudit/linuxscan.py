#!/usr/bin/env python3
"""Desktop-Linux tool driver for the linux lane.

Why this exists
---------------
The linux lane's three tools each need per-artifact discovery plus per-artifact
attribution, which `lanes/*.json` cannot express:

  * `systemd-analyze security` scores ONE unit per invocation, and every finding
    has to carry the unit file it came from.
  * `lintian` analyses a BUILT package (`.deb`/`.dsc`/`.changes`/`.buildinfo`),
    one per invocation, and emits text — not JSON — in the version shipped by
    Debian/Ubuntu today.
  * `checksec` walks a directory in one pass, but the two programs called
    `checksec` return different documents (see below).

Each tool is driven separately (`--tool`) so the lane keeps one entry per tool
and therefore one probe, one applicability rule and one skip reason per tool,
exactly as if they were ordinary lane entries.

Invocations, all verified against the installed tools on 2026-08-27
-------------------------------------------------------------------
Every one of the three invocations previously documented for this lane was
wrong, and two of them were wrong in a way that produced confident nonsense
rather than an error:

  * `lintian --output-format=json <dir>` — **no such option** (`Unknown option:
    output-format`) in Lintian 2.117, the very version the reference names as
    the one that supports it. And lintian cannot read a source directory at all:
    `bad package file name . (neither .deb, .udeb, .ddeb, .changes, .dsc or
    .buildinfo file)`. The lane gated lintian on `debian/control` being present
    — i.e. on precisely the case where lintian has nothing it can open.
  * `checksec --file=<elf> --output=json` — `unknown flag: --file`. There are two
    different programs named `checksec`: `checksec-py` (which the reference
    documents, and which returns an object keyed by binary path) and the Go
    `checksec` (installed here at 3.1.0, subcommand-based, returning an ARRAY of
    objects each with a nested `checks` map). Both output shapes are accepted
    below rather than picking a winner.
  * `systemd-analyze security --offline=true --profile=strict <unit>` — correct,
    but text-only. `--json=short` returns the same analysis as structured rows
    (`set`, `name`, `json_field`, `description`, `exposure`) and is used here.

Exit codes: 0 complete, 1 a run failed, 3 inapplicable (nothing of this tool's
shape under the target). The lane maps 3 to that tool's clean-skip reason.

Output: sec-audit finding JSONL on stdout, `origin` "linux". Summary on stderr.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

REF = "linux-tools.md"
PRUNE = {
    # Deliberately NOT pruning build/dist/target: those hold exactly the BUILT
    # artifacts lintian (.deb) and checksec (ELF) analyse. Pruning them (as this
    # list did until 2026-09-03) meant a package built into build/ was never
    # found and the lane reported `no-debian-package` over it.
    ".git", "node_modules", ".venv", "venv",
    "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache", "vendor",
    ".tox", "htmlcov", ".cache",
}
TIMEOUT = 600

# CWE assignments. Deliberately NOT invented here: the systemd table is
# transcribed from references/desktop/linux-systemd.md and the lintian/checksec
# ones from linux-runner.md Step 6 ("CWE-693 default; CWE-426 for
# rpath/runpath") and the same reference pack. Any
# directive or tag not listed gets `null`, which is the rule the runner already
# states for unmapped lintian tags. Extend from a cited source, never by guess.
# Keyed by the directive name systemd-analyze reports in `json_field`, matched
# on the part before any `_` suffix (`SystemCallFilter_resources` ->
# `SystemCallFilter`, `RestrictAddressFamilies_AF_UNIX` ->
# `RestrictAddressFamilies`). Transcribed from
# references/desktop/linux-systemd.md, which is the cited source of record.
SYSTEMD_CWE = {
    "ProtectSystem": "CWE-732",
    "PrivateTmp": "CWE-377",
    "NoNewPrivileges": "CWE-250",
    "CapabilityBoundingSet": "CWE-269",
    "SystemCallFilter": "CWE-693",
    "ReadWritePaths": "CWE-732",
    "User": "CWE-250",
    "UserOrDynamicUser": "CWE-250",
    "RestrictAddressFamilies": "CWE-284",
    "SetCredential": "CWE-312",
    "StandardOutput": "CWE-532",
    "StandardError": "CWE-532",
}
LINTIAN_CWE = {
    "maintainer-script-without-set-e": "CWE-390",
    # lintian >= 2.104 renamed the set -e check; same defect, same CWE.
    # https://lintian.debian.org/tags/maintainer-script-ignores-errors
    "maintainer-script-ignores-errors": "CWE-390",
    "setuid-binary": "CWE-250",
    # https://lintian.debian.org/tags/elevated-privileges — setuid/setgid file.
    "elevated-privileges": "CWE-250",
}

LINTIAN_ARTIFACTS = (".deb", ".udeb", ".ddeb", ".dsc", ".changes", ".buildinfo")
# `E:` error, `W:` warning, `I:` info, `P:` pedantic, `X:` experimental,
# `C:` classification, `O:` overridden.
LINTIAN_SEVERITY = {"E": "HIGH", "W": "MEDIUM", "I": "LOW", "P": "LOW",
                    "X": "LOW", "C": "INFO", "O": "INFO"}
# lintian 2.117 prints `<L>: <pkg>: <tag> [<context words>] [<file>]` — the
# context is free text ("0664 != 0644 [etc/cron.d/x]"), not only a bracketed
# file. The previous pattern accepted a bracket-only tail and so silently
# dropped every tag that carries context (10 of 16 on the fixture package).
LINTIAN_RE = re.compile(r"^([EWIPXCO]): (\S+): (\S+)(?:\s+(.*?))?\s*$")


def walk(target):
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in PRUNE)
        for name in sorted(files):
            yield os.path.join(root, name)


def finding(fid, severity, cwe, title, path, line, evidence, tool, target,
            url=None, confidence="high"):
    try:
        rel = os.path.relpath(path, target)
    except ValueError:
        rel = str(path)
    return {
        "id": fid,
        "severity": severity,
        "cwe": cwe,
        "title": str(title)[:200],
        "file": rel,
        "line": line,
        "evidence": str(evidence)[:200],
        "confidence": confidence,
        "reference": REF,
        "reference_url": url,
        "fix_recipe": None,
        "origin": "linux",
        "tool": tool,
    }


def run(argv):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except Exception as e:                                   # noqa: BLE001
        sys.stderr.write(f"linuxscan: {' '.join(argv)} failed: {e}\n")
        return None


# --------------------------------------------------------------- systemd
def systemd_host():
    """Same two-signal check the runner documents."""
    if os.path.isdir("/run/systemd/system"):
        return True
    proc = run(["systemctl", "--version"])
    return proc is not None and proc.returncode == 0


def _exposure(row):
    try:
        return float(row.get("exposure") or 0)
    except (TypeError, ValueError):
        return 0.0


def do_systemd(target):
    units = [p for p in walk(target) if p.endswith(".service")]
    if not units:
        sys.stderr.write("linuxscan: no .service unit under target\n")
        return [], 3
    if not systemd_host():
        sys.stderr.write("linuxscan: not a systemd host\n")
        return [], 3
    out, failures = [], 0
    for unit in units:
        proc = run(["systemd-analyze", "security", "--offline=true",
                    "--profile=strict", "--json=short", unit])
        if proc is None or not proc.stdout.strip():
            failures += 1
            continue
        try:
            rows = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"linuxscan: {unit}: unparseable JSON: {e}\n")
            failures += 1
            continue
        for row in rows:
            exp = _exposure(row)
            # `set: true` means the hardening directive IS applied. Only an
            # unset directive that carries a non-zero exposure is a finding;
            # everything else is the tool reporting that the unit is fine.
            if exp <= 0 or row.get("set") is True:
                continue
            sev = "HIGH" if exp >= 0.5 else "MEDIUM" if exp >= 0.2 else "LOW"
            field = str(row.get("json_field") or row.get("name") or "unknown")
            cwe = SYSTEMD_CWE.get(field) or SYSTEMD_CWE.get(field.split("_", 1)[0])
            out.append(finding(
                f"systemd-analyze:{field}", sev, cwe,
                row.get("description", ""), unit, 0,
                f"exposure {row.get('exposure')}: {row.get('description', '')}",
                "systemd-analyze", target,
                url="https://www.freedesktop.org/software/systemd/man/latest/"
                    "systemd.exec.html"))
    return out, (1 if failures and not out else 0)


# --------------------------------------------------------------- lintian
def do_lintian(target):
    artifacts = [p for p in walk(target) if p.endswith(LINTIAN_ARTIFACTS)]
    if not artifacts:
        sys.stderr.write("linuxscan: no built Debian package under target\n")
        return [], 3
    out, failures = [], 0
    for art in artifacts:
        proc = run(["lintian", art])
        if proc is None:
            failures += 1
            continue
        # lintian exits non-zero merely because it emitted tags; only a total
        # absence of parseable output alongside stderr noise is a failure.
        text = proc.stdout
        if not text.strip() and proc.stderr.strip():
            sys.stderr.write(f"linuxscan: lintian {art}: {proc.stderr[:200]}\n")
            failures += 1
            continue
        for raw in text.splitlines():
            m = LINTIAN_RE.match(raw.strip())
            if not m:
                continue
            letter, pkg, tag, context = m.groups()
            out.append(finding(
                f"lintian:{tag}", LINTIAN_SEVERITY.get(letter, "LOW"),
                LINTIAN_CWE.get(tag), tag, art, 0,
                f"{pkg}: {tag}" + (f" [{context}]" if context else ""),
                "lintian", target,
                url=f"https://lintian.debian.org/tags/{tag}.html"))
    return out, (1 if failures and not out else 0)


# --------------------------------------------------------------- checksec
def _checksec_entries(doc):
    """(path, checks-map) pairs from either checksec's output shape.

    Go checksec 3.x: a LIST of objects, each with a nested `checks` map.
    checksec-py:     an OBJECT keyed by binary path, values are the check maps.
    """
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict):
                checks = item.get("checks") if isinstance(
                    item.get("checks"), dict) else item
                yield str(item.get("file") or item.get("name") or ""), checks
    elif isinstance(doc, dict):
        for path, checks in doc.items():
            if isinstance(checks, dict):
                yield str(path), checks


def _missing(value):
    """Whether a hardening check reads as absent. Both tools report free text
    ('No RPATH', 'Full RELRO', 'NX enabled', 'no', 'yes'), so match on the
    negative words rather than on a fixed vocabulary neither guarantees."""
    v = str(value).strip().lower()
    return v.startswith("no") or v in ("false", "disabled", "none", "")


def do_checksec(target):
    proc = run(["checksec", "dir", target, "--output", "json", "--no-banner"])
    if proc is None:
        return [], 1
    blob = (proc.stdout or "").strip()
    if not blob:
        if "no binary files found" in (proc.stderr or "").lower():
            sys.stderr.write("linuxscan: no ELF binary under target\n")
            return [], 3
        sys.stderr.write(f"linuxscan: checksec: {proc.stderr[:200]}\n")
        return [], 1
    try:
        doc = json.loads(blob)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"linuxscan: checksec: unparseable JSON: {e}\n")
        return [], 1
    out = []
    for path, checks in _checksec_entries(doc):
        for key, label in (("relro", "RELRO"), ("nx", "NX"),
                           ("pie", "PIE"), ("canary", "stack canary")):
            if key in checks and _missing(checks[key]):
                out.append(finding(
                    f"checksec:no-{key}", "MEDIUM", "CWE-693",
                    f"binary built without {label}", path or target, 0,
                    f"{key}: {checks[key]}", "checksec", target))
        for key in ("rpath", "runpath"):
            if key in checks and not _missing(checks[key]):
                out.append(finding(
                    f"checksec:{key}", "HIGH", "CWE-426",
                    f"binary sets {key.upper()}", path or target, 0,
                    f"{key}: {checks[key]}", "checksec", target))
    return out, 0


TOOLS = {"systemd-analyze": do_systemd, "lintian": do_lintian,
         "checksec": do_checksec}


def main(argv):
    ap = argparse.ArgumentParser(prog="linuxscan.py")
    ap.add_argument("target")
    ap.add_argument("--tool", required=True, choices=sorted(TOOLS))
    args = ap.parse_args(argv[1:])

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        sys.stderr.write(f"linuxscan: not a directory: {target}\n")
        return 2
    if shutil.which(args.tool) is None:
        # The lane probes first, so this means PATH moved underneath us. Emit
        # nothing and say so rather than reporting a clean scan.
        sys.stderr.write(f"linuxscan: {args.tool} not on PATH\n")
        return 1

    findings, rc = TOOLS[args.tool](target)
    for f in findings:
        sys.stdout.write(json.dumps(f, sort_keys=True) + "\n")
    sys.stderr.write(
        f"linuxscan: {args.tool} -> {len(findings)} finding(s), rc={rc}\n")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
