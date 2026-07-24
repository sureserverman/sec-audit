#!/usr/bin/env python3
"""Stable finding identity + file-hash manifest for sec-audit's incremental mode.

Two jobs, both deterministic:

1. **fingerprint(finding)** — a stable id for "the same finding" across runs.
   Line numbers are deliberately EXCLUDED from the key: a finding that survives
   an unrelated edit shifting it 40 lines down is the same finding, and treating
   it as a new one would make every re-audit look like a regression. The line is
   kept as a mutable attribute instead.

2. **manifest(target)** — {relpath: {sha256, size}} over the audited tree, the
   baseline §2.5 diffs the next run against.

The manifest MUST see exactly the tree the scanners see: it reuses
inventory.py's SKIP_DIRS pruning rather than defining its own. If those two ever
disagree, a file could change without the manifest noticing (a missed finding)
or churn endlessly in the changed set (wasted re-scans).

Usage:
  fingerprint.py manifest <target> [--files <listfile>]  -> {"manifest": {...}}
  fingerprint.py findings [<jsonl-or-json-file>]         -> findings + `fingerprint`
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secaudit.inventory import SKIP_DIRS  # noqa: E402  (single source of truth for pruning)

ALGO = "v1"
EVIDENCE_CAP = 200
CHUNK = 1 << 16


def _norm(text):
    """Collapse whitespace runs, strip, cap. Case is preserved — a secret, a
    path and an identifier all differ meaningfully by case."""
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    return " ".join(text.split())[:EVIDENCE_CAP]


def fingerprint(finding):
    """Stable identity for a finding. Same inputs -> same digest, every run,
    every process (no PYTHONHASHSEED dependence: only sha256 over a fixed
    field order)."""
    evidence = _norm(finding.get("evidence") or "")
    if not evidence:
        # Some lanes emit no snippet (a manifest-level or whole-file finding).
        # Fall back to the title so such findings still carry a stable identity.
        evidence = _norm(finding.get("title") or "")
    parts = [
        _norm(finding.get("origin") or ""),
        _norm(finding.get("tool") or ""),
        _norm(finding.get("rule_id") or finding.get("id") or ""),
        _norm(finding.get("file") or finding.get("path") or ""),
        _norm(str(finding.get("cwe") or "")),
        evidence,
    ]
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return f"{ALGO}:{digest}"


def annotate(findings):
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        g = dict(f)
        g["fingerprint"] = fingerprint(f)
        g["fingerprint_algo"] = ALGO
        out.append(g)
    return out


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def manifest(target, files=None):
    """{relpath: {sha256, size}} for the audited tree.

    files=None walks the tree (pruning SKIP_DIRS, exactly as inventory.py does);
    files=<iterable of relpaths> hashes only those (--diff scoping). Unreadable
    entries and symlinks are skipped: a dangling link is not project content,
    and a permission error must not abort a whole audit."""
    out = {}
    if files is None:
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in names:
                p = os.path.join(root, fn)
                rel = os.path.relpath(p, target)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                try:
                    out[rel] = {"sha256": file_sha256(p), "size": os.path.getsize(p)}
                except OSError:
                    continue
    else:
        for rel in files:
            p = os.path.join(target, rel)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            try:
                out[rel] = {"sha256": file_sha256(p), "size": os.path.getsize(p)}
            except OSError:
                continue
    return out


def _read_findings(path):
    raw = sys.stdin.read() if path in (None, "-") else open(path, encoding="utf-8").read()
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("["):
        return json.loads(raw)
    return [json.loads(ln) for ln in raw.splitlines() if ln.strip()]


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: fingerprint.py manifest <target> [--files F] | findings [FILE]\n")
        return 2
    cmd = argv[1]
    if cmd == "manifest":
        if len(argv) < 3:
            sys.stderr.write("fingerprint: manifest needs a <target>\n")
            return 2
        target = argv[2]
        files = None
        if "--files" in argv:
            lf = argv[argv.index("--files") + 1]
            with open(lf, encoding="utf-8") as f:
                files = [ln.strip() for ln in f if ln.strip()]
        sys.stdout.write(json.dumps({"manifest": manifest(target, files)},
                                    indent=2, sort_keys=True) + "\n")
        return 0
    if cmd == "findings":
        path = argv[2] if len(argv) > 2 else None
        for f in annotate(_read_findings(path)):
            sys.stdout.write(json.dumps(f, sort_keys=True) + "\n")
        return 0
    sys.stderr.write(f"fingerprint: unknown command {cmd!r}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
