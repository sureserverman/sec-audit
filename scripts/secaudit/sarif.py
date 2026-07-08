#!/usr/bin/env python3
"""Emit SARIF 2.1.0 from sec-audit scored findings (GitHub code-scanning compatible).

Reads the scored findings JSON array on stdin (the output of score.py — each
finding carries the sec-audit finding schema plus `score`/`bucket`). Writes a
minimal, valid SARIF 2.1.0 log on stdout: one `runs[0]` whose tool driver is
`sec-audit`, one `results[]` entry per finding, and a deduped `rules[]` array.

Pure stdlib. No network. `partialFingerprints` is intentionally omitted — GitHub
auto-populates it on the `upload-sarif` action path (see references/sast-tools.md).

Severity mapping (SARIF `level` vocabulary): CRITICAL/HIGH -> error,
MEDIUM -> warning, LOW/INFO -> note. GitHub ranks security alerts by
`rule.properties.security-severity` (0.0-10.0): the CVSS base score when present,
else the sec-audit 0-100 priority score scaled to 0-10.
"""
import json
import sys

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
         "LOW": "note", "INFO": "note"}


def _level(f):
    return LEVEL.get((f.get("severity") or "").upper(), "warning")


def _security_severity(f):
    """GitHub's 0.0-10.0 ranking key: CVSS if present, else score/10. Clamped to
    the documented [0,10] range so a stray out-of-range upstream value can't
    produce an invalid SARIF."""
    cvss = f.get("cvss")
    if isinstance(cvss, (int, float)):
        return max(0.0, min(10.0, round(float(cvss), 1)))
    score = f.get("score")
    if isinstance(score, (int, float)):
        return max(0.0, min(10.0, round(score / 10.0, 1)))
    return None


def _message(f):
    """Result message. NEVER fall back to `evidence`: `title` is not a required
    field and some lanes map raw source (and thus possibly a plaintext secret)
    into `evidence` — a SARIF log is uploaded to GitHub, so it must never carry
    a credential. A less-informative message beats a leak."""
    return f.get("title") or f.get("id") or "finding"


def _is_sentinel(f):
    """Pipeline sentinels (the `__dep_inventory__` object, per-lane
    `__<lane>_status__` records) ride in the findings stream but are not
    findings — they must never become SARIF results."""
    if not isinstance(f, dict):
        return True
    fid = f.get("id")
    if isinstance(fid, str) and fid.startswith("__"):
        return True
    return any(isinstance(k, str) and k.startswith("__") and k.endswith("_status__") for k in f)


def to_sarif(findings):
    rules = {}
    results = []
    for f in findings:
        if _is_sentinel(f):
            continue
        rid = f.get("id") or "finding"
        if rid not in rules:
            rule = {"id": rid}
            if f.get("title"):
                rule["shortDescription"] = {"text": f["title"]}
            props = {}
            if f.get("cwe"):
                props["cwe"] = f["cwe"]
            ss = _security_severity(f)
            if ss is not None:
                props["security-severity"] = str(ss)
            if props:
                rule["properties"] = props
            rules[rid] = rule
        phys = {"artifactLocation": {"uri": f.get("file") or "unknown"}}
        line = f.get("line")
        # SARIF region.startLine minimum is 1 — findings with no source line
        # (line 0, e.g. DAST/package-level) omit region entirely.
        if isinstance(line, int) and line > 0:
            phys["region"] = {"startLine": line}
        results.append({
            "ruleId": rid,
            "level": _level(f),
            "message": {"text": _message(f)},
            "locations": [{"physicalLocation": phys}],
        })
    return {
        "version": "2.1.0",
        "$schema": SCHEMA,
        "runs": [{
            "tool": {"driver": {
                "name": "sec-audit",
                "informationUri": "https://github.com/sureserverman/sec-audit",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def main():
    # Fail loudly on bad input: a security tool must not turn a broken pipe
    # (e.g. score.py crashed and its traceback landed on stdin) into a
    # false-clean, zero-result SARIF. Mirrors score.py's loud json.load.
    try:
        findings = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as e:
        sys.stderr.write(f"sarif.py: invalid JSON on stdin: {e}\n")
        sys.exit(1)
    if not isinstance(findings, list):
        sys.stderr.write("sarif.py: expected a JSON array of findings on stdin\n")
        sys.exit(1)
    json.dump(to_sarif(findings), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
