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
    """GitHub's 0.0-10.0 ranking key: CVSS if present, else score/10."""
    cvss = f.get("cvss")
    if isinstance(cvss, (int, float)):
        return round(float(cvss), 1)
    score = f.get("score")
    if isinstance(score, (int, float)):
        return round(score / 10.0, 1)
    return None


def _message(f):
    # title is always safe (never a raw secret); evidence is redacted upstream
    # for the secrets lane. Never emit a raw credential here.
    return f.get("title") or f.get("evidence") or f.get("id") or "finding"


def to_sarif(findings):
    rules = {}
    results = []
    for f in findings:
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
    try:
        findings = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        findings = []
    if not isinstance(findings, list):
        findings = []
    json.dump(to_sarif(findings), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
