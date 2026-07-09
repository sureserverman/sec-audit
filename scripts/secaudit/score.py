#!/usr/bin/env python3
"""Deterministic prioritization scoring for sec-audit (SKILL §5 rubric).

Reads a JSON array of findings on stdin; writes the same array with `score`
(0-100 int), `bucket` (CRITICAL/HIGH/MEDIUM/LOW), and `score_breakdown` (the
per-component math, for "show the math in the report") added to each finding.

Rubric (verbatim from SKILL.md §5):
  CVSS      0-40 : min(40, cvss*4) if numeric cvss; else severity tier
                   CRITICAL=36 / HIGH=28 / MEDIUM=16 / LOW=6 / INFO=0
  Exposure  0-25 : unauth=25 / auth=15 / internal=5 / test=0  (field `exposure`)
  Exploit   0-20 : kev True=20 / epss>=0.5=15 / epss>=0.1=10 / poc True=10 / else 0
                   (fields `kev`, `epss`, `poc`; epss null contributes nothing)
  Auth      0-15 : none=15 / user=8 / admin=2 / host=0  (field `auth_required`)
  Buckets   : 90-100 CRITICAL, 70-89 HIGH, 40-69 MEDIUM, 0-39 LOW

Override: a confirmed malicious dependency (kind=="malicious_package" or
deep-deps verdict=="malicious") is not a CVSS-scored vulnerability — it is
known active malware already in the dependency set — so it is pinned to
score 100 / CRITICAL regardless of the additive rubric.
"""
import json
import sys

SEV = {"CRITICAL": 36, "HIGH": 28, "MEDIUM": 16, "LOW": 6, "INFO": 0}
EXPOSURE = {"unauth": 25, "auth": 15, "internal": 5, "test": 0}
AUTH = {"none": 15, "user": 8, "admin": 2, "host": 0}


def bucket(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def score_one(f):
    if f.get("kind") == "malicious_package" or f.get("verdict") == "malicious":
        return 100, {"override": "malicious-dependency pinned to CRITICAL"}

    cvss = f.get("cvss")
    if isinstance(cvss, (int, float)):
        cvss_pts = min(40, int(round(cvss * 4)))
    else:
        cvss_pts = SEV.get((f.get("severity") or "").upper(), 0)

    exposure_pts = EXPOSURE.get(f.get("exposure"), 0)

    # Graded exploit term: KEV (known exploited) dominates; else EPSS
    # (exploit-probability) grades the middle; else a bare PoC; else nothing.
    # epss null (feed offline / no row) contributes nothing — unknown is unknown.
    epss = f.get("epss")
    if f.get("kev") is True:
        exploit_pts = 20
    elif isinstance(epss, (int, float)) and epss >= 0.5:
        exploit_pts = 15
    elif isinstance(epss, (int, float)) and epss >= 0.1:
        exploit_pts = 10
    elif f.get("poc") is True:
        exploit_pts = 10
    else:
        exploit_pts = 0

    auth_pts = AUTH.get(f.get("auth_required"), 0)

    total = max(0, min(100, cvss_pts + exposure_pts + exploit_pts + auth_pts))
    return total, {"cvss": cvss_pts, "exposure": exposure_pts,
                   "exploit": exploit_pts, "auth": auth_pts, "total": total}


def main():
    findings = json.load(sys.stdin)
    for f in findings:
        s, breakdown = score_one(f)
        f["score"] = s
        f["bucket"] = bucket(s)
        f["score_breakdown"] = breakdown
    findings.sort(key=lambda f: f["score"], reverse=True)
    json.dump(findings, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
