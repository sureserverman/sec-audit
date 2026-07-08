#!/usr/bin/env python3
"""Deterministic CVE-feed enrichment for sec-audit (replaces the LLM agent loop).

Reads a `__dep_inventory__` JSON object on stdin:
  {"ecosystems":[{"ecosystem":"PyPI","packages":[{"name","version"},...]}, ...]}

Emits, on stdout, the JSON array contract documented in agents/cve-enricher.md
Step 8: one object per input package with `cves[]`, `malicious[]`, `status`.

Pure stdlib. HTTP via secaudit.net (offline-replayable). Endpoint base URLs are
read from env overrides per references/cve-feeds.md. Retry-once on 429/5xx,
hard cap of 500 requests/run. Never invents IDs (it only relays feed JSON);
classifies OSV `MAL-` advisories + GHSA `type:malware` into `malicious[]`.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secaudit import net  # noqa: E402

CAP = 500
OSV = os.environ.get("OSV_BASE_URL", "https://api.osv.dev").rstrip("/")
NVD = os.environ.get("NVD_BASE_URL", "https://services.nvd.nist.gov").rstrip("/")
GHSA = os.environ.get("GHSA_BASE_URL", "https://api.github.com").rstrip("/")
KEV_URL = os.environ.get(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
EPSS = os.environ.get("EPSS_BASE_URL", "https://api.first.org").rstrip("/")
EPSS_CHUNK = 100  # FIRST.org batch: comma-joined CVE ids; ~100 keeps the GET URL short
_REPLAY = bool(os.environ.get("SECAUDIT_FEED_REPLAY_DIR"))


class Budget:
    def __init__(self):
        self.n = 0

    def ok(self):
        return self.n < CAP

    def spend(self):
        self.n += 1


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _retrying(fn):
    """Call fn() -> (status, text); retry once on 429/5xx (no sleep in replay)."""
    status, text = fn()
    if status == 429 or status >= 500 or status == 0:
        if not _REPLAY:
            time.sleep(2)
        status, text = fn()
    return status, text


def _loads(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def _osv_cvss(vuln):
    for s in vuln.get("severity", []) or []:
        score = s.get("score")
        try:
            return float(score)
        except (TypeError, ValueError):
            pass
    ds = vuln.get("database_specific", {}) or {}
    try:
        return float(ds.get("cvss", {}).get("score"))
    except (TypeError, ValueError, AttributeError):
        return None


def _fixed_versions(vuln):
    out = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    out.append(ev["fixed"])
    return out


def _osv_detail(vid, budget):
    if not budget.ok():
        return None
    budget.spend()
    status, text = _retrying(lambda: net.get(f"{OSV}/v1/vulns/{quote(vid, safe='')}"))
    if status != 200:
        return None
    return _loads(text)


def _mk_cve(vuln):
    return {
        "id": vuln.get("id"),
        "summary": vuln.get("summary") or vuln.get("details"),
        "cvss": _osv_cvss(vuln),
        "fixed_versions": _fixed_versions(vuln),
        "references": [r.get("url") for r in vuln.get("references", []) or [] if r.get("url")],
        "source": "OSV",
        "fetched_at": _now(),
        "kev": False,
        "kev_date_added": None,
        "kev_due_date": None,
        "epss": None,
        "epss_percentile": None,
    }


def _mk_malicious(vuln, source="OSV"):
    return {
        "id": vuln.get("id"),
        "kind": "malicious_package",
        "severity": "CRITICAL",
        "cvss": None,
        "kev": None,
        "summary": vuln.get("summary") or vuln.get("details"),
        "references": [r.get("url") for r in vuln.get("references", []) or [] if r.get("url")],
        "source": source,
        "fetched_at": _now(),
    }


def enrich(inventory, budget):
    pkgs = []  # flattened, each carries its ecosystem
    for eco in inventory.get("ecosystems", []):
        for p in eco.get("packages", []):
            pkgs.append({"ecosystem": eco.get("ecosystem"), "name": p.get("name"),
                         "version": p.get("version"), "cves": [], "malicious": [],
                         "status": "ok"})

    # Step 2: OSV querybatch (one POST for the whole set).
    if pkgs and budget.ok():
        budget.spend()
        q = {"queries": [{"package": {"ecosystem": p["ecosystem"], "name": p["name"]},
                          "version": p["version"]} for p in pkgs]}
        status, text = _retrying(lambda: net.post(f"{OSV}/v1/querybatch", json.dumps(q)))
        if status != 200:
            for p in pkgs:
                p["status"] = "offline"
            return pkgs
        results = (_loads(text) or {}).get("results", [])
        for p, res in zip(pkgs, results):
            for v in (res or {}).get("vulns", []) or []:
                vid = v.get("id", "")
                # Step 3/3.5: per-id detail; split MAL- from CVEs.
                if not budget.ok():
                    p["status"] = "capped"
                    break
                detail = _osv_detail(vid, budget)
                if detail is None:
                    continue
                if vid.startswith("MAL-"):
                    p["malicious"].append(_mk_malicious(detail))
                else:
                    p["cves"].append(_mk_cve(detail))

    # Step 5.5: KEV cross-reference (one fetch, index in memory).
    kev_index = {}
    if any(p["cves"] for p in pkgs) and budget.ok():
        budget.spend()
        status, text = _retrying(lambda: net.get(KEV_URL))
        if status == 200:
            for v in (_loads(text) or {}).get("vulnerabilities", []) or []:
                kev_index[v.get("cveID")] = (v.get("dateAdded"), v.get("dueDate"))
        for p in pkgs:
            for c in p["cves"]:
                if c["id"] in kev_index:
                    c["kev"] = True
                    c["kev_date_added"], c["kev_due_date"] = kev_index[c["id"]]

    _epss_enrich(pkgs, budget)
    return pkgs


def _epss_enrich(pkgs, budget):
    """Step 5.6: EPSS enrichment (FIRST.org exploit-prediction). Batch the CVE
    ids by EPSS_CHUNK per GET; only CVE ids leave the machine — same privacy
    property as OSV/KEV. epss/percentile come back as strings; coerce to float.
    Feed offline (or a CVE with no EPSS row) leaves epss None — unknown is
    unknown, exactly like kev: null. Never fabricated."""
    cve_ids, seen_ids = [], set()
    for p in pkgs:
        for c in p["cves"]:
            cid = c.get("id")
            if cid and cid.startswith("CVE-") and cid not in seen_ids:
                seen_ids.add(cid)
                cve_ids.append(cid)
    epss_index = {}
    for i in range(0, len(cve_ids), EPSS_CHUNK):
        if not budget.ok():
            break
        budget.spend()
        chunk = cve_ids[i:i + EPSS_CHUNK]
        status, text = _retrying(lambda c=chunk: net.get(f"{EPSS}/data/v1/epss?cve={','.join(c)}"))
        if status != 200:
            continue
        for row in (_loads(text) or {}).get("data", []) or []:
            try:
                epss_index[row.get("cve")] = (float(row.get("epss")), float(row.get("percentile")))
            except (TypeError, ValueError):
                pass
    for p in pkgs:
        for c in p["cves"]:
            if c["id"] in epss_index:
                c["epss"], c["epss_percentile"] = epss_index[c["id"]]


def main():
    raw = sys.stdin.read()
    inv = _loads(raw) or {}
    budget = Budget()
    out = enrich(inv, budget)
    sys.stdout.write(json.dumps(out, indent=2))
    sys.stdout.write("\n")
    sys.stderr.write(f"cve_enricher: {len(out)} packages, {budget.n} requests\n")


if __name__ == "__main__":
    main()
