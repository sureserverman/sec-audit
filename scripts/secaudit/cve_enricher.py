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
from datetime import datetime, timedelta, timezone
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


ADVISORY_TTL_DAYS = int(os.environ.get("SECAUDIT_ADVISORY_TTL_DAYS", "7"))


class AdvisoryCache:
    """Per-advisory-id cache of OSV detail documents (v1.32).

    What is cached and what is NOT is the whole point of this class:

      cached      per-id detail GETs — the expensive part, one request per
                  advisory per run, and an advisory's content is stable enough
                  to reuse for ADVISORY_TTL_DAYS (they do get amended, hence a
                  TTL rather than forever).
      NEVER cached  the OSV `querybatch` call. It is one request for up to 1000
                  packages AND it is precisely the "did this unchanged version
                  become vulnerable overnight?" probe. Caching it would defeat
                  the entire purpose of re-auditing unchanged code.

    A corrupt cache file is discarded with a warning and the run proceeds at
    full cost — a damaged cache must never be able to hide an advisory."""

    def __init__(self, path=None, now=None):
        self.path = path
        self.now = now or datetime.now(timezone.utc)
        self.entries = {}
        self.hits = 0
        self.misses = 0
        self.stale = 0
        self.corrupt = False
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    doc = json.load(f)
                if isinstance(doc, dict) and isinstance(doc.get("advisories"), dict):
                    self.entries = doc["advisories"]
                else:
                    self.corrupt = True
            except (OSError, ValueError):
                self.corrupt = True
            if self.corrupt:
                self.entries = {}
                sys.stderr.write(
                    f"cve_enricher: advisory cache at {path} is unreadable — "
                    "ignoring it and re-fetching everything (a damaged cache must "
                    "never be able to hide an advisory)\n")

    def _fresh(self, entry):
        try:
            fetched = datetime.fromisoformat(
                str(entry.get("fetched_at", "")).replace("Z", "+00:00"))
        except ValueError:
            return False
        return (self.now - fetched) <= timedelta(days=ADVISORY_TTL_DAYS)

    def get(self, vid):
        entry = self.entries.get(vid)
        if not entry:
            self.misses += 1
            return None
        if not self._fresh(entry):
            self.stale += 1
            return None
        self.hits += 1
        return entry.get("detail")

    def put(self, vid, detail):
        if detail is None:
            return
        self.entries[vid] = {
            "fetched_at": self.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "detail": detail,
        }

    def save(self):
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"schema": 1, "advisories": self.entries}, f, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.path)

    def stats(self):
        return {"hits": self.hits, "misses": self.misses, "stale": self.stale,
                "cached_advisories": len(self.entries), "corrupt": self.corrupt,
                "ttl_days": ADVISORY_TTL_DAYS}


def _osv_detail(vid, budget, cache=None):
    if cache is not None:
        hit = cache.get(vid)
        if hit is not None:
            return hit
    if not budget.ok():
        return None
    budget.spend()
    status, text = _retrying(lambda: net.get(f"{OSV}/v1/vulns/{quote(vid, safe='')}"))
    if status != 200:
        return None
    detail = _loads(text)
    if cache is not None:
        cache.put(vid, detail)
    return detail


def _cve_alias(vuln):
    """The CVE identifier for a vuln — for KEV/EPSS lookups, which are keyed by
    CVE. OSV's native `id` is often GHSA-… / PYSEC-… with the CVE in `aliases`;
    without this, CVE-keyed feeds silently never match OSV-sourced advisories."""
    vid = vuln.get("id", "") or ""
    if vid.startswith("CVE-"):
        return vid
    for a in vuln.get("aliases", []) or []:
        if isinstance(a, str) and a.startswith("CVE-"):
            return a
    return None


def _affected_projection(vuln):
    """Keep the whole `affected[]` shape versions.py needs to decide whether a
    version is in range: per entry the package, the enumerated `versions[]` and
    every range's `type` + raw `events[]`.

    `fixed_versions` (below) is a lossy summary — it cannot tell 'fixed in
    2.2.28 on the 2.2 line' from 'fixed in 2.2.28 for everything', which is
    exactly the distinction a minimum-safe-upgrade computation turns on."""
    out = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        entry = {
            "ecosystem": pkg.get("ecosystem"),
            "name": pkg.get("name"),
            "versions": aff.get("versions") or [],
            "ranges": [{"type": r.get("type"), "events": r.get("events") or []}
                       for r in (aff.get("ranges") or [])],
        }
        out.append(entry)
    return out


def _mk_cve(vuln):
    return {
        "id": vuln.get("id"),
        "cve": _cve_alias(vuln),
        "summary": vuln.get("summary") or vuln.get("details"),
        "cvss": _osv_cvss(vuln),
        "fixed_versions": _fixed_versions(vuln),
        "affected": _affected_projection(vuln),
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


def enrich(inventory, budget, cache=None):
    pkgs = []  # flattened, each carries its ecosystem
    for eco in inventory.get("ecosystems", []):
        for p in eco.get("packages", []):
            pkgs.append({"ecosystem": eco.get("ecosystem"), "name": p.get("name"),
                         "version": p.get("version"), "cves": [], "malicious": [],
                         # How exact the installed version is (depinv.py):
                         # lockfile/pinned are exact; declared/unparsed can only
                         # ever yield UNKNOWN in the safety verdict.
                         "resolution": p.get("resolution", "lockfile"),
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
            # Still attach a verdict — an offline run must say UNKNOWN out loud
            # rather than leave the field missing, which a renderer could read
            # as "nothing to report".
            _version_safety(pkgs)
            return pkgs
        results = (_loads(text) or {}).get("results", [])
        for p, res in zip(pkgs, results):
            for v in (res or {}).get("vulns", []) or []:
                vid = v.get("id", "")
                # Step 3/3.5: per-id detail; split MAL- from CVEs.
                if not budget.ok():
                    p["status"] = "capped"
                    break
                detail = _osv_detail(vid, budget, cache)
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
                cve = c.get("cve")   # KEV is keyed by CVE, not OSV-native id
                if cve and cve in kev_index:
                    c["kev"] = True
                    c["kev_date_added"], c["kev_due_date"] = kev_index[cve]

    _epss_enrich(pkgs, budget)
    _version_safety(pkgs)
    return pkgs


def _version_safety(pkgs):
    """Attach the VULNERABLE / SAFE / UNKNOWN verdict + minimum safe upgrade.

    This is what lets the report say which versions are vulnerable and which are
    safe. versions.py refuses to claim SAFE from an offline feed, a declared
    range, an unsupported ecosystem, or an approximate comparison — those all
    come back UNKNOWN, and the report renders them as such."""
    from secaudit import versions as _versions
    for p in pkgs:
        advisories = [{"id": c.get("id"), "cve": c.get("cve"),
                       "affected": c.get("affected") or []}
                      for c in p.get("cves") or []]
        verdict = _versions.package_status(
            p.get("version"), advisories, p.get("ecosystem"),
            resolution=p.get("resolution", "lockfile"),
            feeds_ok=p.get("status") == "ok",
            name=p.get("name"))
        # A package the feeds flagged but whose ranges we could not evaluate is
        # still vulnerable — the advisory named it. Do not let an evaluation gap
        # downgrade a positive hit to UNKNOWN.
        if verdict["status"] != "VULNERABLE" and advisories:
            mine = [aff for a in advisories
                    for aff in _versions.entries_for(a["affected"], p.get("ecosystem"),
                                                     p.get("name"))]
            verdict = {"status": "VULNERABLE",
                       "advisories": [a["id"] for a in advisories],
                       "ranges": _versions.describe_ranges(mine, p.get("ecosystem")),
                       "fixed_versions": _versions.fixed_versions(mine),
                       "note": verdict.get("reason")}
            ms, sm, _ = _versions.min_safe_version(p.get("version"), advisories,
                                                   p.get("ecosystem"), p.get("name"))
            verdict["min_safe"], verdict["min_safe_same_major"] = ms, sm
        p["version_safety"] = verdict


def _epss_enrich(pkgs, budget):
    """Step 5.6: EPSS enrichment (FIRST.org exploit-prediction). Batch the CVE
    ids by EPSS_CHUNK per GET; only CVE ids leave the machine — same privacy
    property as OSV/KEV. epss/percentile come back as strings; coerce to float.
    Feed offline (or a CVE with no EPSS row) leaves epss None — unknown is
    unknown, exactly like kev: null. Never fabricated."""
    cve_ids, seen_ids = [], set()
    for p in pkgs:
        for c in p["cves"]:
            cid = c.get("cve")   # EPSS is keyed by CVE, not OSV-native id
            if cid and cid not in seen_ids:
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
            cve = row.get("cve")
            if not cve:
                continue
            # Coerce independently: a malformed `percentile` must not discard a
            # valid `epss` reading (that would silently under-score a real
            # exploit signal). A bad `epss` leaves the CVE null — unknown.
            try:
                e = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
            try:
                pc = float(row.get("percentile"))
            except (TypeError, ValueError):
                pc = None
            epss_index[cve] = (e, pc)
    for p in pkgs:
        for c in p["cves"]:
            cve = c.get("cve")
            if cve and cve in epss_index:
                c["epss"], c["epss_percentile"] = epss_index[cve]


def main():
    # --cache <path> enables the advisory-detail cache (v1.32). Absent -> every
    # detail is fetched, exactly as before.
    cache_path = None
    argv = sys.argv[1:]
    if "--cache" in argv:
        i = argv.index("--cache")
        cache_path = argv[i + 1] if i + 1 < len(argv) else None
    raw = sys.stdin.read()
    inv = _loads(raw) or {}
    budget = Budget()
    cache = AdvisoryCache(cache_path) if cache_path else None
    out = enrich(inv, budget, cache)
    if cache is not None:
        cache.save()
    sys.stdout.write(json.dumps(out, indent=2))
    sys.stdout.write("\n")
    msg = f"cve_enricher: {len(out)} packages, {budget.n} requests"
    if cache is not None:
        st = cache.stats()
        msg += (f", cache hits={st['hits']} misses={st['misses']} "
                f"stale={st['stale']} stored={st['cached_advisories']}")
    sys.stderr.write(msg + "\n")


if __name__ == "__main__":
    main()
