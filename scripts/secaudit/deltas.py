#!/usr/bin/env python3
"""Merge carried-forward findings with fresh ones and classify each (§5.5).

Every finding in a re-audit gets exactly one status:

  NEW        not in the baseline
  REVERIFIED in the baseline, its lane re-ran, still found
  CARRIED    in the baseline, its lane did NOT re-run (or ran degraded) — the
             finding stands, but this run did not re-check it, and the report
             says so
  FIXED      in the baseline, its lane re-ran cleanly, and it is gone
  REGRESSED  previously FIXED, and it is back

Three safety invariants, because the way incremental auditing fails is by
quietly dropping a real finding:

  (a) A finding may be marked FIXED **only if the lane that produced it actually
      re-ran and completed `ok`.** Not re-running is not evidence of absence.
  (b) A lane that re-ran but degraded (tool missing / partial) carries its
      findings forward with `stale: true` and fixes nothing — a scanner that
      could not run has not cleared anything.
  (c) A finding whose file was deleted is FIXED without needing a lane re-run:
      the code that carried it is gone, which IS evidence.

And the conservation law, checked on every run: every baseline finding that was
open comes out as exactly one of CARRIED / REVERIFIED / FIXED. If that sum ever
disagrees with the baseline count, we lost one — that is a hard error, not a
warning.

Usage:
  deltas.py --state <state.json> --changeset <changeset.json> --run-id <id>
            [--findings <fresh.jsonl>] [--lane-status <json>] [--now <ISO>]
"""
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secaudit.fingerprint import fingerprint  # noqa: E402

TRIAGE_FIELDS = ("confidence", "fp_suspected", "triage_notes", "exposure", "auth_required")


class ConservationError(Exception):
    """A baseline finding was neither carried, re-verified nor resolved."""


def _now_iso(now=None):
    return (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lane_of(finding):
    return finding.get("origin") or "unknown"


def _file_of(finding):
    return finding.get("file") or finding.get("path") or ""


def classify(state, fresh, changeset, run_id, lane_status=None, now=None):
    """Return (findings, deltas, state_findings)."""
    lane_status = lane_status or {}
    stored = dict(state.get("findings") or {})
    lanes = changeset.get("lanes") or {}
    deleted_files = set((changeset.get("files") or {}).get("deleted") or [])
    ts = _now_iso(now)

    def lane_reran_cleanly(lane):
        """Invariants (a) + (b): only a lane that re-ran AND finished `ok` is
        allowed to resolve findings."""
        entry = lanes.get(lane)
        if not entry or not entry.get("rerun"):
            return False
        return lane_status.get(lane, "ok") == "ok"

    fresh_by_fp = {}
    for f in fresh or []:
        fp = f.get("fingerprint") or fingerprint(f)
        g = dict(f)
        g["fingerprint"] = fp
        fresh_by_fp[fp] = g

    out = []
    new_state = {}
    counts = {"new": 0, "reverified": 0, "carried": 0, "fixed": 0, "regressed": 0}
    baseline_open = 0
    accounted = 0

    # --- baseline findings ---------------------------------------------------
    for fp, rec in stored.items():
        finding = dict(rec.get("finding") or {})
        lane = rec.get("lane") or _lane_of(finding)
        prev_status = rec.get("status", "open")
        was_open = prev_status != "fixed"
        if was_open:
            baseline_open += 1

        if fp in fresh_by_fp:
            g = dict(fresh_by_fp[fp])
            # A re-verified finding inherits triage the human/triager already
            # did, so unchanged findings are not re-triaged every run.
            for k in TRIAGE_FIELDS:
                if k not in g and k in (rec.get("triage") or {}):
                    g[k] = rec["triage"][k]
            g["status"] = "REGRESSED" if prev_status == "fixed" else "REVERIFIED"
            g["first_seen"] = rec.get("first_seen", run_id)
            g["last_seen"] = run_id
            g["last_verified_at"] = ts
            if g["status"] == "REGRESSED":
                g["previously_fixed_in"] = rec.get("fixed_in_run")
                counts["regressed"] += 1
            else:
                counts["reverified"] += 1
                accounted += 1
            out.append(g)
            new_state[fp] = _state_rec(g, lane, "open", rec, run_id, ts)
            continue

        if prev_status == "fixed":
            # Still fixed; keep it in state so a future reappearance is a
            # REGRESSION rather than a NEW finding, but do not report it again.
            new_state[fp] = rec
            continue

        # invariant (c): the file it lived in is gone
        if _file_of(finding) and _file_of(finding) in deleted_files:
            g = dict(finding)
            g.update({"fingerprint": fp, "status": "FIXED",
                      "resolution": "file-deleted",
                      "first_seen": rec.get("first_seen"), "last_seen": rec.get("last_seen"),
                      "fixed_in_run": run_id, "fixed_at": ts})
            counts["fixed"] += 1
            accounted += 1
            out.append(g)
            new_state[fp] = _state_rec(g, lane, "fixed", rec, run_id, ts)
            continue

        # invariants (a) + (b): absence only counts if the lane really looked
        if lane_reran_cleanly(lane):
            g = dict(finding)
            g.update({"fingerprint": fp, "status": "FIXED",
                      "resolution": "not-found-on-rescan",
                      "first_seen": rec.get("first_seen"), "last_seen": rec.get("last_seen"),
                      "fixed_in_run": run_id, "fixed_at": ts})
            counts["fixed"] += 1
            accounted += 1
            out.append(g)
            new_state[fp] = _state_rec(g, lane, "fixed", rec, run_id, ts)
            continue

        # otherwise: carried, with an explicit statement of why it was not re-checked
        entry = lanes.get(lane) or {}
        degraded = entry.get("rerun") and lane_status.get(lane, "ok") != "ok"
        g = dict(finding)
        for k in TRIAGE_FIELDS:
            if k not in g and k in (rec.get("triage") or {}):
                g[k] = rec["triage"][k]
        g.update({
            "fingerprint": fp,
            "status": "CARRIED",
            "stale": bool(degraded),
            "carried_reason": (
                f"{lane} lane ran but degraded ({lane_status.get(lane)}) — findings "
                "carried unverified" if degraded
                else entry.get("reason", f"{lane} lane did not re-run this run")),
            "first_seen": rec.get("first_seen"),
            "last_seen": rec.get("last_seen"),
            "last_verified_at": rec.get("last_verified_at"),
        })
        counts["carried"] += 1
        accounted += 1
        out.append(g)
        new_state[fp] = _state_rec(g, lane, "open", rec, run_id, ts, touch=False)

    # --- fresh findings not in the baseline ----------------------------------
    for fp, g in fresh_by_fp.items():
        if fp in stored:
            continue
        h = dict(g)
        h.update({"status": "NEW", "first_seen": run_id, "last_seen": run_id,
                  "last_verified_at": ts})
        counts["new"] += 1
        out.append(h)
        new_state[fp] = _state_rec(h, _lane_of(h), "open", None, run_id, ts)

    if accounted != baseline_open:
        raise ConservationError(
            f"baseline had {baseline_open} open finding(s) but only {accounted} were "
            f"accounted for (carried={counts['carried']} reverified={counts['reverified']} "
            f"fixed={counts['fixed']}). A finding would have been silently dropped.")

    deltas = dict(counts)
    deltas["baseline_open"] = baseline_open
    deltas["total_open"] = counts["new"] + counts["reverified"] + counts["carried"] + counts["regressed"]
    return out, deltas, new_state


def _state_rec(finding, lane, status, prev, run_id, ts, touch=True):
    rec = {
        "lane": lane,
        "status": status,
        "first_seen": finding.get("first_seen") or (prev or {}).get("first_seen") or run_id,
        "last_seen": run_id if touch else (prev or {}).get("last_seen"),
        "last_verified_at": ts if touch else (prev or {}).get("last_verified_at"),
        "finding": {k: v for k, v in finding.items()
                    if k not in ("status", "stale", "carried_reason", "resolution")},
        "triage": {k: finding[k] for k in TRIAGE_FIELDS if k in finding},
    }
    if status == "fixed":
        rec["fixed_in_run"] = finding.get("fixed_in_run", run_id)
        rec["resolution"] = finding.get("resolution")
    return rec


def advisory_deltas(prev_deps, cve_output, run_id):
    """Classify what the FEEDS changed since the last audit (§5.2, v1.32).

    This is the half of incrementality a file hash can never see: the code did
    not move, but the world's knowledge about it did. Three classes:

      NEW (feed-driven)  an advisory now returned for a package whose version
                         did NOT change — i.e. an unchanged dependency became
                         known-vulnerable. This is the highest-value output of a
                         re-audit.
      ESCALATED          an already-known advisory whose severity signal moved:
                         added to CISA KEV, or EPSS crossing a scoring threshold.
                         A MEDIUM you triaged last month and CISA added to KEV
                         yesterday is not the same finding.
      WITHDRAWN          an advisory the feeds no longer return. Reported as
                         withdrawn, NOT as fixed — nothing about the code
                         changed, so calling it fixed would be a lie.

    `prev_deps` is the state's `deps` map: {"eco|name": {version, advisories:[],
    kev:[], epss:{}}}.
    """
    prev_deps = prev_deps or {}
    out = {"new": [], "escalated": [], "withdrawn": [], "unchanged": 0}
    # Thresholds mirror score.py's exploit sub-score bands: crossing one of
    # these changes the finding's priority, so it is worth telling the user.
    bands = (0.5, 0.1)

    for pkg in cve_output or []:
        key = f"{pkg.get('ecosystem')}|{pkg.get('name')}"
        prev = prev_deps.get(key) or {}
        prev_ids = set(prev.get("advisories") or [])
        prev_kev = set(prev.get("kev") or [])
        prev_epss = prev.get("epss") or {}
        version_changed = bool(prev) and prev.get("version") != pkg.get("version")
        now_ids = set()

        for c in (pkg.get("cves") or []) + (pkg.get("malicious") or []):
            vid = c.get("id")
            if not vid:
                continue
            now_ids.add(vid)
            if prev and vid not in prev_ids:
                out["new"].append({
                    "package": key, "version": pkg.get("version"), "advisory": vid,
                    "cve": c.get("cve"), "cvss": c.get("cvss"),
                    "dep_unchanged": not version_changed,
                    "since": prev.get("last_seen_run"),
                    "first_seen": run_id,
                })
                continue
            if not prev:
                continue
            # already known — did its exploit signal move?
            if c.get("kev") and vid not in prev_kev:
                out["escalated"].append({
                    "package": key, "advisory": vid, "kind": "kev",
                    "from": "not in KEV", "to": "CISA KEV",
                    "kev_date_added": c.get("kev_date_added")})
            old_e, new_e = prev_epss.get(vid), c.get("epss")
            if isinstance(new_e, (int, float)) and isinstance(old_e, (int, float)):
                for b in bands:
                    if new_e >= b > old_e:
                        out["escalated"].append({
                            "package": key, "advisory": vid, "kind": "epss",
                            "from": old_e, "to": new_e, "threshold": b})
                        break
        if prev:
            for vid in sorted(prev_ids - now_ids):
                out["withdrawn"].append({
                    "package": key, "advisory": vid,
                    "note": "no longer returned by the feeds — withdrawn, not fixed"})
            if not (prev_ids ^ now_ids):
                out["unchanged"] += 1
    return out


def deps_state_from_cve_output(cve_output, run_id):
    """The `deps` map to persist so the NEXT run can compute advisory deltas."""
    out = {}
    for pkg in cve_output or []:
        key = f"{pkg.get('ecosystem')}|{pkg.get('name')}"
        cves = (pkg.get("cves") or []) + (pkg.get("malicious") or [])
        out[key] = {
            "version": pkg.get("version"),
            "resolution": pkg.get("resolution"),
            "advisories": sorted({c["id"] for c in cves if c.get("id")}),
            "kev": sorted({c["id"] for c in cves if c.get("kev") and c.get("id")}),
            "epss": {c["id"]: c["epss"] for c in cves
                     if c.get("id") and isinstance(c.get("epss"), (int, float))},
            "status": pkg.get("status"),
            "last_seen_run": run_id,
        }
    return out


def _read_findings(path):
    if not path:
        return []
    raw = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("["):
        return json.loads(raw)
    return [json.loads(ln) for ln in raw.splitlines() if ln.strip()]


def main(argv):
    args = {}
    i = 1
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            key = a[2:]
            if "=" in key:
                key, val = key.split("=", 1)
            else:
                i += 1
                val = argv[i] if i < len(argv) else ""
            args[key] = val
        i += 1
    if "changeset" not in args or "run-id" not in args:
        sys.stderr.write("usage: deltas.py --state <f> --changeset <f> --run-id <id> "
                         "[--findings <f>] [--lane-status <f>] [--cve-output <f>] "
                         "[--now ISO]\n")
        return 2

    state = json.load(open(args["state"], encoding="utf-8")) if args.get("state") and \
        os.path.exists(args["state"]) else {}
    changeset = json.load(open(args["changeset"], encoding="utf-8"))
    fresh = _read_findings(args.get("findings"))
    lane_status = json.load(open(args["lane-status"], encoding="utf-8")) \
        if args.get("lane-status") else {}
    now = None
    if args.get("now"):
        now = datetime.fromisoformat(args["now"].replace("Z", "+00:00"))

    try:
        findings, deltas, new_state = classify(state, fresh, changeset,
                                               args["run-id"], lane_status, now)
    except ConservationError as e:
        sys.stderr.write(f"deltas: CONSERVATION FAILURE — {e}\n")
        return 5
    doc = {"findings": findings, "deltas": deltas, "state_findings": new_state}
    if args.get("cve-output") and os.path.exists(args["cve-output"]):
        cve_out = json.load(open(args["cve-output"], encoding="utf-8"))
        doc["advisory_deltas"] = advisory_deltas(state.get("deps"), cve_out,
                                                 args["run-id"])
        doc["state_deps"] = deps_state_from_cve_output(cve_out, args["run-id"])
    sys.stdout.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
