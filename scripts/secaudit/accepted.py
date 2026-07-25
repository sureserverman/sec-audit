#!/usr/bin/env python3
"""Accepted-risk register: user-declared suppressions keyed by v1 fingerprint.

A finding the maintainer has explicitly accepted renders as ACCEPTED instead of
re-appearing at full severity every run. This is the ONE place in sec-audit where
a human can lower the volume of a report, so every rule here is written to make
the suppression visible, bounded and reversible rather than silent:

  * Expiry is MANDATORY. An acceptance with no `expires` is not an acceptance,
    it is a permanent blind spot — such an entry is rejected with a warning and
    its finding keeps full severity.
  * A CRITICAL finding may be accepted for at most 30 days per acceptance
    (`CRITICAL_MAX_DAYS`). A longer `expires` is CLAMPED down, not honoured, and
    the report says it was clamped. Renewing is a deliberate act, so "accept a
    CRITICAL and forget" cannot happen.
  * Nothing here can ever REMOVE a finding. Acceptance rewrites `status` and
    records the original in `suppressed_status`; the finding stays in the
    pipeline, stays in the state store, and stays counted.
  * A register this module cannot read NEVER fails the audit and NEVER silently
    disappears: it degrades to "no acceptances" plus a loud warning. Refusing to
    audit because a suppression file is corrupt would be a worse failure than
    ignoring it; hiding the corruption would be worse still.

Register format (`<state_home>/accepted.json`), hand-editable:

  {"schema": 1,
   "accepted": [
     {"fingerprint": "v1:<64 hex>",     # exact match, from the report
      "reason":      "why this is acceptable here",
      "accepted":    "2026-07-01",      # date the call was made
      "expires":     "2026-10-01",      # inclusive; MANDATORY
      "accepted_by": "alice"}]}         # optional, free text

Pure stdlib. No network. Never writes.
"""
import json
import os
import re
import sys
from datetime import date, timedelta

SCHEMA = 1
CRITICAL_MAX_DAYS = 30
FP_RE = re.compile(r"^v1:[0-9a-f]{64}$")
REQUIRED = ("fingerprint", "reason", "accepted", "expires")
# Severities that may be accepted for the full requested window. CRITICAL is
# absent by design, and so is anything unrecognised — see effective_expiry().
UNCAPPED_SEVERITIES = frozenset({"HIGH", "MEDIUM", "LOW", "INFO"})


def _parse_date(v):
    if not isinstance(v, str):
        return None
    try:
        return date.fromisoformat(v)
    except ValueError:
        return None


def load(path, now=None):
    """Read and validate the register. NEVER raises, NEVER returns partial junk.

    Returns {"entries": {fp: entry}, "warnings": [str], "expired": [entry],
             "present": bool}. `entries` holds only entries that are structurally
    valid AND not yet expired — everything else is surfaced, not dropped.
    """
    today = now or date.today()
    out = {"entries": {}, "warnings": [], "expired": [], "present": False}
    if not path or not os.path.exists(path):
        return out
    out["present"] = True
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        # Loud, single, non-fatal: the audit proceeds with zero acceptances.
        out["warnings"].append(
            f"accepted.json is unreadable ({e}) — ALL acceptances ignored this "
            f"run; every accepted finding is reported at full severity")
        return out

    if not isinstance(doc, dict):
        out["warnings"].append(
            "accepted.json must be a JSON object with an `accepted` list — "
            "ALL acceptances ignored this run")
        return out
    schema = doc.get("schema")
    if schema is not None and schema != SCHEMA:
        out["warnings"].append(
            f"accepted.json schema {schema} is not supported (expected {SCHEMA}) "
            f"— ALL acceptances ignored this run")
        return out
    rows = doc.get("accepted")
    if not isinstance(rows, list):
        out["warnings"].append(
            "accepted.json has no `accepted` list — ALL acceptances ignored")
        return out

    for i, entry in enumerate(rows):
        label = f"accepted[{i}]"
        if not isinstance(entry, dict):
            out["warnings"].append(f"{label}: not an object — entry ignored")
            continue
        fp = entry.get("fingerprint")
        if isinstance(fp, str):
            label = f"accepted[{i}] ({fp[:15]}…)"
        # Validate by TYPE, not truthiness. This file is hand-edited, so a
        # forgotten quote ("fingerprint": 123) or a YAML-ish list is expected
        # input, not an impossible one — and a TypeError escaping here would
        # abort the whole audit, the one thing this module promises never to do.
        missing = [k for k in REQUIRED
                   if not isinstance(entry.get(k), str) or not entry[k].strip()]
        if missing:
            wrong_type = [k for k in missing if entry.get(k) is not None
                          and not isinstance(entry.get(k), str)]
            detail = (f" ({', '.join(wrong_type)} must be a quoted string)"
                      if wrong_type else "")
            out["warnings"].append(
                f"{label}: missing or non-string required field(s) "
                f"{', '.join(missing)}{detail} — entry ignored, finding keeps "
                f"full severity"
                + (" (expiry is mandatory)" if "expires" in missing else ""))
            continue
        if not FP_RE.match(fp):
            out["warnings"].append(
                f"{label}: fingerprint is not a v1 fingerprint (`v1:` + 64 hex) — "
                f"entry ignored")
            continue
        d_acc, d_exp = _parse_date(entry["accepted"]), _parse_date(entry["expires"])
        if d_acc is None or d_exp is None:
            bad = "accepted" if d_acc is None else "expires"
            out["warnings"].append(
                f"{label}: `{bad}` is not an ISO date (YYYY-MM-DD) — entry ignored")
            continue
        if d_exp < d_acc:
            out["warnings"].append(
                f"{label}: expires ({d_exp}) precedes accepted ({d_acc}) — entry ignored")
            continue
        by = entry.get("accepted_by")
        rec = {"fingerprint": fp, "reason": str(entry["reason"]).strip(),
               "accepted": d_acc.isoformat(), "expires": d_exp.isoformat(),
               # optional + free text, but still normalised to a string so a
               # mis-typed value cannot reach the report as a list or number
               "accepted_by": by.strip() if isinstance(by, str) else ""}
        if d_exp < today:
            rec["expired_on"] = d_exp.isoformat()
            out["expired"].append(rec)
            continue
        if fp in out["entries"]:
            out["warnings"].append(
                f"{label}: duplicate fingerprint — the later entry wins")
        out["entries"][fp] = rec
    return out


def effective_expiry(entry, severity):
    """Expiry actually enforced. CRITICAL acceptances are capped at
    CRITICAL_MAX_DAYS from the date the call was made — a longer `expires` is
    clamped, never honoured. Returns (date, clamped: bool)."""
    exp = _parse_date(entry["expires"])
    # `severity` arrives from the findings stream, not the register. A lane
    # emitting a non-string or unknown severity must not take acceptance
    # processing down with it — but it must not buy an UNCAPPED suppression
    # either. Only a recognised non-critical severity skips the cap; anything
    # unrecognised is capped, because capping merely makes the finding resurface
    # sooner, while wrongly skipping the cap hides a possible CRITICAL for as
    # long as the file says.
    sev = severity.upper() if isinstance(severity, str) else ""
    if sev in UNCAPPED_SEVERITIES:
        return exp, False
    cap = _parse_date(entry["accepted"]) + timedelta(days=CRITICAL_MAX_DAYS)
    if exp > cap:
        return cap, True
    return exp, False


def apply(findings, register, now=None):
    """Overlay ACCEPTED onto matching findings, in place on copies.

    Returns (findings, info). A finding is never dropped: its prior delta status
    moves to `suppressed_status` so the report and the state store keep it.
    """
    today = now or date.today()
    entries = register.get("entries") or {}
    info = {"accepted": 0, "clamped": [], "lapsed": [],
            "expired": list(register.get("expired") or []),
            "warnings": list(register.get("warnings") or [])}
    out = []
    for f in findings:
        fp = f.get("fingerprint")
        entry = entries.get(fp) if fp else None
        if not entry:
            out.append(f)
            continue
        exp, clamped = effective_expiry(entry, f.get("severity"))
        if exp < today:
            # The clamp expired it even though the file says otherwise. Report
            # it as a live finding and say why the acceptance did not apply.
            info["lapsed"].append({
                "fingerprint": fp, "title": f.get("title") or f.get("id"),
                "severity": f.get("severity"), "expires": entry["expires"],
                "enforced_expiry": exp.isoformat(), "clamped": clamped})
            out.append(f)
            continue
        g = dict(f)
        g["suppressed_status"] = f.get("status")
        g["status"] = "ACCEPTED"
        g["accepted_reason"] = entry["reason"]
        g["accepted_on"] = entry["accepted"]
        g["accepted_expires"] = exp.isoformat()
        g["accepted_by"] = entry["accepted_by"]
        if clamped:
            g["accepted_clamped_from"] = entry["expires"]
            info["clamped"].append({
                "fingerprint": fp, "title": f.get("title") or f.get("id"),
                "requested": entry["expires"], "enforced": exp.isoformat()})
        info["accepted"] += 1
        out.append(g)
    return out, info


def _read_findings(path):
    """Read the findings JSONL. Unlike the register, a broken findings file is
    a WIRING bug, not user input — so it fails, but with a one-line diagnostic
    instead of a traceback. Degrading to "no findings" here would silently
    report zero acceptances over a real finding set, which is the failure mode
    this module exists to prevent."""
    if not path:
        return []
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise SystemExit(
                        f"accepted.py: {path}:{n} is not valid JSON ({e}) — "
                        f"refusing to process a partial findings stream")
    except OSError as e:
        raise SystemExit(f"accepted.py: cannot read findings file {path}: {e}")
    return rows


def main(argv):
    args, i = {}, 1
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
    if "register" not in args:
        sys.stderr.write(
            "usage: accepted.py --register <accepted.json> [--findings <f.jsonl>] "
            "[--now YYYY-MM-DD]\n")
        return 2
    now = None
    if args.get("now"):
        now = _parse_date(args["now"])
        if now is None:
            # --now exists for deterministic runs; silently falling back to the
            # wall clock would make a caller's typo look like a passing test.
            sys.stderr.write(
                f"accepted.py: --now={args['now']!r} is not an ISO date "
                f"(YYYY-MM-DD)\n")
            return 2
    reg = load(args["register"], now)
    findings, info = apply(_read_findings(args.get("findings")), reg, now)
    doc = {"entries": len(reg["entries"]), "warnings": reg["warnings"],
           "expired": reg["expired"], "info": info}
    if args.get("findings"):
        doc["findings"] = findings
    sys.stdout.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
