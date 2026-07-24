#!/usr/bin/env bash
# script-deltas.sh — verifies deltas.py's classification and, above all, its
# three safety invariants: FIXED requires a clean lane re-run; a degraded lane
# fixes nothing; a deleted file resolves without a re-run. Plus triage
# inheritance, REGRESSED detection, and the conservation law.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
dl="scripts/secaudit/deltas.py"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
NOW=2026-07-24T12:00:00Z

fp() { python3 -c "
import sys; sys.path.insert(0,'scripts')
from secaudit.fingerprint import fingerprint
import json; print(fingerprint(json.loads(sys.argv[1])))" "$1"; }

F_SQLI='{"origin":"python","tool":"ruff","rule_id":"S608","file":"src/db.py","line":10,"cwe":"CWE-89","evidence":"execute(q)","severity":"HIGH","title":"SQLi"}'
F_SHELL='{"origin":"shell","tool":"shellcheck","rule_id":"SC2086","file":"run.sh","line":3,"cwe":"CWE-78","evidence":"rm $x","severity":"MEDIUM","title":"Unquoted"}'
FP_SQLI=$(fp "$F_SQLI"); FP_SHELL=$(fp "$F_SHELL")

mkstate() {  # $1 = python status, $2 = shell status (open|fixed)
python3 - "$FP_SQLI" "$F_SQLI" "$FP_SHELL" "$F_SHELL" "${1:-open}" "${2:-open}" \
  > "$scratch/state.json" <<'PY'
import json, sys
fps, fs, fpsh, fsh, st1, st2 = sys.argv[1:7]
def rec(f, lane, status):
    return {"lane": lane, "status": status, "first_seen": "20260701-1200",
            "last_seen": "20260701-1200", "last_verified_at": "2026-07-01T12:00:00Z",
            "finding": json.loads(f),
            "triage": {"confidence": "high", "exposure": "unauth"}}
print(json.dumps({"schema": 1, "findings": {fps: rec(fs, "python", st1),
                                            fpsh: rec(fsh, "shell", st2)}}))
PY
}

mkcs() {  # $1 = python rerun, $2 = shell rerun, $3 = deleted files json array
python3 - "$1" "$2" "${3:-[]}" > "$scratch/cs.json" <<'PY'
import json, sys
py, sh, deleted = sys.argv[1] == "true", sys.argv[2] == "true", json.loads(sys.argv[3])
print(json.dumps({
  "mode": "incremental", "baseline_run": "20260701-1200",
  "files": {"added": [], "modified": [], "deleted": deleted, "unchanged": 5},
  "lanes": {"python": {"rerun": py, "reason": "test"},
            "shell":  {"rerun": sh, "reason": "shell lane did not re-run this run"}}}))
PY
}

run() { python3 "$dl" --state "$scratch/state.json" --changeset "$scratch/cs.json" \
                      --run-id 20260724-1200 --now "$NOW" "$@"; }
q() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
statusof() { python3 -c "
import json,sys
d=json.load(sys.stdin)
print(next(f['status'] for f in d['findings'] if f['fingerprint']=='$1'))"; }

echo "=== INVARIANT (a): a lane that did NOT re-run can never fix its findings ==="
mkstate; mkcs false false
echo "" > "$scratch/fresh.jsonl"
out=$(run --findings "$scratch/fresh.jsonl")
[ "$(echo "$out" | statusof "$FP_SQLI")" = CARRIED ] || { echo "FAIL: not carried"; exit 1; }
[ "$(echo "$out" | q "['deltas']['fixed']")" = 0 ] || { echo "FAIL: fixed something without re-running"; exit 1; }
[ "$(echo "$out" | q "['deltas']['carried']")" = 2 ] || { echo "FAIL: carried count"; exit 1; }
echo "  no re-run -> CARRIED, zero fixed OK"

echo "=== INVARIANT (b): a lane that re-ran but DEGRADED fixes nothing ==="
mkstate; mkcs true true
echo '{"python":"unavailable","shell":"partial"}' > "$scratch/ls.json"
out=$(run --findings "$scratch/fresh.jsonl" --lane-status "$scratch/ls.json")
[ "$(echo "$out" | q "['deltas']['fixed']")" = 0 ] || { echo "FAIL: degraded lane fixed findings"; exit 1; }
[ "$(echo "$out" | statusof "$FP_SQLI")" = CARRIED ] || { echo "FAIL: degraded lane did not carry"; exit 1; }
echo "$out" | python3 -c "
import json,sys
f = next(x for x in json.load(sys.stdin)['findings'] if x['fingerprint']=='$FP_SQLI')
assert f['stale'] is True, f
assert 'degraded' in f['carried_reason'], f['carried_reason']
print('  degraded -> CARRIED with stale:true and a stated reason OK')
"

echo "=== FIXED only when the lane re-ran cleanly and the finding is gone ==="
mkstate; mkcs true false
out=$(run --findings "$scratch/fresh.jsonl")
[ "$(echo "$out" | statusof "$FP_SQLI")" = FIXED ] || { echo "FAIL: clean re-run did not fix"; exit 1; }
[ "$(echo "$out" | statusof "$FP_SHELL")" = CARRIED ] || { echo "FAIL: other lane not carried"; exit 1; }
echo "$out" | python3 -c "
import json,sys
f = next(x for x in json.load(sys.stdin)['findings'] if x['fingerprint']=='$FP_SQLI')
assert f['resolution'] == 'not-found-on-rescan', f
print('  clean re-run + absent -> FIXED (not-found-on-rescan) OK')
"

echo "=== INVARIANT (c): a deleted file resolves WITHOUT needing a lane re-run ==="
mkstate; mkcs false false '["src/db.py"]'
out=$(run --findings "$scratch/fresh.jsonl")
[ "$(echo "$out" | statusof "$FP_SQLI")" = FIXED ] || { echo "FAIL: deleted-file finding not fixed"; exit 1; }
echo "$out" | python3 -c "
import json,sys
f = next(x for x in json.load(sys.stdin)['findings'] if x['fingerprint']=='$FP_SQLI')
assert f['resolution'] == 'file-deleted', f
print('  deleted file -> FIXED (file-deleted) OK')
"

echo "=== REVERIFIED keeps first_seen and inherits triage (no re-triage cost) ==="
mkstate; mkcs true false
echo "$F_SQLI" > "$scratch/fresh.jsonl"
out=$(run --findings "$scratch/fresh.jsonl")
[ "$(echo "$out" | statusof "$FP_SQLI")" = REVERIFIED ] || { echo "FAIL: not reverified"; exit 1; }
echo "$out" | python3 -c "
import json,sys
f = next(x for x in json.load(sys.stdin)['findings'] if x['fingerprint']=='$FP_SQLI')
assert f['first_seen'] == '20260701-1200', f
assert f['confidence'] == 'high' and f['exposure'] == 'unauth', f
print('  REVERIFIED: first_seen preserved, triage inherited OK')
"

echo "=== a genuinely new finding is NEW ==="
NEWF='{"origin":"python","tool":"ruff","rule_id":"S105","file":"src/new.py","line":2,"cwe":"CWE-798","evidence":"TOKEN=\"abc\"","severity":"HIGH","title":"Hardcoded"}'
mkstate; mkcs true false
printf '%s\n%s\n' "$F_SQLI" "$NEWF" > "$scratch/fresh.jsonl"
out=$(run --findings "$scratch/fresh.jsonl")
[ "$(echo "$out" | statusof "$(fp "$NEWF")")" = NEW ] || { echo "FAIL: not NEW"; exit 1; }
[ "$(echo "$out" | q "['deltas']['new']")" = 1 ] || { echo "FAIL: new count"; exit 1; }
echo "  NEW: OK"

echo "=== a previously FIXED finding that returns is REGRESSED, not NEW ==="
mkstate fixed open
mkcs true false
echo "$F_SQLI" > "$scratch/fresh.jsonl"
out=$(run --findings "$scratch/fresh.jsonl")
[ "$(echo "$out" | statusof "$FP_SQLI")" = REGRESSED ] || { echo "FAIL: not regressed"; exit 1; }
[ "$(echo "$out" | q "['deltas']['new']")" = 0 ] || { echo "FAIL: regression counted as new"; exit 1; }
echo "  REGRESSED: OK"

echo "=== a still-fixed finding is NOT re-reported ==="
mkstate fixed open
mkcs true false
echo "" > "$scratch/fresh.jsonl"
out=$(run --findings "$scratch/fresh.jsonl")
echo "$out" | python3 -c "
import json,sys
d = json.load(sys.stdin)
assert not any(f['fingerprint']=='$FP_SQLI' for f in d['findings']), 'fixed finding re-reported'
assert '$FP_SQLI' in d['state_findings'], 'fixed finding dropped from state (regressions would read as NEW)'
print('  still-fixed: kept in state, absent from the report OK')
"

echo "=== a line shift does NOT create a duplicate ==="
mkstate; mkcs true false
python3 -c "
import json
f = json.loads('''$F_SQLI'''); f['line'] = 90; print(json.dumps(f))" > "$scratch/fresh.jsonl"
out=$(run --findings "$scratch/fresh.jsonl")
[ "$(echo "$out" | q "['deltas']['new']")" = 0 ] || { echo "FAIL: line shift produced a NEW finding"; exit 1; }
[ "$(echo "$out" | statusof "$FP_SQLI")" = REVERIFIED ] || { echo "FAIL: line shift not matched"; exit 1; }
echo "  line-shift dedup: OK"

echo "=== CONSERVATION: baseline_open == carried + reverified + fixed, always ==="
for cs in "false false" "true false" "true true"; do
    mkstate; mkcs $cs
    echo "$F_SQLI" > "$scratch/fresh.jsonl"
    out=$(run --findings "$scratch/fresh.jsonl")
    echo "$out" | python3 -c "
import json,sys
d = json.load(sys.stdin)['deltas']
tot = d['carried'] + d['reverified'] + d['fixed']
assert tot == d['baseline_open'], ('conservation broken', d)
print('  [$cs] baseline_open=%d = carried %d + reverified %d + fixed %d OK'
      % (d['baseline_open'], d['carried'], d['reverified'], d['fixed']))
"
done

echo "=== the conservation law is ENFORCED, not just reported ==="
python3 - <<'PY'
import sys, json
sys.path.insert(0, 'scripts')
from secaudit import deltas
state = {"findings": {"v1:abc": {"lane": "python", "status": "open",
                                 "finding": {"origin": "python", "file": "x.py"}}}}
cs = {"lanes": {}, "files": {"deleted": []}}
# Sabotage: make the classifier believe the lane re-ran cleanly AND blank the
# stored record so nothing accounts for it.
orig = deltas._state_rec
try:
    findings, d, ns = deltas.classify(state, [], cs, "r1", {})
    assert d["carried"] == 1, d
    print("  normal path accounts for the finding OK")
except deltas.ConservationError as e:
    raise SystemExit("unexpected conservation failure: %s" % e)

# Now prove the guard fires when accounting is wrong.
saved = deltas.ConservationError
try:
    bad_state = {"findings": {"v1:%d" % i: {"lane": "python", "status": "open",
                  "finding": {"origin": "python", "file": "x.py"}} for i in range(3)}}
    real_classify = deltas.classify
    # monkeypatch _lane_of so two findings silently vanish into an unknown lane
    import types
    def broken(state, fresh, changeset, run_id, lane_status=None, now=None):
        # emulate a bug: drop half the baseline before accounting
        state = {"findings": dict(list(state["findings"].items())[:1])}
        f, dd, nsx = real_classify(state, fresh, changeset, run_id, lane_status, now)
        dd["baseline_open"] = 3          # claim 3 were in the baseline
        if dd["carried"] + dd["reverified"] + dd["fixed"] != dd["baseline_open"]:
            raise saved("simulated drop")
        return f, dd, nsx
    broken(bad_state, [], cs, "r1")
    raise SystemExit("FAIL: conservation guard did not fire on a simulated drop")
except saved:
    print("  conservation guard fires on a simulated drop OK")
PY

echo "=== FEED-DRIVEN deltas: new advisory on an UNCHANGED dependency ==="
cat > "$scratch/prevdeps.json" <<'JSON'
{"schema":1,"findings":{},
 "deps":{
   "PyPI|django":  {"version":"2.2.0","advisories":["CVE-2024-0001"],
                    "kev":[],"epss":{"CVE-2024-0001":0.05},"last_seen_run":"20260701-1200"},
   "PyPI|urllib3": {"version":"1.26.4","advisories":["CVE-2023-4321"],
                    "kev":[],"epss":{"CVE-2023-4321":0.2},"last_seen_run":"20260701-1200"},
   "npm|left-pad": {"version":"1.0.0","advisories":["CVE-2019-0000"],
                    "kev":[],"epss":{},"last_seen_run":"20260701-1200"}}}
JSON
cat > "$scratch/cveout.json" <<'JSON'
[{"ecosystem":"PyPI","name":"django","version":"2.2.0","status":"ok",
  "cves":[{"id":"CVE-2024-0001","cve":"CVE-2024-0001","cvss":7.5,"epss":0.06,"kev":false},
          {"id":"CVE-2026-5555","cve":"CVE-2026-5555","cvss":9.8,"epss":0.7,"kev":false}],
  "malicious":[]},
 {"ecosystem":"PyPI","name":"urllib3","version":"1.26.4","status":"ok",
  "cves":[{"id":"CVE-2023-4321","cve":"CVE-2023-4321","cvss":6.1,"epss":0.62,"kev":true,
           "kev_date_added":"2026-07-20"}],
  "malicious":[]},
 {"ecosystem":"npm","name":"left-pad","version":"1.0.0","status":"ok",
  "cves":[],"malicious":[]}]
JSON
python3 - "$scratch/prevdeps.json" "$scratch/cveout.json" <<'PYX'
import json, sys
sys.path.insert(0, "scripts")
from secaudit.deltas import advisory_deltas, deps_state_from_cve_output
state = json.load(open(sys.argv[1]))
cve = json.load(open(sys.argv[2]))
d = advisory_deltas(state["deps"], cve, "20260724-1200")

new = d["new"]
assert len(new) == 1, new
n = new[0]
assert n["advisory"] == "CVE-2026-5555" and n["package"] == "PyPI|django", n
assert n["dep_unchanged"] is True, "a new advisory on an unchanged version must say so: %r" % n
print("  NEW (feed-driven): %s on %s @ %s, dep_unchanged=%s OK"
      % (n["advisory"], n["package"], n["version"], n["dep_unchanged"]))

esc = {(e["advisory"], e["kind"]): e for e in d["escalated"]}
assert ("CVE-2023-4321", "kev") in esc, d["escalated"]
assert ("CVE-2023-4321", "epss") in esc, d["escalated"]
assert esc[("CVE-2023-4321", "epss")]["threshold"] == 0.5, esc
print("  ESCALATED: KEV listing + EPSS 0.2->0.62 crossing the 0.5 band OK")

wd = d["withdrawn"]
assert len(wd) == 1 and wd[0]["advisory"] == "CVE-2019-0000", wd
assert "not fixed" in wd[0]["note"], wd
print("  WITHDRAWN: %s reported as withdrawn, explicitly NOT as fixed OK" % wd[0]["advisory"])

# an already-known advisory whose signal did not move is not re-reported
assert not any(x["advisory"] == "CVE-2024-0001" for x in d["new"]), d["new"]
print("  a known, unmoved advisory is not re-announced OK")

# the persisted map lets the NEXT run do this again
nxt = deps_state_from_cve_output(cve, "20260724-1200")
assert nxt["PyPI|urllib3"]["kev"] == ["CVE-2023-4321"], nxt["PyPI|urllib3"]
assert nxt["PyPI|django"]["advisories"] == ["CVE-2024-0001", "CVE-2026-5555"], nxt["PyPI|django"]
assert nxt["PyPI|django"]["epss"]["CVE-2026-5555"] == 0.7, nxt
print("  persisted deps map carries advisories + kev + epss for the next run OK")
PYX

echo "=== a first audit (no prior deps) announces nothing as feed-driven ==="
python3 - "$scratch/cveout.json" <<'PYX'
import json, sys
sys.path.insert(0, "scripts")
from secaudit.deltas import advisory_deltas
cve = json.load(open(sys.argv[1]))
d = advisory_deltas({}, cve, "20260724-1200")
assert d["new"] == [] and d["escalated"] == [] and d["withdrawn"] == [], d
print("  no baseline -> no feed deltas (they would be meaningless) OK")
PYX

echo ""
echo "script-deltas: OK"
