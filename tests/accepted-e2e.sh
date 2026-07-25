#!/usr/bin/env bash
# accepted-e2e.sh — the accepted-risk register's full lifecycle over the real
# scripts, in a sandboxed state home (BL-004).
#
#   run 1  baseline audit                          -> findings open, no register
#   run 2  after the maintainer writes accepted.json -> HIGH and CRITICAL both
#                                                     ACCEPTED, the CRITICAL's
#                                                     expiry clamped to 30 days,
#                                                     severity buckets shrink
#   run 3  simulated post-expiry (--now past both) -> both back at full severity
#                                                     carrying previously_accepted
#
# What this defends that the unit suites cannot: that acceptance survives a REAL
# state round-trip through statestore, that an accepted finding is still stored
# `open` (so it is never mistaken for resolved), and that the suppression really
# does lapse on its own without anyone editing the file.
#
# Hermetic: statehome + statestore + fingerprint + deltas + accepted + score only.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
S=scripts/secaudit
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
export SECAUDIT_PORTFOLIO_ROOT="$scratch/vault/Portfolio"
export SECAUDIT_DEV_ROOT="$scratch/dev"
export SECAUDIT_REGISTRY="$scratch/registry.yaml"
mkdir -p "$SECAUDIT_PORTFOLIO_ROOT" "$scratch/dev/web"

target="$scratch/dev/web/demo"
mkdir -p "$target/src"
cat > "$SECAUDIT_REGISTRY" <<YAML
version: 1
projects:
  - path: $target
    name: demo
    area: web
    enabled: true
YAML
printf 'q = "select 1"\n' > "$target/src/db.py"
printf 'PW = "hunter2"\n' > "$target/src/cfg.py"

home=$(python3 "$S/statehome.py" "$target" | python3 -c "import json,sys; print(json.load(sys.stdin)['home'])")
mkdir -p "$home"
echo "state home: ${home#$scratch/}"

F_HIGH='{"origin":"python","tool":"ruff","rule_id":"S608","file":"src/db.py","line":1,"cwe":"CWE-89","evidence":"select 1","severity":"HIGH","title":"SQLi"}'
F_CRIT='{"origin":"python","tool":"ruff","rule_id":"S105","file":"src/cfg.py","line":1,"cwe":"CWE-798","evidence":"PW=hunter2","severity":"CRITICAL","title":"Hardcoded password"}'
fp() { python3 -c "
import sys; sys.path.insert(0,'scripts')
from secaudit.fingerprint import fingerprint
import json; print(fingerprint(json.loads(sys.argv[1])))" "$1"; }
FP_HIGH=$(fp "$F_HIGH"); FP_CRIT=$(fp "$F_CRIT")
printf '%s\n%s\n' "$F_HIGH" "$F_CRIT" > "$scratch/fresh.jsonl"

cat > "$scratch/cs.json" <<'JSON'
{"mode":"incremental","baseline_run":"20260701-1200",
 "files":{"added":[],"modified":["src/db.py"],"deleted":[],"unchanged":0},
 "lanes":{"python":{"rerun":true,"reason":"changed"}}}
JSON
echo '{"python":"ok"}' > "$scratch/lane.json"

merge() {  # $1 run-id, $2 now-iso, $3 optional --accepted path
  local extra=()
  [ -n "${3:-}" ] && extra=(--accepted "$3")
  python3 "$S/deltas.py" --state "$home/audit-state.json" \
      --changeset "$scratch/cs.json" --findings "$scratch/fp.jsonl" \
      --lane-status "$scratch/lane.json" --run-id "$1" --now "$2" "${extra[@]}"
}
persist() {  # $1 merged.json, $2 run-id
python3 - "$home" "$1" "$2" <<'PY'
import json, sys, os
sys.path.insert(0, "scripts")
from secaudit import statestore
home, merged, run_id = sys.argv[1], json.load(open(sys.argv[2])), sys.argv[3]
st = statestore.load(home) if os.path.exists(os.path.join(home, statestore.STATE_FILE)) \
     else statestore.skeleton()
st["findings"] = merged["state_findings"]
statestore.save(home, st)
statestore.append_run(home, {"run_id": run_id, "mode": "incremental",
                             "counts": {"open": merged["deltas"]["total_open"]},
                             "deltas": merged["deltas"]})
PY
}

echo "=== run 1: baseline, no register ==="
python3 "$S/fingerprint.py" findings "$scratch/fresh.jsonl" > "$scratch/fp.jsonl"
merge 20260701-1200 2026-07-01T12:00:00Z > "$scratch/m1.json"
persist "$scratch/m1.json" 20260701-1200
python3 - "$scratch/m1.json" <<PY
import json, sys
d = json.load(open(sys.argv[1]))
st = {f["fingerprint"]: f["status"] for f in d["findings"]}
assert st["$FP_HIGH"] == "NEW" and st["$FP_CRIT"] == "NEW", st
assert "accepted" not in d["deltas"], d["deltas"]
assert "acceptances" not in d, "no register was passed; none must be reported"
print("  2 NEW findings, no acceptance machinery engaged OK")
PY

echo "=== run 2: the maintainer accepts both ==="
# The CRITICAL asks for a year; the 30-day cap must overrule the file.
cat > "$home/accepted.json" <<JSON
{"schema": 1, "accepted": [
 {"fingerprint": "$FP_HIGH", "reason": "mitigated by the WAF rule",
  "accepted": "2026-07-05", "expires": "2026-10-01", "accepted_by": "alice"},
 {"fingerprint": "$FP_CRIT", "reason": "vendor fix pending",
  "accepted": "2026-07-05", "expires": "2027-07-05", "accepted_by": "bob"}]}
JSON
merge 20260710-1200 2026-07-10T12:00:00Z "$home/accepted.json" > "$scratch/m2.json"
persist "$scratch/m2.json" 20260710-1200
python3 - "$scratch/m2.json" <<PY
import json, sys
d = json.load(open(sys.argv[1]))
fs = {f["fingerprint"]: f for f in d["findings"]}
h, c = fs["$FP_HIGH"], fs["$FP_CRIT"]
assert h["status"] == "ACCEPTED" and c["status"] == "ACCEPTED", (h["status"], c["status"])
assert h["suppressed_status"] == "REVERIFIED", h["suppressed_status"]
assert h["accepted_expires"] == "2026-10-01", h            # honoured as written
assert c["accepted_expires"] == "2026-08-04", c            # 2026-07-05 + 30d
assert c["accepted_clamped_from"] == "2027-07-05", c
assert d["deltas"]["accepted"] == 2, d["deltas"]
# still open: acceptance is not resolution
assert d["deltas"]["total_open"] == 2, d["deltas"]
assert len(d["acceptances"]["clamped"]) == 1, d["acceptances"]["clamped"]
print("  both ACCEPTED; CRITICAL clamped 2027-07-05 -> 2026-08-04; total_open unchanged OK")
PY
# the REAL state round-trip: accepted findings persist as OPEN, never resolved
python3 - "$home" <<PY
import json, sys
sys.path.insert(0, "scripts")
from secaudit import statestore
st = statestore.load(sys.argv[1])
for fp in ("$FP_HIGH", "$FP_CRIT"):
    rec = st["findings"][fp]
    assert rec["status"] == "open", (fp, rec["status"])
    assert rec["triage"]["accepted_expires"], rec["triage"]
    assert "accepted_reason" not in rec["finding"], rec["finding"]
print("  state round-trip: accepted findings stored open, acceptance in triage OK")
PY
# scoring excludes ACCEPTED exactly like FIXED -> the buckets shrink to zero
python3 -c "
import json,sys
d=json.load(open('$scratch/m2.json'))
open('$scratch/scoreme.json','w').write(json.dumps(
    [f for f in d['findings'] if f['status'] not in ('FIXED','ACCEPTED')]))"
python3 "$S/score.py" < "$scratch/scoreme.json" > "$scratch/scored2.json"
python3 -c "
import json
s=json.load(open('$scratch/scored2.json'))
assert s == [], f'ACCEPTED findings reached the severity buckets: {s}'
print('  severity buckets empty while both risks remain open OK')"
# and neither is re-raised as a code-scanning alert, in either SARIF mode
for m in all new; do
  python3 "$S/sarif.py" --mode=$m < "$scratch/m2.json" >/dev/null 2>&1 || true
  python3 -c "
import json,subprocess,sys
d=json.load(open('$scratch/m2.json'))
p=subprocess.run(['python3','$S/sarif.py','--mode=$m'],input=json.dumps(d['findings']),
                 capture_output=True,text=True,check=True)
res=json.loads(p.stdout)['runs'][0]['results']
assert res == [], f'--mode=$m re-raised an accepted risk: {res}'
print('  --mode=$m emits no alert for an accepted risk OK')"
done

echo "=== run 3: the acceptances lapse on their own ==="
# Nobody edits accepted.json. Time passes past BOTH the clamped CRITICAL expiry
# and the HIGH's stated one; the findings must come back by themselves.
merge 20261101-1200 2026-11-01T12:00:00Z "$home/accepted.json" > "$scratch/m3.json"
persist "$scratch/m3.json" 20261101-1200
python3 - "$scratch/m3.json" <<PY
import json, sys
d = json.load(open(sys.argv[1]))
fs = {f["fingerprint"]: f for f in d["findings"]}
h, c = fs["$FP_HIGH"], fs["$FP_CRIT"]
assert h["status"] == "REVERIFIED" and c["status"] == "REVERIFIED", (h["status"], c["status"])
assert h["previously_accepted"] and c["previously_accepted"], (h, c)
assert d["deltas"]["accepted"] == 0, d["deltas"]
assert d["deltas"]["previously_accepted"] == 2, d["deltas"]
# The two lapse by DIFFERENT mechanisms, and the report distinguishes them:
#   HIGH     -- its own stated expiry passed, so it is register-level "expired"
#   CRITICAL — the file still says 2027, but the 30-day clamp already ran out
#              so it is finding-level "lapsed", with the enforced date shown
exp = d["acceptances"]["expired"]
lap = d["acceptances"]["lapsed"]
assert [e["fingerprint"] for e in exp] == ["$FP_HIGH"], exp
assert [l["fingerprint"] for l in lap] == ["$FP_CRIT"], lap
assert lap[0]["clamped"] and lap[0]["enforced_expiry"] == "2026-08-04", lap
assert lap[0]["expires"] == "2027-07-05", lap   # what the file still claims
print("  both lapsed WITHOUT any file edit: 1 by stated expiry, 1 by the clamp OK")
PY
# the file is untouched: sec-audit never rewrites the user's register
python3 - "$home" <<'PY'
import json, sys
reg = json.load(open(sys.argv[1] + "/accepted.json"))
assert len(reg["accepted"]) == 2, reg
assert reg["accepted"][1]["expires"] == "2027-07-05", reg["accepted"][1]
print("  accepted.json byte-preserved (clamp enforced at read time, not by editing) OK")
PY
# and they score again, at full severity
python3 -c "
import json
d=json.load(open('$scratch/m3.json'))
open('$scratch/scoreme3.json','w').write(json.dumps(
    [f for f in d['findings'] if f['status'] not in ('FIXED','ACCEPTED')]))"
python3 "$S/score.py" < "$scratch/scoreme3.json" \
  | python3 -c "
import json,sys
s=json.load(sys.stdin)
sev=sorted(f['severity'] for f in s)
assert sev == ['CRITICAL','HIGH'], sev
print('  both risks score again at full severity OK')"

echo "=== the run history records all three runs ==="
python3 - "$home" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1] + "/history.jsonl") if l.strip()]
assert len(rows) == 3, len(rows)
assert [r["run_id"] for r in rows] == ["20260701-1200", "20260710-1200", "20261101-1200"], rows
# open count never dropped because of a suppression
assert [r["counts"]["open"] for r in rows] == [2, 2, 2], [r["counts"] for r in rows]
assert rows[1]["deltas"]["accepted"] == 2 and rows[2]["deltas"]["accepted"] == 0, rows
print("  history: 3 runs, open count never reduced by acceptance OK")
PY

echo ""
echo "accepted-e2e: OK"
