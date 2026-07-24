#!/usr/bin/env bash
# incremental-e2e.sh — the two-run contract, end to end over the real scripts.
#
#   run 1  full audit of a fixture tree            -> baseline state
#   run 2  after mutating one file + deleting one  -> only the right lanes re-run,
#                                                     every run-1 finding is
#                                                     accounted for, nothing lost
#   run 3  --full                                  -> reproduces run 1 exactly
#
# Hermetic: statehome + statestore + fingerprint + changeset + deltas only. The
# lane scanners are simulated by a fixed finding set per lane (this test is about
# the incremental machinery, not about semgrep).
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

printf 'q = "SELECT " + name\ncur.execute(q)\n' > "$target/src/db.py"
printf 'print("hello")\n'                        > "$target/src/util.py"
printf 'rm $x\n'                                 > "$target/run.sh"
printf 'legacy = True\n'                         > "$target/old_legacy.py"

home=$(python3 "$S/statehome.py" "$target" | python3 -c "import json,sys; print(json.load(sys.stdin)['home'])")
echo "state home: $home"

# --- lane finding sets (stand-ins for real scanners) -------------------------
findings_python() {  # $1 = "run1" | "run2"
python3 - "$1" <<'PY'
import json, sys
sys.path.insert(0, "scripts")
from secaudit.fingerprint import fingerprint
rows = [
  {"origin":"python","tool":"ruff","rule_id":"S608","file":"src/db.py","line":2,
   "cwe":"CWE-89","title":"SQL injection","severity":"HIGH","evidence":"cur.execute(q)"},
  {"origin":"python","tool":"ruff","rule_id":"S105","file":"old_legacy.py","line":1,
   "cwe":"CWE-798","title":"Hardcoded flag","severity":"LOW","evidence":"legacy = True"},
]
if sys.argv[1] == "run2":
    # old_legacy.py was deleted; db.py gained a new issue and its SQLi shifted down
    rows = [
      {"origin":"python","tool":"ruff","rule_id":"S608","file":"src/db.py","line":9,
       "cwe":"CWE-89","title":"SQL injection","severity":"HIGH","evidence":"cur.execute(q)"},
      {"origin":"python","tool":"ruff","rule_id":"S307","file":"src/db.py","line":4,
       "cwe":"CWE-94","title":"eval of request data","severity":"CRITICAL","evidence":"eval(raw)"},
    ]
for r in rows:
    r["fingerprint"] = fingerprint(r)
    print(json.dumps(r))
PY
}
findings_shell() {
python3 - <<'PY'
import json, sys
sys.path.insert(0, "scripts")
from secaudit.fingerprint import fingerprint
r = {"origin":"shell","tool":"shellcheck","rule_id":"SC2086","file":"run.sh","line":1,
     "cwe":"CWE-78","title":"Unquoted variable","severity":"MEDIUM","evidence":"rm $x"}
r["fingerprint"] = fingerprint(r)
print(json.dumps(r))
PY
}

lanes_json() { printf '{"lanes":{"python":true,"shell":true}}\n' > "$scratch/lanes.json"; }
lanes_json

# --- one audit "run" ---------------------------------------------------------
audit() {  # $1 = run_id, $2 = "run1"|"run2", $3... = extra changeset flags
    local run_id="$1" phase="$2"; shift 2
    python3 "$S/fingerprint.py" manifest "$target" > "$scratch/manifest.json"
    python3 "$S/changeset.py" --manifest "$scratch/manifest.json" \
        --state "$home/audit-state.json" --lanes "$scratch/lanes.json" \
        --now 2026-07-24T12:00:00Z "$@" > "$scratch/cs-$run_id.json"

    # dispatch only lanes the changeset says must re-run
    : > "$scratch/fresh-$run_id.jsonl"
    for lane in python shell; do
        if python3 -c "
import json,sys
cs=json.load(open('$scratch/cs-$run_id.json'))
sys.exit(0 if cs['lanes'].get('$lane',{}).get('rerun') else 1)"; then
            findings_"$lane" "$phase" >> "$scratch/fresh-$run_id.jsonl"
        fi
    done
    printf '{"python":"ok","shell":"ok"}\n' > "$scratch/ls.json"

    python3 "$S/deltas.py" --state "$home/audit-state.json" \
        --changeset "$scratch/cs-$run_id.json" --findings "$scratch/fresh-$run_id.jsonl" \
        --lane-status "$scratch/ls.json" --run-id "$run_id" \
        --now 2026-07-24T12:00:00Z > "$scratch/merged-$run_id.json"

    # persist: state findings + manifest + lane_state (what SKILL §6 does)
    python3 - "$home" "$scratch/merged-$run_id.json" "$scratch/manifest.json" \
                "$scratch/cs-$run_id.json" "$run_id" <<'PY'
import json, sys
sys.path.insert(0, "scripts")
from secaudit import statestore
from secaudit.changeset import lane_digest
home, merged_p, man_p, cs_p, run_id = sys.argv[1:6]
merged = json.load(open(merged_p)); man = json.load(open(man_p)); cs = json.load(open(cs_p))
state = statestore.load(home)
state["findings"] = merged["state_findings"]
state["manifest"] = man["manifest"]
counts = {}
for f in merged["findings"]:
    if f["status"] != "FIXED":
        counts[f.get("origin", "?")] = counts.get(f.get("origin", "?"), 0) + 1
for lane, entry in cs["lanes"].items():
    if entry["rerun"]:
        state.setdefault("lane_state", {})[lane] = {
            "last_run": run_id, "last_run_at": "2026-07-24T12:00:00Z",
            "status": "ok", "digest": lane_digest(lane),
            "findings": counts.get(lane, 0)}
statestore.save(home, state)
statestore.append_run(home, {"run_id": run_id, "mode": cs["mode"],
                             "plugin_version": "test",
                             "counts": counts, "deltas": merged["deltas"]}, state)
PY
}

q() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

echo "=== RUN 1: first audit is always full ==="
audit 20260724-1200 run1
cs1=$(cat "$scratch/cs-20260724-1200.json"); m1=$(cat "$scratch/merged-20260724-1200.json")
[ "$(echo "$cs1" | q "['mode']")" = full ] || { echo "FAIL: first run not full"; exit 1; }
run1_open=$(echo "$m1" | q "['deltas']['total_open']")
[ "$run1_open" = 3 ] || { echo "FAIL: expected 3 findings in run 1, got $run1_open"; exit 1; }
[ "$(echo "$m1" | q "['deltas']['new']")" = 3 ] || { echo "FAIL: all run-1 findings should be NEW"; exit 1; }
echo "  run 1: full, 3 findings, all NEW OK"

echo "=== mutate: edit src/db.py (new issue + line shift), delete old_legacy.py ==="
printf 'import x\n\n# padding\neval(raw)\n\n\n\n\nq = "SELECT " + name\ncur.execute(q)\n' > "$target/src/db.py"
rm "$target/old_legacy.py"

echo "=== RUN 2: incremental ==="
audit 20260724-1300 run2
cs2=$(cat "$scratch/cs-20260724-1300.json"); m2=$(cat "$scratch/merged-20260724-1300.json")

[ "$(echo "$cs2" | q "['mode']")" = incremental ] || { echo "FAIL: run 2 not incremental"; exit 1; }
[ "$(echo "$cs2" | q "['baseline_run']")" = 20260724-1200 ] || { echo "FAIL: wrong baseline"; exit 1; }

echo "--- only the affected lane re-ran ---"
[ "$(echo "$cs2" | q "['lanes']['python']['rerun']")" = True ] || { echo "FAIL: python did not re-run"; exit 1; }
[ "$(echo "$cs2" | q "['lanes']['shell']['rerun']")" = False ] || { echo "FAIL: shell re-ran needlessly"; exit 1; }
echo "  python re-ran, shell carried OK"

echo "--- CONSERVATION: every run-1 finding is accounted for ---"
echo "$m2" | python3 -c "
import json,sys
d = json.load(sys.stdin)['deltas']
tot = d['carried'] + d['reverified'] + d['fixed']
assert d['baseline_open'] == $run1_open, ('baseline mismatch', d)
assert tot == d['baseline_open'], ('CONSERVATION BROKEN', d)
print('  run1_open=%d == carried %d + reverified %d + fixed %d OK'
      % (d['baseline_open'], d['carried'], d['reverified'], d['fixed']))
"

echo "--- per-finding classification ---"
echo "$m2" | python3 -c "
import json,sys
fs = json.load(sys.stdin)['findings']
by = {f['title']: f for f in fs}
# the SQLi moved from line 2 to line 9 in a MODIFIED file -> re-verified, not new
sqli = by['SQL injection']
assert sqli['status'] == 'REVERIFIED', sqli
assert sqli['line'] == 9, sqli
assert sqli['first_seen'] == '20260724-1200', sqli
# the deleted file's finding -> FIXED (file-deleted), without shell re-running
leg = by['Hardcoded flag']
assert leg['status'] == 'FIXED' and leg['resolution'] == 'file-deleted', leg
# the new issue in the modified file -> NEW
ev = by['eval of request data']
assert ev['status'] == 'NEW', ev
# the untouched shell finding -> CARRIED with a reason, not silently dropped
sh = by['Unquoted variable']
assert sh['status'] == 'CARRIED', sh
assert 'no applicable file changed' in sh['carried_reason'], sh
assert sh['stale'] is False, sh
print('  SQLi REVERIFIED (line 2->9, same identity)')
print('  deleted-file finding FIXED (file-deleted)')
print('  new issue NEW')
print('  untouched shell finding CARRIED: %s' % sh['carried_reason'])
"

echo "--- history + state persisted ---"
[ "$(wc -l < "$home/history.jsonl")" = 2 ] || { echo "FAIL: history should have 2 runs"; exit 1; }
python3 -c "
import json
s = json.load(open('$home/audit-state.json'))
assert len(s['runs']) == 2, s['runs']
assert s['manifest'] and 'old_legacy.py' not in s['manifest'], 'manifest not refreshed'
print('  state: 2 runs, manifest refreshed OK')
"

echo "=== RUN 3: --full reproduces run 1's view (no state-induced drift) ==="
# restore the tree to its run-1 content, then force a full audit
printf 'q = "SELECT " + name\ncur.execute(q)\n' > "$target/src/db.py"
printf 'legacy = True\n' > "$target/old_legacy.py"
audit 20260724-1400 run1 --full
m3=$(cat "$scratch/merged-20260724-1400.json")
[ "$(cat "$scratch/cs-20260724-1400.json" | q "['mode']")" = full ] || { echo "FAIL: run 3 not full"; exit 1; }
echo "$m3" | python3 -c "
import json,sys
fs = [f for f in json.load(sys.stdin)['findings'] if f['status'] != 'FIXED']
titles = sorted(f['title'] for f in fs)
expected = sorted(['SQL injection', 'Hardcoded flag', 'Unquoted variable'])
assert titles == expected, (titles, expected)
print('  --full open set == run 1 open set: %s OK' % titles)
"

echo ""
echo "incremental-e2e: OK"
