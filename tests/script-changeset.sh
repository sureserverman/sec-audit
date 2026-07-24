#!/usr/bin/env bash
# script-changeset.sh — verifies changeset.py's rerun-decision matrix: unchanged
# tree skips, per-lane file matching, deletions, degraded previous runs, lane
# definition digests, tool-version drift, staleness TTL, --full, always-on lanes,
# and the fail-safe for unknown lanes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
cs="scripts/secaudit/changeset.py"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
NOW=2026-07-24T12:00:00Z

# Lane digests are computed from the real plugin tree, so the fixture state must
# carry the SAME digests to represent "definition unchanged".
digest() { python3 -c "
import sys; sys.path.insert(0,'scripts')
from secaudit.changeset import lane_digest; print(lane_digest('$1'))"; }

mkstate() {  # $1=json of lane_state overrides ; writes $scratch/state.json
python3 - "$1" > "$scratch/state.json" <<'PY'
import json, sys
overrides = json.loads(sys.argv[1])
state = {
  "schema": 1, "project": {"name": "demo"},
  "runs": [{"run_id": "20260701-1200", "mode": "full"}],
  "manifest": {
     "src/a.py":   {"sha256": "aaa", "size": 1},
     "src/keep.py":{"sha256": "kkk", "size": 1},
     "run.sh":     {"sha256": "sss", "size": 1},
     "gone.rs":    {"sha256": "ggg", "size": 1},
  },
  "lane_state": overrides, "findings": {}, "deps": {}, "programs": {}, "feeds": {},
}
print(json.dumps(state))
PY
}

mkmanifest() {  # writes $scratch/manifest.json from key=hash pairs
python3 - "$@" > "$scratch/manifest.json" <<'PY'
import json, sys
m = {}
for pair in sys.argv[1:]:
    k, _, v = pair.partition('=')
    m[k] = {"sha256": v, "size": 1}
print(json.dumps({"manifest": m}))
PY
}

lanes_json() {  # $@ = lane names
python3 - "$@" > "$scratch/lanes.json" <<'PY'
import json, sys
print(json.dumps({"lanes": {l: True for l in sys.argv[1:]}}))
PY
}

run() { python3 "$cs" --manifest "$scratch/manifest.json" --state "$scratch/state.json" \
                     --lanes "$scratch/lanes.json" --now "$NOW" "$@"; }
q() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

PY_D=$(digest python); SH_D=$(digest shell); RS_D=$(digest rust); SAST_D=$(digest sast)
FRESH='"last_run":"20260701-1200","last_run_at":"2026-07-20T12:00:00Z","status":"ok","findings":3'

echo "=== nothing changed -> every lane carries, zero re-runs ==="
mkstate "{\"python\":{$FRESH,\"digest\":\"$PY_D\"},\"shell\":{$FRESH,\"digest\":\"$SH_D\"},\"rust\":{$FRESH,\"digest\":\"$RS_D\"}}"
mkmanifest "src/a.py=aaa" "src/keep.py=kkk" "run.sh=sss" "gone.rs=ggg"
lanes_json python shell rust
out=$(run)
[ "$(echo "$out" | q "['mode']")" = incremental ] || { echo "FAIL: mode"; exit 1; }
for l in python shell rust; do
    [ "$(echo "$out" | q "['lanes']['$l']['rerun']")" = False ] || { echo "FAIL: $l re-ran on an unchanged tree"; exit 1; }
done
[ "$(echo "$out" | q "['lanes']['python']['carried']")" = 3 ] || { echo "FAIL: carried count"; exit 1; }
echo "  unchanged tree: 0 re-runs, findings carried OK"

echo "=== touching a .py re-runs python+sast, not rust/shell ==="
mkmanifest "src/a.py=MODIFIED" "src/keep.py=kkk" "run.sh=sss" "gone.rs=ggg"
lanes_json python shell rust sast
mkstate "{\"python\":{$FRESH,\"digest\":\"$PY_D\"},\"shell\":{$FRESH,\"digest\":\"$SH_D\"},\"rust\":{$FRESH,\"digest\":\"$RS_D\"},\"sast\":{$FRESH,\"digest\":\"$SAST_D\"}}"
out=$(run)
[ "$(echo "$out" | q "['lanes']['python']['rerun']")" = True ] || { echo "FAIL: python did not re-run"; exit 1; }
[ "$(echo "$out" | q "['lanes']['sast']['rerun']")" = True ]   || { echo "FAIL: sast did not re-run"; exit 1; }
[ "$(echo "$out" | q "['lanes']['rust']['rerun']")" = False ]  || { echo "FAIL: rust re-ran on a .py change"; exit 1; }
[ "$(echo "$out" | q "['lanes']['shell']['rerun']")" = False ] || { echo "FAIL: shell re-ran on a .py change"; exit 1; }
echo "$out" | q "['lanes']['python']['reason']" | grep -q 'applicable file' || { echo "FAIL: reason"; exit 1; }
echo "$out" | q "['lanes']['python']['files']" | grep -q 'src/a.py' || { echo "FAIL: matched file not reported"; exit 1; }
echo "  per-lane matching: OK"

echo "=== a DELETED file re-runs its lane (its findings must be resolvable) ==="
mkmanifest "src/a.py=aaa" "src/keep.py=kkk" "run.sh=sss"   # gone.rs deleted
lanes_json python rust
mkstate "{\"python\":{$FRESH,\"digest\":\"$PY_D\"},\"rust\":{$FRESH,\"digest\":\"$RS_D\"}}"
out=$(run)
[ "$(echo "$out" | q "['lanes']['rust']['rerun']")" = True ] || { echo "FAIL: deletion did not re-run rust"; exit 1; }
echo "$out" | q "['files']['deleted']" | grep -q 'gone.rs' || { echo "FAIL: deletion not tracked"; exit 1; }
echo "  deletion: OK"

echo "=== a NEW file re-runs its lane ==="
mkmanifest "src/a.py=aaa" "src/keep.py=kkk" "run.sh=sss" "gone.rs=ggg" "new/thing.go=nnn"
lanes_json go python
mkstate "{\"python\":{$FRESH,\"digest\":\"$PY_D\"},\"go\":{$FRESH,\"digest\":\"$(digest go)\"}}"
out=$(run)
[ "$(echo "$out" | q "['lanes']['go']['rerun']")" = True ] || { echo "FAIL: new file did not re-run go"; exit 1; }
echo "  addition: OK"

echo "=== a lane whose DEFINITION changed re-runs on an unchanged tree ==="
mkmanifest "src/a.py=aaa" "src/keep.py=kkk" "run.sh=sss" "gone.rs=ggg"
lanes_json python
mkstate "{\"python\":{$FRESH,\"digest\":\"STALEDIGEST\"}}"
out=$(run)
[ "$(echo "$out" | q "['lanes']['python']['rerun']")" = True ] || { echo "FAIL: stale lane digest did not re-run"; exit 1; }
echo "$out" | q "['lanes']['python']['reason']" | grep -qi 'definition changed' || { echo "FAIL: reason"; exit 1; }
echo "$out" | q "['invalidations']" | grep -q 'lane_definition_digest python' || { echo "FAIL: not recorded in invalidations"; exit 1; }
echo "  new rules on an unchanged tree: OK"

echo "=== a lane whose previous run DEGRADED re-runs ==="
mkstate "{\"python\":{\"last_run\":\"20260701-1200\",\"last_run_at\":\"2026-07-20T12:00:00Z\",\"status\":\"unavailable\",\"findings\":0,\"digest\":\"$PY_D\"}}"
out=$(run)
[ "$(echo "$out" | q "['lanes']['python']['rerun']")" = True ] || { echo "FAIL: degraded lane not retried"; exit 1; }
echo "$out" | q "['lanes']['python']['reason']" | grep -q "unavailable" || { echo "FAIL: reason"; exit 1; }
echo "  degraded lane retried: OK"

echo "=== tool-version drift re-runs the lane ==="
mkstate "{\"python\":{$FRESH,\"digest\":\"$PY_D\",\"tool_versions\":{\"ruff\":\"0.5.0\"}}}"
echo '{"python":{"ruff":"0.6.0"}}' > "$scratch/tools.json"
out=$(run --tool-versions "$scratch/tools.json")
[ "$(echo "$out" | q "['lanes']['python']['rerun']")" = True ] || { echo "FAIL: tool drift not detected"; exit 1; }
echo "$out" | q "['lanes']['python']['reason']" | grep -qi 'tool versions changed' || { echo "FAIL: reason"; exit 1; }
echo "  tool-version drift: OK"

echo "=== staleness TTL forces a re-verify even with nothing changed ==="
mkstate "{\"python\":{\"last_run\":\"20260101-1200\",\"last_run_at\":\"2026-01-01T12:00:00Z\",\"status\":\"ok\",\"findings\":3,\"digest\":\"$PY_D\"}}"
out=$(run)
[ "$(echo "$out" | q "['lanes']['python']['rerun']")" = True ] || { echo "FAIL: stale lane not re-verified"; exit 1; }
echo "$out" | q "['lanes']['python']['reason']" | grep -qi 'staleness TTL' || { echo "FAIL: reason"; exit 1; }
# ...and a custom TTL is honoured
out=$(run --staleness-days 9999)
[ "$(echo "$out" | q "['lanes']['python']['rerun']")" = False ] || { echo "FAIL: --staleness-days ignored"; exit 1; }
echo "  staleness TTL: OK"

echo "=== always-on lanes re-run regardless (secrets: git history; dast: live target) ==="
mkstate "{\"secrets\":{$FRESH,\"digest\":\"x\"},\"dast\":{$FRESH,\"digest\":\"y\"}}"
lanes_json secrets dast
out=$(run)
for l in secrets dast; do
    [ "$(echo "$out" | q "['lanes']['$l']['rerun']")" = True ] || { echo "FAIL: $l did not re-run"; exit 1; }
    echo "$out" | q "['lanes']['$l']['reason']" | grep -qi 'always-on' || { echo "FAIL: $l reason"; exit 1; }
done
echo "  always-on lanes: OK"

echo "=== an UNKNOWN lane re-runs (fail-safe, never silently skipped) ==="
lanes_json some-future-lane
mkstate "{\"some-future-lane\":{$FRESH,\"digest\":\"z\"}}"
out=$(run)
[ "$(echo "$out" | q "['lanes']['some-future-lane']['rerun']")" = True ] || { echo "FAIL: unknown lane skipped"; exit 1; }
echo "$out" | q "['lanes']['some-future-lane']['reason']" | grep -qi 'fail-safe' || { echo "FAIL: reason"; exit 1; }
echo "  unknown lane fail-safe: OK"

echo "=== --full re-runs everything and reports mode=full ==="
lanes_json python shell rust
mkstate "{\"python\":{$FRESH,\"digest\":\"$PY_D\"},\"shell\":{$FRESH,\"digest\":\"$SH_D\"},\"rust\":{$FRESH,\"digest\":\"$RS_D\"}}"
out=$(run --full)
[ "$(echo "$out" | q "['mode']")" = full ] || { echo "FAIL: mode not full"; exit 1; }
for l in python shell rust; do
    [ "$(echo "$out" | q "['lanes']['$l']['rerun']")" = True ] || { echo "FAIL: --full skipped $l"; exit 1; }
done
echo "  --full: OK"

echo "=== no baseline (first audit) -> full, every lane re-runs ==="
echo '{"schema":1,"runs":[],"manifest":{},"lane_state":{}}' > "$scratch/state.json"
out=$(run)
[ "$(echo "$out" | q "['mode']")" = full ] || { echo "FAIL: first run not full"; exit 1; }
[ "$(echo "$out" | q "['baseline_run']")" = None ] || { echo "FAIL: baseline should be null"; exit 1; }
echo "$out" | q "['lanes']['python']['reason']" | grep -qi 'first run is always full' || { echo "FAIL: reason"; exit 1; }
echo "  first audit: OK"

echo ""
echo "script-changeset: OK"
