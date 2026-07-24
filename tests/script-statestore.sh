#!/usr/bin/env bash
# script-statestore.sh — verifies statestore.py: skeleton on first run, atomic
# save, refusal of corrupt/future-schema state (never silently rebaselining),
# append-run history semantics, and the MAX_RUNS cap on the in-state runs array.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
ss="scripts/secaudit/statestore.py"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
home="$scratch/security"

j() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

echo "=== first run: missing state file -> empty schema-v1 skeleton, no error ==="
out=$(python3 "$ss" load "$home")
[ "$(echo "$out" | j "['schema']")" = 1 ] || { echo "FAIL: schema"; exit 1; }
[ "$(echo "$out" | j "['runs']")" = "[]" ] || { echo "FAIL: runs not empty"; exit 1; }
for k in manifest lane_state findings deps programs feeds; do
    [ "$(echo "$out" | j "['$k']")" = "{}" ] || { echo "FAIL: missing section $k"; exit 1; }
done
[ -e "$home/audit-state.json" ] && { echo "FAIL: load created the state file"; exit 1; }
echo "  skeleton: OK"

echo "=== save then load round-trips ==="
echo "$out" | python3 -c "
import json,sys
s = json.load(sys.stdin)
s['project'] = {'name':'demo','area':'web','path':'/x/demo'}
s['manifest'] = {'a.py': {'sha256':'deadbeef','size':3}}
print(json.dumps(s))
" | python3 "$ss" save "$home"
out=$(python3 "$ss" load "$home")
[ "$(echo "$out" | j "['project']['name']")" = demo ] || { echo "FAIL: round-trip project"; exit 1; }
[ "$(echo "$out" | j "['manifest']['a.py']['sha256']")" = deadbeef ] || { echo "FAIL: round-trip manifest"; exit 1; }
echo "  round-trip: OK"

echo "=== atomic save: a crash before replace leaves the PREVIOUS state intact ==="
cp "$home/audit-state.json" "$scratch/before.json"
set +e
echo '{"schema":1,"project":{"name":"clobbered"},"runs":[],"manifest":{},"lane_state":{},"findings":{},"deps":{},"programs":{},"feeds":{}}' \
  | SECAUDIT_STATESTORE_FAIL_BEFORE_REPLACE=1 python3 "$ss" save "$home" 2>"$scratch/err.txt"
rc=$?
set -e
[ "$rc" != 0 ] || { echo "FAIL: simulated crash reported success"; exit 1; }
cmp -s "$scratch/before.json" "$home/audit-state.json" \
    || { echo "FAIL: previous state was damaged by an interrupted save"; exit 1; }
ls "$home"/*.tmp >/dev/null 2>&1 && { echo "FAIL: partial .tmp file left behind"; exit 1; }
echo "  atomicity: previous state intact, no .tmp residue OK"

echo "=== corrupt state -> hard error, NOT a silent empty skeleton ==="
cp "$home/audit-state.json" "$scratch/good.json"
printf '{not json' > "$home/audit-state.json"
set +e
python3 "$ss" load "$home" >/dev/null 2>"$scratch/err.txt"; rc=$?
set -e
[ "$rc" = 4 ] || { echo "FAIL: expected exit 4 on corrupt state, got $rc"; exit 1; }
grep -qi 'would report every existing finding as NEW' "$scratch/err.txt" \
    || { echo "FAIL: error does not explain the risk"; exit 1; }
grep -q -- '--full' "$scratch/err.txt" || { echo "FAIL: error does not name --full"; exit 1; }
echo "  corrupt state: refused with actionable message OK"

echo "=== future schema -> refused with an upgrade message ==="
python3 -c "
import json
s = json.load(open('$scratch/good.json')); s['schema'] = 999
json.dump(s, open('$home/audit-state.json','w'))
"
set +e
python3 "$ss" load "$home" >/dev/null 2>"$scratch/err2.txt"; rc=$?
set -e
[ "$rc" = 4 ] || { echo "FAIL: expected exit 4 on future schema, got $rc"; exit 1; }
grep -qi 'newer sec-audit' "$scratch/err2.txt" || { echo "FAIL: no newer-build message"; exit 1; }
echo "  future schema: refused OK"
cp "$scratch/good.json" "$home/audit-state.json"

echo "=== append-run: one JSONL line per run, prior lines byte-identical ==="
echo '{"run_id":"20260724-1800","mode":"full","counts":{"CRITICAL":1}}' | python3 "$ss" append-run "$home"
first=$(cat "$home/history.jsonl")
echo '{"run_id":"20260724-1830","mode":"incremental","counts":{"CRITICAL":0}}' | python3 "$ss" append-run "$home"
[ "$(wc -l < "$home/history.jsonl")" = 2 ] || { echo "FAIL: expected 2 history lines"; exit 1; }
[ "$(head -1 "$home/history.jsonl")" = "$first" ] || { echo "FAIL: first history line was rewritten"; exit 1; }
out=$(python3 "$ss" load "$home")
[ "$(echo "$out" | j "['runs'][-1]['run_id']")" = 20260724-1830 ] || { echo "FAIL: runs[] not updated"; exit 1; }
[ "$(echo "$out" | j "['runs'].__len__()")" = 2 ] || { echo "FAIL: runs[] length"; exit 1; }
echo "  append-run: OK"

echo "=== a run without run_id / mode is refused ==="
set +e
echo '{"mode":"full"}' | python3 "$ss" append-run "$home" 2>/dev/null; rc=$?
set -e
[ "$rc" = 4 ] || { echo "FAIL: run without run_id accepted"; exit 1; }
set +e
echo '{"run_id":"x"}' | python3 "$ss" append-run "$home" 2>"$scratch/mode.txt"; rc=$?
set -e
[ "$rc" = 4 ] || { echo "FAIL: run without mode accepted"; exit 1; }
grep -q 'mode' "$scratch/mode.txt" || { echo "FAIL: error does not name the missing field"; exit 1; }
echo "  run_id + mode required: OK"

echo "=== a full canonical run record round-trips into history.jsonl ==="
cat > "$scratch/run.json" <<'JSON'
{"run_id":"20260724-1900","mode":"incremental","started_at":"2026-07-24T19:00:00Z",
 "finished_at":"2026-07-24T19:06:12Z","plugin_version":"1.29.0",
 "counts":{"CRITICAL":1,"HIGH":3,"MEDIUM":7,"LOW":2},
 "deltas":{"new":2,"fixed":1,"carried":9,"regressed":0},
 "lanes_ran":["sast","python"],"lanes_carried":["rust","shell"],
 "cost":{"tokens_out":41233,"usd":1.87}}
JSON
python3 "$ss" append-run "$home" < "$scratch/run.json"
line=$(grep '20260724-1900' "$home/history.jsonl")
for k in run_id mode plugin_version counts deltas lanes_ran lanes_carried cost started_at finished_at; do
    echo "$line" | grep -q "\"$k\"" || { echo "FAIL: history line lost field $k"; exit 1; }
done
echo "$line" | python3 -c "
import json,sys
r = json.loads(sys.stdin.read())
assert r['counts']['CRITICAL'] == 1, r
assert r['deltas']['carried'] == 9, r
assert r['lanes_carried'] == ['rust','shell'], r
print('  full record: all fields preserved OK')
"

echo "=== a thin record normalizes missing fields to null, never to zero ==="
echo '{"run_id":"20260724-1901","mode":"full"}' | python3 "$ss" append-run "$home"
grep '20260724-1901' "$home/history.jsonl" | python3 -c "
import json,sys
r = json.loads(sys.stdin.read())
assert r['counts'] is None, 'missing counts must be null (unknown), not {} or 0: %r' % (r['counts'],)
assert r['plugin_version'] is None, r
print('  unknown stays unknown OK')
"

echo "=== runs[] capped at 50 while history.jsonl keeps everything ==="
before_lines=$(wc -l < "$home/history.jsonl")
for i in $(seq 1 60); do
    printf '{"run_id":"cap-%03d","mode":"full"}\n' "$i" | python3 "$ss" append-run "$home"
done
out=$(python3 "$ss" load "$home")
[ "$(echo "$out" | j "['runs'].__len__()")" = 50 ] || { echo "FAIL: runs[] not capped at 50"; exit 1; }
[ "$(echo "$out" | j "['runs'][-1]['run_id']")" = cap-060 ] || { echo "FAIL: cap dropped the newest"; exit 1; }
[ "$(wc -l < "$home/history.jsonl")" = "$((before_lines + 60))" ] \
    || { echo "FAIL: history.jsonl lost lines (cap must not touch history)"; exit 1; }
echo "  cap + full history: OK"

echo ""
echo "script-statestore: OK"
