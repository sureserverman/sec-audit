#!/usr/bin/env bash
# script-runner.sh <lane> — parity test for the config-driven runner engine.
# Maps recorded raw tool output (tests/fixtures/raw-tool-output/<lane>/<tool>.json)
# through the engine and asserts the mapped finding objects equal the golden
# .pipeline/<lane>.jsonl findings; also checks the no-tools unavailable sentinel.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"

# No lane arg: run parity for every lane that has recorded raw fixtures.
if [ $# -eq 0 ]; then
  rc=0
  for d in tests/fixtures/raw-tool-output/*/; do
    [ -d "$d" ] || continue
    bash "$0" "$(basename "$d")" || rc=1
  done
  exit $rc
fi

lane="$1"
runner="scripts/secaudit/runner.py"
rawdir="tests/fixtures/raw-tool-output/$lane"
[ -d "$rawdir" ] || { echo "script-runner($lane): FAIL — no raw fixtures at $rawdir" >&2; exit 1; }

# Comparison target. Editorial lanes (whose .pipeline golden carries LLM-polished
# titles/severity the deterministic engine can't reproduce) ship an explicit
# expected.jsonl = the engine's faithful output. Clean lanes compare to the
# golden directly (the engine reproduces it byte-for-byte).
if [ -f "$rawdir/expected.jsonl" ]; then
  golden="$rawdir/expected.jsonl"
elif [ "$lane" = "sast" ]; then
  golden="tests/fixtures/sample-stack/.pipeline/sast.jsonl"
else
  golden="tests/fixtures/vulnerable-$lane/.pipeline/$lane.jsonl"
fi
[ -f "$golden" ] || { echo "script-runner($lane): FAIL — no comparison target $golden" >&2; exit 1; }

scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
: > "$scratch/mapped.jsonl"
for raw in "$rawdir"/*.json "$rawdir"/*.xml; do
  [ -e "$raw" ] || continue
  tool="$(basename "$raw")"; tool="${tool%.*}"   # strip .json / .xml; tool == config tool name
  python3 "$runner" "$lane" --map-only "$raw" --tool "$tool" >> "$scratch/mapped.jsonl"
done

python3 - "$scratch/mapped.jsonl" "$golden" <<'PY'
import json, sys
mapped = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
# golden findings = all lines except the trailing __*_status__ sentinel
golden = []
for l in open(sys.argv[2]):
    l = l.strip()
    if not l:
        continue
    o = json.loads(l)
    if any(k.startswith("__") and k.endswith("_status__") for k in o):
        continue
    golden.append(o)
def norm(rows):
    return sorted(json.dumps(r, sort_keys=True) for r in rows)
m, g = norm(mapped), norm(golden)
if m != g:
    print(f"  mapped={len(mapped)} golden={len(golden)}", file=sys.stderr)
    mg = set(m) - set(g); gm = set(g) - set(m)
    for x in list(mg)[:3]: print("  ONLY-IN-MAPPED:", x, file=sys.stderr)
    for x in list(gm)[:3]: print("  ONLY-IN-GOLDEN:", x, file=sys.stderr)
    sys.exit(1)
print(f"  parity: {len(mapped)} mapped findings == golden")
PY

echo "=== no-tools sentinel (live, PATH scrubbed) ==="
empty="$scratch/empty"; mkdir -p "$empty"
# Scrub PATH to a python3-only stub so the engine's `command -v <tool>` probes
# all fail — guaranteeing the degrade path regardless of what's installed
# locally (some lane tools, e.g. addons-linter/retire, may be present here).
stub="$scratch/stub"; mkdir -p "$stub"; ln -sf "$(command -v python3)" "$stub/python3"
last="$(PATH="$stub" python3 "$runner" "$lane" "$empty" 2>/dev/null | tail -n1)"
python3 - "$lane" "$last" <<'PY'
import json, sys
o = json.loads(sys.argv[2])
key = "__" + sys.argv[1].replace("-", "_") + "_status__"
assert o.get(key) == "unavailable" and o.get("tools") == [], o
print("  no-tools -> unavailable sentinel: OK")
PY

echo ""
echo "script-runner($lane): OK"
