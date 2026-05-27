#!/usr/bin/env bash
# script-score.sh — verifies score.py implements the SKILL §5 rubric exactly,
# with hand-computed expected scores/buckets.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"

scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
cat > "$scratch/in.json" <<'JSON'
[
  {"id":"a","severity":"CRITICAL","cvss":9.8,"exposure":"unauth","kev":true,"auth_required":"none"},
  {"id":"b","kind":"malicious_package","severity":"CRITICAL"},
  {"id":"c","origin":"deep-deps","verdict":"malicious","severity":"CRITICAL"},
  {"id":"d","severity":"LOW","exposure":"test"},
  {"id":"e","severity":"HIGH","exposure":"auth","auth_required":"user"},
  {"id":"f","cvss":7.0,"exposure":"internal","poc":true,"auth_required":"admin"},
  {"id":"g","severity":"CRITICAL"}
]
JSON
python3 scripts/secaudit/score.py < "$scratch/in.json" > "$scratch/out.json"
python3 - "$scratch/out.json" <<'PY'
import json, sys
by = {f["id"]: f for f in json.load(open(sys.argv[1]))}
exp = {  # hand-computed (score, bucket)
  "a": (99,  "CRITICAL"),  # min(40, round(9.8*4)=39) + 25 + 20 + 15
  "b": (100, "CRITICAL"),  # malicious_package override
  "c": (100, "CRITICAL"),  # deep-deps malicious verdict override
  "d": (6,   "LOW"),       # sev 6 + 0 + 0 + 0
  "e": (51,  "MEDIUM"),    # 28 + 15 + 0 + 8
  "f": (45,  "MEDIUM"),    # min(40,28) + 5 + 10 + 2
  "g": (36,  "LOW"),       # sev 36 only -> below 40
}
for k, (sc, bk) in exp.items():
    got = (by[k]["score"], by[k]["bucket"])
    assert got == (sc, bk), f"{k}: expected {(sc,bk)} got {got}"
# descending order
scores = [f["score"] for f in json.load(open(sys.argv[1]))]
assert scores == sorted(scores, reverse=True), scores
print("  scoring assertions: OK (7 cases + descending order)")
PY
echo ""
echo "script-score: OK"
