#!/usr/bin/env bash
# report-incremental-e2e.sh — the incremental report contract.
#
# SCOPE, stated honestly: report-writer is an LLM agent, so no hermetic test can
# render its markdown. This test asserts the two halves that ARE checkable:
#   1. the contract — report-writer.md documents every required section and the
#      mandatory disclosure wording;
#   2. the data — a real deltas.py run emits every field those sections render
#      from, so the agent is never asked to invent one.
# What remains unproven is only "the agent follows its instructions".
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
rw="agents/report-writer.md"

need() {  # file, pattern, message
    grep -q "$2" "$1" || { echo "FAIL: $3"; exit 1; }
}

echo "=== contract: delta sections are documented ==="
need "$rw" '## Changes since last audit'  "missing 'Changes since last audit' section"
need "$rw" '## Fixed since last audit'    "missing 'Fixed since last audit' section"
need "$rw" 'Step 2.7'                     "missing Step 2.7 (changes section)"
need "$rw" 'Step 2.8'                     "missing Step 2.8 (fixed section)"
need "$rw" 'REGRESSED'                    "missing REGRESSED status"
need "$rw" 'REVERIFIED'                   "missing REVERIFIED status"
need "$rw" 'file-deleted'                 "missing the file-deleted resolution"
need "$rw" 'not-found-on-rescan'          "missing the not-found-on-rescan resolution"
echo "  sections: OK"

echo "=== contract: the CARRIED disclosure wording is mandatory ==="
need "$rw" 'not re-verified this run'     "missing the mandatory 'not re-verified this run' wording"
need "$rw" 'lane degraded, findings unverified' "missing the degraded-lane suffix"
need "$rw" '\*\*Status:\*\*'              "per-finding blocks missing the Status line"
# The skip-on-full-run rule must be explicit, so a full report is not padded
# with meaningless zeroes.
need "$rw" 'Skip this section entirely on a full run' "missing the full-run skip rule"
need "$rw" 'must not be faked'                        "missing the no-fake-zeroes rule"
echo "  disclosure wording: OK"

echo "=== contract: per-lane summary distinguishes carried from skipped/excluded ==="
need "$rw" 'Re-run' "per-lane summary missing the Re-run column"
need "$rw" 'the three must remain visually distinct' \
    "missing the carried-vs-out-of-scope-vs-excluded distinction"
need "$rw" '^- Lanes carried:' "metadata missing the Lanes carried line"
need "$rw" '^- Lanes re-run:'  "metadata missing the Lanes re-run line"
need "$rw" '^- Mode:'          "metadata missing the Mode line"
echo "  lane accounting: OK"

echo "=== data: a real deltas.py run emits every field those sections need ==="
cat > "$scratch/state.json" <<'JSON'
{"schema":1,
 "findings":{
   "v1:aaa":{"lane":"python","status":"open","first_seen":"20260701-1200",
             "last_seen":"20260701-1200","last_verified_at":"2026-07-01T12:00:00Z",
             "finding":{"origin":"python","tool":"ruff","file":"src/db.py","line":10,
                        "cwe":"CWE-89","title":"SQLi","severity":"HIGH","evidence":"execute(q)"},
             "triage":{"confidence":"high"}},
   "v1:bbb":{"lane":"shell","status":"open","first_seen":"20260527-2055",
             "last_seen":"20260701-1200","last_verified_at":"2026-07-01T12:00:00Z",
             "finding":{"origin":"shell","tool":"shellcheck","file":"run.sh","line":3,
                        "cwe":"CWE-78","title":"Unquoted","severity":"MEDIUM","evidence":"rm $x"},
             "triage":{}},
   "v1:ccc":{"lane":"python","status":"open","first_seen":"20260709-1738",
             "last_seen":"20260709-1738","last_verified_at":"2026-07-09T17:38:00Z",
             "finding":{"origin":"python","tool":"ruff","file":"old/legacy.py","line":1,
                        "cwe":"CWE-798","title":"Hardcoded token","severity":"HIGH",
                        "evidence":"TOKEN='x'"},
             "triage":{}},
   "v1:ddd":{"lane":"python","status":"fixed","first_seen":"20260527-2055",
             "fixed_in_run":"20260709-1738",
             "finding":{"origin":"python","tool":"ruff","file":"src/db.py","line":50,
                        "cwe":"CWE-22","title":"Path traversal","severity":"HIGH",
                        "evidence":"open(p)"},
             "triage":{}}}}
JSON
cat > "$scratch/cs.json" <<'JSON'
{"mode":"incremental","baseline_run":"20260709-1738",
 "files":{"added":["src/new.py"],"modified":["src/db.py"],"deleted":["old/legacy.py"],"unchanged":809},
 "lanes":{"python":{"rerun":true,"reason":"2 applicable files changed"},
          "shell":{"rerun":false,"reason":"no applicable file changed since 20260709-1738","carried":1}}}
JSON
# fresh stream: the SQLi is still there (reverified), the previously-fixed path
# traversal is back (regressed), and one genuinely new finding appeared.
python3 - > "$scratch/fresh.jsonl" <<'PY'
import json, sys
sys.path.insert(0, "scripts")
from secaudit.fingerprint import fingerprint
rows = [
 {"origin":"python","tool":"ruff","file":"src/db.py","line":12,"cwe":"CWE-89",
  "title":"SQLi","severity":"HIGH","evidence":"execute(q)"},
 {"origin":"python","tool":"ruff","file":"src/db.py","line":50,"cwe":"CWE-22",
  "title":"Path traversal","severity":"HIGH","evidence":"open(p)"},
 {"origin":"python","tool":"ruff","file":"src/new.py","line":4,"cwe":"CWE-94",
  "title":"eval of user input","severity":"CRITICAL","evidence":"eval(x)"},
]
for r in rows:
    r["fingerprint"] = fingerprint(r)
    print(json.dumps(r))
PY
# Point the stored fingerprints at the real ones so the fixture is coherent.
python3 - "$scratch/state.json" "$scratch/fresh.jsonl" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
fresh = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
by_title = {f["title"]: f["fingerprint"] for f in fresh}
remap = {"v1:aaa": by_title["SQLi"], "v1:ddd": by_title["Path traversal"]}
state["findings"] = { remap.get(k, k): v for k, v in state["findings"].items() }
json.dump(state, open(sys.argv[1], "w"))
PY

python3 scripts/secaudit/deltas.py --state "$scratch/state.json" \
    --changeset "$scratch/cs.json" --findings "$scratch/fresh.jsonl" \
    --run-id 20260724-1200 --now 2026-07-24T12:00:00Z > "$scratch/merged.json"

python3 - "$scratch/merged.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
by = {}
for f in d["findings"]:
    by.setdefault(f["status"], []).append(f)
dl = d["deltas"]

# Every status the report renders must be present in this one merged set.
for st in ("NEW", "REGRESSED", "REVERIFIED", "CARRIED", "FIXED"):
    assert st in by, "status %s absent from the merged set: %s" % (st, sorted(by))

# Step 2.7 table inputs
for k in ("new", "regressed", "reverified", "carried", "fixed", "baseline_open"):
    assert k in dl, "deltas missing %s" % k

# Step 2.8 needs a resolution on every FIXED finding
for f in by["FIXED"]:
    assert f.get("resolution") in ("file-deleted", "not-found-on-rescan"), f
    assert f.get("first_seen"), "FIXED finding lacks first_seen (report renders it)"
assert any(f["resolution"] == "file-deleted" for f in by["FIXED"]), \
    "deleted-file resolution not exercised"

# Status line inputs
for f in by["CARRIED"]:
    assert f.get("carried_reason"), "CARRIED finding lacks carried_reason"
    assert "stale" in f, "CARRIED finding lacks the stale flag"
    assert f.get("first_seen"), "CARRIED finding lacks first_seen"
for f in by["REVERIFIED"]:
    assert f.get("first_seen") and f.get("last_verified_at"), f
for f in by["REGRESSED"]:
    assert "previously_fixed_in" in f, "REGRESSED finding lacks previously_fixed_in"

# Conservation, restated at report level: nothing may be dropped on the way in.
assert dl["carried"] + dl["reverified"] + dl["fixed"] == dl["baseline_open"], dl
print("  merged set carries every field the report renders:")
print("    %s" % {k: len(v) for k, v in sorted(by.items())})
print("    deltas: %s" % {k: dl[k] for k in ('new','regressed','reverified','carried','fixed')})
PY

echo ""
echo "report-incremental-e2e: OK"
