#!/usr/bin/env bash
# script-inventory.sh — verifies inventory.py's deterministic §2 detection
# against existing fixtures (ecosystems + lanes).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
inv="scripts/secaudit/inventory.py"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

check() {  # fixture, expected-ecosystems-csv, expected-lanes-csv
  local fx="$1" eco="$2" lanes="$3"
  python3 "$inv" "tests/fixtures/$fx" > "$scratch/inv.json"
  python3 - "$scratch/inv.json" "$fx" "$eco" "$lanes" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
fx, eco_exp, lanes_exp = sys.argv[2], sys.argv[3], sys.argv[4]
got_eco = {e["ecosystem"] for e in d["ecosystems"]}
got_lanes = set(d["lanes"].keys())
for e in [x for x in eco_exp.split(",") if x]:
    assert e in got_eco, f"{fx}: ecosystem {e} not in {sorted(got_eco)}"
for l in [x for x in lanes_exp.split(",") if x]:
    assert l in got_lanes, f"{fx}: lane {l} not in {sorted(got_lanes)}"
print(f"  {fx}: ecosystems={sorted(got_eco)} lanes={sorted(got_lanes)} OK")
PY
}

check sample-stack            "PyPI"     "python,supply-chain,virt"
check vulnerable-supply-chain "PyPI,npm" "python,supply-chain"
check vulnerable-go           "Go"       "go"
check vulnerable-iac          ""         "iac"
check vulnerable-gh-actions   ""         "gh-actions"
check vulnerable-deep-deps    "npm"      "supply-chain"

# Empty target -> empty inventory (no crash).
python3 "$inv" "$scratch" > "$scratch/empty.json"
python3 - "$scratch/empty.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["ecosystems"] == [] and d["lanes"] == {}, d
print("  empty target -> empty inventory OK")
PY

echo ""
echo "script-inventory: OK"
