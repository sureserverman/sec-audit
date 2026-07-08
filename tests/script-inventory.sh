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

check sample-stack            "PyPI"     "python,supply-chain,virt,secrets"
check vulnerable-supply-chain "PyPI,npm" "python,supply-chain,secrets"
check vulnerable-go           "Go"       "go,secrets"
check vulnerable-iac          ""         "iac,secrets"
check vulnerable-gh-actions   ""         "gh-actions,secrets"
check vulnerable-deep-deps    "npm"      "supply-chain,secrets"

# Empty target -> empty inventory (no crash). Use a genuinely empty dir: the
# secrets lane fires on ANY file, so $scratch (which holds inv.json) is not empty.
mkdir -p "$scratch/empty_dir"
python3 "$inv" "$scratch/empty_dir" > "$scratch/empty.json"
python3 - "$scratch/empty.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["ecosystems"] == [] and d["lanes"] == {}, d
print("  empty target -> empty inventory OK")
PY

# secrets lane: tree-only on a non-git dir, tree+git-history on a git repo.
mkdir -p "$scratch/plain"; printf 'x\n' > "$scratch/plain/file.txt"
python3 "$inv" "$scratch/plain" > "$scratch/plain.json"
python3 - "$scratch/plain.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["lanes"].get("secrets") == ["tree"], d["lanes"].get("secrets")
print("  non-git tree -> secrets=['tree'] OK")
PY
mkdir -p "$scratch/repo/.git"; printf 'x\n' > "$scratch/repo/file.txt"
python3 "$inv" "$scratch/repo" > "$scratch/repo.json"
python3 - "$scratch/repo.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["lanes"].get("secrets") == ["tree", "git-history"], d["lanes"].get("secrets")
print("  git repo -> secrets=['tree','git-history'] OK")
PY

echo ""
echo "script-inventory: OK"
