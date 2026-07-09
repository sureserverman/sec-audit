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
check vulnerable-c            ""         "c-cpp,secrets"
check vulnerable-compose      ""         "virt,secrets"

# c-cpp FP guard: a header-only tree (no translation-unit source) must NOT fire
# the c-cpp lane — vendored / JNI *.h is ubiquitous. Source *.c DOES fire it.
mkdir -p "$scratch/hdr_only"; printf '#define X 1\nint f(void);\n' > "$scratch/hdr_only/api.h"
python3 "$inv" "$scratch/hdr_only" > "$scratch/hdr.json"
python3 - "$scratch/hdr.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert "c-cpp" not in d["lanes"], f"header-only tree must NOT fire c-cpp: {d['lanes']}"
print("  header-only *.h -> c-cpp NOT fired OK")
PY
mkdir -p "$scratch/c_src"; printf 'int main(void){return 0;}\n' > "$scratch/c_src/m.c"
python3 "$inv" "$scratch/c_src" > "$scratch/csrc.json"
python3 - "$scratch/csrc.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert "c-cpp" in d["lanes"], f"a *.c source must fire c-cpp: {d['lanes']}"
print("  source *.c -> c-cpp fired OK")
PY

# compose FP guard: an unrelated *.yml (no services:/version:) must NOT fire virt;
# a docker-compose.yml with services: DOES. (Stage 2 v1.25 detection.)
mkdir -p "$scratch/nocompose"; printf 'foo: bar\n' > "$scratch/nocompose/random.yml"
python3 "$inv" "$scratch/nocompose" > "$scratch/nc.json"
python3 - "$scratch/nc.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert "virt" not in d["lanes"], f"a plain *.yml must NOT fire virt: {d['lanes']}"
print("  plain *.yml -> virt NOT fired OK")
PY

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

# --files scoping (--diff mode): detection restricted to the listed paths.
multi="$scratch/multi"; mkdir -p "$multi"
printf 'x\n' > "$multi/deploy.sh"
printf 'django==2.2\n' > "$multi/requirements.txt"
printf 'print(1)\n' > "$multi/app.py"
# (a) list only the .sh -> shell + secrets, NOT python (its signal is unlisted)
printf 'deploy.sh\n' > "$multi/list-sh.txt"
python3 "$inv" "$multi" --files "$multi/list-sh.txt" > "$scratch/sh.json"
python3 - "$scratch/sh.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
lanes = set(d["lanes"])
assert "shell" in lanes and "secrets" in lanes, lanes
assert "python" not in lanes, f"python should not fire for a .sh-only file list: {lanes}"
print("  --files [deploy.sh] -> shell+secrets, no python OK")
PY
# (b) list including requirements.txt -> PyPI ecosystem; excluding it -> absent
printf 'requirements.txt\n' > "$multi/list-req.txt"
python3 "$inv" "$multi" --files "$multi/list-req.txt" > "$scratch/req.json"
python3 "$inv" "$multi" --files "$multi/list-sh.txt" > "$scratch/noreq.json"
python3 - "$scratch/req.json" "$scratch/noreq.json" <<'PY'
import json, sys
withreq = {e["ecosystem"] for e in json.load(open(sys.argv[1]))["ecosystems"]}
noreq = {e["ecosystem"] for e in json.load(open(sys.argv[2]))["ecosystems"]}
assert "PyPI" in withreq, withreq
assert "PyPI" not in noreq, noreq
print("  --files: PyPI present iff requirements.txt is in the list OK")
PY
# (c) regression: no --files == whole-tree (byte-identical)
python3 "$inv" "$multi" > "$scratch/full1.json"
python3 "$inv" "$multi" > "$scratch/full2.json"
diff -q "$scratch/full1.json" "$scratch/full2.json" >/dev/null && echo "  no --files: whole-tree unchanged OK"

echo ""
echo "script-inventory: OK"
