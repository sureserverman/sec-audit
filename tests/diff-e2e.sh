#!/usr/bin/env bash
# diff-e2e.sh — end-to-end proof of --diff scoping through the real pipeline:
# diffscope.py -> inventory.py --files -> runner.py --files. Uses a stub
# `shellcheck` on PATH (no external dep) so the findings-level assertion is
# hermetic: a diff-scoped run must produce findings ONLY from the changed file,
# and the whole-tree run must be a superset.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

# --- stub shellcheck: one shellcheck-style JSON warning per .sh file arg ---
stub="$scratch/bin"; mkdir -p "$stub"
cat > "$stub/shellcheck" <<'SH'
#!/usr/bin/env bash
files=(); for a in "$@"; do case "$a" in *.sh) files+=("$a");; esac; done
printf '['
first=1
for f in "${files[@]}"; do
  [ $first -eq 0 ] && printf ','
  printf '{"file":"%s","line":1,"endLine":1,"column":1,"endColumn":1,"level":"warning","code":2086,"message":"stub SC2086"}' "$f"
  first=0
done
printf ']\n'
SH
chmod +x "$stub/shellcheck"

# --- synthesize a git repo with two shell scripts, tag a ref ---
repo="$scratch/repo"; mkdir -p "$repo"
git -C "$repo" init -q
git -C "$repo" config core.hooksPath /dev/null
git -C "$repo" config commit.gpgsign false
git -C "$repo" config user.email t@t.t
git -C "$repo" config user.name t
printf 'echo $UNQUOTED\n' > "$repo/a.sh"
printf 'echo $ALSO\n'     > "$repo/b.sh"
git -C "$repo" add -A && git -C "$repo" commit -qm base
git -C "$repo" tag baseref

# change ONLY a.sh (working-tree change)
printf 'echo $UNQUOTED_CHANGED\n' > "$repo/a.sh"

# --- 1. diffscope -> changed set is exactly a.sh ---
python3 scripts/secaudit/diffscope.py "$repo" > "$scratch/changed.txt"
grep -qx 'a.sh' "$scratch/changed.txt" || { echo "diff-e2e: FAIL — a.sh not in changed set"; exit 1; }
grep -qx 'b.sh' "$scratch/changed.txt" && { echo "diff-e2e: FAIL — b.sh should not be changed"; exit 1; }
echo "  diffscope -> changed = a.sh"

# --- 2. inventory --files -> shell lane present ---
python3 scripts/secaudit/inventory.py "$repo" --files "$scratch/changed.txt" > "$scratch/inv.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "shell" in d["lanes"], d["lanes"]' "$scratch/inv.json"
echo "  inventory --files -> shell lane present"

# --- 3. runner --files (scoped) vs whole-tree, via stub shellcheck ---
scoped=$(PATH="$stub:$PATH" python3 scripts/secaudit/runner.py shell "$repo" --files "$scratch/changed.txt")
whole=$(PATH="$stub:$PATH" python3 scripts/secaudit/runner.py shell "$repo")

python3 - "$repo" <<PY
import json, sys
repo = sys.argv[1]
scoped = '''$scoped'''
whole  = '''$whole'''
def files(blob):
    out = set()
    for l in blob.splitlines():
        o = json.loads(l)
        if any(k.startswith("__") and k.endswith("_status__") for k in o):
            continue
        out.add(o["file"].split("/")[-1])
    return out
sf, wf = files(scoped), files(whole)
assert sf == {"a.sh"}, f"scoped findings must reference only a.sh, got {sf}"
assert wf == {"a.sh", "b.sh"}, f"whole-tree must cover both, got {wf}"
assert sf < wf, "scoped must be a strict subset of whole-tree"
print(f"  scoped findings: {sorted(sf)}  whole-tree: {sorted(wf)}  (scoped ⊂ whole) OK")
PY

# --- 4. SUBDIR target: the full chain agrees on target-relative paths ---
# scripts live in src/; target is the src/ subdir (not the repo root).
mkdir -p "$repo/src"
printf 'echo $S1\n' > "$repo/src/x.sh"
printf 'echo $S2\n' > "$repo/src/y.sh"
git -C "$repo" add -A && git -C "$repo" commit -qm add-src
printf 'echo $S1_CHANGED\n' > "$repo/src/x.sh"   # change only src/x.sh
sub="$repo/src"
python3 scripts/secaudit/diffscope.py "$sub" > "$scratch/subchanged.txt"
grep -qx 'x.sh' "$scratch/subchanged.txt" || { echo "diff-e2e: FAIL — subdir diff not target-relative"; exit 1; }
sub_scoped=$(PATH="$stub:$PATH" python3 scripts/secaudit/runner.py shell "$sub" --files "$scratch/subchanged.txt")
python3 - <<PY
import json
blob = '''$sub_scoped'''
files = {json.loads(l)["file"].split("/")[-1] for l in blob.splitlines()
         if not any(k.startswith("__") and k.endswith("_status__") for k in json.loads(l))}
assert files == {"x.sh"}, f"subdir-target scoped run must find only x.sh, got {files}"
print("  subdir target full chain: scoped findings = {'x.sh'} OK")
PY

echo ""
echo "diff-e2e: OK"
