#!/usr/bin/env bash
# script-diffscope.sh — verifies diffscope.py computes the changed-file set for
# --diff mode: bare (working tree + untracked), ref (branch changes since ref),
# deletions excluded, non-git target errors.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
ds="scripts/secaudit/diffscope.py"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

repo="$scratch/repo"; mkdir -p "$repo"
git -C "$repo" init -q
# Neutralize any globally-configured hooks/templates so this throwaway repo is
# hermetic (the host may install a pre-commit hook via init.templateDir).
git -C "$repo" config core.hooksPath /dev/null
git -C "$repo" config commit.gpgsign false
git -C "$repo" config user.email t@t.t
git -C "$repo" config user.name t
printf 'a\n' > "$repo/tracked.txt"
printf 'b\n' > "$repo/todelete.txt"
printf 'c\n' > "$repo/base.py"
git -C "$repo" add -A
git -C "$repo" commit -qm base
git -C "$repo" tag baseref

# working-tree changes: modify tracked, add untracked, delete a tracked file
printf 'a-modified\n' > "$repo/tracked.txt"
printf 'new\n' > "$repo/untracked.py"
rm "$repo/todelete.txt"

echo "=== bare mode: modified + untracked, NOT deleted ==="
out=$(python3 "$ds" "$repo")
echo "$out" | grep -qx 'tracked.txt'   || { echo "FAIL: tracked.txt missing"; exit 1; }
echo "$out" | grep -qx 'untracked.py'  || { echo "FAIL: untracked.py missing"; exit 1; }
echo "$out" | grep -qx 'todelete.txt'  && { echo "FAIL: deleted file present"; exit 1; }
echo "  bare: $(echo "$out" | tr '\n' ' ')OK"

echo "=== ref mode: includes a file changed by a commit since ref ==="
git -C "$repo" add -A && git -C "$repo" commit -qm change
printf 'c2\n' >> "$repo/base.py"
git -C "$repo" add -A && git -C "$repo" commit -qm base-change
out=$(python3 "$ds" "$repo" baseref)
echo "$out" | grep -qx 'base.py'    || { echo "FAIL: base.py (branch change since ref) missing"; exit 1; }
echo "$out" | grep -qx 'tracked.txt' || { echo "FAIL: tracked.txt (committed change since ref) missing"; exit 1; }
echo "  ref: $(echo "$out" | tr '\n' ' ')OK"

echo "=== non-git target -> non-zero exit + stderr ==="
nongit="$scratch/plain"; mkdir -p "$nongit"; printf 'x\n' > "$nongit/f.txt"
if python3 "$ds" "$nongit" 2>"$scratch/err.txt"; then
    echo "FAIL: non-git target did not error"; exit 1
fi
grep -qi 'not a git repository' "$scratch/err.txt" || { echo "FAIL: no clear stderr"; exit 1; }
echo "  non-git: errored with clear message OK"

echo "=== bad ref -> non-zero exit ==="
if python3 "$ds" "$repo" no-such-ref 2>/dev/null; then
    echo "FAIL: bad ref did not error"; exit 1
fi
echo "  bad ref: errored OK"

echo "=== ref that looks like an option -> refused (CWE-88 guard) ==="
if python3 "$ds" "$repo" -- --output=/tmp/x 2>/dev/null; then :; fi  # arg parsing: 3rd arg is ref
if python3 "$ds" "$repo" '--output=/tmp/pwned' 2>"$scratch/opt.txt"; then
    echo "FAIL: option-like ref was accepted"; exit 1
fi
grep -qi 'looks like an option' "$scratch/opt.txt" || { echo "FAIL: no option-guard message"; exit 1; }
echo "  option-like ref refused OK"

echo "=== SUBDIR target: paths are target-relative (not repo-root-relative) ==="
# a fresh repo with a subdir; change a tracked file inside the subdir; run
# diffscope with the SUBDIR as target — output must be relative to the subdir.
sub="$scratch/subrepo"; mkdir -p "$sub/pkg"
git -C "$sub" init -q
git -C "$sub" config core.hooksPath /dev/null
git -C "$sub" config commit.gpgsign false
git -C "$sub" config user.email t@t.t
git -C "$sub" config user.name t
printf 'x\n' > "$sub/pkg/tracked.py"
printf 'root\n' > "$sub/rootfile.txt"
git -C "$sub" add -A && git -C "$sub" commit -qm base
printf 'x-changed\n' > "$sub/pkg/tracked.py"   # tracked change inside subdir
printf 'new\n' > "$sub/pkg/untracked.py"       # untracked inside subdir
out=$(python3 "$ds" "$sub/pkg")
# target = subdir -> paths must be 'tracked.py'/'untracked.py', NOT 'pkg/tracked.py'
echo "$out" | grep -qx 'tracked.py'    || { echo "FAIL: tracked change not target-relative: [$out]"; exit 1; }
echo "$out" | grep -qx 'untracked.py'  || { echo "FAIL: untracked not present"; exit 1; }
echo "$out" | grep -q  'pkg/'          && { echo "FAIL: repo-root-relative path leaked: [$out]"; exit 1; }
echo "  subdir target: $(echo "$out" | tr '\n' ' ')(target-relative) OK"

echo ""
echo "script-diffscope: OK"
