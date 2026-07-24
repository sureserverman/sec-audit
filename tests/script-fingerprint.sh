#!/usr/bin/env bash
# script-fingerprint.sh — verifies fingerprint.py: line-shift stability, field
# sensitivity, whitespace normalization, empty-evidence fallback, cross-process
# determinism, and a file manifest that prunes exactly what inventory.py prunes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
fp="scripts/secaudit/fingerprint.py"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

fpof() {  # finding JSON on stdin -> fingerprint
    python3 "$fp" findings - | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['fingerprint'])"
}

base='{"origin":"sast","tool":"semgrep","rule_id":"py.sqli","file":"src/db.py","line":42,"cwe":"CWE-89","evidence":"cur.execute(\"SELECT \" + name)"}'

echo "=== a 40-line shift does NOT change the fingerprint ==="
a=$(echo "$base" | fpof)
b=$(echo "$base" | python3 -c "
import json,sys
f=json.loads(sys.stdin.read()); f['line']=82; print(json.dumps(f))" | fpof)
[ "$a" = "$b" ] || { echo "FAIL: line shift changed identity ($a vs $b)"; exit 1; }
echo "  line-shift stability: OK"

echo "=== whitespace-only reformatting of the evidence does NOT change it ==="
c=$(echo "$base" | python3 -c "
import json,sys
f=json.loads(sys.stdin.read())
f['evidence']='   cur.execute(\"SELECT \"    +   name)  '
print(json.dumps(f))" | fpof)
[ "$a" = "$c" ] || { echo "FAIL: whitespace changed identity"; exit 1; }
echo "  whitespace normalization: OK"

echo "=== rule / file / cwe / evidence / origin / tool each DO change it ==="
for mut in \
  'f["rule_id"]="py.xss"' \
  'f["file"]="src/other.py"' \
  'f["cwe"]="CWE-79"' \
  'f["evidence"]="cur.execute(SAFE)"' \
  'f["origin"]="webapp"' \
  'f["tool"]="bearer"' ; do
    d=$(echo "$base" | python3 -c "
import json,sys
f=json.loads(sys.stdin.read()); $mut; print(json.dumps(f))" | fpof)
    [ "$a" != "$d" ] || { echo "FAIL: mutation [$mut] did not change identity"; exit 1; }
done
echo "  field sensitivity: OK"

echo "=== two distinct findings in the same file never collide ==="
f1=$(echo '{"origin":"sast","tool":"semgrep","rule_id":"a","file":"x.py","cwe":"CWE-1","evidence":"one"}' | fpof)
f2=$(echo '{"origin":"sast","tool":"semgrep","rule_id":"b","file":"x.py","cwe":"CWE-2","evidence":"two"}' | fpof)
[ "$f1" != "$f2" ] || { echo "FAIL: collision"; exit 1; }
echo "  no collision: OK"

echo "=== empty evidence falls back to title, still stable ==="
e1=$(echo '{"origin":"linux","tool":"systemd-analyze","rule_id":"","file":"u.service","cwe":"CWE-250","title":"Unit runs as root"}' | fpof)
e2=$(echo '{"origin":"linux","tool":"systemd-analyze","rule_id":"","file":"u.service","cwe":"CWE-250","title":"Unit runs as root","line":9}' | fpof)
[ "$e1" = "$e2" ] || { echo "FAIL: title fallback unstable"; exit 1; }
e3=$(echo '{"origin":"linux","tool":"systemd-analyze","rule_id":"","file":"u.service","cwe":"CWE-250","title":"Unit has no seccomp filter"}' | fpof)
[ "$e1" != "$e3" ] || { echo "FAIL: different titles collided"; exit 1; }
echo "  title fallback: OK"

echo "=== deterministic across processes (no hash-seed dependence) ==="
s1=$(PYTHONHASHSEED=1 bash -c "echo '$base' | python3 '$fp' findings -" | md5sum)
s2=$(PYTHONHASHSEED=99 bash -c "echo '$base' | python3 '$fp' findings -" | md5sum)
[ "$s1" = "$s2" ] || { echo "FAIL: output varies with PYTHONHASHSEED"; exit 1; }
echo "  cross-process determinism: OK"

echo "=== algo prefix is carried so a future v2 can invalidate cleanly ==="
echo "$a" | grep -q '^v1:' || { echo "FAIL: no algo prefix"; exit 1; }
echo "  algo prefix: OK"

echo "=== manifest: hashes files, prunes exactly inventory.py's SKIP_DIRS ==="
tree="$scratch/tree"; mkdir -p "$tree/src" "$tree/node_modules/pkg" "$tree/.git" "$tree/target"
printf 'print(1)\n'  > "$tree/src/a.py"
printf 'x\n'         > "$tree/README.md"
printf 'junk\n'      > "$tree/node_modules/pkg/index.js"
printf 'junk\n'      > "$tree/.git/config"
printf 'junk\n'      > "$tree/target/blob.bin"
out=$(python3 "$fp" manifest "$tree")
echo "$out" | python3 -c "
import json,sys
m = json.load(sys.stdin)['manifest']
assert 'src/a.py' in m and 'README.md' in m, m
for pruned in ('node_modules/pkg/index.js', '.git/config', 'target/blob.bin'):
    assert pruned not in m, 'SKIP_DIRS not honoured: %s' % pruned
assert len(m['src/a.py']['sha256']) == 64, m
assert m['src/a.py']['size'] == 9, m
print('  manifest content + pruning: OK')
"

echo "=== manifest agrees with inventory.py's pruning set (shared constant) ==="
python3 -c "
import sys; sys.path.insert(0, 'scripts')
from secaudit.fingerprint import SKIP_DIRS as f
from secaudit.inventory import SKIP_DIRS as i
assert f is i or f == i, (f, i)
print('  SKIP_DIRS shared with inventory.py: OK')
"

echo "=== manifest changes iff content changes ==="
h1=$(python3 "$fp" manifest "$tree" | python3 -c "import json,sys; print(json.load(sys.stdin)['manifest']['src/a.py']['sha256'])")
touch "$tree/src/a.py"   # mtime only
h2=$(python3 "$fp" manifest "$tree" | python3 -c "import json,sys; print(json.load(sys.stdin)['manifest']['src/a.py']['sha256'])")
[ "$h1" = "$h2" ] || { echo "FAIL: mtime-only touch changed the hash"; exit 1; }
printf 'print(2)\n' > "$tree/src/a.py"
h3=$(python3 "$fp" manifest "$tree" | python3 -c "import json,sys; print(json.load(sys.stdin)['manifest']['src/a.py']['sha256'])")
[ "$h1" != "$h3" ] || { echo "FAIL: content change did not change the hash"; exit 1; }
echo "  content-addressed, not mtime: OK"

echo "=== --files scoping restricts the manifest to the listed paths ==="
printf 'src/a.py\n' > "$scratch/files.txt"
python3 "$fp" manifest "$tree" --files "$scratch/files.txt" | python3 -c "
import json,sys
m = json.load(sys.stdin)['manifest']
assert list(m) == ['src/a.py'], m
print('  --files scoping: OK')
"

echo "=== a dangling symlink is skipped, not fatal ==="
ln -s /nonexistent "$tree/broken.link"
python3 "$fp" manifest "$tree" >/dev/null || { echo "FAIL: dangling symlink aborted the manifest"; exit 1; }
echo "  symlink tolerance: OK"

echo ""
echo "script-fingerprint: OK"
