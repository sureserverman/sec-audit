#!/usr/bin/env bash
# script-statehome.sh — verifies statehome.py resolves the portfolio state home:
# registry match (incl. subdir longest-prefix), --state-dir override, dev-root
# inference with confirm_required, deterministic _adhoc fallback, disabled
# registry entries ignored, and the unwritable-root error naming --state-dir.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"; cd "$root"
sh_py="scripts/secaudit/statehome.py"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT

vault="$scratch/vault/Portfolio"
dev="$scratch/dev"
reg="$scratch/projects-registry.yaml"
mkdir -p "$vault" "$dev/ai-tools/sec-audit/scripts" "$dev/web/unregistered-app" "$scratch/elsewhere/thing"

cat > "$reg" <<'YAML'
# Portfolio projects registry
version: 1
projects:
  - path: SCRATCH/dev/ai-tools/sec-audit
    name: sec-audit
    area: ai-tools
    enabled: true
    added: 2026-05-23
  - path: SCRATCH/dev/ai-tools/sec
    name: sec
    area: ai-tools
    enabled: true
    added: 2026-05-23
  - path: SCRATCH/dev/web/retired-app
    name: retired-app
    area: web
    enabled: false
    added: 2026-01-01
YAML
sed -i "s|SCRATCH|$scratch|g" "$reg"
mkdir -p "$dev/ai-tools/sec" "$dev/web/retired-app"

export SECAUDIT_PORTFOLIO_ROOT="$vault"
export SECAUDIT_REGISTRY="$reg"
export SECAUDIT_DEV_ROOT="$dev"

j() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

echo "=== registered project -> <vault>/<area>/<name>/security ==="
out=$(python3 "$sh_py" "$dev/ai-tools/sec-audit")
[ "$(echo "$out" | j "['home']")" = "$vault/ai-tools/sec-audit/security" ] \
    || { echo "FAIL: home=$(echo "$out" | j "['home']")"; exit 1; }
[ "$(echo "$out" | j "['source']")" = registry ] || { echo "FAIL: source"; exit 1; }
[ "$(echo "$out" | j "['confirm_required']")" = False ] || { echo "FAIL: confirm_required"; exit 1; }
echo "  registry: OK"

echo "=== SUBDIR of a registered project resolves to that project ==="
out=$(python3 "$sh_py" "$dev/ai-tools/sec-audit/scripts")
[ "$(echo "$out" | j "['home']")" = "$vault/ai-tools/sec-audit/security" ] \
    || { echo "FAIL: subdir home=$(echo "$out" | j "['home']")"; exit 1; }
[ "$(echo "$out" | j "['project']['name']")" = sec-audit ] || { echo "FAIL: subdir name"; exit 1; }
echo "  subdir longest-prefix: OK"

echo "=== longest-prefix, not string-prefix: 'sec-audit' must not match 'sec' ==="
# registry holds both .../sec and .../sec-audit — a naive startswith() picks the
# wrong one for the /sec target's SIBLING path.
out=$(python3 "$sh_py" "$dev/ai-tools/sec")
[ "$(echo "$out" | j "['project']['name']")" = sec ] \
    || { echo "FAIL: sibling matched $(echo "$out" | j "['project']['name']")"; exit 1; }
out=$(python3 "$sh_py" "$dev/ai-tools/sec-audit")
[ "$(echo "$out" | j "['project']['name']")" = sec-audit ] \
    || { echo "FAIL: sec-audit matched $(echo "$out" | j "['project']['name']")"; exit 1; }
echo "  path-boundary matching: OK"

echo "=== disabled registry entry is ignored (falls through to inference) ==="
out=$(python3 "$sh_py" "$dev/web/retired-app")
[ "$(echo "$out" | j "['source']")" = inferred ] \
    || { echo "FAIL: disabled entry used, source=$(echo "$out" | j "['source']")"; exit 1; }
echo "  enabled:false ignored: OK"

echo "=== unregistered under dev root -> inferred + confirm_required ==="
out=$(python3 "$sh_py" "$dev/web/unregistered-app")
[ "$(echo "$out" | j "['home']")" = "$vault/web/unregistered-app/security" ] \
    || { echo "FAIL: inferred home"; exit 1; }
[ "$(echo "$out" | j "['source']")" = inferred ] || { echo "FAIL: inferred source"; exit 1; }
[ "$(echo "$out" | j "['confirm_required']")" = True ] \
    || { echo "FAIL: inferred must require confirmation"; exit 1; }
# once the home exists, no confirmation is needed on later runs
mkdir -p "$vault/web/unregistered-app/security"
out=$(python3 "$sh_py" "$dev/web/unregistered-app")
[ "$(echo "$out" | j "['confirm_required']")" = False ] \
    || { echo "FAIL: existing home must not re-prompt"; exit 1; }
echo "  inference + one-time confirm: OK"

echo "=== outside dev root -> deterministic _adhoc slug ==="
out1=$(python3 "$sh_py" "$scratch/elsewhere/thing")
out2=$(python3 "$sh_py" "$scratch/elsewhere/thing")
[ "$(echo "$out1" | j "['source']")" = adhoc ] || { echo "FAIL: adhoc source"; exit 1; }
[ "$(echo "$out1" | j "['home']")" = "$(echo "$out2" | j "['home']")" ] \
    || { echo "FAIL: adhoc slug not deterministic"; exit 1; }
echo "$(echo "$out1" | j "['home']")" | grep -q "_adhoc/" || { echo "FAIL: no _adhoc segment"; exit 1; }
echo "  adhoc determinism: OK"

echo "=== --state-dir override wins over everything ==="
out=$(python3 "$sh_py" "$dev/ai-tools/sec-audit" --state-dir "$scratch/override")
[ "$(echo "$out" | j "['home']")" = "$scratch/override" ] || { echo "FAIL: override home"; exit 1; }
[ "$(echo "$out" | j "['source']")" = override ] || { echo "FAIL: override source"; exit 1; }
out=$(python3 "$sh_py" "$dev/ai-tools/sec-audit" "--state-dir=$scratch/override2")
[ "$(echo "$out" | j "['home']")" = "$scratch/override2" ] || { echo "FAIL: --state-dir= form"; exit 1; }
echo "  override: OK"

echo "=== missing/unwritable portfolio root -> exit 3 naming --state-dir ==="
SECAUDIT_PORTFOLIO_ROOT="/nonexistent-root-$$/Portfolio" python3 "$sh_py" "$dev/ai-tools/sec-audit" \
    >/dev/null 2>"$scratch/err.txt" && { echo "FAIL: missing root did not error"; exit 1; }
rc=$?
[ "$rc" = 3 ] || { echo "FAIL: expected exit 3, got $rc"; exit 1; }
grep -q -- '--state-dir' "$scratch/err.txt" || { echo "FAIL: error does not name --state-dir"; exit 1; }
grep -qi 'not fall back' "$scratch/err.txt" || { echo "FAIL: error does not state the no-fallback rule"; exit 1; }
echo "  unwritable root: exit 3 + actionable message OK"

echo "=== side-effect free: resolving never creates the home ==="
before=$(find "$vault" -type d | sort)
python3 "$sh_py" "$scratch/elsewhere/thing" >/dev/null
after=$(find "$vault" -type d | sort)
[ "$before" = "$after" ] || { echo "FAIL: resolution created directories"; exit 1; }
echo "  no side effects: OK"

echo ""
echo "script-statehome: OK"
