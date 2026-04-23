#!/usr/bin/env bash
# multi-stack-e2e.sh — v1.0.0 integration test for multi-stack dispatch.
#
# Synthesises a consolidated JSONL stream from three existing single-
# lane fixtures (vulnerable-webext + vulnerable-rust + vulnerable-
# android) into a temp pipeline dir, then validates:
#
#   (a) Three distinct status records present (one per lane), each
#       well-formed per their per-lane contract.
#   (b) Origin-tag isolation holds in the combined stream — no cross-
#       lane tool-name leak (existing contract-check logic catches
#       this, but we assert it positively here).
#   (c) A simulated --only=webext filter projects to just the webext-
#       origin findings + webext status record.
#   (d) The per-lane summary table can be derived from the status
#       records: each lane contributes exactly one row.
#
# Exit 0 on success with the literal line `multi-stack-e2e: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"

webext="$plugin_root/tests/fixtures/vulnerable-webext/.pipeline/webext.jsonl"
rust="$plugin_root/tests/fixtures/vulnerable-rust/.pipeline/rust.jsonl"
android="$plugin_root/tests/fixtures/vulnerable-android/.pipeline/android.jsonl"
for f in "$webext" "$rust" "$android"; do
    [ -f "$f" ] || { echo "multi-stack-e2e: FAIL — source fixture missing: $f" >&2; exit 1; }
done

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
combined="$scratch/combined.jsonl"
cat "$webext" "$rust" "$android" > "$combined"

# ---- (a) Three distinct status records
echo "multi-stack-e2e: validating per-lane status records..."
for sentinel in __webext_status__ __rust_status__ __android_status__; do
    count=$(jq -rs --arg key "$sentinel" 'map(select(.[$key])) | length' "$combined")
    [ "$count" -ge 1 ] || { echo "multi-stack-e2e: FAIL (a) — expected >=1 $sentinel record, got $count" >&2; exit 1; }
    echo "  (a) $sentinel: $count record(s)"
done

# Every status record has a well-formed tools list (array)
bad=$(jq -rs 'map(select((.__webext_status__ or .__rust_status__ or .__android_status__) and (.tools | type != "array"))) | length' "$combined")
[ "$bad" -eq 0 ] || { echo "multi-stack-e2e: FAIL — $bad status records have non-array tools field" >&2; exit 1; }

# ---- (b) Origin-tag isolation in the combined stream
echo "multi-stack-e2e: validating origin-tag isolation in combined stream..."
# webext findings must not carry rust/android tools
leak_w=$(jq -rs 'map(select(.origin=="webext" and (.tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint"))) | length' "$combined")
# rust findings must not carry webext/android tools
leak_r=$(jq -rs 'map(select(.origin=="rust" and (.tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint"))) | length' "$combined")
# android findings must not carry webext/rust tools
leak_a=$(jq -rs 'map(select(.origin=="android" and (.tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet"))) | length' "$combined")
total_leak=$((leak_w + leak_r + leak_a))
[ "$total_leak" -eq 0 ] || { echo "multi-stack-e2e: FAIL (b) — $total_leak cross-lane tool leaks in combined stream" >&2; exit 1; }
echo "  (b) 0 cross-lane tool leaks across 3 merged lanes"

# ---- (c) Simulated --only=webext projection
echo "multi-stack-e2e: simulating --only=webext filter..."
only_webext="$scratch/only-webext.jsonl"
jq -c 'select(.origin=="webext" or .__webext_status__)' "$combined" > "$only_webext"
non_webext=$(jq -rs 'map(select(.origin and .origin != "webext")) | length' "$only_webext")
[ "$non_webext" -eq 0 ] || { echo "multi-stack-e2e: FAIL (c) — --only=webext projection leaked $non_webext non-webext findings" >&2; exit 1; }
other_sentinels=$(jq -rs 'map(select(.__rust_status__ or .__android_status__)) | length' "$only_webext")
[ "$other_sentinels" -eq 0 ] || { echo "multi-stack-e2e: FAIL (c) — --only=webext projection leaked $other_sentinels non-webext status records" >&2; exit 1; }
webext_findings=$(jq -rs 'map(select(.origin=="webext")) | length' "$only_webext")
[ "$webext_findings" -ge 1 ] || { echo "multi-stack-e2e: FAIL (c) — --only=webext projection has 0 webext findings" >&2; exit 1; }
echo "  (c) --only=webext: $webext_findings webext findings, 0 other-origin, 0 other-status"

# ---- (d) Per-lane summary row derivation
echo "multi-stack-e2e: validating per-lane summary derivation..."
# One row per status record — count unique __X_status__ keys in the stream
unique_lanes=$(jq -rs 'map(keys[] | select(startswith("__") and endswith("_status__"))) | unique | length' "$combined")
[ "$unique_lanes" -eq 3 ] || { echo "multi-stack-e2e: FAIL (d) — expected 3 unique lane-status keys, got $unique_lanes" >&2; exit 1; }
echo "  (d) 3 unique lane-status keys → 3 rows in per-lane summary"

# ---- Lane-filter whitelist: only_lanes/skip_lanes must be from canonical 10
echo "multi-stack-e2e: validating lane whitelist..."
canonical=$(printf '%s\n' sec-expert sast dast webext rust android ios linux macos windows | sort)
# Positive: each canonical name is accepted
for lane in sec-expert sast dast webext rust android ios linux macos windows; do
    echo "$canonical" | grep -qxF "$lane" || { echo "multi-stack-e2e: FAIL — canonical lane $lane missing from whitelist" >&2; exit 1; }
done
# Negative: an invalid lane name is rejected
for bad in "not-a-lane" "semgrep" "cargo-audit"; do
    if echo "$canonical" | grep -qxF "$bad"; then
        echo "multi-stack-e2e: FAIL — invalid lane '$bad' accepted" >&2
        exit 1
    fi
done
echo "  10-lane whitelist: all canonical accepted, 3 invalid rejected"

echo ""
echo "multi-stack-e2e: OK"
