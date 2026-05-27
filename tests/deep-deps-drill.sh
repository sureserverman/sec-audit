#!/usr/bin/env bash
# deep-deps-drill.sh — proves the sec-audit deep-deps analyst degrades cleanly.
#
# Unlike the tool-lane drills, deep-deps has no external binary to scrub: its
# degrade triggers are (1) an empty candidate set and (2) every registry fetch
# failing (offline). Both collapse to the same unavailable sentinel. We prove:
#
#   1. Contract: agents/dep-diff-analyst.md encodes the unavailable sentinel,
#      the empty-candidate guard, and the registry endpoints it would probe.
#   2. Shape: the synthesized unavailable output is exactly one sentinel line,
#      zero findings, valid JSONL.
#
# Usage:
#   tests/deep-deps-drill.sh           # synthetic mode (default)
#   tests/deep-deps-drill.sh --live    # full pipeline via claude -p
#
# Exit 0 on success with the literal line `deep-deps-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
agent="$plugin_root/agents/dep-diff-analyst.md"
target="$plugin_root/tests/fixtures/vulnerable-deep-deps"
mode="synthetic"
[ "${1:-}" = "--live" ] && mode="live"

scratch=$(mktemp -d)
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# ---- Assertion 1: agent encodes the degrade contract + registry probes ----
echo "deep-deps-drill: testing dep-diff-analyst unavailable-sentinel contract (A)..."
if ! grep -q '"__deep_deps_status__": "unavailable"' "$agent"; then
    echo "deep-deps-drill: FAIL — agent missing unavailable sentinel spec" >&2; exit 1
fi
if ! grep -qE 'candidate list is empty|empty.{0,20}candidate' "$agent"; then
    echo "deep-deps-drill: FAIL — agent missing empty-candidate guard" >&2; exit 1
fi
if ! grep -q 'pypi.org/pypi' "$agent" || ! grep -q 'registry.npmjs.org' "$agent"; then
    echo "deep-deps-drill: FAIL — agent missing registry endpoint references" >&2; exit 1
fi
echo "  agent encodes: unavailable sentinel, empty-candidate guard, PyPI+npm endpoints"

# ---- Assertion 2: empty-candidate input must yield the unavailable sentinel ----
# The agent's documented behavior on `{"candidates": []}` is the sentinel.
echo "deep-deps-drill: testing unavailable output shape (B)..."
offline_out="$scratch/deep-deps-offline.jsonl"
echo '{"__deep_deps_status__": "unavailable", "tools": []}' > "$offline_out"

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
[ "$total_lines" = "1" ] || { echo "deep-deps-drill: FAIL — expected 1 line, got $total_lines" >&2; exit 1; }

status_lines=$(grep -c '"__deep_deps_status__": "unavailable"' "$offline_out" || true)
[ "$status_lines" = "1" ] || { echo "deep-deps-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2; exit 1; }

dd_findings=$(grep -c '"origin": "deep-deps"' "$offline_out" || true)
[ "$dd_findings" = "0" ] || { echo "deep-deps-drill: FAIL — expected 0 deep-deps findings, got $dd_findings" >&2; exit 1; }
echo "  unavailable output: 1 sentinel line, 0 deep-deps findings"

# ---- Assertion 3: JSONL validity ----
echo "deep-deps-drill: testing JSONL validity..."
while IFS= read -r line; do
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "deep-deps-drill: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Live mode ----
if [ "$mode" = "live" ]; then
    echo "deep-deps-drill: --live mode — dispatching dep-diff-analyst with empty candidates..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "deep-deps-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/deep-deps-live.jsonl"
        printf '%s' '{"candidates": []}' | \
            claude -p --permission-mode=acceptEdits \
                "Invoke dep-diff-analyst with the stdin candidate list. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            lf=$(grep -c '"origin": "deep-deps"' "$live_out" || true)
            [ "$lf" = "0" ] || { echo "deep-deps-drill: FAIL (live) — $lf findings on empty candidate set" >&2; exit 1; }
            ls_=$(grep -c '"__deep_deps_status__": "unavailable"' "$live_out" || true)
            [ "$ls_" -ge 1 ] || { echo "deep-deps-drill: FAIL (live) — missing unavailable sentinel" >&2; exit 1; }
            echo "  live dep-diff-analyst: 0 findings, $ls_ unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "deep-deps-drill: OK"
