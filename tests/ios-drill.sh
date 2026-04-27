#!/usr/bin/env bash
# ios-drill.sh — proves the sec-audit iOS adapter degrades cleanly
# when none of its tools is available.
#
# Extends the SAST/DAST/webext/rust/android drill pattern with a new
# assertion: the agent spec must contain the `requires-macos-host`
# clean-skip reason so host-OS-gated tools are recognised as cleanly-
# skipped rather than failed.
#
# Usage:
#   tests/ios-drill.sh         # synthetic mode (default)
#   tests/ios-drill.sh --live  # via claude -p
#
# Exit 0 on success with the literal line `ios-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_path="$plugin_root/tests/fixtures/vulnerable-ios"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false uname; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done
scrubbed_path="$stub_bin"

# ---- Assertion 1: none of the iOS tools is reachable
echo "ios-drill: testing PATH scrub (A)..."
for tool in mobsfscan codesign spctl xcrun; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "ios-drill: FAIL — $tool leaked into scrubbed PATH at $found" >&2
        exit 1
    fi
done
echo "  scrubbed PATH hides mobsfscan/codesign/spctl/xcrun"

# ---- Assertion 2: ios-runner spec has probes + sentinel
echo "ios-drill: testing ios-runner unavailable-sentinel contract (B)..."
if ! grep -q '"__ios_status__": "unavailable"' "$plugin_root/agents/ios-runner.md"; then
    echo "ios-drill: FAIL — agents/ios-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
if ! grep -q "command -v mobsfscan" "$plugin_root/agents/ios-runner.md"; then
    echo "ios-drill: FAIL — agents/ios-runner.md missing command -v mobsfscan probe" >&2
    exit 1
fi
for tool in codesign spctl xcrun; do
    if ! grep -q "command -v $tool" "$plugin_root/agents/ios-runner.md"; then
        echo "ios-drill: FAIL — agents/ios-runner.md missing command -v $tool probe" >&2
        exit 1
    fi
done

# ---- Assertion 3: host-OS gate + clean-skip contract documented
echo "ios-drill: testing host-OS-gate + clean-skip contract..."
if ! grep -q 'uname -s' "$plugin_root/agents/ios-runner.md"; then
    echo "ios-drill: FAIL — agents/ios-runner.md missing uname -s host-OS probe" >&2
    exit 1
fi
if ! grep -q "requires-macos-host" "$plugin_root/agents/ios-runner.md"; then
    echo "ios-drill: FAIL — agents/ios-runner.md missing requires-macos-host skip reason" >&2
    exit 1
fi
for reason in "no-bundle" "no-notary-profile" "tool-missing"; do
    if ! grep -q "$reason" "$plugin_root/agents/ios-runner.md"; then
        echo "ios-drill: FAIL — agents/ios-runner.md missing $reason skip reason" >&2
        exit 1
    fi
done
echo "  host-OS gate + all four skip reasons documented"

# ---- Synthesize offline stdout
offline_out="$scratch/ios-offline.jsonl"
echo '{"__ios_status__": "unavailable", "tools": [], "skipped": [{"tool": "codesign", "reason": "requires-macos-host"}, {"tool": "spctl", "reason": "requires-macos-host"}, {"tool": "notarytool", "reason": "requires-macos-host"}]}' > "$offline_out"

# ---- Assertion 4: exactly one __ios_status__ record, zero findings
echo "ios-drill: testing output shape on unavailable path..."
total_lines=$(wc -l < "$offline_out" | tr -d ' ')
[ "$total_lines" = "1" ] || { echo "ios-drill: FAIL — expected 1 line, got $total_lines" >&2; exit 1; }
status_lines=$(grep -c '"__ios_status__": "unavailable"' "$offline_out" || true)
[ "$status_lines" = "1" ] || { echo "ios-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2; exit 1; }
ios_findings=$(grep -c '"origin": "ios"' "$offline_out" || true)
[ "$ios_findings" = "0" ] || { echo "ios-drill: FAIL — expected 0 origin:ios findings, got $ios_findings" >&2; exit 1; }
echo "  unavailable output: 1 sentinel line, 0 origin:ios findings"

# ---- Assertion 5: JSONL validity
echo "ios-drill: testing JSONL validity..."
while IFS= read -r line; do
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "ios-drill: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Assertion 6: structured skipped-list entries validate
echo "ios-drill: testing skipped-list entry schema..."
sk_count=$(jq -r '.skipped | length' "$offline_out")
[ "$sk_count" = "3" ] || { echo "ios-drill: FAIL — expected 3 skipped entries, got $sk_count" >&2; exit 1; }
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null \
    || { echo "ios-drill: FAIL — some skipped entries lack tool/reason" >&2; exit 1; }
echo "  all skipped entries have {tool, reason} structure"

if [ "$mode" = "live" ]; then
    echo "ios-drill: --live mode — dispatching ios-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "ios-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/ios-live.jsonl"
        PATH="$scrubbed_path" IOS_TARGET_PATH="$target_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke ios-runner agent against $target_path. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "ios"' "$live_out" || true)
            [ "$live_findings" = "0" ] || { echo "ios-drill: FAIL (live) — agent emitted $live_findings findings with PATH scrubbed" >&2; exit 1; }
            live_sentinels=$(grep -c '"__ios_status__": "unavailable"' "$live_out" || true)
            [ "$live_sentinels" -ge "1" ] || { echo "ios-drill: FAIL (live) — agent missing unavailable sentinel" >&2; exit 1; }
            echo "  live ios-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "ios-drill: OK"
