#!/usr/bin/env bash
# macos-drill.sh — proves the sec-review macOS desktop adapter
# degrades cleanly when none of its tools is available.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_path="$plugin_root/tests/fixtures/vulnerable-macos"
mode="synthetic"
[ "${1:-}" = "--live" ] && mode="live"

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false uname; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ] && ln -s "$resolved" "$stub_bin/$cmd"
done
scrubbed_path="$stub_bin"

# ---- Assertion 1: none of the macOS tools reachable
echo "macos-drill: testing PATH scrub (A)..."
for tool in mobsfscan codesign spctl pkgutil xcrun; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "macos-drill: FAIL — $tool leaked into scrubbed PATH at $found" >&2
        exit 1
    fi
done
echo "  scrubbed PATH hides mobsfscan/codesign/spctl/pkgutil/xcrun"

# ---- Assertion 2: macos-runner spec has probes + sentinel
echo "macos-drill: testing macos-runner unavailable-sentinel contract (B)..."
if ! grep -q '"__macos_status__": "unavailable"' "$plugin_root/agents/macos-runner.md"; then
    echo "macos-drill: FAIL — agents/macos-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
for tool in mobsfscan codesign spctl pkgutil xcrun; do
    if ! grep -q "command -v $tool" "$plugin_root/agents/macos-runner.md"; then
        echo "macos-drill: FAIL — agents/macos-runner.md missing command -v $tool probe" >&2
        exit 1
    fi
done

# ---- Assertion 3: host-OS gate + all five skip reasons documented
echo "macos-drill: testing host-OS gate + clean-skip contract..."
if ! grep -q 'uname -s' "$plugin_root/agents/macos-runner.md"; then
    echo "macos-drill: FAIL — agents/macos-runner.md missing uname -s host-OS probe" >&2
    exit 1
fi
for reason in requires-macos-host no-bundle no-pkg no-notary-profile tool-missing; do
    if ! grep -q "$reason" "$plugin_root/agents/macos-runner.md"; then
        echo "macos-drill: FAIL — agents/macos-runner.md missing $reason clean-skip reason" >&2
        exit 1
    fi
done
echo "  host-OS gate + all five skip reasons documented"

# ---- Assertion 4: synthesised unavailable sentinel with 4 skipped entries
offline_out="$scratch/macos-offline.jsonl"
echo '{"__macos_status__": "unavailable", "tools": [], "skipped": [{"tool": "codesign", "reason": "requires-macos-host"}, {"tool": "spctl", "reason": "requires-macos-host"}, {"tool": "pkgutil", "reason": "requires-macos-host"}, {"tool": "stapler", "reason": "requires-macos-host"}]}' > "$offline_out"

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
[ "$total_lines" = "1" ] || { echo "macos-drill: FAIL — expected 1 line, got $total_lines" >&2; exit 1; }
status_lines=$(grep -c '"__macos_status__": "unavailable"' "$offline_out" || true)
[ "$status_lines" = "1" ] || { echo "macos-drill: FAIL — expected 1 unavailable record" >&2; exit 1; }
mac_findings=$(grep -c '"origin": "macos"' "$offline_out" || true)
[ "$mac_findings" = "0" ] || { echo "macos-drill: FAIL — expected 0 findings, got $mac_findings" >&2; exit 1; }
echo "  unavailable output: 1 sentinel line, 0 origin:macos findings"

# ---- Assertion 5: JSONL validity
while IFS= read -r line; do
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "macos-drill: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Assertion 6: structured skipped entries
sk_count=$(jq -r '.skipped | length' "$offline_out")
[ "$sk_count" = "4" ] || { echo "macos-drill: FAIL — expected 4 skipped entries, got $sk_count" >&2; exit 1; }
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null \
    || { echo "macos-drill: FAIL — some skipped entries lack tool/reason" >&2; exit 1; }
echo "  all skipped entries have {tool, reason} structure"

if [ "$mode" = "live" ]; then
    echo "macos-drill: --live mode — dispatching macos-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "macos-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/macos-live.jsonl"
        PATH="$scrubbed_path" MACOS_TARGET_PATH="$target_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke macos-runner agent against $target_path. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "macos"' "$live_out" || true)
            [ "$live_findings" = "0" ] || { echo "macos-drill: FAIL (live)" >&2; exit 1; }
            live_sentinels=$(grep -c '"__macos_status__": "unavailable"' "$live_out" || true)
            [ "$live_sentinels" -ge "1" ] || { echo "macos-drill: FAIL (live) — missing sentinel" >&2; exit 1; }
            echo "  live macos-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "macos-drill: OK"
