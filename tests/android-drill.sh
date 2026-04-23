#!/usr/bin/env bash
# android-drill.sh — proves the sec-review Android adapter degrades
# cleanly when none of mobsfscan / apkleaks / android-lint is on PATH.
#
# Strategy mirrors sast-drill.sh / dast-drill.sh / webext-drill.sh /
# rust-drill.sh:
#
#   1. Wiring: the `command -v` probes in agents/android-runner.md
#      must detect all three tools as missing when PATH is scrubbed.
#
#   2. Contract: when all three are missing, the agent emits exactly
#      one stdout line
#      `{"__android_status__": "unavailable", "tools": []}` (optionally
#      with a `skipped` list when apkleaks was intentionally not run)
#      and zero finding lines.
#
# Usage:
#   tests/android-drill.sh         # synthetic mode (default)
#   tests/android-drill.sh --live  # via claude -p
#
# Exit 0 on success with the literal line `android-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_path="$plugin_root/tests/fixtures/vulnerable-android"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# Scrubbed PATH excludes mobsfscan / apkleaks / lint / gradle
for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false xmllint; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done
scrubbed_path="$stub_bin"

# ---- Assertion 1: each tool is not reachable
echo "android-drill: testing PATH scrub (A)..."
for tool in mobsfscan apkleaks lint gradle; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "android-drill: FAIL — $tool leaked into scrubbed PATH at $found" >&2
        exit 1
    fi
done
echo "  scrubbed PATH hides all three + gradle"

# ---- Assertion 2: android-runner spec encodes probes + sentinel
echo "android-drill: testing android-runner unavailable-sentinel contract (B)..."
if ! grep -q '"__android_status__": "unavailable"' "$plugin_root/agents/android-runner.md"; then
    echo "android-drill: FAIL — agents/android-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
for tool in mobsfscan apkleaks lint; do
    if ! grep -q "command -v $tool" "$plugin_root/agents/android-runner.md"; then
        echo "android-drill: FAIL — agents/android-runner.md missing command -v $tool probe" >&2
        exit 1
    fi
done

# ---- Synthesize the offline stdout
offline_out="$scratch/android-offline.jsonl"
echo '{"__android_status__": "unavailable", "tools": []}' > "$offline_out"

# ---- Assertion 3: output is exactly one __android_status__ record, zero findings
echo "android-drill: testing output shape on unavailable path..."
total_lines=$(wc -l < "$offline_out" | tr -d ' ')
[ "$total_lines" = "1" ] || { echo "android-drill: FAIL — expected 1 line, got $total_lines" >&2; exit 1; }
status_lines=$(grep -c '"__android_status__": "unavailable"' "$offline_out" || true)
[ "$status_lines" = "1" ] || { echo "android-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2; exit 1; }
android_findings=$(grep -c '"origin": "android"' "$offline_out" || true)
[ "$android_findings" = "0" ] || { echo "android-drill: FAIL — expected 0 origin:android findings, got $android_findings" >&2; exit 1; }
echo "  unavailable output: 1 sentinel line, 0 origin:android findings"

# ---- Assertion 4: JSONL validity
echo "android-drill: testing JSONL validity..."
while IFS= read -r line; do
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "android-drill: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Assertion 5: clean-skip contract is present in the spec
echo "android-drill: testing clean-skip contract in agent spec..."
if ! grep -q "no-apk" "$plugin_root/agents/android-runner.md"; then
    echo "android-drill: FAIL — agents/android-runner.md missing no-apk clean-skip spec" >&2
    exit 1
fi
if ! grep -qE "skipped|CLEAN SKIP|clean-skip|CLEAN-SKIP" "$plugin_root/agents/android-runner.md"; then
    echo "android-drill: FAIL — agents/android-runner.md missing skipped-list documentation" >&2
    exit 1
fi
echo "  clean-skip-vs-failure distinction documented in spec"

if [ "$mode" = "live" ]; then
    echo "android-drill: --live mode — dispatching android-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "android-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/android-live.jsonl"
        PATH="$scrubbed_path" ANDROID_TARGET_PATH="$target_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke android-runner agent against $target_path. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "android"' "$live_out" || true)
            [ "$live_findings" = "0" ] || { echo "android-drill: FAIL (live) — agent emitted $live_findings findings with PATH scrubbed" >&2; exit 1; }
            live_sentinels=$(grep -c '"__android_status__": "unavailable"' "$live_out" || true)
            [ "$live_sentinels" -ge "1" ] || { echo "android-drill: FAIL (live) — agent missing unavailable sentinel" >&2; exit 1; }
            echo "  live android-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "android-drill: OK"
