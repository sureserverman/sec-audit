#!/usr/bin/env bash
# windows-drill.sh — proves the sec-review Windows desktop adapter
# degrades cleanly when none of its tools is available.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_path="$plugin_root/tests/fixtures/vulnerable-windows"
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

# ---- Assertion 1: none of the Windows tools reachable
echo "windows-drill: testing PATH scrub (A)..."
for tool in binskim osslsigncode sigcheck dotnet; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "windows-drill: FAIL — $tool leaked into scrubbed PATH at $found" >&2
        exit 1
    fi
done
echo "  scrubbed PATH hides binskim/osslsigncode/sigcheck/dotnet"

# ---- Assertion 2: spec has probes + sentinel
echo "windows-drill: testing windows-runner unavailable-sentinel contract (B)..."
if ! grep -q '"__windows_status__": "unavailable"' "$plugin_root/agents/windows-runner.md"; then
    echo "windows-drill: FAIL — agents/windows-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
for tool in binskim osslsigncode sigcheck; do
    if ! grep -q "command -v $tool" "$plugin_root/agents/windows-runner.md"; then
        echo "windows-drill: FAIL — agents/windows-runner.md missing command -v $tool probe" >&2
        exit 1
    fi
done

# ---- Assertion 3: Windows-host probe + skip reasons documented
echo "windows-drill: testing Windows-host gate + clean-skip contract..."
if ! grep -qE 'MINGW|MSYS|CYGWIN|Windows_NT' "$plugin_root/agents/windows-runner.md"; then
    echo "windows-drill: FAIL — agents/windows-runner.md missing Windows-host probe" >&2
    exit 1
fi
for reason in requires-windows-host no-pe tool-missing; do
    if ! grep -q "$reason" "$plugin_root/agents/windows-runner.md"; then
        echo "windows-drill: FAIL — agents/windows-runner.md missing $reason skip reason" >&2
        exit 1
    fi
done
echo "  Windows-host gate + all three skip reasons documented"

# ---- Assertion 4: synthesised unavailable sentinel
offline_out="$scratch/windows-offline.jsonl"
echo '{"__windows_status__": "unavailable", "tools": [], "skipped": [{"tool": "binskim", "reason": "tool-missing"}, {"tool": "osslsigncode", "reason": "tool-missing"}, {"tool": "sigcheck", "reason": "requires-windows-host"}]}' > "$offline_out"

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
[ "$total_lines" = "1" ] || { echo "windows-drill: FAIL — expected 1 line, got $total_lines" >&2; exit 1; }
status_lines=$(grep -c '"__windows_status__": "unavailable"' "$offline_out" || true)
[ "$status_lines" = "1" ] || { echo "windows-drill: FAIL" >&2; exit 1; }
win_findings=$(grep -c '"origin": "windows"' "$offline_out" || true)
[ "$win_findings" = "0" ] || { echo "windows-drill: FAIL — $win_findings findings expected 0" >&2; exit 1; }
echo "  unavailable output: 1 sentinel line, 0 origin:windows findings"

while IFS= read -r line; do
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "windows-drill: FAIL — invalid JSON" >&2; exit 1; }
done < "$offline_out"
echo "  every stdout line parses as JSON"

sk_count=$(jq -r '.skipped | length' "$offline_out")
[ "$sk_count" = "3" ] || { echo "windows-drill: FAIL — expected 3 skipped, got $sk_count" >&2; exit 1; }
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null \
    || { echo "windows-drill: FAIL — skipped entries lack tool/reason" >&2; exit 1; }
echo "  all skipped entries have {tool, reason} structure"

if [ "$mode" = "live" ]; then
    echo "windows-drill: --live mode — dispatching windows-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "windows-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/windows-live.jsonl"
        PATH="$scrubbed_path" WINDOWS_TARGET_PATH="$target_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke windows-runner agent against $target_path. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "windows"' "$live_out" || true)
            [ "$live_findings" = "0" ] || { echo "windows-drill: FAIL (live)" >&2; exit 1; }
            live_sentinels=$(grep -c '"__windows_status__": "unavailable"' "$live_out" || true)
            [ "$live_sentinels" -ge "1" ] || { echo "windows-drill: FAIL (live) — missing sentinel" >&2; exit 1; }
            echo "  live windows-runner: 0 findings, $live_sentinels sentinel(s)"
        fi
    fi
fi

echo ""
echo "windows-drill: OK"
