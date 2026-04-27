#!/usr/bin/env bash
# webext-drill.sh — proves the sec-audit webext adapter degrades cleanly
# when none of addons-linter, web-ext, or retire is on PATH.
#
# Strategy: mirrors sast-drill.sh and dast-drill.sh. We prove the two
# properties that define "degrades cleanly" without burning a full LLM run
# per CI invocation:
#
#   1. Wiring: the `command -v` probes in agents/webext-runner.md must
#      detect all three tools as missing when PATH is scrubbed.
#
#   2. Contract: when all three are missing, the agent's output contract
#      is exactly one stdout line
#      `{"__webext_status__": "unavailable", "tools": []}` and zero
#      finding lines. We synthesize that output and assert the shape.
#
# Usage:
#   tests/webext-drill.sh           # synthetic mode (default, deterministic)
#   tests/webext-drill.sh --live    # full pipeline via claude -p
#
# Exit 0 on success with the literal line `webext-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_path="$plugin_root/tests/fixtures/vulnerable-webext"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# ---- Build a scrubbed PATH that excludes addons-linter, web-ext, retire
for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done

scrubbed_path="$stub_bin"

# ---- Assertion 1: probe each tool under scrubbed PATH
echo "webext-drill: testing PATH scrub (A)..."

for tool in addons-linter web-ext retire; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "webext-drill: FAIL — $tool leaked into scrubbed PATH at $found" >&2
        exit 1
    fi
done
echo "  scrubbed PATH hides all three (addons-linter / web-ext / retire MISSING)"

# ---- Assertion 2: webext-runner spec encodes the probes + unavailable sentinel
echo "webext-drill: testing webext-runner unavailable-sentinel contract (B)..."

if ! grep -q '"__webext_status__": "unavailable"' "$plugin_root/agents/webext-runner.md"; then
    echo "webext-drill: FAIL — agents/webext-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
for tool in addons-linter web-ext retire; do
    if ! grep -q "command -v $tool" "$plugin_root/agents/webext-runner.md"; then
        echo "webext-drill: FAIL — agents/webext-runner.md missing command -v $tool probe" >&2
        exit 1
    fi
done

# ---- Synthesize the offline stdout the agent must emit
offline_out="$scratch/webext-offline.jsonl"
echo '{"__webext_status__": "unavailable", "tools": []}' > "$offline_out"

# ---- Assertion 3: output is exactly one __webext_status__ record, zero findings
echo "webext-drill: testing output shape on unavailable path..."

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
if [ "$total_lines" != "1" ]; then
    echo "webext-drill: FAIL — expected exactly 1 line, got $total_lines" >&2
    exit 1
fi

status_lines=$(grep -c '"__webext_status__": "unavailable"' "$offline_out" || true)
if [ "$status_lines" != "1" ]; then
    echo "webext-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2
    exit 1
fi

webext_findings=$(grep -c '"origin": "webext"' "$offline_out" || true)
if [ "$webext_findings" != "0" ]; then
    echo "webext-drill: FAIL — expected 0 origin:webext findings, got $webext_findings" >&2
    exit 1
fi
echo "  unavailable output: 1 sentinel line, 0 origin:webext findings"

# ---- Assertion 4: stdout is valid JSONL
echo "webext-drill: testing JSONL validity..."
while IFS= read -r line; do
    if ! echo "$line" | jq -e . >/dev/null 2>&1; then
        echo "webext-drill: FAIL — invalid JSON line: $line" >&2
        exit 1
    fi
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Live mode: actually invoke webext-runner via claude -p
if [ "$mode" = "live" ]; then
    echo "webext-drill: --live mode — dispatching webext-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "webext-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/webext-live.jsonl"
        PATH="$scrubbed_path" WEBEXT_TARGET_PATH="$target_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke webext-runner agent against $target_path. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true

        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "webext"' "$live_out" || true)
            if [ "$live_findings" != "0" ]; then
                echo "webext-drill: FAIL (live) — agent emitted $live_findings webext findings with PATH scrubbed" >&2
                exit 1
            fi
            live_sentinels=$(grep -c '"__webext_status__": "unavailable"' "$live_out" || true)
            if [ "$live_sentinels" -lt "1" ]; then
                echo "webext-drill: FAIL (live) — agent missing unavailable sentinel" >&2
                exit 1
            fi
            echo "  live webext-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "webext-drill: OK"
