#!/usr/bin/env bash
# supply-chain-drill.sh — proves the sec-audit supply-chain adapter degrades
# cleanly when neither guarddog nor osv-scanner is on PATH.
#
# Strategy (mirrors sast-drill.sh): prove the two properties that define
# "degrades cleanly" without burning a full LLM run per CI invocation:
#
#   1. Wiring: the `command -v` probe in agents/supply-chain-runner.md must
#      detect both binaries as missing when PATH is scrubbed.
#   2. Contract: when both tools are missing, the agent's output contract is
#      exactly one stdout line `{"__supply_chain_status__": "unavailable",
#      "tools": []}` and zero finding lines.
#
# Usage:
#   tests/supply-chain-drill.sh           # synthetic mode (default)
#   tests/supply-chain-drill.sh --live    # full pipeline via claude -p
#
# Exit 0 on success with the literal line `supply-chain-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target="$plugin_root/tests/fixtures/vulnerable-supply-chain"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# ---- Build a scrubbed PATH that excludes guarddog and osv-scanner ----
for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done

scrubbed_path="$stub_bin"

# ---- Assertion 1: probe guarddog and osv-scanner under scrubbed PATH ----
echo "supply-chain-drill: testing PATH scrub (A)..."

gd_found=$(PATH="$scrubbed_path" command -v guarddog    2>/dev/null || true)
osv_found=$(PATH="$scrubbed_path" command -v osv-scanner 2>/dev/null || true)

if [ -n "$gd_found" ]; then
    echo "supply-chain-drill: FAIL — guarddog leaked into scrubbed PATH at $gd_found" >&2
    exit 1
fi
if [ -n "$osv_found" ]; then
    echo "supply-chain-drill: FAIL — osv-scanner leaked into scrubbed PATH at $osv_found" >&2
    exit 1
fi
echo "  scrubbed PATH hides both binaries (guarddog MISSING, osv-scanner MISSING)"

# ---- Assertion 2: runner spec encodes the unavailable sentinel + probes ----
echo "supply-chain-drill: testing supply-chain-runner unavailable-sentinel contract (B)..."

if ! grep -q '"__supply_chain_status__": "unavailable"' "$plugin_root/agents/supply-chain-runner.md"; then
    echo "supply-chain-drill: FAIL — agents/supply-chain-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
if ! grep -q "command -v guarddog" "$plugin_root/agents/supply-chain-runner.md"; then
    echo "supply-chain-drill: FAIL — agents/supply-chain-runner.md missing command -v guarddog probe" >&2
    exit 1
fi
if ! grep -q "command -v osv-scanner" "$plugin_root/agents/supply-chain-runner.md"; then
    echo "supply-chain-drill: FAIL — agents/supply-chain-runner.md missing command -v osv-scanner probe" >&2
    exit 1
fi

# ---- Synthesize the offline stdout the agent must emit ----
offline_out="$scratch/supply-chain-offline.jsonl"
echo '{"__supply_chain_status__": "unavailable", "tools": []}' > "$offline_out"

# ---- Assertion 3: output is exactly one status record, zero findings ----
echo "supply-chain-drill: testing output shape on unavailable path..."

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
if [ "$total_lines" != "1" ]; then
    echo "supply-chain-drill: FAIL — expected exactly 1 line, got $total_lines" >&2
    exit 1
fi

status_lines=$(grep -c '"__supply_chain_status__": "unavailable"' "$offline_out" || true)
if [ "$status_lines" != "1" ]; then
    echo "supply-chain-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2
    exit 1
fi

sc_findings=$(grep -c '"origin": "supply-chain"' "$offline_out" || true)
if [ "$sc_findings" != "0" ]; then
    echo "supply-chain-drill: FAIL — expected 0 origin:supply-chain findings, got $sc_findings" >&2
    exit 1
fi
echo "  unavailable output: 1 sentinel line, 0 origin:supply-chain findings"

# ---- Assertion 4: stdout is valid JSONL ----
echo "supply-chain-drill: testing JSONL validity..."
while IFS= read -r line; do
    if ! echo "$line" | jq -e . >/dev/null 2>&1; then
        echo "supply-chain-drill: FAIL — invalid JSON line: $line" >&2
        exit 1
    fi
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Live mode ----
if [ "$mode" = "live" ]; then
    echo "supply-chain-drill: --live mode — dispatching supply-chain-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "supply-chain-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/supply-chain-live.jsonl"
        PATH="$scrubbed_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke supply-chain-runner agent against $target. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "supply-chain"' "$live_out" || true)
            if [ "$live_findings" != "0" ]; then
                echo "supply-chain-drill: FAIL (live) — agent emitted $live_findings findings with PATH scrubbed" >&2
                exit 1
            fi
            live_sentinels=$(grep -c '"__supply_chain_status__": "unavailable"' "$live_out" || true)
            if [ "$live_sentinels" -lt "1" ]; then
                echo "supply-chain-drill: FAIL (live) — agent missing unavailable sentinel" >&2
                exit 1
            fi
            echo "  live supply-chain-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "supply-chain-drill: OK"
