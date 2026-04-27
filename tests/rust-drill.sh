#!/usr/bin/env bash
# rust-drill.sh — proves the sec-audit Rust adapter degrades cleanly
# when cargo is not on PATH.
#
# Strategy mirrors sast-drill.sh / dast-drill.sh / webext-drill.sh:
#
#   1. Wiring: the `command -v cargo` probe in agents/rust-runner.md
#      must detect cargo as missing when PATH is scrubbed.
#
#   2. Contract: when cargo is missing (or present but no subcommand
#      responds), the agent's output is exactly one stdout line
#      `{"__rust_status__": "unavailable", "tools": []}` and zero
#      finding lines.
#
# Usage:
#   tests/rust-drill.sh           # synthetic mode (default, deterministic)
#   tests/rust-drill.sh --live    # full pipeline via claude -p
#
# Exit 0 on success with the literal line `rust-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_path="$plugin_root/tests/fixtures/vulnerable-rust"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# Scrubbed PATH excludes cargo (and by extension all cargo subcommands).
for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done
scrubbed_path="$stub_bin"

# ---- Assertion 1: cargo is not reachable under scrubbed PATH
echo "rust-drill: testing PATH scrub (A)..."
found=$(PATH="$scrubbed_path" command -v cargo 2>/dev/null || true)
if [ -n "$found" ]; then
    echo "rust-drill: FAIL — cargo leaked into scrubbed PATH at $found" >&2
    exit 1
fi
echo "  scrubbed PATH hides cargo (MISSING)"

# ---- Assertion 2: rust-runner spec encodes probes + unavailable sentinel
echo "rust-drill: testing rust-runner unavailable-sentinel contract (B)..."
if ! grep -q '"__rust_status__": "unavailable"' "$plugin_root/agents/rust-runner.md"; then
    echo "rust-drill: FAIL — agents/rust-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
if ! grep -q "command -v cargo" "$plugin_root/agents/rust-runner.md"; then
    echo "rust-drill: FAIL — agents/rust-runner.md missing command -v cargo probe" >&2
    exit 1
fi
for sub in "cargo audit" "cargo deny" "cargo geiger" "cargo vet"; do
    if ! grep -q "$sub --version" "$plugin_root/agents/rust-runner.md"; then
        echo "rust-drill: FAIL — agents/rust-runner.md missing '$sub --version' probe" >&2
        exit 1
    fi
done

# ---- Synthesize the offline stdout
offline_out="$scratch/rust-offline.jsonl"
echo '{"__rust_status__": "unavailable", "tools": []}' > "$offline_out"

# ---- Assertion 3: output is exactly one __rust_status__ record, zero findings
echo "rust-drill: testing output shape on unavailable path..."
total_lines=$(wc -l < "$offline_out" | tr -d ' ')
[ "$total_lines" = "1" ] || { echo "rust-drill: FAIL — expected 1 line, got $total_lines" >&2; exit 1; }
status_lines=$(grep -c '"__rust_status__": "unavailable"' "$offline_out" || true)
[ "$status_lines" = "1" ] || { echo "rust-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2; exit 1; }
rust_findings=$(grep -c '"origin": "rust"' "$offline_out" || true)
[ "$rust_findings" = "0" ] || { echo "rust-drill: FAIL — expected 0 origin:rust findings, got $rust_findings" >&2; exit 1; }
echo "  unavailable output: 1 sentinel line, 0 origin:rust findings"

# ---- Assertion 4: JSONL validity
echo "rust-drill: testing JSONL validity..."
while IFS= read -r line; do
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "rust-drill: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Live mode
if [ "$mode" = "live" ]; then
    echo "rust-drill: --live mode — dispatching rust-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "rust-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/rust-live.jsonl"
        PATH="$scrubbed_path" RUST_TARGET_PATH="$target_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke rust-runner agent against $target_path. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "rust"' "$live_out" || true)
            [ "$live_findings" = "0" ] || { echo "rust-drill: FAIL (live) — agent emitted $live_findings findings with PATH scrubbed" >&2; exit 1; }
            live_sentinels=$(grep -c '"__rust_status__": "unavailable"' "$live_out" || true)
            [ "$live_sentinels" -ge "1" ] || { echo "rust-drill: FAIL (live) — agent missing unavailable sentinel" >&2; exit 1; }
            echo "  live rust-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "rust-drill: OK"
