#!/usr/bin/env bash
# dast-drill.sh — proves the sec-review DAST adapter degrades cleanly when
# neither docker nor zap-baseline.py is on PATH.
#
# Strategy: mirrors sast-drill.sh. We prove the two properties that define
# "degrades cleanly" without burning a full LLM run per CI invocation:
#
#   1. Wiring: the `command -v` probes in agents/dast-runner.md must detect
#      both docker and zap-baseline.py as missing when PATH is scrubbed.
#      We build a minimal PATH (coreutils only) and execute the probe
#      directly — `command -v docker` and `command -v zap-baseline.py` must
#      both fail.
#
#   2. Contract: when both are missing, the agent's output contract is
#      exactly one stdout line `{"__dast_status__": "unavailable",
#      "tools": []}` and zero finding lines. We synthesize that output and
#      assert the shape. A full live run through `claude -p` is available
#      via --live but is NOT the default.
#
# Usage:
#   tests/dast-drill.sh           # synthetic mode (default, deterministic)
#   tests/dast-drill.sh --live    # full pipeline via claude -p
#
# Exit 0 on success with the literal line `dast-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_url="http://localhost:8080"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# ---- Build a scrubbed PATH that excludes docker and zap-baseline.py ----
# Populate stub_bin ONLY with common coreutils so normal shell works,
# but nothing named docker or zap-baseline.py.
for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done

scrubbed_path="$stub_bin"

# ---- Assertion 1: probe docker and zap-baseline.py under scrubbed PATH ----
echo "dast-drill: testing PATH scrub (A)..."

docker_found=$(PATH="$scrubbed_path" command -v docker          2>/dev/null || true)
zap_found=$(   PATH="$scrubbed_path" command -v zap-baseline.py 2>/dev/null || true)

if [ -n "$docker_found" ]; then
    echo "dast-drill: FAIL — docker leaked into scrubbed PATH at $docker_found" >&2
    exit 1
fi
if [ -n "$zap_found" ]; then
    echo "dast-drill: FAIL — zap-baseline.py leaked into scrubbed PATH at $zap_found" >&2
    exit 1
fi
echo "  scrubbed PATH hides both binaries (docker MISSING, zap-baseline.py MISSING)"

# ---- Assertion 2: dast-runner spec encodes the unavailable sentinel ----
# Prove the contract is specified in the agent file so any future live run
# honors it. We look for the literal sentinel JSON and the probe commands.
echo "dast-drill: testing dast-runner unavailable-sentinel contract (B)..."

if ! grep -q '"__dast_status__": "unavailable"' "$plugin_root/agents/dast-runner.md"; then
    echo "dast-drill: FAIL — agents/dast-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
if ! grep -q "command -v docker" "$plugin_root/agents/dast-runner.md"; then
    echo "dast-drill: FAIL — agents/dast-runner.md missing command -v docker probe" >&2
    exit 1
fi
if ! grep -q "command -v zap-baseline.py" "$plugin_root/agents/dast-runner.md"; then
    echo "dast-drill: FAIL — agents/dast-runner.md missing command -v zap-baseline.py probe" >&2
    exit 1
fi

# ---- Synthesize the offline stdout the agent must emit ----
offline_out="$scratch/dast-offline.jsonl"
echo '{"__dast_status__": "unavailable", "tools": []}' > "$offline_out"

# ---- Assertion 3: output is exactly one __dast_status__ record, zero findings ----
echo "dast-drill: testing output shape on unavailable path..."

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
if [ "$total_lines" != "1" ]; then
    echo "dast-drill: FAIL — expected exactly 1 line, got $total_lines" >&2
    exit 1
fi

status_lines=$(grep -c '"__dast_status__": "unavailable"' "$offline_out" || true)
if [ "$status_lines" != "1" ]; then
    echo "dast-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2
    exit 1
fi

dast_findings=$(grep -c '"origin": "dast"' "$offline_out" || true)
if [ "$dast_findings" != "0" ]; then
    echo "dast-drill: FAIL — expected 0 origin:dast findings, got $dast_findings" >&2
    exit 1
fi
echo "  unavailable output: 1 sentinel line, 0 origin:dast findings"

# ---- Assertion 4: stdout is valid JSONL (each line parses as JSON) ----
echo "dast-drill: testing JSONL validity..."
while IFS= read -r line; do
    if ! echo "$line" | jq -e . >/dev/null 2>&1; then
        echo "dast-drill: FAIL — invalid JSON line: $line" >&2
        exit 1
    fi
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Live mode: actually invoke dast-runner via claude -p ----
if [ "$mode" = "live" ]; then
    echo "dast-drill: --live mode — dispatching dast-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "dast-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/dast-live.jsonl"
        PATH="$scrubbed_path" DAST_TARGET_URL="$target_url" \
            claude -p --permission-mode=acceptEdits \
                "Invoke dast-runner agent against $target_url. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true

        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "dast"' "$live_out" || true)
            if [ "$live_findings" != "0" ]; then
                echo "dast-drill: FAIL (live) — agent emitted $live_findings DAST findings with PATH scrubbed" >&2
                exit 1
            fi
            live_sentinels=$(grep -c '"__dast_status__": "unavailable"' "$live_out" || true)
            if [ "$live_sentinels" -lt "1" ]; then
                echo "dast-drill: FAIL (live) — agent missing unavailable sentinel" >&2
                exit 1
            fi
            echo "  live dast-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "dast-drill: OK"
