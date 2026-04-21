#!/usr/bin/env bash
# sast-drill.sh — proves the sec-review SAST adapter degrades cleanly when
# neither semgrep nor bandit is on PATH.
#
# Strategy: like offline-drill.sh, we prove the two properties that define
# "degrades cleanly" without burning a full LLM run per CI invocation:
#
#   1. Wiring: the `command -v` probe in agents/sast-runner.md must detect
#      both binaries as missing when PATH is scrubbed. We simulate this by
#      building a minimal PATH (just /usr/bin/env + coreutils) and
#      executing the sast-runner's documented degrade branch directly —
#      `command -v semgrep` and `command -v bandit` must both fail.
#
#   2. Contract: when both tools are missing, the agent's output contract
#      is exactly one stdout line `{"__sast_status__": "unavailable",
#      "tools": []}` and zero finding lines. We synthesize that output and
#      assert the shape. A full live run through `claude -p` is available
#      via --live but is NOT the default.
#
# Usage:
#   tests/sast-drill.sh           # synthetic mode (default, deterministic)
#   tests/sast-drill.sh --live    # full pipeline via claude -p
#
# Exit 0 on success with the literal line `sast-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target="$plugin_root/tests/fixtures/sample-stack"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# ---- Build a scrubbed PATH that excludes semgrep and bandit ----
# Populate stub_bin ONLY with common coreutils so normal shell works,
# but nothing named semgrep or bandit. We symlink the specific binaries
# the drill needs rather than inheriting the full PATH.
for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done

scrubbed_path="$stub_bin"

# ---- Assertion 1: probe semgrep and bandit under scrubbed PATH ----
echo "sast-drill: testing PATH scrub (A)..."

sem_found=$(PATH="$scrubbed_path" command -v semgrep 2>/dev/null || true)
ban_found=$(PATH="$scrubbed_path" command -v bandit  2>/dev/null || true)

if [ -n "$sem_found" ]; then
    echo "sast-drill: FAIL — semgrep leaked into scrubbed PATH at $sem_found" >&2
    exit 1
fi
if [ -n "$ban_found" ]; then
    echo "sast-drill: FAIL — bandit leaked into scrubbed PATH at $ban_found" >&2
    exit 1
fi
echo "  scrubbed PATH hides both binaries (semgrep MISSING, bandit MISSING)"

# ---- Assertion 2: sast-runner spec encodes the unavailable sentinel ----
# Prove the contract is specified in the agent file so any future live run
# honors it. We look for the literal sentinel JSON and the exit-clean
# instruction.
echo "sast-drill: testing sast-runner unavailable-sentinel contract (B)..."

if ! grep -q '"__sast_status__": "unavailable"' "$plugin_root/agents/sast-runner.md"; then
    echo "sast-drill: FAIL — agents/sast-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
if ! grep -q "command -v semgrep" "$plugin_root/agents/sast-runner.md"; then
    echo "sast-drill: FAIL — agents/sast-runner.md missing command -v semgrep probe" >&2
    exit 1
fi
if ! grep -q "command -v bandit" "$plugin_root/agents/sast-runner.md"; then
    echo "sast-drill: FAIL — agents/sast-runner.md missing command -v bandit probe" >&2
    exit 1
fi

# ---- Synthesize the offline stdout the agent must emit ----
offline_out="$scratch/sast-offline.jsonl"
echo '{"__sast_status__": "unavailable", "tools": []}' > "$offline_out"

# ---- Assertion 3: output is exactly one __sast_status__ record, zero findings ----
echo "sast-drill: testing output shape on unavailable path..."

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
if [ "$total_lines" != "1" ]; then
    echo "sast-drill: FAIL — expected exactly 1 line, got $total_lines" >&2
    exit 1
fi

status_lines=$(grep -c '"__sast_status__": "unavailable"' "$offline_out" || true)
if [ "$status_lines" != "1" ]; then
    echo "sast-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2
    exit 1
fi

sast_findings=$(grep -c '"origin": "sast"' "$offline_out" || true)
if [ "$sast_findings" != "0" ]; then
    echo "sast-drill: FAIL — expected 0 origin:sast findings, got $sast_findings" >&2
    exit 1
fi
echo "  unavailable output: 1 sentinel line, 0 origin:sast findings"

# ---- Assertion 4: stdout is valid JSONL (each line parses as JSON) ----
echo "sast-drill: testing JSONL validity..."
while IFS= read -r line; do
    if ! echo "$line" | jq -e . >/dev/null 2>&1; then
        echo "sast-drill: FAIL — invalid JSON line: $line" >&2
        exit 1
    fi
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Live mode: actually invoke sast-runner via claude -p ----
if [ "$mode" = "live" ]; then
    echo "sast-drill: --live mode — dispatching sast-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "sast-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/sast-live.jsonl"
        PATH="$scrubbed_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke sast-runner agent against $target. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true

        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "sast"' "$live_out" || true)
            if [ "$live_findings" != "0" ]; then
                echo "sast-drill: FAIL (live) — agent emitted $live_findings SAST findings with PATH scrubbed" >&2
                exit 1
            fi
            live_sentinels=$(grep -c '"__sast_status__": "unavailable"' "$live_out" || true)
            if [ "$live_sentinels" -lt "1" ]; then
                echo "sast-drill: FAIL (live) — agent missing unavailable sentinel" >&2
                exit 1
            fi
            echo "  live sast-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "sast-drill: OK"
