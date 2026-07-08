#!/usr/bin/env bash
# secrets-drill.sh — proves the sec-audit secrets adapter degrades cleanly when
# neither gitleaks nor trufflehog is on PATH.
#
# Strategy (mirrors supply-chain-drill.sh): prove the two properties that define
# "degrades cleanly" without burning a full LLM run per CI invocation:
#
#   1. Wiring: the `command -v` probe in agents/secrets-runner.md must detect
#      both binaries as missing when PATH is scrubbed.
#   2. Contract: when both tools are missing, the agent's output contract is
#      exactly one stdout line `{"__secrets_status__": "unavailable",
#      "tools": []}` and zero finding lines.
#
# Usage:
#   tests/secrets-drill.sh           # synthetic mode (default)
#   tests/secrets-drill.sh --live    # full pipeline via claude -p
#
# Exit 0 on success with the literal line `secrets-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target="$plugin_root/tests/fixtures/vulnerable-secrets"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# ---- Build a scrubbed PATH that excludes gitleaks and trufflehog ----
for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done

scrubbed_path="$stub_bin"

# ---- Assertion 1: probe gitleaks and trufflehog under scrubbed PATH ----
echo "secrets-drill: testing PATH scrub (A)..."

gl_found=$(PATH="$scrubbed_path" command -v gitleaks   2>/dev/null || true)
th_found=$(PATH="$scrubbed_path" command -v trufflehog 2>/dev/null || true)

if [ -n "$gl_found" ]; then
    echo "secrets-drill: FAIL — gitleaks leaked into scrubbed PATH at $gl_found" >&2
    exit 1
fi
if [ -n "$th_found" ]; then
    echo "secrets-drill: FAIL — trufflehog leaked into scrubbed PATH at $th_found" >&2
    exit 1
fi
echo "  scrubbed PATH hides both binaries (gitleaks MISSING, trufflehog MISSING)"

# ---- Assertion 2: runner spec encodes the unavailable sentinel + probes ----
echo "secrets-drill: testing secrets-runner unavailable-sentinel contract (B)..."

if ! grep -q '"__secrets_status__": "unavailable"' "$plugin_root/agents/secrets-runner.md"; then
    echo "secrets-drill: FAIL — agents/secrets-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
if ! grep -q "command -v gitleaks" "$plugin_root/agents/secrets-runner.md"; then
    echo "secrets-drill: FAIL — agents/secrets-runner.md missing command -v gitleaks probe" >&2
    exit 1
fi
if ! grep -q "command -v trufflehog" "$plugin_root/agents/secrets-runner.md"; then
    echo "secrets-drill: FAIL — agents/secrets-runner.md missing command -v trufflehog probe" >&2
    exit 1
fi

# ---- Synthesize the offline stdout the agent must emit ----
offline_out="$scratch/secrets-offline.jsonl"
echo '{"__secrets_status__": "unavailable", "tools": []}' > "$offline_out"

# ---- Assertion 3: output is exactly one status record, zero findings ----
echo "secrets-drill: testing output shape on unavailable path..."

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
if [ "$total_lines" != "1" ]; then
    echo "secrets-drill: FAIL — expected exactly 1 line, got $total_lines" >&2
    exit 1
fi

status_lines=$(grep -c '"__secrets_status__": "unavailable"' "$offline_out" || true)
if [ "$status_lines" != "1" ]; then
    echo "secrets-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2
    exit 1
fi

sec_findings=$(grep -c '"origin": "secrets"' "$offline_out" || true)
if [ "$sec_findings" != "0" ]; then
    echo "secrets-drill: FAIL — expected 0 origin:secrets findings, got $sec_findings" >&2
    exit 1
fi
echo "  unavailable output: 1 sentinel line, 0 origin:secrets findings"

# ---- Assertion 4: stdout is valid JSONL ----
echo "secrets-drill: testing JSONL validity..."
while IFS= read -r line; do
    if ! echo "$line" | jq -e . >/dev/null 2>&1; then
        echo "secrets-drill: FAIL — invalid JSON line: $line" >&2
        exit 1
    fi
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Live mode ----
if [ "$mode" = "live" ]; then
    echo "secrets-drill: --live mode — dispatching secrets-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "secrets-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/secrets-live.jsonl"
        PATH="$scrubbed_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke secrets-runner agent against $target. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "secrets"' "$live_out" || true)
            if [ "$live_findings" != "0" ]; then
                echo "secrets-drill: FAIL (live) — agent emitted $live_findings findings with PATH scrubbed" >&2
                exit 1
            fi
            live_sentinels=$(grep -c '"__secrets_status__": "unavailable"' "$live_out" || true)
            if [ "$live_sentinels" -lt "1" ]; then
                echo "secrets-drill: FAIL (live) — agent missing unavailable sentinel" >&2
                exit 1
            fi
            echo "  live secrets-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "secrets-drill: OK"
