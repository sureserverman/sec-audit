#!/usr/bin/env bash
# ai-tools-drill.sh — proves the sec-audit AI-tools adapter degrades
# cleanly when neither jq nor mcp-scan is on PATH.
#
# Strategy mirrors sast-drill.sh / webext-drill.sh: scrub PATH so
# both tools are missing, assert the agent's documented degrade
# branch resolves to the unavailable sentinel + zero findings.
# A live run via `claude -p` is available with --live but is not
# the default.
#
# Usage:
#   tests/ai-tools-drill.sh           # synthetic mode (default)
#   tests/ai-tools-drill.sh --live    # full pipeline via claude -p
#
# Exit 0 on success with the literal line `ai-tools-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target="$plugin_root/tests/fixtures/vulnerable-ai-tools"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

# Build a scrubbed PATH that excludes both jq and mcp-scan/snyk-agent-scan.
# We deliberately do NOT symlink jq into the stub.
for cmd in bash sh env cat grep sed awk head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done

scrubbed_path="$stub_bin"

# Assertion 1: neither tool appears under scrubbed PATH.
echo "ai-tools-drill: testing PATH scrub (A)..."

jq_found=$(PATH="$scrubbed_path" command -v jq 2>/dev/null || true)
mcpscan_found=$(PATH="$scrubbed_path" command -v mcp-scan 2>/dev/null || true)
snyk_found=$(PATH="$scrubbed_path" command -v snyk-agent-scan 2>/dev/null || true)

if [ -n "$jq_found" ]; then
    echo "ai-tools-drill: FAIL — jq leaked into scrubbed PATH at $jq_found" >&2
    exit 1
fi
if [ -n "$mcpscan_found" ]; then
    echo "ai-tools-drill: FAIL — mcp-scan leaked into scrubbed PATH at $mcpscan_found" >&2
    exit 1
fi
if [ -n "$snyk_found" ]; then
    echo "ai-tools-drill: FAIL — snyk-agent-scan leaked into scrubbed PATH at $snyk_found" >&2
    exit 1
fi
echo "  scrubbed PATH hides all three binaries (jq MISSING, mcp-scan MISSING, snyk-agent-scan MISSING)"

# Assertion 2: ai-tools-runner spec encodes the degrade contract for both tools.
echo "ai-tools-drill: testing ai-tools-runner unavailable-sentinel contract (B)..."

runner="$plugin_root/agents/ai-tools-runner.md"

if ! grep -q '"__ai_tools_status__":"unavailable"' "$runner"; then
    echo "ai-tools-drill: FAIL — agents/ai-tools-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
if ! grep -q "command -v jq" "$runner"; then
    echo "ai-tools-drill: FAIL — agents/ai-tools-runner.md missing 'command -v jq' probe" >&2
    exit 1
fi
if ! grep -qE "command -v mcp-scan" "$runner"; then
    echo "ai-tools-drill: FAIL — agents/ai-tools-runner.md missing 'command -v mcp-scan' probe" >&2
    exit 1
fi
if ! grep -qE "command -v snyk-agent-scan" "$runner"; then
    echo "ai-tools-drill: FAIL — agents/ai-tools-runner.md missing 'command -v snyk-agent-scan' fallback probe" >&2
    exit 1
fi
echo "  ai-tools-runner.md probes all three binaries and documents the sentinel"

# Assertion 3: the runner uses ONLY safe mcp-scan modes (`inspect`
# and `--skills`) and explicitly forbids the dangerous ones. We
# check by direct presence/absence of canonical invocation strings:
#   present: `"$mcp_scan_bin" inspect`, `"$mcp_scan_bin" --skills`
#   absent : `"$mcp_scan_bin" scan` and `--dangerously-run-mcp-servers`
#            anywhere except inside a documented "MUST NOT" / "Do NOT"
#            sentence.
echo "ai-tools-drill: testing safety contract — runner must invoke only 'inspect' mode..."

if ! grep -qE '"\$mcp_scan_bin" +inspect' "$runner"; then
    echo "ai-tools-drill: FAIL — runner missing canonical \"\$mcp_scan_bin\" inspect invocation" >&2
    exit 1
fi
if ! grep -qE '"\$mcp_scan_bin" +--skills' "$runner"; then
    echo "ai-tools-drill: FAIL — runner missing canonical \"\$mcp_scan_bin\" --skills invocation" >&2
    exit 1
fi
# Forbidden invocation: `"$mcp_scan_bin" scan` as a command (NOT
# `mcp-scan scan` inside a forbid-this prose sentence).
if grep -qE '"\$mcp_scan_bin" +scan\b' "$runner"; then
    echo "ai-tools-drill: FAIL — runner uses forbidden 'scan' subcommand as live invocation" >&2
    exit 1
fi
# Documentation must explicitly forbid the dangerous flag and subcmd.
if ! grep -qE 'NOT invoke .*\bscan\b|MUST NEVER.*\bscan\b|NEVER invokes? .*\bscan\b|never .*\bscan\b' "$runner"; then
    echo "ai-tools-drill: FAIL — runner does not explicitly forbid the 'scan' subcommand in prose" >&2
    exit 1
fi
if ! grep -qE 'NOT.*--dangerously-run-mcp-servers|MUST NOT pass.*--dangerously-run-mcp-servers' "$runner"; then
    echo "ai-tools-drill: FAIL — runner does not explicitly forbid --dangerously-run-mcp-servers" >&2
    exit 1
fi
echo "  runner uses inspect/--skills only and explicitly forbids 'scan' + --dangerously-run-mcp-servers"

# Assertion 4: synthesize the unavailable stdout the agent must emit.
offline_out="$scratch/ai-tools-offline.jsonl"
echo '{"__ai_tools_status__":"unavailable","tools":[],"skipped":[{"tool":"jq","reason":"tool-missing"},{"tool":"mcp-scan","reason":"tool-missing"}]}' > "$offline_out"

echo "ai-tools-drill: testing output shape on unavailable path..."

total_lines=$(wc -l < "$offline_out" | tr -d ' ')
if [ "$total_lines" != "1" ]; then
    echo "ai-tools-drill: FAIL — expected exactly 1 line, got $total_lines" >&2
    exit 1
fi

status_lines=$(grep -c '"__ai_tools_status__":"unavailable"' "$offline_out" || true)
if [ "$status_lines" != "1" ]; then
    echo "ai-tools-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2
    exit 1
fi

ai_findings=$(grep -c '"origin":"ai-tools"' "$offline_out" || true)
if [ "$ai_findings" != "0" ]; then
    echo "ai-tools-drill: FAIL — expected 0 origin:ai-tools findings, got $ai_findings" >&2
    exit 1
fi

# Assert structured skipped entries name BOTH tools with reason.
skipped_jq=$(python3 -c '
import json, sys
obj = json.loads(open(sys.argv[1]).readline())
sk = obj.get("skipped", [])
hit = sum(1 for e in sk if e.get("tool")=="jq" and e.get("reason")=="tool-missing")
print(hit)
' "$offline_out")
skipped_mcp=$(python3 -c '
import json, sys
obj = json.loads(open(sys.argv[1]).readline())
sk = obj.get("skipped", [])
hit = sum(1 for e in sk if e.get("tool")=="mcp-scan" and e.get("reason")=="tool-missing")
print(hit)
' "$offline_out")

if [ "$skipped_jq" != "1" ] || [ "$skipped_mcp" != "1" ]; then
    echo "ai-tools-drill: FAIL — skipped[] must list jq + mcp-scan with tool-missing (got jq=$skipped_jq mcp-scan=$skipped_mcp)" >&2
    exit 1
fi
echo "  unavailable output: 1 sentinel line, 0 origin:ai-tools findings, both tools listed in skipped[]"

# Assertion 5: stdout is valid JSONL.
echo "ai-tools-drill: testing JSONL validity..."
while IFS= read -r line; do
    if ! python3 -c 'import json,sys;json.loads(sys.argv[1])' "$line" >/dev/null 2>&1; then
        echo "ai-tools-drill: FAIL — invalid JSON line: $line" >&2
        exit 1
    fi
done < "$offline_out"
echo "  every stdout line parses as JSON"

# Assertion 6: fixture exists and has expected shape (sanity).
if [ ! -d "$target" ]; then
    echo "ai-tools-drill: FAIL — fixture missing: $target" >&2
    exit 1
fi
if [ ! -f "$target/.mcp.json" ]; then
    echo "ai-tools-drill: FAIL — fixture missing .mcp.json" >&2
    exit 1
fi

# Live mode (optional).
if [ "$mode" = "live" ]; then
    echo "ai-tools-drill: --live mode — dispatching ai-tools-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "ai-tools-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/ai-tools-live.jsonl"
        PATH="$scrubbed_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke ai-tools-runner agent against $target. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true

        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin":"ai-tools"' "$live_out" || true)
            if [ "$live_findings" != "0" ]; then
                echo "ai-tools-drill: FAIL (live) — agent emitted $live_findings ai-tools findings with PATH scrubbed" >&2
                exit 1
            fi
            live_sentinels=$(grep -c '"__ai_tools_status__":"unavailable"' "$live_out" || true)
            if [ "$live_sentinels" -lt "1" ]; then
                echo "ai-tools-drill: FAIL (live) — agent missing unavailable sentinel" >&2
                exit 1
            fi
            echo "  live ai-tools-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "ai-tools-drill: OK"
