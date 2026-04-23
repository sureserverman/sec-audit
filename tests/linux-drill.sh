#!/usr/bin/env bash
# linux-drill.sh — proves the sec-review Linux desktop adapter
# degrades cleanly when none of its tools is available.
#
# Extends the drill pattern from v0.6-v0.9 with assertions for the
# new host-systemd clean-skip vocabulary (requires-systemd-host,
# no-debian-source, no-elf).
#
# Usage:
#   tests/linux-drill.sh         # synthetic mode (default)
#   tests/linux-drill.sh --live  # via claude -p
#
# Exit 0 on success with the literal line `linux-drill: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
target_path="$plugin_root/tests/fixtures/vulnerable-linux"
mode="synthetic"

if [ "${1:-}" = "--live" ]; then
    mode="live"
fi

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find file test true false uname; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    if [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ]; then
        ln -s "$resolved" "$stub_bin/$cmd"
    fi
done
scrubbed_path="$stub_bin"

# ---- Assertion 1: none of the Linux tools reachable
echo "linux-drill: testing PATH scrub (A)..."
for tool in systemd-analyze lintian checksec systemctl; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "linux-drill: FAIL — $tool leaked into scrubbed PATH at $found" >&2
        exit 1
    fi
done
echo "  scrubbed PATH hides systemd-analyze / lintian / checksec / systemctl"

# ---- Assertion 2: linux-runner spec has probes + sentinel
echo "linux-drill: testing linux-runner unavailable-sentinel contract (B)..."
if ! grep -q '"__linux_status__": "unavailable"' "$plugin_root/agents/linux-runner.md"; then
    echo "linux-drill: FAIL — agents/linux-runner.md missing unavailable sentinel spec" >&2
    exit 1
fi
for tool in systemd-analyze lintian checksec; do
    if ! grep -q "command -v $tool" "$plugin_root/agents/linux-runner.md"; then
        echo "linux-drill: FAIL — agents/linux-runner.md missing command -v $tool probe" >&2
        exit 1
    fi
done
# Host-systemd probe documented
if ! grep -qE '/run/systemd/system|systemctl --version' "$plugin_root/agents/linux-runner.md"; then
    echo "linux-drill: FAIL — agents/linux-runner.md missing systemd-host probe" >&2
    exit 1
fi
echo "  probes for all three tools + host-systemd check documented"

# ---- Assertion 3: all clean-skip reasons documented
echo "linux-drill: testing clean-skip reasons..."
for reason in requires-systemd-host no-debian-source no-elf tool-missing; do
    if ! grep -q "$reason" "$plugin_root/agents/linux-runner.md"; then
        echo "linux-drill: FAIL — agents/linux-runner.md missing $reason clean-skip reason" >&2
        exit 1
    fi
done
echo "  all four clean-skip reasons documented"

# ---- Synthesize offline stdout
offline_out="$scratch/linux-offline.jsonl"
echo '{"__linux_status__": "unavailable", "tools": [], "skipped": [{"tool": "systemd-analyze", "reason": "requires-systemd-host"}, {"tool": "lintian", "reason": "tool-missing"}, {"tool": "checksec", "reason": "no-elf"}]}' > "$offline_out"

# ---- Assertion 4: exactly one record, zero findings
echo "linux-drill: testing output shape on unavailable path..."
total_lines=$(wc -l < "$offline_out" | tr -d ' ')
[ "$total_lines" = "1" ] || { echo "linux-drill: FAIL — expected 1 line, got $total_lines" >&2; exit 1; }
status_lines=$(grep -c '"__linux_status__": "unavailable"' "$offline_out" || true)
[ "$status_lines" = "1" ] || { echo "linux-drill: FAIL — expected 1 unavailable record, got $status_lines" >&2; exit 1; }
lin_findings=$(grep -c '"origin": "linux"' "$offline_out" || true)
[ "$lin_findings" = "0" ] || { echo "linux-drill: FAIL — expected 0 origin:linux findings, got $lin_findings" >&2; exit 1; }
echo "  unavailable output: 1 sentinel line, 0 origin:linux findings"

# ---- Assertion 5: JSONL validity
echo "linux-drill: testing JSONL validity..."
while IFS= read -r line; do
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "linux-drill: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$offline_out"
echo "  every stdout line parses as JSON"

# ---- Assertion 6: structured skipped entries
echo "linux-drill: testing skipped-list entry schema..."
sk_count=$(jq -r '.skipped | length' "$offline_out")
[ "$sk_count" = "3" ] || { echo "linux-drill: FAIL — expected 3 skipped entries, got $sk_count" >&2; exit 1; }
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null \
    || { echo "linux-drill: FAIL — some skipped entries lack tool/reason" >&2; exit 1; }
echo "  all skipped entries have {tool, reason} structure"

if [ "$mode" = "live" ]; then
    echo "linux-drill: --live mode — dispatching linux-runner via claude -p..."
    if ! command -v claude >/dev/null 2>&1; then
        echo "linux-drill: SKIP live — claude CLI not in PATH" >&2
    else
        live_out="$scratch/linux-live.jsonl"
        PATH="$scrubbed_path" LINUX_TARGET_PATH="$target_path" \
            claude -p --permission-mode=acceptEdits \
                "Invoke linux-runner agent against $target_path. Write JSONL output to $live_out." \
                2>&1 | tail -30 || true
        if [ -f "$live_out" ]; then
            live_findings=$(grep -c '"origin": "linux"' "$live_out" || true)
            [ "$live_findings" = "0" ] || { echo "linux-drill: FAIL (live) — agent emitted $live_findings findings with PATH scrubbed" >&2; exit 1; }
            live_sentinels=$(grep -c '"__linux_status__": "unavailable"' "$live_out" || true)
            [ "$live_sentinels" -ge "1" ] || { echo "linux-drill: FAIL (live) — agent missing unavailable sentinel" >&2; exit 1; }
            echo "  live linux-runner: 0 findings, $live_sentinels unavailable sentinel(s)"
        fi
    fi
fi

echo ""
echo "linux-drill: OK"
