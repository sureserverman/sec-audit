#!/usr/bin/env bash
# netcfg-drill.sh — v1.9.0 degrade drill for the netcfg lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false uname xargs; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ] && ln -s "$resolved" "$stub_bin/$cmd"
done
scrubbed_path="$stub_bin"

echo "netcfg-drill: testing PATH scrub..."
for tool in sing-box xray; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "netcfg-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides sing-box/xray"

echo "netcfg-drill: testing netcfg-runner spec..."
grep -q '"__netcfg_status__": "unavailable"' "$plugin_root/agents/netcfg-runner.md" || { echo "netcfg-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
for tool in sing-box xray; do
    grep -q "command -v $tool" "$plugin_root/agents/netcfg-runner.md" || { echo "netcfg-drill: FAIL — missing command -v $tool" >&2; exit 1; }
done
for reason in tool-missing no-singbox-config no-xray-config; do
    grep -q "$reason" "$plugin_root/agents/netcfg-runner.md" || { echo "netcfg-drill: FAIL — missing $reason" >&2; exit 1; }
done
# Critical: must use the STRUCTURAL validator subcommands, not run.
grep -q "sing-box check" "$plugin_root/agents/netcfg-runner.md" || { echo "netcfg-drill: FAIL — missing sing-box check (must use structural validator, not run)" >&2; exit 1; }
grep -q "xray test" "$plugin_root/agents/netcfg-runner.md" || { echo "netcfg-drill: FAIL — missing xray test" >&2; exit 1; }

offline_out="$scratch/netcfg-offline.jsonl"
echo '{"__netcfg_status__": "unavailable", "tools": [], "skipped": [{"tool": "sing-box", "reason": "tool-missing"}, {"tool": "xray", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__netcfg_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "netcfg"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

clean_skip='{"__netcfg_status__": "unavailable", "tools": [], "skipped": [{"tool": "sing-box", "reason": "no-singbox-config"}, {"tool": "xray", "reason": "no-xray-config"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "no-singbox-config" or .reason == "no-xray-config")' >/dev/null \
    || { echo "netcfg-drill: FAIL — target-shape skip-reason vocabulary not parseable" >&2; exit 1; }

echo ""
echo "netcfg-drill: OK"
