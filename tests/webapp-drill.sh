#!/usr/bin/env bash
# webapp-drill.sh — v1.14.0 degrade drill for the Webapp lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"

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

echo "webapp-drill: testing PATH scrub..."
for tool in bearer njsscan brakeman; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "webapp-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides bearer/njsscan/brakeman"

echo "webapp-drill: testing webapp-runner spec..."
grep -q '"__webapp_status__": "unavailable"' "$plugin_root/agents/webapp-runner.md" || { echo "webapp-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
for tool in bearer njsscan brakeman; do
    grep -q "command -v $tool" "$plugin_root/agents/webapp-runner.md" || { echo "webapp-drill: FAIL — missing command -v $tool" >&2; exit 1; }
done
for reason in tool-missing no-webapp-source no-node-source no-rails-source; do
    grep -q "$reason" "$plugin_root/agents/webapp-runner.md" || { echo "webapp-drill: FAIL — missing $reason" >&2; exit 1; }
done

offline_out="$scratch/webapp-offline.jsonl"
echo '{"__webapp_status__": "unavailable", "tools": [], "skipped": [{"tool": "bearer", "reason": "tool-missing"}, {"tool": "njsscan", "reason": "tool-missing"}, {"tool": "brakeman", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__webapp_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "webapp"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

clean_skip='{"__webapp_status__": "partial", "tools": ["bearer"], "skipped": [{"tool": "njsscan", "reason": "no-node-source"}, {"tool": "brakeman", "reason": "no-rails-source"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "no-rails-source")' >/dev/null \
    || { echo "webapp-drill: FAIL — no-rails-source target-shape skip not parseable" >&2; exit 1; }

echo ""
echo "webapp-drill: OK"
