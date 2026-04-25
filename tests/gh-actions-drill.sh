#!/usr/bin/env bash
# gh-actions-drill.sh — v1.3.0 degrade drill for the GitHub Actions lane.

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

echo "gh-actions-drill: testing PATH scrub..."
for tool in actionlint zizmor; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "gh-actions-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides actionlint/zizmor"

echo "gh-actions-drill: testing gh-actions-runner spec..."
grep -q '"__gh_actions_status__": "unavailable"' "$plugin_root/agents/gh-actions-runner.md" || { echo "gh-actions-drill: FAIL" >&2; exit 1; }
for tool in actionlint zizmor; do
    grep -q "command -v $tool" "$plugin_root/agents/gh-actions-runner.md" || { echo "gh-actions-drill: FAIL" >&2; exit 1; }
done
grep -q "tool-missing" "$plugin_root/agents/gh-actions-runner.md" || { echo "gh-actions-drill: FAIL" >&2; exit 1; }

offline_out="$scratch/gh-actions-offline.jsonl"
echo '{"__gh_actions_status__": "unavailable", "tools": [], "skipped": [{"tool": "actionlint", "reason": "tool-missing"}, {"tool": "zizmor", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__gh_actions_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "gh-actions"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

echo ""
echo "gh-actions-drill: OK"
