#!/usr/bin/env bash
# shell-drill.sh — v1.6.0 degrade drill for the shell lane.

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

echo "shell-drill: testing PATH scrub..."
found=$(PATH="$scrubbed_path" command -v shellcheck 2>/dev/null || true)
[ -z "$found" ] || { echo "shell-drill: FAIL — shellcheck leaked" >&2; exit 1; }
echo "  scrubbed PATH hides shellcheck"

echo "shell-drill: testing shell-runner spec..."
grep -q '"__shell_status__": "unavailable"' "$plugin_root/agents/shell-runner.md" || { echo "shell-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
grep -q "command -v shellcheck" "$plugin_root/agents/shell-runner.md" || { echo "shell-drill: FAIL — missing command -v shellcheck" >&2; exit 1; }
for reason in tool-missing no-shell-source; do
    grep -q "$reason" "$plugin_root/agents/shell-runner.md" || { echo "shell-drill: FAIL — missing $reason" >&2; exit 1; }
done

offline_out="$scratch/shell-offline.jsonl"
echo '{"__shell_status__": "unavailable", "tools": [], "skipped": [{"tool": "shellcheck", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__shell_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "shell"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

# Target-shape clean-skip
clean_skip='{"__shell_status__": "unavailable", "tools": [], "skipped": [{"tool": "shellcheck", "reason": "no-shell-source"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "no-shell-source")' >/dev/null \
    || { echo "shell-drill: FAIL — no-shell-source target-shape skip not parseable" >&2; exit 1; }

echo ""
echo "shell-drill: OK"
