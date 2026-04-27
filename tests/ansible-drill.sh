#!/usr/bin/env bash
# ansible-drill.sh — v1.8.0 degrade drill for the Ansible lane.

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

echo "ansible-drill: testing PATH scrub..."
found=$(PATH="$scrubbed_path" command -v ansible-lint 2>/dev/null || true)
[ -z "$found" ] || { echo "ansible-drill: FAIL — ansible-lint leaked" >&2; exit 1; }
echo "  scrubbed PATH hides ansible-lint"

echo "ansible-drill: testing ansible-runner spec..."
grep -q '"__ansible_status__": "unavailable"' "$plugin_root/agents/ansible-runner.md" || { echo "ansible-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
grep -q "command -v ansible-lint" "$plugin_root/agents/ansible-runner.md" || { echo "ansible-drill: FAIL — missing command -v ansible-lint" >&2; exit 1; }
for reason in tool-missing no-playbook; do
    grep -q "$reason" "$plugin_root/agents/ansible-runner.md" || { echo "ansible-drill: FAIL — missing $reason" >&2; exit 1; }
done
grep -q -- "--offline" "$plugin_root/agents/ansible-runner.md" || { echo "ansible-drill: FAIL — missing --offline hardening" >&2; exit 1; }

offline_out="$scratch/ansible-offline.jsonl"
echo '{"__ansible_status__": "unavailable", "tools": [], "skipped": [{"tool": "ansible-lint", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__ansible_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "ansible"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

clean_skip='{"__ansible_status__": "unavailable", "tools": [], "skipped": [{"tool": "ansible-lint", "reason": "no-playbook"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "no-playbook")' >/dev/null \
    || { echo "ansible-drill: FAIL — no-playbook target-shape skip not parseable" >&2; exit 1; }

echo ""
echo "ansible-drill: OK"
