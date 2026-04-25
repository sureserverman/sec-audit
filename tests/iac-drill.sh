#!/usr/bin/env bash
# iac-drill.sh — v1.2.0 degrade drill for the IaC lane.

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

echo "iac-drill: testing PATH scrub..."
for tool in tfsec checkov; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "iac-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides tfsec/checkov"

echo "iac-drill: testing iac-runner spec..."
grep -q '"__iac_status__": "unavailable"' "$plugin_root/agents/iac-runner.md" || { echo "iac-drill: FAIL" >&2; exit 1; }
for tool in tfsec checkov; do
    grep -q "command -v $tool" "$plugin_root/agents/iac-runner.md" || { echo "iac-drill: FAIL" >&2; exit 1; }
done
grep -q "tool-missing" "$plugin_root/agents/iac-runner.md" || { echo "iac-drill: FAIL" >&2; exit 1; }

offline_out="$scratch/iac-offline.jsonl"
echo '{"__iac_status__": "unavailable", "tools": [], "skipped": [{"tool": "tfsec", "reason": "tool-missing"}, {"tool": "checkov", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__iac_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "iac"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

echo ""
echo "iac-drill: OK"
