#!/usr/bin/env bash
# python-drill.sh — v1.7.0 degrade drill for the Python lane.

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

echo "python-drill: testing PATH scrub..."
for tool in pip-audit ruff; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "python-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides pip-audit/ruff"

echo "python-drill: testing python-runner spec..."
grep -q '"__python_status__": "unavailable"' "$plugin_root/agents/python-runner.md" || { echo "python-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
for tool in pip-audit ruff; do
    grep -q "command -v $tool" "$plugin_root/agents/python-runner.md" || { echo "python-drill: FAIL — missing command -v $tool" >&2; exit 1; }
done
for reason in tool-missing no-requirements; do
    grep -q "$reason" "$plugin_root/agents/python-runner.md" || { echo "python-drill: FAIL — missing $reason" >&2; exit 1; }
done

offline_out="$scratch/python-offline.jsonl"
echo '{"__python_status__": "unavailable", "tools": [], "skipped": [{"tool": "pip-audit", "reason": "tool-missing"}, {"tool": "ruff", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__python_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "python"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

clean_skip='{"__python_status__": "unavailable", "tools": [], "skipped": [{"tool": "pip-audit", "reason": "no-requirements"}, {"tool": "ruff", "reason": "no-requirements"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "no-requirements")' >/dev/null \
    || { echo "python-drill: FAIL — no-requirements target-shape skip not parseable" >&2; exit 1; }

echo ""
echo "python-drill: OK"
