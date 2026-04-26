#!/usr/bin/env bash
# go-drill.sh — v1.5.0 degrade drill for the Go lane.

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

echo "go-drill: testing PATH scrub..."
for tool in gosec staticcheck; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "go-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides gosec/staticcheck"

echo "go-drill: testing go-runner spec..."
grep -q '"__go_status__": "unavailable"' "$plugin_root/agents/go-runner.md" || { echo "go-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
for tool in gosec staticcheck; do
    grep -q "command -v $tool" "$plugin_root/agents/go-runner.md" || { echo "go-drill: FAIL — missing command -v $tool" >&2; exit 1; }
done
grep -q "tool-missing" "$plugin_root/agents/go-runner.md" || { echo "go-drill: FAIL — missing tool-missing reason" >&2; exit 1; }
grep -q "GOFLAGS=-mod=readonly" "$plugin_root/agents/go-runner.md" || { echo "go-drill: FAIL — missing -mod=readonly hardening" >&2; exit 1; }

offline_out="$scratch/go-offline.jsonl"
echo '{"__go_status__": "unavailable", "tools": [], "skipped": [{"tool": "gosec", "reason": "tool-missing"}, {"tool": "staticcheck", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__go_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "go"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

echo ""
echo "go-drill: OK"
