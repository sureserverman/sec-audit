#!/usr/bin/env bash
# virt-drill.sh — v1.4.0 degrade drill for the virt lane.

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

echo "virt-drill: testing PATH scrub..."
for tool in hadolint virt-xml-validate; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "virt-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides hadolint/virt-xml-validate"

echo "virt-drill: testing virt-runner spec..."
grep -q '"__virt_status__": "unavailable"' "$plugin_root/agents/virt-runner.md" || { echo "virt-drill: FAIL" >&2; exit 1; }
for tool in hadolint virt-xml-validate; do
    grep -q "command -v $tool" "$plugin_root/agents/virt-runner.md" || { echo "virt-drill: FAIL — missing command -v $tool" >&2; exit 1; }
done
for reason in tool-missing no-containerfile no-libvirt-xml; do
    grep -q "$reason" "$plugin_root/agents/virt-runner.md" || { echo "virt-drill: FAIL — missing $reason" >&2; exit 1; }
done

offline_out="$scratch/virt-offline.jsonl"
echo '{"__virt_status__": "unavailable", "tools": [], "skipped": [{"tool": "hadolint", "reason": "tool-missing"}, {"tool": "virt-xml-validate", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__virt_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "virt"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

# Target-shape clean-skip: tools present, no Containerfile / no libvirt XML.
clean_skip='{"__virt_status__": "unavailable", "tools": [], "skipped": [{"tool": "hadolint", "reason": "no-containerfile"}, {"tool": "virt-xml-validate", "reason": "no-libvirt-xml"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "no-containerfile" or .reason == "no-libvirt-xml")' >/dev/null \
    || { echo "virt-drill: FAIL — target-shape skip-reason vocabulary not parseable" >&2; exit 1; }

echo ""
echo "virt-drill: OK"
