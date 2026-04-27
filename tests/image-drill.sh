#!/usr/bin/env bash
# image-drill.sh — v1.11.0 degrade drill for the image lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"

scratch=$(mktemp -d)
stub_bin="$scratch/bin"
mkdir -p "$stub_bin"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT

for cmd in bash sh env cat grep sed awk jq head tail tr cut sort uniq wc \
           mktemp mkdir rm ls dirname basename python3 find test true false uname tar; do
    resolved=$(command -v "$cmd" 2>/dev/null || true)
    [ -n "$resolved" ] && [ ! -e "$stub_bin/$cmd" ] && ln -s "$resolved" "$stub_bin/$cmd"
done
scrubbed_path="$stub_bin"

echo "image-drill: testing PATH scrub..."
for tool in trivy grype; do
    found=$(PATH="$scrubbed_path" command -v "$tool" 2>/dev/null || true)
    [ -z "$found" ] || { echo "image-drill: FAIL — $tool leaked" >&2; exit 1; }
done
echo "  scrubbed PATH hides trivy/grype"

echo "image-drill: testing image-runner spec..."
grep -q '"__image_status__": "unavailable"' "$plugin_root/agents/image-runner.md" || { echo "image-drill: FAIL — missing unavailable sentinel" >&2; exit 1; }
for tool in trivy grype; do
    grep -q "command -v $tool" "$plugin_root/agents/image-runner.md" || { echo "image-drill: FAIL — missing command -v $tool" >&2; exit 1; }
done
for reason in tool-missing no-image-artifact; do
    grep -q "$reason" "$plugin_root/agents/image-runner.md" || { echo "image-drill: FAIL — missing $reason" >&2; exit 1; }
done
# Critical: must use --input (NOT positional registry refs), --skip-update for offline,
# --scanners vuln (NOT misconfig/secret/license which duplicate other lanes).
grep -q -- "--input" "$plugin_root/agents/image-runner.md" || { echo "image-drill: FAIL — missing --input flag (must NOT pull from registry)" >&2; exit 1; }
grep -q -- "--skip-update" "$plugin_root/agents/image-runner.md" || { echo "image-drill: FAIL — missing --skip-update flag (DB must be operator-managed)" >&2; exit 1; }
grep -q -- "--scanners vuln" "$plugin_root/agents/image-runner.md" || { echo "image-drill: FAIL — missing --scanners vuln (must NOT enable misconfig/secret/license)" >&2; exit 1; }
# Must mention deduplication
grep -qi "dedup" "$plugin_root/agents/image-runner.md" || { echo "image-drill: FAIL — missing dedup logic" >&2; exit 1; }

offline_out="$scratch/image-offline.jsonl"
echo '{"__image_status__": "unavailable", "tools": [], "skipped": [{"tool": "trivy", "reason": "tool-missing"}, {"tool": "grype", "reason": "tool-missing"}]}' > "$offline_out"

[ "$(wc -l < "$offline_out" | tr -d ' ')" = "1" ] || exit 1
[ "$(grep -c '"__image_status__": "unavailable"' "$offline_out")" = "1" ] || exit 1
[ "$(grep -c '"origin": "image"' "$offline_out")" = "0" ] || exit 1
jq -e '.skipped | all(. | has("tool") and has("reason"))' "$offline_out" >/dev/null || exit 1

clean_skip='{"__image_status__": "unavailable", "tools": [], "skipped": [{"tool": "trivy", "reason": "no-image-artifact"}, {"tool": "grype", "reason": "no-image-artifact"}]}'
echo "$clean_skip" | jq -e '.skipped[] | select(.reason == "no-image-artifact")' >/dev/null \
    || { echo "image-drill: FAIL — no-image-artifact target-shape skip not parseable" >&2; exit 1; }

echo ""
echo "image-drill: OK"
