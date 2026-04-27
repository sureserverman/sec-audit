#!/usr/bin/env bash
# linux-e2e.sh — end-to-end contract test for the sec-audit Linux
# desktop lane. Validates tests/fixtures/vulnerable-linux/.pipeline/
# linux.jsonl against:
#
#   (a) >=1 finding with origin=linux and tool=systemd-analyze
#   (b) >=1 finding with origin=linux and tool=lintian
#   (c) 12-lane origin-tag isolation: NO linux finding carries any
#       tool name from the eleven other lanes
#   (d) Trailing __linux_status__ ok|partial with a structured
#       skipped entry carrying a canonical Linux-lane reason
#   (e) Reverse isolation: no linux bleed into any other fixture
#
# Exit 0 on success with the literal line `linux-e2e: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-linux/.pipeline/linux.jsonl"

[ -f "$jsonl" ] || { echo "linux-e2e: FAIL — fixture missing: $jsonl" >&2; exit 1; }

# ---- JSONL validity
echo "linux-e2e: validating JSONL..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "linux-e2e: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$jsonl"
echo "  every line parses as JSON"

# ---- (a) systemd-analyze findings
sa=$(jq -rs 'map(select(.origin=="linux" and .tool=="systemd-analyze")) | length' "$jsonl")
[ "$sa" -ge 1 ] || { echo "linux-e2e: FAIL (a) — expected >=1 systemd-analyze finding, got $sa" >&2; exit 1; }
echo "  (a) systemd-analyze findings: $sa"

# ---- (b) lintian findings
li=$(jq -rs 'map(select(.origin=="linux" and .tool=="lintian")) | length' "$jsonl")
[ "$li" -ge 1 ] || { echo "linux-e2e: FAIL (b) — expected >=1 lintian finding, got $li" >&2; exit 1; }
echo "  (b) lintian findings: $li"

# ---- (c) 12-lane origin-tag isolation
leak=$(jq -rs 'map(select(.origin=="linux" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "linux-e2e: FAIL (c) — $leak linux findings carry a non-linux tool tag" >&2; exit 1; }
echo "  (c) origin-tag isolation: 0 cross-tagged findings (11 other lanes' tools rejected)"

# ---- (d) trailing status line + skipped schema
tail_obj=$(tail -n 1 "$jsonl")
tail_status=$(echo "$tail_obj" | jq -r '.__linux_status__ // empty')
if [ "$tail_status" != "ok" ] && [ "$tail_status" != "partial" ]; then
    echo "linux-e2e: FAIL (d) — expected trailing __linux_status__ ok|partial, got '$tail_status'" >&2
    exit 1
fi
valid_reasons=$(echo "$tail_obj" | jq -r '.skipped // [] | map(select(.reason=="requires-systemd-host" or .reason=="no-debian-source" or .reason=="no-elf" or .reason=="no-systemd-unit" or .reason=="tool-missing")) | length')
if [ "$valid_reasons" -lt 1 ]; then
    echo "linux-e2e: FAIL (d) — expected >=1 skipped entry with a canonical Linux-lane reason, got $valid_reasons" >&2
    exit 1
fi
echo "  (d) trailing status: __linux_status__=$tail_status + $valid_reasons canonical skipped entr(ies)"

# ---- (e) reverse isolation
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios; do
    other_dir="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$other_dir" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="linux")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "linux-e2e: FAIL — $jf contains $bleed origin=linux findings (should be 0)" >&2; exit 1; }
    done < <(find "$other_dir" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (e) reverse isolation: no linux bleed into other fixtures"

echo ""
echo "linux-e2e: OK"
