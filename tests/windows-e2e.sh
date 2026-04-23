#!/usr/bin/env bash
# windows-e2e.sh — end-to-end contract test for the sec-review
# Windows desktop lane. Validates tests/fixtures/vulnerable-windows/
# .pipeline/windows.jsonl against:
#
#   (a) >=1 finding with origin=windows and tool=binskim
#   (b) >=1 finding with origin=windows and tool=osslsigncode
#   (c) 16-lane origin-tag isolation: NO windows finding carries any
#       tool name from the 12 other lanes
#   (d) Trailing __windows_status__ ok|partial with a structured
#       skipped list carrying a canonical Windows-lane reason
#   (e) Reverse isolation across 10 other fixtures

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-windows/.pipeline/windows.jsonl"

[ -f "$jsonl" ] || { echo "windows-e2e: FAIL — fixture missing: $jsonl" >&2; exit 1; }

echo "windows-e2e: validating JSONL..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "windows-e2e: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$jsonl"
echo "  every line parses as JSON"

bs=$(jq -rs 'map(select(.origin=="windows" and .tool=="binskim")) | length' "$jsonl")
[ "$bs" -ge 1 ] || { echo "windows-e2e: FAIL (a) — expected >=1 binskim, got $bs" >&2; exit 1; }
echo "  (a) binskim findings: $bs"

os=$(jq -rs 'map(select(.origin=="windows" and .tool=="osslsigncode")) | length' "$jsonl")
[ "$os" -ge 1 ] || { echo "windows-e2e: FAIL (b) — expected >=1 osslsigncode, got $os" >&2; exit 1; }
echo "  (b) osslsigncode findings: $os"

# 16-lane origin-tag isolation — reject 21 other tool names
leak=$(jq -rs 'map(select(.origin=="windows" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "windows-e2e: FAIL (c) — $leak windows findings carry a non-windows tool tag" >&2; exit 1; }
echo "  (c) origin-tag isolation: 0 cross-tagged findings (21 other tools rejected)"

tail_obj=$(tail -n 1 "$jsonl")
tail_status=$(echo "$tail_obj" | jq -r '.__windows_status__ // empty')
if [ "$tail_status" != "ok" ] && [ "$tail_status" != "partial" ]; then
    echo "windows-e2e: FAIL (d) — expected __windows_status__ ok|partial, got '$tail_status'" >&2
    exit 1
fi
valid=$(echo "$tail_obj" | jq -r '.skipped // [] | map(select(.reason=="requires-windows-host" or .reason=="no-pe" or .reason=="tool-missing")) | length')
[ "$valid" -ge 1 ] || { echo "windows-e2e: FAIL (d) — expected >=1 canonical skipped entry, got $valid" >&2; exit 1; }
echo "  (d) trailing status: __windows_status__=$tail_status + $valid canonical skipped entr(ies)"

for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos; do
    other_dir="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$other_dir" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="windows")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "windows-e2e: FAIL — $jf contains $bleed origin=windows findings" >&2; exit 1; }
    done < <(find "$other_dir" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (e) reverse isolation: no windows bleed into other fixtures"

echo ""
echo "windows-e2e: OK"
