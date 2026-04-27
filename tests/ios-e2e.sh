#!/usr/bin/env bash
# ios-e2e.sh — end-to-end contract test for the sec-audit iOS lane.
# Validates tests/fixtures/vulnerable-ios/.pipeline/ios.jsonl against:
#
#   (a) >=1 finding with origin=ios and tool=mobsfscan
#   (b) Trailing __ios_status__ ok|partial with a structured skipped
#       list documenting either requires-macos-host, no-bundle, or
#       no-notary-profile
#   (c) 8-lane origin-tag isolation: NO ios finding carries any tool
#       name from SAST/DAST/webext/rust/android lanes
#       (note: mobsfscan is allowed for both android and ios — dispatch
#       context disambiguates; the assertion is on the OTHER lanes)
#   (d) Reverse isolation: no ios bleed into any other fixture
#
# Exit 0 on success with the literal line `ios-e2e: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-ios/.pipeline/ios.jsonl"

[ -f "$jsonl" ] || { echo "ios-e2e: FAIL — fixture missing: $jsonl" >&2; exit 1; }

# ---- JSONL validity
echo "ios-e2e: validating JSONL..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "ios-e2e: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$jsonl"
echo "  every line parses as JSON"

# ---- (a) mobsfscan findings
mob=$(jq -rs 'map(select(.origin=="ios" and .tool=="mobsfscan")) | length' "$jsonl")
if [ "$mob" -lt 1 ]; then
    echo "ios-e2e: FAIL (a) — expected >=1 mobsfscan finding, got $mob" >&2
    exit 1
fi
echo "  (a) mobsfscan findings: $mob"

# ---- (b) Trailing status line + structured skipped entries
tail_obj=$(tail -n 1 "$jsonl")
tail_status=$(echo "$tail_obj" | jq -r '.__ios_status__ // empty')
if [ "$tail_status" != "ok" ] && [ "$tail_status" != "partial" ]; then
    echo "ios-e2e: FAIL (b) — expected trailing __ios_status__ ok|partial, got '$tail_status'" >&2
    exit 1
fi
# At least one skipped entry with a canonical iOS-lane reason
valid_reasons=$(echo "$tail_obj" | jq -r '.skipped // [] | map(select(.reason=="requires-macos-host" or .reason=="no-bundle" or .reason=="no-notary-profile" or .reason=="tool-missing")) | length')
if [ "$valid_reasons" -lt 1 ]; then
    echo "ios-e2e: FAIL (b) — expected >=1 skipped entry with a canonical iOS-lane reason, got $valid_reasons" >&2
    exit 1
fi
echo "  (b) trailing status: __ios_status__=$tail_status + $valid_reasons skipped entr(ies) with canonical reason(s)"

# ---- (c) 8-lane origin-tag isolation
leak=$(jq -rs 'map(select(.origin=="ios" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="apkleaks" or .tool=="android-lint"))) | length' "$jsonl")
if [ "$leak" -ne 0 ]; then
    echo "ios-e2e: FAIL (c) — $leak ios findings carry a non-ios tool tag" >&2
    exit 1
fi
echo "  (c) origin-tag isolation: 0 cross-tagged findings"

# ---- (d) Reverse isolation
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android; do
    other_dir="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$other_dir" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="ios")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "ios-e2e: FAIL — $jf contains $bleed origin=ios findings (should be 0)" >&2; exit 1; }
    done < <(find "$other_dir" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (d) reverse isolation: no ios bleed into other fixtures"

echo ""
echo "ios-e2e: OK"
