#!/usr/bin/env bash
# macos-e2e.sh — end-to-end contract test for the sec-review macOS
# desktop lane. Validates tests/fixtures/vulnerable-macos/.pipeline/
# macos.jsonl against:
#
#   (a) >=1 finding with origin=macos and tool=mobsfscan
#   (b) Trailing __macos_status__ ok|partial with a structured skipped
#       list carrying a canonical macOS-lane reason
#   (c) 15-lane origin-tag isolation: NO macos finding carries any
#       exclusive tool name from the 15 other lanes (mobsfscan/
#       codesign/spctl are shared with other Apple lanes and are
#       therefore allowed here)
#   (d) Reverse isolation across 9 other fixtures
#
# Exit 0 on success with the literal line `macos-e2e: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-macos/.pipeline/macos.jsonl"

[ -f "$jsonl" ] || { echo "macos-e2e: FAIL — fixture missing: $jsonl" >&2; exit 1; }

echo "macos-e2e: validating JSONL..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "macos-e2e: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$jsonl"
echo "  every line parses as JSON"

mob=$(jq -rs 'map(select(.origin=="macos" and .tool=="mobsfscan")) | length' "$jsonl")
[ "$mob" -ge 1 ] || { echo "macos-e2e: FAIL (a) — expected >=1 mobsfscan finding, got $mob" >&2; exit 1; }
echo "  (a) mobsfscan findings: $mob"

tail_obj=$(tail -n 1 "$jsonl")
tail_status=$(echo "$tail_obj" | jq -r '.__macos_status__ // empty')
if [ "$tail_status" != "ok" ] && [ "$tail_status" != "partial" ]; then
    echo "macos-e2e: FAIL (b) — expected trailing __macos_status__ ok|partial, got '$tail_status'" >&2
    exit 1
fi
valid_reasons=$(echo "$tail_obj" | jq -r '.skipped // [] | map(select(.reason=="requires-macos-host" or .reason=="no-bundle" or .reason=="no-pkg" or .reason=="no-notary-profile" or .reason=="tool-missing")) | length')
[ "$valid_reasons" -ge 1 ] || { echo "macos-e2e: FAIL (b) — expected >=1 canonical skipped entry, got $valid_reasons" >&2; exit 1; }
echo "  (b) trailing status: __macos_status__=$tail_status + $valid_reasons canonical skipped entr(ies)"

# 15-lane origin-tag isolation: macos findings must NOT carry the
# 16 exclusive non-macOS tool names. Shared tools (mobsfscan, codesign,
# spctl are allowed — dispatch context disambiguates).
leak=$(jq -rs 'map(select(.origin=="macos" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="notarytool" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "macos-e2e: FAIL (c) — $leak macos findings carry a non-macos tool tag" >&2; exit 1; }
echo "  (c) origin-tag isolation: 0 cross-tagged findings (16 exclusive tools rejected)"

# Reverse isolation
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux; do
    other_dir="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$other_dir" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="macos")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "macos-e2e: FAIL — $jf contains $bleed origin=macos findings" >&2; exit 1; }
    done < <(find "$other_dir" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (d) reverse isolation: no macos bleed into other fixtures"

echo ""
echo "macos-e2e: OK"
