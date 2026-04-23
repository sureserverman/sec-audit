#!/usr/bin/env bash
# android-e2e.sh — end-to-end contract test for the sec-review Android
# lane. Validates the fixture pipeline output at
# tests/fixtures/vulnerable-android/.pipeline/android.jsonl against the
# Stage 2 Task 2.3 assertions:
#
#   (a) >=1 finding with origin=android and tool=mobsfscan
#   (b) >=1 finding with origin=android and tool=android-lint
#   (c) 7-lane origin-tag isolation: NO android finding carries a
#       SAST/DAST/webext/rust tool name
#   (d) Trailing status line has __android_status__=ok|partial AND a
#       `skipped` list containing apkleaks with reason "no-apk"
#       (exercises the clean-skip-vs-failure distinction unique to
#       this lane)
#
# Exit 0 on success with the literal line `android-e2e: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-android/.pipeline/android.jsonl"

[ -f "$jsonl" ] || { echo "android-e2e: FAIL — fixture missing: $jsonl" >&2; exit 1; }

# ---- JSONL validity
echo "android-e2e: validating JSONL..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "android-e2e: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$jsonl"
echo "  every line parses as JSON"

# ---- (a) mobsfscan findings
mob=$(jq -rs 'map(select(.origin=="android" and .tool=="mobsfscan")) | length' "$jsonl")
if [ "$mob" -lt 1 ]; then
    echo "android-e2e: FAIL (a) — expected >=1 mobsfscan finding, got $mob" >&2
    exit 1
fi
echo "  (a) mobsfscan findings: $mob"

# ---- (b) android-lint findings
lint=$(jq -rs 'map(select(.origin=="android" and .tool=="android-lint")) | length' "$jsonl")
if [ "$lint" -lt 1 ]; then
    echo "android-e2e: FAIL (b) — expected >=1 android-lint finding, got $lint" >&2
    exit 1
fi
echo "  (b) android-lint findings: $lint"

# ---- (c) 7-lane origin-tag isolation
leak=$(jq -rs 'map(select(.origin=="android" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet"))) | length' "$jsonl")
if [ "$leak" -ne 0 ]; then
    echo "android-e2e: FAIL (c) — $leak android findings carry a non-android tool tag" >&2
    exit 1
fi
echo "  (c) origin-tag isolation: 0 cross-tagged findings"

# ---- (d) Trailing status line with skipped=apkleaks-no-apk
tail_obj=$(tail -n 1 "$jsonl")
tail_status=$(echo "$tail_obj" | jq -r '.__android_status__ // empty')
if [ "$tail_status" != "ok" ] && [ "$tail_status" != "partial" ]; then
    echo "android-e2e: FAIL (d) — expected trailing __android_status__ ok|partial, got '$tail_status'" >&2
    exit 1
fi
apkleaks_skip=$(echo "$tail_obj" | jq -r '.skipped // [] | map(select(.tool=="apkleaks" and .reason=="no-apk")) | length')
if [ "$apkleaks_skip" -ne 1 ]; then
    echo "android-e2e: FAIL (d) — expected apkleaks cleanly-skipped with reason=no-apk, got $apkleaks_skip entries" >&2
    exit 1
fi
echo "  (d) trailing status: __android_status__=$tail_status + apkleaks cleanly-skipped (no-apk)"

# ---- Reverse isolation across all 6 other fixtures
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust; do
    other_dir="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$other_dir" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="android")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "android-e2e: FAIL — $jf contains $bleed origin=android findings (should be 0)" >&2; exit 1; }
    done < <(find "$other_dir" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  reverse isolation: no android bleed into other fixtures"

echo ""
echo "android-e2e: OK"
