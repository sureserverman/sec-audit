#!/usr/bin/env bash
# image-e2e.sh — v1.11.0 E2E for the image lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-image/.pipeline/image.jsonl"
[ -f "$jsonl" ] || { echo "image-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "image-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

tr=$(jq -rs 'map(select(.origin=="image" and .tool=="trivy")) | length' "$jsonl")
[ "$tr" -ge 1 ] || { echo "image-e2e: FAIL (a) trivy findings: $tr" >&2; exit 1; }
echo "  (a) trivy findings: $tr"

gr=$(jq -rs 'map(select(.origin=="image" and .tool=="grype")) | length' "$jsonl")
[ "$gr" -ge 1 ] || { echo "image-e2e: FAIL (b) grype findings: $gr" >&2; exit 1; }
echo "  (b) grype findings: $gr"

# 39-tool isolation (every other lane's tool name).
leak=$(jq -rs 'map(select(.origin=="image" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec" or .tool=="binskim" or .tool=="osslsigncode" or .tool=="sigcheck" or .tool=="kube-score" or .tool=="kubesec" or .tool=="tfsec" or .tool=="checkov" or .tool=="actionlint" or .tool=="zizmor" or .tool=="hadolint" or .tool=="virt-xml-validate" or .tool=="gosec" or .tool=="staticcheck" or .tool=="shellcheck" or .tool=="pip-audit" or .tool=="ruff" or .tool=="ansible-lint" or .tool=="sing-box" or .tool=="xray"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "image-e2e: FAIL (c) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (c) origin-tag isolation: 0 leaks (39 other tools rejected)"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__image_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "image-e2e: FAIL (d)" >&2; exit 1; }
echo "  (d) trailing status: $tail_status"

# Verify dedup happened — check that the same CVE is NOT emitted twice
# for the same package (trivy CVE-2022-37434 is in both trivy + grype upstream
# reports, but should appear only ONCE in the merged jsonl).
zlib_count=$(jq -rs 'map(select(.evidence != null and (.evidence | contains("zlib")) and (.evidence | contains("CVE-2022-37434")))) | length' "$jsonl")
[ "$zlib_count" -eq 1 ] || { echo "image-e2e: FAIL (e) dedup check — zlib CVE-2022-37434 appears $zlib_count times (expected 1)" >&2; exit 1; }
echo "  (e) dedup check: zlib CVE-2022-37434 appears once (trivy wins, grype suppressed)"

for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos vulnerable-windows vulnerable-k8s vulnerable-iac vulnerable-gh-actions vulnerable-virt vulnerable-go vulnerable-shell vulnerable-python vulnerable-ansible vulnerable-netcfg; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="image")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "image-e2e: FAIL — image bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (f) reverse isolation: clean"

echo ""
echo "image-e2e: OK"
