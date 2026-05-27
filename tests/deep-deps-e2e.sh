#!/usr/bin/env bash
# deep-deps-e2e.sh — v1.16.0 E2E for the deep-deps release-diff lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-deep-deps/.pipeline/deep-deps.jsonl"
[ -f "$jsonl" ] || { echo "deep-deps-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "deep-deps-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

dd=$(jq -rs 'map(select(.origin=="deep-deps" and .tool=="dep-diff")) | length' "$jsonl")
[ "$dd" -ge 1 ] || { echo "deep-deps-e2e: FAIL (a) dep-diff findings: $dd" >&2; exit 1; }
echo "  (a) dep-diff findings: $dd"

# Every deep-deps finding MUST carry a malicious|suspicious verdict (benign
# verdicts emit no finding line).
badv=$(jq -rs 'map(select(.origin=="deep-deps" and ((.verdict=="malicious" or .verdict=="suspicious")|not))) | length' "$jsonl")
[ "$badv" -eq 0 ] || { echo "deep-deps-e2e: FAIL (b) — $badv findings with bad/absent verdict" >&2; exit 1; }
echo "  (b) every finding has a malicious|suspicious verdict"

# At least one malicious verdict (the compromised-release case).
mal=$(jq -rs 'map(select(.origin=="deep-deps" and .verdict=="malicious")) | length' "$jsonl")
[ "$mal" -ge 1 ] || { echo "deep-deps-e2e: FAIL (c) malicious verdicts: $mal" >&2; exit 1; }
echo "  (c) malicious verdicts: $mal"

# Origin-tag isolation: no other lane's tool name on a deep-deps finding.
leak=$(jq -rs 'map(select(.origin=="deep-deps" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec" or .tool=="binskim" or .tool=="osslsigncode" or .tool=="sigcheck" or .tool=="kube-score" or .tool=="kubesec" or .tool=="tfsec" or .tool=="checkov" or .tool=="actionlint" or .tool=="zizmor" or .tool=="hadolint" or .tool=="virt-xml-validate" or .tool=="gosec" or .tool=="staticcheck" or .tool=="shellcheck" or .tool=="pip-audit" or .tool=="ruff" or .tool=="ansible-lint" or .tool=="sing-box" or .tool=="xray" or .tool=="trivy" or .tool=="grype" or .tool=="jq" or .tool=="mcp-scan" or .tool=="bearer" or .tool=="njsscan" or .tool=="brakeman" or .tool=="guarddog" or .tool=="osv-scanner"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "deep-deps-e2e: FAIL (d) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (d) origin-tag isolation: 0 leaks"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__deep_deps_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "deep-deps-e2e: FAIL (e) trailing status: $tail_status" >&2; exit 1; }
echo "  (e) trailing status: $tail_status"

# Reverse isolation: no deep-deps bleed into any other fixture's pipeline.
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos vulnerable-windows vulnerable-k8s vulnerable-iac vulnerable-gh-actions vulnerable-virt vulnerable-go vulnerable-ai-tools vulnerable-ansible vulnerable-supply-chain; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="deep-deps")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "deep-deps-e2e: FAIL — deep-deps bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (f) reverse isolation: clean"

echo ""
echo "deep-deps-e2e: OK"
