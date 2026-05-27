#!/usr/bin/env bash
# supply-chain-e2e.sh — v1.15.0 E2E for the supply-chain lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-supply-chain/.pipeline/supply-chain.jsonl"
[ -f "$jsonl" ] || { echo "supply-chain-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "supply-chain-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

gd=$(jq -rs 'map(select(.origin=="supply-chain" and .tool=="guarddog")) | length' "$jsonl")
[ "$gd" -ge 1 ] || { echo "supply-chain-e2e: FAIL (a) guarddog findings: $gd" >&2; exit 1; }
echo "  (a) guarddog findings: $gd"

osv=$(jq -rs 'map(select(.origin=="supply-chain" and .tool=="osv-scanner")) | length' "$jsonl")
[ "$osv" -ge 1 ] || { echo "supply-chain-e2e: FAIL (b) osv-scanner findings: $osv" >&2; exit 1; }
echo "  (b) osv-scanner findings: $osv"

# Every osv-scanner finding in this lane MUST be a MAL- advisory (CVEs are
# cve-enricher's job and must not be double-reported here).
non_mal=$(jq -rs 'map(select(.origin=="supply-chain" and .tool=="osv-scanner" and (.id|startswith("MAL-")|not))) | length' "$jsonl")
[ "$non_mal" -eq 0 ] || { echo "supply-chain-e2e: FAIL (c) — $non_mal non-MAL osv-scanner rows leaked" >&2; exit 1; }
echo "  (c) osv-scanner emits MAL- advisories only: 0 CVE leaks"

# Origin-tag isolation: no other lane's tool name on a supply-chain finding.
leak=$(jq -rs 'map(select(.origin=="supply-chain" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec" or .tool=="binskim" or .tool=="osslsigncode" or .tool=="sigcheck" or .tool=="kube-score" or .tool=="kubesec" or .tool=="tfsec" or .tool=="checkov" or .tool=="actionlint" or .tool=="zizmor" or .tool=="hadolint" or .tool=="virt-xml-validate" or .tool=="gosec" or .tool=="staticcheck" or .tool=="shellcheck" or .tool=="pip-audit" or .tool=="ruff" or .tool=="ansible-lint" or .tool=="sing-box" or .tool=="xray" or .tool=="trivy" or .tool=="grype" or .tool=="jq" or .tool=="mcp-scan" or .tool=="bearer" or .tool=="njsscan" or .tool=="brakeman" or .tool=="dep-diff"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "supply-chain-e2e: FAIL (d) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (d) origin-tag isolation: 0 leaks"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__supply_chain_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "supply-chain-e2e: FAIL (e) trailing status: $tail_status" >&2; exit 1; }
echo "  (e) trailing status: $tail_status"

# Reverse isolation: no supply-chain bleed into any other fixture's pipeline.
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos vulnerable-windows vulnerable-k8s vulnerable-iac vulnerable-gh-actions vulnerable-virt vulnerable-go vulnerable-ai-tools vulnerable-ansible; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="supply-chain")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "supply-chain-e2e: FAIL — supply-chain bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (f) reverse isolation: clean"

echo ""
echo "supply-chain-e2e: OK"
