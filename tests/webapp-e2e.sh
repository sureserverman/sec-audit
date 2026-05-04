#!/usr/bin/env bash
# webapp-e2e.sh — v1.14.0 E2E for the Webapp lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-webapp/.pipeline/webapp.jsonl"
[ -f "$jsonl" ] || { echo "webapp-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "webapp-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

be=$(jq -rs 'map(select(.origin=="webapp" and .tool=="bearer")) | length' "$jsonl")
[ "$be" -ge 1 ] || { echo "webapp-e2e: FAIL (a) bearer findings: $be" >&2; exit 1; }
echo "  (a) bearer findings: $be"

# 38-tool isolation (every other lane's tool name).
leak=$(jq -rs 'map(select(.origin=="webapp" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec" or .tool=="binskim" or .tool=="osslsigncode" or .tool=="sigcheck" or .tool=="kube-score" or .tool=="kubesec" or .tool=="tfsec" or .tool=="checkov" or .tool=="actionlint" or .tool=="zizmor" or .tool=="hadolint" or .tool=="virt-xml-validate" or .tool=="gosec" or .tool=="staticcheck" or .tool=="shellcheck" or .tool=="pip-audit" or .tool=="ruff" or .tool=="ansible-lint" or .tool=="sing-box" or .tool=="xray" or .tool=="trivy" or .tool=="grype" or .tool=="jq" or .tool=="mcp-scan"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "webapp-e2e: FAIL (b) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (b) origin-tag isolation: 0 leaks"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__webapp_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "webapp-e2e: FAIL (c)" >&2; exit 1; }
echo "  (c) trailing status: $tail_status"

# Reverse isolation — no other fixture's lane bleeds into webapp findings.
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos vulnerable-windows vulnerable-k8s vulnerable-iac vulnerable-gh-actions vulnerable-virt vulnerable-go vulnerable-shell vulnerable-python vulnerable-ansible vulnerable-netcfg vulnerable-image vulnerable-ai-tools; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="webapp")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "webapp-e2e: FAIL — webapp bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (d) reverse isolation: clean"

echo ""
echo "webapp-e2e: OK"
