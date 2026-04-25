#!/usr/bin/env bash
# iac-e2e.sh — v1.2.0 E2E for the IaC lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-iac/.pipeline/iac.jsonl"
[ -f "$jsonl" ] || { echo "iac-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "iac-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

tf=$(jq -rs 'map(select(.origin=="iac" and .tool=="tfsec")) | length' "$jsonl")
[ "$tf" -ge 1 ] || { echo "iac-e2e: FAIL (a)" >&2; exit 1; }
echo "  (a) tfsec findings: $tf"

ch=$(jq -rs 'map(select(.origin=="iac" and .tool=="checkov")) | length' "$jsonl")
[ "$ch" -ge 1 ] || { echo "iac-e2e: FAIL (b)" >&2; exit 1; }
echo "  (b) checkov findings: $ch"

# 26-tool isolation (all other lanes' tools)
leak=$(jq -rs 'map(select(.origin=="iac" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec" or .tool=="binskim" or .tool=="osslsigncode" or .tool=="sigcheck" or .tool=="kube-score" or .tool=="kubesec"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "iac-e2e: FAIL (c) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (c) origin-tag isolation: 0 leaks (26 other tools rejected)"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__iac_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "iac-e2e: FAIL (d)" >&2; exit 1; }
echo "  (d) trailing status: $tail_status"

for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos vulnerable-windows vulnerable-k8s; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="iac")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "iac-e2e: FAIL — iac bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (e) reverse isolation: clean"

echo ""
echo "iac-e2e: OK"
