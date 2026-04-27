#!/usr/bin/env bash
# python-e2e.sh — v1.7.0 E2E for the Python lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-python/.pipeline/python.jsonl"
[ -f "$jsonl" ] || { echo "python-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "python-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

ru=$(jq -rs 'map(select(.origin=="python" and .tool=="ruff")) | length' "$jsonl")
[ "$ru" -ge 1 ] || { echo "python-e2e: FAIL (a) ruff findings: $ru" >&2; exit 1; }
echo "  (a) ruff findings: $ru"

pa=$(jq -rs 'map(select(.origin=="python" and .tool=="pip-audit")) | length' "$jsonl")
[ "$pa" -ge 1 ] || { echo "python-e2e: FAIL (b) pip-audit findings: $pa" >&2; exit 1; }
echo "  (b) pip-audit findings: $pa"

# 35-tool isolation (every other lane's tool name).
leak=$(jq -rs 'map(select(.origin=="python" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec" or .tool=="binskim" or .tool=="osslsigncode" or .tool=="sigcheck" or .tool=="kube-score" or .tool=="kubesec" or .tool=="tfsec" or .tool=="checkov" or .tool=="actionlint" or .tool=="zizmor" or .tool=="hadolint" or .tool=="virt-xml-validate" or .tool=="gosec" or .tool=="staticcheck" or .tool=="shellcheck"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "python-e2e: FAIL (c) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (c) origin-tag isolation: 0 leaks (35 other tools rejected)"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__python_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "python-e2e: FAIL (d)" >&2; exit 1; }
echo "  (d) trailing status: $tail_status"

for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos vulnerable-windows vulnerable-k8s vulnerable-iac vulnerable-gh-actions vulnerable-virt vulnerable-go vulnerable-shell; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="python")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "python-e2e: FAIL — python bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (e) reverse isolation: clean"

echo ""
echo "python-e2e: OK"
