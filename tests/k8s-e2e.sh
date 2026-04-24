#!/usr/bin/env bash
# k8s-e2e.sh — v1.1.0 E2E contract test for the K8s lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-k8s/.pipeline/k8s.jsonl"

[ -f "$jsonl" ] || { echo "k8s-e2e: FAIL — fixture missing" >&2; exit 1; }

echo "k8s-e2e: validating JSONL..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "k8s-e2e: FAIL — invalid JSON" >&2; exit 1; }
done < "$jsonl"

ks=$(jq -rs 'map(select(.origin=="k8s" and .tool=="kube-score")) | length' "$jsonl")
[ "$ks" -ge 1 ] || { echo "k8s-e2e: FAIL (a) — no kube-score findings" >&2; exit 1; }
echo "  (a) kube-score findings: $ks"

se=$(jq -rs 'map(select(.origin=="k8s" and .tool=="kubesec")) | length' "$jsonl")
[ "$se" -ge 1 ] || { echo "k8s-e2e: FAIL (b) — no kubesec findings" >&2; exit 1; }
echo "  (b) kubesec findings: $se"

leak=$(jq -rs 'map(select(.origin=="k8s" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec" or .tool=="binskim" or .tool=="osslsigncode" or .tool=="sigcheck"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "k8s-e2e: FAIL (c) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (c) origin-tag isolation: 0 cross-lane leaks (24 other tools rejected)"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__k8s_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "k8s-e2e: FAIL (d) — bad trailing status" >&2; exit 1; }
echo "  (d) trailing status: __k8s_status__=$tail_status"

for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos vulnerable-windows; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="k8s")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "k8s-e2e: FAIL — $jf has k8s bleed" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (e) reverse isolation: clean"

echo ""
echo "k8s-e2e: OK"
