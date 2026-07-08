#!/usr/bin/env bash
# secrets-e2e.sh — v1.21.0 E2E for the secrets lane.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-secrets/.pipeline/secrets.jsonl"
[ -f "$jsonl" ] || { echo "secrets-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "secrets-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

gl=$(jq -rs 'map(select(.origin=="secrets" and .tool=="gitleaks")) | length' "$jsonl")
[ "$gl" -ge 1 ] || { echo "secrets-e2e: FAIL (a) gitleaks findings: $gl" >&2; exit 1; }
echo "  (a) gitleaks findings: $gl"

th=$(jq -rs 'map(select(.origin=="secrets" and .tool=="trufflehog")) | length' "$jsonl")
[ "$th" -ge 1 ] || { echo "secrets-e2e: FAIL (b) trufflehog findings: $th" >&2; exit 1; }
echo "  (b) trufflehog findings: $th"

# Every secrets finding must be CWE-798 (hard-coded credentials).
non798=$(jq -rs 'map(select(.origin=="secrets" and .cwe!="CWE-798")) | length' "$jsonl")
[ "$non798" -eq 0 ] || { echo "secrets-e2e: FAIL (c) — $non798 findings not CWE-798" >&2; exit 1; }
echo "  (c) every secrets finding is CWE-798: OK"

# Redaction invariant: the plaintext canary in the raw trufflehog fixture's Raw
# field must NEVER appear in the mapped golden.
canary=$(grep -c 'CANARY_RAW_SECRET' "$jsonl" || true)
[ "$canary" -eq 0 ] || { echo "secrets-e2e: FAIL (d) — raw-secret canary leaked into golden ($canary)" >&2; exit 1; }
echo "  (d) redaction invariant: 0 raw-secret canary leaks"

# Origin-tag isolation: no other lane's tool name on a secrets finding.
leak=$(jq -rs 'map(select(.origin=="secrets" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire" or .tool=="cargo-audit" or .tool=="cargo-deny" or .tool=="cargo-geiger" or .tool=="cargo-vet" or .tool=="mobsfscan" or .tool=="apkleaks" or .tool=="android-lint" or .tool=="codesign" or .tool=="spctl" or .tool=="notarytool" or .tool=="pkgutil" or .tool=="stapler" or .tool=="systemd-analyze" or .tool=="lintian" or .tool=="checksec" or .tool=="binskim" or .tool=="osslsigncode" or .tool=="sigcheck" or .tool=="kube-score" or .tool=="kubesec" or .tool=="tfsec" or .tool=="checkov" or .tool=="actionlint" or .tool=="zizmor" or .tool=="hadolint" or .tool=="virt-xml-validate" or .tool=="gosec" or .tool=="staticcheck" or .tool=="shellcheck" or .tool=="pip-audit" or .tool=="ruff" or .tool=="ansible-lint" or .tool=="sing-box" or .tool=="xray" or .tool=="trivy" or .tool=="grype" or .tool=="jq" or .tool=="mcp-scan" or .tool=="bearer" or .tool=="njsscan" or .tool=="brakeman" or .tool=="dep-diff" or .tool=="guarddog" or .tool=="osv-scanner"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "secrets-e2e: FAIL (e) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (e) origin-tag isolation: 0 leaks"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__secrets_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "secrets-e2e: FAIL (f) trailing status: $tail_status" >&2; exit 1; }
echo "  (f) trailing status: $tail_status"

# Reverse isolation: no secrets bleed into any other fixture's pipeline.
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext vulnerable-rust vulnerable-android vulnerable-ios vulnerable-linux vulnerable-macos vulnerable-windows vulnerable-k8s vulnerable-iac vulnerable-gh-actions vulnerable-virt vulnerable-go vulnerable-ai-tools vulnerable-ansible vulnerable-supply-chain vulnerable-deep-deps; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="secrets")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "secrets-e2e: FAIL — secrets bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (g) reverse isolation: clean"

echo ""
echo "secrets-e2e: OK"
