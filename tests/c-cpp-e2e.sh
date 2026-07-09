#!/usr/bin/env bash
# c-cpp-e2e.sh — v1.26.0 E2E for the c-cpp lane (recorded golden fixture).

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-c/.pipeline/c-cpp.jsonl"
[ -f "$jsonl" ] || { echo "c-cpp-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "c-cpp-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

cc=$(jq -rs 'map(select(.origin=="c-cpp" and .tool=="cppcheck")) | length' "$jsonl")
[ "$cc" -ge 1 ] || { echo "c-cpp-e2e: FAIL (a) cppcheck findings: $cc" >&2; exit 1; }
echo "  (a) cppcheck findings: $cc"

ff=$(jq -rs 'map(select(.origin=="c-cpp" and .tool=="flawfinder")) | length' "$jsonl")
[ "$ff" -ge 1 ] || { echo "c-cpp-e2e: FAIL (b) flawfinder findings: $ff" >&2; exit 1; }
echo "  (b) flawfinder findings: $ff"

# Canonical C hazards must be present: OS-command injection (CWE-78 via system())
# and the gets()/buffer-overflow surface.
sysinj=$(jq -rs 'map(select(.origin=="c-cpp" and .cwe=="CWE-78")) | length' "$jsonl")
[ "$sysinj" -ge 1 ] || { echo "c-cpp-e2e: FAIL (c) no CWE-78 system-injection finding" >&2; exit 1; }
overflow=$(jq -rs 'map(select(.origin=="c-cpp" and (.cwe=="CWE-120" or .cwe=="CWE-788"))) | length' "$jsonl")
[ "$overflow" -ge 1 ] || { echo "c-cpp-e2e: FAIL (c) no buffer-overflow finding" >&2; exit 1; }
echo "  (c) canonical hazards: CWE-78=$sysinj, buffer-overflow=$overflow"

# cwe well-formedness: every non-null cwe is CWE-<n>.
badcwe=$(jq -rs 'map(select(.cwe != null and (.cwe | test("^CWE-[0-9]+$") | not))) | length' "$jsonl")
[ "$badcwe" -eq 0 ] || { echo "c-cpp-e2e: FAIL (d) malformed cwe: $badcwe" >&2; exit 1; }
echo "  (d) all cwe well-formed"

# Origin-tag isolation: c-cpp findings must NOT carry any other lane's tool name.
leak=$(jq -rs 'map(select(.origin=="c-cpp" and (.tool=="semgrep" or .tool=="bandit" or .tool=="hadolint" or .tool=="kics" or .tool=="virt-xml-validate" or .tool=="gosec" or .tool=="staticcheck" or .tool=="gitleaks" or .tool=="trufflehog" or .tool=="cargo-audit" or .tool=="mobsfscan" or .tool=="tfsec" or .tool=="checkov" or .tool=="guarddog" or .tool=="osv-scanner"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "c-cpp-e2e: FAIL (e) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (e) origin-tag isolation: 0 leaks"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__c_cpp_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "c-cpp-e2e: FAIL (f) trailing status: $tail_status" >&2; exit 1; }
echo "  (f) trailing status: $tail_status"

# Reverse isolation: c-cpp must not bleed into other lanes' fixtures.
for other in dast-target sample-stack iis-stack tiny-django vulnerable-virt vulnerable-webext vulnerable-rust vulnerable-go; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="c-cpp")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "c-cpp-e2e: FAIL — c-cpp bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (g) reverse isolation: clean"

echo ""
echo "c-cpp-e2e: OK"
