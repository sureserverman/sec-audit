#!/usr/bin/env bash
# php-e2e.sh — v1.27.0 E2E for the php lane (recorded golden fixture).

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-php/.pipeline/php.jsonl"
[ -f "$jsonl" ] || { echo "php-e2e: FAIL — fixture missing" >&2; exit 1; }

while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "php-e2e: FAIL — bad JSON" >&2; exit 1; }
done < "$jsonl"

pc=$(jq -rs 'map(select(.origin=="php" and .tool=="phpcs")) | length' "$jsonl")
[ "$pc" -ge 1 ] || { echo "php-e2e: FAIL (a) phpcs findings: $pc" >&2; exit 1; }
echo "  (a) phpcs findings: $pc"

# The four canonical WordPress web hazards must be present.
xss=$(jq -rs 'map(select(.cwe=="CWE-79")) | length' "$jsonl")
csrf=$(jq -rs 'map(select(.cwe=="CWE-352")) | length' "$jsonl")
sqli=$(jq -rs 'map(select(.cwe=="CWE-89")) | length' "$jsonl")
inp=$(jq -rs 'map(select(.cwe=="CWE-20")) | length' "$jsonl")
{ [ "$xss" -ge 1 ] && [ "$csrf" -ge 1 ] && [ "$sqli" -ge 1 ] && [ "$inp" -ge 1 ]; } \
    || { echo "php-e2e: FAIL (b) hazards XSS=$xss CSRF=$csrf SQLi=$sqli input=$inp" >&2; exit 1; }
echo "  (b) hazards: XSS(79)=$xss CSRF(352)=$csrf SQLi(89)=$sqli input(20)=$inp"

# cwe well-formedness.
badcwe=$(jq -rs 'map(select(.cwe != null and (.cwe | test("^CWE-[0-9]+$") | not))) | length' "$jsonl")
[ "$badcwe" -eq 0 ] || { echo "php-e2e: FAIL (c) malformed cwe: $badcwe" >&2; exit 1; }
echo "  (c) all cwe well-formed"

# every finding's id is a phpcs WordPress sniff source.
badid=$(jq -rs 'map(select(.origin=="php" and (.id | startswith("WordPress.") | not))) | length' "$jsonl")
[ "$badid" -eq 0 ] || { echo "php-e2e: FAIL (d) non-WordPress sniff id: $badid" >&2; exit 1; }
echo "  (d) all ids are WordPress sniff sources"

# Origin-tag isolation.
leak=$(jq -rs 'map(select(.origin=="php" and (.tool=="semgrep" or .tool=="bandit" or .tool=="cppcheck" or .tool=="flawfinder" or .tool=="hadolint" or .tool=="kics" or .tool=="gosec" or .tool=="gitleaks" or .tool=="brakeman" or .tool=="njsscan" or .tool=="bearer"))) | length' "$jsonl")
[ "$leak" -eq 0 ] || { echo "php-e2e: FAIL (e) — $leak cross-lane leaks" >&2; exit 1; }
echo "  (e) origin-tag isolation: 0 leaks"

tail_status=$(tail -n 1 "$jsonl" | jq -r '.__php_status__ // empty')
{ [ "$tail_status" = "ok" ] || [ "$tail_status" = "partial" ]; } || { echo "php-e2e: FAIL (f) trailing status: $tail_status" >&2; exit 1; }
echo "  (f) trailing status: $tail_status"

# Reverse isolation: php must not bleed into other lanes' fixtures.
for other in dast-target sample-stack iis-stack tiny-django vulnerable-virt vulnerable-c vulnerable-webext vulnerable-go; do
    d="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$d" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="php")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "php-e2e: FAIL — php bleed in $jf" >&2; exit 1; }
    done < <(find "$d" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  (g) reverse isolation: clean"

echo ""
echo "php-e2e: OK"
