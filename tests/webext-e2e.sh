#!/usr/bin/env bash
# webext-e2e.sh — end-to-end contract test for the sec-review webext lane.
# Validates the fixture pipeline output at
# tests/fixtures/vulnerable-webext/.pipeline/webext.jsonl against the
# three assertions required by Stage 2 Task 2.4:
#
#   (a) at least one finding with origin=webext and tool=addons-linter
#   (b) at least one finding with tool=retire (CVE-carrying)
#   (c) NO webext-origin finding carries a SAST/DAST tool name
#       (semgrep, bandit, zap-baseline)
#
# Also verifies the trailing __webext_status__ line and JSONL validity.
#
# Exit 0 on success with the literal line `webext-e2e: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-webext/.pipeline/webext.jsonl"

if [ ! -f "$jsonl" ]; then
    echo "webext-e2e: FAIL — fixture pipeline output missing: $jsonl" >&2
    exit 1
fi

# ---- JSONL validity
echo "webext-e2e: validating JSONL..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || {
        echo "webext-e2e: FAIL — invalid JSON line: $line" >&2
        exit 1
    }
done < "$jsonl"
echo "  every line parses as JSON"

# ---- Assertion (a): >= 1 finding with origin=webext and tool=addons-linter
addons_count=$(jq -rs 'map(select(.origin=="webext" and .tool=="addons-linter")) | length' "$jsonl")
if [ "$addons_count" -lt 1 ]; then
    echo "webext-e2e: FAIL (a) — expected >=1 finding with tool=addons-linter, got $addons_count" >&2
    exit 1
fi
echo "  (a) addons-linter findings: $addons_count"

# ---- Assertion (b): >= 1 finding with tool=retire
retire_count=$(jq -rs 'map(select(.origin=="webext" and .tool=="retire")) | length' "$jsonl")
if [ "$retire_count" -lt 1 ]; then
    echo "webext-e2e: FAIL (b) — expected >=1 finding with tool=retire, got $retire_count" >&2
    exit 1
fi
echo "  (b) retire findings: $retire_count"

# ---- Assertion (c): origin-tag isolation — no webext finding carries a
# SAST or DAST tool name.
leak=$(jq -rs 'map(select(.origin=="webext" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline"))) | length' "$jsonl")
if [ "$leak" -ne 0 ]; then
    echo "webext-e2e: FAIL (c) — $leak webext findings carry a SAST/DAST tool tag" >&2
    exit 1
fi
echo "  (c) origin-tag isolation: 0 cross-tagged findings"

# ---- Trailing status line
tail_status=$(tail -n 1 "$jsonl" | jq -r '.__webext_status__ // empty')
if [ "$tail_status" != "ok" ] && [ "$tail_status" != "partial" ]; then
    echo "webext-e2e: FAIL — expected trailing __webext_status__ ok|partial, got '$tail_status'" >&2
    exit 1
fi
echo "  trailing status line: __webext_status__=$tail_status"

# ---- Reverse-isolation sanity: other fixture pipelines must NOT
# contain origin=webext lines (they shouldn't, but verify).
for other in dast-target sample-stack iis-stack tiny-django; do
    other_dir="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$other_dir" ] || continue
    while IFS= read -r -d '' jf; do
        webext_bleed=$(jq -rs 'map(select(.origin=="webext")) | length' "$jf" 2>/dev/null || echo 0)
        if [ "$webext_bleed" -ne 0 ]; then
            echo "webext-e2e: FAIL — $jf contains $webext_bleed origin=webext findings (should be 0)" >&2
            exit 1
        fi
    done < <(find "$other_dir" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  reverse isolation: no webext bleed into other fixtures"

echo ""
echo "webext-e2e: OK"
