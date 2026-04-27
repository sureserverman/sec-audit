#!/usr/bin/env bash
# rust-e2e.sh — end-to-end contract test for the sec-audit Rust lane.
# Validates the fixture pipeline output at
# tests/fixtures/vulnerable-rust/.pipeline/rust.jsonl against the
# Stage 2 Task 2.3 assertions:
#
#   (a) >=1 finding with origin=rust and tool=cargo-audit carrying a CVE
#   (b) >=1 finding with origin=rust and tool=cargo-geiger at INFO
#   (c) NO rust-origin finding carries a SAST/DAST/webext tool name
#       (semgrep, bandit, zap-baseline, addons-linter, web-ext, retire)
#
# Also verifies the trailing __rust_status__ line and JSONL validity.
#
# Exit 0 on success with the literal line `rust-e2e: OK`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
plugin_root="$(cd "$here/.." && pwd)"
jsonl="$plugin_root/tests/fixtures/vulnerable-rust/.pipeline/rust.jsonl"

[ -f "$jsonl" ] || { echo "rust-e2e: FAIL — fixture pipeline output missing: $jsonl" >&2; exit 1; }

# ---- JSONL validity
echo "rust-e2e: validating JSONL..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 || { echo "rust-e2e: FAIL — invalid JSON: $line" >&2; exit 1; }
done < "$jsonl"
echo "  every line parses as JSON"

# ---- (a) cargo-audit with a CVE
audit_cve=$(jq -rs 'map(select(.origin=="rust" and .tool=="cargo-audit" and (.id | startswith("CVE-")))) | length' "$jsonl")
if [ "$audit_cve" -lt 1 ]; then
    echo "rust-e2e: FAIL (a) — expected >=1 cargo-audit finding with CVE id, got $audit_cve" >&2
    exit 1
fi
echo "  (a) cargo-audit CVE findings: $audit_cve"

# ---- (b) cargo-geiger at INFO
geiger_info=$(jq -rs 'map(select(.origin=="rust" and .tool=="cargo-geiger" and .severity=="INFO")) | length' "$jsonl")
if [ "$geiger_info" -lt 1 ]; then
    echo "rust-e2e: FAIL (b) — expected >=1 cargo-geiger INFO finding, got $geiger_info" >&2
    exit 1
fi
echo "  (b) cargo-geiger INFO findings: $geiger_info"

# cargo-geiger INFO ceiling: none above INFO
geiger_elevated=$(jq -rs 'map(select(.tool=="cargo-geiger" and .severity != "INFO")) | length' "$jsonl")
if [ "$geiger_elevated" -ne 0 ]; then
    echo "rust-e2e: FAIL — $geiger_elevated cargo-geiger findings elevated above INFO" >&2
    exit 1
fi
echo "  cargo-geiger ceiling: 0 findings above INFO"

# ---- (c) origin-tag isolation across 6 other lanes
leak=$(jq -rs 'map(select(.origin=="rust" and (.tool=="semgrep" or .tool=="bandit" or .tool=="zap-baseline" or .tool=="addons-linter" or .tool=="web-ext" or .tool=="retire"))) | length' "$jsonl")
if [ "$leak" -ne 0 ]; then
    echo "rust-e2e: FAIL (c) — $leak rust findings carry a non-rust tool tag" >&2
    exit 1
fi
echo "  (c) origin-tag isolation: 0 cross-tagged findings"

# ---- Trailing status line
tail_status=$(tail -n 1 "$jsonl" | jq -r '.__rust_status__ // empty')
if [ "$tail_status" != "ok" ] && [ "$tail_status" != "partial" ]; then
    echo "rust-e2e: FAIL — expected trailing __rust_status__ ok|partial, got '$tail_status'" >&2
    exit 1
fi
echo "  trailing status line: __rust_status__=$tail_status"

# ---- Reverse isolation: other fixtures must not contain origin=rust
for other in dast-target sample-stack iis-stack tiny-django vulnerable-webext; do
    other_dir="$plugin_root/tests/fixtures/$other/.pipeline"
    [ -d "$other_dir" ] || continue
    while IFS= read -r -d '' jf; do
        bleed=$(jq -rs 'map(select(.origin=="rust")) | length' "$jf" 2>/dev/null || echo 0)
        [ "$bleed" -eq 0 ] || { echo "rust-e2e: FAIL — $jf contains $bleed origin=rust findings (should be 0)" >&2; exit 1; }
    done < <(find "$other_dir" -maxdepth 1 -type f -name '*.jsonl' -print0)
done
echo "  reverse isolation: no rust bleed into other fixtures"

echo ""
echo "rust-e2e: OK"
