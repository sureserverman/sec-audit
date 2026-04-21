#!/usr/bin/env bash
# Stage 2 gate check — cross-agent JSON contract alignment.
#
# Walks the four agent files and confirms the field names each one reads and
# emits line up with what the upstream/downstream agents agree on. This is a
# surface-level grep, not a full schema check — it catches rename drift early
# (e.g., sec-expert renames `cwe` to `cwe_id` without coordinating with the
# triager). Stage 4 Task 4.3 runs the actual schema validation against real
# pipeline output.

set -euo pipefail

here="$(cd "$(dirname "$0")"/.. && pwd)"
cd "$here"

fail=0
check() {
    local file="$1"; local needle="$2"; local reason="$3"
    if ! grep -q -- "$needle" "$file"; then
        echo "CONTRACT FAIL: $file missing \"$needle\" ($reason)" >&2
        fail=1
    fi
}
# Field-name check: match either "foo" (JSON example) or `foo` (prose).
# Captures agent references to a named field regardless of quoting style.
check_field() {
    local file="$1"; local field="$2"; local reason="$3"
    if ! grep -qE "[\"\`]${field}[\"\`]" "$file"; then
        echo "CONTRACT FAIL: $file missing field reference to ${field} ($reason)" >&2
        fail=1
    fi
}

# sec-expert → finding-triager: finding schema fields
for field in id severity cwe file line evidence reference reference_url fix_recipe confidence; do
    check_field agents/sec-expert.md      "$field" "sec-expert finding field"
    check_field agents/finding-triager.md "$field" "triager must read"
done

# finding-triager output additions → report-writer input
for field in confidence fp_suspected triage_notes; do
    check agents/finding-triager.md "$field" "triager emits $field"
    check agents/report-writer.md  "$field" "report-writer reads $field"
done
# triage_notes in the report-writer is allowed to be optional; we only warn if
# unused. Stage 4 contract validation is the authoritative check.

# sec-expert dep inventory → cve-enricher input
check agents/sec-expert.md   '__dep_inventory__' "sec-expert must emit __dep_inventory__"
check agents/cve-enricher.md 'ecosystem'         "cve-enricher reads ecosystem"
check agents/cve-enricher.md 'packages'          "cve-enricher reads packages"
check agents/cve-enricher.md 'version'           "cve-enricher reads version"

# cve-enricher output → report-writer input
for field in cvss fixed_versions source fetched_at status; do
    check agents/cve-enricher.md "$field" "cve-enricher emits $field"
    check agents/report-writer.md "$field" "report-writer reads $field"
done

# model pinning (caller-model-independence)
for pair in "agents/sec-expert.md:sonnet" "agents/cve-enricher.md:haiku" \
            "agents/finding-triager.md:sonnet" "agents/report-writer.md:sonnet"; do
    file="${pair%%:*}"; model="${pair##*:}"
    awk '/^---$/{n++;next} n==1' "$file" | \
        python3 -c "import sys,yaml; d=yaml.safe_load(sys.stdin); \
        assert d.get('model')=='$model', ('wrong model', d.get('model'), 'expected $model'); \
        print(f'model pin ok: $file -> $model')"
done

if [ "$fail" -ne 0 ]; then
    echo "contract-check: FAIL" >&2
    exit 1
fi
echo "contract-check: OK"
