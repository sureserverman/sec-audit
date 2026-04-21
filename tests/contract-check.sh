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
            "agents/finding-triager.md:sonnet" "agents/report-writer.md:sonnet" \
            "agents/sast-runner.md:haiku"; do
    file="${pair%%:*}"; model="${pair##*:}"
    awk '/^---$/{n++;next} n==1' "$file" | \
        python3 -c "import sys,yaml; d=yaml.safe_load(sys.stdin); \
        assert d.get('model')=='$model', ('wrong model', d.get('model'), 'expected $model'); \
        print(f'model pin ok: $file -> $model')"
done

# Per-fixture JSONL pipeline output validation against the sec-expert finding
# schema. Walks every subdirectory of tests/fixtures/ and validates any
# .pipeline/*.jsonl file found there. A fixture without a .pipeline/ directory
# (or with no .jsonl files in it) is skipped with an informational line rather
# than failing — fixtures may exist before any pipeline has been run against
# them.
validate_fixture_jsonl() {
    local fixture_dir="$1"
    local fixture_name
    fixture_name="$(basename "$fixture_dir")"
    local pipeline_dir="$fixture_dir/.pipeline"
    if [ ! -d "$pipeline_dir" ]; then
        echo "$fixture_name: no JSONL pipeline output yet, skipping"
        return 0
    fi
    # Collect .jsonl files (nullglob-style via find to avoid literal glob).
    local jsonl_files=()
    while IFS= read -r -d '' f; do
        jsonl_files+=("$f")
    done < <(find "$pipeline_dir" -maxdepth 1 -type f -name '*.jsonl' -print0)
    if [ "${#jsonl_files[@]}" -eq 0 ]; then
        echo "$fixture_name: no JSONL pipeline output yet, skipping"
        return 0
    fi
    local jf
    for jf in "${jsonl_files[@]}"; do
        if ! python3 - "$jf" "$fixture_name" <<'PY'
import json, sys
path, fixture = sys.argv[1], sys.argv[2]
required = ["id", "severity", "cwe", "file", "line", "evidence",
            "reference", "reference_url", "fix_recipe", "confidence"]
severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
confidences = {"high", "medium", "low"}
errs = 0
with open(path) as fh:
    for i, line in enumerate(fh, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception as e:
            print(f"CONTRACT FAIL: {path}:{i} not valid JSON: {e}", file=sys.stderr)
            errs += 1
            continue
        if not isinstance(obj, dict):
            print(f"CONTRACT FAIL: {path}:{i} not a JSON object", file=sys.stderr)
            errs += 1
            continue
        # Allow the dep-inventory sentinel line emitted by sec-expert.
        if "__dep_inventory__" in obj or obj.get("id") == "__dep_inventory__":
            continue
        missing = [k for k in required if k not in obj]
        if missing:
            print(f"CONTRACT FAIL: {path}:{i} missing fields: {missing}", file=sys.stderr)
            errs += 1
            continue
        if obj["severity"] not in severities:
            print(f"CONTRACT FAIL: {path}:{i} bad severity {obj['severity']!r}", file=sys.stderr)
            errs += 1
        if obj["confidence"] not in confidences:
            print(f"CONTRACT FAIL: {path}:{i} bad confidence {obj['confidence']!r}", file=sys.stderr)
            errs += 1
        if not isinstance(obj["line"], int):
            print(f"CONTRACT FAIL: {path}:{i} line must be int", file=sys.stderr)
            errs += 1
sys.exit(1 if errs else 0)
PY
        then
            fail=1
        else
            echo "$fixture_name: $(basename "$jf") schema ok"
        fi
    done
}

if [ -d tests/fixtures ]; then
    for fixture in tests/fixtures/*/; do
        [ -d "$fixture" ] || continue
        validate_fixture_jsonl "${fixture%/}"
    done
fi

if [ "$fail" -ne 0 ]; then
    echo "contract-check: FAIL" >&2
    exit 1
fi
echo "contract-check: OK"
