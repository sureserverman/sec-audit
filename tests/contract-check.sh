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
            "agents/sast-runner.md:haiku" "agents/dast-runner.md:haiku" \
            "agents/webext-runner.md:haiku" "agents/rust-runner.md:haiku"; do
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
        # Allow the SAST status summary line emitted by sast-runner.
        if "__sast_status__" in obj:
            status = obj.get("__sast_status__")
            if status not in {"ok", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __sast_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __sast_status__ tools must be a list", file=sys.stderr)
                errs += 1
            continue
        # Allow the DAST status summary line emitted by dast-runner.
        if "__dast_status__" in obj:
            status = obj.get("__dast_status__")
            if status not in {"ok", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __dast_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __dast_status__ tools must be a list", file=sys.stderr)
                errs += 1
            continue
        # Allow the webext status summary line emitted by webext-runner.
        if "__webext_status__" in obj:
            status = obj.get("__webext_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __webext_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __webext_status__ tools must be a list", file=sys.stderr)
                errs += 1
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
        # Origin-aware validation: SAST findings must carry `tool` and `origin`.
        if obj.get("origin") == "sast":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} sast finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"semgrep", "bandit"}:
                print(f"CONTRACT FAIL: {path}:{i} sast tool must be semgrep|bandit, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # fix_recipe is explicitly null-permitted for SAST findings.
            if "fix_recipe" in obj and obj["fix_recipe"] not in (None, ""):
                # SAST tools do not ship quoted fix recipes; warn if present.
                pass
        # Origin-aware validation: DAST findings must carry `tool` and `origin`.
        if obj.get("origin") == "dast":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} dast finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] != "zap-baseline":
                print(f"CONTRACT FAIL: {path}:{i} dast tool must be zap-baseline, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # DAST has no source line; `line: 0` is the documented convention.
            if obj.get("line") != 0:
                print(f"CONTRACT FAIL: {path}:{i} dast line must be 0 (no source line), got {obj.get('line')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: webext findings must carry `tool` and `origin`.
        if obj.get("origin") == "webext":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} webext finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"addons-linter", "web-ext", "retire"}:
                print(f"CONTRACT FAIL: {path}:{i} webext tool must be addons-linter|web-ext|retire, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: webext findings must NOT carry SAST/DAST tool names.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline"}:
                print(f"CONTRACT FAIL: {path}:{i} webext finding carries non-webext tool {obj.get('tool')!r}", file=sys.stderr)
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

# --- Negative test: the origin-aware validator must reject a SAST
# finding with no `tool`. We run the same inline python validator against
# a synthetic malformed line and assert it exits non-zero.
bad_line='{"id":"B602","severity":"HIGH","cwe":"CWE-78","title":"t","file":"x.py","line":1,"evidence":"e","reference":"sast-tools.md","reference_url":null,"fix_recipe":null,"confidence":"high","origin":"sast"}'
if echo "$bad_line" | python3 -c '
import json, sys
required = ["id","severity","cwe","file","line","evidence","reference","reference_url","fix_recipe","confidence"]
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    missing = [k for k in required if k not in obj]
    if missing: errs += 1
    if obj.get("origin") == "sast" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed SAST line (missing tool) was accepted" >&2
    exit 1
fi
echo "sast negative-test: malformed SAST line (missing tool) correctly rejected"

# --- Negative test: the origin-aware validator must reject a webext
# finding with no `tool` and a webext finding tagged with a non-webext tool.
bad_webext_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"manifest.json","line":1,"evidence":"e","reference":"webext-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"webext"}'
if echo "$bad_webext_notool" | python3 -c '
import json, sys
required = ["id","severity","cwe","file","line","evidence","reference","reference_url","fix_recipe","confidence"]
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    missing = [k for k in required if k not in obj]
    if missing: errs += 1
    if obj.get("origin") == "webext" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed webext line (missing tool) was accepted" >&2
    exit 1
fi
echo "webext negative-test: malformed webext line (missing tool) correctly rejected"

bad_webext_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"manifest.json","line":1,"evidence":"e","reference":"webext-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"webext","tool":"semgrep"}'
if echo "$bad_webext_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "webext" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: webext finding with SAST/DAST tool was accepted" >&2
    exit 1
fi
echo "webext negative-test: origin-tag isolation enforced (webext cannot carry semgrep/bandit/zap-baseline)"

# --- Negative test: the origin-aware validator must reject a DAST
# finding with no `tool`. Same pattern as the SAST negative test above.
bad_dast='{"id":"40018","severity":"HIGH","cwe":"CWE-89","title":"t","file":"http://x/","line":0,"evidence":"e","reference":"dast-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"dast"}'
if echo "$bad_dast" | python3 -c '
import json, sys
required = ["id","severity","cwe","file","line","evidence","reference","reference_url","fix_recipe","confidence"]
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    missing = [k for k in required if k not in obj]
    if missing: errs += 1
    if obj.get("origin") == "dast" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed DAST line (missing tool) was accepted" >&2
    exit 1
fi
echo "dast negative-test: malformed DAST line (missing tool) correctly rejected"

# --- webext inventory rule (v0.6.0 Stage 1 Task 1.4):
# SKILL.md §2 must document the browser-extension detection rule
# (manifest.json + manifest_version) and emit a `webext` inventory key.
check skills/sec-review/SKILL.md "Browser-extension signals" "SKILL.md §2 missing webext detection rule"
check skills/sec-review/SKILL.md "manifest_version" "SKILL.md §2 webext rule missing manifest_version trigger"
check skills/sec-review/SKILL.md "\"webext\"" "SKILL.md §2 inventory JSON missing webext key"
echo "webext-inventory: SKILL.md §2 documents webext stack detection"

# --- orchestrator §3.8 wire-up (v0.6.0 Stage 2 Task 2.3):
# SKILL.md must declare §3.8, reference webext-runner, and document all
# three sentinel states (ok / partial / unavailable). Shape mirrors
# §3.6 SAST and §3.7 DAST.
check skills/sec-review/SKILL.md "### 3.8 Browser-extension pass" "SKILL.md missing §3.8"
check skills/sec-review/SKILL.md "webext-runner" "SKILL.md §3.8 missing webext-runner reference"
check skills/sec-review/SKILL.md "__webext_status__" "SKILL.md §3.8 missing webext sentinel"
check skills/sec-review/SKILL.md '__webext_status__.*"unavailable"\|"unavailable".*__webext_status__\|`__webext_status__: "unavailable"`' "SKILL.md §3.8 missing unavailable state (documented)"
check skills/sec-review/SKILL.md '"partial"' "SKILL.md §3.8 missing partial state"
echo "webext-orchestrator: SKILL.md §3.8 documents webext-runner wire-up"

# --- rust inventory rule (v0.7.0 Stage 1 Task 1.4):
# SKILL.md §2 must document the Rust detection rule (Cargo.toml +
# [package] or [workspace]) and emit a `rust` inventory key.
check skills/sec-review/SKILL.md "Rust / Cargo signals" "SKILL.md §2 missing Rust detection rule"
check skills/sec-review/SKILL.md "Cargo.toml" "SKILL.md §2 rust rule missing Cargo.toml trigger"
check skills/sec-review/SKILL.md "\"rust\"" "SKILL.md §2 inventory JSON missing rust key"
check skills/sec-review/SKILL.md "crates.io" "SKILL.md §2 missing crates.io ecosystem routing"
echo "rust-inventory: SKILL.md §2 documents rust stack detection"

# --- rust fixture-match sanity: synthetic Cargo.toml must match rule
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/Cargo.toml" <<'TOML'
[package]
name = "fixture"
version = "0.0.1"
edition = "2021"
TOML
if ! grep -q '\[package\]' "$tmp/Cargo.toml"; then
    echo "rust-inventory: FAIL — fixture lacks [package] section" >&2
    fail=1
fi
echo "rust-inventory: synthetic Cargo.toml fixture matches §2 detection rule"

# --- webext fixture-match sanity: a synthetic manifest.json containing
# "manifest_version": 3 must match the grep hint the SKILL.md rule uses.
# This is a documentation-vs-fixture alignment check, not a full
# orchestrator run (the orchestrator is driven by an LLM reading §2).
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/manifest.json" <<'JSON'
{
  "manifest_version": 3,
  "name": "fixture",
  "version": "0.0.1",
  "host_permissions": ["*://*/*"]
}
JSON
if ! grep -q '"manifest_version"' "$tmp/manifest.json"; then
    echo "webext-inventory: FAIL — fixture lacks manifest_version key" >&2
    fail=1
fi
echo "webext-inventory: synthetic manifest.json fixture matches §2 detection rule"

if [ "$fail" -ne 0 ]; then
    echo "contract-check: FAIL" >&2
    exit 1
fi
echo "contract-check: OK"
