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
            "agents/webext-runner.md:haiku" "agents/rust-runner.md:haiku" \
            "agents/android-runner.md:haiku" "agents/ios-runner.md:haiku" \
            "agents/linux-runner.md:haiku" "agents/macos-runner.md:haiku" \
            "agents/windows-runner.md:haiku" "agents/k8s-runner.md:haiku" \
            "agents/iac-runner.md:haiku" "agents/gh-actions-runner.md:haiku" \
            "agents/virt-runner.md:haiku" \
            "agents/go-runner.md:haiku" \
            "agents/shell-runner.md:haiku" \
            "agents/python-runner.md:haiku" \
            "agents/ansible-runner.md:haiku" \
            "agents/netcfg-runner.md:haiku" \
            "agents/image-runner.md:haiku" \
            "agents/ai-tools-runner.md:haiku"; do
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
        # Allow the rust status summary line emitted by rust-runner.
        if "__rust_status__" in obj:
            status = obj.get("__rust_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __rust_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __rust_status__ tools must be a list", file=sys.stderr)
                errs += 1
            continue
        # Allow the android status summary line emitted by android-runner.
        # Unique to this lane: may carry a `skipped` list alongside tools/failed.
        if "__android_status__" in obj:
            status = obj.get("__android_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __android_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __android_status__ tools must be a list", file=sys.stderr)
                errs += 1
            # Optional skipped list — if present, must be a list of {tool, reason}.
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __android_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __android_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the iOS status summary line emitted by ios-runner.
        # Same skipped-list schema as android; adds requires-macos-host as a valid reason.
        if "__ios_status__" in obj:
            status = obj.get("__ios_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __ios_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __ios_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __ios_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __ios_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the Linux desktop status summary line emitted by linux-runner.
        # Same skipped-list schema; adds requires-systemd-host / no-debian-source / no-elf reasons.
        if "__linux_status__" in obj:
            status = obj.get("__linux_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __linux_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __linux_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __linux_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __linux_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the macOS desktop status summary line emitted by macos-runner.
        # Same skipped-list schema as ios; adds no-pkg reason (NEW in v0.11).
        if "__macos_status__" in obj:
            status = obj.get("__macos_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __macos_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __macos_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __macos_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __macos_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the Windows desktop status summary line emitted by windows-runner.
        # Same skipped-list schema; adds requires-windows-host (3rd host gate) + no-pe reasons.
        if "__windows_status__" in obj:
            status = obj.get("__windows_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __windows_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __windows_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __windows_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __windows_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the K8s status summary line emitted by k8s-runner.
        if "__k8s_status__" in obj:
            status = obj.get("__k8s_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __k8s_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __k8s_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __k8s_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __k8s_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the IaC status summary line emitted by iac-runner.
        if "__iac_status__" in obj:
            status = obj.get("__iac_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __iac_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __iac_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __iac_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __iac_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the gh-actions status summary line emitted by gh-actions-runner.
        if "__gh_actions_status__" in obj:
            status = obj.get("__gh_actions_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __gh_actions_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __gh_actions_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __gh_actions_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __gh_actions_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the virt status summary line emitted by virt-runner.
        # Skip vocabulary: tool-missing, no-containerfile, no-libvirt-xml.
        if "__virt_status__" in obj:
            status = obj.get("__virt_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __virt_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __virt_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __virt_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __virt_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the go status summary line emitted by go-runner.
        # Skip vocabulary: tool-missing only (no host-OS gate, no
        # target-shape preconditions beyond go.mod presence).
        if "__go_status__" in obj:
            status = obj.get("__go_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __go_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __go_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __go_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __go_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the shell status summary line emitted by shell-runner.
        # Single-tool lane: only ok / unavailable shapes (no partial).
        # Skip vocabulary: tool-missing, no-shell-source.
        if "__shell_status__" in obj:
            status = obj.get("__shell_status__")
            if status not in {"ok", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __shell_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __shell_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __shell_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __shell_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the python status summary line emitted by python-runner.
        # Skip vocabulary: tool-missing, no-requirements.
        if "__python_status__" in obj:
            status = obj.get("__python_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __python_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __python_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __python_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __python_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the ansible status summary line emitted by ansible-runner.
        # Single-tool lane: only ok / unavailable shapes.
        # Skip vocabulary: tool-missing, no-playbook.
        if "__ansible_status__" in obj:
            status = obj.get("__ansible_status__")
            if status not in {"ok", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __ansible_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __ansible_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __ansible_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __ansible_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the netcfg status summary line emitted by netcfg-runner.
        # Skip vocabulary: tool-missing, no-singbox-config, no-xray-config.
        if "__netcfg_status__" in obj:
            status = obj.get("__netcfg_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __netcfg_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __netcfg_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __netcfg_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __netcfg_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the image status summary line emitted by image-runner.
        # Skip vocabulary: tool-missing, no-image-artifact.
        # Optional `deduplicated` field carries dedup count when both tools ran.
        if "__image_status__" in obj:
            status = obj.get("__image_status__")
            if status not in {"ok", "partial", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __image_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __image_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __image_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __image_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
                        errs += 1
            continue
        # Allow the ai-tools status summary line emitted by ai-tools-runner.
        # Skip vocabulary: tool-missing, no-ai-tool-config.
        # Single-tool lane: only ok/unavailable (no partial).
        if "__ai_tools_status__" in obj:
            status = obj.get("__ai_tools_status__")
            if status not in {"ok", "unavailable"}:
                print(f"CONTRACT FAIL: {path}:{i} bad __ai_tools_status__ {status!r}", file=sys.stderr)
                errs += 1
            if not isinstance(obj.get("tools", []), list):
                print(f"CONTRACT FAIL: {path}:{i} __ai_tools_status__ tools must be a list", file=sys.stderr)
                errs += 1
            sk = obj.get("skipped", [])
            if not isinstance(sk, list):
                print(f"CONTRACT FAIL: {path}:{i} __ai_tools_status__ skipped must be a list", file=sys.stderr)
                errs += 1
            else:
                for e in sk:
                    if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                        print(f"CONTRACT FAIL: {path}:{i} __ai_tools_status__ skipped entry must have tool+reason: {e!r}", file=sys.stderr)
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
            # Origin-tag isolation: webext findings must NOT carry SAST/DAST/rust tool names.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet"}:
                print(f"CONTRACT FAIL: {path}:{i} webext finding carries non-webext tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: rust findings must carry `tool` and `origin`.
        if obj.get("origin") == "rust":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} rust finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet"}:
                print(f"CONTRACT FAIL: {path}:{i} rust tool must be cargo-audit|cargo-deny|cargo-geiger|cargo-vet, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: rust findings must NOT carry SAST/DAST/webext/android tool names.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "mobsfscan", "apkleaks", "android-lint"}:
                print(f"CONTRACT FAIL: {path}:{i} rust finding carries non-rust tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
            # cargo-geiger findings MUST be INFO — never elevated.
            if obj.get("tool") == "cargo-geiger" and obj.get("severity") != "INFO":
                print(f"CONTRACT FAIL: {path}:{i} cargo-geiger finding must be INFO severity, got {obj.get('severity')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: android findings must carry `tool` and `origin`.
        if obj.get("origin") == "android":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} android finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"mobsfscan", "apkleaks", "android-lint"}:
                print(f"CONTRACT FAIL: {path}:{i} android tool must be mobsfscan|apkleaks|android-lint, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: android findings must NOT carry other lanes' tool names.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "codesign", "spctl", "notarytool"}:
                print(f"CONTRACT FAIL: {path}:{i} android finding carries non-android tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: ios findings must carry `tool` and `origin`.
        if obj.get("origin") == "ios":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} ios finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"mobsfscan", "codesign", "spctl", "notarytool"}:
                print(f"CONTRACT FAIL: {path}:{i} ios tool must be mobsfscan|codesign|spctl|notarytool, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: ios findings must NOT carry the other lanes' tool names
            # (note: mobsfscan is allowed for both android and ios — dispatch context disambiguates).
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "apkleaks", "android-lint", "systemd-analyze", "lintian", "checksec"}:
                print(f"CONTRACT FAIL: {path}:{i} ios finding carries non-ios tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: linux findings must carry `tool` and `origin`.
        if obj.get("origin") == "linux":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} linux finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"systemd-analyze", "lintian", "checksec"}:
                print(f"CONTRACT FAIL: {path}:{i} linux tool must be systemd-analyze|lintian|checksec, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: linux findings must NOT carry any other lane's tool names.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler"}:
                print(f"CONTRACT FAIL: {path}:{i} linux finding carries non-linux tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: macos findings must carry `tool` and `origin`.
        if obj.get("origin") == "macos":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} macos finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"mobsfscan", "codesign", "spctl", "pkgutil", "stapler"}:
                print(f"CONTRACT FAIL: {path}:{i} macos tool must be mobsfscan|codesign|spctl|pkgutil|stapler, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: macos findings must NOT carry other lanes' exclusive tool names.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "apkleaks", "android-lint", "notarytool", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck"}:
                print(f"CONTRACT FAIL: {path}:{i} macos finding carries non-macos tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: windows findings must carry `tool` and `origin`.
        if obj.get("origin") == "windows":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} windows finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"binskim", "osslsigncode", "sigcheck"}:
                print(f"CONTRACT FAIL: {path}:{i} windows tool must be binskim|osslsigncode|sigcheck, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: windows findings must NOT carry any other lane's tool names.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "kube-score", "kubesec"}:
                print(f"CONTRACT FAIL: {path}:{i} windows finding carries non-windows tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: k8s findings must carry `tool` and `origin`.
        if obj.get("origin") == "k8s":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} k8s finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"kube-score", "kubesec"}:
                print(f"CONTRACT FAIL: {path}:{i} k8s tool must be kube-score|kubesec, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: k8s findings must NOT carry other lanes' tool names.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate"}:
                print(f"CONTRACT FAIL: {path}:{i} k8s finding carries non-k8s tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: iac findings must carry `tool` and `origin`.
        if obj.get("origin") == "iac":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} iac finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"tfsec", "checkov"}:
                print(f"CONTRACT FAIL: {path}:{i} iac tool must be tfsec|checkov, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "actionlint", "zizmor", "hadolint", "virt-xml-validate"}:
                print(f"CONTRACT FAIL: {path}:{i} iac finding carries non-iac tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: gh-actions findings must carry `tool` and `origin`.
        if obj.get("origin") == "gh-actions":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} gh-actions finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"actionlint", "zizmor"}:
                print(f"CONTRACT FAIL: {path}:{i} gh-actions tool must be actionlint|zizmor, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "hadolint", "virt-xml-validate"}:
                print(f"CONTRACT FAIL: {path}:{i} gh-actions finding carries non-gh-actions tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: virt findings must carry `tool` and `origin`.
        if obj.get("origin") == "virt":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} virt finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"hadolint", "virt-xml-validate"}:
                print(f"CONTRACT FAIL: {path}:{i} virt tool must be hadolint|virt-xml-validate, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: virt findings must NOT carry any other lane's tool name.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "gosec", "staticcheck"}:
                print(f"CONTRACT FAIL: {path}:{i} virt finding carries non-virt tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: go findings must carry `tool` and `origin`.
        if obj.get("origin") == "go":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} go finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"gosec", "staticcheck"}:
                print(f"CONTRACT FAIL: {path}:{i} go tool must be gosec|staticcheck, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: go findings must NOT carry any other lane's tool name.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "shellcheck"}:
                print(f"CONTRACT FAIL: {path}:{i} go finding carries non-go tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: shell findings must carry `tool` and `origin`.
        if obj.get("origin") == "shell":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} shell finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] != "shellcheck":
                print(f"CONTRACT FAIL: {path}:{i} shell tool must be shellcheck, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: shell findings must NOT carry any other lane's tool name.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "pip-audit", "ruff"}:
                print(f"CONTRACT FAIL: {path}:{i} shell finding carries non-shell tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: python findings must carry `tool` and `origin`.
        if obj.get("origin") == "python":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} python finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"pip-audit", "ruff"}:
                print(f"CONTRACT FAIL: {path}:{i} python tool must be pip-audit|ruff, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: python findings must NOT carry any other lane's tool name.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "ansible-lint"}:
                print(f"CONTRACT FAIL: {path}:{i} python finding carries non-python tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: ansible findings must carry `tool` and `origin`.
        if obj.get("origin") == "ansible":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} ansible finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] != "ansible-lint":
                print(f"CONTRACT FAIL: {path}:{i} ansible tool must be ansible-lint, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: ansible findings must NOT carry any other lane's tool name.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "pip-audit", "ruff", "sing-box", "xray"}:
                print(f"CONTRACT FAIL: {path}:{i} ansible finding carries non-ansible tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: netcfg findings must carry `tool` and `origin`.
        if obj.get("origin") == "netcfg":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} netcfg finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"sing-box", "xray"}:
                print(f"CONTRACT FAIL: {path}:{i} netcfg tool must be sing-box|xray, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: netcfg findings must NOT carry any other lane's tool name.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "pip-audit", "ruff", "ansible-lint", "trivy", "grype"}:
                print(f"CONTRACT FAIL: {path}:{i} netcfg finding carries non-netcfg tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: image findings must carry `tool` and `origin`.
        if obj.get("origin") == "image":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} image finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"trivy", "grype"}:
                print(f"CONTRACT FAIL: {path}:{i} image tool must be trivy|grype, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: image findings must NOT carry any other lane's tool name.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "pip-audit", "ruff", "ansible-lint", "sing-box", "xray", "jq", "mcp-scan"}:
                print(f"CONTRACT FAIL: {path}:{i} image finding carries non-image tool {obj.get('tool')!r}", file=sys.stderr)
                errs += 1
        # Origin-aware validation: ai-tools findings must carry `tool` and `origin`.
        if obj.get("origin") == "ai-tools":
            if "tool" not in obj:
                print(f"CONTRACT FAIL: {path}:{i} ai-tools finding missing 'tool' field", file=sys.stderr)
                errs += 1
            elif obj["tool"] not in {"jq", "mcp-scan"}:
                print(f"CONTRACT FAIL: {path}:{i} ai-tools tool must be jq|mcp-scan, got {obj['tool']!r}", file=sys.stderr)
                errs += 1
            # Origin-tag isolation: ai-tools findings must NOT carry any other lane's tool name.
            if obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "pip-audit", "ruff", "ansible-lint", "sing-box", "xray", "trivy", "grype"}:
                print(f"CONTRACT FAIL: {path}:{i} ai-tools finding carries non-ai-tools tool {obj.get('tool')!r}", file=sys.stderr)
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

# --- Negative tests for rust origin: missing tool + cross-tag + INFO ceiling
bad_rust_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"Cargo.toml","line":1,"evidence":"e","reference":"rust-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"rust"}'
if echo "$bad_rust_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "rust" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed rust line (missing tool) was accepted" >&2
    exit 1
fi
echo "rust negative-test: malformed rust line (missing tool) correctly rejected"

bad_rust_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"Cargo.toml","line":1,"evidence":"e","reference":"rust-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"rust","tool":"semgrep"}'
if echo "$bad_rust_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "rust" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: rust finding with non-rust tool was accepted" >&2
    exit 1
fi
echo "rust negative-test: origin-tag isolation enforced (rust cannot carry semgrep/bandit/zap-baseline/addons-linter/web-ext/retire)"

bad_geiger_severity='{"id":"serde@1.0.0","severity":"HIGH","cwe":null,"title":"Unsafe code in serde","file":"serde","line":0,"evidence":"unsafe fns: 5","reference":"rust-tools.md","reference_url":null,"fix_recipe":null,"confidence":"low","origin":"rust","tool":"cargo-geiger"}'
if echo "$bad_geiger_severity" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("tool") == "cargo-geiger" and obj.get("severity") != "INFO":
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: cargo-geiger finding with non-INFO severity was accepted" >&2
    exit 1
fi
echo "rust negative-test: cargo-geiger INFO ceiling enforced"

# --- Negative tests for android origin: missing tool + cross-tag + malformed skipped entry
bad_android_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"AndroidManifest.xml","line":1,"evidence":"e","reference":"mobile-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"android"}'
if echo "$bad_android_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "android" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed android line (missing tool) was accepted" >&2
    exit 1
fi
echo "android negative-test: malformed android line (missing tool) correctly rejected"

bad_android_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"AndroidManifest.xml","line":1,"evidence":"e","reference":"mobile-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"android","tool":"cargo-audit"}'
if echo "$bad_android_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "android" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: android finding with non-android tool was accepted" >&2
    exit 1
fi
echo "android negative-test: origin-tag isolation enforced (android cannot carry 7 other lanes' tool names)"

bad_android_skipped='{"__android_status__":"partial","tools":["mobsfscan"],"runs":1,"findings":3,"skipped":[{"wrong":"shape"}]}'
if echo "$bad_android_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__android_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed skipped entry was accepted" >&2
    exit 1
fi
echo "android negative-test: malformed skipped-list entry correctly rejected"

# --- Negative tests for ios origin: missing tool + cross-tag + malformed skipped
bad_ios_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"Info.plist","line":1,"evidence":"e","reference":"mobile-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"ios"}'
if echo "$bad_ios_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "ios" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed ios line (missing tool) was accepted" >&2
    exit 1
fi
echo "ios negative-test: malformed ios line (missing tool) correctly rejected"

bad_ios_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"Info.plist","line":1,"evidence":"e","reference":"mobile-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"ios","tool":"apkleaks"}'
if echo "$bad_ios_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "ios" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "apkleaks", "android-lint"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: ios finding with non-ios tool was accepted" >&2
    exit 1
fi
echo "ios negative-test: origin-tag isolation enforced (ios cannot carry other lanes' tool names)"

bad_ios_skipped='{"__ios_status__":"ok","tools":["mobsfscan"],"runs":1,"findings":2,"skipped":[{"bad":"entry"}]}'
if echo "$bad_ios_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__ios_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed ios skipped entry was accepted" >&2
    exit 1
fi
echo "ios negative-test: malformed skipped-list entry correctly rejected"

# --- Negative tests for linux origin
bad_linux_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"a.service","line":1,"evidence":"e","reference":"linux-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"linux"}'
if echo "$bad_linux_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "linux" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed linux line (missing tool) was accepted" >&2
    exit 1
fi
echo "linux negative-test: malformed linux line (missing tool) correctly rejected"

bad_linux_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"a.service","line":1,"evidence":"e","reference":"linux-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"linux","tool":"codesign"}'
if echo "$bad_linux_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "linux" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: linux finding with non-linux tool was accepted" >&2
    exit 1
fi
echo "linux negative-test: origin-tag isolation enforced (linux cannot carry the other 11 lanes' tool names)"

bad_linux_skipped='{"__linux_status__":"ok","tools":["lintian"],"runs":1,"findings":2,"skipped":[{"malformed":"entry"}]}'
if echo "$bad_linux_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__linux_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed linux skipped entry was accepted" >&2
    exit 1
fi
echo "linux negative-test: malformed skipped-list entry correctly rejected"

# --- Negative tests for macos origin
bad_macos_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"Info.plist","line":1,"evidence":"e","reference":"mobile-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"macos"}'
if echo "$bad_macos_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "macos" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed macos line (missing tool) was accepted" >&2
    exit 1
fi
echo "macos negative-test: malformed macos line (missing tool) correctly rejected"

bad_macos_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"Info.plist","line":1,"evidence":"e","reference":"mobile-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"macos","tool":"apkleaks"}'
if echo "$bad_macos_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "macos" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "apkleaks", "android-lint", "notarytool", "systemd-analyze", "lintian", "checksec"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: macos finding with non-macos tool was accepted" >&2
    exit 1
fi
echo "macos negative-test: origin-tag isolation enforced (macos cannot carry other lanes' exclusive tool names)"

bad_macos_skipped='{"__macos_status__":"ok","tools":["mobsfscan"],"runs":1,"findings":1,"skipped":[{"bad":"entry"}]}'
if echo "$bad_macos_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__macos_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed macos skipped entry was accepted" >&2
    exit 1
fi
echo "macos negative-test: malformed skipped-list entry correctly rejected"

# --- Negative tests for windows origin
bad_win_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"a.exe","line":0,"evidence":"e","reference":"windows-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"windows"}'
if echo "$bad_win_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "windows" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed windows line (missing tool) was accepted" >&2
    exit 1
fi
echo "windows negative-test: malformed windows line (missing tool) correctly rejected"

bad_win_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"a.exe","line":0,"evidence":"e","reference":"windows-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"windows","tool":"codesign"}'
if echo "$bad_win_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "windows" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: windows finding with non-windows tool was accepted" >&2
    exit 1
fi
echo "windows negative-test: origin-tag isolation enforced (windows cannot carry any of the other 12 lanes' tools)"

bad_win_skipped='{"__windows_status__":"ok","tools":["binskim"],"runs":1,"findings":2,"skipped":[{"no_reason":"shape"}]}'
if echo "$bad_win_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__windows_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed windows skipped entry was accepted" >&2
    exit 1
fi
echo "windows negative-test: malformed skipped-list entry correctly rejected"

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
check skills/sec-audit/SKILL.md "Browser-extension signals" "SKILL.md §2 missing webext detection rule"
check skills/sec-audit/SKILL.md "manifest_version" "SKILL.md §2 webext rule missing manifest_version trigger"
check skills/sec-audit/SKILL.md "\"webext\"" "SKILL.md §2 inventory JSON missing webext key"
echo "webext-inventory: SKILL.md §2 documents webext stack detection"

# --- k8s inventory rule (v1.1.0 Stage 1):
check skills/sec-audit/SKILL.md "Kubernetes signals" "SKILL.md §2 missing K8s detection rule"
check skills/sec-audit/SKILL.md "apiVersion" "SKILL.md §2 k8s rule missing apiVersion trigger"
check skills/sec-audit/SKILL.md "\"k8s\"" "SKILL.md §2 inventory JSON missing k8s key"
echo "k8s-inventory: SKILL.md §2 documents k8s stack detection"

# --- k8s fixture-match sanity
tmp_k=$(mktemp -d); trap 'rm -rf "$tmp_k"' EXIT
cat > "$tmp_k/deploy.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fixture
YAML
if ! grep -qE '^apiVersion:|^kind:' "$tmp_k/deploy.yaml"; then
    echo "k8s-inventory: FAIL — fixture manifest malformed" >&2; fail=1
fi
echo "k8s-inventory: synthetic Deployment fixture matches §2 detection rule"

# --- orchestrator §3.15 wire-up (v1.1.0 Stage 2):
check skills/sec-audit/SKILL.md "### 3.15 Kubernetes admission pass" "SKILL.md missing §3.15"
check skills/sec-audit/SKILL.md "k8s-runner" "SKILL.md §3.15 missing k8s-runner reference"
check skills/sec-audit/SKILL.md "__k8s_status__" "SKILL.md §3.15 missing k8s sentinel"
check skills/sec-audit/SKILL.md "kube-score\|kubesec" "SKILL.md §3.15 missing kube-score/kubesec"
echo "k8s-orchestrator: SKILL.md §3.15 documents k8s-runner wire-up"

# --- iac inventory + §3.16 (v1.2.0):
check skills/sec-audit/SKILL.md "IaC signals" "SKILL.md §2 missing IaC detection"
check skills/sec-audit/SKILL.md "\"iac\"" "SKILL.md §2 missing iac key"
check skills/sec-audit/SKILL.md "### 3.16 IaC pass" "SKILL.md missing §3.16"
check skills/sec-audit/SKILL.md "iac-runner" "SKILL.md §3.16 missing iac-runner"
check skills/sec-audit/SKILL.md "__iac_status__" "SKILL.md §3.16 missing iac sentinel"
check skills/sec-audit/SKILL.md "tfsec\|checkov" "SKILL.md §3.16 missing tfsec/checkov"
echo "iac-orchestrator: SKILL.md §3.16 documents iac-runner wire-up"

# --- gh-actions inventory + §3.17 (v1.3.0):
check skills/sec-audit/SKILL.md "GitHub Actions signals" "SKILL.md §2 missing gh-actions detection"
check skills/sec-audit/SKILL.md "\"gh-actions\"" "SKILL.md §2 missing gh-actions key"
check skills/sec-audit/SKILL.md "### 3.17 GitHub Actions pass" "SKILL.md missing §3.17"
check skills/sec-audit/SKILL.md "gh-actions-runner" "SKILL.md §3.17 missing gh-actions-runner"
check skills/sec-audit/SKILL.md "__gh_actions_status__" "SKILL.md §3.17 missing gh-actions sentinel"
check skills/sec-audit/SKILL.md "actionlint\|zizmor" "SKILL.md §3.17 missing actionlint/zizmor"
echo "gh-actions-orchestrator: SKILL.md §3.17 documents gh-actions-runner wire-up"

# --- dispatch discipline (v1.0.0 Stage 1 Task 1.2):
# SKILL.md §3.0 formally documents multi-stack dispatch + lane-filter semantics.
check skills/sec-audit/SKILL.md "### 3.0 Dispatch discipline" "SKILL.md missing §3.0 Dispatch discipline"
check skills/sec-audit/SKILL.md "Multi-stack dispatch" "SKILL.md §3.0 missing multi-stack documentation"
check skills/sec-audit/SKILL.md "only_lanes\|skip_lanes" "SKILL.md §3.0 missing lane-filter references"
check skills/sec-audit/SKILL.md "COVERAGE.md" "SKILL.md §3.0 missing COVERAGE.md pointer"
echo "dispatch-discipline: SKILL.md §3.0 formalises multi-stack dispatch"

# --- COVERAGE.md presence (v1.0.0 Stage 1 Task 1.1):
check skills/sec-audit/references/COVERAGE.md "^## Lanes" "COVERAGE.md missing Lanes section"
check skills/sec-audit/references/COVERAGE.md "^## Ecosystems" "COVERAGE.md missing Ecosystems section"
check skills/sec-audit/references/COVERAGE.md "^## Skip-reason vocabulary" "COVERAGE.md missing skip-reason vocabulary"
check skills/sec-audit/references/COVERAGE.md "requires-macos-host" "COVERAGE.md missing requires-macos-host"
check skills/sec-audit/references/COVERAGE.md "requires-systemd-host" "COVERAGE.md missing requires-systemd-host"
check skills/sec-audit/references/COVERAGE.md "requires-windows-host" "COVERAGE.md missing requires-windows-host"
echo "coverage-md: references/COVERAGE.md enumerates all lanes + skip vocabulary"

# --- report-writer per-lane summary (v1.0.0 Stage 1 Task 1.3):
check agents/report-writer.md "Per-lane summary" "report-writer missing per-lane summary table"
check agents/report-writer.md "Step 2\.5" "report-writer missing Step 2.5"
check agents/report-writer.md "Lanes dispatched" "report-writer missing Lanes-dispatched metadata line"
check agents/report-writer.md "Lane filter applied" "report-writer missing Lane-filter-applied line"
echo "per-lane-summary: report-writer renders per-lane summary table + filter metadata"

# --- CLI --only/--skip flags (v1.0.0 Stage 2 Task 2.1):
check commands/sec-audit.md "\-\-only=" "commands/sec-audit.md missing --only flag"
check commands/sec-audit.md "\-\-skip=" "commands/sec-audit.md missing --skip flag"
check commands/sec-audit.md "mutually exclusive" "commands/sec-audit.md missing --only/--skip mutual-exclusion rule"
check commands/sec-audit.md "sec-expert.*sast.*dast.*webext.*rust.*android.*ios.*linux.*macos.*windows\|Canonical lane names" "commands/sec-audit.md missing canonical lane list"
echo "cli-flags: commands/sec-audit.md documents --only/--skip with mutual-exclusion"

# --- orchestrator §3.8 wire-up (v0.6.0 Stage 2 Task 2.3):
# SKILL.md must declare §3.8, reference webext-runner, and document all
# three sentinel states (ok / partial / unavailable). Shape mirrors
# §3.6 SAST and §3.7 DAST.
check skills/sec-audit/SKILL.md "### 3.8 Browser-extension pass" "SKILL.md missing §3.8"
check skills/sec-audit/SKILL.md "webext-runner" "SKILL.md §3.8 missing webext-runner reference"
check skills/sec-audit/SKILL.md "__webext_status__" "SKILL.md §3.8 missing webext sentinel"
check skills/sec-audit/SKILL.md '__webext_status__.*"unavailable"\|"unavailable".*__webext_status__\|`__webext_status__: "unavailable"`' "SKILL.md §3.8 missing unavailable state (documented)"
check skills/sec-audit/SKILL.md '"partial"' "SKILL.md §3.8 missing partial state"
echo "webext-orchestrator: SKILL.md §3.8 documents webext-runner wire-up"

# --- rust inventory rule (v0.7.0 Stage 1 Task 1.4):
# SKILL.md §2 must document the Rust detection rule (Cargo.toml +
# [package] or [workspace]) and emit a `rust` inventory key.
check skills/sec-audit/SKILL.md "Rust / Cargo signals" "SKILL.md §2 missing Rust detection rule"
check skills/sec-audit/SKILL.md "Cargo.toml" "SKILL.md §2 rust rule missing Cargo.toml trigger"
check skills/sec-audit/SKILL.md "\"rust\"" "SKILL.md §2 inventory JSON missing rust key"
check skills/sec-audit/SKILL.md "crates.io" "SKILL.md §2 missing crates.io ecosystem routing"
echo "rust-inventory: SKILL.md §2 documents rust stack detection"

# --- android inventory rule (v0.8.0 Stage 1 Task 1.5):
# SKILL.md §2 must document the Android detection rule (AndroidManifest.xml
# OR com.android.application/library plugin) and emit an `android` key.
check skills/sec-audit/SKILL.md "Android signals" "SKILL.md §2 missing Android detection rule"
check skills/sec-audit/SKILL.md "AndroidManifest.xml" "SKILL.md §2 android rule missing AndroidManifest.xml trigger"
check skills/sec-audit/SKILL.md "\"android\"" "SKILL.md §2 inventory JSON missing android key"
check skills/sec-audit/SKILL.md "com.android.application\|com.android.library" "SKILL.md §2 missing gradle Android plugin trigger"
check skills/sec-audit/SKILL.md "Maven" "SKILL.md §2 missing Maven ecosystem routing"
echo "android-inventory: SKILL.md §2 documents android stack detection"

# --- ios inventory rule (v0.9.0 Stage 1 Task 1.5):
check skills/sec-audit/SKILL.md "iOS / Apple-platform signals" "SKILL.md §2 missing iOS detection rule"
check skills/sec-audit/SKILL.md "Info.plist" "SKILL.md §2 ios rule missing Info.plist trigger"
check skills/sec-audit/SKILL.md "xcodeproj\|Package.swift\|Podfile" "SKILL.md §2 missing Xcode/SwiftPM/CocoaPods trigger"
check skills/sec-audit/SKILL.md "\"ios\"" "SKILL.md §2 inventory JSON missing ios key"
check skills/sec-audit/SKILL.md "CocoaPods\|SwiftPM" "SKILL.md §2 missing iOS ecosystem routing"
echo "ios-inventory: SKILL.md §2 documents ios stack detection"

# --- macos inventory rule (v0.11.0 Stage 1 Task 1.5):
check skills/sec-audit/SKILL.md "macOS desktop signals" "SKILL.md §2 missing macOS detection rule"
check skills/sec-audit/SKILL.md "LSMinimumSystemVersion" "SKILL.md §2 macos rule missing LSMinimumSystemVersion trigger"
check skills/sec-audit/SKILL.md "\"macos\"" "SKILL.md §2 inventory JSON missing macos key"
check skills/sec-audit/SKILL.md "Sparkle\|SUFeedURL" "SKILL.md §2 missing Sparkle trigger"
check skills/sec-audit/SKILL.md "\.pkg\|\.dmg" "SKILL.md §2 missing pkg/dmg trigger"
echo "macos-inventory: SKILL.md §2 documents macos stack detection"

# --- macos fixture-match sanity: synthetic Info.plist with LSMinimumSystemVersion
tmp_m=$(mktemp -d); trap 'rm -rf "$tmp_m"' EXIT
cat > "$tmp_m/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.fixture</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
</dict></plist>
PLIST
if ! grep -q 'LSMinimumSystemVersion' "$tmp_m/Info.plist"; then
    echo "macos-inventory: FAIL — fixture Info.plist missing LSMinimumSystemVersion" >&2; fail=1
fi
echo "macos-inventory: synthetic macOS Info.plist fixture matches §2 detection rule"

# --- windows inventory rule (v0.12.0 Stage 1 Task 1.5):
check skills/sec-audit/SKILL.md "Windows-desktop signals" "SKILL.md §2 missing Windows detection rule"
check skills/sec-audit/SKILL.md "\.csproj\|\.vcxproj\|\.sln" "SKILL.md §2 windows rule missing .NET/C++ project trigger"
check skills/sec-audit/SKILL.md "\.wxs\|AppxManifest\|Package.appxmanifest" "SKILL.md §2 missing WiX/MSIX trigger"
check skills/sec-audit/SKILL.md "\"windows\"" "SKILL.md §2 inventory JSON missing windows key"
check skills/sec-audit/SKILL.md "NuGet" "SKILL.md §2 missing NuGet ecosystem routing"
echo "windows-inventory: SKILL.md §2 documents windows stack detection"

# --- windows fixture-match sanity: synthetic .csproj with PackageReference
tmp_w=$(mktemp -d); trap 'rm -rf "$tmp_w"' EXIT
cat > "$tmp_w/VulnerableWin.csproj" <<'CSPROJ'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <OutputType>Exe</OutputType>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
CSPROJ
if ! grep -q '<PackageReference' "$tmp_w/VulnerableWin.csproj"; then
    echo "windows-inventory: FAIL — fixture .csproj malformed" >&2; fail=1
fi
echo "windows-inventory: synthetic .csproj fixture matches §2 detection rule"

# --- linux inventory rule (v0.10.0 Stage 1 Task 1.5):
check skills/sec-audit/SKILL.md "Linux-desktop signals" "SKILL.md §2 missing Linux detection rule"
check skills/sec-audit/SKILL.md "\.service\|\.socket\|\.timer" "SKILL.md §2 linux rule missing systemd unit trigger"
check skills/sec-audit/SKILL.md "debian/control\|debian/rules" "SKILL.md §2 missing Debian packaging trigger"
check skills/sec-audit/SKILL.md "snapcraft.yaml\|flatpak" "SKILL.md §2 missing Snap/Flatpak trigger"
check skills/sec-audit/SKILL.md "\"linux\"" "SKILL.md §2 inventory JSON missing linux key"
check skills/sec-audit/SKILL.md "\"Debian\"\|ecosystem.*Debian" "SKILL.md §2 missing Debian ecosystem routing"
echo "linux-inventory: SKILL.md §2 documents linux stack detection"

# --- linux fixture-match sanity: synthetic .service
tmp_l=$(mktemp -d); trap 'rm -rf "$tmp_l"' EXIT
mkdir -p "$tmp_l/systemd"
cat > "$tmp_l/systemd/fixture.service" <<'SVC'
[Unit]
Description=fixture

[Service]
ExecStart=/usr/bin/fixture
User=root

[Install]
WantedBy=multi-user.target
SVC
if ! grep -q '^\[Service\]' "$tmp_l/systemd/fixture.service"; then
    echo "linux-inventory: FAIL — fixture .service malformed" >&2; fail=1
fi
echo "linux-inventory: synthetic .service fixture matches §2 detection rule"

# --- ios fixture-match sanity: synthetic Info.plist
tmp_i=$(mktemp -d); trap 'rm -rf "$tmp_i"' EXIT
cat > "$tmp_i/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.fixture</string>
  <key>CFBundleVersion</key><string>1</string>
</dict></plist>
PLIST
if ! grep -q '<plist' "$tmp_i/Info.plist"; then
    echo "ios-inventory: FAIL — fixture Info.plist malformed" >&2; fail=1
fi
echo "ios-inventory: synthetic Info.plist fixture matches §2 detection rule"

# --- android fixture-match sanity: synthetic AndroidManifest.xml + build.gradle
tmp_a=$(mktemp -d); trap 'rm -rf "$tmp_a"' EXIT
mkdir -p "$tmp_a/app/src/main"
cat > "$tmp_a/app/src/main/AndroidManifest.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
  <application android:label="fixture" />
</manifest>
XML
cat > "$tmp_a/app/build.gradle" <<'GRADLE'
plugins { id 'com.android.application' }
android { compileSdk 34 }
GRADLE
if ! grep -q '<manifest' "$tmp_a/app/src/main/AndroidManifest.xml"; then
    echo "android-inventory: FAIL — fixture manifest malformed" >&2; fail=1
fi
if ! grep -q 'com.android.application' "$tmp_a/app/build.gradle"; then
    echo "android-inventory: FAIL — fixture gradle missing plugin" >&2; fail=1
fi
echo "android-inventory: synthetic AndroidManifest.xml + build.gradle fixture matches §2 detection rule"

# --- orchestrator §3.9 wire-up (v0.7.0 Stage 2 Task 2.2):
# SKILL.md must declare §3.9, reference rust-runner, and document all
# three sentinel states (ok / partial / unavailable). Shape mirrors
# §3.6 / §3.7 / §3.8.
check skills/sec-audit/SKILL.md "### 3.9 Rust toolchain pass" "SKILL.md missing §3.9"
check skills/sec-audit/SKILL.md "rust-runner" "SKILL.md §3.9 missing rust-runner reference"
check skills/sec-audit/SKILL.md "__rust_status__" "SKILL.md §3.9 missing rust sentinel"
check skills/sec-audit/SKILL.md "cargo-audit\|cargo audit" "SKILL.md §3.9 missing cargo-audit"
check skills/sec-audit/SKILL.md "cargo-geiger\|cargo geiger" "SKILL.md §3.9 missing cargo-geiger"
echo "rust-orchestrator: SKILL.md §3.9 documents rust-runner wire-up"

# --- orchestrator §3.10 wire-up (v0.8.0 Stage 2 Task 2.2):
check skills/sec-audit/SKILL.md "### 3.10 Android pass" "SKILL.md missing §3.10"
check skills/sec-audit/SKILL.md "android-runner" "SKILL.md §3.10 missing android-runner reference"
check skills/sec-audit/SKILL.md "__android_status__" "SKILL.md §3.10 missing android sentinel"
check skills/sec-audit/SKILL.md "mobsfscan" "SKILL.md §3.10 missing mobsfscan"
check skills/sec-audit/SKILL.md "apkleaks" "SKILL.md §3.10 missing apkleaks"
check skills/sec-audit/SKILL.md "no-apk\|Clean-skip" "SKILL.md §3.10 missing clean-skip documentation"
echo "android-orchestrator: SKILL.md §3.10 documents android-runner wire-up"

# --- orchestrator §3.11 wire-up (v0.9.0 Stage 2 Task 2.2):
check skills/sec-audit/SKILL.md "### 3.11 iOS pass" "SKILL.md missing §3.11"
check skills/sec-audit/SKILL.md "ios-runner" "SKILL.md §3.11 missing ios-runner reference"
check skills/sec-audit/SKILL.md "__ios_status__" "SKILL.md §3.11 missing ios sentinel"
check skills/sec-audit/SKILL.md "requires-macos-host" "SKILL.md §3.11 missing macOS-host clean-skip reason"
check skills/sec-audit/SKILL.md "codesign" "SKILL.md §3.11 missing codesign"
check skills/sec-audit/SKILL.md "notarytool" "SKILL.md §3.11 missing notarytool"
echo "ios-orchestrator: SKILL.md §3.11 documents ios-runner wire-up"

# --- orchestrator §3.12 wire-up (v0.10.0 Stage 2 Task 2.2):
check skills/sec-audit/SKILL.md "### 3.12 Desktop Linux pass" "SKILL.md missing §3.12"
check skills/sec-audit/SKILL.md "linux-runner" "SKILL.md §3.12 missing linux-runner reference"
check skills/sec-audit/SKILL.md "__linux_status__" "SKILL.md §3.12 missing linux sentinel"
check skills/sec-audit/SKILL.md "requires-systemd-host" "SKILL.md §3.12 missing systemd-host clean-skip reason"
check skills/sec-audit/SKILL.md "systemd-analyze" "SKILL.md §3.12 missing systemd-analyze"
check skills/sec-audit/SKILL.md "lintian" "SKILL.md §3.12 missing lintian"
check skills/sec-audit/SKILL.md "no-elf\|no-debian-source" "SKILL.md §3.12 missing target-shape skip reasons"
echo "linux-orchestrator: SKILL.md §3.12 documents linux-runner wire-up"

# --- orchestrator §3.13 wire-up (v0.11.0 Stage 2 Task 2.2):
check skills/sec-audit/SKILL.md "### 3.13 Desktop macOS pass" "SKILL.md missing §3.13"
check skills/sec-audit/SKILL.md "macos-runner" "SKILL.md §3.13 missing macos-runner reference"
check skills/sec-audit/SKILL.md "__macos_status__" "SKILL.md §3.13 missing macos sentinel"
check skills/sec-audit/SKILL.md "pkgutil" "SKILL.md §3.13 missing pkgutil"
check skills/sec-audit/SKILL.md "stapler" "SKILL.md §3.13 missing stapler"
check skills/sec-audit/SKILL.md "no-pkg" "SKILL.md §3.13 missing no-pkg clean-skip reason"
echo "macos-orchestrator: SKILL.md §3.13 documents macos-runner wire-up"

# --- orchestrator §3.14 wire-up (v0.12.0 Stage 2 Task 2.2):
check skills/sec-audit/SKILL.md "### 3.14 Desktop Windows pass" "SKILL.md missing §3.14"
check skills/sec-audit/SKILL.md "windows-runner" "SKILL.md §3.14 missing windows-runner reference"
check skills/sec-audit/SKILL.md "__windows_status__" "SKILL.md §3.14 missing windows sentinel"
check skills/sec-audit/SKILL.md "requires-windows-host" "SKILL.md §3.14 missing Windows-host clean-skip reason"
check skills/sec-audit/SKILL.md "binskim" "SKILL.md §3.14 missing binskim"
check skills/sec-audit/SKILL.md "osslsigncode\|sigcheck" "SKILL.md §3.14 missing osslsigncode/sigcheck"
check skills/sec-audit/SKILL.md "no-pe" "SKILL.md §3.14 missing no-pe clean-skip reason"
echo "windows-orchestrator: SKILL.md §3.14 documents windows-runner wire-up"

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

# --- virt inventory + §3.18 (v1.4.0):
check skills/sec-audit/SKILL.md "Virtualization / alternative-runtime signals" "SKILL.md §2 missing virt detection"
check skills/sec-audit/SKILL.md "\"virt\"" "SKILL.md §2 inventory JSON missing virt key"
check skills/sec-audit/SKILL.md "### 3.18 Virtualization pass" "SKILL.md missing §3.18"
check skills/sec-audit/SKILL.md "virt-runner" "SKILL.md §3.18 missing virt-runner"
check skills/sec-audit/SKILL.md "__virt_status__" "SKILL.md §3.18 missing virt sentinel"
check skills/sec-audit/SKILL.md "hadolint\|virt-xml-validate" "SKILL.md §3.18 missing hadolint/virt-xml-validate"
check skills/sec-audit/SKILL.md "no-containerfile" "SKILL.md §3.18 missing no-containerfile clean-skip reason"
check skills/sec-audit/SKILL.md "no-libvirt-xml" "SKILL.md §3.18 missing no-libvirt-xml clean-skip reason"
echo "virt-orchestrator: SKILL.md §3.18 documents virt-runner wire-up"

# --- virt fixture-match sanity: synthetic Dockerfile + libvirt domain XML.
tmp_v=$(mktemp -d); trap 'rm -rf "$tmp_v"' EXIT
cat > "$tmp_v/Dockerfile" <<'DOCKERFILE'
FROM alpine:latest
USER root
DOCKERFILE
cat > "$tmp_v/vuln.xml" <<'XML'
<?xml version="1.0"?>
<domain type='kvm'>
  <name>x</name>
  <memory unit='WHAT'>1</memory>
</domain>
XML
if ! grep -q '^FROM' "$tmp_v/Dockerfile"; then
    echo "virt-inventory: FAIL — fixture Dockerfile malformed" >&2; fail=1
fi
if ! grep -q '<domain' "$tmp_v/vuln.xml"; then
    echo "virt-inventory: FAIL — fixture libvirt XML malformed" >&2; fail=1
fi
echo "virt-inventory: synthetic Dockerfile + libvirt XML fixture matches §2 detection rule"

# --- Negative tests for virt origin: missing tool + cross-tag + malformed skipped.
bad_virt_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"Dockerfile","line":1,"evidence":"e","reference":"virt-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"virt"}'
if echo "$bad_virt_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "virt" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed virt line (missing tool) was accepted" >&2
    exit 1
fi
echo "virt negative-test: malformed virt line (missing tool) correctly rejected"

bad_virt_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"Dockerfile","line":1,"evidence":"e","reference":"virt-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"virt","tool":"semgrep"}'
if echo "$bad_virt_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "virt" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: virt finding with non-virt tool was accepted" >&2
    exit 1
fi
echo "virt negative-test: origin-tag isolation enforced (virt cannot carry the other 13 lanes' tools)"

bad_virt_skipped='{"__virt_status__":"partial","tools":["hadolint"],"runs":1,"findings":2,"skipped":[{"oops":"shape"}]}'
if echo "$bad_virt_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__virt_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed virt skipped entry was accepted" >&2
    exit 1
fi
echo "virt negative-test: malformed skipped-list entry correctly rejected"

# --- go inventory + §3.19 (v1.5.0):
check skills/sec-audit/SKILL.md "Go signals" "SKILL.md §2 missing go detection"
check skills/sec-audit/SKILL.md "\"go\"" "SKILL.md §2 inventory JSON missing go key"
check skills/sec-audit/SKILL.md "### 3.19 Go pass" "SKILL.md missing §3.19"
check skills/sec-audit/SKILL.md "go-runner" "SKILL.md §3.19 missing go-runner"
check skills/sec-audit/SKILL.md "__go_status__" "SKILL.md §3.19 missing go sentinel"
check skills/sec-audit/SKILL.md "gosec\|staticcheck" "SKILL.md §3.19 missing gosec/staticcheck"
check skills/sec-audit/SKILL.md "ecosystem.*Go\|\"Go\"" "SKILL.md §2 missing Go ecosystem routing"
echo "go-orchestrator: SKILL.md §3.19 documents go-runner wire-up"

# --- go fixture-match sanity: synthetic go.mod + main.go.
tmp_g=$(mktemp -d); trap 'rm -rf "$tmp_g"' EXIT
cat > "$tmp_g/go.mod" <<'GOMOD'
module example.com/fixture

go 1.22
GOMOD
cat > "$tmp_g/main.go" <<'GOSRC'
package main

func main() {}
GOSRC
if ! grep -q '^module' "$tmp_g/go.mod"; then
    echo "go-inventory: FAIL — fixture go.mod malformed" >&2; fail=1
fi
if ! grep -q '^package' "$tmp_g/main.go"; then
    echo "go-inventory: FAIL — fixture main.go malformed" >&2; fail=1
fi
echo "go-inventory: synthetic go.mod + main.go fixture matches §2 detection rule"

# --- Negative tests for go origin: missing tool + cross-tag + malformed skipped.
bad_go_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"main.go","line":1,"evidence":"e","reference":"go-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"go"}'
if echo "$bad_go_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "go" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed go line (missing tool) was accepted" >&2
    exit 1
fi
echo "go negative-test: malformed go line (missing tool) correctly rejected"

bad_go_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"main.go","line":1,"evidence":"e","reference":"go-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"go","tool":"semgrep"}'
if echo "$bad_go_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "go" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: go finding with non-go tool was accepted" >&2
    exit 1
fi
echo "go negative-test: origin-tag isolation enforced (go cannot carry the other 14 lanes' tools)"

bad_go_skipped='{"__go_status__":"partial","tools":["gosec"],"runs":1,"findings":3,"skipped":[{"oops":"shape"}]}'
if echo "$bad_go_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__go_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed go skipped entry was accepted" >&2
    exit 1
fi
echo "go negative-test: malformed skipped-list entry correctly rejected"

# --- shell inventory + §3.20 (v1.6.0):
check skills/sec-audit/SKILL.md "Shell signals" "SKILL.md §2 missing shell detection"
check skills/sec-audit/SKILL.md "\"shell\"" "SKILL.md §2 inventory JSON missing shell key"
check skills/sec-audit/SKILL.md "### 3.20 Shell pass" "SKILL.md missing §3.20"
check skills/sec-audit/SKILL.md "shell-runner" "SKILL.md §3.20 missing shell-runner"
check skills/sec-audit/SKILL.md "__shell_status__" "SKILL.md §3.20 missing shell sentinel"
check skills/sec-audit/SKILL.md "shellcheck" "SKILL.md §3.20 missing shellcheck"
check skills/sec-audit/SKILL.md "no-shell-source" "SKILL.md §3.20 missing no-shell-source clean-skip reason"
echo "shell-orchestrator: SKILL.md §3.20 documents shell-runner wire-up"

# --- shell fixture-match sanity: synthetic *.sh
tmp_sh=$(mktemp -d); trap 'rm -rf "$tmp_sh"' EXIT
cat > "$tmp_sh/install.sh" <<'BASH'
#!/bin/bash
echo $1
BASH
if ! head -1 "$tmp_sh/install.sh" | grep -q '^#!'; then
    echo "shell-inventory: FAIL — fixture install.sh missing shebang" >&2; fail=1
fi
echo "shell-inventory: synthetic *.sh fixture matches §2 detection rule"

# --- Negative tests for shell origin: missing tool + cross-tag + malformed skipped.
bad_shell_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"a.sh","line":1,"evidence":"e","reference":"shell-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"shell"}'
if echo "$bad_shell_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "shell" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed shell line (missing tool) was accepted" >&2
    exit 1
fi
echo "shell negative-test: malformed shell line (missing tool) correctly rejected"

bad_shell_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"a.sh","line":1,"evidence":"e","reference":"shell-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"shell","tool":"semgrep"}'
if echo "$bad_shell_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "shell" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: shell finding with non-shell tool was accepted" >&2
    exit 1
fi
echo "shell negative-test: origin-tag isolation enforced (shell cannot carry the other 15 lanes' tools)"

bad_shell_skipped='{"__shell_status__":"unavailable","tools":[],"skipped":[{"oops":"shape"}]}'
if echo "$bad_shell_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__shell_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed shell skipped entry was accepted" >&2
    exit 1
fi
echo "shell negative-test: malformed skipped-list entry correctly rejected"

# --- python inventory + §3.21 (v1.7.0):
check skills/sec-audit/SKILL.md "Python signals" "SKILL.md §2 missing python detection"
check skills/sec-audit/SKILL.md "\"python\"" "SKILL.md §2 inventory JSON missing python key"
check skills/sec-audit/SKILL.md "### 3.21 Python pass" "SKILL.md missing §3.21"
check skills/sec-audit/SKILL.md "python-runner" "SKILL.md §3.21 missing python-runner"
check skills/sec-audit/SKILL.md "__python_status__" "SKILL.md §3.21 missing python sentinel"
check skills/sec-audit/SKILL.md "pip-audit\|ruff" "SKILL.md §3.21 missing pip-audit/ruff"
check skills/sec-audit/SKILL.md "no-requirements" "SKILL.md §3.21 missing no-requirements clean-skip reason"
echo "python-orchestrator: SKILL.md §3.21 documents python-runner wire-up"

# --- python fixture-match sanity: synthetic requirements.txt + *.py
tmp_py=$(mktemp -d); trap 'rm -rf "$tmp_py"' EXIT
cat > "$tmp_py/requirements.txt" <<'REQ'
django==4.2.0
REQ
cat > "$tmp_py/app.py" <<'PY'
def main(): pass
PY
if ! grep -q '==' "$tmp_py/requirements.txt"; then
    echo "python-inventory: FAIL — fixture requirements.txt malformed" >&2; fail=1
fi
echo "python-inventory: synthetic requirements.txt + app.py fixture matches §2 detection rule"

# --- Negative tests for python origin
bad_py_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"app.py","line":1,"evidence":"e","reference":"python-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"python"}'
if echo "$bad_py_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "python" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed python line (missing tool) was accepted" >&2
    exit 1
fi
echo "python negative-test: malformed python line (missing tool) correctly rejected"

bad_py_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"app.py","line":1,"evidence":"e","reference":"python-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"python","tool":"shellcheck"}'
if echo "$bad_py_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "python" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: python finding with non-python tool was accepted" >&2
    exit 1
fi
echo "python negative-test: origin-tag isolation enforced (python cannot carry the other 16 lanes' tools)"

bad_py_skipped='{"__python_status__":"partial","tools":["pip-audit"],"runs":1,"findings":2,"skipped":[{"oops":"shape"}]}'
if echo "$bad_py_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__python_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed python skipped entry was accepted" >&2
    exit 1
fi
echo "python negative-test: malformed skipped-list entry correctly rejected"

# --- ansible inventory + §3.22 (v1.8.0):
check skills/sec-audit/SKILL.md "Ansible signals" "SKILL.md §2 missing ansible detection"
check skills/sec-audit/SKILL.md "\"ansible\"" "SKILL.md §2 inventory JSON missing ansible key"
check skills/sec-audit/SKILL.md "### 3.22 Ansible pass" "SKILL.md missing §3.22"
check skills/sec-audit/SKILL.md "ansible-runner" "SKILL.md §3.22 missing ansible-runner"
check skills/sec-audit/SKILL.md "__ansible_status__" "SKILL.md §3.22 missing ansible sentinel"
check skills/sec-audit/SKILL.md "ansible-lint" "SKILL.md §3.22 missing ansible-lint"
check skills/sec-audit/SKILL.md "no-playbook" "SKILL.md §3.22 missing no-playbook clean-skip reason"
echo "ansible-orchestrator: SKILL.md §3.22 documents ansible-runner wire-up"

# --- ansible fixture-match sanity: synthetic playbook YAML
tmp_an=$(mktemp -d); trap 'rm -rf "$tmp_an"' EXIT
cat > "$tmp_an/playbook.yml" <<'YAML'
---
- hosts: webservers
  tasks:
    - name: Test
      command: echo hi
YAML
if ! grep -q '^hosts:' "$tmp_an/playbook.yml" 2>/dev/null && ! grep -qE '^- hosts:' "$tmp_an/playbook.yml"; then
    echo "ansible-inventory: FAIL — fixture playbook missing hosts:" >&2; fail=1
fi
echo "ansible-inventory: synthetic playbook.yml fixture matches §2 detection rule"

# --- Negative tests for ansible origin
bad_an_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"playbook.yml","line":1,"evidence":"e","reference":"ansible-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"ansible"}'
if echo "$bad_an_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "ansible" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed ansible line (missing tool) was accepted" >&2
    exit 1
fi
echo "ansible negative-test: malformed ansible line (missing tool) correctly rejected"

bad_an_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"playbook.yml","line":1,"evidence":"e","reference":"ansible-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"ansible","tool":"shellcheck"}'
if echo "$bad_an_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "ansible" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "pip-audit", "ruff"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: ansible finding with non-ansible tool was accepted" >&2
    exit 1
fi
echo "ansible negative-test: origin-tag isolation enforced (ansible cannot carry the other 17 lanes' tools)"

bad_an_skipped='{"__ansible_status__":"unavailable","tools":[],"skipped":[{"oops":"shape"}]}'
if echo "$bad_an_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__ansible_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed ansible skipped entry was accepted" >&2
    exit 1
fi
echo "ansible negative-test: malformed skipped-list entry correctly rejected"

# --- netcfg inventory + §3.23 (v1.9.0):
check skills/sec-audit/SKILL.md "Networking-as-code signals" "SKILL.md §2 missing netcfg detection"
check skills/sec-audit/SKILL.md "\"netcfg\"" "SKILL.md §2 inventory JSON missing netcfg key"
check skills/sec-audit/SKILL.md "### 3.23 Networking-as-code pass" "SKILL.md missing §3.23"
check skills/sec-audit/SKILL.md "netcfg-runner" "SKILL.md §3.23 missing netcfg-runner"
check skills/sec-audit/SKILL.md "__netcfg_status__" "SKILL.md §3.23 missing netcfg sentinel"
check skills/sec-audit/SKILL.md "sing-box check\|xray test" "SKILL.md §3.23 missing sing-box check / xray test"
check skills/sec-audit/SKILL.md "no-singbox-config\|no-xray-config" "SKILL.md §3.23 missing target-shape skip reasons"
echo "netcfg-orchestrator: SKILL.md §3.23 documents netcfg-runner wire-up"

# --- netcfg fixture-match sanity: synthetic torrc + WG conf + sing-box JSON + xray JSON
tmp_nc=$(mktemp -d); trap 'rm -rf "$tmp_nc"' EXIT
cat > "$tmp_nc/torrc" <<'TORRC'
ControlPort 9051
HiddenServiceDir /var/lib/tor/x/
TORRC
cat > "$tmp_nc/wg0.conf" <<'WG'
[Interface]
PrivateKey = ABC=
ListenPort = 51820
[Peer]
PublicKey = DEF=
AllowedIPs = 10.0.0.2/32
WG
cat > "$tmp_nc/sb.json" <<'JSON'
{"inbounds":[{"type":"vless","listen":"::"}],"outbounds":[{"type":"direct"}]}
JSON
cat > "$tmp_nc/xr.json" <<'JSON'
{"inbounds":[{"protocol":"vmess","port":443}],"outbounds":[{"protocol":"freedom"}]}
JSON
if ! grep -q '^ControlPort' "$tmp_nc/torrc"; then
    echo "netcfg-inventory: FAIL — fixture torrc malformed" >&2; fail=1
fi
if ! grep -q '\[Interface\]' "$tmp_nc/wg0.conf"; then
    echo "netcfg-inventory: FAIL — fixture wg0.conf malformed" >&2; fail=1
fi
echo "netcfg-inventory: synthetic torrc + WG + sing-box + xray fixture matches §2 detection rule"

# --- Negative tests for netcfg origin
bad_nc_notool='{"id":"X","severity":"MEDIUM","cwe":null,"title":"t","file":"a.json","line":1,"evidence":"e","reference":"netcfg-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"netcfg"}'
if echo "$bad_nc_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "netcfg" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed netcfg line (missing tool) was accepted" >&2
    exit 1
fi
echo "netcfg negative-test: malformed netcfg line (missing tool) correctly rejected"

bad_nc_crosstag='{"id":"X","severity":"MEDIUM","cwe":null,"title":"t","file":"a.json","line":1,"evidence":"e","reference":"netcfg-tools.md","reference_url":null,"fix_recipe":null,"confidence":"medium","origin":"netcfg","tool":"shellcheck"}'
if echo "$bad_nc_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "netcfg" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "pip-audit", "ruff", "ansible-lint"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: netcfg finding with non-netcfg tool was accepted" >&2
    exit 1
fi
echo "netcfg negative-test: origin-tag isolation enforced (netcfg cannot carry the other 18 lanes' tools)"

bad_nc_skipped='{"__netcfg_status__":"unavailable","tools":[],"skipped":[{"oops":"shape"}]}'
if echo "$bad_nc_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__netcfg_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed netcfg skipped entry was accepted" >&2
    exit 1
fi
echo "netcfg negative-test: malformed skipped-list entry correctly rejected"

# --- image inventory + §3.24 (v1.11.0):
check skills/sec-audit/SKILL.md "Image artifact signals" "SKILL.md §2 missing image detection"
check skills/sec-audit/SKILL.md "\"image\"" "SKILL.md §2 inventory JSON missing image key"
check skills/sec-audit/SKILL.md "### 3.24 Image vulnerability pass" "SKILL.md missing §3.24"
check skills/sec-audit/SKILL.md "image-runner" "SKILL.md §3.24 missing image-runner"
check skills/sec-audit/SKILL.md "__image_status__" "SKILL.md §3.24 missing image sentinel"
check skills/sec-audit/SKILL.md "trivy\|grype" "SKILL.md §3.24 missing trivy/grype"
check skills/sec-audit/SKILL.md "no-image-artifact" "SKILL.md §3.24 missing no-image-artifact clean-skip reason"
check skills/sec-audit/SKILL.md "Docker Scout" "SKILL.md §3.24 missing Docker Scout positioning"
echo "image-orchestrator: SKILL.md §3.24 documents image-runner wire-up"

# --- image fixture-match sanity: synthetic SBOM + image tarball reference
tmp_im=$(mktemp -d); trap 'rm -rf "$tmp_im"' EXIT
cat > "$tmp_im/myapp.spdx.json" <<'JSON'
{"spdxVersion":"SPDX-2.3","name":"myapp","packages":[{"name":"requests","versionInfo":"2.20.0"}]}
JSON
if ! grep -q '"spdxVersion"' "$tmp_im/myapp.spdx.json"; then
    echo "image-inventory: FAIL — fixture SBOM malformed" >&2; fail=1
fi
echo "image-inventory: synthetic SPDX SBOM fixture matches §2 detection rule"

# --- Negative tests for image origin
bad_im_notool='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"a.tar","line":0,"evidence":"e","reference":"image-tools.md","reference_url":null,"fix_recipe":null,"confidence":"high","origin":"image"}'
if echo "$bad_im_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "image" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed image line (missing tool) was accepted" >&2
    exit 1
fi
echo "image negative-test: malformed image line (missing tool) correctly rejected"

bad_im_crosstag='{"id":"X","severity":"HIGH","cwe":null,"title":"t","file":"a.tar","line":0,"evidence":"e","reference":"image-tools.md","reference_url":null,"fix_recipe":null,"confidence":"high","origin":"image","tool":"shellcheck"}'
if echo "$bad_im_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "image" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "pip-audit", "ruff", "ansible-lint", "sing-box", "xray"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: image finding with non-image tool was accepted" >&2
    exit 1
fi
echo "image negative-test: origin-tag isolation enforced (image cannot carry the other 19 lanes' tools)"

bad_im_skipped='{"__image_status__":"unavailable","tools":[],"skipped":[{"oops":"shape"}]}'
if echo "$bad_im_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__image_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed image skipped entry was accepted" >&2
    exit 1
fi
echo "image negative-test: malformed skipped-list entry correctly rejected"

# --- ai-tools inventory + §3.25 (v1.12.0; v1.13 adds mcp-scan):
check skills/sec-audit/SKILL.md "AI-tools signals" "SKILL.md §2 missing ai-tools detection"
check skills/sec-audit/SKILL.md "\"ai-tools\"" "SKILL.md §2 inventory JSON missing ai-tools key"
check skills/sec-audit/SKILL.md "### 3.25 AI-tools pass" "SKILL.md missing §3.25"
check skills/sec-audit/SKILL.md "ai-tools-runner" "SKILL.md §3.25 missing ai-tools-runner"
check skills/sec-audit/SKILL.md "__ai_tools_status__" "SKILL.md §3.25 missing ai-tools sentinel"
check skills/sec-audit/SKILL.md "no-ai-tool-config" "SKILL.md §3.25 missing no-ai-tool-config clean-skip reason"
echo "ai-tools-orchestrator: SKILL.md §3.25 documents ai-tools-runner wire-up"

# --- ai-tools mcp-scan integration (v1.13.0):
check agents/ai-tools-runner.md "mcp-scan" "ai-tools-runner.md missing mcp-scan integration"
check agents/ai-tools-runner.md "snyk-agent-scan" "ai-tools-runner.md missing snyk-agent-scan fallback probe"
check agents/ai-tools-runner.md "inspect" "ai-tools-runner.md missing 'inspect' (static-only) mode"
check skills/sec-audit/references/ai-tools-tools.md "mcp-scan" "ai-tools-tools.md missing mcp-scan canonical invocation"
check skills/sec-audit/references/ai-tools-tools.md "parse-failed" "ai-tools-tools.md missing parse-failed skip vocab"
echo "ai-tools-mcp-scan: agents/ai-tools-runner.md + references/ai-tools-tools.md document mcp-scan inspect mode"

# --- ai-tools fixture-match sanity: synthetic plugin.json + .mcp.json reference
tmp_at=$(mktemp -d); trap 'rm -rf "$tmp_at"' EXIT
mkdir -p "$tmp_at/.claude-plugin"
cat > "$tmp_at/.claude-plugin/plugin.json" <<'JSON'
{"name":"demo","version":"0.1.0","description":"demo plugin"}
JSON
cat > "$tmp_at/.mcp.json" <<'JSON'
{"mcpServers":{"foo":{"command":"npx","args":["-y","@modelcontextprotocol/server-foo"]}}}
JSON
if ! [ -f "$tmp_at/.claude-plugin/plugin.json" ] || ! [ -f "$tmp_at/.mcp.json" ]; then
    echo "ai-tools-inventory: FAIL — fixture missing" >&2; fail=1
fi
echo "ai-tools-inventory: synthetic plugin.json + .mcp.json fixture matches §2 detection rule"

# --- Negative tests for ai-tools origin
bad_at_notool='{"id":"X","severity":"MEDIUM","cwe":"CWE-1284","title":"t","file":"plugin.json","line":1,"evidence":"e","reference":"ai-tools-tools.md","reference_url":null,"fix_recipe":null,"confidence":"high","origin":"ai-tools"}'
if echo "$bad_at_notool" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "ai-tools" and "tool" not in obj:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed ai-tools line (missing tool) was accepted" >&2
    exit 1
fi
echo "ai-tools negative-test: malformed ai-tools line (missing tool) correctly rejected"

bad_at_crosstag='{"id":"X","severity":"MEDIUM","cwe":"CWE-1284","title":"t","file":"plugin.json","line":1,"evidence":"e","reference":"ai-tools-tools.md","reference_url":null,"fix_recipe":null,"confidence":"high","origin":"ai-tools","tool":"shellcheck"}'
if echo "$bad_at_crosstag" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if obj.get("origin") == "ai-tools" and obj.get("tool") in {"semgrep", "bandit", "zap-baseline", "addons-linter", "web-ext", "retire", "cargo-audit", "cargo-deny", "cargo-geiger", "cargo-vet", "mobsfscan", "apkleaks", "android-lint", "codesign", "spctl", "notarytool", "pkgutil", "stapler", "systemd-analyze", "lintian", "checksec", "binskim", "osslsigncode", "sigcheck", "kube-score", "kubesec", "tfsec", "checkov", "actionlint", "zizmor", "hadolint", "virt-xml-validate", "gosec", "staticcheck", "shellcheck", "pip-audit", "ruff", "ansible-lint", "sing-box", "xray", "trivy", "grype"}:
        errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: ai-tools finding with non-ai-tools tool was accepted" >&2
    exit 1
fi
echo "ai-tools negative-test: origin-tag isolation enforced (ai-tools cannot carry the other 20 lanes' tools)"

bad_at_skipped='{"__ai_tools_status__":"unavailable","tools":[],"skipped":[{"oops":"shape"}]}'
if echo "$bad_at_skipped" | python3 -c '
import json, sys
errs = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    obj = json.loads(line)
    if "__ai_tools_status__" in obj:
        for e in obj.get("skipped", []):
            if not (isinstance(e, dict) and "tool" in e and "reason" in e):
                errs += 1
sys.exit(1 if errs else 0)
' >/dev/null 2>&1; then
    echo "contract-check: FAIL — negative test: malformed ai-tools skipped entry was accepted" >&2
    exit 1
fi
echo "ai-tools negative-test: malformed skipped-list entry correctly rejected"

# --- v1.10 default-cwd UX (commands/sec-audit.md):
check commands/sec-audit.md "Default-target behaviour" "commands/sec-audit.md missing v1.10 default-target section"
check commands/sec-audit.md "current working directory" "commands/sec-audit.md missing default-to-cwd rule"
check commands/sec-audit.md "Reviewing \`\$PWD\`\|Reviewing.*\$PWD" "commands/sec-audit.md missing canonical cwd-confirmation line"
echo "v1.10-default-cwd: commands/sec-audit.md documents the default-to-cwd rule"

# --- v1.10 default-cwd UX (skill SKILL.md §1):
check skills/sec-audit/SKILL.md "Default-to-cwd (v1.10.0+)\|Default-to-cwd" "SKILL.md §1 missing v1.10 default-to-cwd bullet"
check skills/sec-audit/SKILL.md "Default behaviour (v1.10.0+)\|when invoked without a positional path argument" "SKILL.md Inputs missing v1.10 default-to-cwd doc"
echo "v1.10-default-cwd: SKILL.md §1 documents the default-to-cwd contract"

# --- v1.10 uncovered-tech detection registry:
check skills/sec-audit/references/uncovered-tech-fingerprints.md "^## Detection entries" "uncovered-tech-fingerprints.md missing Detection entries section"
check skills/sec-audit/references/uncovered-tech-fingerprints.md "suggested_lane:.*\`java\`" "uncovered-tech-fingerprints.md missing Java entry"
check skills/sec-audit/references/uncovered-tech-fingerprints.md "suggested_lane:.*\`cpp\`" "uncovered-tech-fingerprints.md missing C/C++ entry"
check skills/sec-audit/references/uncovered-tech-fingerprints.md "suggested_lane:.*\`solidity\`" "uncovered-tech-fingerprints.md missing Solidity entry"
check skills/sec-audit/references/uncovered-tech-fingerprints.md "suggested_lane:.*\`php\`" "uncovered-tech-fingerprints.md missing PHP entry"
check skills/sec-audit/references/uncovered-tech-fingerprints.md "spotbugs\|find-sec-bugs" "uncovered-tech-fingerprints.md missing Java tooling"
echo "v1.10-uncovered-tech: references/uncovered-tech-fingerprints.md catalogues 16 known-but-uncovered technologies"

# --- v1.10 SKILL.md §2 uncovered-tech subsection:
check skills/sec-audit/SKILL.md "Uncovered-technology detection (v1.10.0+)" "SKILL.md §2 missing uncovered-tech detection subsection"
check skills/sec-audit/SKILL.md "uncovered_tech" "SKILL.md §2 missing uncovered_tech array reference"
check skills/sec-audit/SKILL.md "uncovered-tech-fingerprints.md" "SKILL.md §2 missing fingerprint registry pointer"
echo "v1.10-uncovered-tech: SKILL.md §2 documents uncovered-technology detection"

# --- v1.10 report-writer Step 5.5 wire-up:
check agents/report-writer.md "### Step 5.5 — Emit Coverage-gap suggestions" "report-writer missing Step 5.5"
check agents/report-writer.md "Coverage-gap suggestions" "report-writer missing Coverage-gap section template"
check agents/report-writer.md "uncovered_tech" "report-writer missing uncovered_tech array reference"
check agents/report-writer.md "OMIT the entire section" "report-writer missing empty-array omission rule"
echo "v1.10-report-writer: agents/report-writer.md renders Coverage-gap suggestions section"

# --- v1.10 negative test: empty uncovered_tech array MUST suppress the section.
# The report-writer rule is "render only when non-empty"; the contract check
# verifies the agent spec carries that rule.
if ! grep -q "OMIT the entire section\|omit.*entire section\|do not render an empty" agents/report-writer.md; then
    echo "contract-check: FAIL — report-writer Step 5.5 missing empty-array omission rule" >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "contract-check: FAIL" >&2
    exit 1
fi
echo "contract-check: OK"
