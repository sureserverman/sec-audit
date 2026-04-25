# iac-tools

<!--
    Tool-lane reference for sec-review's IaC lane (v1.2.0+). Consumed
    by the `iac-runner` sub-agent. Documents tfsec + checkov.
-->

## Source

- https://github.com/aquasecurity/tfsec — tfsec canonical (Terraform-focused static scanner)
- https://github.com/bridgecrewio/checkov — checkov canonical (multi-IaC scanner)
- https://developer.hashicorp.com/terraform/language
- https://www.pulumi.com/docs/iac/concepts/
- https://cwe.mitre.org/

## Scope

In-scope: the two tools invoked by `iac-runner` — `tfsec` (Go binary,
Terraform-specific) and `checkov` (Python, multi-IaC). Both
cross-platform. Out of scope: terrascan (alternative tool — use
checkov instead); cloud-provider-live audits (Prowler, ScoutSuite);
Pulumi deep linting (limited tool support; `checkov` covers common
Pulumi cases).

## Canonical invocations

### tfsec

- Install: `brew install tfsec` OR `go install github.com/aquasecurity/tfsec/cmd/tfsec@latest` OR docker.
- Invocation:
  ```bash
  tfsec --format json --out "$TMPDIR/iac-runner-tfsec.json" "$target_path" \
      2> "$TMPDIR/iac-runner-tfsec.stderr"
  rc_tf=$?
  ```
- Output: JSON with `results[]` array. Each result has `rule_id`,
  `severity` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), `description`,
  `impact`, `resolution`, `location.filename`, `location.start_line`,
  `link` (upstream rule doc URL).
- Primary source: https://github.com/aquasecurity/tfsec

Source: https://github.com/aquasecurity/tfsec

### checkov

- Install: `pip install checkov`.
- Invocation:
  ```bash
  checkov --directory "$target_path" --output json \
      --framework terraform,pulumi,kubernetes,cloudformation,arm,bicep \
      > "$TMPDIR/iac-runner-checkov.json" \
      2> "$TMPDIR/iac-runner-checkov.stderr"
  rc_ch=$?
  ```
  For the IaC lane we pass `--framework terraform,pulumi` only;
  the broader `kubernetes`/`cloudformation`/`arm`/`bicep` frameworks
  are covered by sec-expert + future lanes.
- Output: JSON with top-level `results.failed_checks[]`. Each has
  `check_id`, `check_name`, `severity`, `file_path`, `file_line_range`,
  `resource`, `guideline` (upstream rule doc URL).
- Tool behaviour: exit non-zero when any check fails. NOT a crash —
  parse JSON regardless.
- Primary source: https://github.com/bridgecrewio/checkov

Source: https://github.com/bridgecrewio/checkov

## Output-field mapping

Every finding carries `origin: "iac"`, `tool: "tfsec" | "checkov"`,
`reference: "iac-tools.md"`.

### tfsec → sec-review finding

| upstream                                   | sec-review field             |
|--------------------------------------------|------------------------------|
| `"tfsec:" + .rule_id`                      | `id`                         |
| `.severity` (CRITICAL/HIGH/MEDIUM/LOW) verbatim | `severity`              |
| Per-rule CWE table — tfsec emits AVD-* IDs; map via the rule short-name to known CWEs: AWS S3 public (CWE-732), IAM wildcard (CWE-732), unencrypted storage (CWE-311), open security group (CWE-284), hardcoded secrets (CWE-798). Unmapped → null. | `cwe` |
| `.description`                             | `title`                      |
| `.location.filename` relative to target    | `file`                       |
| `.location.start_line`                     | `line`                       |
| `.impact`                                  | `evidence`                   |
| `.link` (if present)                       | `reference_url`              |
| `.resolution`                              | `fix_recipe`                 |
| `"high"`                                   | `confidence`                 |

### checkov → sec-review finding

| upstream                                     | sec-review field             |
|----------------------------------------------|------------------------------|
| `"checkov:" + .check_id`                     | `id`                         |
| `.severity` remap: `CRITICAL`/`HIGH` → HIGH, `MEDIUM` → MEDIUM, `LOW`/`INFO` → LOW; null → MEDIUM default | `severity` |
| CWE from Checkov policy category — `GENERAL_SECURITY`, `LOGGING`, `IAM`, `SECRETS`, `ENCRYPTION` map to CWE-732, CWE-532, CWE-732, CWE-798, CWE-311 respectively. Unmapped → null. | `cwe` |
| `.check_name`                                | `title`                      |
| `.file_path` (trim leading `/`)              | `file`                       |
| `.file_line_range[0]`                        | `line`                       |
| `.resource` + ": " + `.check_name`           | `evidence`                   |
| `.guideline`                                 | `reference_url`              |
| null (checkov doesn't ship fix recipes inline) | `fix_recipe`               |
| `"high"`                                     | `confidence`                 |

## Degrade rules

`__iac_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}. Only
`tool-missing` applies — both tools are cross-platform source-tree
scanners with no host-OS gates.

## Version pins

- `tfsec` ≥ 1.28 (stable JSON schema). Pinned 2026-04.
- `checkov` ≥ 3.0 (stable JSON output + Pulumi framework). Pinned 2026-04.
