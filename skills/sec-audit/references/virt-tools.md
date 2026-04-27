# virt-tools

<!--
    Tool-lane reference for sec-audit's virt lane (v1.4.0+).
    Consumed by the `virt-runner` sub-agent. Documents
    hadolint + virt-xml-validate.
-->

## Source

- https://github.com/hadolint/hadolint — hadolint canonical (Haskell binary; Dockerfile/Containerfile static linter)
- https://github.com/hadolint/hadolint/wiki — hadolint rule reference (`DLxxxx` rule IDs and remediation pointers)
- https://libvirt.org/manpages/virt-xml-validate.html — virt-xml-validate(1) man page (canonical)
- https://libvirt.org/format.html — libvirt XML schema index (the schemas virt-xml-validate validates against)
- https://cwe.mitre.org/

## Scope

In-scope: the two tools invoked by `virt-runner` — `hadolint` (Haskell binary; static linter for `Dockerfile` / `Containerfile` syntax + best-practice rules, with `DLxxxx` rule IDs) and `virt-xml-validate` (libvirt-clients package; XSD validator that checks libvirt domain/network/storage XML against the libvirt-shipped schemas). Both cross-platform; no host-OS gate. Out of scope: container-image scanning (image content scanners like trivy/grype are out of this lane's source-only scope); UTM `config.plist` validation (no first-party scanner exists — sec-expert handles via reference pack); Apple Containers `container.yaml` validation (schema is pre-1.0 and evolving — sec-expert handles).

## Canonical invocations

### hadolint

- Install: `brew install hadolint` OR `docker pull hadolint/hadolint` OR pre-built binaries from GitHub Releases (Linux/macOS amd64+arm64).
- Invocation:
  ```bash
  hadolint --format json \
      $(find "$target_path" -type f \
          \( -iname 'Dockerfile' -o -iname 'Dockerfile.*' \
             -o -iname '*.dockerfile' -o -iname 'Containerfile' \
             -o -iname '*.containerfile' \) -print) \
      > "$TMPDIR/virt-runner-hadolint.json" \
      2> "$TMPDIR/virt-runner-hadolint.stderr"
  rc_hl=$?
  ```
  hadolint accepts a list of files; passing the find-result keeps it deterministic and respects target_path scoping.
- Output: JSON array. Each element has `file`, `line`, `column`, `level`
  (`error` / `warning` / `info` / `style`), `code` (rule id, e.g.
  `DL3002`, `DL3008`, `DL4006`, `SC2086` for embedded shellcheck),
  `message`. The `code` carries the upstream rule URL fragment.
- Tool behaviour: exits non-zero when any lint fires. NOT a crash —
  parse JSON regardless. Empty target file list yields `[]` with
  exit 0.
- Primary source: https://github.com/hadolint/hadolint

Source: https://github.com/hadolint/hadolint

### virt-xml-validate

- Install: `apt install libvirt-clients` (Debian/Ubuntu) / `dnf install libvirt-client` (Fedora/RHEL) / `brew install libvirt` (macOS, ships the validator). Cross-platform; the validator is XSD-only and does NOT require a running libvirtd.
- Invocation (per-file loop, since virt-xml-validate accepts one path
  per call and returns a one-line verdict):
  ```bash
  while IFS= read -r f; do
      out=$( virt-xml-validate "$f" 2>&1 )
      rc=$?
      printf '%s\t%d\t%s\n' "$f" "$rc" "$out" \
          >> "$TMPDIR/virt-runner-virtxml.tsv"
  done < <(find "$target_path" -type f -name '*.xml' \
              -exec grep -l '<domain\b\|<network\b\|<pool\b\|<volume\b' {} +)
  rc_vx=0
  ```
  The `find` step pre-filters XML files that look like libvirt
  artefacts (presence of a libvirt root element); files without
  one are not validated and not counted as "skipped".
- Output: TSV (file, rc, message). `rc=0` with message
  `<file> validates` indicates the file passed; non-zero with a
  parser/validator error indicates a finding. The runner converts
  each non-passing line into one finding.
- Tool behaviour: validator exits 0 on success, non-zero on any
  schema violation. The error text carries the line number and a
  short description (e.g. `Relax-NG validity error : Element
  domain failed to validate content`).
- Primary source: https://libvirt.org/manpages/virt-xml-validate.html

Source: https://libvirt.org/manpages/virt-xml-validate.html

## Output-field mapping

Every finding carries `origin: "virt"`,
`tool: "hadolint" | "virt-xml-validate"`, `reference: "virt-tools.md"`.

### hadolint → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"hadolint:" + .code`                                 | `id`                         |
| `.level` remap: `error` → HIGH, `warning` → MEDIUM, `info` → LOW, `style` → LOW | `severity` |
| Per-rule CWE table — `DL3002` (root user) → CWE-250, `DL3004` (sudo) → CWE-269, `DL3007` (latest tag) → CWE-829, `DL3020`/`DL3021` (ADD/COPY misuse) → CWE-22, `DL3025` (JSON form CMD) → null (style), `DL4006` (set -o pipefail) → CWE-754, `SC2086` (unquoted variable) → CWE-78, `SC2046` (unquoted command substitution) → CWE-78, all others → null | `cwe` |
| `.message`                                            | `title`                      |
| `.file`                                               | `file`                       |
| `.line`                                               | `line`                       |
| `.message` (snippet truncated to 200 chars)           | `evidence`                   |
| `https://github.com/hadolint/hadolint/wiki/` + code   | `reference_url`              |
| null (hadolint does not ship inline fix recipes)      | `fix_recipe`                 |
| `"high"`                                              | `confidence`                 |

### virt-xml-validate → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"virt-xml:invalid"` (validator has no rule IDs)      | `id`                         |
| `MEDIUM` (XSD violations indicate libvirt will refuse to define the domain — operationally important, not a security vulnerability per se) | `severity` |
| `CWE-1284` (Improper Validation of Specified Quantity in Input) — the only CWE that fits a generic schema-violation class | `cwe` |
| Validator's error message (truncated to 200 chars)    | `title`                      |
| The .xml file path (column 0 of the TSV)              | `file`                       |
| Line number extracted from the validator message (regex `line\s+(\d+)`); 0 if absent | `line` |
| Validator message verbatim                            | `evidence`                   |
| `https://libvirt.org/format.html`                     | `reference_url`              |
| null                                                  | `fix_recipe`                 |
| `"high"` (validator is deterministic — no FP)         | `confidence`                 |

## Degrade rules

`__virt_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary (v1.4.0):

- `tool-missing` — the tool's binary is absent from PATH.
- `no-containerfile` — hadolint is on PATH but the target tree
  contains no Dockerfile / Containerfile / `*.dockerfile` /
  `*.containerfile` files. Target-shape clean-skip; parallel to the
  v0.10 `no-debian-source`, v0.10 `no-elf`, v0.11 `no-pkg`, v0.12
  `no-pe` reasons.
- `no-libvirt-xml` — virt-xml-validate is on PATH but the target
  tree contains no XML files with a libvirt root element
  (`<domain>` / `<network>` / `<pool>` / `<volume>`).
  Target-shape clean-skip; parallel to the above target-shape
  primitives.

No host-OS gate — both tools are cross-platform with no
`requires-<host>-host` precondition.

## Version pins

- `hadolint` ≥ 2.12 (stable JSON schema; `level`/`code`/`message`
  vocabulary fixed; embedded shellcheck SC-rule pass-through).
  Pinned 2026-04.
- `virt-xml-validate` ≥ libvirt 9.0 (XSD coverage of `<launchSecurity>`,
  `<tpm>`, virtiofs `<filesystem>` driver). Pinned 2026-04.
