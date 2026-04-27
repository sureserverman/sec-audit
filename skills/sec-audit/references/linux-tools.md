# linux-tools

<!--
    Tool-lane reference for sec-audit's Linux desktop lane (v0.10.0+).
    Consumed by the `linux-runner` sub-agent. Documents canonical
    invocations, upstream output → sec-expert finding-schema maps, and
    the three-state-plus-skipped-list sentinel contract for three
    Linux desktop static-analysis CLIs.
-->

## Source

- https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html — canonical `systemd-analyze security` reference
- https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html — unit hardening directives scored by `systemd-analyze security`
- https://lintian.debian.org/manual/ — Lintian manual (tag severities, JSON output format)
- https://man7.org/linux/man-pages/man7/capabilities.7.html — capabilities reference (CWE-269 mapping)
- https://cwe.mitre.org/ — CWE dictionary

## Scope

In-scope: the three tools invoked by `linux-runner` (the Linux desktop
lane sub-agent added in v0.10.0) — `systemd-analyze security`,
`lintian`, and `checksec`. Out of scope: live-system audit tools
(lynis, debsecan — out of scope for v0.10 because they target a
live host, not a source tree); packaging-format linters beyond
Debian/RPM; kernel module review.

Each tool has asymmetric applicability: `systemd-analyze security`
requires a systemd host; `lintian` requires `debian/` source; `checksec`
requires an ELF binary artifact. The runner clean-skips per-tool when
preconditions are unmet, extending the skipped-list primitive
introduced in v0.8 and elaborated in v0.9.

## Canonical invocations

### systemd-analyze security

- Install: bundled with systemd (every systemd host has it). macOS /
  Windows / Alpine-musl-without-systemd hosts CANNOT run it — the
  runner clean-skips with `reason: "requires-systemd-host"`.
- Invocation (offline mode, systemd ≥ 252):
  ```bash
  systemd-analyze security \
      --offline=true \
      --profile=strict \
      "$path_to_unit.service" \
      > "$TMPDIR/linux-runner-systemd-analyze.txt" \
      2> "$TMPDIR/linux-runner-systemd-analyze.stderr"
  rc_sa=$?
  ```
- Output: human-readable text with an overall score (0-10, higher is
  worse), a per-directive table, and a final verdict line. Parse the
  per-directive lines with regex — each line is of the form
  `✗ <Directive>=<value>            <reason>  <impact>` (UTF-8 bullet).
- Primary source:
  https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html

Source: https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html

### lintian

- Install: `apt install lintian` on Debian/Ubuntu; `brew install lintian`
  on macOS. Perl-based — not pip-installable.
- Invocation (JSON output, Lintian ≥ 2.117):
  ```bash
  lintian --output-format=json \
      "$path_to_debian_source_dir" \
      > "$TMPDIR/linux-runner-lintian.json" \
      2> "$TMPDIR/linux-runner-lintian.stderr"
  rc_li=$?
  ```
  Fallback for Lintian < 2.117 (tagged-text format): `--output-format=letterqualified`.
- Output (JSON): a top-level array of tag objects, each with
  `severity` (`error`|`warning`|`info`|`pedantic`|`experimental`|`classification`),
  `tag`, `context`, `visibility`, `type`, `package`. Parse with jq.
- Tool behaviour: non-zero exit when tags are found; this is NOT a
  crash. The runner treats any exit with a valid JSON file as success.
- Primary source: https://lintian.debian.org/manual/

Source: https://lintian.debian.org/manual/

### checksec

- Install: `pip install checksec-py` (cross-platform) OR `apt install
  checksec` (Debian/Ubuntu) OR `brew install checksec` (macOS).
- Invocation (JSON output):
  ```bash
  checksec --file="$path_to_elf" --output=json \
      > "$TMPDIR/linux-runner-checksec.json" \
      2> "$TMPDIR/linux-runner-checksec.stderr"
  rc_ck=$?
  ```
- Output (JSON): one top-level object keyed by binary path, with
  boolean/string values for `relro`, `canary`, `nx`, `pie`, `rpath`,
  `runpath`, `symbols`, `fortify_source`, `fortified`, `fortify-able`.
- Primary source: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
  (for cross-ref on hardening-flag rationale) — the tool itself
  docs are upstream at github but the hardening concepts cite the
  systemd.exec man page and CWE references.

Source: https://cwe.mitre.org/

## Output-field mapping

Every finding produced by `linux-runner` carries:

- `origin: "linux"`
- `tool: "systemd-analyze" | "lintian" | "checksec"`
- `reference: "linux-tools.md"`

### systemd-analyze → sec-audit finding

| upstream (per-directive row)            | sec-audit field                 |
|-----------------------------------------|----------------------------------|
| `"systemd-analyze:" + directive-name`   | `id`                             |
| impact-column → `HIGH`/`MEDIUM`/`LOW` map: "exposure ≥ 3.0" → HIGH, "2.0–3.0" → MEDIUM, "< 2.0" → LOW; overall score 9-10 → any individual directive emits HIGH | `severity` |
| CWE-693 default for `"unsafe"` rows; CWE-250 for `NoNewPrivileges=false` / `User=root` / privilege-related; CWE-269 for capabilities; per-directive table documented in `linux-systemd.md` | `cwe` |
| "Unit <name> is <status>" verbatim      | `title`                          |
| unit-file basename                      | `file`                           |
| 0                                       | `line`                           |
| the directive line verbatim             | `evidence`                       |
| `linux-tools.md`                        | `reference`                      |
| null                                    | `reference_url`                  |
| synthesised from `linux-systemd.md` fix recipe for the offending directive | `fix_recipe` |
| `"medium"`                              | `confidence`                     |

### lintian → sec-audit finding

| Lintian JSON field                      | sec-audit field                 |
|-----------------------------------------|----------------------------------|
| `"lintian:" + tag`                      | `id`                             |
| severity remap: `error` → HIGH, `warning` → MEDIUM, `info` → LOW, `pedantic`/`experimental` → LOW, `classification` → INFO | `severity` |
| per-tag CWE map — the runner maintains an explicit table (see `linux-packaging.md`): `setuid-binary` → CWE-250, `missing-homepage-field` → null (hygiene, not security), `maintainer-script-without-set-e` → CWE-390, `non-standard-file-perm` → CWE-732, `shell-script-fails-syntax-check` → CWE-1176. Unknown tag → null — do NOT invent | `cwe` |
| `context` (or `tag` when context empty) | `title`                          |
| `"debian/" + (visibility field or "control")` | `file`                     |
| 0                                       | `line`                           |
| `context` verbatim                      | `evidence`                       |
| `linux-tools.md`                        | `reference`                      |
| `"https://lintian.debian.org/tags/" + tag + ".html"` | `reference_url`     |
| synthesised from the matching `linux-packaging.md` recipe, or null | `fix_recipe` |
| `"high"` (Lintian matches are deterministic tag hits) | `confidence`      |

### checksec → sec-audit finding

| checksec JSON field                     | sec-audit field                 |
|-----------------------------------------|----------------------------------|
| `"checksec:" + property`                | `id`                             |
| severity: missing `relro=full` / `nx=yes` / `pie=yes` → MEDIUM; missing `canary=yes` → MEDIUM; insecure `rpath` / `runpath` present → HIGH; all others → LOW | `severity` |
| CWE-693 Protection Mechanism Failure for missing hardening flags; CWE-426 Untrusted Search Path for `rpath`/`runpath`; CWE-121 Stack-based Buffer Overflow as secondary for missing canary | `cwe` |
| `"<property> is <value>"` (e.g. `"relro is no"`) | `title`                 |
| binary basename                         | `file`                           |
| 0                                       | `line`                           |
| the property + value verbatim           | `evidence`                       |
| null                                    | `reference_url`                  |
| `"Rebuild with -Wl,-z,relro -Wl,-z,now"` / per-property recipe | `fix_recipe` |
| `"high"` (ELF flag checks are deterministic) | `confidence`                |

## Degrade rules

The `linux-runner` agent follows the three-state sentinel contract
consistent with the other lanes. `__linux_status__` ∈
{`"ok"`, `"partial"`, `"unavailable"`}. The `skipped` list (introduced
in v0.8, extended in v0.9) now recognises six reasons, five of them
Linux-lane-specific:

- `"requires-systemd-host"` — `systemd-analyze security` requires a
  systemd host. macOS/Windows/Alpine-without-systemd runners clean-
  skip. Parallel to `requires-macos-host` from v0.9. NEW in v0.10.
- `"no-debian-source"` — `lintian` needs a `debian/` source dir under
  the target. Projects without Debian packaging metadata clean-skip.
  NEW in v0.10.
- `"no-elf"` — `checksec` needs an ELF binary under the target.
  Source-only reviews without a pre-built binary clean-skip. NEW in
  v0.10.
- `"tool-missing"` — the binary is absent AND its host/target
  preconditions were satisfied (e.g. lintian missing on Debian with
  `debian/control` present).
- `"no-bundle"` / `"no-apk"` / `"requires-macos-host"` /
  `"no-notary-profile"` — inherited from v0.8–v0.9; not used by the
  Linux lane but documented here for cross-lane consistency.

Canonical status-line shapes for the Linux lane:

```json
{"__linux_status__": "ok", "tools": ["systemd-analyze","lintian"], "runs": 2, "findings": 7, "skipped": [{"tool": "checksec", "reason": "no-elf"}]}
```

```json
{"__linux_status__": "unavailable", "tools": [], "skipped": [{"tool": "systemd-analyze", "reason": "requires-systemd-host"}, {"tool": "lintian", "reason": "tool-missing"}, {"tool": "checksec", "reason": "no-elf"}]}
```

Every skipped entry is a `{tool, reason}` object. The structured
schema is validated by `tests/contract-check.sh`.

## Version pins

- `systemd` ≥ 252 (offline scoring mode for `systemd-analyze security
  --offline=true` was added in 252). Pinned 2026-04.
- `lintian` ≥ 2.117 (`--output-format=json`). Pinned 2026-04.
- `checksec-py` ≥ 2.5 OR `checksec` (bash) ≥ 2.5 (`--output=json`
  support). Pinned 2026-04.

## Common false positives

- **systemd-analyze** scores short-running timer-triggered jobs as
  "unsafe" when they legitimately need `User=root` for setup; flag
  with `confidence: "low"` and note that operator judgment is required.
- **lintian** `pedantic`/`experimental` tags are often noise — the
  mapping above down-grades them to LOW; review recommends filtering
  out `pedantic` entirely for CI gates.
- **checksec** `runpath` findings in container images are common and
  not always exploitable; pair with the `containers/` reference pack
  for context.

## CI notes

The runner writes all outputs to `$TMPDIR`. When gradle-wrapper or
any build tool would be tempted, the runner refuses — build-time
action is out of scope. Cross-reference with `linux-systemd.md`,
`linux-sandboxing.md`, and `linux-packaging.md` for pattern-level
guidance beyond tool-produced findings.
