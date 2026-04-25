# gh-actions-tools

<!--
    Tool-lane reference for sec-review's GitHub Actions lane (v1.3.0+).
    Consumed by the `gh-actions-runner` sub-agent. Documents
    actionlint + zizmor.
-->

## Source

- https://github.com/rhysd/actionlint — actionlint canonical (Go binary; static linter for GitHub Actions workflow YAML)
- https://github.com/woodruffw/zizmor — zizmor canonical (Python; security-focused auditor for GitHub Actions)
- https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- https://cwe.mitre.org/

## Scope

In-scope: the two tools invoked by `gh-actions-runner` — `actionlint`
(Go binary, broad lint coverage including a `shellcheck`-backed
script-injection check) and `zizmor` (Python, narrower focus on
security audits: pinning, permissions, template-injection,
artifact-poisoning). Both cross-platform, no host-OS gate. Out of
scope: GitHub-API-driven repo audits (`gh-actions-runner` is
source-only); private-action source review (composite-action
authoring is a different lane); Dependabot config validation.

## Canonical invocations

### actionlint

- Install: `go install github.com/rhysd/actionlint/cmd/actionlint@latest` OR `brew install actionlint` OR docker `rhysd/actionlint`.
- Invocation:
  ```bash
  actionlint -format '{{json .}}' > "$TMPDIR/gh-actions-runner-actionlint.json" \
      2> "$TMPDIR/gh-actions-runner-actionlint.stderr"
  rc_al=$?
  ```
  Run with the workflow directory as cwd, OR pass `<target>/.github/workflows/`.
- Output: JSON array. Each element has `message`, `filepath`, `line`,
  `column`, `kind` (rule category), `snippet`. `kind: "expression"`
  +  message containing "shellcheck" indicates a script-injection
  finding via the bundled shellcheck pass.
- Tool behaviour: exits non-zero when any lint fires. NOT a crash —
  parse JSON regardless.
- Primary source: https://github.com/rhysd/actionlint

Source: https://github.com/rhysd/actionlint

### zizmor

- Install: `pip install zizmor` (Python ≥ 3.11).
- Invocation:
  ```bash
  zizmor --format json "$target_path" \
      > "$TMPDIR/gh-actions-runner-zizmor.json" \
      2> "$TMPDIR/gh-actions-runner-zizmor.stderr"
  rc_zz=$?
  ```
  zizmor walks `.github/workflows/` under target by default.
- Output: JSON document with `findings: [...]`. Each finding has
  `ident` (rule id, e.g. `template-injection`,
  `dangerous-triggers`, `unpinned-uses`, `excessive-permissions`,
  `artipacked`), `desc`, `severity` (`Unknown`/`Informational`/
  `Low`/`Medium`/`High`), `confidence`, and `locations[]` each
  with `symbolic.path` + `concrete.location.start_point.row`.
- Tool behaviour: exits non-zero when any audit fires. NOT a crash —
  parse JSON regardless.
- Primary source: https://github.com/woodruffw/zizmor

Source: https://github.com/woodruffw/zizmor

## Output-field mapping

Every finding carries `origin: "gh-actions"`,
`tool: "actionlint" | "zizmor"`, `reference: "gh-actions-tools.md"`.

### actionlint → sec-review finding

| upstream                                             | sec-review field             |
|------------------------------------------------------|------------------------------|
| `"actionlint:" + .kind`                              | `id`                         |
| `kind`-derived: `expression` → HIGH (script-injection class), `syntax-check` → MEDIUM, all other kinds → LOW | `severity` |
| Per-kind CWE table — `expression` (script-injection via context) → CWE-94, `permissions` → CWE-732, `events` (esp. pull_request_target) → CWE-94, `shellcheck` → CWE-78, all others → null | `cwe` |
| `.message`                                           | `title`                      |
| `.filepath`                                          | `file`                       |
| `.line`                                              | `line`                       |
| `.snippet` (truncated to 200 chars)                  | `evidence`                   |
| `https://github.com/rhysd/actionlint/blob/main/docs/checks.md#` + kind | `reference_url`    |
| null (actionlint does not ship inline fix recipes)   | `fix_recipe`                 |
| `"high"`                                             | `confidence`                 |

### zizmor → sec-review finding

| upstream                                                    | sec-review field             |
|-------------------------------------------------------------|------------------------------|
| `"zizmor:" + .ident`                                        | `id`                         |
| `.severity` remap: `High` → HIGH, `Medium` → MEDIUM, `Low` → LOW, `Informational` → LOW, `Unknown` → LOW | `severity` |
| Per-ident CWE table — `template-injection` → CWE-94, `dangerous-triggers` → CWE-94, `unpinned-uses` → CWE-829, `excessive-permissions` → CWE-732, `artipacked` → CWE-522 (persist-credentials class), `secrets-inherit` → CWE-200, all others → null | `cwe` |
| `.desc`                                                     | `title`                      |
| `.locations[0].symbolic.path`                               | `file`                       |
| `.locations[0].concrete.location.start_point.row`           | `line`                       |
| `.locations[0].concrete.location.start_column` snippet (when present) | `evidence`         |
| `https://woodruffw.github.io/zizmor/audits/#` + ident       | `reference_url`              |
| null (zizmor does not ship inline fix recipes)              | `fix_recipe`                 |
| `.confidence` remap: `High` → high, `Medium` → medium, `Low` → low, else medium | `confidence`     |

## Degrade rules

`__gh_actions_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.
Only `tool-missing` applies — both tools are cross-platform with
no host-OS gates. The runner cleanly-skips when `target_path` has
no `.github/workflows/` directory or the directory contains zero
`*.y(a)ml` files (no work to do, not a failure).

## Version pins

- `actionlint` ≥ 1.7 (stable JSON schema; bundled shellcheck path
  finalised). Pinned 2026-04.
- `zizmor` ≥ 1.0 (stable JSON output; ident vocabulary stabilised).
  Pinned 2026-04.
