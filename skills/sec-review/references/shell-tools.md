# shell-tools

<!--
    Tool-lane reference for sec-review's shell lane (v1.6.0+).
    Consumed by the `shell-runner` sub-agent. Documents
    shellcheck (single-tool lane).
-->

## Source

- https://www.shellcheck.net/ — shellcheck canonical (Haskell binary; static analyzer for shell scripts)
- https://github.com/koalaman/shellcheck — shellcheck source repo
- https://www.shellcheck.net/wiki/ — full rule reference (`SCxxxx` IDs)
- https://cwe.mitre.org/

## Scope

In-scope: `shellcheck` — Haskell binary; static analyzer for
bash, sh, dash, ksh shell scripts; well-defined `SCxxxx` rule
catalogue covering quoting, command injection, file-handling,
control-flow correctness, and portability. Cross-platform; no
host-OS gate; runs as a pure source-tree static scanner. Out
of scope: shfmt (formatter only — no security signal), bashate
(style-only OpenStack tool — overlaps with shellcheck's style
rules without security depth), checkbashisms (sh-portability
only — narrow).

This is the **first single-tool lane in sec-review since
DAST**: shellcheck is the canonical (and effectively sole)
mature shell-script linter — adding a second tool for
symmetry would be overhead with no signal lift.

## Canonical invocations

### shellcheck

- Install: `apt install shellcheck` (Debian/Ubuntu) /
  `brew install shellcheck` (macOS) /
  `dnf install ShellCheck` (Fedora) / pre-built binaries from
  GitHub Releases (Linux/macOS amd64+arm64, Windows).
- Invocation:
  ```bash
  files=$( find "$target_path" -type f \( \
              -name '*.sh' -o -name '*.bash' \
              -o -name '*.zsh' -o -name '*.ksh' \) \
           -not -path '*/node_modules/*' \
           -not -path '*/.venv/*' \
           -not -path '*/vendor/*' \
           -not -path '*/dist/*' \
           -not -path '*/build/*' \
           -not -path '*/target/*' \
           -print )
  if [ -n "$files" ]; then
      shellcheck -f json $files \
          > "$TMPDIR/shell-runner-shellcheck.json" \
          2> "$TMPDIR/shell-runner-shellcheck.stderr"
      rc_sh=$?
  fi
  ```
  shellcheck accepts a list of files. The find pre-filter
  excludes vendored / build-output directories that the
  inventory rule already excludes via `.gitignore` — defence
  in depth. Pass `--severity=info` (default) to capture all
  rule fires; `--severity=warning` filters out style-only
  rules if the caller wants a tighter signal.
- Output: JSON array. Each element has `file`, `line`,
  `endLine`, `column`, `endColumn`, `level` (`error` /
  `warning` / `info` / `style`), `code` (rule ID — integer
  like `2086`, formatted `SC2086` in user-facing output),
  `message`, `fix` (optional structured diff), `comments`
  (related notes).
- Tool behaviour: exits non-zero when any rule fires (exit
  code = highest severity level, 0/1/2/3/4 mapping to
  none/info/style/warning/error). NOT a crash — parse JSON
  regardless. Empty target file list yields `[]` with exit 0.
- Primary source: https://www.shellcheck.net/

Source: https://www.shellcheck.net/

## Output-field mapping

Every finding carries `origin: "shell"`, `tool: "shellcheck"`,
`reference: "shell-tools.md"`.

### shellcheck → sec-review finding

| upstream                                              | sec-review field             |
|-------------------------------------------------------|------------------------------|
| `"shellcheck:SC" + (.code \| tostring)`               | `id`                         |
| `.level` remap: `error` → HIGH, `warning` → MEDIUM, `info` → LOW, `style` → LOW | `severity` |
| Per-`code` CWE table (security-relevant subset; non-listed → null): `2086` (unquoted variable in command) → CWE-78, `2046` (unquoted command substitution) → CWE-78, `2068` (unquoted array expansion) → CWE-78, `2294` (eval array) → CWE-94, `2156` (find -exec sh -c with `{}` interpolated) → CWE-78, `2038` (find pipe to xargs without -print0/-0) → CWE-78, `2129` (predictable temp file via `$$`) → CWE-377, `2162` (read without -r) → CWE-117, `2148` (missing/incorrect shebang) → CWE-1188, `1090` / `1091` (unsourced source) → CWE-829, `2317` (set -e in subshell ineffective) → CWE-754, `3040` (pipefail not in POSIX sh) → CWE-754 | `cwe` |
| `.message`                                            | `title`                      |
| `.file`                                               | `file`                       |
| `.line`                                               | `line`                       |
| `.message` (truncated to 200 chars)                   | `evidence`                   |
| `https://www.shellcheck.net/wiki/SC` + (.code \| tostring) | `reference_url`         |
| null (shellcheck's `fix` field carries a structured diff but is not always present; do not promote to fix_recipe — sec-expert reasoning over the shell/ reference packs is the authoritative recipe source) | `fix_recipe` |
| `"high"` (shellcheck is deterministic; no FP rate above the level remap)| `confidence` |

## Degrade rules

`__shell_status__` ∈ {`"ok"`, `"unavailable"`}.

Skip vocabulary (v1.6.0):

- `tool-missing` — `shellcheck` is absent from PATH.

No `partial` state — single-tool lane, so the runner is
either fully available or fully unavailable. No host-OS gate
— shellcheck is cross-platform. No target-shape skip — the
inventory rule guarantees at least one shell-shaped file
under target before dispatch.

## Version pins

- `shellcheck` ≥ 0.9.0 (stable JSON schema; `SC2317`
  set-e-in-subshell rule landed; `SC2294` eval-array rule
  finalised). Pinned 2026-04. Older versions (0.7.x) lack
  several of the security-relevant rules in the per-code
  CWE table above; if the runner detects an older version
  via `shellcheck --version`, it should still run (no
  version gate) but may produce a smaller finding set.
