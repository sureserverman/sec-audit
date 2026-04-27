# ansible-tools

<!--
    Tool-lane reference for sec-audit's ansible lane (v1.8.0+).
    Consumed by the `ansible-runner` sub-agent. Documents
    ansible-lint (single-tool lane).
-->

## Source

- https://ansible.readthedocs.io/projects/lint/ — ansible-lint canonical
- https://github.com/ansible/ansible-lint — ansible-lint source
- https://ansible.readthedocs.io/projects/lint/rules/ — full rule reference
- https://docs.ansible.com/ansible/latest/ — Ansible canonical
- https://cwe.mitre.org/

## Scope

In-scope: `ansible-lint` — Python-implemented Ansible
playbook + role + collection linter; mature rule catalogue
covering security (`risky-shell-pipe`, `no-log-password`,
`command-instead-of-shell`, `package-latest`,
`risky-octal`, `risky-file-permissions`,
`partial-become`), idempotency (`no-changed-when`,
`literal-compare`), syntax/style (`yaml`, `key-order`),
deprecation tracking (`deprecated-*`). Cross-platform; runs
as a pure source-tree static scanner; no network I/O for
the default rule set (Galaxy collection lookups happen only
when explicitly enabled via `--enable-list`).

This is a **single-tool lane** like Shell (v1.6) and DAST
(v0.5). ansible-lint is the canonical mature Ansible
linter; competitors (`yamllint` for YAML-only, custom
internal linters) lack the security-rule depth and the
idiom-aware coverage.

Out of scope: `yamllint` (YAML-syntax-only, no Ansible
semantics — runs as a separate concern); `molecule` (Ansible
testing framework — operational not security);
`ansible-galaxy collection install` integrity checks
(future work — would require a separate runner that
verifies SHA256 fingerprints against the Galaxy registry).

## Canonical invocations

### ansible-lint

- Install: `pip install ansible-lint` (Python 3.9+) OR `pipx install ansible-lint`. Cross-platform; pure Python (with optional Rust-based YAML parser via `ruamel.yaml.clib`).
- Invocation:
  ```bash
  ansible-lint --format=json \
               --offline \
               "$target_path" \
      > "$TMPDIR/ansible-runner-ansible-lint.json" \
      2> "$TMPDIR/ansible-runner-ansible-lint.stderr"
  rc_al=$?
  ```
  `--offline` skips Galaxy collection lookups (sec-audit
  is source-only). The walker auto-discovers playbooks +
  roles + collections under target_path.
- Output: JSON array. Each element has `check_name` (rule
  ID — e.g. `risky-shell-pipe`, `no-log-password`,
  `command-instead-of-shell`), `message`,
  `location.path`, `location.lines.begin.line` (NOTE: nested
  shape since 6.x), `severity` (`major`/`minor`/`info`),
  `categories` (rule-tag set including `security`,
  `idempotency`, `syntax`).
- Tool behaviour: exits non-zero when any rule fires. Empty
  result is `[]` with exit 0. Parse JSON regardless.
- Primary source: https://ansible.readthedocs.io/projects/lint/

Source: https://ansible.readthedocs.io/projects/lint/

## Output-field mapping

Every finding carries `origin: "ansible"`,
`tool: "ansible-lint"`, `reference: "ansible-tools.md"`.

### ansible-lint → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"ansible-lint:" + .check_name`                       | `id`                         |
| Per-rule severity table — security-relevant rules HIGH (`risky-shell-pipe`, `no-log-password`, `partial-become`), idempotency rules MEDIUM (`no-changed-when`, `command-instead-of-shell`, `command-instead-of-module`, `package-latest`), style/deprecation LOW (everything else). | `severity` |
| Per-rule CWE table (security-relevant subset; non-listed → null): `risky-shell-pipe` → CWE-78, `command-instead-of-shell` → CWE-78, `no-log-password` → CWE-532, `partial-become` → CWE-269, `package-latest` → CWE-1104, `risky-file-permissions` → CWE-732, `risky-octal` → CWE-732, `var-spacing` / `jinja[invalid]` → CWE-94 (Jinja injection class) | `cwe` |
| `.message`                                            | `title`                      |
| `.location.path`                                      | `file`                       |
| `.location.lines.begin.line` (or `.line` for older 6.x) | `line`                     |
| `.message` (truncated to 200 chars)                   | `evidence`                   |
| `https://ansible.readthedocs.io/projects/lint/rules/` + check_name + `/` | `reference_url`   |
| null (ansible-lint does not ship inline citation-grade fix recipes — its `_fixed` field is structural autofix data) | `fix_recipe` |
| `"high"` (ansible-lint is deterministic; no FP rate above the per-rule severity remap) | `confidence` |

## Degrade rules

`__ansible_status__` ∈ {`"ok"`, `"unavailable"`}.

Skip vocabulary (v1.8.0):

- `tool-missing` — `ansible-lint` is absent from PATH.
- `no-playbook` — ansible-lint is on PATH but the target
  has no Ansible-shaped files (no `*.yml`/`*.yaml` with
  `hosts:` + `tasks:` keys, no `roles/` or `collections/`
  directory at the canonical Ansible layout depth).
  Target-shape clean-skip.

No `partial` state — single-tool lane, so the runner is
either fully available or fully unavailable. No host-OS
gate.

## Version pins

- `ansible-lint` ≥ 6.20 (stable JSON schema with nested
  `location.lines.begin.line` shape; `risky-shell-pipe`
  rule finalised; `--offline` flag stable). Pinned 2026-04.
  Older (5.x) versions emit `.line` directly and have a
  smaller rule catalogue; the runner's jq path tolerates
  both shapes.
