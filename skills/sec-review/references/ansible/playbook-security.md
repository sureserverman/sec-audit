# Ansible — Playbook Security Patterns

## Source

- https://docs.ansible.com/ansible/latest/playbook_guide/ — Ansible playbook guide (canonical)
- https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html — Ansible YAML syntax
- https://ansible.readthedocs.io/projects/lint/rules/ — ansible-lint rule reference (canonical rule IDs)
- https://docs.ansible.com/ansible/latest/reference_appendices/playbooks_keywords.html — playbook keywords
- https://docs.ansible.com/ansible/latest/collections/ansible/builtin/command_module.html — `command` module
- https://docs.ansible.com/ansible/latest/collections/ansible/builtin/shell_module.html — `shell` module
- https://owasp.org/www-project-top-ten/ — OWASP Top Ten
- https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final — NIST SP 800-53 r5 (configuration management family)

## Scope

Covers Ansible playbook security patterns: `shell` vs
`command` module choice, Jinja2 template injection in tasks,
`become: yes` privilege escalation defaults, idempotency
breaches that mask state drift (`changed_when` / `failed_when`
gaps), `latest` package version pins (CWE-1104 supply-chain
class), `no_log` for secret-handling tasks, dynamic include /
import patterns that bypass static review. Out of scope:
secret-handling deep-dive (covered in
`ansible/role-secrets-and-vault.md`); Ansible role-internals
(roles structure, role-default precedence — operational concern
not security). Detection requires playbook YAML: top-level
`hosts:` + `tasks:` keys (the canonical playbook shape).

## Dangerous patterns (regex/AST hints)

### `shell:` module with attacker-influenced variable interpolation — CWE-78

- Why: Ansible's `shell:` module wraps the command in
  `/bin/sh -c`, performing shell expansion on the entire
  string — variable interpolation through Jinja2 (`{{ var }}`)
  is then re-interpreted by the shell. `shell: "rm -rf {{
  cleanup_path }}"` with `cleanup_path: "; rm -rf /"` becomes
  `rm -rf ; rm -rf /`. The hardened pattern is the `command:`
  module (which does NOT invoke a shell) plus arguments via
  the `argv:` list form. ansible-lint's `command-instead-of-shell`
  rule flags this universally; the security distinction is
  that `command:` with argv is structurally injection-safe.
- Grep: `shell:\s*["'][^"']*\{\{` — shell-module with
  embedded Jinja interpolation.
- File globs: `**/*.yml`, `**/*.yaml`, `playbooks/**`, `roles/**/tasks/*.yml`.
- Source: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/shell_module.html

### `command:` / `shell:` without `changed_when` — CWE-754

- Why: Ansible's `command` and `shell` modules report
  `changed: true` on every run by default (they have no way
  to know whether the command was idempotent). Playbooks
  that rely on `changed_when` to suppress false-positive
  changes are auditable — without it, the playbook reports
  "drift" on every dry-run, masking genuine drift signals.
  ansible-lint's `no-changed-when` rule. Functionally a
  hygiene rule, but it has security implications: when every
  task reports change, real configuration drift (a privileged
  user changed a file out-of-band) is hidden in the noise.
- Grep: `(shell|command)\s*:\s*` task blocks without a
  matching `changed_when:` line within the same task.
- File globs: `**/*.yml`, `**/*.yaml`.
- Source: https://ansible.readthedocs.io/projects/lint/rules/no-changed-when/

### Jinja2 template-injection in module arg — CWE-94

- Why: Ansible's modules accept arguments that may include
  Jinja2 templates. When a variable's value comes from
  attacker-influenced sources (an external API response, a
  Git repo's commit message, a user-supplied environment
  variable), interpolating it into a `template:` module's
  `src:` parameter or into a `lineinfile:` `regexp:` parameter
  enables Jinja injection — Ansible re-renders the variable
  expansion as a Jinja expression, which has access to module
  imports and Python builtins. The hardened pattern is to
  escape such variables via the `| quote` filter, or to keep
  attacker-influenced values out of arguments that are
  Jinja-rendered.
- Grep: module arguments containing `{{ [^}]+ }}` where the
  variable is sourced from `register:`, `ansible_facts.*`, or
  external data via `lookup` / `set_fact`.
- File globs: `**/*.yml`, `**/*.yaml`, `roles/**/tasks/*.yml`.
- Source: https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_templating.html

### `latest` package version with no `changed_when` — CWE-1104

- Why: `package: name=foo state=latest` runs the package
  manager's "upgrade if newer available" logic on every
  playbook run. This silently propagates upstream changes —
  including a compromised maintainer's malicious release —
  into the production environment without review. The
  hardened pattern is `state: present` plus a pinned version:
  `name: foo` with `version: "1.2.3"`. This requires manual
  review when bumping but eliminates the silent-update
  surface. ansible-lint's `package-latest` rule.
- Grep: `state\s*:\s*latest` in any task block (apt, yum,
  dnf, pip, npm modules).
- File globs: `**/*.yml`, `**/*.yaml`.
- Source: https://ansible.readthedocs.io/projects/lint/rules/package-latest/

### Task with `become: yes` not scoped to specific commands — CWE-269

- Why: `become: yes` escalates the entire task to root (or
  another user via `become_user:`). Playbook-level
  `become: yes` (set on the play, not on individual tasks)
  means every task in the play runs with elevated privileges,
  even tasks that don't need them. The hardened pattern is
  task-level `become:` only on tasks that genuinely require
  it; default the play to non-privileged. ansible-lint's
  `risky-shell-pipe` and related risk rules cover the
  surrounding patterns.
- Grep: top-level `become:\s*(yes|true)` AND no
  `become_user` scoping plus all tasks lack their own
  `become:` declaration (i.e. inherits play-level become).
- File globs: `**/*.yml`, `**/*.yaml` (playbook-shape files).
- Source: https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html

### `risky-shell-pipe` — `shell:` module piping output to another command — CWE-754

- Why: `shell: "curl https://... | sh"` (or any other pipeline)
  via the shell module has TWO layers of injection surface:
  the shell expansion itself, and the missing `pipefail`
  setting that means a failure in the upstream command (`curl`)
  does not fail the task. ansible-lint's `risky-shell-pipe`
  flags this. The hardened pattern is `shell: "set -o pipefail
  && curl https://... | sh"` (with the explicit pipefail), OR
  better, decompose into two tasks: download (with
  `get_url:` + `checksum:`) then execute.
- Grep: `shell:` task content containing a `\|` pipe operator
  AND not preceded by `pipefail`.
- File globs: `**/*.yml`, `**/*.yaml`.
- Source: https://ansible.readthedocs.io/projects/lint/rules/risky-shell-pipe/

### `command-instead-of-module` — ad-hoc `command:` for operations Ansible has a module for — CWE-693

- Why: Ansible ships idempotent modules for most common
  operations: `service:` / `systemd:` instead of `command:
  systemctl`, `file:` instead of `command: chmod`, `package:`
  instead of `command: apt-get install`, `git:` instead of
  `command: git clone`. Using `command:` for these forfeits
  idempotency, the module's input validation, and
  module-specific security defaults (e.g. `git:` validates
  the remote URL and SSH key handling). ansible-lint's
  `command-instead-of-module` flags this universally.
- Grep: `command:\s*(systemctl|chmod|chown|apt-get|yum|dnf|git)`-style task content.
- File globs: `**/*.yml`, `**/*.yaml`.
- Source: https://ansible.readthedocs.io/projects/lint/rules/command-instead-of-module/

## Secure patterns

Hardened command invocation with argv list:

```yaml
- name: Restart the API service
  ansible.builtin.command:
    argv:
      - /usr/bin/systemctl
      - restart
      - api.service
  changed_when: false   # restart is intentionally always-changed
  become: true
```

Source: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/command_module.html

Pinned package install:

```yaml
- name: Install nginx (pinned)
  ansible.builtin.apt:
    name: "nginx=1.24.0-1ubuntu1"
    state: present
    update_cache: yes
```

Source: https://ansible.readthedocs.io/projects/lint/rules/package-latest/

Module-based service management (idempotent):

```yaml
- name: Ensure api.service is running and enabled
  ansible.builtin.systemd:
    name: api.service
    state: started
    enabled: yes
```

Source: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/systemd_module.html

Task-scoped become (no play-level escalation):

```yaml
- hosts: webservers
  # NOTE: no top-level `become:` — only specific tasks elevate.
  tasks:
    - name: Read public banner
      ansible.builtin.command:
        cmd: cat /etc/motd
      register: banner
      changed_when: false

    - name: Replace nginx config
      ansible.builtin.copy:
        src: nginx.conf
        dest: /etc/nginx/nginx.conf
        owner: root
        group: root
        mode: "0644"
      become: true                              # scoped to this task only
      notify: reload nginx
```

Source: https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html

## Fix recipes

### Recipe: replace `shell:` with `command:` argv form — addresses CWE-78

**Before (dangerous):**

```yaml
- name: Cleanup user upload
  ansible.builtin.shell: "rm -rf {{ upload_path }}/*"
```

**After (safe):**

```yaml
- name: Cleanup user upload
  ansible.builtin.file:
    path: "{{ upload_path }}"
    state: absent
- name: Recreate empty upload dir
  ansible.builtin.file:
    path: "{{ upload_path }}"
    state: directory
    owner: app
    group: app
    mode: "0750"
```

Source: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/file_module.html

### Recipe: pin package version — addresses CWE-1104

**Before (dangerous):**

```yaml
- ansible.builtin.apt:
    name: nginx
    state: latest
```

**After (safe):**

```yaml
- ansible.builtin.apt:
    name: "nginx=1.24.0-1ubuntu1"
    state: present
    update_cache: yes
```

Source: https://ansible.readthedocs.io/projects/lint/rules/package-latest/

### Recipe: scope `become:` to specific tasks — addresses CWE-269

**Before (dangerous):**

```yaml
- hosts: webservers
  become: yes        # entire play runs as root
  tasks:
    - debug:
        msg: "starting deploy"
    - apt: name=nginx state=present
```

**After (safe):**

```yaml
- hosts: webservers
  tasks:
    - debug:
        msg: "starting deploy"
    - apt: name=nginx state=present
      become: true   # scoped to this task only
```

Source: https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html

## Version notes

- ansible-core 2.14+ defaults `injected_template` warning for
  Jinja-in-args; pre-2.14 silently injects.
- ansible-lint 6.x ships the `risky-shell-pipe` rule;
  ansible-lint 5.x has it under a different name. Pin the
  ansible-lint version in CI; older versions have a smaller
  rule catalogue.
- The `package` module (cross-distro abstraction) calls into
  `apt`/`yum`/`dnf` based on host facts — pin via the
  cross-distro module's `name=foo-1.2.3` syntax for
  portability.

## Common false positives

- `shell:` with hard-coded command strings (no Jinja
  interpolation) used for genuinely shell-only constructs
  (heredocs, IO redirection, complex pipelines with
  pipefail) — annotate; flag only when interpolation is
  present.
- `command-instead-of-module` on tasks targeting commands
  Ansible's modules don't cover (vendor-specific CLIs,
  obscure system tools) — annotate; downgrade.
- `state: latest` in playbooks explicitly tagged
  `--tags update` for the dedicated update-cycle workflow —
  annotate; the latest semantics are intentional in that
  context.
- Top-level `become: yes` in playbooks scoped to a single
  hosts pattern that the operator has documented as "the
  cluster-management playbook always needs root" — annotate;
  flag if the playbook also performs non-privileged tasks.
