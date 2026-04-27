# Ansible — Roles, Secrets, and Vault Handling

## Source

- https://docs.ansible.com/ansible/latest/vault_guide/index.html — Ansible Vault guide (canonical)
- https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_keywords.html#task — `no_log` keyword
- https://docs.ansible.com/ansible/latest/collections/ansible/builtin/git_module.html — `git` module (SSH/SSL handling)
- https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_lookups.html — lookups (env / file / pipe)
- https://ansible.readthedocs.io/projects/lint/rules/no-log-password/ — ansible-lint `no-log-password`
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — OWASP secrets management
- https://csrc.nist.gov/publications/detail/sp/800-57/part-1/rev-5/final — NIST SP 800-57 (key management)

## Scope

Covers Ansible secret-handling patterns: `ansible-vault` use
+ vault password sources, `no_log: true` on secret-touching
tasks, secrets via `lookup('env', ...)` vs hard-coded values,
`group_vars/all/vault.yml` storage layout, role-default
precedence with secrets, ssh / git module credential handling,
and the `become_user` + secrets interaction. Out of scope:
playbook-level injection (covered in
`ansible/playbook-security.md`); roles-as-distribution
(Galaxy collection signing — separate operational concern).

## Dangerous patterns (regex/AST hints)

### Plaintext secret in playbook YAML — CWE-798

- Why: Ansible playbooks commit to git as YAML. A `vars:`
  block (or `vars_files:` referencing a non-vault file) that
  contains a plaintext password / API key / private key is
  a published secret the moment the playbook is committed.
  The hardened pattern is to encrypt the secret-bearing file
  with `ansible-vault encrypt` (or use `ansible-vault
  encrypt_string` for individual values) — Ansible decrypts
  in-memory at run time using a vault-password file or
  prompt. Hard-coded secrets in unencrypted YAML are the
  single most common Ansible secret leak.
- Grep: YAML files with keys matching
  `(password|secret|api[_-]?key|token|access[_-]?key)\s*:\s*["']?[^!{][^"']+["']?` AND no `$ANSIBLE_VAULT;` header on the file AND no `!vault` tag on the value.
- File globs: `**/*.yml`, `**/*.yaml`, `group_vars/**`, `host_vars/**`, `vars/**`, `defaults/**`.
- Source: https://docs.ansible.com/ansible/latest/vault_guide/vault.html

### Task handling secrets without `no_log: true` — CWE-532

- Why: Ansible's default verbosity (`-v`) prints task arguments
  to stdout. A task that takes a `password:` parameter (e.g.
  `mysql_user:`, `htpasswd:`, `community.docker.docker_login:`)
  without `no_log: true` prints the password value to the run
  log — which often ends up in CI logs, on the deployment
  host's shell history, or in Ansible Tower's run history.
  ansible-lint's `no-log-password` flags this universally.
  The hardened pattern is `no_log: true` on every task that
  takes a secret-bearing argument.
- Grep: tasks with module arguments containing
  `(password|passphrase|secret|api[_-]?key|token)\s*:\s*` AND no `no_log:\s*true` in the same task.
- File globs: `**/*.yml`, `**/*.yaml`, `roles/**/tasks/*.yml`.
- Source: https://ansible.readthedocs.io/projects/lint/rules/no-log-password/

### `lookup('env', 'SECRET_NAME')` directly in task argv — CWE-214

- Why: `lookup('env', 'API_TOKEN')` reads the token from the
  Ansible-controller's environment at template-render time.
  When the resulting value flows into a `command:` / `shell:`
  argv that runs on the remote host, the token may appear in
  the remote host's `ps` output and `/proc/<pid>/cmdline`
  during the brief window the task runs. The hardened pattern
  is to write the secret to a temp file with restrictive
  permissions on the remote (`copy: content="{{ lookup(...)
  }}" dest=/tmp/secret mode=0600 no_log=true`) and have the
  command read from the file, OR pass via stdin.
- Grep: `(command|shell)\s*:\s*[^\\n]*\{\{\s*lookup\s*\(\s*["']env["']`.
- File globs: `**/*.yml`, `**/*.yaml`.
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

### Git module with SSH key inline / no host-key check — CWE-295

- Why: Ansible's `git:` module accepts `accept_hostkey: yes`
  to bypass StrictHostKeyChecking, AND `key_file:` to point
  at an SSH key file. Combined: a playbook that auto-accepts
  any host key while authenticating with a privileged
  deploy key is structurally MITM-vulnerable on the first
  clone. The hardened pattern is to pre-populate
  `~/.ssh/known_hosts` with the legitimate host's key
  fingerprint (e.g. via the `known_hosts:` module) and
  declare `accept_hostkey: no` on `git:` tasks.
- Grep: `accept_hostkey\s*:\s*(yes|true)` in `git:` module
  blocks.
- File globs: `**/*.yml`, `**/*.yaml`.
- Source: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/git_module.html

### Vault password in playbook command-line arg / shell history — CWE-214

- Why: Invoking `ansible-playbook --vault-password
  $VAULT_PW playbook.yml` puts the password in the process
  arglist visible to other users via `ps`, and in the
  invoking user's shell history. The hardened patterns are
  (a) `--vault-password-file ~/.vault_pass.txt` (mode 0600)
  reading from a file, (b) `--ask-vault-pass` prompting at
  invocation, or (c) `ANSIBLE_VAULT_PASSWORD_FILE` env var
  exported in a sourced-only shell rc.
- Grep: shell scripts / Makefile / CI configs containing
  `ansible-playbook[^|;]*--vault-password\s+\$`.
- File globs: `**/*.sh`, `**/*.bash`, `Makefile`, `.github/workflows/*.y(a)ml`, `.gitlab-ci.yml`, `tox.ini`.
- Source: https://docs.ansible.com/ansible/latest/vault_guide/vault.html

## Secure patterns

Vault-encrypted variables file:

```yaml
# group_vars/all/vault.yml — encrypted with `ansible-vault encrypt`
$ANSIBLE_VAULT;1.1;AES256
33336132646332626263323632653...
```

Source: https://docs.ansible.com/ansible/latest/vault_guide/vault.html

Inline vault-encrypted value:

```yaml
api_token: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  37633864363561663832663835613...
```

Source: https://docs.ansible.com/ansible/latest/vault_guide/vault.html

Task with `no_log` for secret handling:

```yaml
- name: Configure database password
  community.postgresql.postgresql_user:
    name: "{{ db_user }}"
    password: "{{ db_password }}"
    state: present
  no_log: true                                # password never appears in -v output
  become: true
  become_user: postgres
```

Source: https://ansible.readthedocs.io/projects/lint/rules/no-log-password/

Vault-password file with strict mode:

```bash
# ~/.vault_pass — mode 0600, owned by the operator user only.
chmod 600 ~/.vault_pass
ansible-playbook --vault-password-file ~/.vault_pass playbook.yml
```

Source: https://docs.ansible.com/ansible/latest/vault_guide/vault.html

## Fix recipes

### Recipe: encrypt plaintext secret with `ansible-vault encrypt_string` — addresses CWE-798

**Before (dangerous):**

```yaml
# group_vars/all/main.yml — committed plaintext
db_password: "hunter2-prod"
```

**After (safe):**

```yaml
# group_vars/all/main.yml — vault-tagged inline encryption
db_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  37663538393565386436306530323...
```

Source: https://docs.ansible.com/ansible/latest/vault_guide/vault.html

### Recipe: add `no_log: true` to secret-handling tasks — addresses CWE-532

**Before (dangerous):**

```yaml
- name: Create htpasswd entry
  community.general.htpasswd:
    path: /etc/nginx/htpasswd
    name: api_user
    password: "{{ api_password }}"
```

**After (safe):**

```yaml
- name: Create htpasswd entry
  community.general.htpasswd:
    path: /etc/nginx/htpasswd
    name: api_user
    password: "{{ api_password }}"
  no_log: true
```

Source: https://ansible.readthedocs.io/projects/lint/rules/no-log-password/

### Recipe: use known_hosts pre-population instead of accept_hostkey — addresses CWE-295

**Before (dangerous):**

```yaml
- ansible.builtin.git:
    repo: git@github.com:example/private.git
    dest: /opt/example
    accept_hostkey: yes
    key_file: /home/deploy/.ssh/id_ed25519
```

**After (safe):**

```yaml
- ansible.builtin.known_hosts:
    name: github.com
    key: "github.com {{ github_ssh_pubkey }}"   # from a vault-encrypted variable
    state: present
- ansible.builtin.git:
    repo: git@github.com:example/private.git
    dest: /opt/example
    accept_hostkey: no
    key_file: /home/deploy/.ssh/id_ed25519
```

Source: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/known_hosts_module.html

## Version notes

- `ansible-vault` AES256 mode is the only supported algorithm
  in 2.4+; earlier AES128 vaults must be re-encrypted on
  upgrade. The vault file format is forward-compatible.
- `no_log` was introduced in Ansible 2.0; pre-2.0 codebases
  have no equivalent secret-suppression mechanism.
- `community.hashi_vault` and `community.azure.azure_keyvault_secret`
  collections provide HashiCorp Vault and Azure Key Vault
  integration; for new deployments, prefer external secret
  stores over `ansible-vault` for production secrets — vault-
  encrypted-in-git secrets cannot be rotated without a git
  history rewrite.

## Common false positives

- A `password:` field in a task whose value is a templated
  reference to a vault-decrypted variable (e.g.
  `password: "{{ vault_db_password }}"` where
  `vault_db_password` lives in a `$ANSIBLE_VAULT;`-headed
  file) — the secret is not literally in the playbook;
  flag only the missing `no_log:` separately.
- `accept_hostkey: yes` in a playbook scoped to ephemeral
  test infrastructure (e.g. a Vagrant box, a fresh CI VM) —
  annotate; downgrade to MEDIUM.
- `lookup('env', ...)` inside a `set_fact` that immediately
  hands the value to a vault-encrypted store — annotate;
  the env-var exposure is brief and the secret is then
  encrypted at rest.
- Test playbooks under `tests/fixtures/` with intentionally
  insecure patterns — annotate.
