# Shell — Script Hardening (set flags, signal handling, PATH safety)

## Source

- https://www.gnu.org/software/bash/manual/bash.html — GNU Bash manual (canonical)
- https://www.shellcheck.net/wiki/ — shellcheck wiki
- https://mywiki.wooledge.org/BashFAQ — Bash FAQ
- https://google.github.io/styleguide/shellguide.html — Google Shell Style Guide
- https://csrc.nist.gov/publications/detail/sp/800-190/final — NIST SP 800-190 (relevant for container-bundled scripts)
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html — OWASP Logging cheat sheet

## Scope

Covers shell-script structural hardening: `set -euo pipefail` and its constituents, `IFS` defaulting, signal handling (`trap`), `read -r` for safe input, secrets-in-env-vars management, `sudo` minimisation, `PATH` safety (relative-PATH attacks), shebang correctness, `$0` self-reference patterns, and stdout/stderr handling. Out of scope: command-injection patterns (covered by `shell/command-injection.md`); file-handling and TOCTOU (covered by `shell/file-handling.md`).

## Dangerous patterns (regex/AST hints)

### Missing `set -e` — CWE-754

- Why: Without `set -e` (errexit), a command that fails returns a non-zero exit code that the script silently ignores, continuing to the next line. A failed `cd /important/dir` followed by `rm -rf *` deletes the WRONG directory's contents. `set -e` makes the shell exit on any uncaught command failure — the equivalent of a programming language's exception propagation. Every script that performs state-changing operations should declare `set -e` (or its compound `set -euo pipefail`) at the top. The exception is interactive scripts where partial-failure recovery is intentional.
- Grep: scripts that perform `rm`, `mv`, `cp`, `chmod`, `chown`, `ln`, `mkdir`, `dd`, or `>` redirection AND do not contain `set\s+-[a-zA-Z]*e` or `set\s+-o\s+errexit`.
- File globs: `*.sh`, `*.bash`
- Source: https://google.github.io/styleguide/shellguide.html

### Missing `set -u` — CWE-457 / CWE-908

- Why: Without `set -u` (nounset), referencing an unset variable expands to the empty string. `rm -rf "$undefined/*"` becomes `rm -rf "/*"` — disaster. `set -u` makes unset-variable references fatal errors, which catches the misspelled-variable class of bugs and the missed-environment-variable class. Combined with `set -e`, the script halts cleanly rather than executing an empty-expanded command. Use `${var:-default}` or `${var-}` to deliberately tolerate unset variables in specific contexts.
- Grep: scripts containing destructive commands (rm, mv, dd, >) AND not containing `set\s+-[a-zA-Z]*u` or `set\s+-o\s+nounset`.
- File globs: `*.sh`, `*.bash`
- Source: https://www.gnu.org/software/bash/manual/bash.html

### Missing `set -o pipefail` — CWE-754

- Why: In `cmd1 | cmd2 | cmd3`, the pipeline's exit status is the exit status of `cmd3` ONLY. If `cmd1` fails (e.g. `cat /missing | jq .name | tee out`), the pipeline reports success because `tee` succeeded. `set -o pipefail` makes the pipeline's exit status the exit status of the LAST command to fail, so `set -e` actually catches mid-pipeline failures. Pair with `set -e` always.
- Grep: scripts containing `\|\s*` pipelines AND not containing `pipefail`.
- File globs: `*.sh`, `*.bash`
- Source: https://www.shellcheck.net/wiki/SC3040

### `read` without `-r` — CWE-117

- Why: Plain `read line` interprets backslashes as escape characters — `read line < file` with `\n` in the file produces a logical newline, distorting the input. `read -r line` (raw mode) preserves the input verbatim. The plain mode is almost never what you want and silently corrupts data. shellcheck's `SC2162` flags this universally.
- Grep: `\bread\s+(-[a-zA-Z]*[^r-]|[a-zA-Z_])` — `read` followed by a flag set without `r`, or by a variable name directly.
- File globs: `*.sh`, `*.bash`
- Source: https://www.shellcheck.net/wiki/SC2162

### Missing `trap` for cleanup of temp resources — CWE-459

- Why: A script that creates temp files (`mktemp`), background processes, lock files, or open file descriptors must register a `trap` to clean up on exit — otherwise interruption (Ctrl+C, OOM-kill, signal from systemd) leaves orphaned resources. The canonical pattern is `trap 'rm -f -- "$tmpfile"; kill 0' EXIT`. The `EXIT` pseudo-signal fires on any exit path, including normal exit, errors, and signals.
- Grep: scripts containing `mktemp\b` AND not containing `trap\s+`.
- File globs: `*.sh`, `*.bash`
- Source: https://www.gnu.org/software/bash/manual/bash.html

### Relative `PATH` (e.g. `PATH=$PATH:.`) — CWE-426

- Why: Adding `.` (current directory) to `PATH` means commands typed without a full path resolve to executables in the cwd before resolving to system binaries. An attacker who writes a malicious `ls` into a directory the user `cd`s to gets that `ls` executed before `/bin/ls`. The canonical `PATH` for production scripts is an absolute, ordered list: `PATH=/usr/local/bin:/usr/bin:/bin`. Setting `PATH` at the top of every privileged script is good hygiene.
- Grep: `PATH\s*=\s*[^"]*[":](\.|\$PWD|\$HOME)(:|$|")`.
- File globs: `*.sh`, `*.bash`
- Source: https://cwe.mitre.org/data/definitions/426.html

### `sudo` invocation in interactive section without `-n` or `-A` — CWE-269

- Why: A script that calls `sudo cmd` in a non-interactive context (cron, systemd, CI) blocks if a password prompt appears — and may write the prompt to stderr where it ends up in logs. The hardened pattern is `sudo -n cmd` (non-interactive: fail if a password is needed) which produces a clean error rather than hanging. For scripts that genuinely need elevated privileges, configure `/etc/sudoers` (with `NOPASSWD:` for specific commands) rather than embedding passwords or running the entire script as root.
- Grep: `\bsudo\s+(?!-n|-A)[a-zA-Z_]` (sudo without `-n`/`-A` flag).
- File globs: `*.sh`, `*.bash`
- Source: https://man7.org/linux/man-pages/man8/sudoers.5.html

### Secrets passed via command-line argument (visible in `ps`) — CWE-214

- Why: `mysql -u root -p$DB_PASSWORD` puts the password in the process arglist where any user with `ps`/`/proc/<pid>/cmdline` access can read it. The same applies to `curl -u user:$PASSWORD`, `aws --secret-access-key $SECRET`, `git clone https://user:$TOKEN@...`. The hardened patterns are: (a) read from a file with restrictive permissions (`mysql --defaults-file=$conf`); (b) read from stdin (`mysql -u root --password < <(echo "$DB_PASSWORD")`); (c) use the tool's environment-variable form (`MYSQL_PWD=...`), preferably via `env` so the variable is scoped to the single invocation rather than inherited.
- Grep: `\b(mysql|psql|curl|aws|git|docker|ssh|scp)\s+[^|]*-(p|u|--password|--secret-access-key|--token)\s*[:=]?\s*\$[A-Z_]+`.
- File globs: `*.sh`, `*.bash`
- Source: https://cwe.mitre.org/data/definitions/214.html

### Missing or incorrect shebang — CWE-1188

- Why: A script without a shebang relies on the calling shell's default interpreter — when invoked via `./script` it may run under `sh` even if it uses bash-isms (arrays, `[[ ... ]]`, `(( ... ))`), causing silent misbehaviour. Shebang inconsistencies (`#!/bin/bash` vs `#!/usr/bin/env bash` vs `#!/bin/sh` for a bash-syntax script) lead to the same class of bug. The hardened convention is `#!/usr/bin/env bash` for bash-specific scripts (portable across distros that put bash in different paths) and `#!/bin/sh` ONLY for genuinely POSIX-portable scripts.
- Grep: scripts with bash-isms (`\[\[`, `\(\(`, `arr=\(`, `${arr\[`) but `#!/bin/sh` shebang, OR scripts with no shebang at all.
- File globs: `*.sh`, `*.bash`
- Source: https://www.shellcheck.net/wiki/SC2148

## Secure patterns

Hardened script preamble:

```bash
#!/usr/bin/env bash
#
# myscript - one-line description
#
# Usage: myscript [-v] <input-file>

set -euo pipefail
shopt -s inherit_errexit          # bash 4.4+: errexit propagates into command-substitution
IFS=$'\n\t'                       # restrict word-splitting to newline + tab
PATH=/usr/local/bin:/usr/bin:/bin

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly LOCKFILE="/var/lock/$(basename -- "$0").lock"

cleanup() {
    local rc=$?
    [[ -n "${tmpfile:-}" ]] && rm -f -- "$tmpfile"
    exit "$rc"
}
trap cleanup EXIT INT TERM
```

Source: https://google.github.io/styleguide/shellguide.html

`sudo` non-interactive with NOPASSWD scope in /etc/sudoers:

```bash
# /etc/sudoers.d/myapp:
# myapp ALL=(root) NOPASSWD: /usr/sbin/systemctl reload nginx

sudo -n /usr/sbin/systemctl reload nginx
```

Source: https://man7.org/linux/man-pages/man8/sudoers.5.html

Secret via stdin instead of arglist:

```bash
# Read DB_PASSWORD from a 0600-mode file:
mysql --defaults-file=/etc/myapp/db.conf -e "SELECT 1"

# OR use process substitution to keep secrets out of the arglist:
mysql --defaults-file=<(printf '[client]\npassword=%s\n' "$DB_PASSWORD")
```

Source: https://cwe.mitre.org/data/definitions/214.html

## Fix recipes

### Recipe: add `set -euo pipefail` preamble — addresses CWE-754

**Before (dangerous):**

```bash
#!/bin/bash
cd /var/lib/myapp
rm -rf *
```

**After (safe):**

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
cd -- /var/lib/myapp
rm -rf -- ./*    # the ./ prefix protects against filenames starting with -
```

Source: https://google.github.io/styleguide/shellguide.html

### Recipe: register `trap` for temp-file cleanup — addresses CWE-459

**Before (dangerous):**

```bash
tmpfile=$(mktemp)
do_something > "$tmpfile"
process "$tmpfile"
rm -f "$tmpfile"
```

**After (safe):**

```bash
tmpfile=$(mktemp)
trap 'rm -f -- "$tmpfile"' EXIT
do_something > "$tmpfile"
process "$tmpfile"
# implicit: tmpfile cleaned up on EXIT, including error paths
```

Source: https://www.gnu.org/software/bash/manual/bash.html

### Recipe: pin absolute `PATH` — addresses CWE-426

**Before (dangerous):**

```bash
PATH=$PATH:.:/opt/myapp/bin
```

**After (safe):**

```bash
PATH=/usr/local/bin:/usr/bin:/bin:/opt/myapp/bin
# never include . or any user-writable directory in a privileged script
```

Source: https://cwe.mitre.org/data/definitions/426.html

### Recipe: move secret out of arglist — addresses CWE-214

**Before (dangerous):**

```bash
curl -u "$API_USER:$API_TOKEN" https://api.example.com/data
```

**After (safe):**

```bash
# Use a netrc file with 0600 permissions:
chmod 600 ~/.netrc
curl --netrc-file ~/.netrc https://api.example.com/data

# OR pass via stdin:
printf 'user = "%s"\npassword = "%s"\n' "$API_USER" "$API_TOKEN" | \
    curl -K - https://api.example.com/data
```

Source: https://cwe.mitre.org/data/definitions/214.html

## Version notes

- `set -e` has surprisingly subtle semantics in bash: it does NOT trigger inside `&&`/`||` chains, inside `if`/`while`/`until` conditions, or inside command-substitution (`$(...)`) before bash 4.4 + `shopt -s inherit_errexit`. The `errexit` propagation gap inside `$(...)` is one of the most common silent-failure classes in bash; `inherit_errexit` (bash 4.4 / 2016) closes it.
- `pipefail` is bash/zsh-specific. POSIX `sh` (dash, busybox) does not have it; in those shells, mid-pipeline failure is unrecoverable without `${PIPESTATUS[@]}`-equivalent gymnastics.
- `IFS=$'\n\t'` (Google Shell Style Guide convention) restricts word-splitting to newline and tab, eliminating space-as-separator surprises in unquoted expansions. Pair with universal quoting; the IFS restriction is defence-in-depth.
- `readonly` declarations protect against later overwrites — useful for path constants and feature flags. Combined with `set -u`, attempts to use a `readonly` as a different value are detected.
- `shopt -s nullglob` makes `for f in *.txt` produce zero iterations when no files match (instead of literal `*.txt`); `failglob` makes it an error. Either is safer than the default behaviour for most scripts.

## Common false positives

- Single-purpose one-liner scripts where `set -e` is overkill — annotate; downgrade unless the script performs destructive operations.
- `read` without `-r` in a context where backslash-escapes are intentional (e.g. parsing literal escape sequences) — annotate; flag only when the input is untrusted.
- `sudo` without `-n` in scripts explicitly designed for interactive use (e.g. user-installed CLI tools) — downgrade unless the script also runs in cron/systemd contexts.
- Missing shebang in scripts that are explicitly sourced (`source ./lib.sh` / `. ./lib.sh`) rather than executed — sourced scripts run in the parent shell's interpreter; shebang is irrelevant. Detect via the surrounding code's calling pattern.
- Scripts under `tests/fixtures/` that intentionally lack hardening flags as part of the fixture — downgrade.
