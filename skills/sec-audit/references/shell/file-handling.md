# Shell — File Handling, Temp Files, and TOCTOU

## Source

- https://www.shellcheck.net/wiki/ — shellcheck wiki
- https://mywiki.wooledge.org/BashFAQ/062 — BashFAQ on `mktemp`
- https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html — coreutils `mktemp`
- https://man7.org/linux/man-pages/man3/mkstemp.3.html — `mkstemp(3)` (the underlying C primitive)
- https://cheatsheetseries.owasp.org/cheatsheets/Race_Condition_Cheat_Sheet.html — OWASP race-condition cheat sheet
- https://cwe.mitre.org/data/definitions/367.html — CWE-367 TOCTOU

## Scope

Covers shell-script file-handling hazards: temp-file creation patterns (predictable `/tmp/foo-$$`, race-prone `mktemp` alternatives), `umask` defaults, permissions-set-after-write race windows, archive-extraction path-traversal (Zip Slip / tar slip), TOCTOU in `[ -f file ] && cat file`-style patterns, symlink-attack surface in shared directories, log-file ownership and permissions, and PID-file race conditions. Out of scope: variable-interpolation injection (covered by `shell/command-injection.md`); script execution hardening flags (covered by `shell/script-hardening.md`).

## Dangerous patterns (regex/AST hints)

### Predictable temp file via `$$` — CWE-377

- Why: `tmpfile=/tmp/foo-$$` constructs a temp filename from the script's PID. PIDs are guessable (and on busy systems, low-numbered PIDs cycle quickly), so an attacker with write access to `/tmp` can pre-create the file (or a symlink to a sensitive file) with a guessed name. When the script later writes to `$tmpfile`, it follows the symlink and overwrites the attacker's chosen target. The only safe primitive is `mktemp(1)` (or `mkstemp(3)` from a shell wrapper), which atomically creates a file with `O_CREAT|O_EXCL` and an unguessable name. POSIX 2008 mandates `mktemp` exists on every modern system.
- Grep: `(=|tmpfile=|tmp=|tempfile=)\s*"?(/tmp|/var/tmp|\$TMPDIR)/[^"$]*\$\$` — assignment of a path containing `$$` in `/tmp`, `/var/tmp`, or `$TMPDIR`.
- File globs: `*.sh`, `*.bash`, `*.zsh`
- Source: https://www.shellcheck.net/wiki/SC2129

### File created with default `umask`, then `chmod` to restrict — CWE-732

- Why: The race window between `> /tmp/secret-data` (file created with default 0644 / 0666 minus umask) and `chmod 600 /tmp/secret-data` is small but real — a concurrent process can `open` the file during this window and read its contents. The hardened pattern is to set a tight `umask` BEFORE creating the file (`umask 077; >/tmp/file; ...`) so the file is created with restrictive permissions atomically, OR to use `mktemp -m 600` (GNU coreutils) to set the mode at creation.
- Grep: `>\s*"?[^"]+"?` followed within the same function/block by `chmod\s+(0?[0-7][0-7][0-7])`. The intervening lines may contain a redirect or write.
- File globs: `*.sh`, `*.bash`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Race_Condition_Cheat_Sheet.html

### `tar -xf` / `unzip` on attacker-supplied archive without `--no-overwrite-dir` / path-validation — CWE-22 (Zip Slip / Tar Slip)

- Why: `tar -xf attacker.tar -C /tmp/extract/` honours absolute paths and `..` segments inside the archive — an entry named `../../etc/cron.d/backdoor` extracts to `/etc/cron.d/backdoor` regardless of the `-C` target directory. GNU tar 1.32+ has `--strip-components`, `--no-absolute-names`, and `--keep-old-files`; the hardened invocation is `tar --no-absolute-names --no-overwrite-dir -xf "$archive" -C "$dest"` plus a pre-extraction inspection (`tar -tf` and reject any entry with `..` or absolute path). `unzip` has the same class — use `unzip -L -X -P "" -d "$dest"` and validate paths beforehand. The Snyk "Zip Slip" advisory documents this class across multiple ecosystems.
- Grep: `(tar\s+(-[a-z]*x[a-z]*f|-x[a-z]*\s+--?file)|unzip\s+)[^|]*` not followed by `--no-absolute-names` (tar) or a pre-extraction validation step.
- File globs: `*.sh`, `*.bash`
- Source: https://snyk.io/research/zip-slip-vulnerability

### TOCTOU in `[ -f "$file" ] && cat "$file"` — CWE-367

- Why: The check (`[ -f ]`) and the use (`cat`) are two separate syscalls. Between them, an attacker with write access to the directory can replace `$file` with a symlink to a sensitive target — the `cat` then reads the attacker's chosen file. The class is structural in shell because shell has no atomic check-and-open primitive. Mitigations: (a) use the file directly and handle "not exist" via the command's error code rather than a pre-check; (b) operate in a private directory the attacker cannot write; (c) use `flock`-based locking when concurrent access matters.
- Grep: `\[\s*-[a-z]\s+"?\$[a-zA-Z_]+"?\s*\]` in close proximity to `(cat|less|tail|head|cp|mv|rm|chown|chmod)\s+"?\$[a-zA-Z_]+`.
- File globs: `*.sh`, `*.bash`
- Source: https://cwe.mitre.org/data/definitions/367.html

### `curl | sh` / `wget -O - | bash` install pattern — CWE-494

- Why: Piping a remote script directly into a shell is a documented supply-chain antipattern: the script is fetched and executed with no integrity verification, no version pinning, and no opportunity to review. A registry MITM, DNS poisoning, or maintainer compromise lands attacker-chosen code in the user's shell with the user's privileges. Equally problematic: the server can detect that the request is being piped to a shell (via the `User-Agent` and the lack of a slow-read pattern) and serve different content to interactive vs piped requests, evading reviewers. The hardened pattern is to download to a file, verify a signature or known SHA-256, then execute.
- Grep: `(curl|wget)\s+[^|]+\|\s*(sh|bash|/bin/(sh|bash))\b`.
- File globs: `*.sh`, `*.bash`, `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `Makefile`, install scripts, README install instructions.
- Source: https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/

### Logging secrets to `/tmp` or world-readable paths — CWE-532

- Why: Debug logs, command-trace output (`set -x`), and error captures often include environment variables — including any secrets injected via env-vars (passwords, API keys, JWT tokens). When the log lands in `/tmp/script-debug.log` (mode 0644 by default) or in `/var/log/` without restricted permissions, any local user can read the secrets. The fix is to (a) never log secret-bearing variables, (b) write logs to a directory with `umask 077` set, (c) prefer the systemd journal (which is access-controlled) over flat files.
- Grep: `set\s+-x\b` OR `>>?\s*"?(/tmp|/var/tmp|/var/log|\$LOG)/` paired with `(PASS|TOKEN|SECRET|KEY|API_KEY|AUTH)\b` env-var references in the same script.
- File globs: `*.sh`, `*.bash`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

### PID-file race / stale-lock pattern without `flock` — CWE-667

- Why: A common cron / daemon pattern is `[ -f /var/run/foo.pid ] && exit 0` to prevent concurrent runs. This races (TOCTOU) between the check and the subsequent `echo $$ > /var/run/foo.pid`. Two simultaneous invocations can both pass the check before either writes. The Linux-canonical primitive is `flock` (advisory file locking via `fcntl`): `exec 9>/var/lock/foo.lock; flock -n 9 || exit 0`. The lock is automatic-released when the script exits, so stale locks from killed processes do not require manual cleanup.
- Grep: `\[\s*-f\s+"?[^"]*\.(pid|lock)"?\s*\]` in a script that does NOT also call `flock`.
- File globs: `*.sh`, `*.bash`
- Source: https://man7.org/linux/man-pages/man1/flock.1.html

## Secure patterns

`mktemp`-based temp file with restrictive mode:

```bash
tmpfile=$(mktemp --tmpdir 'foo-XXXXXXXX' 2>/dev/null) || {
    echo "mktemp failed" >&2
    exit 1
}
trap 'rm -f -- "$tmpfile"' EXIT       # cleanup on any exit
chmod 600 -- "$tmpfile"                # belt + braces; mktemp already creates 0600
```

Source: https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html

Hardened tar extraction:

```bash
# Pre-validate: reject any entry with absolute path or .. segment.
if tar -tf "$archive" | grep -qE '^/|(^|/)\.\.(/|$)'; then
    echo "archive contains unsafe paths" >&2
    exit 1
fi
mkdir -p -- "$dest"
tar --no-absolute-names --no-overwrite-dir -xf "$archive" -C "$dest"
```

Source: https://snyk.io/research/zip-slip-vulnerability

`flock`-based singleton run:

```bash
LOCKFILE=/var/lock/myscript.lock
exec 9>"$LOCKFILE"
flock -n 9 || { echo "already running" >&2; exit 0; }
trap 'rm -f -- "$LOCKFILE"' EXIT
# ... script body ...
```

Source: https://man7.org/linux/man-pages/man1/flock.1.html

Restrictive umask before sensitive write:

```bash
umask 077                              # 0600 for files, 0700 for dirs
secret_file=$(mktemp)
printf '%s' "$DB_PASSWORD" > "$secret_file"
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Race_Condition_Cheat_Sheet.html

## Fix recipes

### Recipe: replace `$$` temp file with `mktemp` — addresses CWE-377

**Before (dangerous):**

```bash
tmpfile=/tmp/myscript-$$
echo "$data" > "$tmpfile"
```

**After (safe):**

```bash
tmpfile=$(mktemp --tmpdir 'myscript-XXXXXXXX')
trap 'rm -f -- "$tmpfile"' EXIT
echo "$data" > "$tmpfile"
```

Source: https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html

### Recipe: tighten umask before writing secrets — addresses CWE-732

**Before (dangerous):**

```bash
echo "$DB_PASSWORD" > /etc/myapp/db.password
chmod 600 /etc/myapp/db.password
```

**After (safe):**

```bash
( umask 077
  echo "$DB_PASSWORD" > /etc/myapp/db.password ) # subshell scopes umask
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Race_Condition_Cheat_Sheet.html

### Recipe: replace `curl | sh` with download + checksum + run — addresses CWE-494

**Before (dangerous):**

```bash
curl -sSL https://example.com/install.sh | sh
```

**After (safe):**

```bash
expected_sha="abc123def456..."
tmp=$(mktemp)
trap 'rm -f -- "$tmp"' EXIT
curl -sSL --fail https://example.com/install.sh -o "$tmp"
echo "$expected_sha  $tmp" | sha256sum -c - || {
    echo "checksum mismatch" >&2
    exit 1
}
sh -- "$tmp"
```

Source: https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/

### Recipe: replace TOCTOU pre-check with direct use + error handling — addresses CWE-367

**Before (dangerous):**

```bash
if [ -f "$config" ]; then
    cat "$config"
fi
```

**After (safe):**

```bash
if ! cat -- "$config" 2>/dev/null; then
    return 1   # file does not exist, or unreadable, or removed mid-read
fi
```

Source: https://cwe.mitre.org/data/definitions/367.html

## Version notes

- `mktemp` POSIX-2008 is universal; the `--tmpdir` and `-d` (directory) flags are GNU coreutils. On BSD/macOS, the syntax is slightly different (`mktemp -t prefix`); shellcheck's `SC2186` flags portability hazards.
- `flock(1)` is util-linux only — not available on macOS by default. The portable alternative is `lockf(1)` (BSD) or implementing the lock-via-symlink primitive (`ln -s "$$" /var/lock/myscript.lock`).
- `tar --no-absolute-names` and `--no-overwrite-dir` are GNU-tar; BSD-tar (libarchive) uses `-P` (preserve absolute path) by default and requires `--no-same-owner`/`--no-same-permissions` for similar protection. Detect at the top of the script via `tar --version | head -1`.
- `set -x` debug output cannot be selectively redacted — if a script may run with `-x` enabled, every variable expansion appears in stderr, including secret-bearing ones. The mitigation is to ensure secrets are read from files (not env-vars) and that `set -x` is bounded to non-secret-handling sections.

## Common false positives

- `mktemp` invocations under `tests/` directories using PID-based names for deterministic test fixture paths — annotate; downgrade.
- `curl | sh` patterns inside Dockerfiles for installing well-known tools with vendored sha256 verification immediately after — flag the absence of the checksum step, not the pipe pattern itself.
- TOCTOU `[ -f ]` checks where the surrounding code documents the file is created and never deleted by a separate process (e.g. config files in `/etc` written by a deployment script that races nothing) — downgrade.
- `set -x` in test fixtures, debug shell scripts, or `--verbose` code paths — annotate; flag only when the script handles secrets.
