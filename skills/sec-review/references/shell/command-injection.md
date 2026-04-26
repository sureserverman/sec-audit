# Shell — Command Injection and Variable Interpolation

## Source

- https://www.shellcheck.net/wiki/ — shellcheck wiki (canonical rule documentation, `SCxxxx` IDs)
- https://mywiki.wooledge.org/BashFAQ — Bash FAQ (the de-facto authoritative reference)
- https://mywiki.wooledge.org/BashGuide — Bash Guide
- https://www.gnu.org/software/bash/manual/bash.html — GNU Bash manual
- https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html — POSIX shell command-language reference
- https://owasp.org/www-community/attacks/Command_Injection — OWASP Command Injection
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — OWASP OS Command Injection Defense

## Scope

Covers shell-script (bash, sh, dash, ksh, zsh) command-injection patterns: unquoted variable interpolation in command position, `eval` with attacker-controlled strings, `bash -c "$VAR"`-style indirection, `xargs`/`find -exec` argument splitting, command-substitution `$(...)` / backtick quoting hazards, here-doc / here-string interpolation, and SSH `ssh remote "$cmd"`-style remote execution. Out of scope: file-handling and TOCTOU patterns (covered by `shell/file-handling.md`); script-hardening flags and signal handling (covered by `shell/script-hardening.md`); shell-quoting in non-shell contexts (Python `subprocess(shell=True)`, Node `child_process.exec` — covered by language-specific reference packs).

## Dangerous patterns (regex/AST hints)

### Unquoted variable in command position — CWE-78

- Why: `rm $file` with `file="-rf /"` reads as `rm -rf /` because the shell performs word-splitting on the unquoted variable. Quoting (`rm "$file"`) prevents word-splitting and globbing — the variable is passed as a single argument regardless of its content. Every shell variable expansion in a command-execution context should be double-quoted unless the script explicitly wants word-splitting (in which case a comment should justify it). shellcheck's `SC2086` is the canonical detection.
- Grep: any unquoted `\$[a-zA-Z_][a-zA-Z0-9_]*` token in a command-argument position OR `\$\{[^}]+\}` without surrounding `"..."`.
- File globs: `*.sh`, `*.bash`, `*.zsh`, `*.ksh`, files with shell shebangs.
- Source: https://www.shellcheck.net/wiki/SC2086

### `eval` with attacker-influenced string — CWE-94

- Why: `eval "$user_input"` re-parses the string as shell syntax — every metacharacter in the input is interpreted, not quoted. There is no way to safely interpolate untrusted data into an `eval` argument; the only defence is to not use `eval` at all. Legitimate uses of `eval` (dynamic variable name construction, e.g. `eval "$(ssh-agent -s)"`) operate on outputs from trusted commands; any path where attacker data reaches `eval` is structurally vulnerable. shellcheck's `SC2294` flags `eval` with array arguments; the broader hazard is `eval` with any non-constant string.
- Grep: `\beval\s+("[^"]*\$[^"]*"|'[^']*\$[^']*'|[^"';\s]*\$)` — eval followed by a non-constant string containing variable references.
- File globs: `*.sh`, `*.bash`
- Source: https://owasp.org/www-community/attacks/Command_Injection

### `bash -c "$VAR"` / `sh -c "$VAR"` indirection — CWE-78

- Why: Spawning a fresh shell with `-c` and a constructed command string re-introduces the shell-quoting hazards that direct command invocation avoids. `bash -c "ls $userInput"` performs word-splitting and globbing on `$userInput` inside the inner shell — the outer-shell quotes do not protect against this. The fix is to either (a) call the binary directly without `-c` if no shell features are needed, or (b) use `bash -c '...' _ "$arg1" "$arg2"` to pass arguments positionally where the inner shell sees them as `$1`/`$2` already-quoted.
- Grep: `\b(bash|sh|/bin/(bash|sh)|zsh|dash|ksh)\s+-c\s+("[^"]*\$[^"]*"|'[^']*\$[^']*'|\$)`.
- File globs: `*.sh`, `*.bash`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### `find -exec` with shell expansion of `{}` — CWE-78

- Why: `find ... -exec sh -c 'cmd $0' {} \;` runs `sh -c` for each file with the filename as `$0`; if any filename contains shell metacharacters (newlines, semicolons, backticks, `$(...)`), they are interpreted in the inner shell. The safe pattern is `find ... -exec cmd {} \;` (direct exec, no shell) or `find ... -exec cmd {} +` (xargs-style batched exec). When shell features are genuinely required, pass the filename as a quoted positional: `find ... -exec sh -c 'echo "$1"' _ {} \;` makes the filename `$1` and the inner shell sees it pre-quoted.
- Grep: `find\s+[^|]*-exec\s+(sh|bash|/bin/(sh|bash))\s+-c\s+'[^']*\{\}` — find with a shell -c containing `{}` directly.
- File globs: `*.sh`, `*.bash`
- Source: https://www.shellcheck.net/wiki/SC2156

### `xargs` without `-0` reading from `find` without `-print0` — CWE-78

- Why: The default `xargs` field separator is whitespace; filenames containing spaces, tabs, or newlines are split into multiple arguments. `find -print0 | xargs -0` uses NUL as the separator, which cannot appear in filenames — this is the safe pairing. `find | xargs` (without `-print0`/`-0`) silently mis-handles malicious filenames an attacker can control (e.g. via a writable-by-others directory).
- Grep: `xargs\b` not preceded in the same pipeline by `find\s+[^|]*-print0`.
- File globs: `*.sh`, `*.bash`
- Source: https://www.shellcheck.net/wiki/SC2038

### Command substitution in unquoted context with attacker-influenced output — CWE-78

- Why: `cd $(some_command)` expands the output of `some_command` and then word-splits the result. If `some_command` is e.g. `git config remote.origin.url` and the URL contains spaces or shell metacharacters, the `cd` command receives multiple arguments. Quote the substitution: `cd "$(some_command)"`.
- Grep: unquoted `\$\([^)]+\)` or unquoted backtick `\` ... \`` in a command-argument position.
- File globs: `*.sh`, `*.bash`
- Source: https://www.shellcheck.net/wiki/SC2046

### `ssh remote "$cmd"` with attacker-influenced cmd — CWE-78

- Why: `ssh user@host "ls $dir"` sends the literal string `ls $dir` to the remote shell — the remote `sh` then word-splits and expands, with NO protection from local-shell quoting. Even if `$dir` is safely quoted on the local side, the remote-side expansion happens in a fresh shell. The fix is to rigorously validate or escape the remote-side string before sending, OR pass arguments via stdin (`ssh host bash -s -- "$dir" < script.sh`) so the remote shell sees them as already-quoted positional parameters.
- Grep: `ssh\s+[^"\s]+\s+("[^"]*\$[^"]*"|[^|;&\n]*\$)` — ssh with a remote command containing variable references.
- File globs: `*.sh`, `*.bash`
- Source: https://mywiki.wooledge.org/BashFAQ/048

### `IFS` modified without restoration — CWE-668

- Why: A script that sets `IFS` (e.g. `IFS=','` to parse a CSV) and does not restore the previous value affects every subsequent command's word-splitting behaviour. Subtle bugs and security gaps follow when later code expects default-IFS splitting (whitespace) but operates under `IFS=,`. The hardened pattern is `local IFS_save="$IFS"; IFS=','; ...; IFS="$IFS_save"`, OR scoped via `( IFS=','; ... )` in a subshell so the change is isolated.
- Grep: top-level `IFS\s*=` assignment without a matching restore in the same scope.
- File globs: `*.sh`, `*.bash`
- Source: https://mywiki.wooledge.org/IFS

## Secure patterns

Quoted variable expansion (the default for every variable in a command):

```bash
file="/tmp/upload/$user_provided_name"
rm -- "$file"             # -- prevents leading-dash interpretation as flag
mv -- "$src" "$dst"
echo "input was: $input"  # quoting preserves spacing + prevents glob expansion
```

Source: https://www.shellcheck.net/wiki/SC2086

`find` + `xargs` with NUL separator:

```bash
find /srv/uploads -type f -name '*.tmp' -print0 | xargs -0 -r rm --
# OR
find /srv/uploads -type f -name '*.tmp' -exec rm -- {} +
```

Source: https://www.shellcheck.net/wiki/SC2038

`bash -c` with positional arguments instead of interpolation:

```bash
# Safe: $1, $2 inside the inner shell are pre-quoted positional params,
# not subject to outer-shell interpolation hazards.
bash -c 'cp -- "$1" "$2"' _ "$src" "$dst"
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

## Fix recipes

### Recipe: quote variable expansions — addresses CWE-78

**Before (dangerous):**

```bash
rm $tempfile
echo Found $count results in $dir
```

**After (safe):**

```bash
rm -- "$tempfile"
echo "Found $count results in $dir"
```

Source: https://www.shellcheck.net/wiki/SC2086

### Recipe: replace `eval` with array expansion — addresses CWE-94

**Before (dangerous):**

```bash
cmd="ls -l $dir"
eval "$cmd"
```

**After (safe):**

```bash
cmd=(ls -l "$dir")
"${cmd[@]}"
```

Source: https://owasp.org/www-community/attacks/Command_Injection

### Recipe: quote command substitution — addresses CWE-78

**Before (dangerous):**

```bash
cd $(git rev-parse --show-toplevel)
```

**After (safe):**

```bash
cd -- "$(git rev-parse --show-toplevel)"
```

Source: https://www.shellcheck.net/wiki/SC2046

### Recipe: pair `find -print0` with `xargs -0` — addresses CWE-78

**Before (dangerous):**

```bash
find . -name '*.bak' | xargs rm
```

**After (safe):**

```bash
find . -name '*.bak' -print0 | xargs -0 -r rm --
```

Source: https://www.shellcheck.net/wiki/SC2038

## Version notes

- The `--` separator (end-of-options) is honoured by GNU coreutils (`rm`, `mv`, `cp`, `chmod`, `chown`) and prevents filenames starting with `-` from being interpreted as flags. Always include it when working with attacker-influenced filenames.
- `xargs -r` (`--no-run-if-empty`) is GNU-specific; on BSD `xargs`, the equivalent is to pre-check that the input is non-empty (`if [ -n "$(...)" ]`).
- Bash 4.4+ adds `${var@Q}` for POSIX-quoted output of a variable — useful for safe interpolation into eval-via-eval (still discouraged, but if eval is unavoidable, `eval "$(printf '%q ' "${args[@]}")"` is the least-unsafe form).
- Bash 5.2+ improved `printf %q` handling for multi-byte locale characters; older bash may produce incorrectly quoted output for non-ASCII filenames.

## Common false positives

- Unquoted variables that intentionally produce word-splitting (e.g. `compiler_flags="-O2 -Wall"; gcc $compiler_flags ...`) — these are deliberate; downgrade if the surrounding code makes the intent clear.
- `eval` used solely on the output of a known-trusted command (e.g. `eval "$(ssh-agent -s)"`) — the input is from a system binary, not user data; downgrade to INFO.
- Shell scripts under `tests/fixtures/` that are intentionally vulnerable as fixtures for sec-review's own validation — annotate; downgrade to INFO unless mistakenly shipped to production.
- `bash -c` invocations with hard-coded constant strings (no variable interpolation) — the shell has no injection surface; flag only when interpolation is present.
