# C/C++ Memory Safety & Banned-Function Surface

## Source

- https://cwe.mitre.org/data/definitions/120.html — CWE-120 Classic Buffer Overflow (and the CWE-119 family)
- https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard — SEI CERT C Coding Standard (STR/ARR/MEM/FIO rules)
- https://owasp.org/www-community/vulnerabilities/Buffer_Overflow — OWASP Buffer Overflow
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/security-enhanced-versions-of-crt-functions — the `_s` "secure" CRT replacements (MS-banned list)
- https://man7.org/linux/man-pages/man3/gets.3.html — `gets(3)` (removed from C11; never safe)
- https://cwe.mitre.org/ — CWE index

## Scope

The two surfaces the `c-cpp` lane's tools cover: (1) **memory-safety** defects
cppcheck proves by data-flow — buffer overruns, leaks, use-after-free,
uninitialised reads, null-deref; and (2) the **banned-libc-function** family
flawfinder flags lexically — `strcpy`/`strcat`/`sprintf`/`gets`/`scanf`/
`system`/`exec*`/`printf`-as-format. This pack is the pattern reference the
sec-expert reads to reason about a finding (is this reachable with attacker
input? is the fixed-size buffer actually bounded upstream?) that the tools
cannot decide, plus the quoted fix recipes. Out of scope: compiled-binary
hardening (the `windows`/`linux` lanes' RELRO/stack-canary/PIE checks run on
built ELF/PE), and C/C++ dependency CVEs (no manifest for cve-enricher).

## Dangerous patterns (regex/AST hints)

### Unbounded string copy — `strcpy` / `strcat` — CWE-120

- Why: `strcpy(dst, src)` copies until `src`'s NUL with no bound on `dst`'s
  size; an `src` longer than `dst` overruns the buffer (stack-smash → control-
  flow hijack, or heap corruption). cppcheck proves the overflow when `src` is a
  literal; flawfinder flags every call regardless of provability.
- Grep: `\bstrcpy\s*\(` / `\bstrcat\s*\(`
- Tools: flawfinder `buffer/strcpy` (CWE-120); cppcheck `bufferAccessOutOfBounds`
  (CWE-788) when provable.
- Source: https://wiki.sei.cmu.edu/confluence/display/c/STR31-C

### `gets` — unbounded stdin read — CWE-120 / CWE-242

- Why: `gets(buf)` reads a line from stdin with NO size argument — it cannot be
  used safely and was removed from C11. Any input longer than `buf` overruns it.
- Grep: `\bgets\s*\(`
- Tools: cppcheck `getsCalled` (CWE-477 obsolete-function); flawfinder
  `buffer/gets` (CWE-120).
- Source: https://man7.org/linux/man-pages/man3/gets.3.html

### `sprintf` into a fixed buffer — CWE-120

- Why: `sprintf(buf, fmt, ...)` writes an unbounded number of bytes into `buf`;
  a `%s` of attacker-controlled length overruns it. Use `snprintf(buf,
  sizeof buf, ...)`.
- Grep: `\bsprintf\s*\(` / `\bvsprintf\s*\(`
- Tools: flawfinder `buffer/sprintf` (CWE-120).
- Source: https://wiki.sei.cmu.edu/confluence/display/c/FIO47-C

### Command execution — `system` / `popen` / `exec*` with built strings — CWE-78

- Why: `system(cmd)` where `cmd` interpolates untrusted input runs it through
  `/bin/sh` — a classic OS-command-injection sink (CWE-78). `popen` and the
  `execl`/`execlp` family with a shell are equivalent hazards.
- Grep: `\bsystem\s*\(` / `\bpopen\s*\(` / `\bexeclp\s*\(`
- Tools: flawfinder `shell/system` (CWE-78).
- Source: https://cwe.mitre.org/data/definitions/78.html

### Format string from a non-literal — CWE-134

- Why: `printf(buf)` / `fprintf(f, buf)` / `syslog(pri, buf)` where `buf` is
  user-influenced lets an attacker inject `%n`/`%x` conversions to read or write
  memory. The format string must always be a literal; use `printf("%s", buf)`.
- Grep: `\bprintf\s*\(\s*[A-Za-z_]` (first arg is a variable, not a string literal)
- Tools: flawfinder `format/printf` (CWE-134).
- Source: https://cwe.mitre.org/data/definitions/134.html

### Memory leak / use-after-free / double-free — CWE-401 / CWE-416 / CWE-415

- Why: an allocation (`malloc`/`calloc`/`new`) whose owning pointer goes out of
  scope without `free`/`delete` leaks (CWE-401); using or freeing a pointer
  after it was freed is a use-after-free (CWE-416) / double-free (CWE-415) —
  both are exploitable heap-corruption primitives. cppcheck's data-flow tracks
  allocation lifetimes.
- Tools: cppcheck `memleak` (CWE-401), `useAfterFree` (CWE-416),
  `doubleFree` (CWE-415).
- Source: https://wiki.sei.cmu.edu/confluence/display/c/MEM31-C

## Secure patterns

Bounded copies and a literal format string:

```c
#include <stdio.h>
#include <string.h>

void handle(const char *user) {
    char buf[64];
    /* Bounded copy — never overruns buf. */
    snprintf(buf, sizeof buf, "%s", user);

    /* Never build a shell command from input; avoid system() entirely.
       If you must exec, use execve with an argv array (no shell). */
    char *const argv[] = { "/bin/ls", "--", (char *)user, NULL };
    /* fork()+execve(argv[0], argv, envp) — no /bin/sh, no injection. */

    /* Literal format string. */
    printf("%s\n", buf);
}
```

Source: https://wiki.sei.cmu.edu/confluence/display/c/STR31-C

## Fix recipes

### Recipe: Replace `strcpy` with a bounded copy — addresses CWE-120

**Before (dangerous):**

```c
char buf[8];
strcpy(buf, user);          /* overruns buf if user > 7 chars */
```

**After (safe):**

```c
char buf[8];
snprintf(buf, sizeof buf, "%s", user);   /* truncates, never overruns */
/* or, when truncation is unacceptable, allocate to strlen(user)+1 */
```

Source: https://wiki.sei.cmu.edu/confluence/display/c/STR31-C

### Recipe: Replace `system` with `execve` (no shell) — addresses CWE-78

**Before (dangerous):**

```c
char cmd[128];
sprintf(cmd, "ls %s", user);
system(cmd);                 /* /bin/sh -c "ls <user>" — injectable */
```

**After (safe):**

```c
pid_t pid = fork();
if (pid == 0) {
    char *const argv[] = { "/bin/ls", "--", (char *)user, NULL };
    execve("/bin/ls", argv, environ);   /* no shell → no injection */
    _exit(127);
}
```

Source: https://cwe.mitre.org/data/definitions/78.html

## Version notes

- C11 removed `gets` entirely; `gets_s` (Annex K) is the bounded replacement but
  is not universally implemented — `fgets(buf, sizeof buf, stdin)` is the
  portable choice.
- The MS-banned-function list (`strcpy`/`strcat`/`sprintf`/`scanf`/…) maps to
  `_s` "secure" CRT variants on Windows; on POSIX prefer the `snprintf`/`strlcpy`
  (BSD) / explicit-length idioms.
- cppcheck's `--enable=all` adds `style`/`information`; the lane deliberately
  runs only `warning,portability` to keep signal high.

## Common false positives

- A `strcpy` into a buffer provably sized to `strlen(src)+1` immediately above —
  cppcheck won't flag it, but flawfinder (lexical) will; down-rank when the
  bound is visible and correct.
- A `system`/`exec*` call with a **fully literal** argument (no interpolation) —
  still a code-smell, but not injectable; treat as LOW.
- A hazardous call inside a `#if 0` block or a demonstrably unreachable branch —
  flawfinder scans dead code; confirm reachability before ranking HIGH.
- `printf(gettext("..."))` — the format string is a translated *literal*, not
  attacker-controlled; a known flawfinder FP for i18n'd code.
