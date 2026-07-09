# c-cpp-tools

<!--
    Tool-lane reference for sec-audit's c-cpp lane (v1.26.0+).
    Consumed by the `c-cpp-runner` sub-agent. Documents
    cppcheck + flawfinder.
-->

## Source

- https://cppcheck.sourceforge.io/ — cppcheck canonical (C/C++ static analyzer)
- https://cppcheck.sourceforge.io/manual.pdf — cppcheck manual (`--enable`, `--xml`, severity vocabulary, CWE mapping)
- https://dwheeler.com/flawfinder/ — flawfinder canonical (David A. Wheeler; lexical security scanner for the banned-libc-function family)
- https://cwe.mitre.org/ — CWE catalogue (both tools emit CWE ids)

## Scope

In-scope: the two tools invoked by `c-cpp-runner` — `cppcheck` (data-flow
static analyzer: buffer overruns, memory leaks, use-after-free, null-pointer
deref, uninitialised reads, integer overflow) and `flawfinder` (lexical
pattern scanner for the dangerous-libc-function family: `strcpy`, `gets`,
`sprintf`, `system`, `printf`-family format strings). Both are cross-platform
(apt / pip installable) and static — neither compiles nor executes the target.
Complementary by design: cppcheck reasons about program semantics (it proves a
literal overruns `buf`); flawfinder flags every call to a hazardous function
regardless of context (higher recall, lower precision). Out of scope:
compiled-binary review (the `windows` lane's binskim runs on PE artefacts;
this lane is source-only), `clang-tidy` / `clang-analyzer` (heavier, needs a
compilation database — deferred), and C/C++ dependency CVEs (no manifest;
system-package / vendored-tree dependency management is out-of-band).

## Canonical invocations

### cppcheck

- Install: `apt install cppcheck` (Debian/Ubuntu) / `dnf install cppcheck`
  (Fedora) / `brew install cppcheck` (macOS). Cross-platform.
- Invocation:
  ```bash
  cppcheck --xml --enable=warning,portability --inline-suppr \
      --output-file="$TMPDIR/cppcheck.xml" "$target_path"
  ```
  `--enable=warning,portability` adds the warning + portability checks on top of
  the always-on `error` checks (buffer overrun, memory leak, use-after-free,
  null deref) while excluding the noisier `style`/`information` classes.
  `--inline-suppr` honours in-source `// cppcheck-suppress` comments.
- Output: XML to `--output-file` (cppcheck writes diagnostics to stderr by
  default; `--output-file` captures the XML deterministically). Structure:
  `<results><errors><error id= severity= msg= verbose= cwe= file0=>`
  `<location file= line= column=/></error></errors></results>`. `severity` ∈
  `error` / `warning` / `style` / `performance` / `portability` / `information`.
  The `cwe` attribute carries the numeric CWE (e.g. `788`, `401`, `477`).
- Tool behaviour: exits 0 even when issues are found (issues go to the XML, not
  the exit code) unless `--error-exitcode` is set — the runner does NOT set it,
  so a non-empty `<errors>` with exit 0 is the normal path.
- Primary source: https://cppcheck.sourceforge.io/manual.pdf

Source: https://cppcheck.sourceforge.io/

### flawfinder

- Install: `apt install flawfinder` / `pip install flawfinder`. Cross-platform
  (pure Python).
- Invocation:
  ```bash
  flawfinder --sarif --minlevel=2 "$target_path" > "$TMPDIR/flawfinder.sarif"
  ```
  `--minlevel=2` drops the level-0/1 noise (very-low-risk hits) while keeping
  levels 2–5 (the exploitable-function surface). `--sarif` emits SARIF 2.1.0.
- Output: SARIF JSON. `runs[0].results[]` — each result has `ruleId`
  (`FF<n>`, e.g. `FF1044` for `system`), `level` (`note` / `warning` /
  `error`), `message.text` (carries the function name and the canonical
  `(CWE-<n>)`), and `locations[0].physicalLocation` (`artifactLocation.uri`,
  `region.startLine`). The runner extracts the CWE from `message.text` with a
  `CWE-[0-9]+` regex.
- Tool behaviour: exits non-zero when hits are found; NOT a crash — read the
  SARIF regardless. Pure-lexical, so it flags hazardous calls even in dead code
  (a known FP class — the triager down-ranks these).
- Primary source: https://dwheeler.com/flawfinder/

Source: https://dwheeler.com/flawfinder/

## Output-field mapping

Every finding carries `origin: "c-cpp"`,
`tool: "cppcheck" | "flawfinder"`, `reference: "c-cpp-tools.md"`.

### cppcheck → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"cppcheck:" + .id`                                   | `id`                         |
| `.severity` remap: `error` → HIGH, `warning` → MEDIUM, `performance`/`portability`/`style`/`information` → LOW | `severity` |
| `"CWE-" + .cwe` (verbatim `cwe` attribute; `null` when absent) | `cwe`               |
| `.msg`                                                | `title`                      |
| `.location.file`                                      | `file`                       |
| `.location.line` (coerced to int)                     | `line`                       |
| `.verbose` (truncated to 200 chars)                   | `evidence`                   |
| null (cppcheck ships no per-rule fix URL in XML)      | `reference_url`              |
| null                                                  | `fix_recipe`                 |
| `"high"` (data-flow analysis — low FP for `error` class) | `confidence`             |

### flawfinder → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"flawfinder:" + .ruleId`                             | `id`                         |
| `.level` remap: `error` → HIGH, `warning` → MEDIUM, `note` → LOW | `severity`        |
| `CWE-<n>` regex-extracted from `.message.text` (or `null`) | `cwe`                   |
| `.message.text` (truncated to 120 chars)              | `title`                      |
| `.locations[0].physicalLocation.artifactLocation.uri` | `file`                       |
| `.locations[0].physicalLocation.region.startLine`     | `line`                       |
| `.message.text` (truncated to 200 chars)              | `evidence`                   |
| null                                                  | `reference_url`              |
| null                                                  | `fix_recipe`                 |
| `"medium"` (lexical — higher recall, more FPs than cppcheck) | `confidence`          |

## Degrade rules

`__c_cpp_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary:

- `tool-missing` — the tool's binary is absent from PATH.
- `no-c-source` — the tool is on PATH but the target tree contains no
  `*.c` / `*.cc` / `*.cpp` / `*.cxx` / `*.c++` / `*.h` / `*.hpp` / `*.hxx`
  files. Target-shape clean-skip. (Note: the §2 inventory gate is *stricter* —
  it requires a translation-unit source file, not a header, before dispatching
  the lane at all; the runner's glob is broader so a direct header-only run
  still scans.)

No host-OS gate — both tools are cross-platform with no
`requires-<host>-host` precondition.

## Version pins

- `cppcheck` ≥ 2.10 (stable XML `version="2"` schema; `cwe` attribute on
  errors; `--enable`/`--inline-suppr`/`--output-file` flags fixed). Pinned
  2026-07 (2.13.0).
- `flawfinder` ≥ 2.0.19 (stable SARIF 2.1.0 exporter; `ruleId`/`level`/
  `message.text` with embedded `(CWE-<n>)`; `--sarif`/`--minlevel` flags).
  Pinned 2026-07.
