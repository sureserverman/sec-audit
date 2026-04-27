# WebExt Tools

## Source

- https://github.com/mozilla/addons-linter — addons-linter source repo (README + docs/rules.md)
- https://extensionworkshop.com/documentation/develop/web-ext-command-reference/ — web-ext CLI reference (official)
- https://github.com/mozilla/web-ext — web-ext source repo
- https://retirejs.github.io/retire.js/ — retire.js documentation (official)
- https://github.com/RetireJS/retire.js — retire.js source repo
- https://cwe.mitre.org/ — CWE index (for mapping tool rules to CWEs)

## Scope

This reference pack documents the three WebExt-lane binaries invoked by the
`webext-runner` sub-agent (addons-linter, web-ext lint, and retire.js). It
specifies canonical CLI invocations, JSON output schemas, field mappings to
sec-audit's finding schema, and offline-degrade rules. Out of scope:
AMO submission workflows, browser-specific compatibility testing beyond
linting, active network-based extension testing, and other extension-security
tools — deferred to future versions. This pack documents how the
`webext-runner` sub-agent invokes each tool, not anti-patterns in user code.

## Dangerous patterns

> **Operational sentinel:** This file describes how to invoke external WebExt
> security binaries, not source code under review. Suppress grep/AST matches
> for the invocation strings below when the enclosing file path is
> `references/webext-tools.md`. This section lists "invocations that go
> wrong" — the anti-patterns apply to scripts and CI config that shell out to
> `addons-linter`, `web-ext lint`, or `retire`, not to product code.

### Running addons-linter without --output json — CWE-1188

- Why: Without `--output json`, addons-linter writes a human-readable table
  to stdout. That format is not a stable contract; column widths, colour
  codes, and wording change across versions. Regex-parsing it produces empty
  finding sets that look like "clean scan." The `webext-runner` agent MUST
  request structured output on every invocation.
- Grep: `addons-linter\s+(?!.*--output\s+json)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`,
  `.github/workflows/*.yml`
- Source: https://github.com/mozilla/addons-linter

### Running web-ext lint without --output=json — CWE-1188

- Why: Same contract as addons-linter — web-ext lint's default text output
  is human-oriented and changes across releases. The runner MUST pass
  `--output=json` to get a stable, parseable shape.
- Grep: `web-ext\s+lint\s+(?!.*--output=json|.*--output\s+json)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`,
  `.github/workflows/*.yml`
- Source: https://extensionworkshop.com/documentation/develop/web-ext-command-reference/

### Running web-ext lint without --no-config-discovery — CWE-1188

- Why: Without `--no-config-discovery`, web-ext reads any `.web-ext.yml` or
  `package.json#web-ext` config it finds walking up the directory tree.
  An ambient config can silently override `--output=json`, `--source-dir`,
  or ignore-lists, making the scan non-deterministic across machines.
- Grep: `web-ext\s+lint\s+(?!.*--no-config-discovery)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`
- Source: https://extensionworkshop.com/documentation/develop/web-ext-command-reference/

### Running retire without JSON output — CWE-1188

- Why: retire.js's default output is a terminal-oriented text table.
  Parsing it with regex produces empty or inaccurate results on version
  upgrades. The runner MUST request JSON output explicitly (`--outputformat
  json --outputpath -` or `-f json`).
- Grep: `retire\s+(?!.*--outputformat\s+json|.*-f\s+json)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`
- Source: https://retirejs.github.io/retire.js/

### Running retire without --path — CWE-754

- Why: Without `--path`, retire.js scans the current working directory.
  Scripts that invoke `retire` without anchoring the path silently scan
  the wrong tree (e.g. the plugin itself rather than the target extension),
  producing a misleading clean result for the actual target.
- Grep: `retire\s+(?!.*--path\s|.*-p\s)`
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Makefile`
- Source: https://retirejs.github.io/retire.js/

## Secure patterns

Canonical invocations for the `webext-runner` agent. Each is the minimum
correct form — callers may add `--warnings-as-errors`, `--self-hosted`, or
targeting flags, but MUST NOT drop any flag shown here.

```bash
# addons-linter baseline — JSON to stdout, run against an extension
# directory or a .zip file.
addons-linter --output json <path-to-extension-dir-or-zip>
```

Source: https://github.com/mozilla/addons-linter

```bash
# web-ext lint baseline — JSON to stdout, source dir explicit, no ambient
# config, deterministic across machines.
web-ext lint \
  --source-dir=<path> \
  --output=json \
  --no-config-discovery
```

Source: https://extensionworkshop.com/documentation/develop/web-ext-command-reference/

```bash
# retire.js baseline — JSON to stdout (outputpath "-"), anchored to the
# extension path. retire exits 0 when no vulnerable components are found
# and 13 when vulnerabilities are detected; both produce valid JSON.
retire \
  --path <path> \
  --outputformat json \
  --outputpath -
```

Source: https://retirejs.github.io/retire.js/

```bash
# Non-gating CI — run all three tools, always continue regardless of
# exit code, let the parser decide severity. retire --js is a useful
# scoping flag when the target is a packed extension with no node_modules.
addons-linter --output json <path> ; al_rc=$?
web-ext lint --source-dir=<path> --output=json --no-config-discovery ; we_rc=$?
retire --path <path> --outputformat json --outputpath - ; re_rc=$?
# The runner reads al_rc/we_rc/re_rc to distinguish "no findings" (0 or 13)
# from genuine tool failures.
```

Source: https://github.com/mozilla/addons-linter,
https://extensionworkshop.com/documentation/develop/web-ext-command-reference/,
https://retirejs.github.io/retire.js/

## Canonical invocations

### addons-linter

**Install:** `npm install -g addons-linter` (requires Node.js ≥ 18).

**Run command:**

```bash
addons-linter --output json <path-to-extension-dir-or-zip>
```

Prints JSON to stdout. Exits 0 whether or not there are messages — all
signal is in the JSON body. Non-zero exit means addons-linter itself
failed (bad path, internal error).

**Expected JSON output shape:**

```json
{
  "summary": {
    "errors": 2,
    "notices": 1,
    "warnings": 3,
    "signing_summary": {}
  },
  "errors": [
    {
      "type": "error",
      "code": "MANIFEST_CSP",
      "message": "content_security_policy is not allowed",
      "description": "Remove the content_security_policy key from manifest.json",
      "file": "manifest.json",
      "line": 12,
      "column": 3
    }
  ],
  "warnings": [],
  "notices": []
}
```

Top-level keys: `summary`, `errors[]`, `warnings[]`, `notices[]`. Each
message object carries `type`, `code`, `message`, `description`, `file`,
and optionally `line` and `column`.

**Worked example:**

```bash
# Lint an unpacked extension directory
addons-linter --output json ./my-extension/

# Lint a packaged .zip
addons-linter --output json my-extension-1.0.zip
```

Source: https://github.com/mozilla/addons-linter

### web-ext lint

**Install:** `npm install -g web-ext` (requires Node.js ≥ 18).

**Run command:**

```bash
web-ext lint \
  --source-dir=<path> \
  --output=json \
  --no-config-discovery
```

Prints JSON to stdout. Uses addons-linter internally; the output schema
is identical — `summary`, `errors[]`, `warnings[]`, `notices[]` — with
the same per-message fields (`type`, `code`, `message`, `description`,
`file`, `line`, `column`).

**Expected JSON output shape:**

```json
{
  "summary": {
    "errors": 0,
    "notices": 2,
    "warnings": 1
  },
  "errors": [],
  "warnings": [
    {
      "type": "warning",
      "code": "PERMISSIONS_REQUIRED_UNKNOWN",
      "message": "An unknown permission was found in the manifest",
      "description": "Remove the unrecognised permission from permissions[]",
      "file": "manifest.json",
      "line": 7,
      "column": 5
    }
  ],
  "notices": []
}
```

**Worked example:**

```bash
# Lint a source directory, no ambient config, JSON to stdout
web-ext lint \
  --source-dir=./my-extension \
  --output=json \
  --no-config-discovery

# Firefox for Android target (stricter set of allowed APIs)
web-ext lint \
  --source-dir=./my-extension \
  --target=firefox-android \
  --output=json \
  --no-config-discovery

# Self-hosted extension (AMO signing rules suppressed)
web-ext lint \
  --source-dir=./my-extension \
  --self-hosted \
  --output=json \
  --no-config-discovery
```

Source: https://extensionworkshop.com/documentation/develop/web-ext-command-reference/

### retire.js

**Install:** `npm install -g retire` (requires Node.js ≥ 18).

**Run command:**

```bash
retire --path <path> --outputformat json --outputpath -
```

Writes JSON to stdout (the `-` in `--outputpath` means stdout). Exits 0
when no vulnerable components are detected, 13 when vulnerabilities are
found, and other non-zero values for tool errors (e.g. path not found).
Both exit codes 0 and 13 produce valid JSON output.

**Expected JSON output shape:**

```json
[
  {
    "file": "my-extension/vendor/jquery-3.1.0.min.js",
    "component": "jquery",
    "version": "3.1.0",
    "vulnerabilities": [
      {
        "info": ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"],
        "below": "3.5.0",
        "severity": "medium",
        "identifiers": {
          "CVE": ["CVE-2020-11022", "CVE-2020-11023"],
          "summary": "Passing HTML from untrusted sources can lead to XSS"
        }
      }
    ]
  }
]
```

Top-level: an array of objects, each with `file`, `component`, `version`,
and `vulnerabilities[]`. Each vulnerability has `info[]` (advisory URLs),
`severity` (string: `critical`/`high`/`medium`/`low`), and `identifiers`
containing `CVE[]` and `summary`.

**Worked example:**

```bash
# Scan bundled JavaScript in an extension directory
retire --path ./my-extension --outputformat json --outputpath -

# Short form equivalent
retire -p ./my-extension -f json
```

Source: https://retirejs.github.io/retire.js/, https://github.com/RetireJS/retire.js

## Output-field mapping

### addons-linter → sec-audit finding

| addons-linter JSON field | sec-audit finding field | Notes                                                                                    |
|--------------------------|--------------------------|------------------------------------------------------------------------------------------|
| `code`                   | `id`                     | Rule code string, e.g. `MANIFEST_CSP`                                                   |
| `type`                   | `severity`               | `"error"` → `HIGH`, `"warning"` → `MEDIUM`, `"notice"` → `LOW`                          |
| (see notes)              | `cwe`                    | Best-effort: `null` unless the `code` is an explicit security rule (see CWE note below)  |
| `message`                | `title`                  | Short human-readable description                                                         |
| `description`            | `fix_recipe`             | Upstream `description` field quoted verbatim                                             |
| `file`                   | `file`                   | Path as addons-linter reports it, relative to the scanned root                          |
| `line`                   | `line`                   | 1-indexed; emit `0` when absent (field is optional)                                      |
| `description`            | `evidence`               | Same string as `fix_recipe`; keeps both fields populated per schema                      |
| (constant)               | `reference_url`          | `null` — addons-linter messages do not carry per-finding URLs                            |

Constants on every addons-linter finding:

- `origin: "webext"`
- `tool: "addons-linter"`
- `reference: "webext-tools.md"`
- `confidence: "medium"`

**CWE mapping note for addons-linter:** The tool covers both policy/packaging
rules and security rules. CWE is left `null` for most findings because the
rule codes address manifest conformance, not specific vulnerability classes.
Exception table (extend as new security-specific codes are confirmed):

| Rule code                       | CWE     | Source                                                        |
|---------------------------------|---------|---------------------------------------------------------------|
| `MANIFEST_CSP`                  | CWE-693 | Policy violation: missing protection mechanism (CSP weakened) |
| `DANGEROUS_EVAL`                | CWE-95  | Eval injection                                                |
| `UNSAFE_VAR_ASSIGNMENT`         | CWE-79  | Cross-site scripting (reflected assignment to innerHTML)      |

If a `code` is not in this table, emit `cwe: null`. Do not guess.

Source: https://github.com/mozilla/addons-linter

### web-ext lint → sec-audit finding

web-ext lint wraps addons-linter and emits the same JSON schema. Apply the
identical field mapping as the addons-linter table above, with one change to
the constants:

- `tool: "web-ext"` (not `"addons-linter"`)
- All other constants remain: `origin: "webext"`, `reference: "webext-tools.md"`,
  `confidence: "medium"`

The `type` → `severity` mapping is identical: `"error"` → `HIGH`,
`"warning"` → `MEDIUM`, `"notice"` → `LOW`. The CWE exception table is
also identical — it describes rules by `code`, which is the same string in
both tools.

Source: https://extensionworkshop.com/documentation/develop/web-ext-command-reference/

### retire.js → sec-audit finding

retire.js emits one array element per vulnerable component/file pair. When a
component has multiple vulnerabilities, emit one sec-audit finding per
vulnerability entry.

| retire.js JSON field                         | sec-audit finding field | Notes                                                                                            |
|----------------------------------------------|--------------------------|--------------------------------------------------------------------------------------------------|
| `component` + `"@"` + `version`              | `id`                     | Synthesised, e.g. `"jquery@3.1.0"` — retire has no rule-code concept                            |
| `vulnerabilities[n].severity`                | `severity`               | `"critical"` → `CRITICAL`, `"high"` → `HIGH`, `"medium"` → `MEDIUM`, `"low"` → `LOW`            |
| (see notes)                                  | `cwe`                    | Derived from `identifiers.CVE[]` advisory if present; else `CWE-1104` as default (see below)    |
| `vulnerabilities[n].identifiers.summary`     | `title`                  | Short vulnerability summary string                                                               |
| `vulnerabilities[n].identifiers.summary`     | `evidence`               | Same string as `title`; keep both for schema consistency                                         |
| `file`                                       | `file`                   | Path to the bundled JS file containing the vulnerable library                                    |
| (constant)                                   | `line`                   | `0` — retire.js reports at file level, not line level                                            |
| `vulnerabilities[n].info[0]`                 | `reference_url`          | First advisory URL; `null` if the list is empty or absent                                        |
| (see notes)                                  | `fix_recipe`             | `"Upgrade <component> to a version above <below>."` synthesised from the `below` field           |

Constants on every retire.js finding:

- `origin: "webext"`
- `tool: "retire"`
- `reference: "webext-tools.md"`
- `confidence: "high"` — version matches are deterministic; retire does not
  use heuristics

**CWE derivation for retire.js:** retire advisories include CVE identifiers
in `identifiers.CVE[]`. When at least one CVE is present, the runner should
note it in a `notes` field (e.g. `"CVE-2020-11022"`) but cannot reliably
derive a CWE from a CVE without an NVD lookup — therefore emit `CWE-1104`
("Use of Unmaintained Third-Party Components") as a safe, honest default for
all retire.js findings, regardless of whether a CVE is present. Reviewers who
want the specific CWE should follow the `reference_url` advisory.

Source: https://retirejs.github.io/retire.js/, https://cwe.mitre.org/

## Fix recipes

These recipes document the contract between the `webext-runner` sub-agent
and the rest of the sec-audit pipeline. They are NOT fix recipes in the
user-code sense; each recipe specifies how each tool's native JSON maps into
sec-audit's canonical finding schema.

### Recipe: addons-linter / web-ext finding → sec-audit finding

addons-linter and web-ext lint produce `errors[]`, `warnings[]`, and
`notices[]` arrays. Iterate all three arrays, tagging each item with its
parent array's `type` value. Emit one sec-audit finding per item.

Per-message shape (addons-linter; identical for web-ext):

```json
{
  "type": "error",
  "code": "MANIFEST_CSP",
  "message": "content_security_policy is not allowed",
  "description": "Remove the content_security_policy key from manifest.json",
  "file": "manifest.json",
  "line": 12,
  "column": 3
}
```

Maps to:

```json
{
  "id":            "MANIFEST_CSP",
  "severity":      "HIGH",
  "cwe":           "CWE-693",
  "title":         "content_security_policy is not allowed",
  "file":          "manifest.json",
  "line":          12,
  "evidence":      "Remove the content_security_policy key from manifest.json",
  "reference":     "webext-tools.md",
  "reference_url": null,
  "fix_recipe":    "Remove the content_security_policy key from manifest.json",
  "confidence":    "medium",
  "origin":        "webext",
  "tool":          "addons-linter"
}
```

### Recipe: retire.js finding → sec-audit finding

retire.js produces an array of component objects, each with a
`vulnerabilities[]` sub-array. Emit one sec-audit finding per
vulnerability.

```json
{
  "file": "my-extension/vendor/jquery-3.1.0.min.js",
  "component": "jquery",
  "version": "3.1.0",
  "vulnerabilities": [
    {
      "info": ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"],
      "below": "3.5.0",
      "severity": "medium",
      "identifiers": {
        "CVE": ["CVE-2020-11022"],
        "summary": "Passing HTML from untrusted sources can lead to XSS"
      }
    }
  ]
}
```

Maps to:

```json
{
  "id":            "jquery@3.1.0",
  "severity":      "MEDIUM",
  "cwe":           "CWE-1104",
  "title":         "Passing HTML from untrusted sources can lead to XSS",
  "file":          "my-extension/vendor/jquery-3.1.0.min.js",
  "line":          0,
  "evidence":      "Passing HTML from untrusted sources can lead to XSS",
  "reference":     "webext-tools.md",
  "reference_url": "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/",
  "fix_recipe":    "Upgrade jquery to a version above 3.5.0.",
  "confidence":    "high",
  "origin":        "webext",
  "tool":          "retire",
  "notes":         "CVE-2020-11022"
}
```

### Recipe: Unavailable-tool sentinel

When NONE of `addons-linter`, `web-ext`, or `retire` is on `PATH`, the
`webext-runner` agent MUST NOT emit any findings and MUST NOT guess. It
emits exactly one line to stdout:

```json
{"__webext_status__": "unavailable", "tools": []}
```

Exit code 0. No findings, no partial results. The downstream aggregator
reads this sentinel and propagates it into the top-level review summary so
that the absence of WebExt findings cannot be misread as a clean WebExt pass.

Source: https://github.com/mozilla/addons-linter,
https://extensionworkshop.com/documentation/develop/web-ext-command-reference/,
https://retirejs.github.io/retire.js/

### Recipe: Status summary line

After all available tools have run and all findings have been emitted, the
`webext-runner` agent emits exactly one final JSON line at the END of stdout
(after every finding):

```json
{"__webext_status__": "ok", "tools": ["addons-linter", "retire"], "runs": 2, "findings": 5}
```

- `tools` is the list of tools that actually executed (omit any that were
  not on `PATH`).
- `runs` is the number of successful tool invocations.
- `findings` is the total count of findings emitted this run (across all
  tools).

This line is mandatory — its absence means the agent crashed mid-run and
the finding set is untrusted.

Source: https://github.com/mozilla/addons-linter,
https://extensionworkshop.com/documentation/develop/web-ext-command-reference/,
https://retirejs.github.io/retire.js/

## Degrade rules

The `webext-runner` agent follows a three-state sentinel contract identical
to the one used by `sast-runner` (`__sast_status__`) and `dast-runner`
(`__dast_status__`).

**State 1 — NONE available:**

If none of `addons-linter`, `web-ext`, or `retire` is on `PATH`, the runner
emits exactly one sentinel line and exits 0:

```json
{"__webext_status__": "unavailable", "tools": []}
```

No findings are emitted. No fabricated results. The sentinel tells the
downstream aggregator that the WebExt lane did not run, so its absence of
findings cannot be misread as a clean pass.

**State 2 — SOME available:**

If at least one tool is on `PATH` but not all three, the runner runs the
available tools, emits their findings, and then emits a partial-status
summary line listing only the tools that actually ran:

```json
{"__webext_status__": "partial", "tools": ["addons-linter", "retire"], "runs": 2, "findings": 3}
```

The `partial` status tells the downstream aggregator that the WebExt lane ran
with reduced coverage — findings from the missing tool(s) are simply absent,
not "clean."

**State 3 — ALL available and successful:**

If all three tools ran and each exited with a documented success code, the
runner emits the standard status line:

```json
{"__webext_status__": "ok", "tools": ["addons-linter", "web-ext", "retire"], "runs": 3, "findings": 12}
```

**Exit-code semantics per tool:**

| Tool           | Success codes | Failure codes (tool errored, not findings found) |
|----------------|---------------|--------------------------------------------------|
| addons-linter  | `0`           | Any other non-zero                               |
| web-ext lint   | `0`           | Any other non-zero                               |
| retire         | `0`, `13`     | Any other non-zero (13 = vulnerabilities found)  |

When a tool was on `PATH` but its run failed (exit code outside the success
set, or its JSON could not be parsed), omit it from the `tools[]` list and
do not emit findings for it. If this exhausts all available tools, emit the
`unavailable` sentinel instead of an `ok` or `partial` line — a tool being
on `PATH` but failing to produce usable output is equivalent to it being
absent for the purposes of the downstream aggregator.

Source: https://github.com/mozilla/addons-linter,
https://extensionworkshop.com/documentation/develop/web-ext-command-reference/,
https://retirejs.github.io/retire.js/

## Common false positives

The `webext-runner` agent emits these findings at their tool-declared
severity, but the triage step SHOULD downgrade or suppress them when the
listed context applies.

- **addons-linter / web-ext `MANIFEST_PERMISSIONS_REQUIRED`** on extensions
  that legitimately need broad permissions (e.g. a developer-tool or proxy
  extension that must access all URLs) — the permission is intentional.
  Downgrade to `info` and annotate with the rationale when the permission is
  documented in the extension's privacy policy or AMO listing.
- **addons-linter / web-ext `UNSAFE_VAR_ASSIGNMENT`** in generated or
  minified third-party bundles under `vendor/`, `dist/`, or `lib/` —
  the bundler produces patterns (e.g. `innerHTML` assignments in templating
  micro-libraries) that are safe in the context of a controlled build. Triage
  separately from hand-written content-script code; suppress when the file is
  a known upstream bundle.
- **retire.js findings on `devDependencies`-only libraries** that were not
  bundled into the final extension — retire.js scans all `.js` files under
  the path, including build tooling. Suppress findings whose `file` path
  resolves to `node_modules/<pkg>` when `<pkg>` is declared only in
  `devDependencies` and the build output does not include it.
- **retire.js low-severity advisories on libraries with no known exploit**
  — `severity: "low"` retire findings are informational and frequently
  represent theoretical issues in code paths the extension does not invoke
  (e.g. a jQuery XSS vector that requires `$.parseHTML` which the extension
  never calls). Downgrade to `info` with a note when the vulnerable API is
  verifiably unreachable from extension entry points.
- **web-ext lint `NOTICE`-type findings on `strict_min_version`** — notices
  about `browser_specific_settings.gecko.strict_min_version` being absent or
  too permissive are packaging hygiene items, not security issues. Suppress
  these from security-focused reports; they belong in a packaging-quality
  checklist instead.

Source: https://github.com/mozilla/addons-linter,
https://retirejs.github.io/retire.js/

## Version pins

Minimum tested versions (Pinned 2026-04 against upstream stable releases;
later upgrades should update this line):

| Tool           | Minimum version | Notes                                                         |
|----------------|-----------------|---------------------------------------------------------------|
| addons-linter  | 7.0.0           | JSON output format stable since 6.x; 7.x is the current line |
| web-ext         | 8.0.0           | Wraps addons-linter ≥ 7.x at this version                     |
| retire         | 5.0.0           | JSON schema stable since 4.x; 5.x is the current line        |

All three install via `npm install -g <tool>` and require Node.js ≥ 18.
The `webext-runner` agent MUST verify each binary's version before use:

```bash
addons-linter --version 2>/dev/null  # expect 7.x or higher
web-ext --version 2>/dev/null        # expect 8.x or higher
retire --version 2>/dev/null         # expect 5.x or higher
```

If a binary is present but reports a version below the minimum, the runner
SHOULD log a warning to stderr (e.g. `webext-runner: addons-linter 5.2.1 is
below minimum 7.0.0 — results may differ`) and proceed rather than refusing,
because older versions still produce parseable JSON. Refuse only when the
tool exits non-zero on `--version`.

Source: https://github.com/mozilla/addons-linter,
https://extensionworkshop.com/documentation/develop/web-ext-command-reference/,
https://retirejs.github.io/retire.js/

## CI notes

These notes apply when the WebExt lane runs inside a GitHub Actions workflow
or equivalent CI system.

- **Node.js version**: pin the runner's `actions/setup-node` step to Node.js
  18 or 20 (LTS). All three tools require Node.js ≥ 18; earlier versions
  produce install errors that look like tool failures rather than environment
  failures.
- **npm global prefix**: in CI, `npm install -g` may write to a path not on
  `PATH`. Either use `$(npm root -g)/../bin/<tool>` as the binary path, or
  add `$(npm bin -g)` to `PATH` in the workflow step.
- **Caching**: retire.js fetches its vulnerability database from
  `https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/`
  on first run. Cache `~/.config/retire/` (or the path reported by
  `retire --help`) between CI runs to avoid a network fetch on every job.
- **Exit-code handling**: retire exits 13 when it finds vulnerabilities.
  Treat this as a data-bearing success, not a tool failure. A naive
  `if [ $? -ne 0 ]; then echo "retire failed"; fi` will silently suppress
  all retire findings. The runner MUST check for exit code 13 explicitly.
- **Parallel invocation**: all three tools are read-only and safe to run in
  parallel against the same extension directory. When wall-clock time
  matters, launch all three simultaneously and collect their outputs.

Source: https://github.com/mozilla/addons-linter,
https://extensionworkshop.com/documentation/develop/web-ext-command-reference/,
https://retirejs.github.io/retire.js/
