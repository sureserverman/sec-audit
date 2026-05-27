# Deep-Deps Tools (release-diff mechanics)

## Source

- https://docs.pypi.org/api/json/ — PyPI JSON API (`/pypi/<name>/json`: releases, artifact URLs, upload times)
- https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md — npm registry package-metadata document (versions, `dist.tarball`, `time`)
- https://github.com/ossf/malicious-packages — OpenSSF Malicious Packages (real compromised-release exemplars)
- https://github.com/elastic/supply-chain-monitor — the release-diff + classification technique this lane ports
- https://peps.python.org/pep-0440/ — PEP 440 version ordering (for selecting the prior PyPI version)
- https://semver.org/ — semantic versioning (for selecting the prior npm version)
- https://cwe.mitre.org/ — CWE index

## Scope

Mechanics for the `dep-diff-analyst` agent (`--deep-deps` lane): how to fetch a
dependency's installed version N and its immediately-prior published version
N-1 directly from PyPI / npm (no `pip` / `npm install`), build a bounded
unified diff, and map a verdict to a sec-audit finding. The *heuristic
catalogue* (what malicious changes look like) is NOT duplicated here — the
analyst reuses `references/supply-chain/malicious-packages.md`. Out of scope:
ecosystems beyond PyPI/npm (Go, crates.io, Maven diffing is a future lane),
transitive-graph traversal (the supply-chain lane + cve-enricher own that), and
running package code (diff is static).

## Dangerous patterns (regex/AST hints)

> **Operational sentinel:** This file describes how to fetch and diff package
> releases, not source under review. Suppress grep/AST matches for the
> invocation strings below when the enclosing file path is
> `references/deep-deps-tools.md`.

### Installing the package to diff it — CWE-829

- Why: running `pip install` / `npm install <name>` to obtain the sources
  executes the package's own install hooks / `setup.py` — i.e. it runs the very
  malware you are trying to inspect, on the auditor's machine. The analyst MUST
  fetch the artifact URL and extract it inertly (`tar`/`unzip`), never install.
- Grep: `pip\s+install\s+|npm\s+install\s+[^-]`
- File globs: `**/*.sh`, `**/*.md`
- Source: https://github.com/ossf/malicious-packages

### Unbounded diff fed to the model — CWE-400

- Why: a release that adds a huge vendored blob produces a multi-megabyte diff
  that blows the analyst's context and cost. The diff MUST be truncated to the
  size budget below before classification.
- Grep: `diff\s+-ruN(?!.*head|.*-c\s)`
- File globs: `**/*.sh`, `**/*.md`
- Source: https://github.com/elastic/supply-chain-monitor

## Secure patterns

```bash
# PyPI — resolve artifact URLs (no auth, no pip). Pick the sdist for the
# installed version and for the highest PEP440 release strictly below it.
curl -sf "https://pypi.org/pypi/${NAME}/json" \
  | jq -r '.releases | to_entries[]
           | select(.value[]?.packagetype=="sdist")
           | "\(.key)\t\(.value[] | select(.packagetype=="sdist") | .url)"'
```

Source: https://docs.pypi.org/api/json/

```bash
# npm — resolve tarball URLs (no auth, no npm). Prior version = highest semver
# below the installed one; .time disambiguates.
curl -sf "https://registry.npmjs.org/${NAME}" \
  | jq -r '.versions | to_entries[] | "\(.key)\t\(.value.dist.tarball)"'
```

Source: https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md

```bash
# Download + extract + bounded diff. Budget: 4000 lines OR 256 KiB, whichever
# first — truncate and set notes."truncated": true when hit.
mkdir -p "$TMPDIR/old" "$TMPDIR/new"
curl -sf "$OLD_URL" -o "$TMPDIR/old.archive" && tar -xf "$TMPDIR/old.archive" -C "$TMPDIR/old" 2>/dev/null || unzip -q "$TMPDIR/old.archive" -d "$TMPDIR/old"
curl -sf "$NEW_URL" -o "$TMPDIR/new.archive" && tar -xf "$TMPDIR/new.archive" -C "$TMPDIR/new" 2>/dev/null || unzip -q "$TMPDIR/new.archive" -d "$TMPDIR/new"
diff -ruN "$TMPDIR/old" "$TMPDIR/new" | head -c 262144 | head -n 4000
```

Source: https://github.com/elastic/supply-chain-monitor

## Fix recipes

These map the analyst's verdict into sec-audit's finding schema — they are not
user-code fix recipes.

### Recipe: Verdict rubric

Classify the N-1 → N diff:

- **malicious** (⇒ `severity: CRITICAL`, `confidence: high`): the diff
  *introduces* a clear attack primitive absent in N-1 — a new install hook
  (`postinstall`/`preinstall`/`setup.py` shelling out), a newly-added
  `exec`/`eval` of base64/hex-decoded data, a new outbound connection to a
  hardcoded host exfiltrating env/credentials/wallet data, download-and-exec, or
  added bidirectional-control characters. CWE per the
  `malicious-packages.md` class (CWE-506 / CWE-94 / CWE-494 / CWE-200 /
  CWE-1007).
- **suspicious** (⇒ `severity: HIGH` if a network/exec sink is touched, else
  `MEDIUM`; `confidence: medium`): the diff shows a *concerning but not
  conclusive* change — new obfuscation, a new dependency on a networking
  library in a previously-pure-utility package, large minified additions, or a
  maintainer/email change alongside behavioral edits. `cwe: null` allowed.
- **benign** (no finding emitted): ordinary feature/bugfix/version-bump churn,
  docs, tests, dependency-range updates with no new sink. Counted only in the
  status line.

Every malicious/suspicious finding MUST quote the triggering hunk verbatim in
`evidence`. No quotable hunk ⇒ downgrade to `benign` or `skipped[]`, never a
bare assertion.

Source: https://github.com/ossf/malicious-packages,
https://github.com/elastic/supply-chain-monitor

### Recipe: Verdict → sec-audit finding

| Source                          | sec-audit field | Notes                                          |
|---------------------------------|------------------|------------------------------------------------|
| `deep-deps:<eco>/<name>@<ver>`  | `id`             | Synthetic, stable per candidate                |
| verdict → severity (rubric)     | `severity`       | malicious=CRITICAL; suspicious=HIGH/MEDIUM     |
| triggering class                | `cwe`            | CWE-506/94/494/200/1007, or null               |
| one-line verdict summary        | `title`          |                                                |
| `<eco>/<name>@<ver> (vs <prior>)`| `file`          | Package coordinate + prior version diffed      |
| quoted diff hunk / added path   | `evidence`       | Verbatim from `diff -ruN`                      |
| registry artifact / advisory URL| `reference_url`  | or null                                        |

Constants: `origin: "deep-deps"`, `tool: "dep-diff"`,
`reference: "deep-deps-tools.md"`, `fix_recipe: null`, `line: 1`,
`verdict: "malicious" | "suspicious"`.

Source: https://docs.pypi.org/api/json/

### Recipe: Unavailable sentinel

Empty candidate list, OR every registry fetch failed:

```json
{"__deep_deps_status__": "unavailable", "tools": []}
```

Exit 0, no findings.

Source: https://github.com/elastic/supply-chain-monitor

### Recipe: Status summary line

```json
{"__deep_deps_status__": "ok", "tools": ["dep-diff"], "analyzed": 7, "findings": 2, "skipped": [{"tool": "dep-diff", "reason": "no-prior-version"}]}
```

`ok` = ≥1 candidate diffed; `partial` = some diffed, some skipped; `unavailable`
= none. Skip reasons: `no-prior-version`, `registry-unreachable`. Each
`skipped[]` entry has both `tool` and `reason`.

Source: https://github.com/elastic/supply-chain-monitor

## Version notes

- **PyPI JSON API**: `/pypi/<name>/json` is stable and unauthenticated;
  `releases` is a map of version → artifact list. Some releases ship only
  wheels (`bdist_wheel`) — when no `sdist` exists, diff the wheel contents
  (still a zip) rather than skipping.
- **npm registry**: the full package document can be large; `Accept:
  application/vnd.npm.install-v1+json` returns an abbreviated form, but it still
  carries `dist.tarball`, which is all the analyst needs.

## Common false positives

- A version bump that vendors a new minified bundle (`dist/*.min.js`) — large
  added blob fires "obfuscation," but it is the package's own built output.
  Downgrade to `benign`/`suspicious` unless the bundle contains an exfil host
  or install hook.
- A package that legitimately adds telemetry/network behavior announced in its
  changelog — `suspicious` on the diff alone; the analyst should note the
  changelog context and not over-escalate to `malicious` without an exfil sink.
- Whitespace/formatter churn (a `prettier`/`black` run) producing a huge but
  semantically-empty diff — `benign`.
