# Audit: what the `.pipeline` recordings actually prove (2026-08-27)

Two lanes were caught by accident during the BL-002 engine migration asserting
their end-to-end behaviour against a hand-authored recording rather than a live
run. This audit checks all of them deliberately.

Method: for every `tests/fixtures/*/.pipeline/*.jsonl`, run the lane live
against the same fixture and compare tool-by-tool and id-by-id. Where a
recording claims findings the live run does not produce, check whether the
claimed rule IDs exist in the tool at all — a recording of a real run can drift,
but it cannot contain IDs the tool has never emitted.

## Headline: 24 of 26 e2e tests never run their lane

| e2e | runs the lane | reads a recording |
|---|---|---|
| `ai-tools`, `diff` | yes | no |
| the other 24 | **no** | yes |

`<lane>-e2e.sh` reads `tests/fixtures/<fixture>/.pipeline/<lane>.jsonl` and
asserts over it. Nothing in that path executes the tool, the lane, or the
engine. A green e2e therefore proves the recording is well-formed and
self-consistent. It does not prove the lane works, and it did not notice when
two lanes stopped working.

## Recordings that cannot be reproduced, with the tool present

| Lane | Recorded | Live | Verdict |
|---|---|---|---|
| `ios` | 4 mobsfscan findings | 0 | **Fabricated.** None of `ios_ats_arbitrary_loads`, `ios_userdefaults_secret`, `ios_keychain_accessible_always`, `ios_webview_js_bridge` exists in mobsfscan 0.4.5. mobsfscan ships iOS rule files; these are not among their IDs. |
| `macos` | 4 mobsfscan findings | 0 | **Fabricated.** Same check: `macos_userdefaults_secret`, `macos_sparkle_http_feed`, `macos_sparkle_missing_edkey`, `macos_entitlement_allow_jit` are not mobsfscan rule IDs. |
| `linux` | 4 lintian findings | 0 (`no-debian-package`) | **Fabricated.** The recording is in a lintian JSON format no shipping lintian emits, and lintian cannot read the source-tree fixture at all. Recorded separately in `bash-scope-inventory.md`. |
| `secrets` | 2 gitleaks findings | 0 | **Not reproducible, but not fabricated.** `gitleaks:aws-access-token` and `generic-api-key` are real rules, and the lane's exact invocation finds a planted canonical secret (gitleaks 8.30.1, 1 leak). The fixture's own credentials are written with `FAKE` interpolated and gitleaks matches none of them. The fixture does not contain a detectable secret; the recording says it does. |
| `android` | 6 findings | 0 | **Real IDs, unreachable via the lane.** `android_certificate_pinning` and `android_root_detection` are genuine mobsfscan rules and fire live — but the lane could not see them (`--output -` bug, fixed) and still cannot map them (metadata-only rules, see below). |

The control that makes "fabricated" a fair word: `android_certificate_pinning`
and `android_root_detection` are found in mobsfscan's rule set by the same
grep that finds nothing for the six `ios_*`/`macos_*` IDs. The check
distinguishes real-and-drifted from authored.

## Recordings that are merely stale

Tool present, live run produces findings, but the sets have diverged. These are
ordinary rot — tool versions moved — and are not evidence of anything worse:

| Lane | Recorded | Live | Same IDs |
|---|---|---|---|
| `python` | 13 | 66 | 1 |
| `webext` | 6 | 8 | 1 |
| `ansible` | 6 | 1 | 0 |
| `php` | 14 | 14 | 7 |
| `gh-actions` | 8 | 5 | 3 |
| `shell` | 8 | 6 | 4 |
| `c-cpp` | 12 | 12 | 9 |
| `sast` | 7 | 7 | 6 |
| `virt` | 21 | 22 | 15 |
| `ai-tools` | 5 | 5 | 4 |
| `netcfg` | 2 | 2 | 2 |

`ansible` is the outlier worth a look: zero overlap on a present tool.

## Not assessable here

`dast`, `go`, `iac`, `image`, `k8s`, `webapp`, `supply-chain` (partly),
`windows` — the tools are not installed on this host, so their recordings are
neither confirmed nor impeached.

## The engine defect this exposed

`run_live` had two outcomes for a tool, not three. A tool whose output would not
parse was appended to **neither** `ran` nor `skipped`: it vanished from the
sentinel entirely, and because `status` was `"ok" if ran and not skipped`, a
lane where most tools failed still reported a clean scan.

The rust lane is the live example. Before:

    {"__rust_status__": "ok", "tools": ["cargo-deny"], "runs": 1, "findings": 0}

`cargo-audit` and `cargo-geiger` had both failed and were simply absent. The
lane reported `ok` — a clean bill of health — over a deliberately vulnerable
fixture it had not scanned. After:

    {"__rust_status__": "partial", "tools": ["cargo-deny"], "runs": 1,
     "findings": 0, "failed": [{"tool": "cargo-audit", "reason": "parse-failed"},
                               {"tool": "cargo-geiger", "reason": "parse-failed"}]}

`failed` is not a new concept — the runner contracts have always documented it
(`windows-runner.md`: "Build `tools_available`, `tools_clean_skipped`,
`tools_failed`"). The engine had never implemented it. A clean skip is a
decision the lane made; a failure is a tool it could not read, and reporting
that as `ok` claims coverage the run does not have.

Sweeping every lane after the change, `rust` is the only one that was hiding a
failure. Everything else was already honestly accounted for by a skip or a
`tool-missing`.

## Left open deliberately

- **`rust`'s invocations carry no `{target}`.** `cargo audit --json`,
  `cargo deny --format json check` and `cargo geiger --output-format Json` run
  in the *runner's* working directory, not the target — so the lane scans
  whatever tree it was invoked from. Fixing it means choosing between
  `--manifest-path` and a `cwd` argument to the engine, and the fixture pins a
  fake git dependency (`https://example.com/gremlin.git`) that makes
  cargo-audit and cargo-geiger fail offline regardless, so the fix cannot be
  verified here. Not guessed at.
- **mobsfscan metadata-only rules are dropped.** Rules with no `files` array
  (app-wide findings such as "does not use certificate pinning") are discarded
  by `flatten: "files"`, which is why the repaired android lane reports 0
  findings while 6 rules fire. Fixing it requires deciding what `file` such a
  finding carries.
- **`android-lint --xml -` and `zap-baseline -J -`** have the same
  `-`-as-stdout shape as the mobsfscan bug that broke the android lane. Their
  tools are not installed here. Unconfirmed, and worth checking first on a host
  that has them.
- **The recordings themselves are not regenerated here.** Replacing a
  fabricated recording with a captured one is a separate change, and for `ios`,
  `macos` and `secrets` it needs fixtures that actually trigger their tools.

## The structural point

Every lane's e2e can pass while its lane is broken, because the e2e reads a file
a human wrote. Two lanes were broken. Three recordings assert findings their
tools cannot produce. The cheapest durable fix is not to regenerate the
recordings — it is to make at least one gate per lane execute the lane, so a
recording can drift without the suite going quiet about it.

## Resolution (2026-09-02)

Everything "left open deliberately" above except the two unverifiable
suspects is now closed, and the three fabricated recordings are replaced by
captures of real runs. Verified by `tests/lane-live-gate.sh` executing all 24
lanes plus one scenario, and by the per-lane e2e / parity suites over the new
recordings.

| Item | Outcome |
|---|---|
| `ios`, `macos` recordings | Regenerated from mobsfscan 0.4.5 over rewritten Swift fixtures (17 and 12 findings, every id a real rule). |
| `secrets` recording | Regenerated from gitleaks 8.30.1 over a fixture whose values its rules actually match (2 findings; trufflehog honestly `no-git-history`). No AWS-shaped key: gitleaks' rule and GitHub push protection match the same shape, so such a fixture cannot be pushed. The history claim moved to a live scenario that builds a repository, commits a secret, deletes it, and asserts trufflehog reports it. |
| `rust` `{target}` | Every invocation names the target (`--file`, `--manifest-path`); `CARGO_TARGET_DIR` keeps geiger's build out of the target. The fixture's unresolvable git dep is gone, `Cargo.lock` committed; the live gate's only waiver removed. |
| `rust` mappings | cargo-deny and cargo-geiger were mapped against hand-authored shapes; both remapped against captures (deny writes to **stderr**, word codes under `fields`). |
| mobsfscan metadata-only rules | Decided: kept as app-wide findings at file `.`, line 0 (`flatten_missing: "self"`) on ios, macos and android. |
| Redundant recording-only e2e assertions | Decided: **not trimmed.** With every recording now a capture of a real run, the e2e suites are the hermetic shape/contract check the live gate cannot be on CI (where no scanner is installed). What was wrong was the recordings, not the assertions. |

### Why the 2026-08-27 comparison saw "0 live" for ios and macos

mobsfscan hard-codes `fixtures` (and `spec`) as ignored path segments, so a
run against `tests/fixtures/<x>` in place scans no file at all and reports
only the absence-of-best-practice rules. The "fabricated" verdict stands
(the recorded ids do not exist in the tool) but the live-side zero was the
path, not the fixture. The live gate now stages every fixture into a
scratch copy before running its lane. This also stops tools that write next
to their input (mobsfscan `-`, cargo `target/`) from dirtying the checkout.

### Still not assessable here

`android-lint --xml -` and `zap-baseline -J -` — tools not installed on any
reachable host. Unconfirmed, and still worth checking first on a host that
has them. `windows` (BL-002) likewise.
