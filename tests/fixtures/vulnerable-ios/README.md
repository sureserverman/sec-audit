# vulnerable-ios fixture

Minimal source-tree iOS project used by the sec-audit iOS lane's E2E
assertions and executed for real by `tests/lane-live-gate.sh`.

## Intentional findings

- `VulnerableiOS/AppDelegate.swift` — every pattern names the mobsfscan 0.4.5
  rule it trips (see the comments): `ios_hardcoded_secret` (CWE-312, twice),
  `ios_log`, `ios_keychain_weak_accessibility_value` (`kSecAttrAccessibleAlways`),
  `ios_weak_hash` (`CC_MD5`), `ios_insecure_random_no_generator`,
  `ios_file_no_special` (`.noFileProtection`), `ios_load_html_string`,
  `ios_uiwebview`. The WKWebView JS bridge and the AVCaptureDevice call
  without a usage description are for the sec-expert reference packs.
- `VulnerableiOS/Info.plist`: `NSAllowsArbitraryLoads` disables ATS
  (CWE-319), custom URL scheme without `LSApplicationQueriesSchemes`
  (CWE-939), background audio without usage-description rationale,
  deliberately missing `NSCameraUsageDescription`. mobsfscan does not read
  plists; these are reference-pack patterns.
- `VulnerableiOS/VulnerableiOS.entitlements`: `get-task-allow=true`
  (CWE-489), `cs.allow-jit=true` (CWE-693), `cs.disable-library-
  validation=true` (CWE-347) — read by `macscan.py` on a macOS host with a
  built bundle.

## `.pipeline/`

Both files are **captures of a real mobsfscan 0.4.5 run** (2026-09-02),
replacing hand-authored versions whose four rule ids
(`ios_ats_arbitrary_loads`, `ios_userdefaults_secret`,
`ios_keychain_accessible_always`, `ios_webview_js_bridge`) do not exist in
mobsfscan and could never have been produced (2026-08-27 recording audit).

- `mobsfscan-report.json` — `mobsfscan --json <copy>`, `file_path` values
  rewritten from the staging directory to fixture-relative.
- `ios.jsonl` — the engine's output: 17 findings (12 file-level, 5 app-wide
  rules at file `.` such as `ios_cert_pinning`) and a `partial` sentinel
  with codesign / spctl / notarytool skipped `tool-missing` — the Linux
  shape. On a macOS host those become findings or `no-bundle` /
  `no-notary-profile` skips.

## Regenerating

mobsfscan hard-codes `fixtures` as an ignored path segment, so it must be
run against a copy of this directory placed somewhere else:

```bash
d=$(mktemp -d); cp -a tests/fixtures/vulnerable-ios "$d/"; rm -rf "$d/vulnerable-ios/.pipeline"
python3 scripts/secaudit/runner.py ios "$d/vulnerable-ios" > tests/fixtures/vulnerable-ios/.pipeline/ios.jsonl
```

The engine emits `file` relative to the target, so the recording carries no
host path.
