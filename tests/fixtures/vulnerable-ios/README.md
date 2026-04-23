# vulnerable-ios fixture

Minimal source-tree iOS project used by the sec-review iOS lane's
E2E assertions (Stage 2 Task 2.3 of v0.9.0).

## Intentional findings

- `VulnerableiOS/Info.plist`: `NSAllowsArbitraryLoads` disables ATS
  (CWE-319), custom URL scheme without `LSApplicationQueriesSchemes`
  (CWE-939), background audio without usage-description rationale
  (App Store policy), deliberately missing `NSCameraUsageDescription`
  paired with the AVCaptureDevice call in AppDelegate.swift.
- `VulnerableiOS/AppDelegate.swift`: UserDefaults credential storage
  (CWE-312), `kSecAttrAccessibleAlways` Keychain item (CWE-522),
  WKWebView with `userContentController.add` JS bridge (CWE-749),
  missing-usage-description-dependent AVCaptureDevice call.
- `VulnerableiOS/VulnerableiOS.entitlements`: `get-task-allow=true`
  (CWE-489), `cs.allow-jit=true` (CWE-693), `cs.disable-library-
  validation=true` (CWE-347).

## `.pipeline/`

- `mobsfscan-report.json` — synthetic canonical mobsfscan 0.4.x
  output. Four findings matching the four source-level patterns
  (ATS, UserDefaults, Keychain, WKWebView bridge).
- `ios.jsonl` — expected ios-runner output: 4 mobsfscan findings +
  a trailing `{"__ios_status__": "ok", ..., "skipped": [...]}` line
  with THREE entries (`codesign`, `spctl`, `notarytool`) each with
  `reason: "requires-macos-host"`. This exercises the v0.9 host-OS-
  clean-skip primitive in its canonical form (Linux CI running the
  runner against an iOS source tree).

All `.pipeline/*.json` files are synthetic. On a macOS host with a
`.app` bundle built, the skipped list would reduce to
`[{"tool": "notarytool", "reason": "no-notary-profile"}]` (or empty
if `NOTARY_PROFILE` is configured) — both shapes are valid per the
contract-check validator.
