# vulnerable-macos fixture

Minimal source-tree macOS app used by the sec-review macOS lane's
E2E assertions (Stage 2 Task 2.3 of v0.11.0).

## Intentional findings

- `VulnerableMac/Info.plist` — `LSMinimumSystemVersion` (triggers
  macOS inventory detection, distinguishing from iOS), Sparkle
  `SUFeedURL` over cleartext HTTP (CWE-319 / CVE-2014-9390 class),
  missing `SUPublicEDKey` (CWE-494), `SUAllowsAutomaticUpdates` +
  `SUAutomaticallyUpdate` both true, missing
  `NSCameraUsageDescription` paired with camera entitlement.
- `VulnerableMac/AppDelegate.swift` — UserDefaults credential
  storage (CWE-312), `AVCaptureDevice.default` without usage-
  description (runtime crash risk).
- `VulnerableMac/VulnerableMac.entitlements` — `cs.allow-jit`,
  `cs.disable-library-validation`, `cs.allow-unsigned-executable-memory`,
  `files.all` (CWE-693 / 347 / 749 / 732).
- `pkg/postinstall` — no `set -e` (CWE-390), `curl | bash` over
  HTTP (CWE-494/829/319), unnecessary `chown root:wheel` (CWE-250).
- No `.app` bundle built, no `.pkg` installer present — exercises
  all four Apple-binary clean-skip paths on Linux CI
  (`requires-macos-host`).

## `.pipeline/`

- `mobsfscan-report.json` — synthetic canonical mobsfscan output
  covering UserDefaults secret, Sparkle HTTP feed, missing
  SUPublicEDKey, allow-jit entitlement.
- `macos.jsonl` — expected macos-runner output: 4 mobsfscan
  findings + trailing status `__macos_status__: "ok"` with FOUR
  `requires-macos-host` skipped entries (codesign / spctl / pkgutil
  / stapler — all Apple-only). Exercises the full host-OS-gated
  clean-skip vocabulary.

All synthetic — contract-check passes without mobsfscan / any Apple
binary installed. On a macOS host with a built `.app` AND a `.pkg`,
the skipped list would be empty or contain only `no-notary-profile`.
