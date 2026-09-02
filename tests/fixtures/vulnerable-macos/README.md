# vulnerable-macos fixture

Minimal source-tree macOS app used by the sec-audit macOS lane's E2E
assertions and executed for real by `tests/lane-live-gate.sh`.

## Intentional findings

- `VulnerableMac/AppDelegate.swift` — mobsfscan applies its Swift rule set to
  any `.swift` file, macOS included; each pattern names its rule:
  `ios_hardcoded_secret` (CWE-312), `ios_log` / `ios_app_logging` (`NSLog`),
  `ios_weak_hash` (`CC_MD5`), `ios_insecure_random_no_generator`
  (`arc4random_uniform`), `ios_keychain_weak_accessibility_value`
  (`kSecAttrAccessibleAfterFirstUnlock`).
- `VulnerableMac/Info.plist` — `LSMinimumSystemVersion` (macOS inventory
  detection), Sparkle `SUFeedURL` over cleartext HTTP (CWE-319), missing
  `SUPublicEDKey` (CWE-494), missing `NSCameraUsageDescription`. Reference-
  pack patterns; mobsfscan does not read plists.
- `VulnerableMac/VulnerableMac.entitlements` — `cs.allow-jit`,
  `cs.disable-library-validation`, `cs.allow-unsigned-executable-memory`,
  `files.all` (CWE-693 / 347 / 749 / 732) — read by `macscan.py` on a macOS
  host with a built bundle.
- `pkg/postinstall` — no `set -e` (CWE-390), `curl | bash` over HTTP
  (CWE-494/829/319), unnecessary `chown root:wheel` (CWE-250).
- No `.app` bundle, no `.pkg` — the Apple-binary tools skip.

## `.pipeline/`

Both files are **captures of a real mobsfscan 0.4.5 run** (2026-09-02),
replacing hand-authored versions whose rule ids (`macos_userdefaults_secret`,
`macos_sparkle_http_feed`, `macos_sparkle_missing_edkey`,
`macos_entitlement_allow_jit`) do not exist in mobsfscan (2026-08-27
recording audit).

- `mobsfscan-report.json` — `mobsfscan --json <copy>`, `file_path` values
  rewritten to fixture-relative.
- `macos.jsonl` — the engine's output: 12 findings (7 file-level, 5 app-wide
  at file `.`) and a `partial` sentinel with codesign / spctl / pkgutil /
  stapler skipped `tool-missing` — the Linux shape.

## Regenerating

mobsfscan ignores any path containing `fixtures`; run against a copy:

```bash
d=$(mktemp -d); cp -a tests/fixtures/vulnerable-macos "$d/"; rm -rf "$d/vulnerable-macos/.pipeline"
python3 scripts/secaudit/runner.py macos "$d/vulnerable-macos" > tests/fixtures/vulnerable-macos/.pipeline/macos.jsonl
```
