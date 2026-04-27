# vulnerable-android fixture

Minimal source-tree Android project used by the sec-audit Android
lane's E2E assertions (Stage 2 Task 2.3 of v0.8.0).

## Intentional findings

- `app/build.gradle`: declares `com.android.application` plugin
  (triggers inventory detection); `release` build type intentionally
  has no ProGuard config (out of scope for v0.8 — noted for v0.12
  Windows-release-packaging territory).
- `app/src/main/AndroidManifest.xml`:
  - `android:allowBackup="true"` → CWE-200.
  - `android:debuggable="true"` → CWE-489.
  - `android:usesCleartextTraffic="true"` → CWE-319.
  - `<receiver android:exported="true">` without `android:permission`
    → CWE-926.
  - Deep-link `<data android:scheme="fixtureapp" />` without
    `android:host` → CWE-939.
- `app/src/main/java/com/example/MainActivity.java`:
  - `WebView.setJavaScriptEnabled(true)` + `addJavascriptInterface`
    → CWE-79 / CWE-749.
  - `SharedPreferences` storing an API key and JWT in plain text
    → CWE-312.

## `.pipeline/`

- `mobsfscan-report.json` — synthetic canonical JSON matching
  mobsfscan 0.4.x output shape. Two findings (CWE-312 hardcoded
  secret + CWE-749 JS bridge).
- `lint-results-debug.xml` — synthetic XML matching Android Lint
  format 6 (AGP 8.x). Four Security-category issues
  (HardcodedDebugMode, AllowBackup, ExportedReceiver,
  SetJavaScriptEnabled).
- `android.jsonl` — expected android-runner output: 6 findings + a
  trailing `{"__android_status__": "ok", ..., "skipped":
  [{"tool": "apkleaks", "reason": "no-apk"}]}` line. The `skipped`
  list exercises the v0.8 clean-skip-vs-failure distinction — there
  is intentionally no APK under the fixture (source-only review), so
  apkleaks is cleanly skipped, NOT failed.

All `.pipeline/*.json` files are synthetic, not output from live
runs, so contract-check passes without mobsfscan / apkleaks /
android-lint installed.
