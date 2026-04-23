# iOS Code-Signing, Entitlements, and Notarization

## Source

- https://developer.apple.com/documentation/bundleresources/entitlements — Entitlements reference: key names, allowed values, and capability-to-entitlement mappings for iOS and macOS
- https://developer.apple.com/documentation/security/hardened_runtime — Hardened Runtime: entitlement keys that relax runtime restrictions and the conditions under which each is legitimate
- https://developer.apple.com/documentation/security/app_sandbox — App Sandbox: sandboxing entitlements and the principle of least privilege for app capabilities
- https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution — Notarizing macOS software before distribution: Gatekeeper requirements, notarytool workflow, and stapling
- https://developer.apple.com/app-store/review/guidelines/ — App Store Review Guidelines: provisioning and entitlement requirements for App Store distribution
- https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html — Cocoa Keys InfoPlist reference: CFBundleVersion, CFBundleShortVersionString, and related bundle-identity keys
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet

## Scope

In-scope: iOS and macOS app code-signing discipline — the `.entitlements` property-list file, `embedded.mobileprovision` profile contents, Hardened Runtime exception keys, App Sandbox capability entitlements, notarization and Gatekeeper stapling requirements, provisioning-profile/entitlement drift, and bundle-version string integrity as an anti-tamper control. Out of scope: `Info.plist` keys beyond bundle version strings (covered by `ios-plist.md`); on-device data storage, Keychain usage, and file protection classes (covered by `ios-data.md`); tool invocations such as `codesign`, `otool`, MobSF, and `objection` (covered by `mobile-tools.md`).

## Dangerous patterns (regex/AST hints)

### `get-task-allow=true` in a release entitlements file — CWE-489

- Why: The `com.apple.security.get-task-allow` entitlement permits any process holding the `task_for_pid` right — including `lldb` and Instruments — to attach to the app and inspect or modify its memory at runtime. Xcode injects this key automatically in debug builds; a release build or provisioning profile that retains it is debuggable in the field, allowing an attacker with device access to extract secrets, bypass certificate pinning, or tamper with runtime state without a jailbreak.
- Grep: `<key>com\.apple\.security\.get-task-allow</key>\s*<true/>`
- File globs: `**/*.entitlements`, `**/embedded.mobileprovision`
- Source: https://developer.apple.com/documentation/bundleresources/entitlements

### `com.apple.security.cs.allow-jit=true` on a release build — CWE-693

- Why: This Hardened Runtime exception permits the process to create memory pages that are simultaneously writable and executable (the `MAP_JIT` flag). It is legitimate only for JavaScript engine VMs and similar JIT compilers. On a general-purpose app it removes the W^X memory protection that Code Signing enforces, making it possible to inject and execute arbitrary shellcode in the process address space without modifying the binary on disk.
- Grep: `<key>com\.apple\.security\.cs\.allow-jit</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/hardened_runtime

### `com.apple.security.cs.allow-unsigned-executable-memory=true` — CWE-693 / CWE-749

- Why: This Hardened Runtime exception permits the process to mark arbitrary anonymous memory pages as executable without a code-signature covering them. Unlike `allow-jit`, no `MAP_JIT` flag is required; the app can `mprotect` any heap page to `PROT_EXEC`. This defeats Code Signing's guarantee of executable-page integrity entirely and provides a landing zone for self-modifying-code or shellcode injection attacks.
- Grep: `<key>com\.apple\.security\.cs\.allow-unsigned-executable-memory</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/hardened_runtime

### `com.apple.security.cs.disable-library-validation=true` — CWE-347

- Why: Library validation requires that every dynamic library loaded into the process is signed by Apple or by the same team identity as the main executable. Disabling it allows the process to load dylibs signed by any identity or unsigned entirely, enabling dylib injection, plugin-based code injection, and DLL-hijacking style attacks. Plug-in host apps (e.g. DAW audio plug-in hosts) may have a legitimate need, but the entitlement must be justified; any app that does not load third-party plug-ins should never carry it.
- Grep: `<key>com\.apple\.security\.cs\.disable-library-validation</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/hardened_runtime

### Entitlements declared in `.entitlements` not present in the provisioning profile — CWE-732

- Why: The provisioning profile's embedded `Entitlements` plist is the authority that Gatekeeper and the kernel trust; the `.entitlements` file in the Xcode project is what the developer requests at build time. When the project file claims a capability (e.g. `com.apple.developer.associated-domains`, push notifications, iCloud) that the profile does not grant, the OS silently drops or defaults that capability at runtime. Detection requires a side-by-side diff: extract the profile's entitlements with `security cms -D -i embedded.mobileprovision | plutil -extract Entitlements xml1 -o - -` and compare against the project's `.entitlements` file. Capability drift can mask a provisioning mistake or signal a tampered embedded profile substituted during a supply-chain step.
- Grep: `<key>com\.apple\.developer\.` (extract all keys from both sources and diff)
- File globs: `**/*.entitlements`, `**/embedded.mobileprovision`
- Source: https://developer.apple.com/documentation/bundleresources/entitlements

### Notarization absent from macOS release artifacts — CWE-693

- Why: macOS Gatekeeper requires that software distributed outside the App Store be notarized by Apple and have its notarization ticket stapled to the bundle before shipping. An un-notarized or un-stapled binary is quarantined on first launch on any modern macOS system, and on macOS 13+ is blocked by default even with Gatekeeper reduced to `assess`. More critically, a release pipeline that skips notarization provides no Apple-side malware scan; a supply-chain compromise between build and distribution will reach end users without that check. Detection: `codesign -dv --verbose=4 <App.app>` output must show `Notarization=accepted`; additionally `xcrun stapler validate <App.app>` must exit 0.
- Grep: (runner-side; no source-file grep applies — check CI workflow for absence of `xcrun notarytool submit` and `xcrun stapler staple` steps)
- File globs: `**/*.yml`, `**/*.yaml`, `**/Makefile`, `**/Fastfile`
- Source: https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution

### `CFBundleVersion` / `CFBundleShortVersionString` mismatch between `Info.plist` and binary — CWE-732

- Why: `CFBundleVersion` is the monotonically increasing build number used by the App Store and TestFlight to distinguish builds; `CFBundleShortVersionString` is the user-visible marketing version. A mismatch between the value declared in `Info.plist` and the value embedded in the signed binary (readable via `codesign -dv --verbose=4`) can indicate a binary-substitution or post-build injection event in the distribution pipeline, because a legitimate build system sets both fields once from the same source of truth. Flag when the two values diverge or when `CFBundleVersion` does not monotonically increase across successive release artifacts.
- Grep: `<key>CFBundleVersion</key>` and `<key>CFBundleShortVersionString</key>` (cross-reference values)
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

### Embedded provisioning profile absent from ad-hoc or enterprise distribution bundle — CWE-732

- Why: Ad-hoc and enterprise (in-house) distributions require `embedded.mobileprovision` to be present inside the `.ipa` bundle (at `Payload/<App>.app/embedded.mobileprovision`). Its absence means the codesign seal was applied without a profile — the bundle can only have been resigned after the original build, which is a strong indicator of repackaging or binary injection. `codesign -dv --verbose=4` on a correctly packaged bundle reports the profile UUID; absence of that line is a finding.
- Grep: (runner-side; check `.ipa` contents with `unzip -l *.ipa | grep embedded.mobileprovision`)
- File globs: `**/*.ipa`
- Source: https://developer.apple.com/app-store/review/guidelines/

## Secure patterns

Minimal production `.entitlements` file for a sandboxed iOS app: no debug entitlement, no Hardened Runtime exceptions, App Sandbox enabled, only the narrowest capabilities the app genuinely uses.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- App Sandbox: required for Mac App Store; best practice for all release builds. -->
    <key>com.apple.security.app-sandbox</key>
    <true/>

    <!-- Network client access: request only if the app makes outbound connections. -->
    <key>com.apple.security.network.client</key>
    <true/>

    <!-- get-task-allow MUST be absent in release builds.
         Xcode injects it only in debug-signed builds; stripping it here ensures
         it cannot survive an accidental release signing step. -->

    <!-- No JIT, no unsigned-executable-memory, no disable-library-validation.
         If any of these appear, a written justification and approval is required
         before the entitlements file is merged. -->
</dict>
</plist>
```

Source: https://developer.apple.com/documentation/security/app_sandbox

Notarization verification one-liner — confirms a stapled ticket is present and valid on the release artifact before it ships. Exit code 0 means Gatekeeper will accept the binary offline.

```sh
# Verify that the notarization ticket is stapled to the release app bundle.
# Run this as the final gate in the release CI step, after xcrun stapler staple.
xcrun stapler validate path/to/YourApp.app

# For a signed disk image:
xcrun stapler validate path/to/YourApp.dmg

# For a deeper check that also verifies the code signature and entitlements:
codesign --verify --deep --strict --verbose=2 path/to/YourApp.app
spctl --assess --type exec --verbose=4 path/to/YourApp.app
```

A passing `xcrun stapler validate` means the bundle carries a stapled Gatekeeper ticket and will launch offline on any macOS system with Gatekeeper enabled, without requiring a network call to Apple's OCSP/notarization CDN.

Source: https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution

## Fix recipes

### Recipe: Remove `get-task-allow` from a release entitlements file — addresses CWE-489

**Before (dangerous):**

```xml
<!-- Release.entitlements — contains the debug entitlement; any debugger can attach. -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
```

**After (safe):**

```xml
<!-- Release.entitlements — get-task-allow removed entirely.
     Xcode automatically injects it into Debug builds via the debug-variant
     signing identity; it must never appear in the release entitlements file. -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
</dict>
</plist>
```

If the project uses a single `.entitlements` file for both debug and release, split it: add a `Debug.entitlements` that includes `get-task-allow` for developer convenience, and a `Release.entitlements` without it. Set the Xcode build setting `CODE_SIGN_ENTITLEMENTS[config=Release]` to point at `Release.entitlements`.

Source: https://developer.apple.com/documentation/bundleresources/entitlements

### Recipe: Remove or scope `com.apple.security.cs.allow-jit` — addresses CWE-693

**Before (dangerous):**

```xml
<!-- App.entitlements — JIT exception applied project-wide, including to the
     main app target that contains no JIT engine. -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
</dict>
</plist>
```

**After (safe — no JIT engine in this target):**

```xml
<!-- App.entitlements — allow-jit removed from the main app target entirely.
     If a helper process (e.g. a JavaScript engine XPC service) genuinely
     requires JIT, confine the entitlement to that helper's own .entitlements
     file and keep the main app target clean. -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
</dict>
</plist>
```

**After (safe — JIT is legitimate, confined to an XPC helper target):**

```xml
<!-- JITHelper.entitlements — used only for the XPC service target that hosts
     the JavaScript engine; the main app target has no allow-jit entitlement. -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <!-- Inherit sandbox from the parent app that launched this service. -->
    <key>com.apple.security.inherit</key>
    <true/>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
</dict>
</plist>
```

Source: https://developer.apple.com/documentation/security/hardened_runtime

### Recipe: Add notarytool submission and stapling to the release CI workflow — addresses CWE-693

**Before (dangerous — release step ships without notarization):**

```yaml
# .github/workflows/release.yml (excerpt)
- name: Archive and export
  run: |
    xcodebuild archive -scheme MyApp -archivePath build/MyApp.xcarchive
    xcodebuild -exportArchive \
      -archivePath build/MyApp.xcarchive \
      -exportOptionsPlist ExportOptions.plist \
      -exportPath build/export

- name: Upload release artifact
  uses: actions/upload-artifact@v4
  with:
    name: MyApp
    path: build/export/MyApp.app
```

**After (safe — notarize and staple before the artifact is published):**

```yaml
# .github/workflows/release.yml (excerpt)
- name: Archive and export
  run: |
    xcodebuild archive -scheme MyApp -archivePath build/MyApp.xcarchive
    xcodebuild -exportArchive \
      -archivePath build/MyApp.xcarchive \
      -exportOptionsPlist ExportOptions.plist \
      -exportPath build/export

- name: Compress for notarization
  run: |
    ditto -c -k --keepParent build/export/MyApp.app build/MyApp.zip

- name: Notarize with notarytool
  env:
    APPLE_ID: ${{ secrets.APPLE_ID }}
    APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
    APPLE_APP_PASSWORD: ${{ secrets.APPLE_APP_PASSWORD }}
  run: |
    xcrun notarytool submit build/MyApp.zip \
      --apple-id "$APPLE_ID" \
      --team-id "$APPLE_TEAM_ID" \
      --password "$APPLE_APP_PASSWORD" \
      --wait  # blocks until Apple returns Accepted or Invalid

- name: Staple notarization ticket
  run: |
    xcrun stapler staple build/export/MyApp.app

- name: Verify stapled ticket
  run: |
    xcrun stapler validate build/export/MyApp.app
    spctl --assess --type exec --verbose=4 build/export/MyApp.app

- name: Upload release artifact
  uses: actions/upload-artifact@v4
  with:
    name: MyApp
    path: build/export/MyApp.app
```

The `--wait` flag on `notarytool submit` causes the step to block and exit non-zero if Apple returns `Invalid`, failing the CI job before the artifact is published. Store `APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_APP_PASSWORD` (an app-specific password, not the account password) as encrypted repository secrets; never hardcode them in the workflow file.

Source: https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution

## Version notes

- `xcrun notarytool` replaces the deprecated `xcrun altool --notarize-app`; `altool` notarization was shut down by Apple on 1 November 2023. Any pipeline still using `altool` for notarization will fail and must be migrated to `notarytool`.
- The `com.apple.security.get-task-allow` entitlement is automatically stripped from iOS App Store builds by Xcode at archive time. For macOS Developer ID and ad-hoc builds, the stripping is not automatic — the release `.entitlements` file must explicitly omit the key.
- Hardened Runtime is mandatory for macOS Developer ID notarization (required since macOS 10.14.5 / June 2019). App Store Mac apps also require it. iOS apps on device do not use the same Hardened Runtime model, but the analogous control is the provisioning profile's entitlement grant authority.
- `CFBundleVersion` must be a period-separated list of integers (e.g. `1.0.3`) and must increase monotonically for each TestFlight or App Store submission. Xcode Cloud and Fastlane's `increment_build_number` action automate this; manual edits are a common source of drift.

## Common false positives

- `com.apple.security.get-task-allow` present in a `.entitlements` file that is used exclusively for the Debug build configuration — confirm via Xcode build settings (`CODE_SIGN_ENTITLEMENTS[config=Debug]`) that a separate release entitlements file is used; if so, the debug-only entitlement is expected and not a finding.
- `com.apple.security.cs.allow-jit` in the entitlements of a target whose name or bundle ID contains `JSContext`, `WebKit`, `JavaScriptCore`, `Renderer`, or `Engine` — these sub-process helpers plausibly run a JIT engine; verify by inspecting the target's source for `MAP_JIT` usage or `JSVirtualMachine` / WKWebView instantiation before flagging.
- `com.apple.security.cs.disable-library-validation` in a target identified as a plug-in host (DAW, creative suite, developer tool) — plug-in hosts must load third-party dylibs signed by arbitrary teams and have a documented legitimate need; verify that the app's documentation or App Store description mentions plug-in support before downgrading severity.
- `xcrun stapler validate` failing on a `.app` bundle that is distributed exclusively via the Mac App Store — App Store apps do not carry a stapled ticket because Gatekeeper checks are performed by the App Store process itself at install time; the absence of a stapled ticket is not a finding for MAS-distributed builds.
- `CFBundleVersion` values that reset to `1` or `1.0.0` in a repository that uses separate version-tracking per branch — confirm whether the mismatch is between the source `Info.plist` and the signed binary (a finding) versus between two source-tree branches (a workflow concern, not a security finding).
