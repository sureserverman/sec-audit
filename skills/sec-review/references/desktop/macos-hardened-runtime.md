# macOS Hardened Runtime and Entitlements Hygiene

## Source

- https://developer.apple.com/documentation/security/hardened_runtime — Hardened Runtime: entitlement keys that relax runtime restrictions and the conditions under which each is legitimate
- https://developer.apple.com/documentation/security/app_sandbox — App Sandbox: sandboxing entitlements and the principle of least privilege for app capabilities
- https://developer.apple.com/documentation/bundleresources/entitlements — Entitlements reference: key names, allowed values, and capability-to-entitlement mappings for macOS and iOS
- https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac — Creating distribution-signed code for the Mac: code-signing workflow for Developer ID and App Store distribution, including the `--options runtime` requirement
- https://developer.apple.com/library/archive/technotes/tn2206/_index.html — Technical Note TN2206: macOS Code Signing In Depth — canonical reference for codesign flags, signature structure, and Gatekeeper evaluation
- https://developer.apple.com/documentation/coreservices/launch_services — Launch Services: `LSUIElement` and `LSBackgroundOnly` Info.plist keys governing menu-bar and background-only app presentation
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet

## Scope

In scope: macOS hardened runtime configuration and entitlement hygiene for Mach-O GUI apps, frameworks, and command-line tools distributed via Developer ID (outside the Mac App Store) and via the Mac App Store — covering the `--options runtime` codesign flag, all `com.apple.security.cs.*` exception entitlements, `com.apple.security.get-task-allow`, `com.apple.security.app-sandbox`, and the `LSUIElement`/entitlement anti-pattern for menu-bar-only apps. Out of scope: iOS-specific signing, provisioning profiles, and `embedded.mobileprovision` (`mobile/ios-codesign.md`); TCC-triggering usage-description entitlements such as `NSCameraUsageDescription` and `NSMicrophoneUsageDescription` (`macos-tcc.md`); `.pkg` installer hygiene, Sparkle update-framework security, and distribution-pipeline supply-chain controls (`macos-packaging.md`); tool invocations for `codesign`, `otool`, and `jtool2` (`mobile-tools.md`).

## Dangerous patterns (regex/AST hints)

### Hardened Runtime flag absent from release codesign invocation — CWE-693

- Why: The Hardened Runtime (`--options runtime`) enables a set of OS-enforced memory-protection policies — W^X enforcement, library validation, stack canaries for injected dylibs — on the running process. Without it the process can be trivially injected into via `DYLD_INSERT_LIBRARIES`, can load unsigned dylibs, and can mark arbitrary memory pages executable. Apple requires `--options runtime` for Developer ID notarization (mandatory since macOS 10.14.5 / June 2019) and for Mac App Store submission; a CI or build script that signs without it will produce a binary that either fails notarization or ships with reduced runtime protections.
- Grep: `codesign\b(?!.*--options runtime).*(?:--sign|-s)\s+"[^"]+"` (negative-lookahead match: `codesign` invocation with `--sign` but no `--options runtime`)
- File globs: `**/*.sh`, `**/*.yml`, `**/*.yaml`, `**/Fastfile`, `**/*.xcconfig`, `**/Makefile`
- Source: https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac

### `com.apple.security.cs.allow-jit=true` on a release app bundle — CWE-693

- Why: This Hardened Runtime exception permits the process to create memory pages that are simultaneously writable and executable via the `MAP_JIT` flag, defeating the W^X (Write XOR Execute) policy that the runtime enforces by default. It is legitimately required only by JavaScript engine VMs (JavaScriptCore, V8, SpiderMonkey), emulators, and similar JIT-compiling runtimes. On any app that does not contain such an engine the entitlement removes the memory-protection boundary that blocks shellcode injection: an attacker who achieves arbitrary write access can manufacture executable payloads in the writable-executable region without needing a separate code-injection primitive.
- Grep: `<key>com\.apple\.security\.cs\.allow-jit</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/hardened_runtime

### `com.apple.security.cs.allow-unsigned-executable-memory=true` — CWE-749

- Why: This exception permits the process to call `mprotect()` to mark any anonymous memory region `PROT_EXEC` without requiring a code signature over that region. Unlike `allow-jit`, no `MAP_JIT` flag is required; any heap page can be made executable. This defeats the Code Signing guarantee that every executable page in the process is covered by a verifiable signature, providing an unimpeded landing zone for shellcode injected via a memory-corruption vulnerability without any code-signature check to bypass.
- Grep: `<key>com\.apple\.security\.cs\.allow-unsigned-executable-memory</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/hardened_runtime

### `com.apple.security.cs.allow-dyld-environment-variables=true` — CWE-426

- Why: This exception permits the process to be influenced by `DYLD_*` environment variables — most critically `DYLD_INSERT_LIBRARIES`, which instructs the dynamic linker to inject an arbitrary dylib into the process before `main()`. Without this entitlement the Hardened Runtime silently strips all `DYLD_*` variables on launch, blocking this entire class of injection. Granting the exception re-enables the attack surface that the runtime is designed to close. A compromised launch environment (malicious `.zshrc`, `launchd` job, or Terminal profile) or a setuid/setgid helper that inherits the environment can exploit the open surface to load attacker-controlled code into the target process.
- Grep: `<key>com\.apple\.security\.cs\.allow-dyld-environment-variables</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/hardened_runtime

### `com.apple.security.cs.disable-library-validation=true` — CWE-347

- Why: Library validation requires that every dylib loaded into the process is signed either by Apple or by the same Developer ID team as the main executable. Disabling it allows the process to load dylibs signed by any identity or unsigned entirely — enabling dylib injection, plug-in-based code execution, and DLL-hijacking style path-confusion attacks. A legitimate need exists for plug-in host apps (DAWs, creative-suite apps, developer tools) that must load third-party bundles signed by external teams; every other app should treat the presence of this entitlement as a finding. When present, verify that the app's declared purpose explicitly requires third-party plug-in loading before downgrading severity.
- Grep: `<key>com\.apple\.security\.cs\.disable-library-validation</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/hardened_runtime

### `com.apple.security.get-task-allow=true` on a release build — CWE-489

- Why: The `com.apple.security.get-task-allow` entitlement permits any process that holds the `task_for_pid` right — including `lldb`, `Instruments`, and custom tooling — to attach to the app and inspect or modify its memory and register state at runtime. Xcode injects this key automatically into Debug-configuration builds so that the debugger can attach during development. A release binary or distribution archive that retains the key is fully debuggable in the field: an attacker with local access can attach without a jailbreak, extract in-memory secrets (keychain items, API tokens, private keys fetched at runtime), bypass certificate pinning, or patch runtime logic. Unlike iOS, macOS does not automatically strip this key at archive time for Developer ID builds — the release `.entitlements` file must explicitly omit it.
- Grep: `<key>com\.apple\.security\.get-task-allow</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/bundleresources/entitlements

### App Sandbox entitlement absent on a Mac App Store distribution target — CWE-693

- Why: The Mac App Store requires every submitted app to carry `com.apple.security.app-sandbox=true`. Beyond the submission requirement, the sandbox is the primary least-privilege boundary for macOS GUI apps: it restricts the process's access to user files, network sockets, hardware devices, and inter-process communication to only what the entitlements explicitly declare. An app targeting MAS distribution that lacks the sandbox entitlement will be rejected at review, but a build pipeline that skips the MAS target can produce unsigned or Developer-ID-signed artifacts without the sandbox. Detection: check `.entitlements` files associated with targets whose `PRODUCT_BUNDLE_IDENTIFIER` or export-options `method` indicates App Store distribution; confirm `com.apple.security.app-sandbox` is present and set to `true`.
- Grep: absence of `<key>com\.apple\.security\.app-sandbox</key>` in a `.entitlements` file paired with App Store export metadata
- File globs: `**/*.entitlements`, `**/ExportOptions.plist`, `**/*.xcodeproj/project.pbxproj`
- Source: https://developer.apple.com/documentation/security/app_sandbox

### `LSUIElement=true` paired with a camera or microphone entitlement — operational hygiene

- Why: `LSUIElement=true` designates an app as an agent application — it has no Dock icon and no application menu, presenting only as a menu-bar item or entirely headlessly. macOS shows a camera or microphone indicator in the menu bar when hardware is actively in use; an `LSUIElement` app that requests `com.apple.security.device.camera` or `com.apple.security.device.microphone` without any UI surface to explain that access to the user is an anti-pattern and a potential privacy signal. Gatekeeper and TCC will still enforce the entitlement grant and display the hardware-use indicator, but the combination warrants manual review to confirm the camera/microphone access is intentional and surfaced to the user somewhere. Cross-reference with `macos-tcc.md` for the `NSCameraUsageDescription` usage string requirement.
- Grep: `LSUIElement` in `Info.plist` (or `LSUIElement=YES`/`true` in `*.xcconfig`) combined with `com\.apple\.security\.device\.camera` or `com\.apple\.security\.device\.microphone` in the corresponding `.entitlements` file
- File globs: `**/Info.plist`, `**/*.entitlements`, `**/*.xcconfig`
- Source: https://developer.apple.com/documentation/coreservices/launch_services

## Secure patterns

Release `.entitlements` file for a sandboxed Developer ID or Mac App Store app: App Sandbox enabled, network-client access declared because the app makes outbound connections, no debug entitlement, no Hardened Runtime exception keys. Any `cs.*` exception key would require a written justification and explicit approval before merge.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- App Sandbox: required for Mac App Store; strongly recommended for
         Developer ID distribution as the primary least-privilege boundary. -->
    <key>com.apple.security.app-sandbox</key>
    <true/>

    <!-- Declare only the narrowest network capability the app requires.
         Use network.server only if the app accepts inbound connections. -->
    <key>com.apple.security.network.client</key>
    <true/>

    <!-- get-task-allow MUST be absent in release entitlements.
         Xcode injects it only in debug-configuration builds via
         CODE_SIGN_ENTITLEMENTS[config=Debug]; it must not appear here. -->

    <!-- cs.allow-jit, cs.allow-unsigned-executable-memory,
         cs.allow-dyld-environment-variables, cs.disable-library-validation
         MUST all be absent unless a documented, reviewed exception applies. -->
</dict>
</plist>
```

Source: https://developer.apple.com/documentation/security/app_sandbox

Correctly-formed `codesign` invocation for a Developer ID release bundle: Hardened Runtime enabled, secure timestamp embedded (required for notarization), deep signing traverses all nested helpers and frameworks, entitlements supplied explicitly.

```sh
# Sign the release app bundle for Developer ID distribution.
# --options runtime   : enables Hardened Runtime (mandatory for notarization)
# --timestamp         : embeds an Apple-issued secure timestamp (mandatory for notarization)
# --deep              : recursively signs nested .framework, .dylib, and helper bundles
# --strict            : treats deprecated or ambiguous signing options as errors
# --entitlements      : explicitly supplies the release entitlements plist

codesign \
  --deep \
  --options runtime \
  --timestamp \
  --strict \
  --sign "Developer ID Application: Acme Corp (ABCDE12345)" \
  --entitlements "MyApp/MyApp-Release.entitlements" \
  MyApp.app
```

Source: https://developer.apple.com/library/archive/technotes/tn2206/_index.html

## Fix recipes

### Recipe: Add `--options runtime` to a release codesign invocation — addresses CWE-693

**Before (dangerous):**

```sh
# CI release step — Hardened Runtime not enabled; binary will fail notarization
# and ships without W^X enforcement, library validation, and DYLD_* stripping.
codesign \
  --deep \
  --timestamp \
  --sign "Developer ID Application: Acme Corp (ABCDE12345)" \
  --entitlements MyApp/MyApp.entitlements \
  MyApp.app
```

**After (safe):**

```sh
# Add --options runtime to enable Hardened Runtime.
# This is required for notarization and activates W^X, library validation,
# and DYLD_* environment-variable stripping on the running process.
codesign \
  --deep \
  --options runtime \
  --timestamp \
  --sign "Developer ID Application: Acme Corp (ABCDE12345)" \
  --entitlements MyApp/MyApp-Release.entitlements \
  MyApp.app
```

Also rename the entitlements file to `MyApp-Release.entitlements` and ensure it is distinct from the debug entitlements file (see Recipe 3 below) so that `get-task-allow` cannot accidentally survive into the release signing step.

Source: https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac

### Recipe: Remove `cs.allow-jit` from release entitlements, gate to debug only — addresses CWE-693

**Before (dangerous):**

```xml
<!-- MyApp.entitlements — single entitlements file used for all configurations.
     allow-jit bleeds into the release build even though the main app target
     contains no JIT engine. -->
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

**After (safe):**

Split into two entitlements files and point each build configuration at its own file via Xcode build settings.

`MyApp-Release.entitlements` — no JIT exception:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <!-- allow-jit absent: release builds run under strict W^X enforcement. -->
</dict>
</plist>
```

`MyApp-Debug.entitlements` — JIT permitted during development only:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.get-task-allow</key>
    <true/>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
</dict>
</plist>
```

In `project.pbxproj` / Xcode build settings:

```
CODE_SIGN_ENTITLEMENTS[config=Release] = MyApp/MyApp-Release.entitlements
CODE_SIGN_ENTITLEMENTS[config=Debug]   = MyApp/MyApp-Debug.entitlements
```

If a JIT engine genuinely runs in a sub-process, confine `allow-jit` to that XPC helper's own `JITHelper-Release.entitlements` and keep the main app target's release entitlements file clean.

Source: https://developer.apple.com/documentation/security/hardened_runtime

### Recipe: Strip `get-task-allow` from release entitlements via debug/release xcconfig split — addresses CWE-489

**Before (dangerous):**

```xml
<!-- App.entitlements — single file; get-task-allow survives into release builds,
     allowing lldb or any process with task_for_pid rights to attach. -->
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

Create `Configurations/Debug.xcconfig` and `Configurations/Release.xcconfig` (or use the Xcode target build settings editor) to point each configuration at its own entitlements file:

`Configurations/Release.xcconfig`:

```xcconfig
CODE_SIGN_ENTITLEMENTS = MyApp/MyApp-Release.entitlements
```

`Configurations/Debug.xcconfig`:

```xcconfig
CODE_SIGN_ENTITLEMENTS = MyApp/MyApp-Debug.entitlements
```

`MyApp/MyApp-Release.entitlements` — `get-task-allow` absent:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <!-- get-task-allow is intentionally absent.
         Debugger attachment is blocked in all release-signed builds. -->
</dict>
</plist>
```

`MyApp/MyApp-Debug.entitlements` — `get-task-allow` present for developer convenience:

```xml
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

Note: for Mac App Store distribution, Xcode automatically strips `get-task-allow` at archive time. For Developer ID distribution and ad-hoc builds, stripping is not automatic — the release entitlements file must explicitly omit the key.

Source: https://developer.apple.com/documentation/bundleresources/entitlements

## Version notes

- `--options runtime` (Hardened Runtime) is mandatory for Developer ID notarization since macOS 10.14.5 / June 2019. A `codesign` invocation without it will produce a binary that `xcrun notarytool submit` rejects with a `ITMS-90338`-equivalent error.
- `xcrun notarytool` replaces the deprecated `xcrun altool --notarize-app`; Apple shut down `altool` notarization on 1 November 2023. CI pipelines still using `altool` must migrate to `notarytool` immediately.
- Library validation (`!cs.disable-library-validation`) is enabled by default when `--options runtime` is set. If the app embeds a plug-in host that legitimately loads third-party dylibs, the exception must be justified per target; disabling it project-wide to silence dylib-load errors is a common but dangerous shortcut.
- `com.apple.security.get-task-allow` is automatically stripped from Mac App Store builds by Xcode at archive time but is NOT automatically stripped for Developer ID builds. Every Developer ID release pipeline must use a separate release entitlements file that omits the key, or explicitly verify with `codesign -d --entitlements :- MyApp.app | grep get-task-allow` that the signed binary does not carry it.
- The `LSUIElement` + camera/microphone pattern became more visible to users in macOS 14 Sonoma, which introduced persistent menu-bar permission indicators. Apps using this combination that shipped before macOS 14 may surface new user-visible privacy prompts on upgrade.

## Common false positives

- `com.apple.security.get-task-allow` present in a `.entitlements` file mapped exclusively to the Debug build configuration via `CODE_SIGN_ENTITLEMENTS[config=Debug]` — confirm in `project.pbxproj` that a separate release entitlements file is set for the Release configuration and that the release file omits the key; if so, the debug-only instance is expected and not a finding.
- `com.apple.security.cs.allow-jit` in the entitlements of a target whose name or bundle ID contains `JSContext`, `WebKit`, `JavaScriptCore`, `Renderer`, `Engine`, or `VM`, or in a helper XPC service target — these sub-process helpers plausibly run a JIT compiler; verify by inspecting the target's source for `MAP_JIT` usage, `JSVirtualMachine`, or `WKWebView` instantiation before flagging.
- `com.apple.security.cs.disable-library-validation` in a target identified as a plug-in host (DAW, creative suite, developer tool, audio unit host) — plug-in hosts must load third-party dylibs signed by arbitrary teams and have a documented legitimate need; verify that the app's documentation or App Store description mentions third-party plug-in support and that the entitlement is scoped to the host target only, not the main app target.
- `--options runtime` absent in a `codesign` invocation that targets a debug or development build only — confirm via surrounding CI job conditions (`if: github.ref == 'refs/heads/main'` or `if: startsWith(github.ref, 'refs/tags/')`) that the invocation is gated to non-release contexts; debug re-signing steps do not require `--options runtime`.
- `LSUIElement=true` in the `Info.plist` of a helper agent that requests `com.apple.security.device.camera` when the parent app bundle explicitly describes camera-assisted menu-bar functionality (e.g. a screen-capture or video-call menu-bar app) — in this context the combination is intentional; verify that a corresponding `NSCameraUsageDescription` string is present and that TCC consent is surfaced through the parent app's UI.
