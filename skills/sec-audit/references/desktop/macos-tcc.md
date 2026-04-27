# macOS TCC + App Sandbox Entitlements

## Source

- https://developer.apple.com/documentation/security/app_sandbox — App Sandbox — Apple's canonical reference for the macOS App Sandbox entitlement, container layout, and capability entitlement keys
- https://developer.apple.com/documentation/bundleresources/entitlements — Entitlements — Apple entitlement key reference covering every `com.apple.security.*` key value, type, and platform requirement
- https://developer.apple.com/documentation/bundleresources/information_property_list — Information Property List — canonical bundle resource reference for `NS*UsageDescription` and other Info.plist keys
- https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac — Creating Distribution-Signed Code for the Mac — covers MAS vs. Developer-ID signing requirements and entitlement selection for each distribution path
- https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html — Info.plist Key Reference: Cocoa Keys — full key descriptions, value types, and usage guidance for all Info.plist properties including `NS*UsageDescription` entries
- https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web — Apple Platform Security: Protecting against malware — describes Gatekeeper, TCC, and the sandbox as layered defenses against malicious code
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet — cross-platform guidance on permission hygiene, least-privilege capability requests, and usage-description requirements

## Scope

In-scope: macOS TCC (Transparency, Consent, and Control) relevant entitlements in `.entitlements` property-list files — the App Sandbox entitlement (`com.apple.security.app-sandbox`), capability sub-entitlements that trigger TCC prompts (camera, microphone, Bluetooth, location, contacts, all-files), network server/client entitlements, temporary exceptions, XPC helper sandbox inheritance, App Group ID format hygiene, and paired `NS*UsageDescription` keys in `Info.plist` that must accompany those capability entitlements. Out of scope: hardened-runtime flag hygiene such as `com.apple.security.cs.allow-jit` and `com.apple.security.cs.disable-library-validation` (covered in `macos-hardened-runtime.md`); `.pkg` installer signing and notarisation (`macos-packaging.md`); iOS equivalent usage-description hygiene (`mobile/ios-plist.md`).

## Dangerous patterns (regex/AST hints)

### `com.apple.security.app-sandbox` absent or explicitly false on a MAS-targeting build — CWE-693

- Why: The Mac App Store requires every submitted binary to be sandboxed. An `.entitlements` file that omits the key (defaults to `false`) or explicitly sets it to `false` will cause App Store Connect validation to reject the archive. For Developer-ID distribution the sandbox is not enforced by the OS but its absence is a defence-in-depth regression: without a sandbox the process has full access to the user's home directory, network, and hardware from the moment of first exploitation.
- Grep: `<key>com\.apple\.security\.app-sandbox</key>\s*<false/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/app_sandbox

### TCC-sensitive entitlement present without matching `NS*UsageDescription` in Info.plist — CWE-359

- Why: macOS requires a matching `NS*UsageDescription` key in `Info.plist` for every TCC-gated capability the app declares in its entitlements. Without the paired description the OS refuses to display a consent prompt and the capability silently fails at runtime; on MAS the submission is rejected at review. The missing description also means no user-facing explanation was authored for what data is collected, which is a privacy-disclosure gap. Required pairs: `com.apple.security.device.camera` → `NSCameraUsageDescription`; `com.apple.security.device.microphone` or `com.apple.security.device.audio-input` → `NSMicrophoneUsageDescription`; `com.apple.security.device.bluetooth` → `NSBluetoothAlwaysUsageDescription`; `com.apple.security.personal-information.location` → `NSLocationWhenInUseUsageDescription`; `com.apple.security.personal-information.addressbook` → `NSContactsUsageDescription`.
- Grep: `<key>com\.apple\.security\.device\.(camera|microphone|audio-input|bluetooth)</key>` or `<key>com\.apple\.security\.personal-information\.(location|addressbook)</key>` — cross-check that no matching `NS*UsageDescription` key exists in the project's `Info.plist`
- File globs: `**/*.entitlements`, `**/Info.plist`
- Source: https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

### `com.apple.security.files.all` entitlement — CWE-732

- Why: This entitlement grants read and write access to every file in the user's home directory, bypassing the normal sandbox container boundary. Apple's documentation marks it as requiring special approval; it is rejected by App Store review for most app categories and its presence in a shipping binary represents a dramatically over-privileged file-system capability. If the app only needs access to files the user explicitly opens, `com.apple.security.files.user-selected.read-write` combined with security-scoped bookmarks is the correct replacement.
- Grep: `<key>com\.apple\.security\.files\.all</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/app_sandbox

### `com.apple.security.network.server=true` without documented rationale — CWE-732

- Why: The network-server entitlement permits a sandboxed app to accept inbound TCP or UDP connections on arbitrary ports. This is a significant attack-surface expansion: any service listening on a port is reachable by other processes on the same machine or, if the port is not firewalled, by remote hosts. Most apps require `com.apple.security.network.client` at most; `network.server=true` should only appear in entitlement files where the app is explicitly a local server (e.g. a developer-tools proxy or a local web server). Presence without an inline rationale comment is a flag for review.
- Grep: `<key>com\.apple\.security\.network\.server</key>\s*<true/>`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/app_sandbox

### `com.apple.security.temporary-exception.*` present in release entitlements — CWE-693

- Why: Temporary exceptions are explicit sandbox escapes that Apple provides as a migration path while developers adopt proper entitlements. Apple's own documentation states that temporary exceptions must be removed before a shipping release and that submissions containing them without justification are rejected. Each `temporary-exception` key grants a capability that bypasses the normal sandbox boundary — for example `temporary-exception.files.absolute-path.read-write` grants read/write to an arbitrary absolute path. Their presence in a non-development entitlement file signals that a permanent migration was never completed, leaving a sandbox escape in production code.
- Grep: `<key>com\.apple\.security\.temporary-exception\.`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/security/app_sandbox

### `com.apple.security.inherit` absent or false on an XPC helper — CWE-693

- Why: An XPC helper that declares `com.apple.security.app-sandbox=true` but omits `com.apple.security.inherit=true` runs under the sandbox rules defined in its own entitlement file rather than inheriting the host app's sandbox. If the helper's own entitlements are broader than the host's (or if they accidentally omit restrictions present in the host), the helper process operates with more privilege than the host intends. The correct pattern for a child helper that should stay within the parent's sandbox boundary is to set both `app-sandbox=true` and `inherit=true`.
- Grep: absence of `<key>com\.apple\.security\.inherit</key>\s*<true/>` in an `.entitlements` file that also contains `app-sandbox=true` inside an XPC helper target directory
- File globs: `**/XPC*.entitlements`, `**/*Helper*.entitlements`, `**/*Extension*.entitlements`
- Source: https://developer.apple.com/documentation/security/app_sandbox

### `com.apple.security.application-groups` entry without a Team ID prefix — hint

- Why: App Group IDs must be prefixed with the developer's Team ID in the form `<TEAMID>.group.<reverse-dns>`. An ID that lacks the Team ID prefix (e.g. `group.com.example.shared`) silently fails to resolve at runtime on macOS: the shared container directory is never created, inter-process data sharing breaks without any error log entry, and the ID cannot be provisioned through App Store Connect. This is not a direct security vulnerability but the silent failure can mask a security-relevant misconfiguration where shared credentials or tokens intended to be stored in a group container are instead written to an unshared location.
- Grep: `<key>com\.apple\.security\.application-groups</key>` followed by a `<string>` that does not match `^[A-Z0-9]{10}\\.`
- File globs: `**/*.entitlements`
- Source: https://developer.apple.com/documentation/bundleresources/entitlements

### Placeholder or empty `NS*UsageDescription` string — CWE-357

- Why: Apple rejects App Store submissions containing `NS*UsageDescription` values that are empty, contain placeholder text (`TODO`, `FIXME`, `$(PRODUCT_NAME)`, `"Required"`, `"test"`), or do not accurately describe the specific data use. In the security context a vague or empty string prevents the user from making an informed consent decision: the system TCC prompt quotes this string verbatim. A misleading description is a social-engineering vector that conceals actual data-collection intent and, when the string is clearly generic, signals that the capability was added mechanically without privacy review.
- Grep: `<key>NS\w+UsageDescription</key>\s*<string></string>` or `<string>(TODO|FIXME|\$\(PRODUCT_NAME\))</string>` following an `NS*UsageDescription` key
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

## Secure patterns

Minimal MAS `.entitlements` file with App Sandbox enabled, scoped network-client-only access, and camera capability; paired with an `Info.plist` that carries honest, specific usage descriptions:

```xml
<!-- MyApp.entitlements — Mac App Store distribution.
     app-sandbox is required for MAS.
     Only the exact capabilities the app ships with are listed.
     No network.server, no temporary-exception, no files.all. -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Required for Mac App Store submission. -->
    <key>com.apple.security.app-sandbox</key>
    <true/>

    <!-- Outbound network calls only; no inbound listener. -->
    <key>com.apple.security.network.client</key>
    <true/>

    <!-- Camera capability paired with NSCameraUsageDescription below. -->
    <key>com.apple.security.device.camera</key>
    <true/>
</dict>
</plist>
```

```xml
<!-- Info.plist — paired NS*UsageDescription entries.
     Each string names the specific feature and states data handling explicitly.
     The system TCC prompt quotes these strings verbatim. -->
<key>NSCameraUsageDescription</key>
<string>ScanApp uses the camera to read QR codes on product packaging. Images are processed on-device and are never uploaded or stored.</string>
```

Source: https://developer.apple.com/documentation/security/app_sandbox

Minimal XPC helper `.entitlements` that inherits the host app's sandbox and declares only microphone access on top of what the host already grants:

```xml
<!-- MyAppHelper.entitlements — XPC helper target.
     inherit=true: child runs inside the host app's sandbox container
     rather than a separately defined one.
     app-sandbox=true is still required; inherit=true narrows to host rules. -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>

    <!-- Inherit the host app's sandbox container and permissions. -->
    <key>com.apple.security.inherit</key>
    <true/>

    <!-- Minimum additional capability needed only by this helper. -->
    <key>com.apple.security.device.microphone</key>
    <true/>
</dict>
</plist>
```

Source: https://developer.apple.com/documentation/security/app_sandbox

## Fix recipes

### Recipe: Replace `com.apple.security.files.all` with `user-selected.read-write` and a security-scoped bookmark flow — addresses CWE-732

**Before (dangerous):**

```xml
<!-- Grants read/write to every file in the user's home directory.
     Rejected by MAS review; massively over-privileged for typical use. -->
<key>com.apple.security.files.all</key>
<true/>
```

**After (safe):**

```xml
<!-- Grants read/write only to files the user explicitly selects via
     NSOpenPanel or NSSavePanel.  Security-scoped bookmarks let the app
     re-open those files across launches without presenting the panel again. -->
<key>com.apple.security.files.user-selected.read-write</key>
<true/>
```

```swift
// Swift: persist access via a security-scoped bookmark after the user picks
// a file through NSOpenPanel so the sandbox allows re-access on relaunch.
func openAndBookmark(url: URL) throws -> Data {
    // Start accessing the security-scoped resource.
    guard url.startAccessingSecurityScopedResource() else {
        throw SandboxError.accessDenied
    }
    defer { url.stopAccessingSecurityScopedResource() }

    // Create a bookmark so the app can reopen the file after relaunch.
    let bookmark = try url.bookmarkData(
        options: .withSecurityScope,
        includingResourceValuesForKeys: nil,
        relativeTo: nil
    )
    // Persist `bookmark` to UserDefaults or a database keyed by file identity.
    return bookmark
}
```

Remove `com.apple.security.files.all` entirely. If the app genuinely needs to traverse an arbitrary directory tree (e.g. a backup utility), use `com.apple.security.files.user-selected.read-write` plus `com.apple.security.files.bookmarks.app-scope` and prompt the user to select the root folder once; bookmark that URL and access descendants within the security scope.

Source: https://developer.apple.com/documentation/security/app_sandbox

### Recipe: Add missing `NSCameraUsageDescription` to pair with the camera entitlement — addresses CWE-359

**Before (dangerous):**

```xml
<!-- MyApp.entitlements: camera entitlement declared … -->
<key>com.apple.security.device.camera</key>
<true/>

<!-- … but Info.plist contains no NSCameraUsageDescription.
     macOS refuses to show the TCC prompt; camera access silently fails.
     MAS submission is rejected at review. -->
```

**After (safe):**

```xml
<!-- Info.plist: add a usage description that names the feature and
     states what happens to captured images.
     The string is quoted verbatim in the system TCC permission dialog. -->
<key>NSCameraUsageDescription</key>
<string>ScanApp uses the camera to read QR codes on product packaging. Images are processed on-device and are never uploaded or stored.</string>
```

The description must be specific: state which feature uses the camera, what the captured data is used for, and whether it leaves the device. Generic strings such as `"Camera access required"` or `"Needed for app features"` will cause App Store review rejection and deprive the user of the information needed to make an informed consent decision.

Source: https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

### Recipe: Remove `com.apple.security.temporary-exception.*` and migrate to the correct permanent entitlement — addresses CWE-693

**Before (dangerous):**

```xml
<!-- temporary-exception.files.absolute-path grants read/write to an
     arbitrary path outside the sandbox container.
     Apple documents these as migration aids; they are rejected in MAS
     release submissions and signal an incomplete sandbox migration. -->
<key>com.apple.security.temporary-exception.files.absolute-path.read-write</key>
<array>
    <string>/Users/</string>
</array>
```

**After (safe):**

```xml
<!-- Replace the blanket absolute-path exception with the scoped alternative.
     The app now requests only files the user explicitly selects; there is
     no unconditional access to /Users/.
     If the app previously needed access to a well-known location
     (e.g. ~/Music, ~/Downloads) use the corresponding scoped entitlement
     instead: com.apple.security.files.music-folder-read, etc. -->
<key>com.apple.security.files.user-selected.read-write</key>
<true/>

<!-- If cross-launch access to a user-selected location is required,
     also add the bookmarks entitlement and persist a security-scoped
     bookmark as shown in the files.all fix recipe above. -->
<key>com.apple.security.files.bookmarks.app-scope</key>
<true/>
```

Audit every `com.apple.security.temporary-exception.*` key for what capability it was standing in for, then map it to a permanent entitlement. Common mappings: `temporary-exception.files.absolute-path.*` → `files.user-selected.*` plus bookmarks; `temporary-exception.mach-lookup.global-name` → `com.apple.security.temporary-exception.mach-lookup.global-name` has no direct replacement — refactor the IPC to use XPC services with explicit connection policies instead. Remove all temporary-exception keys before submitting to the MAS or Developer-ID notarisation.

Source: https://developer.apple.com/documentation/security/app_sandbox

## Version notes

- `com.apple.security.app-sandbox` has been required for Mac App Store submissions since macOS 10.7 (Lion) / Xcode 4.3. Developer-ID distributed apps are not required to be sandboxed by the OS, but starting with macOS 13 (Ventura) Gatekeeper additionally enforces that all first-run Developer-ID binaries pass notarisation, which itself does not mandate the sandbox but does require hardened-runtime code signing (`com.apple.security.cs.*`). See `macos-hardened-runtime.md`.
- `NSBluetoothAlwaysUsageDescription` replaced `NSBluetoothPeripheralUsageDescription` as the required key for Core Bluetooth on macOS 12+ / iOS 13+. Both keys may need to be present in projects with a deployment target below macOS 12; include both for backward compatibility.
- `NSLocationWhenInUseUsageDescription` is accepted on macOS 13+. On macOS 12 and earlier, apps using `CLLocationManager` require `NSLocationUsageDescription` (deprecated but still honoured). Dual-target projects should include both keys.
- `com.apple.security.personal-information.location` is the sandbox entitlement for Core Location on macOS; it does not correspond 1:1 with the iOS entitlement, which is handled purely through `NS*UsageDescription` without a sandbox key. Flag projects that copy iOS entitlements verbatim to macOS targets — the macOS sandbox entitlement must be explicitly added.
- Security-scoped bookmarks (`com.apple.security.files.bookmarks.app-scope`) require macOS 10.7.3+. For documents shared between apps via iCloud use `com.apple.security.files.bookmarks.document-scope` instead.

## Common false positives

- `com.apple.security.network.server=true` in a debug or development `.entitlements` scheme — many Xcode projects maintain a separate `*Debug.entitlements` that includes server access for local development proxies or test harnesses; flag only if the production distribution scheme entitlements file carries the key.
- `com.apple.security.temporary-exception.*` in a `*Dev.entitlements` or `*Debug.entitlements` — acceptable in debug/staging schemes as long as it does not appear in the release distribution entitlements. Confirm which entitlements file is signed into the App Store or Developer-ID archive.
- `com.apple.security.files.all` present alongside `com.apple.security.app-sandbox=false` in a non-MAS CLI tool — command-line tools distributed outside the MAS are not required to be sandboxed; `files.all` in that context is a no-op entitlement rather than an active over-privilege. Flag only when `app-sandbox=true` is also present.
- Short `NS*UsageDescription` values (under 30 characters) that are genuinely specific (e.g. `"Scan barcodes"`, `"Record audio memos"`) — App Store review rejects obviously generic or empty strings, not concise ones; do not flag a short string as a CWE-357 indicator without confirming it is generic or misleading.
- `com.apple.security.inherit=true` absent from a non-sandboxed helper — `inherit` is only meaningful when `app-sandbox=true` is also set. If the helper target does not declare `app-sandbox`, the absence of `inherit` is not a finding.
