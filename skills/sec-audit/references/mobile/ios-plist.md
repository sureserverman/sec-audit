# iOS / Info.plist

## Source

- https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html — Info.plist Key Reference: Cocoa Keys — complete key descriptions, value types, and usage guidance for all Info.plist properties
- https://developer.apple.com/documentation/bundleresources/information_property_list — Information Property List — canonical bundle resource reference for structured Info.plist keys
- https://developer.apple.com/documentation/security/preventing_insecure_network_connections — Preventing Insecure Network Connections — Apple's ATS guide: NSAppTransportSecurity, NSExceptionDomains, cipher requirements, and TLS minimums
- https://developer.apple.com/documentation/bundleresources/entitlements — Entitlements — Apple entitlement key reference for sandbox and capability declarations
- https://developer.apple.com/app-store/review/guidelines/ — App Store Review Guidelines — policy requirements for usage descriptions, background modes, export compliance, and privacy
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet

## Scope

In-scope: iOS `Info.plist` security-relevant keys — App Transport Security (ATS) configuration keys under `NSAppTransportSecurity`, custom URL scheme registration via `CFBundleURLTypes`, background execution modes under `UIBackgroundModes`, sensitive API usage descriptions (`NS*UsageDescription` keys), and the `ITSAppUsesNonExemptEncryption` export-compliance declaration. Out of scope: on-device data storage classes and Keychain API usage (`ios-data.md`); code signing, provisioning profiles, and entitlement declarations (`ios-codesign.md`); tool invocations such as `objection`, `frida-ios-dump`, and MobSF (`mobile-tools.md`).

## Dangerous patterns (regex/AST hints)

### `NSAllowsArbitraryLoads = true` globally disabling ATS — CWE-319

- Why: Setting `NSAllowsArbitraryLoads` to `true` inside `NSAppTransportSecurity` disables App Transport Security for every network connection the app makes, permitting plaintext HTTP and weak TLS to any host. This fully removes the platform-level guarantee of encrypted transit and exposes all app traffic to passive interception and active MitM attacks.
- Grep: `<key>NSAllowsArbitraryLoads</key>\s*<true/>`
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/documentation/security/preventing_insecure_network_connections

### `NSExceptionAllowsInsecureHTTPLoads` per-domain ATS exemption — CWE-319

- Why: An `NSExceptionDomains` entry with `NSExceptionAllowsInsecureHTTPLoads = true` re-enables plaintext HTTP for a named domain. When the exempted domain is a first-party API host, CDN origin, or analytics endpoint rather than a genuinely legacy third-party asset host, the exception is broader than necessary and exposes authentication tokens, session cookies, and API payloads to interception in transit.
- Grep: `NSExceptionAllowsInsecureHTTPLoads`
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/documentation/security/preventing_insecure_network_connections

### Custom URL scheme registered without origin validation — CWE-939

- Why: An app that registers a `CFBundleURLSchemes` entry in `CFBundleURLTypes` becomes a handler for that scheme system-wide. Any other app or a browser-opened link can invoke the registered handler by crafting a URI with that scheme. Without explicit origin validation in the handler — verifying the calling app's bundle ID or validating an HMAC/state parameter — the handler can be invoked by a malicious app supplying forged parameters, enabling OAuth redirect hijacking, unvalidated deep-link ingestion, or unauthorized state transitions.
- Grep: `<key>CFBundleURLSchemes</key>`
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

### `UIBackgroundModes` entry without corresponding usage description — App Store Review Guideline 2.5.4

- Why: Background modes such as `audio`, `location`, and `voip` keep an app running or woken after the user has left it. Apple's App Store Review Guideline 2.5.4 requires that each declared background mode be justified; in the security context, an app claiming `location` in `UIBackgroundModes` without a corresponding `NSLocationAlwaysAndWhenInUseUsageDescription` (or the weaker `NSLocationAlwaysUsageDescription` for older targets) crashes at runtime on first location access and signals that the capability was added without the corresponding privacy disclosure, which can mask covert background tracking.
- Grep: `<key>UIBackgroundModes</key>`
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/app-store/review/guidelines/

### Missing `NS*UsageDescription` for sensitive API access — CWE-522 adjacent

- Why: iOS requires a corresponding `NS*UsageDescription` key in `Info.plist` for every privacy-sensitive API family the app accesses. Without it, the OS terminates the app with a `SIGABRT` the first time access is attempted, producing no user-facing permission dialog. Absence of the key indicates that the API is being invoked without user consent infrastructure — a gap reviewers treat as equivalent to missing a credential gate. Affected keys: `NSCameraUsageDescription` (paired with `AVCaptureDevice`), `NSMicrophoneUsageDescription` (paired with `AVAudioSession`), `NSLocationWhenInUseUsageDescription` (paired with `CLLocationManager`), `NSContactsUsageDescription` (paired with `CNContactStore`), `NSFaceIDUsageDescription` (paired with `LAContext`).
- Grep: `AVCaptureDevice\|CLLocationManager\|LAContext\|CNContactStore\|AVAudioSession` (in source) paired with absence of corresponding `NS*UsageDescription` in `Info.plist`
- File globs: `**/Info.plist`, `**/*.swift`, `**/*.m`
- Source: https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

### `ITSAppUsesNonExemptEncryption` absent or undocumented — App Store / US export policy

- Why: Apps that incorporate non-exempt cryptography must declare `ITSAppUsesNonExemptEncryption = true` and submit an annual self-classification report to the US Bureau of Industry and Security under EAR. Omitting the key, or setting it to `false` for an app that uses TLS, AES, or any other non-exempt algorithm, constitutes a false export-compliance certification submitted at each App Store release. Note: this is an App Store policy obligation rather than a runtime security vulnerability, but it is listed here because an absent or falsified key appears in `Info.plist` and surfaces during manifest review.
- Grep: `ITSAppUsesNonExemptEncryption`
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/app-store/review/guidelines/

### `NSAllowsLocalNetworking = true` in ATS — CWE-319

- Why: `NSAllowsLocalNetworking` permits the app to connect to unqualified hostnames (e.g. `*.local` Bonjour names) and link-local addresses over plaintext HTTP. For apps that do not require LAN service discovery, the key should be absent or explicitly `false`. When it is present but the app communicates only with public HTTPS endpoints, the exception is a misconfiguration that creates an unnecessary cleartext path exploitable by a local network attacker.
- Grep: `NSAllowsLocalNetworking`
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/documentation/security/preventing_insecure_network_connections

### `NSCameraUsageDescription` with empty or boilerplate text — CWE-357

- Why: Apple rejects submissions where `NS*UsageDescription` values are empty strings, placeholder text (e.g. `"TODO"`, `"Camera access"`), or text that does not accurately describe why the app requires the capability. In the security context, a vague or misleading description prevents users from making an informed consent decision and constitutes a social-engineering vector: the system permission dialog quotes this string verbatim, so an app claiming `"Needed for app functionality"` conceals actual data collection intent.
- Grep: `NSCameraUsageDescription`
- File globs: `**/Info.plist`
- Source: https://developer.apple.com/app-store/review/guidelines/

## Secure patterns

Minimal ATS configuration that disables arbitrary loads and enforces TLS 1.3 for a single exception domain, with no global cleartext exemptions:

```xml
<!-- Info.plist: tight ATS configuration.
     NSAllowsArbitraryLoads is absent (defaults to false).
     The sole exception domain uses TLS 1.3 and does NOT allow insecure HTTP. -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-partner.example.com</key>
        <dict>
            <!-- Require at least TLS 1.3 even for this exception domain. -->
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.3</string>
            <!-- Plaintext HTTP is still disallowed. -->
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <!-- Forward secrecy requirement is maintained. -->
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

Source: https://developer.apple.com/documentation/security/preventing_insecure_network_connections

Correct `NSLocationWhenInUseUsageDescription` that names the specific app purpose and data use, satisfying both App Store Review and the user's informed-consent decision:

```xml
<!-- Info.plist: usage description that names the feature and the data use.
     The string is surfaced verbatim in the system permission dialog. -->
<key>NSLocationWhenInUseUsageDescription</key>
<string>RouteTracker uses your location while the app is open to display your current position on the route map. Location data is not stored or shared.</string>

<key>NSCameraUsageDescription</key>
<string>ScanApp uses the camera to read QR codes on product packaging. Images are processed on-device and are never uploaded or stored.</string>

<key>NSFaceIDUsageDescription</key>
<string>VaultApp uses Face ID to authenticate you before displaying account balances. No biometric data leaves the device.</string>
```

Source: https://developer.apple.com/app-store/review/guidelines/

## Fix recipes

### Recipe: Remove `NSAllowsArbitraryLoads` and replace with scoped `NSExceptionDomains` at TLS 1.3 — addresses CWE-319

**Before (dangerous):**

```xml
<!-- Globally disables ATS; all connections may use plaintext HTTP or weak TLS. -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

**After (safe):**

```xml
<!-- NSAllowsArbitraryLoads is removed entirely (defaults to false).
     Only the single domain that genuinely requires an exception is listed.
     TLS 1.3 is enforced; plaintext HTTP remains disallowed. -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-partner.example.com</key>
        <dict>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.3</string>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

List only domains that the app genuinely cannot reach over TLS 1.2+ without an exception (e.g. a partner-operated legacy endpoint). Every first-party API host and CDN should be removed from `NSExceptionDomains` and allowed to use the default ATS policy. Submit an App Store review note explaining each remaining exception; Apple may reject submissions where the exception scope is broader than stated.

Source: https://developer.apple.com/documentation/security/preventing_insecure_network_connections

### Recipe: Add a missing `NSLocationWhenInUseUsageDescription` with user-facing rationale — addresses CWE-522 adjacent / App Store

**Before (dangerous):**

```xml
<!-- NSLocationWhenInUseUsageDescription is absent.
     CLLocationManager.requestWhenInUseAuthorization() will cause a SIGABRT
     on iOS 10+ because the required key is missing; the user never sees a
     permission dialog and location access silently fails in production. -->
<key>CFBundleDisplayName</key>
<string>RouteTracker</string>
```

**After (safe):**

```xml
<!-- Usage description present and specific: names the feature, the data
     use, and explicitly states that data is not uploaded or stored. -->
<key>NSLocationWhenInUseUsageDescription</key>
<string>RouteTracker uses your location while the app is open to display your current position on the route map. Location data is not stored or shared.</string>

<key>CFBundleDisplayName</key>
<string>RouteTracker</string>
```

Use `NSLocationWhenInUseUsageDescription` when location is only required while the app is in the foreground. Use `NSLocationAlwaysAndWhenInUseUsageDescription` (required alongside `NSLocationWhenInUseUsageDescription` for the always-on prompt on iOS 11+) only when a declared `UIBackgroundModes` entry of `location` is also present and genuinely necessary. Never use placeholder text; App Store review quotes this string verbatim.

Source: https://developer.apple.com/app-store/review/guidelines/

### Recipe: Register a custom URL scheme with `LSApplicationQueriesSchemes` and add handler origin validation — addresses CWE-939

**Before (dangerous):**

```xml
<!-- CFBundleURLTypes registers the scheme with no caller validation in the handler.
     Any app or browser link can invoke this handler with forged parameters. -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>
```

```swift
// AppDelegate.swift — no origin validation before acting on the URL.
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    handleDeepLink(url)   // processes url.queryItems directly — unsafe
    return true
}
```

**After (safe):**

```xml
<!-- Partner app's Info.plist: declares the scheme it needs to query/open
     via LSApplicationQueriesSchemes so canOpenURL works correctly. -->
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>myapp</string>
</array>

<!-- Receiving app's Info.plist: registration is unchanged, but the handler
     in code validates the source bundle ID before acting on parameters. -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
        <key>CFBundleURLName</key>
        <string>com.example.myapp</string>
    </dict>
</array>
```

```swift
// AppDelegate.swift — validate the calling app's bundle ID before processing.
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    let callerBundleID = options[.sourceApplication] as? String
    let allowedCallers: Set<String> = ["com.example.partnerapp"]
    guard let caller = callerBundleID, allowedCallers.contains(caller) else {
        return false  // reject unknown or missing callers
    }
    // Additionally validate a HMAC/state token in url.queryItems
    // before acting on any parameters.
    handleDeepLink(url)
    return true
}
```

For OAuth redirect URIs, prefer Universal Links (HTTPS scheme with Apple App Site Association) over custom URL schemes — Universal Links cannot be claimed by another app because the system verifies ownership via the AASA file on the registered domain.

Source: https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

## Version notes

- `NSAllowsArbitraryLoads` defaults to `false` for apps linked against iOS 9 SDK and later. Apps with a deployment target below iOS 9 or built with older SDKs do not enforce ATS by default; flag any project with `IPHONEOS_DEPLOYMENT_TARGET < 9.0`.
- `NSExceptionMinimumTLSVersion` values `TLSv1.0` and `TLSv1.1` remain syntactically valid but Apple's ATS documentation states TLS 1.2 is the platform floor for non-exempted connections; TLS 1.3 should be preferred for new exception domain entries.
- `NSFaceIDUsageDescription` was introduced in iOS 11. Apps with a deployment target of iOS 10 and below that call `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` only need `NSFaceIDUsageDescription` if they also ship on iOS 11+; multi-target projects should include the key unconditionally.
- `ITSAppUsesNonExemptEncryption = false` is accepted for apps that rely exclusively on operating-system-provided TLS and do not link any third-party cryptographic libraries; Apple clarified this in the App Store Connect export compliance documentation (2019). Apps linking OpenSSL, BoringSSL, or a custom cipher implementation must use `true` and provide the annual self-classification report.
- `UIBackgroundModes` key `location` requires the `Always` location authorization entitlement starting in iOS 14; apps targeting iOS 14+ that declare `location` in `UIBackgroundModes` without also requesting `NSLocationAlwaysAndWhenInUseUsageDescription` will have the background location delivery silently withheld by the OS.

## Common false positives

- `NSAllowsArbitraryLoads` set to `true` inside a `NSAllowsArbitraryLoadsInWebContent`-scoped sub-dictionary rather than at the top level of `NSAppTransportSecurity` — this narrowly permits a `WKWebView` to load user-navigated arbitrary content and does not affect URLSession or other API network calls; confirm the exact key hierarchy before elevating severity.
- `NSExceptionAllowsInsecureHTTPLoads` on a domain that is explicitly `localhost` or `127.0.0.1` — local development servers commonly require plaintext HTTP; flag only if the domain is a routable public hostname.
- `CFBundleURLSchemes` containing `fb`, `twitter`, `googlemaps`, or other well-known third-party scheme prefixes — these are outbound query schemes placed in `LSApplicationQueriesSchemes` by SDKs to check for app presence via `canOpenURL`; they do not register the app as a handler and do not create a hijackable inbound surface.
- `UIBackgroundModes` containing `remote-notification` alone — this mode is required for APNs push notification delivery and does not grant persistent background execution; it does not require an `NS*UsageDescription` and should not be flagged unless combined with another substantive mode such as `location` or `audio`.
- `NSCameraUsageDescription` present but short (under 20 characters) — App Store Review rejects obviously generic strings, but the auditor's job here is to flag strings that are empty, null, or clearly placeholder (`"Required"`, `"test"`, `"TODO"`); short but specific strings (`"Scan barcodes"`) are acceptable at the manifest level; escalate only with supporting evidence that the description is misleading about data handling.
