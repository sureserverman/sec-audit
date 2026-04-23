# iOS App Data Storage

## Source

- https://developer.apple.com/documentation/security/keychain_services — Keychain Services API reference
- https://developer.apple.com/documentation/localauthentication — Local Authentication (LAContext / biometric) API reference
- https://developer.apple.com/documentation/foundation/nsfileprotectionkey — NSFileProtectionKey attribute reference
- https://developer.apple.com/documentation/foundation/userdefaults — UserDefaults API reference
- https://developer.apple.com/documentation/cloudkit — CloudKit API reference
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet

## Scope

In scope: iOS app data storage — Keychain accessibility classes, Keychain access-control flags, UserDefaults / NSUserDefaults credential storage, file Data Protection attributes (NSFileProtection), CloudKit public-vs-private database usage, LAContext biometric-enrollment-state pinning, and hardcoded credentials and managed-configuration escape via CFPreferences. Out of scope: Info.plist transport-security and permission-string hardening (`ios-plist.md`); code-signing, entitlement declarations, and provisioning profile review (`ios-codesign.md`); network-layer TLS configuration and certificate-pinning (`references/tls/`); tool invocations for static and dynamic scanning (`mobile-tools.md`).

## Dangerous patterns (regex/AST hints)

### Keychain item stored with `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAlwaysThisDeviceOnly` — CWE-522

- Why: These accessibility constants allow the Keychain item to be read while the device is locked; they were deprecated in iOS 13. Any process that can query the Keychain — including malware that exploits a sandbox escape — can retrieve the item without the user ever unlocking the device. Credentials, tokens, and private keys stored under these classes have no protection budget when the device is seized or compromised.
- Grep: `kSecAttrAccessibleAlways`
- File globs: `**/*.swift`, `**/*.m`, `**/*.mm`
- Source: https://developer.apple.com/documentation/security/keychain_services

### Keychain item stored with `kSecAttrAccessibleAfterFirstUnlock` for security-sensitive data — CWE-522 / CWE-312

- Why: `kSecAttrAccessibleAfterFirstUnlock` and its `ThisDeviceOnly` variant keep the item decrypted in memory from the first user unlock until the next reboot. Background malware or a stolen unlocked device can read the item at any point during that window without triggering a biometric or passcode prompt. This class is intended only for items accessed by background daemons that cannot prompt the user; it must not be used for passwords, refresh tokens, biometric-gated credentials, or signing keys.
- Grep: `kSecAttrAccessibleAfterFirstUnlock[^T]`
- File globs: `**/*.swift`, `**/*.m`, `**/*.mm`
- Source: https://developer.apple.com/documentation/security/keychain_services

### `UserDefaults` / `NSUserDefaults` storing credentials or tokens — CWE-312

- Why: `UserDefaults` serialises data to an unencrypted plist file under the app's Library/Preferences container. On a jailbroken device, via an iTunes/iCloud backup without backup encryption, or through a physical acquisition tool, the file is readable in plaintext. Credentials, tokens, and API keys stored here are trivially extracted.
- Grep: `UserDefaults\.standard\.set\s*\(.*\b(token|password|secret|api[_-]?key|jwt|bearer|auth)\b` (Swift); `\[\[NSUserDefaults standardUserDefaults\] setObject:.*forKey:\s*@"(token|password|secret|api[_-]?key|jwt)"` (Obj-C)
- File globs: `**/*.swift`, `**/*.m`, `**/*.mm`
- Source: https://developer.apple.com/documentation/foundation/userdefaults

### File written without `NSFileProtection` attribute or with `NSFileProtectionNone` — CWE-311

- Why: Files without an explicit Data Protection class default to `NSFileProtectionNone`, which means the file is accessible even when the device is locked and the user's passcode has never been entered. Sensitive data in files (certificates, session caches, downloaded documents) should use `NSFileProtectionComplete` so the file is encrypted whenever the device is locked.
- Grep: `FileProtectionType\.none|NSFileProtectionNone|NSFileProtectionType\.none`
- File globs: `**/*.swift`, `**/*.m`, `**/*.mm`
- Source: https://developer.apple.com/documentation/foundation/nsfileprotectionkey

### CloudKit public database used for user-private data — CWE-200 / CWE-732

- Why: `CKContainer.default().publicCloudDatabase` stores records that are readable by any authenticated iCloud user — and in some configurations by unauthenticated queries. Selecting `publicCloudDatabase` when `privateCloudDatabase` was intended exposes user records, tokens, or PII to the entire CloudKit user population. The distinction is easy to miss because both properties compile without error in identical call patterns.
- Grep: `publicCloudDatabase`
- File globs: `**/*.swift`, `**/*.m`, `**/*.mm`
- Source: https://developer.apple.com/documentation/cloudkit

### `LAContext.evaluatePolicy` without `evaluatedPolicyDomainState` pinning — CWE-287 / CWE-1289

- Why: When a new fingerprint or Face ID enrollment is added to the device, the biometric domain state changes. Without snapshotting `evaluatedPolicyDomainState` before the first successful authentication and comparing it before each subsequent use, an attacker who gains brief physical access can enroll a new biometric and then authenticate as the victim with their own finger or face. The key or credential gated by the biometric is never invalidated. Pair the grep match with a check for the absence of any reference to `evaluatedPolicyDomainState` in the same scope.
- Grep: `evaluatePolicy\s*\(`
- File globs: `**/*.swift`, `**/*.m`, `**/*.mm`
- Source: https://developer.apple.com/documentation/localauthentication

### Hardcoded API keys or private key material in source — CWE-798

- Why: Secrets committed in source are embedded verbatim in every copy of the repository, every compiled binary (extractable via strings or disassembly), and every CI log. AWS access key IDs, Stripe live-mode secret keys, and PEM private keys committed here require rotation as the only remediation once they escape; the secret is considered permanently compromised.
- Grep: `AKIA[0-9A-Z]{16}|-----BEGIN\s+(RSA|EC|OPENSSH|PRIVATE)\s+KEY-----|sk_live_[A-Za-z0-9]{24,}`
- File globs: `**/*.swift`, `**/*.m`, `**/*.mm`, `**/*.plist`, `**/*.json`, `**/*.yaml`, `**/*.yml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

### `CFPreferences` / managed-configuration plist used for secrets — CWE-522

- Why: Values read via `CFPreferencesCopyAppValue` or the managed-configuration Plist (`com.apple.configuration.managed`) can be written by an MDM profile. An MDM operator — or an attacker who provisions a fraudulent MDM profile — can inject arbitrary values, including what the app treats as a secret. Apps should never treat managed-configuration values as trusted credentials; they are configuration hints, not authentication material.
- Grep: `CFPreferencesCopyAppValue|UserDefaults\.init\(suiteName:\s*"com\.apple\.configuration\.managed"\)`
- File globs: `**/*.swift`, `**/*.m`, `**/*.mm`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

## Secure patterns

Keychain item added with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and a `SecAccessControl` requiring biometric presence — the item is readable only when the device is unlocked, is bound to the device (not migrated via iCloud Keychain backup), and requires a fresh biometric challenge on every read:

```swift
import Security
import LocalAuthentication

// 1. Create an access-control object requiring Face ID / Touch ID on every use.
//    .biometryCurrentSet means the key is invalidated if a new biometric is enrolled.
var cfError: Unmanaged<CFError>?
guard let access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,   // locked = inaccessible
    [.biometryCurrentSet, .privateKeyUsage],         // any new enrollment invalidates item
    &cfError
) else {
    throw cfError!.takeRetainedValue() as Error
}

// 2. Build the Keychain add query.
let addQuery: [String: Any] = [
    kSecClass as String:           kSecClassGenericPassword,
    kSecAttrAccount as String:     "refresh_token",
    kSecAttrAccessControl as String: access,
    kSecUseDataProtectionKeychain as String: true,
    kSecValueData as String:       tokenData     // Data
]

let status = SecItemAdd(addQuery as CFDictionary, nil)
guard status == errSecSuccess else { throw KeychainError.addFailed(status) }
```

Source: https://developer.apple.com/documentation/security/keychain_services

LAContext flow that snapshots `evaluatedPolicyDomainState` before authentication and compares the snapshot before each subsequent sensitive operation, invalidating the Keychain item if the biometric domain state has changed:

```swift
import LocalAuthentication

class BiometricGate {
    private var domainStateSnapshot: Data?

    /// Call once at session start, after the first successful authentication.
    func authenticate(reason: String) async throws {
        let context = LAContext()
        var authError: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                        error: &authError) else {
            throw authError ?? LAError(.biometryNotAvailable)
        }

        try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )

        // Snapshot the enrollment state immediately after a successful auth.
        domainStateSnapshot = context.evaluatedPolicyDomainState
    }

    /// Call before every sensitive operation that relies on the biometric gate.
    /// Returns false if enrollment has changed since the snapshot was taken.
    func isBiometricDomainStateValid() -> Bool {
        guard let snapshot = domainStateSnapshot else { return false }
        let context = LAContext()
        var authError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                        error: &authError) else { return false }
        // If evaluatedPolicyDomainState differs, a new biometric was added.
        guard let currentState = context.evaluatedPolicyDomainState else { return false }
        return currentState == snapshot
    }
}
```

Source: https://developer.apple.com/documentation/localauthentication

## Fix recipes

### Recipe: Migrate UserDefaults secret to Keychain with strict accessibility class — addresses CWE-312

**Before (dangerous):**

```swift
// Token stored as plaintext in Library/Preferences/<bundle-id>.plist
UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
```

**After (safe):**

```swift
import Security

func storeRefreshToken(_ token: String) throws {
    guard let tokenData = token.data(using: .utf8) else { return }

    // Delete any existing item first to avoid errSecDuplicateItem.
    let deleteQuery: [String: Any] = [
        kSecClass as String:       kSecClassGenericPassword,
        kSecAttrAccount as String: "refresh_token"
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    // Store under the strictest class that still allows background-daemons access
    // only when unlocked.  For tokens never needed in the background, prefer
    // kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.
    let addQuery: [String: Any] = [
        kSecClass as String:           kSecClassGenericPassword,
        kSecAttrAccount as String:     "refresh_token",
        kSecAttrAccessible as String:  kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecUseDataProtectionKeychain as String: true,
        kSecValueData as String:       tokenData
    ]
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError.addFailed(status) }
}
```

Source: https://developer.apple.com/documentation/security/keychain_services

### Recipe: Set `NSFileProtectionComplete` on a sensitive file via FileManager — addresses CWE-311

**Before (dangerous):**

```swift
// File written with no protection attribute — defaults to NSFileProtectionNone
let url = documentsDirectory.appendingPathComponent("session_cache.dat")
try data.write(to: url)
```

**After (safe):**

```swift
import Foundation

let url = documentsDirectory.appendingPathComponent("session_cache.dat")

// Write the file first, then apply the protection attribute.
// NSFileProtectionComplete: file is inaccessible while the device is locked.
try data.write(to: url, options: .atomic)
try FileManager.default.setAttributes(
    [.protectionKey: FileProtectionType.complete],
    ofItemAtPath: url.path
)

// Alternatively, open via a stream with protection set before writing:
// FileManager.default.createFile(
//     atPath: url.path,
//     contents: nil,
//     attributes: [.protectionKey: FileProtectionType.complete]
// )
```

Source: https://developer.apple.com/documentation/foundation/nsfileprotectionkey

### Recipe: Wrap a Keychain item in `SecAccessControlCreateWithFlags(.biometryCurrentSet)` so new biometric enrollment invalidates the key — addresses CWE-287 / CWE-1289

**Before (dangerous):**

```swift
// No access control — any process that reaches the Keychain can read the item;
// new biometric enrollment does NOT invalidate the item.
let addQuery: [String: Any] = [
    kSecClass as String:          kSecClassGenericPassword,
    kSecAttrAccount as String:    "signing_key",
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
    kSecValueData as String:      keyData
]
SecItemAdd(addQuery as CFDictionary, nil)
```

**After (safe):**

```swift
import Security

var cfError: Unmanaged<CFError>?

// .biometryCurrentSet: the item is deleted automatically when a new fingerprint
// or face is enrolled, preventing biometric-substitution attacks.
// .biometryAny would survive re-enrollment and must NOT be used here.
guard let access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .biometryCurrentSet,
    &cfError
) else {
    throw cfError!.takeRetainedValue() as Error
}

let addQuery: [String: Any] = [
    kSecClass as String:             kSecClassGenericPassword,
    kSecAttrAccount as String:       "signing_key",
    kSecAttrAccessControl as String: access,       // replaces kSecAttrAccessible
    kSecUseDataProtectionKeychain as String: true,
    kSecValueData as String:         keyData
]
let status = SecItemAdd(addQuery as CFDictionary, nil)
guard status == errSecSuccess else { throw KeychainError.addFailed(status) }
```

Source: https://developer.apple.com/documentation/security/keychain_services

## Version notes

- `kSecAttrAccessibleAlways` and `kSecAttrAccessibleAlwaysThisDeviceOnly` were deprecated in iOS 13 / macOS 10.15. They remain compile-time visible but should not appear in any new code; Xcode will emit a deprecation warning.
- `kSecUseDataProtectionKeychain` was added in iOS 13 and macOS 10.15 for macOS Catalyst and macOS apps using the Keychain on macOS; it is a no-op on iOS but should be included for cross-platform code clarity.
- `.biometryCurrentSet` as an access-control flag requires iOS 11.3+. On iOS 11.0–11.2, use `.touchIDCurrentSet` (the predecessor constant, equivalent on those versions).
- `LAContext.evaluatedPolicyDomainState` returns `nil` when no biometric hardware is enrolled; callers must treat a `nil` return as an invalid state and refuse access rather than falling through.
- `SecAccessControlCreateWithFlags` with `[.biometryCurrentSet, .privateKeyUsage]` is intended for Secure Enclave key pairs (`kSecAttrTokenIDSecureEnclave`); for generic-password items use `.biometryCurrentSet` alone.
- CloudKit container configurations (`CKContainer(identifier:)`) are available on iOS 8+; `privateCloudDatabase` and `sharedCloudDatabase` require the user to be signed in to iCloud — always check `CKContainer.default().accountStatus` before attempting a private database operation.

## Common false positives

- `kSecAttrAccessibleAfterFirstUnlock` in code that manages push-notification credentials or background-refresh tokens — lower severity if the item is not a user authentication credential; flag but note the background-access rationale.
- `UserDefaults.standard.set` with a key name containing "token" where the value is a non-secret UI preference token (e.g. a theme identifier or a pagination cursor) — grep is intentionally broad; review the value type before flagging.
- `publicCloudDatabase` used to store intentionally public content such as app-level announcements, leaderboards, or public asset references — flagging is only warranted when adjacent record types or field names suggest user-private data is being written.
- `evaluatePolicy` grep will match legitimate informational canEvaluatePolicy calls (e.g. checking for biometric availability to show or hide UI); a finding requires the absence of `evaluatedPolicyDomainState` in the same authentication flow, not merely the same file.
- `CFPreferencesCopyAppValue` reading non-sensitive managed configuration (e.g. a server hostname or feature flag) — acceptable when the value controls connectivity, not authentication; flag only when the app treats the managed-config value as a credential or uses it to bypass an auth check.
