// Intentionally-vulnerable macOS AppKit source for fixture purposes.
//
// mobsfscan applies its Swift rule set (rules/patterns/ios/swift/) to any
// .swift file, macOS included; each pattern below names the rule it trips.

import Cocoa
import AVFoundation
import CommonCrypto

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationDidFinishLaunching(_ notification: Notification) {
        // CWE-312: credential stored in UserDefaults (unencrypted plist on disk).
        // mobsfscan ios_hardcoded_secret.
        let apiKey = "fixture-api-key-MACOSDEADBEEFCAFEBABE12345"
        UserDefaults.standard.set(apiKey, forKey: "api_key")

        // CWE-532: the key is logged. mobsfscan ios_log.
        NSLog("update feed key %@", apiKey)

        // CWE-327: MD5 to verify a downloaded update. mobsfscan ios_weak_hash.
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        _ = CC_MD5(apiKey, CC_LONG(apiKey.utf8.count), &digest)

        // CWE-330: installer nonce from arc4random. mobsfscan ios_insecure_random_no_generator.
        let nonce = arc4random_uniform(1_000_000)

        // CWE-522: keychain item readable while locked.
        // mobsfscan ios_keychain_weak_accessibility_value.
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: "updater-\(nonce)",
            kSecValueData: apiKey.data(using: .utf8)!,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock
        ]
        SecItemAdd(query as CFDictionary, nil)

        // Paired with missing NSCameraUsageDescription — runtime crash risk.
        _ = AVCaptureDevice.default(for: .video)
    }
}
