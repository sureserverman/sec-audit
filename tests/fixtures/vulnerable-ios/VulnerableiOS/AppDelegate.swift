// Intentionally-vulnerable iOS source for fixture purposes.
// Paired with Info.plist / .entitlements in this fixture.
//
// Every pattern below is chosen because a rule in mobsfscan 0.4.5's
// rules/patterns/ios/swift/swift_rules.yaml matches it (the rule id is named
// in the comment); the CWE tags are what the sec-expert reference packs see.

import UIKit
import Security
import WebKit
import AVFoundation
import CommonCrypto

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions
                     launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

        // CWE-312: credential stored in UserDefaults (unencrypted).
        // mobsfscan ios_hardcoded_secret: `key = "..."` / `password = "..."`.
        let apiKey = "fixture-api-key-DEADBEEFCAFEBABE1234567890"
        let password = "hunter2-fixture-only"
        UserDefaults.standard.set(apiKey, forKey: "api_key")
        UserDefaults.standard.set(password, forKey: "session_password")

        // CWE-532: sensitive data logged. mobsfscan ios_log.
        print("issued api key \(apiKey)")

        // CWE-522: Keychain item with insecure accessibility class.
        // mobsfscan ios_keychain_weak_accessibility_value.
        let secret = password.data(using: .utf8)!
        let keychainQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "com.example.vulnerable",
            kSecAttrAccount: "user@example.com",
            kSecValueData: secret,
            kSecAttrAccessible: kSecAttrAccessibleAlways
        ]
        SecItemAdd(keychainQuery as CFDictionary, nil)

        // CWE-327: MD5 for an integrity check. mobsfscan ios_weak_hash.
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        _ = CC_MD5(apiKey, CC_LONG(apiKey.utf8.count), &digest)

        // CWE-330: session token from a non-cryptographic RNG.
        // mobsfscan ios_insecure_random_no_generator.
        let sessionNonce = Int.random(in: 0..<1_000_000)

        // CWE-311: file written with no data-protection class.
        // mobsfscan ios_file_no_special.
        try? secret.write(to: URL(fileURLWithPath: "/tmp/nonce-\(sessionNonce)"),
                          options: .noFileProtection)

        // CWE-79 / CWE-749: WKWebView with JS bridge + attacker-influenced HTML.
        // mobsfscan ios_load_html_string (loadHTMLString + webView in one file).
        let webView = WKWebView()
        let cfg = WKWebViewConfiguration()
        cfg.userContentController.add(self as! WKScriptMessageHandler,
                                      name: "VulnerableBridge")
        webView.loadHTMLString(launchOptions?.description ?? "", baseURL: nil)

        // CWE-919: deprecated UIWebView still referenced. mobsfscan ios_uiwebview.
        let legacy = UIWebView()
        legacy.loadRequest(URLRequest(url: URL(string: "http://example.com/")!))

        // Paired with missing NSCameraUsageDescription in Info.plist (crashes at runtime).
        _ = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)

        return true
    }
}
