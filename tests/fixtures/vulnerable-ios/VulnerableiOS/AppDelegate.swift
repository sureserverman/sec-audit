// Intentionally-vulnerable iOS source for fixture purposes.
// Paired with Info.plist / .entitlements in this fixture.

import UIKit
import Security
import WebKit
import AVFoundation

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions
                     launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

        // CWE-312: credential stored in UserDefaults (unencrypted).
        UserDefaults.standard.set("sk_live_DEADBEEFCAFEBABE1234567890ABCDEF",
                                  forKey: "api_key")
        UserDefaults.standard.set("eyJhbGciOiJIUzI1NiJ9.fake.jwt",
                                  forKey: "session_token")

        // CWE-522: Keychain item with insecure accessibility class.
        let secret = "user-password".data(using: .utf8)!
        let keychainQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "com.example.vulnerable",
            kSecAttrAccount: "user@example.com",
            kSecValueData: secret,
            kSecAttrAccessible: kSecAttrAccessibleAlways
        ]
        SecItemAdd(keychainQuery as CFDictionary, nil)

        // CWE-79 / CWE-749: WKWebView with JS bridge + arbitrary URL.
        let webView = WKWebView()
        let cfg = WKWebViewConfiguration()
        cfg.userContentController.add(self as! WKScriptMessageHandler,
                                      name: "VulnerableBridge")
        webView.load(URLRequest(url: URL(string: "http://example.com/")!))

        // Paired with missing NSCameraUsageDescription in Info.plist (crashes at runtime).
        _ = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)

        return true
    }
}
