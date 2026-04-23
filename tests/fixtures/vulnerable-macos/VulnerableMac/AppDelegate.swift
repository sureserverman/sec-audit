// Intentionally-vulnerable macOS AppKit source for fixture purposes.

import Cocoa
import AVFoundation

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationDidFinishLaunching(_ notification: Notification) {
        // CWE-312: credential stored in UserDefaults (unencrypted plist on disk).
        UserDefaults.standard.set("sk_live_MACOSDEADBEEFCAFEBABE1234567890",
                                  forKey: "api_key")

        // Paired with missing NSCameraUsageDescription — runtime crash risk.
        _ = AVCaptureDevice.default(for: .video)
    }
}
