# Android Runtime Security (WebView, Intents, ContentProviders, PendingIntents, BroadcastReceivers)

## Source

- https://developer.android.com/privacy-and-security/security-tips — Android Security Tips
- https://developer.android.com/develop/ui/views/layout/webapps/webview — WebView developer guide
- https://developer.android.com/reference/android/webkit/WebSettings — WebSettings API reference
- https://developer.android.com/reference/android/webkit/JavascriptInterface — addJavascriptInterface / @JavascriptInterface API reference
- https://developer.android.com/reference/android/content/Intent — Intent API reference
- https://developer.android.com/reference/android/app/PendingIntent — PendingIntent API reference (FLAG_MUTABLE / FLAG_IMMUTABLE)
- https://developer.android.com/reference/android/content/ContentProvider — ContentProvider API reference
- https://developer.android.com/reference/android/content/BroadcastReceiver — BroadcastReceiver API reference
- https://developer.android.com/about/versions/14/behavior-changes-14#runtime-registered-broadcasts-exported — Android 14 behavior change: runtime-registered broadcasts exported flag
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet

## Scope

In scope: Android runtime component security — WebView hardening (JavaScript bridge exposure, file-access settings, URL loading), Intent handling (implicit vs. explicit, deep-link URI validation), ContentProvider permission gates (`android:permission` declarations and `checkCallingPermission` guards), PendingIntent mutability (`FLAG_MUTABLE` vs. `FLAG_IMMUTABLE`), and BroadcastReceiver exported-flag hygiene (`RECEIVER_NOT_EXPORTED` / `RECEIVER_EXPORTED` on API 34+). Out of scope: manifest export flags such as `android:exported` on Activity/Service/Provider/Receiver declarations (covered by `android-manifest.md`); data-at-rest storage — SharedPreferences, SQLite, file system (`android-data.md`); tool invocations for mobile SAST/DAST scanning (`mobile-tools.md`).

## Dangerous patterns (regex/AST hints)

### WebView JS bridge via addJavascriptInterface with JavaScript enabled — CWE-79 / CWE-749

- Why: Calling `addJavascriptInterface` on a WebView that has `setJavaScriptEnabled(true)` exposes a named Java object to all JavaScript running in the loaded page; on API < 17 any JS can invoke `getClass().forName("java.lang.Runtime").getMethod("exec",…)` for RCE, and on API ≥ 17 all public methods still form an attack surface accessible to untrusted web content.
- Grep: `addJavascriptInterface\s*\(`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/reference/android/webkit/JavascriptInterface

### WebView file-access settings enabled — CWE-200 / CWE-552

- Why: Enabling `setAllowFileAccess(true)`, `setAllowFileAccessFromFileURLs(true)`, or `setAllowUniversalAccessFromFileURLs(true)` allows JavaScript loaded from a `file://` URL to read arbitrary files on the device that are accessible to the app's process, leaking private app data or external storage.
- Grep: `setAllow(?:File|Universal)Access\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/reference/android/webkit/WebSettings

### WebView loadUrl without URL allowlist — CWE-601

- Why: Passing a user-supplied or externally-sourced URL directly to `webView.loadUrl(...)` without validating the scheme and host allows open redirects to attacker-controlled pages, which can then exploit any enabled WebView capabilities (JS bridge, file access) or phish users within the trusted app chrome.
- Grep: `webView\.loadUrl\s*\(`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/develop/ui/views/layout/webapps/webview

### Implicit Intent for sensitive actions — CWE-927

- Why: An `Intent` constructed with only an action string (e.g. `new Intent(Intent.ACTION_SEND)`) and dispatched via `startActivity`, `startService`, or `sendBroadcast` without `setPackage(...)` or an explicit component can be intercepted by any installed app that declares a matching intent filter, enabling data exfiltration or spoofed responses.
- Grep: `new\s+Intent\s*\(\s*[A-Za-z_]+\.[A-Z_]+\s*\)`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/reference/android/content/Intent

### ContentProvider without permission enforcement — CWE-927 / CWE-732

- Why: A `ContentProvider` that lacks both a `android:permission` attribute in the manifest and runtime `checkCallingPermission` / `enforceCallingPermission` calls in its `query`, `insert`, `update`, and `delete` methods allows any app on the device to read or modify the provider's data without holding a declared permission.
- Grep: `extends\s+ContentProvider`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/reference/android/content/ContentProvider

### PendingIntent with FLAG_MUTABLE — CWE-926

- Why: A `PendingIntent` created with `FLAG_MUTABLE` allows the receiving component to fill in unset Intent fields before the pending intent fires; an attacker who intercepts or receives the `PendingIntent` can rewrite its action, component, extras, or data URI and redirect the privileged operation to an arbitrary target.
- Grep: `PendingIntent\.FLAG_MUTABLE\b|FLAG_MUTABLE\b`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/reference/android/app/PendingIntent

### BroadcastReceiver registered without RECEIVER_NOT_EXPORTED on SDK 34+ — CWE-926 / CWE-927

- Why: On Android 14 (API 34+), `Context.registerReceiver` requires an explicit exported flag; registering without `RECEIVER_NOT_EXPORTED` defaults to exported, meaning any app on the device can send matching broadcasts to the receiver and trigger its `onReceive` handler, bypassing any implicit assumption of a private receiver.
- Grep: `registerReceiver\s*\(`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/about/versions/14/behavior-changes-14#runtime-registered-broadcasts-exported

### Deep-link Activity without URI host/scheme validation — CWE-939

- Why: An `Activity` declared with `<data android:scheme="...">` in the manifest that does not verify `getIntent().getAction()` equals `Intent.ACTION_VIEW` and does not validate `getData().getHost()` (and path) against an allowlist will process deep links from any origin, enabling malicious apps or crafted links to pass arbitrary parameters to the activity's handling logic.
- Grep: `getIntent\(\)\.getData\(\)|Uri\.parse\s*\(`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/reference/android/content/Intent

## Secure patterns

WebView configured with JavaScript disabled, file access disabled, and a strict `WebViewClient` allowlist:

```java
WebView webView = findViewById(R.id.webview);
WebSettings settings = webView.getSettings();

// Disable JavaScript entirely unless the app's threat model explicitly requires it
settings.setJavaScriptEnabled(false);

// Disable all file-origin access (defaults changed across API levels — set explicitly)
settings.setAllowFileAccess(false);
settings.setAllowFileAccessFromFileURLs(false);
settings.setAllowUniversalAccessFromFileURLs(false);

// Restrict navigation to a known-good allowlist
webView.setWebViewClient(new WebViewClient() {
    private static final Set<String> ALLOWED_HOSTS = Set.of("example.com", "www.example.com");

    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        Uri uri = request.getUrl();
        if ("https".equals(uri.getScheme()) && ALLOWED_HOSTS.contains(uri.getHost())) {
            return false; // allow WebView to load it
        }
        // Block everything else — optionally open in external browser
        return true;
    }
});

webView.loadUrl("https://example.com/start");
```

Source: https://developer.android.com/develop/ui/views/layout/webapps/webview

Explicit Intent with `setPackage` to prevent interception:

```kotlin
// Target package is known at compile time — use explicit addressing
val intent = Intent(Intent.ACTION_SEND).apply {
    setPackage("com.example.app.target")  // restricts delivery to exactly one app
    putExtra(Intent.EXTRA_TEXT, payload)
    type = "text/plain"
}
startActivity(intent)
```

Source: https://developer.android.com/privacy-and-security/security-tips

`PendingIntent` created with `FLAG_IMMUTABLE` on SDK 23+:

```kotlin
val intent = Intent(context, TargetActivity::class.java)

// FLAG_IMMUTABLE prevents any receiving component from modifying the wrapped Intent.
// Use this for all PendingIntents whose Intent fields are fully specified here.
val pendingIntent = PendingIntent.getActivity(
    context,
    0,
    intent,
    PendingIntent.FLAG_IMMUTABLE  // SDK 23+; combine with FLAG_UPDATE_CURRENT if needed
)
```

Source: https://developer.android.com/reference/android/app/PendingIntent

## Fix recipes

### Recipe: Annotate JS bridge methods with @JavascriptInterface and scope exposure — addresses CWE-79 / CWE-749

**Before (dangerous):**

```java
// Any JS in the page can call ANY public method on AppBridge, including
// getClass().forName(...) chains on API < 17
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new AppBridge(), "Android");

public class AppBridge {
    public String getToken() { return authToken; }
    public void postData(String data) { uploadService.post(data); }
}
```

**After (safe):**

```java
// Restrict JS-callable surface to the minimum required methods only.
// Every method that must be callable from JS is annotated @JavascriptInterface.
// Methods without the annotation are NOT callable from JS on API >= 17.
// Only load content from a trusted origin and validate with shouldOverrideUrlLoading.
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new AppBridge(), "Android");

public class AppBridge {
    // Explicitly exposed — reviewed and intentional
    @JavascriptInterface
    public void postData(String data) {
        // Validate and sanitize `data` before use
        if (isValidPayload(data)) {
            uploadService.post(data);
        }
    }

    // NOT annotated — invisible to JavaScript; only callable from Java/Kotlin
    public String getToken() { return authToken; }
}
```

Source: https://developer.android.com/reference/android/webkit/JavascriptInterface

### Recipe: Convert implicit Intent to explicit — addresses CWE-927

**Before (dangerous):**

```kotlin
// Any installed app matching ACTION_PROCESS_PAYMENT can receive this Intent
val intent = Intent("com.example.ACTION_PROCESS_PAYMENT")
intent.putExtra("amount", amount)
startService(intent)
```

**After (safe):**

```kotlin
// Locked to the exact package — only the specified app receives the Intent
val intent = Intent("com.example.ACTION_PROCESS_PAYMENT").apply {
    setPackage("com.example.paymentapp")  // explicit target package
    putExtra("amount", amount)
}
startService(intent)
```

Source: https://developer.android.com/reference/android/content/Intent

### Recipe: Replace FLAG_MUTABLE with FLAG_IMMUTABLE on PendingIntents — addresses CWE-926

**Before (dangerous):**

```kotlin
// FLAG_MUTABLE allows any component that receives this PendingIntent to rewrite
// the wrapped Intent's action, component, extras, or data URI before it fires.
val pi = PendingIntent.getBroadcast(
    context, 0, Intent(ACTION_ALARM), PendingIntent.FLAG_MUTABLE
)
alarmManager.set(AlarmManager.RTC_WAKEUP, triggerTime, pi)
```

**After (safe):**

```kotlin
// FLAG_IMMUTABLE: all Intent fields are fixed at creation time.
// Use FLAG_IMMUTABLE for every PendingIntent whose wrapped Intent is fully specified.
// Retain FLAG_MUTABLE ONLY when a system API (e.g. AlarmManager.setExactAndAllowWhileIdle
// with a reply PendingIntent that the system fills in) explicitly requires mutability —
// document that requirement inline.
val pi = PendingIntent.getBroadcast(
    context, 0, Intent(ACTION_ALARM), PendingIntent.FLAG_IMMUTABLE
)
alarmManager.set(AlarmManager.RTC_WAKEUP, triggerTime, pi)
```

Source: https://developer.android.com/reference/android/app/PendingIntent

## Version notes

- `FLAG_IMMUTABLE` is available from API 23 (Android 6.0). On API 31+ (Android 12), the system enforces that any app targeting SDK 31 or higher must specify either `FLAG_MUTABLE` or `FLAG_IMMUTABLE` — omitting both raises an `IllegalArgumentException` at runtime.
- `setAllowFileAccess` defaults to `true` before API 30; in API 30+ the default was changed to `false`. Set it explicitly in code to avoid version-dependent behavior.
- `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs` both default to `false` since API 16 but should still be set explicitly, as some vendor forks have altered the defaults.
- On API 34+ (Android 14), `Context.registerReceiver(receiver, filter)` without an exported-flag argument throws an exception when the app targets SDK 34+; reviewers should check `targetSdkVersion` to assess whether the `RECEIVER_NOT_EXPORTED` requirement is enforced or merely advisory.
- `@JavascriptInterface` annotation enforcement (blocking unannotated methods from JS) was introduced in API 17. Apps with `minSdkVersion` < 17 must treat the entire exposed object as callable by JS.
- App Links (verified deep links with Digital Asset Links) provide stronger host validation than bare intent filters; prefer verified App Links over custom URI schemes for sensitive deep-link targets (API 23+).

## Common false positives

- `addJavascriptInterface(...)` — not a finding when the WebView only loads `file:///android_asset/` resources bundled with the app and JavaScript is isolated to that controlled content; verify the URL loaded and the `WebViewClient` override.
- `webView.loadUrl(...)` — not a finding when the URL is a hard-coded string literal (e.g. `webView.loadUrl("https://example.com/")`) rather than a variable derived from user input or an external Intent; check the source of the URL argument.
- `new Intent(ACTION_X)` — implicit-intent pattern matches broad actions such as `ACTION_VIEW` used with `startActivity` for system UI (share sheet, dialler) where any matching app is the intended recipient; flag only when sensitive data is passed as extras or when the action is custom/private.
- `extends ContentProvider` grep — always needs full class-body review; many providers correctly gate access via `android:permission` in the manifest, making in-code `checkCallingPermission` redundant (though still defence-in-depth).
- `registerReceiver(...)` — lower risk when the filter matches only a system-defined protected broadcast (e.g. `Intent.ACTION_BATTERY_CHANGED`) that the OS restricts to itself; check the action string before escalating.
- `FLAG_MUTABLE` — expected and required when the `PendingIntent` is used as a reply target passed to a system API (e.g. `MediaSession`, `BubbleMetadata`, inline-reply `RemoteInput`) that must write extras back; confirm the use-site before flagging.
