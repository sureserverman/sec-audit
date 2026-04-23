# Android / AndroidManifest.xml

## Source

- https://developer.android.com/guide/topics/manifest/manifest-intro — AndroidManifest.xml overview: structure, element reference, and attribute semantics
- https://developer.android.com/guide/topics/manifest/application-element — `<application>` element: debuggable, allowBackup, networkSecurityConfig, and related attributes
- https://developer.android.com/guide/topics/manifest/activity-element — `<activity>` element: exported, permission, and intent-filter attributes
- https://developer.android.com/guide/topics/manifest/service-element — `<service>` element: exported and permission attributes
- https://developer.android.com/guide/topics/manifest/receiver-element — `<receiver>` element: exported and permission attributes
- https://developer.android.com/guide/topics/manifest/provider-element — `<provider>` element: exported, permission, readPermission, writePermission, and grantUriPermissions attributes
- https://developer.android.com/privacy-and-security/security-tips — Android security best practices: component visibility, permissions, and network policy
- https://developer.android.com/privacy-and-security/security-config — Network Security Configuration: cleartext, certificate pinning, and trust anchors
- https://developer.android.com/training/app-links — Android App Links: deep-link validation, intent-filter host/path requirements, and Digital Asset Links
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet

## Scope

In-scope: the `AndroidManifest.xml` surface for Android applications — component export visibility (`<activity>`, `<service>`, `<receiver>`, `<provider>`), debuggability, backup policy, deep-link intent-filter host/path validation, network security configuration, and the cross-reference to `FLAG_SECURE` as a manifest-paired hardening control. Out of scope: runtime component behaviour such as Intent handling, WebView configuration, and ContentProvider query logic (covered by `android-runtime.md`); on-device data storage and encryption (covered by `android-data.md`); tool invocations such as `apktool`, `apkanalyzer`, and MobSF (covered by `mobile-tools.md`).

## Dangerous patterns (regex/AST hints)

### Exported component without a protecting permission — CWE-926

- Why: A component with `android:exported="true"` and no `android:permission` attribute can be started, bound, or triggered by any installed app on the device, allowing privilege escalation, data exfiltration, or denial of service without any capability check.
- Grep: `android:exported="true"`
- File globs: `**/AndroidManifest.xml`
- Source: https://developer.android.com/privacy-and-security/security-tips

### `android:debuggable="true"` in a release build — CWE-489

- Why: A debuggable APK allows any process with ADB access to attach a JDWP debugger, read heap memory, and invoke arbitrary methods via `am` commands; this flag must be absent or explicitly `false` in release builds; the Android build system sets it automatically in debug variants but does not strip it if it is hardcoded in the manifest.
- Grep: `android:debuggable="true"`
- File globs: `**/AndroidManifest.xml`
- Source: https://developer.android.com/guide/topics/manifest/application-element

### `android:allowBackup="true"` enabling ADB data extraction — CWE-200 / CWE-312

- Why: When `android:allowBackup` is `true` (which is the default for API level 30 and below if the attribute is omitted), any user with physical access and ADB enabled can extract the application's full data directory, including databases, shared preferences, and tokens, without root access.
- Grep: `android:allowBackup="true"`
- File globs: `**/AndroidManifest.xml`
- Source: https://developer.android.com/guide/topics/manifest/application-element

### Deep-link intent-filter missing `android:host` — CWE-939

- Why: An intent-filter `<data>` element that declares a custom `android:scheme` but omits `android:host` matches any host under that scheme; any other app can craft an intent or deep-link URI targeting the activity and supply malicious path or query parameters, enabling link hijacking, open redirects, or unvalidated data ingestion.
- Grep: `<data\s+android:scheme=`
- File globs: `**/AndroidManifest.xml`
- Source: https://developer.android.com/training/app-links

### Missing `android:networkSecurityConfig` or explicit cleartext allowed — CWE-319

- Why: Without a Network Security Configuration file, applications targeting API level 27 and below trust user-installed CA certificates and permit cleartext HTTP to all domains; omitting `android:networkSecurityConfig` on those targets, or setting `android:usesCleartextTraffic="true"`, allows MitM interception of all non-TLS traffic and trust of attacker-installed certificates.
- Grep: `android:usesCleartextTraffic="true"`
- File globs: `**/AndroidManifest.xml`
- Source: https://developer.android.com/privacy-and-security/security-config

### `FLAG_SECURE` omitted on sensitive activities (manifest cross-reference)

- Why: Activities handling authentication, payment, messaging, or personal data should be paired with `window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)` in code to prevent screenshots and screen-share capture; the manifest alone cannot enforce this, but auditors should verify that activities bearing sensitive labels (login, payment, wallet, compose) have a corresponding `FLAG_SECURE` call in the associated `Activity` class. This is a code-level control — see `android-runtime.md` for the runtime pattern; it is listed here so the manifest audit does not miss the paired requirement.
- Grep: `android:name=".*[Ll]ogin.*[Aa]ctivity\|android:name=".*[Pp]ayment.*[Aa]ctivity\|android:name=".*[Ww]allet.*[Aa]ctivity\|android:name=".*[Cc]ompose.*[Aa]ctivity"`
- File globs: `**/AndroidManifest.xml`
- Source: https://developer.android.com/guide/topics/manifest/activity-element

### Exported `<provider>` without a permission or with `grantUriPermissions` open — CWE-927

- Why: A ContentProvider exported without `android:permission`, `android:readPermission`, and `android:writePermission` is readable and writable by any app; additionally, `android:grantUriPermissions="true"` without a tight `<grant-uri-permission>` path constraint allows any component to be granted access to any URI the provider serves, bypassing the permission model entirely.
- Grep: `android:exported="true"`
- File globs: `**/AndroidManifest.xml`
- Source: https://developer.android.com/guide/topics/manifest/provider-element

## Secure patterns

Minimal safe `AndroidManifest.xml` with explicit component visibility, no debuggability, backup disabled, and a network security config reference:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.myapp">

    <application
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        android:allowBackup="false"
        android:fullBackupOnly="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:debuggable="false">

        <!-- Public-facing entry point: exported, but callers must hold a
             signature-level permission defined by this package. -->
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:permission="com.example.myapp.permission.LAUNCH">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Internal activity: not exported; unreachable from outside the app. -->
        <activity
            android:name=".PaymentActivity"
            android:exported="false" />

        <!-- Background service: not exported; only reachable via explicit Intent. -->
        <service
            android:name=".SyncService"
            android:exported="false" />

        <!-- Broadcast receiver for a system broadcast: exported with a
             restricting permission so only the system can deliver it. -->
        <receiver
            android:name=".BootReceiver"
            android:exported="true"
            android:permission="android.permission.RECEIVE_BOOT_COMPLETED">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <!-- ContentProvider: not exported; accessed only within this app's
             process or via documented, permission-gated URI grants. -->
        <provider
            android:name=".AppDataProvider"
            android:authorities="com.example.myapp.provider"
            android:exported="false"
            android:grantUriPermissions="false" />

    </application>
</manifest>
```

Source: https://developer.android.com/privacy-and-security/security-tips

Host-validated App Links intent-filter and the matching `network_security_config.xml` that disables cleartext:

```xml
<!-- AndroidManifest.xml: App Links intent-filter with explicit scheme, host, and path prefix.
     Validates incoming deep-link URIs against a single owned domain only. -->
<activity
    android:name=".DeepLinkActivity"
    android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <!-- Both scheme AND host are required; path prefix scopes the filter further. -->
        <data
            android:scheme="https"
            android:host="www.example.com"
            android:pathPrefix="/app/" />
    </intent-filter>
</activity>
```

```xml
<!-- res/xml/network_security_config.xml: no cleartext, no user-CA trust in release. -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <!-- Trust only the system CA store; user-installed CAs are excluded. -->
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

The `android:autoVerify="true"` attribute triggers Digital Asset Links verification against `https://www.example.com/.well-known/assetlinks.json`; only verified links are routed to this activity, preventing other apps from intercepting them.

Source: https://developer.android.com/training/app-links

## Fix recipes

### Recipe: Add `android:permission` to an exported broadcast receiver — addresses CWE-926

**Before (dangerous):**

```xml
<!-- Any app can send this broadcast and trigger the receiver. -->
<receiver
    android:name=".UpdateReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.example.myapp.ACTION_UPDATE" />
    </intent-filter>
</receiver>
```

**After (safe):**

```xml
<!-- Declare a signature-level permission that only apps signed with the same
     key (i.e. first-party apps) can hold and therefore send this broadcast. -->
<permission
    android:name="com.example.myapp.permission.SEND_UPDATE"
    android:protectionLevel="signature" />

<receiver
    android:name=".UpdateReceiver"
    android:exported="true"
    android:permission="com.example.myapp.permission.SEND_UPDATE">
    <intent-filter>
        <action android:name="com.example.myapp.ACTION_UPDATE" />
    </intent-filter>
</receiver>
```

Use `protectionLevel="signature"` when only first-party callers are legitimate; use `protectionLevel="signatureOrSystem"` only if system-level callers must also be permitted. For completely internal broadcasts that never need to cross a package boundary, prefer `android:exported="false"` and remove the intent-filter instead.

Source: https://developer.android.com/guide/topics/manifest/receiver-element

### Recipe: Disable debuggability and disable unrestricted backup — addresses CWE-489 / CWE-200 / CWE-312

**Before (dangerous):**

```xml
<application
    android:label="@string/app_name"
    android:debuggable="true"
    android:allowBackup="true">
    ...
</application>
```

**After (safe):**

```xml
<application
    android:label="@string/app_name"
    android:debuggable="false"
    android:allowBackup="false">
    ...
</application>
```

Do not hardcode `android:debuggable` in the manifest at all if the Gradle build system controls it — `applicationVariants` in debug builds set it automatically and release builds clear it, preventing an accidental release with the flag set. If selective backup of non-sensitive data (e.g. user preferences, non-credential settings) is genuinely required, set `android:allowBackup="true"` and provide a `android:fullBackupContent` or `android:dataExtractionRules` XML file that explicitly excludes credential stores, authentication tokens, database files, and private keys.

Source: https://developer.android.com/guide/topics/manifest/application-element

### Recipe: Add host validation to a deep-link intent-filter — addresses CWE-939

**Before (dangerous):**

```xml
<!-- Accepts any host under the custom scheme; vulnerable to link hijacking
     from any app that fires an intent with this scheme and a malicious host. -->
<activity
    android:name=".DeepLinkActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="myapp" />
    </intent-filter>
</activity>
```

**After (safe):**

```xml
<!-- Restricts acceptance to a single owned host and a specific path prefix.
     android:autoVerify triggers App Links verification via assetlinks.json,
     routing verified links exclusively to this activity. -->
<activity
    android:name=".DeepLinkActivity"
    android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:scheme="https"
            android:host="www.example.com"
            android:pathPrefix="/app/" />
    </intent-filter>
</activity>
```

Migrate custom URI schemes (`myapp://`) to HTTPS App Links wherever possible — custom schemes cannot be verified via Digital Asset Links and remain susceptible to interception by any app declaring the same scheme. If a custom scheme is unavoidable (e.g. for OAuth redirect URIs targeting a specific app), validate every incoming URI's host, path, and query parameters explicitly in `onNewIntent()` before acting on them.

Source: https://developer.android.com/training/app-links

## Version notes

- `android:exported` was required (rather than defaulting to `false`) starting with API level 31 (Android 12). Apps targeting API 31+ that declare an `<intent-filter>` without an explicit `android:exported` value will fail to install. Build systems should enforce this with `targetSdkVersion 31` or higher.
- `android:allowBackup` defaults to `true` for apps targeting API level 30 and below. Apps targeting API 31+ can use `android:dataExtractionRules` (pointing to a `res/xml/data_extraction_rules.xml` file) to granularly control cloud and device-to-device backup rules; the older `android:fullBackupContent` attribute remains honoured but is superseded.
- `android:networkSecurityConfig` was introduced in API level 24 (Android 7.0). Apps targeting API 23 and below cannot use it and must rely on OkHttp- or HttpURLConnection-level cleartext controls; flag any `minSdkVersion < 24` manifest accordingly and verify library-level TLS enforcement.
- The `android:autoVerify="true"` App Links verification mechanism requires that the hosted `assetlinks.json` file be served over HTTPS with `Content-Type: application/json` and be reachable without redirects from the declared `android:host`. Verification failures cause the OS to fall back to a disambiguation dialog, negating the security benefit.

## Common false positives

- `android:exported="true"` on a `<activity>` that is the application's sole launcher entry point — every app must export its MAIN/LAUNCHER activity; flag only if it lacks a protecting permission and handles data beyond a generic launch intent.
- `android:exported="true"` on a `<receiver>` for `android.intent.action.BOOT_COMPLETED`, `android.intent.action.PACKAGE_REPLACED`, and similar system-delivered broadcasts — these must be exported so the OS can deliver them; verify instead that a protecting `android:permission` restricts delivery to the system or first-party callers.
- `android:allowBackup="true"` when accompanied by a properly scoped `android:fullBackupContent` or `android:dataExtractionRules` file that excludes sensitive data — confirm the exclusion rules cover databases, shared preferences containing tokens, and private files before downgrading severity.
- `<data android:scheme=` without `android:host` inside an intent-filter that also contains `android:mimeType` and no `android:scheme` pointing to a network resource (e.g. `content://` or `file://` MIME-type handlers) — these are local data-scheme filters and do not expose network-level link hijacking; triage by checking whether the scheme is `http`/`https` or a custom vanity scheme.
- `android:debuggable="false"` absent from the manifest but the build is managed by Gradle — Android Gradle Plugin automatically injects `android:debuggable="true"` only in debug build variants and strips it in release; absence of the attribute in the source manifest is safe when the build pipeline is verified; flag only when the attribute is hardcoded as `true`.
