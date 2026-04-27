# Android App Data Storage

## Source

- https://developer.android.com/training/data-storage — App storage overview
- https://developer.android.com/training/data-storage/app-specific — App-specific storage
- https://developer.android.com/topic/security/data — Security best practices for data
- https://developer.android.com/privacy-and-security/keystore — Android Keystore system
- https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences — EncryptedSharedPreferences API reference
- https://developer.android.com/reference/androidx/security/crypto/MasterKey — MasterKey API reference
- https://developer.android.com/training/data-storage/shared — Scoped Storage
- https://developer.android.com/reference/android/content/Context#MODE_PRIVATE — File mode constants
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet

## Scope

In scope: Android app data storage — SharedPreferences (plain and encrypted), SQLite databases, the Android Keystore system, external storage access patterns, hardcoded credentials in source and resource files, and screenshot or recents-screen exposure of sensitive data via missing FLAG_SECURE. Out of scope: manifest permission flags and component declarations (`android-manifest.md`); runtime component hijacking, intent interception, and exported component abuse (`android-runtime.md`); TLS configuration and certificate pinning, which are covered by the existing `references/tls/` pack and the network security config discussion in the runtime pack.

## Dangerous patterns (regex/AST hints)

### Secrets in plain SharedPreferences — CWE-312

- Why: Storing API keys, OAuth tokens, passwords, JWTs, or PII with the default `SharedPreferences` API writes plaintext XML to the app's private data directory; on rooted devices or via ADB backups that data is trivially readable.
- Grep: `getSharedPreferences\s*\(|getDefaultSharedPreferences\s*\(` paired within the same file with `\.putString\s*\(\s*"(api[_-]?key|token|secret|password|jwt|bearer|auth)"`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/topic/security/data

### MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE on files or SharedPreferences — CWE-732

- Why: These modes make internal files readable or writable by every process on the device; they have been deprecated since API 17 and are blocked by `StrictMode` on API 24+, but legacy code that still compiles with them silently exposes data on older OS versions or in custom ROMs that do not enforce the block.
- Grep: `MODE_WORLD_(READ|WRITE)(ABLE)?`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/reference/android/content/Context#MODE_PRIVATE

### SQLite database storing sensitive data without encryption — CWE-312

- Why: `SQLiteOpenHelper` and `openOrCreateDatabase` produce an unencrypted `.db` file under the app's private data directory; on rooted devices, via ADB backup, or after physical extraction the full database is readable in plaintext. Tables holding PII, credentials, health data, or financial records require SQLCipher or equivalent at-rest encryption.
- Grep: `SQLiteOpenHelper|openOrCreateDatabase`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/topic/security/data

### Keystore key generation without user-authentication binding — CWE-522

- Why: A `KeyGenParameterSpec` built without `setUserAuthenticationRequired(true)` allows any process that can reach the key alias — including malware with the same user ID after a sandboxing failure — to perform cryptographic operations with keys intended to gate payment, biometric, or identity-confirmation flows.
- Grep: `KeyGenParameterSpec\.Builder`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/privacy-and-security/keystore

### External storage writes bypassing Scoped Storage (API 29+) — CWE-276 / CWE-200

- Why: `Environment.getExternalStorageDirectory()` and `Environment.getExternalStoragePublicDirectory()` return paths that are world-readable by any app holding `READ_EXTERNAL_STORAGE` (or unconditionally pre-API 19); on API 29+ these calls also trigger a `SecurityException` without the legacy opt-in, so their presence indicates either a crash risk on modern OS or intentional legacy-mode use that should be replaced with MediaStore or app-specific external storage APIs.
- Grep: `Environment\.getExternalStorage(Public)?Directory`
- File globs: `**/*.java`, `**/*.kt`
- Source: https://developer.android.com/training/data-storage/shared

### Hardcoded credentials in source — CWE-798

- Why: Bearer tokens, AWS access key IDs, GitHub personal-access tokens, and PEM private keys committed in source are captured by every developer machine clone, every CI log, and every decompiled APK; rotation is the only remediation once the key escapes.
- Grep: `AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|-----BEGIN\s+(RSA|EC|OPENSSH|PRIVATE)\s+KEY-----|Bearer\s+[A-Za-z0-9\-._~+/]{20,}`
- File globs: `**/*.java`, `**/*.kt`, `**/*.xml`, `**/*.properties`, `**/*.gradle`, `**/*.kts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

### Sensitive Activity without FLAG_SECURE (screenshot and recents exposure) — CWE-200

- Why: Any Activity that displays passwords, payment card numbers, authentication tokens, or health data without `WindowManager.LayoutParams.FLAG_SECURE` can be captured by the Android screenshot API, third-party screen-recording apps, and is always visible in the recents (task-switcher) thumbnail; this is both a direct data-exposure vector and an OWASP MASVS-STORAGE requirement.
- Grep: `getWindow\(\)\.setFlags|addFlags` — review callers that do NOT set `FLAG_SECURE` in Activities whose layout inflates fields such as `passwordInputLayout`, `cardNumber`, or similar sensitive views
- File globs: `**/*.java`, `**/*.kt`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

## Secure patterns

`EncryptedSharedPreferences` backed by an AES256-GCM `MasterKey` — keys and values are authenticated-encrypted before being written to the XML preference file:

```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

// Build a MasterKey backed by the Android Keystore using AES256-GCM.
// The key is created on first call and reused on subsequent calls.
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

// Open (or create) an encrypted SharedPreferences file.
val securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",                                  // file name
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// Usage is identical to plain SharedPreferences.
securePrefs.edit().putString("api_token", token).apply()
```

Source: https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences

`KeyGenParameterSpec` with mandatory strong-biometric authentication, zero-second timeout, and invalidation on new enrollment — ensures the key cannot be used without a fresh biometric challenge:

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

val keyGenSpec = KeyGenParameterSpec.Builder(
    "payment_signing_key",
    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setUserAuthenticationRequired(true)
    // timeout=0 requires authentication for every single key use
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    // invalidate key if the user adds a new biometric enrollment
    .setInvalidatedByBiometricEnrollment(true)
    .build()

val keyPairGenerator = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC,
    "AndroidKeyStore"
)
keyPairGenerator.initialize(keyGenSpec)
keyPairGenerator.generateKeyPair()
```

Source: https://developer.android.com/privacy-and-security/keystore

## Fix recipes

### Recipe: Migrate SharedPreferences to EncryptedSharedPreferences — addresses CWE-312

**Before (dangerous):**

```kotlin
// Stores OAuth token as plaintext XML on disk
val prefs = context.getSharedPreferences("user_prefs", Context.MODE_PRIVATE)
prefs.edit().putString("oauth_token", token).apply()
```

**After (safe):**

```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val prefs = EncryptedSharedPreferences.create(
    context,
    "user_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
// Token is now AES256-GCM encrypted at rest; the MasterKey lives in
// AndroidKeyStore and never leaves the secure hardware element.
prefs.edit().putString("oauth_token", token).apply()
```

Source: https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences

### Recipe: Remove hardcoded secret — inject at build time or retrieve from Keystore — addresses CWE-798

**Before (dangerous):**

```kotlin
// Secret committed in source — visible in every APK decompile and git clone
private const val API_KEY = "sk-prod-AKIA1234ABCD5678EFGH"

fun callApi() {
    request.addHeader("Authorization", "Bearer $API_KEY")
}
```

**After (safe — build-time injection via BuildConfig):**

```groovy
// build.gradle — value injected from CI secret / local.properties, never committed
android {
    defaultConfig {
        buildConfigField("String", "API_KEY",
            "\"${project.findProperty('API_KEY') ?: ''}\"")
    }
}
```

```kotlin
// Source references BuildConfig; the literal never appears in VCS
fun callApi() {
    request.addHeader("Authorization", "Bearer ${BuildConfig.API_KEY}")
}
// For long-lived secrets: store once in EncryptedSharedPreferences or
// derive from a Keystore-backed key; never place raw secrets in source.
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

### Recipe: Set FLAG_SECURE on sensitive Activities — addresses CWE-200

**Before (dangerous):**

```kotlin
class PaymentActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No FLAG_SECURE — payment screen captured in recents and by screen-record
        setContentView(R.layout.activity_payment)
    }
}
```

**After (safe):**

```kotlin
class PaymentActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Prevent screenshots, screen recordings, and recents thumbnails from
        // capturing sensitive payment data. Must be set BEFORE setContentView.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContentView(R.layout.activity_payment)
    }
}
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

## Version notes

- `EncryptedSharedPreferences` and `MasterKey` are part of `androidx.security:security-crypto`; minimum supported SDK is API 23. On API 23–27 the MasterKey falls back to a software-backed key if no secure hardware is present — document this in threat-model reviews for apps targeting low-end devices.
- `setUserAuthenticationParameters(timeout, type)` replaces the deprecated `setUserAuthenticationValidityDurationSeconds(int)` and is required for `AUTH_BIOMETRIC_STRONG` semantics; it was introduced in API 30. On API 23–29, use the deprecated `setUserAuthenticationValidityDurationSeconds(-1)` with `setUserAuthenticationRequired(true)` to require authentication on every use.
- `Environment.getExternalStorageDirectory()` was deprecated in API 29 and returns scoped storage roots from API 30 onwards. Legacy opt-in via `android:requestLegacyExternalStorage="true"` in the manifest is silently ignored from API 30 on devices that ship with API 30+.
- `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` throw `SecurityException` at runtime from API 24 onward; their presence in code is therefore both a security and a correctness issue on modern OS versions.

## Common false positives

- `getSharedPreferences` without a sensitive `putString` key name — low confidence; flag only when the key name or adjacent code context suggests credentials or PII storage.
- `SQLiteOpenHelper` subclasses whose `onCreate` creates only non-sensitive tables (e.g. UI state, cached public content, analytics counters) — the grep is a hint; the reviewer must read which columns are populated.
- `KeyGenParameterSpec.Builder` without `setUserAuthenticationRequired` — acceptable when the key guards non-sensitive operations such as local cache integrity verification or non-PII HMAC; flag only when the surrounding code description references payment, identity, or biometric confirmation.
- `Environment.getExternalStorageDirectory()` used only to read (not write) public media with a runtime `READ_MEDIA_*` permission check present — lower severity, but still worth flagging as the scoped-storage API is the correct replacement.
- `FLAG_SECURE` absence in Activities that display only public or non-sensitive content (e.g. a marketing splash screen) — grep matches every Activity; triage by reading the layout or class name for indicators of sensitive data display.
