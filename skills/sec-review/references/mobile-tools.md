# Mobile Tools

## Source

- https://github.com/MobSF/mobsfscan — mobsfscan source repo (README + `docs/`)
- https://github.com/dwisiswant0/apkleaks — apkleaks source repo (README)
- https://developer.android.com/studio/write/lint — Android Lint official reference
- https://cwe.mitre.org/ — CWE index (for mapping tool rules to CWEs)
- https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html — OWASP Mobile Application Security Cheat Sheet (MASVS-adjacent)

## Scope

This reference pack documents the three Android static-analysis binaries invoked by
the `android-runner` sub-agent (mobsfscan, apkleaks, and android-lint). It specifies
canonical CLI invocations, JSON/XML output schemas, field mappings to sec-review's
finding schema, offline-degrade rules, and the APK-absence clean-skip sub-case unique
to this lane. Out of scope: MobSF server (full web UI), dynamic analysis, iOS tools,
runtime hooking with Frida — all deferred to future versions. This pack documents how
the `android-runner` sub-agent invokes each tool, not anti-patterns in user code.

> **APK-absence sub-case:** apkleaks requires a compiled `.apk` or `.aab` file. When
> no such file exists under the target directory, apkleaks is CLEANLY SKIPPED — this
> is not a tool failure and MUST NOT be recorded in the `"failed"` list. It appears in
> a dedicated `"skipped"` list with reason `"no-apk"`. This distinction is new to the
> Android lane; see the Degrade rules section for the full contract.

## Canonical invocations

### mobsfscan

**Install:** `pip install mobsfscan`

**Run command:**

```bash
mobsfscan --json --output - <path-to-source-tree>
```

Emits a single JSON object to stdout. Exits 0 on success regardless of
whether findings are present. A non-zero exit indicates a tool error (bad
path, missing dependency) — if JSON is still present on stdout, parse it;
otherwise record mobsfscan in the `"failed"` list.

**Expected JSON output shape (0.4.x):**

```json
{
  "results": {
    "android_logging": {
      "metadata": {
        "description": "Log statements used in production code expose sensitive data",
        "severity": "WARNING",
        "cwe": "CWE-312: Cleartext Storage of Sensitive Information",
        "owasp-mobile": "M1: Improper Platform Usage",
        "masvs": "MSTG-STORAGE-3",
        "reference": "https://github.com/MobSF/mobsfscan/blob/main/mobsfscan/rules/android/kotlin/logging.yaml"
      },
      "files": [
        {
          "file_path": "app/src/main/java/com/example/MainActivity.kt",
          "match_lines": [42, 42],
          "match_position": [1, 30],
          "match_string": "Log.d(TAG, userPassword)"
        }
      ]
    }
  },
  "errors": [],
  "total_findings": 1,
  "version": "0.4.0"
}
```

Top-level keys: `results` (dictionary keyed on rule ID), `errors[]`,
`total_findings`, and `version`. Each entry in `results` contains a
`metadata` sub-object and a `files[]` array. One finding is emitted per
file match (not per rule), so a rule that matches in three files produces
three sec-review findings.

**Worked example:**

```bash
# Scan a source tree; JSON to stdout
mobsfscan --json --output - ./app/src/

# Write JSON to a file instead (useful in CI)
mobsfscan --json --output /tmp/mobsfscan-out.json ./app/src/
```

Source: https://github.com/MobSF/mobsfscan

### apkleaks

**Install:** `pip install apkleaks`

**Run command:**

```bash
apkleaks -f <path-to-apk> --json --output <tmpfile>
```

Writes JSON to a file path specified by `--output` — apkleaks does NOT
write findings to stdout by default; the output flag is mandatory. Exits 0
on success. A non-zero exit indicates a tool error; if the output file was
created and contains valid JSON, parse it; otherwise record apkleaks in the
`"failed"` list.

> **IMPORTANT — Clean skip when no APK is present:** When no `*.apk` or
> `*.aab` file exists under the target directory, do NOT attempt to invoke
> apkleaks. Instead, record it in the status line's `"skipped"` list with
> `{"tool": "apkleaks", "reason": "no-apk"}`. This is DISTINCT from the
> `"failed"` list (which captures tools on PATH that crashed at runtime).
> Clean skip is not failure. See the Degrade rules section for the full
> sentinel contract.

**Expected JSON output shape:**

```json
{
  "package": "com.example.myapp",
  "results": [
    {
      "name": "LinkFinder",
      "matches": [
        "https://api.example.com/v1/internal/user",
        "https://cdn.example.com/assets/"
      ]
    },
    {
      "name": "AWS_SECRET_KEY",
      "matches": [
        "AKIAIOSFODNN7EXAMPLE"
      ]
    }
  ]
}
```

Top-level keys: `package` (APK package name) and `results[]`. Each entry
in `results` carries a `name` (rule name) and `matches[]` (the string
values matched). One sec-review finding is emitted per match string.

**Worked example:**

```bash
# Scan a compiled APK; write findings JSON to a temp file
apkleaks -f ./app/build/outputs/apk/debug/app-debug.apk \
         --json \
         --output /tmp/apkleaks-out.json

# Read the output file after the tool exits
cat /tmp/apkleaks-out.json
```

Source: https://github.com/dwisiswant0/apkleaks

### android-lint

**Install:** Ships with Android Studio and the Android SDK `cmdline-tools`
package. Not pip-installable. Two invocation modes:

1. **Gradle (preferred):** `./gradlew :app:lintDebug` — produces
   `app/build/reports/lint-results-debug.xml`.
2. **Standalone fallback:** `lint --xml - <module-dir>` — prints XML to
   stdout.

The runner MUST prefer the Gradle invocation when a `gradlew` wrapper is
present at the project root. Fall back to the standalone `lint` binary only
when no `gradlew` is found.

**Preferred run command (Gradle):**

```bash
./gradlew :app:lintDebug
# XML report written to: app/build/reports/lint-results-debug.xml
```

**Fallback run command (standalone):**

```bash
lint --xml - <module-dir>
# XML written to stdout
```

Gradle exits non-zero when lint errors are present (configurable via
`lintOptions.abortOnError`). The standalone `lint` binary exits 0 on
success. A non-zero Gradle exit due to lint findings is NOT a crash — parse
the XML report and emit findings.

**Expected XML output shape:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<issues format="6" by="lint 8.0.0">
  <issue
      id="AllowBackup"
      severity="Warning"
      message="On SDK version 23 and up, your app data will be automatically backed up..."
      category="Security"
      priority="3"
      summary="AllowBackup/FullBackupContent Problems"
      explanation="The attribute android:allowBackup=&quot;true&quot; is the default..."
      errorLine1="    &lt;application">
    <location
        file="app/src/main/AndroidManifest.xml"
        line="10"
        column="5"/>
  </issue>
  <issue
      id="HardcodedDebugMode"
      severity="Error"
      message="Avoid hardcoding the debug mode..."
      category="Security"
      priority="5"
      summary="Hardcoded value of android:debuggable in the Manifest"
      explanation="Hardcoding android:debuggable=&quot;true&quot; in the manifest...">
    <location
        file="app/src/main/AndroidManifest.xml"
        line="22"
        column="9"/>
  </issue>
</issues>
```

The root element is `<issues>`. Each `<issue>` carries the attributes `id`,
`severity`, `message`, `category`, `priority`, `summary`, and `explanation`.
Each `<issue>` has one or more `<location>` child elements with `file`,
`line`, and `column`. Parse with `xml.etree.ElementTree` or equivalent.

**XPath for Python parsing:**

```python
import xml.etree.ElementTree as ET

tree = ET.parse("app/build/reports/lint-results-debug.xml")
root = tree.getroot()
for issue in root.findall(".//issue"):
    for loc in issue.findall("location"):
        # issue.attrib["id"], issue.attrib["severity"], loc.attrib["file"] ...
        pass
```

**Worked example:**

```bash
# Preferred: run via Gradle wrapper, then parse the XML report
./gradlew :app:lintDebug || true
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('app/build/reports/lint-results-debug.xml')
for issue in tree.getroot().findall('.//issue'):
    print(issue.attrib.get('id'), issue.attrib.get('severity'))
"

# Fallback: standalone lint binary, XML to stdout
lint --xml - ./app/ | python3 -c "
import sys, xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
for issue in root.findall('.//issue'):
    print(issue.attrib.get('id'), issue.attrib.get('severity'))
"
```

Source: https://developer.android.com/studio/write/lint

### codesign  — iOS lane (v0.9.0+)

- Install: ships with Xcode / macOS Command Line Tools. macOS-only
  binary; not available on Linux or Windows hosts.
- Invocation (entitlements dump for review):
  ```bash
  codesign -dv --entitlements :- --xml "$path_to_app_or_binary" \
    > "$TMPDIR/ios-runner-codesign-entitlements.xml" \
    2> "$TMPDIR/ios-runner-codesign.stderr"
  ```
  Use `--verbose=4` to also surface `Notarization=accepted` / Team-ID.
- Target: `.app` / `.framework` / `.xcarchive` / binary. When no such
  bundle exists under the caller's `target_path`, the tool is CLEANLY
  SKIPPED with `reason: "no-bundle"` (same skip-category as apkleaks-
  no-apk; see `## Degrade rules`).
- Output: `--entitlements :- --xml` emits an Entitlements plist to
  stdout; `-dv --verbose=4` emits key:value lines to stderr. The
  ios-runner parses the XML plist for entitlement keys and the
  stderr for `Notarization=`, `Authority=`, `TeamIdentifier=`.
- Primary source:
  https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution
  (notarization); `man codesign(1)` as the binary reference.

Source: https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution

### spctl  — iOS lane (v0.9.0+)

- Install: ships with macOS. macOS-only.
- Invocation:
  ```bash
  spctl --assess --verbose=2 "$path_to_app_bundle" \
    2> "$TMPDIR/ios-runner-spctl.stderr"
  rc_sp=$?
  ```
- Target: `.app` bundle; macOS/iOS-simulator artifact. No bundle →
  clean-skip with `reason: "no-bundle"`.
- Output: a short stderr string like `<path>: accepted source=Notarized Developer ID`
  or `<path>: rejected`. Parse as a Pass/Fail signal; emit one finding
  per rejection.
- Primary source: `man spctl(8)` (macOS system manual).

Source: https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution

### pkgutil  — macOS desktop lane (v0.11.0+)

- Install: ships with macOS. macOS-only.
- Invocation (signature check on a `.pkg`):
  ```bash
  pkgutil --check-signature "$path_to_pkg" \
    2> "$TMPDIR/macos-runner-pkgutil-$(basename "$path_to_pkg").stderr"
  rc_pu=$?
  ```
- Target: `.pkg` installer file. When no `.pkg` is present under the
  caller's `target_path`, the tool is CLEANLY SKIPPED with
  `reason: "no-pkg"` (NEW skip reason in v0.11, parallel to iOS
  `no-bundle` and Android `no-apk`).
- Output: stderr text — `Status: signed by a certificate trusted by
  Mac OS X` vs `Status: no signature` vs `Status: signed Apple
  Software`. Parse as pass/fail; failure → HIGH finding with CWE-693.
- Primary source: `man pkgutil(1)` (macOS system manual);
  https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac

Source: https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac

### stapler validate  — macOS desktop lane (v0.11.0+)

- Install: ships with Xcode (`xcrun stapler`). macOS-only.
- Invocation (validate a stapled notarization ticket):
  ```bash
  xcrun stapler validate "$path_to_app_or_pkg_or_dmg" \
    2> "$TMPDIR/macos-runner-stapler-$(basename "$path_to_artifact").stderr"
  rc_st=$?
  ```
- Target: `.app` / `.pkg` / `.dmg`. When none is present, clean-skip
  with `reason: "no-bundle"` (for `.app`/`.dmg`) or
  `reason: "no-pkg"` (for `.pkg`-only targets). The runner chooses
  the reason matching the target-shape detection.
- Output: stderr text with one of three states —
  `The validate action worked!` (stapled), `Processing: ... does not
  have a ticket stapled to it.` (not stapled — emit finding), or an
  error for invalid tickets. Parse the stderr string for the
  "worked!" substring as pass signal; any other output → MEDIUM
  finding with CWE-693.
- Primary source: `man stapler(1)`;
  https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution

Source: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution

### xcrun notarytool  — iOS lane (v0.9.0+)

- Install: Xcode 13+; requires a valid `AuthKey_<keyId>.p8` or
  app-specific-password. macOS-only.
- Invocation (history / info; never submit from the runner):
  ```bash
  xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" \
    --output-format json > "$TMPDIR/ios-runner-notarytool.json" \
    2> "$TMPDIR/ios-runner-notarytool.stderr"
  rc_nt=$?
  ```
  The runner MUST NOT invoke `notarytool submit` — submitting is a
  developer-side release action, not a review action. When no
  `NOTARY_PROFILE` is configured, the tool is cleanly skipped with
  `reason: "no-notary-profile"`.
- Target: last N notarization submissions for the caller's Apple
  Developer team; use for release-artifact review.
- Output: `--output-format json` produces
  `{"history": [{"id": "...", "createdDate": "...", "status": "Accepted|Invalid|In Progress", "name": "..."}]}`.
- Primary source:
  https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution

Source: https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution

## Output-field mapping

Every finding produced by the `android-runner` sub-agent carries:

- `origin: "android"`
- `tool: "mobsfscan" | "apkleaks" | "android-lint"`
- `reference: "mobile-tools.md"`

### mobsfscan → sec-review finding

One finding is emitted per `files[]` entry within each rule key. A rule
matching three source files produces three sec-review findings.

| mobsfscan JSON field                    | sec-review finding field | Notes                                                                                                                                 |
|-----------------------------------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| rule key (dict key in `results`)        | `id`                     | e.g. `"android_logging"`, `"android_webview_javascript"`                                                                              |
| `metadata.severity` (remapped)          | `severity`               | `"ERROR"` → `HIGH`, `"WARNING"` → `MEDIUM`, `"INFO"` → `LOW`                                                                         |
| `metadata.cwe`                          | `cwe`                    | Input is `"CWE-312: Cleartext Storage..."` — extract `CWE-NNN` with regex `r'CWE-\d+'`; emit `null` when absent or no match          |
| `metadata.description`                  | `title`                  | Short description string, verbatim                                                                                                    |
| `files[i].file_path`                    | `file`                   | Path as reported by mobsfscan; relative to the scan target root when possible                                                         |
| `files[i].match_lines[0]`              | `line`                   | First element of the two-element array; emit `0` when the array is absent or empty                                                   |
| `files[i].match_string`                | `evidence`               | The matched source fragment, verbatim                                                                                                 |
| `metadata.reference`                   | `reference_url`          | URL string when present; `null` otherwise                                                                                             |
| (constant)                              | `fix_recipe`             | `null` — mobsfscan ships rule descriptions, not actionable fixes; the triager's pack lookup supplies the recipe                       |
| (constant)                              | `confidence`             | `"medium"`                                                                                                                            |

Constants on every mobsfscan finding:

- `origin: "android"`
- `tool: "mobsfscan"`
- `reference: "mobile-tools.md"`

**CWE extraction:** The `metadata.cwe` field is a free-text string such as
`"CWE-312: Cleartext Storage of Sensitive Information"`. Extract the
identifier with `re.search(r'CWE-\d+', value)` and emit the matched group
(e.g. `"CWE-312"`). When the field is absent or the regex finds no match,
emit `cwe: null` — do not guess.

Source: https://github.com/MobSF/mobsfscan

### apkleaks → sec-review finding

One finding is emitted per match string within each results entry. A rule
with three matches produces three sec-review findings.

| apkleaks JSON field                                   | sec-review finding field | Notes                                                                                                                                                        |
|-------------------------------------------------------|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `"apkleaks:" + results[i].name + ":" + short-hash`   | `id`                     | Deterministic synthetic ID; short-hash is first 8 chars of `sha256(match_string)`. Not a CVE ID.                                                            |
| (constant)                                            | `severity`               | `"MEDIUM"` uniformly — secret/URI exposure is dangerous but not CRITICAL without evidence of re-use                                                          |
| (per rule type — see table below)                     | `cwe`                    | `"CWE-312"` for secret-pattern rules; `"CWE-200"` for URL/endpoint leaks — see per-rule split below                                                          |
| `"apkleaks detection: " + results[i].name`            | `title`                  | Synthesised title string                                                                                                                                     |
| `<apk-basename>`                                      | `file`                   | Basename of the scanned APK file; apkleaks reports at the APK level, not inner class level                                                                   |
| (constant)                                            | `line`                   | `0` — apkleaks does not report source line numbers                                                                                                           |
| `results[i].matches[j]`                              | `evidence`               | The matched string, verbatim (one finding per match entry)                                                                                                   |
| (constant)                                            | `reference_url`          | `null`                                                                                                                                                       |
| (constant)                                            | `fix_recipe`             | `"Rotate the disclosed credential and store future secrets in EncryptedSharedPreferences or a backend-proxied flow."`                                         |
| (constant)                                            | `confidence`             | `"medium"`                                                                                                                                                   |

Constants on every apkleaks finding:

- `origin: "android"`
- `tool: "apkleaks"`
- `reference: "mobile-tools.md"`

**Per-rule CWE split:** apkleaks ships built-in rules in two broad
categories. Map as follows:

| Rule category                        | Example rule names                                   | CWE        | Rationale                                              |
|--------------------------------------|------------------------------------------------------|------------|--------------------------------------------------------|
| Secret / credential patterns         | `AWS_SECRET_KEY`, `Google_API`, `Generic_Secret`, `RSA_Private_Key`, `Slack_Token` | `CWE-312`  | Cleartext storage of sensitive information (credential exposed in compiled artifact) |
| URL / endpoint patterns              | `LinkFinder`, `IP_Address`, `Email`, `Firebase`      | `CWE-200`  | Exposure of sensitive information to an unauthorised actor (internal endpoint leaked) |

If a rule name does not clearly map to either category, default to
`CWE-200` and note it in the finding's `evidence` or `notes` field.

**ID construction:** Generate the `id` field deterministically:

```python
import hashlib
short_hash = hashlib.sha256(match_string.encode()).hexdigest()[:8]
finding_id = f"apkleaks:{rule_name}:{short_hash}"
# e.g. "apkleaks:AWS_SECRET_KEY:3f7a1c9e"
```

Source: https://github.com/dwisiswant0/apkleaks, https://cwe.mitre.org/

### android-lint → sec-review finding

Parse the XML report using `xml.etree.ElementTree`. One sec-review finding
is emitted per `<issue>` / `<location>` pair. An issue with two location
elements (e.g. in a merged manifest) produces two findings.

| android-lint XML attribute              | sec-review finding field | Notes                                                                                                                                        |
|-----------------------------------------|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `issue[@id]`                            | `id`                     | Lint rule ID string, e.g. `"AllowBackup"`, `"HardcodedDebugMode"`                                                                           |
| `issue[@severity]` (remapped)           | `severity`               | `"Error"` → `HIGH`, `"Warning"` → `MEDIUM`, `"Informational"` → `LOW`                                                                       |
| (lookup table below)                    | `cwe`                    | Mapped per the CWE lookup table; `null` for unmapped IDs — never invent a CWE                                                               |
| `issue[@summary]`                       | `title`                  | Short summary attribute, verbatim                                                                                                            |
| `location[@file]`                       | `file`                   | Path as reported by lint                                                                                                                     |
| `location[@line]`                       | `line`                   | Integer; emit `0` when the attribute is absent                                                                                               |
| `issue[@message]`                       | `evidence`               | Full message attribute, verbatim                                                                                                             |
| `issue[@explanation]`                   | `fix_recipe`             | Explanation attribute when non-empty; `null` otherwise                                                                                       |
| (constant)                              | `reference_url`          | `null` — lint does not embed per-issue advisory URLs in the XML report                                                                       |
| (constant)                              | `confidence`             | `"high"` — lint rules are deterministic AST matches against a compiled or source manifest                                                    |

Constants on every android-lint finding:

- `origin: "android"`
- `tool: "android-lint"`
- `reference: "mobile-tools.md"`

**CWE lookup table** (maintained by the runner; extend as new security rules
are confirmed):

| Lint issue ID(s)                                                     | CWE        | Rationale                                                                      |
|----------------------------------------------------------------------|------------|--------------------------------------------------------------------------------|
| `ExportedReceiver`, `ExportedService`, `ExportedActivity`, `ExportedContentProvider` | `CWE-926`  | Improper export of Android application components                              |
| `HardcodedDebugMode`                                                 | `CWE-489`  | Active debug code (android:debuggable=true in production manifest)             |
| `AllowBackup`                                                        | `CWE-200`  | Exposure of sensitive data via uncontrolled backup channel                     |
| `SetJavaScriptEnabled`                                               | `CWE-749`  | Exposed dangerous method (JavaScript enabled in WebView)                       |
| `JavascriptInterface`                                                | `CWE-749`  | Exposed dangerous method (@JavascriptInterface annotation without restrictions)|
| `UnsafeIntentLaunch`                                                 | `CWE-927`  | Use of implicit intent for sensitive communication                             |
| `TrustAllX509TrustManager`, `BadHostnameVerifier`                    | `CWE-295`  | Improper certificate validation                                                |

**Null fallback:** Any `<issue>` with `category="Security"` whose `id` does
NOT appear in the table above MUST be emitted with `cwe: null`. Do not
guess or extrapolate. The `null` tells the triage step that a human must
assign the CWE — it does not mean the finding is unimportant.

**XPath for filtering security findings only:**

```python
import xml.etree.ElementTree as ET

tree = ET.parse("app/build/reports/lint-results-debug.xml")
root = tree.getroot()
# Emit all issues; filter to category="Security" for security-only mode
security_issues = [i for i in root.findall(".//issue")
                   if i.attrib.get("category") == "Security"]
```

Source: https://developer.android.com/studio/write/lint, https://cwe.mitre.org/

### codesign → sec-review finding (iOS lane)

One finding per entitlement drift / hardened-runtime missing / notarization-
absent signal the tool surfaces for a `.app` / `.framework` / `.xcarchive`.
Parse both the `--entitlements :- --xml` plist (stdout) and `-dv --verbose=4`
stderr. Emit:

| upstream field                          | sec-review field              |
|-----------------------------------------|-------------------------------|
| (synthetic) `"codesign:" + check-name`  | `id`                          |
| rule severity: entitlement-drift HIGH, hardened-runtime missing HIGH, notarization absent HIGH | `severity` |
| per-rule CWE lookup                     | `cwe`                         |
| check description                       | `title`                       |
| bundle basename                         | `file` (e.g. `VulnerableiOS.app`) |
| 0                                       | `line`                        |
| the offending entitlement key / stderr line | `evidence`                |
| `mobile-tools.md`                       | `reference`                   |
| Apple docs URL                          | `reference_url`               |
| synthesised from the corresponding `references/mobile/ios-codesign.md` fix recipe | `fix_recipe` |
| `"high"`                                | `confidence`                  |
| `"ios"` (constant)                      | `origin`                      |
| `"codesign"` (constant)                 | `tool`                        |

### spctl → sec-review finding (iOS lane)

One finding emitted only when the assessment rejects (accepted
assessments produce no finding). Severity HIGH; CWE-693 Protection
Mechanism Failure. `evidence` is the rejection reason string from
spctl's stderr. `tool: "spctl"`.

### xcrun notarytool → sec-review finding (iOS lane)

One finding per release artifact with status `Invalid` or `Rejected`
in the returned history. Severity MEDIUM (legacy releases may be
acceptable to leave unstapled if never distributed); CWE-693.
`evidence` is the verbatim rejection reason. `tool: "notarytool"`.

### pkgutil → sec-review finding (macOS lane, v0.11.0+)

Emit ONE finding per `.pkg` whose `pkgutil --check-signature` result
is not "signed". Severity HIGH; CWE-693. `file` is the pkg basename;
`line` 0. `evidence` is the verbatim stderr line (e.g. `Status: no
signature`). `fix_recipe` = "Sign the .pkg with productsign, then
re-run xcrun notarytool submit + stapler staple." `tool: "pkgutil"`.
`confidence: "high"` (deterministic signature check).

### stapler validate → sec-review finding (macOS lane, v0.11.0+)

Emit ONE finding per artifact that `xcrun stapler validate` reports
as NOT having a stapled notarization ticket. Severity MEDIUM
(historic / internal-only artifacts may be legitimately unstapled;
release artifacts should be). CWE-693. `evidence` is the verbatim
stderr message. `fix_recipe` = "After notarization completes, run
`xcrun stapler staple <artifact>` before distribution." `tool:
"stapler"`. `confidence: "high"`.

## Degrade rules

The `android-runner` agent follows a three-state sentinel contract consistent
with `sast-runner` (`__sast_status__`), `webext-runner` (`__webext_status__`),
`dast-runner` (`__dast_status__`), and `rust-runner` (`__rust_status__`).

The `ios-runner` agent (v0.9.0+) follows an identical three-state
sentinel `__ios_status__` with the same schema. iOS-specific
clean-skip reasons extend the v0.8 skipped-list primitive:

- `{"tool": "<name>", "reason": "requires-macos-host"}` — codesign /
  spctl / notarytool are macOS-only binaries. A Linux or Windows host
  running the runner cannot execute them, even when they would
  conceptually apply. This is a clean skip, NOT a failure.
- `{"tool": "<name>", "reason": "no-bundle"}` — codesign / spctl
  require a `.app` / `.framework` / `.xcarchive` artifact under the
  target. Source-only reviews (the common CI case) lack this
  artifact; tools are cleanly skipped.
- `{"tool": "notarytool", "reason": "no-notary-profile"}` — notarytool
  needs `NOTARY_PROFILE` / `$APPLE_ID` + app-specific password. When
  unconfigured, clean-skip.

Downstream consumers (finding-triager, report-writer) MUST treat
`reason: "requires-macos-host"` entries as informational metadata
rather than as reviewer-fixable gaps. The sec-review report surfaces
them in a separate "Host-OS-unavailable" metadata line so readers
know the review was partial-by-design rather than partial-by-failure.

The `macos-runner` agent (v0.11.0+) follows an identical three-state
sentinel `__macos_status__` with the same schema. macOS-specific
clean-skip reasons extend the vocabulary:

- `{"tool": "<name>", "reason": "requires-macos-host"}` — same as the
  iOS lane; shared across both Apple-ecosystem runners.
- `{"tool": "<name>", "reason": "no-bundle"}` — codesign/spctl/stapler
  require a `.app`/`.framework`/`.dmg` artifact under the target.
- `{"tool": "pkgutil", "reason": "no-pkg"}` — pkgutil requires a
  `.pkg` installer. Source-only reviews lack one. NEW in v0.11.
- `{"tool": "<name>", "reason": "tool-missing"}` — the binary is
  absent when its host+target preconditions held (rare; `.app` on
  macOS without codesign is essentially impossible).

Cross-platform targets (e.g. SwiftPM libraries) may satisfy both iOS
and macOS inventory signals. Both runners dispatch independently,
producing `__ios_status__` and `__macos_status__` status records
that the report-writer renders under separate "iOS findings" and
"macOS findings" subsections. The two lanes do NOT share findings —
origin-tag isolation keeps them distinct.

> **APK-absence sub-case — unique to this lane:** apkleaks requires a
> compiled APK/AAB. When no `*.apk` or `*.aab` file is found under the
> target directory, apkleaks is CLEANLY SKIPPED before invocation. A
> clean skip is recorded in the `"skipped"` list as
> `{"tool": "apkleaks", "reason": "no-apk"}`. It is NOT recorded in the
> `"failed"` list. Clean skip does not change the overall status from `"ok"`
> to `"partial"` — the status reflects tool availability on PATH, not
> whether the target contained an APK. Observability is preserved by
> including the `"skipped"` key even in an `"ok"` status line.

**State 1 — NONE available:**

If none of `mobsfscan`, `apkleaks`, `android-lint`, or `gradle lint` is on
PATH (i.e. no usable Android static-analysis tool is present), emit exactly
one sentinel line and exit 0:

```json
{"__android_status__": "unavailable", "tools": []}
```

No findings are emitted. No fabricated results. The sentinel tells the
downstream aggregator that the Android lane did not run, so its absence of
findings cannot be misread as a clean pass.

**State 2 — SOME available:**

If at least one tool is on PATH but not all, run the available tools, emit
their findings, and then emit a partial-status summary line listing only the
tools that actually ran. Include a `"skipped"` key when apkleaks was cleanly
skipped:

```json
{
  "__android_status__": "partial",
  "tools": ["mobsfscan", "android-lint"],
  "runs": 2,
  "findings": 14,
  "failed": [],
  "skipped": [{"tool": "apkleaks", "reason": "no-apk"}]
}
```

The `"partial"` status tells the downstream aggregator that the Android
lane ran with reduced coverage — findings from the missing tools are simply
absent, not "clean."

**State 3 — ALL available and successful:**

If every available tool ran and each exited with a documented success code,
emit the standard status line. When apkleaks was cleanly skipped (no APK
present) but all PATH-present tools ran successfully, the status is still
`"ok"` with the `"skipped"` key for observability:

```json
{
  "__android_status__": "ok",
  "tools": ["mobsfscan", "apkleaks", "android-lint"],
  "runs": 3,
  "findings": 27
}
```

With APK-absence clean skip:

```json
{
  "__android_status__": "ok",
  "tools": ["mobsfscan", "android-lint"],
  "runs": 2,
  "findings": 27,
  "skipped": [{"tool": "apkleaks", "reason": "no-apk"}]
}
```

**Exit-code semantics per tool:**

| Tool                  | Success / findings-present codes                  | Tool failure (not a findings event)                                    |
|-----------------------|---------------------------------------------------|------------------------------------------------------------------------|
| mobsfscan             | `0`                                               | Any non-zero, or stdout is empty / not valid JSON                      |
| apkleaks              | `0`                                               | Any non-zero, or output file absent / not valid JSON                   |
| android-lint (Gradle) | `0` (no errors), non-zero (lint errors present)   | Exit >= 127, or XML report absent / not parseable                      |
| android-lint (standalone) | `0`                                           | Any non-zero, or stdout is empty / not parseable XML                   |

A tool exiting non-zero because it FOUND findings (Gradle lint with
`abortOnError=true`) is NOT a crash — parse the XML report and emit
findings. Only record a tool in `"failed"` when its output is absent,
unparseable, or when it exits >= 127.

When a tool was on PATH but its run failed, omit it from `"tools"` and do
not emit findings for it. If this exhausts all available tools, emit the
`"unavailable"` sentinel instead of an `"ok"` or `"partial"` line.

Source: https://github.com/MobSF/mobsfscan,
https://github.com/dwisiswant0/apkleaks,
https://developer.android.com/studio/write/lint

## Version pins

Minimum tested versions (pinned 2026-04 against upstream stable releases;
later upgrades should update this line):

| Tool              | Minimum version | Notes                                                                          |
|-------------------|-----------------|--------------------------------------------------------------------------------|
| mobsfscan         | 0.4.0           | JSON output schema (`results` dict keyed on rule ID) stable at this version    |
| apkleaks          | 2.6.0           | `--json` flag and current output schema stable at this version                 |
| android-lint      | AGP 8.0+ (Gradle) / cmdline-tools 11.0+ (standalone) | XML `format="6"` schema stable at these versions |

All Python-based tools install via `pip install <tool>`. android-lint is
distributed with the Android SDK; install `cmdline-tools` via:

```bash
# SDK Manager CLI — downloads cmdline-tools including the standalone lint binary
sdkmanager "cmdline-tools;latest"
```

The `android-runner` agent SHOULD verify each tool's version before use:

```bash
mobsfscan --version 2>/dev/null      # expect 0.4.x or higher
apkleaks --version  2>/dev/null      # expect 2.6.x or higher
lint --version      2>/dev/null      # expect 8.0 or higher (standalone)
./gradlew --version 2>/dev/null      # AGP version visible in output
```

If a tool is present but reports a version below the minimum, the runner
SHOULD log a warning to stderr (e.g. `android-runner: mobsfscan 0.3.1 is
below minimum 0.4.0 — JSON schema may differ`) and proceed rather than
refusing, because older versions may still produce parseable JSON. Refuse
(mark as unavailable) only when the tool exits non-zero on `--version`.

Source: https://github.com/MobSF/mobsfscan,
https://github.com/dwisiswant0/apkleaks,
https://developer.android.com/studio/write/lint

## Common false positives

The `android-runner` agent emits these findings at their tool-declared
severity, but the triage step SHOULD downgrade or suppress them when the
listed context applies.

- **mobsfscan `android_logging`** in files under `debug/`, `test/`,
  `androidTest/`, or `src/test/` — `Log.d()` / `Log.v()` calls in test
  instrumentation are the standard Android testing idiom. Downgrade to
  `INFO` or suppress when the file path is under a test source set.

- **mobsfscan `android_webview_javascript`** on WebView classes that only
  load local `file://` or `asset://` content with no remote URL input —
  JavaScript enabled in a WebView is a risk when the URL is attacker-
  controlled. Downgrade when the WebView is provably local-only (no network
  permission, no `loadUrl()` call with a variable argument).

- **apkleaks `LinkFinder` findings on internal API base URLs** embedded
  in the APK that are not sensitive infrastructure endpoints (e.g.
  `https://fonts.googleapis.com/`, `https://play.google.com/`) — these are
  public SDK dependencies, not leaked internal endpoints. Suppress when the
  URL matches a well-known public Google or Firebase SDK domain.

- **apkleaks `Email` findings on developer contact addresses** in package
  manifest metadata or play-store listing strings compiled into the APK —
  these are intentionally public. Suppress when the email domain matches the
  app's own domain and the string appears in a resource file (e.g.
  `res/values/strings.xml`).

- **android-lint `AllowBackup` Warning** on applications that implement
  a custom `BackupAgent` with explicit include/exclude rules — the lint
  rule fires on the `allowBackup="true"` attribute without inspecting the
  `BackupAgent` class. Downgrade to `INFO` when a `android:backupAgent`
  attribute is also present in the manifest, indicating the developer
  controls what is backed up.

- **android-lint `ExportedReceiver` / `ExportedService`** on components
  that declare a custom `android:permission` restricting access to callers
  holding a signature-level permission — the component is exported
  intentionally and protected. Downgrade when the permission's
  `protectionLevel` is `signature` or `signatureOrSystem`.

- **android-lint `SetJavaScriptEnabled`** in first-party WebView wrappers
  used exclusively to render bundled HTML/JS content (e.g. in-app
  documentation, onboarding flows) where no `loadUrl()` call accepts
  external input — flag for review but note the limited exploitability.

Source: https://github.com/MobSF/mobsfscan,
https://github.com/dwisiswant0/apkleaks,
https://developer.android.com/studio/write/lint,
https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

## CI notes

These notes apply when the Android lane runs inside a GitHub Actions workflow
or equivalent CI system.

- **Java / SDK environment:** android-lint (Gradle) requires a JDK (17 or
  21 recommended for AGP 8.x) and the `ANDROID_HOME` environment variable
  pointing to the Android SDK root. Use `actions/setup-java` and
  `android-actions/setup-android` (or equivalent) before invoking the
  runner. The standalone `lint` binary also requires `ANDROID_HOME`.

- **Gradle build cache:** `./gradlew :app:lintDebug` triggers a partial
  build to resolve resources. Cache the Gradle user home
  (`~/.gradle/caches/` and `~/.gradle/wrapper/`) between CI runs to avoid
  re-downloading the Android Gradle Plugin and lint rule JARs on every job.

- **APK availability:** apkleaks requires a pre-built APK. If the CI
  pipeline does not produce an APK artifact before the android-runner job
  runs, apkleaks will be cleanly skipped (`reason: "no-apk"`). To include
  apkleaks in a full scan, ensure the build step runs before the scan step
  and passes the APK path to the runner. The clean-skip is not a failure;
  the sentinel line records it for observability.

- **mobsfscan source path:** Pass the source root containing Java/Kotlin
  files (e.g. `app/src/main/java/`) rather than the project root to avoid
  scanning Gradle build output directories, which may contain generated
  code that inflates finding counts with non-actionable hits.

- **Exit-code handling:** Gradle lint exits non-zero when lint errors are
  present and `lintOptions { abortOnError true }` (the default). A naive
  `if [ $? -ne 0 ]` guard that stops the CI job before the runner can
  parse the XML report will suppress all lint findings. The runner MUST
  invoke `./gradlew :app:lintDebug || true` (or `continue-on-error: true`
  in Actions) and parse the XML report unconditionally.

- **Parallel invocation:** mobsfscan (source scan) and android-lint (Gradle
  or standalone) are read-only and safe to run in parallel against the same
  source tree. apkleaks operates on the compiled APK and is independent of
  both; it can be run in parallel with the other two once the APK is
  available.

Source: https://github.com/MobSF/mobsfscan,
https://github.com/dwisiswant0/apkleaks,
https://developer.android.com/studio/write/lint
