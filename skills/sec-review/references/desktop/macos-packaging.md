# macOS .pkg / .dmg Installer + Sparkle Auto-Update Hygiene

## Source

- https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac — Apple Developer: Creating Distribution-Signed Code for the Mac
- https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution — Apple Developer: Notarizing macOS Software Before Distribution
- https://developer.apple.com/library/archive/technotes/tn2206/_index.html — Apple Technical Note TN2206: macOS Code Signing In Depth
- https://sparkle-project.org/documentation/ — Sparkle Project: Sparkle Auto-Update Framework Documentation
- https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web — Apple Platform Security: Protecting Against Malware
- https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html — OWASP Software Supply Chain Security Cheat Sheet

## Scope

In-scope: macOS `.pkg` flat-package installer hygiene including `preinstall` and `postinstall` scripts under a `Scripts/` component directory, `.dmg` disk-image distribution hygiene, Gatekeeper codesigning and notarization stapling requirements for both `.pkg` and `.dmg` artifacts, and Sparkle auto-update framework configuration (Info.plist keys `SUFeedURL`, `SUPublicEDKey`, `SUAllowsAutomaticUpdates`, `SUAutomaticallyUpdate`). Out of scope: hardened-runtime entitlements and library-validation flags (`macos-hardened-runtime.md`); TCC privacy permission entitlements such as `NSCameraUsageDescription` and `com.apple.security.files.user-selected.read-write` (`macos-tcc.md`); iOS and iPadOS equivalent distribution including `.ipa` packaging and App Store Connect submission (`mobile/ios-codesign.md`); Linux packaging maintainer scripts (`linux-packaging.md`).

## Dangerous patterns (regex/AST hints)

### `.pkg` installer script missing `set -e` — CWE-390

- Why: A `preinstall` or `postinstall` script that does not begin with `set -e` continues executing silently after any failing command. A failed `chown`, `ditto`, or account-creation call leaves the system in a partially-installed, undefined state; macOS Installer reports success regardless because it reads only the final exit code. CWE-390 (Detection of Error Condition Without Action) applies because the script swallows intermediate failures and the installer surfaces no diagnostic to the user.
- Grep: `^#!/bin/(sh|bash)` present in the file AND the first non-shebang non-comment non-blank line does NOT match `^set -e`
- File globs: `**/postinstall`, `**/preinstall`, `**/*pkg*/Scripts/**`, `**/installer/Scripts/**`, `**/pkg/Scripts/**`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

### `postinstall` executing `curl http://... | sh` or `curl http://... | bash` — CWE-494 / CWE-829 / CWE-319

- Why: A `postinstall` script that fetches a remote URL over cleartext HTTP and pipes it directly to a shell interpreter executes arbitrary attacker-controlled code during installation with the elevated privileges of the macOS Installer process (typically root). A network-positioned attacker or a compromised CDN can substitute the payload with no indication to the user. CWE-494 (Download of Code Without Integrity Check), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), and CWE-319 (Cleartext Transmission of Sensitive Information) all apply. OWASP Supply Chain guidance explicitly prohibits unauthenticated, unverified fetches in install hooks.
- Grep: `(curl|wget)[^\n]*http://[^ ]+` and `(curl|wget)[^\n]*\|[^\n]*(bash|sh)`
- File globs: `**/postinstall`, `**/preinstall`, `**/*pkg*/Scripts/**`, `**/pkg/Scripts/**`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

### `postinstall` `chown`ing files to `root:wheel` without documented necessity — CWE-250

- Why: A `postinstall` script that calls `chown root:wheel` (or `chown root`) on application files, configuration directories, or helper binaries widens the privilege footprint unnecessarily. Any subsequent vulnerability in that file — a TOCTOU race, a symlink follow, or a logic bug — becomes exploitable at root level. CWE-250 (Execution with Unnecessary Privileges) applies. Reviewers must confirm ownership change is required for a specific, documented purpose (e.g. a SUID binary, a privileged helper registered with `SMJobBless`) rather than applied as a blanket default.
- Grep: `chown\s+root(:wheel)?\s+`
- File globs: `**/postinstall`, `**/preinstall`, `**/*pkg*/Scripts/**`
- Source: https://developer.apple.com/library/archive/technotes/tn2206/_index.html

### Unsigned `.pkg` distributed outside the App Store — CWE-693

- Why: A `.pkg` file that carries no Developer ID Installer certificate signature will fail Gatekeeper assessment on the end-user machine at launch time. macOS 13+ enforces Gatekeeper checks on all quarantined files, and an unsigned package cannot be assessed as safe by the OS even if the user has set GK to "App Store and identified developers". Beyond UX impact, an unsigned `.pkg` gives no chain-of-custody guarantee: any party with filesystem access to the artifact can swap the payload without detection. CWE-693 (Protection Mechanism Failure) applies because the distribution-level integrity control is absent. Detection: run `pkgutil --check-signature <file>.pkg`; a result of "no signature" on a release artifact under the target directory is a finding.
- Grep: absence of a codesign step (`pkgbuild --sign` or `productsign --sign`) in release build scripts
- File globs: `**/*.pkg`, `**/Makefile`, `**/*.sh`, `**/.github/workflows/*.yml`, `**/Fastfile`
- Source: https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac

### Missing stapled notarization ticket on release `.pkg` or `.dmg` — CWE-693

- Why: Apple's Notary Service issues a notarization ticket that must be stapled to the artifact before distribution. Without a stapled ticket, Gatekeeper must contact Apple's online notary server on first launch to verify the artifact; users without network access, or on networks that block Apple's notarization CDN, cannot install the software. A stapled ticket also prevents an adversary from re-distributing a notarized binary stripped of its ticket. CWE-693 applies because the protection mechanism (offline Gatekeeper assessment) is absent. Detection: run `xcrun stapler validate <artifact>` on every release `.pkg` and `.dmg`; "The validate action worked" confirms stapling; any other output is a finding.
- Grep: absence of `xcrun stapler staple` in CI release scripts after `xcrun notarytool submit`
- File globs: `**/*.pkg`, `**/*.dmg`, `**/.github/workflows/*.yml`, `**/Fastfile`, `**/release*.sh`
- Source: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution

### Sparkle `SUFeedURL` over HTTP — CWE-319

- Why: A Sparkle `SUFeedURL` that begins with `http://` delivers the appcast XML over cleartext, allowing a network-positioned attacker to substitute the feed with a pointer to a malicious update payload. This is the transport-layer component of the historic Sparkle MITM update class (first documented publicly around CVE-2014-9390 for similar auto-update patterns). Even if EdDSA payload signing is configured, a MITM-substituted feed can point to an older, signed-but-vulnerable build, effecting a downgrade attack. CWE-319 (Cleartext Transmission of Sensitive Information) applies.
- Grep: `<key>SUFeedURL</key>\s*<string>http://`
- File globs: `**/Info.plist`, `**/*-Info.plist`
- Source: https://sparkle-project.org/documentation/

### Sparkle `SUPublicEDKey` absent from an Info.plist that contains `SUFeedURL` — CWE-494

- Why: Sparkle 2.x requires an EdDSA public key (`SUPublicEDKey`) to verify the cryptographic signature on each update archive before installation. When `SUFeedURL` is present but `SUPublicEDKey` is absent, Sparkle 2.x falls back to trusting HTTPS transport alone for integrity: a compromised server, a valid HTTPS MITM certificate, or a CDN compromise is sufficient to deliver and install arbitrary code. CWE-494 (Download of Code Without Integrity Check) applies because the end-to-end payload signature check — independent of transport — is missing.
- Grep: presence of `<key>SUFeedURL</key>` without a matching `<key>SUPublicEDKey</key>` in the same file
- File globs: `**/Info.plist`, `**/*-Info.plist`
- Source: https://sparkle-project.org/documentation/

### Sparkle `SUAllowsAutomaticUpdates=YES` combined with `SUAutomaticallyUpdate=YES` — operational/security hygiene

- Why: When both `SUAllowsAutomaticUpdates` and `SUAutomaticallyUpdate` are set to `YES` in Info.plist, Sparkle silently downloads and installs updates without user confirmation, using whichever update stream `SUFeedURL` points to. If the feed is compromised or the EdDSA key is rotated without user notice, the application is silently replaced. This is an operational and security hygiene concern: silent replacement of a signed binary is opaque to the user, breaks audit trails, and removes the last human checkpoint before code execution. Flag for reviewer attention; downgrade confidence if EdDSA signing is confirmed present and the feed is HTTPS.
- Grep: `<key>SUAllowsAutomaticUpdates</key>` followed by `<true/>` AND `<key>SUAutomaticallyUpdate</key>` followed by `<true/>` in the same file
- File globs: `**/Info.plist`, `**/*-Info.plist`
- Source: https://sparkle-project.org/documentation/

### `.pkg` `CFBundleVersion` mismatch between the package component plist and the embedded `.app` bundle — supply-chain / anti-tamper hint

- Why: A `.pkg` whose component property list (`PackageInfo` or the embedded `.app`'s `Info.plist`) advertises a different `CFBundleVersion` than the `.app` bundle extracted by the installer is a supply-chain integrity hint: the package payload may have been re-signed at a different version, tampered with post-build, or assembled by a script that did not update all version tokens atomically. This is a hint-level finding; the reviewer must extract and compare versions before flagging. Detection: `pkgutil --expand <file>.pkg <dir>` then compare `PackageInfo` `version` attribute with `<dir>/Payload/<App>.app/Contents/Info.plist` `CFBundleVersion`.
- Grep: `CFBundleVersion` values in `PackageInfo` and `Info.plist` that differ after extraction
- File globs: `**/PackageInfo`, `**/Info.plist`
- Source: https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac

## Secure patterns

Minimal `postinstall` with `set -e`, PATH sanitisation, and explicit error logging on failure:

```sh
#!/bin/sh
set -e

# Sanitise PATH to only known system locations; prevents a compromised $PATH
# from redirecting chown, chmod, or dscl to attacker-controlled binaries.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

# Identify script context for log messages.
SCRIPT_NAME=$(basename "$0")
LOG_PREFIX="[$SCRIPT_NAME]"

log_error() {
    echo "${LOG_PREFIX} ERROR: $*" >&2
}

# Example: create a dedicated service account on first install.
if ! dscl . -read /Users/_myapp > /dev/null 2>&1; then
    dscl . -create /Users/_myapp || { log_error "Failed to create _myapp user account."; exit 1; }
    dscl . -create /Users/_myapp UserShell /usr/bin/false
    dscl . -create /Users/_myapp RealName "My App Service"
    dscl . -create /Users/_myapp UniqueID 505
    dscl . -create /Users/_myapp PrimaryGroupID 505
    dscl . -create /Users/_myapp NFSHomeDirectory /var/empty
fi

# Set ownership of the application support directory.
if [ -d "/Library/Application Support/MyApp" ]; then
    chown -R _myapp:_myapp "/Library/Application Support/MyApp"
    chmod 0750 "/Library/Application Support/MyApp"
fi

exit 0
```

`set -e` on the second line ensures the installer process sees a non-zero exit on any failing command. `PATH` is clamped to known system directories before any command runs. `log_error` writes to stderr, which macOS Installer forwards to the install log visible in `/var/log/install.log`. The `|| { log_error ...; exit 1; }` guards on `dscl` calls produce a human-readable entry in the install log when the account creation fails.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

Sparkle Info.plist fragment with HTTPS `SUFeedURL`, EdDSA public key, and automatic updates gated on explicit user consent:

```xml
<!-- Info.plist fragment — Sparkle 2.x secure configuration -->

<!-- HTTPS appcast feed. Never use http://. -->
<key>SUFeedURL</key>
<string>https://updates.example.com/myapp/appcast.xml</string>

<!-- EdDSA public key generated by `generate_keys` from the Sparkle distribution.
     The matching private key is stored offline (NOT in the repo or CI secrets). -->
<key>SUPublicEDKey</key>
<string>REPLACE_WITH_OUTPUT_OF_generate_keys</string>

<!-- Allow the user to opt in to automatic updates via the UI; do NOT force silent
     replacement. SUAutomaticallyUpdate should remain absent or set to NO. -->
<key>SUAllowsAutomaticUpdates</key>
<true/>

<!-- SUAutomaticallyUpdate intentionally omitted (defaults to NO) so that
     Sparkle presents a confirmation dialog before installing any update. -->
```

`SUFeedURL` must use `https://`. `SUPublicEDKey` is the base64-encoded Ed25519 public key produced by running `./bin/generate_keys` from the Sparkle distribution once per app, with the private key stored securely offline. Omitting `SUAutomaticallyUpdate` (or setting it explicitly to `NO`) ensures the user sees a confirmation prompt before any update is installed, preserving audit trail and user agency.

Source: https://sparkle-project.org/documentation/

## Fix recipes

### Recipe: Add `set -e` and `trap` to a bare `postinstall` — addresses CWE-390

**Before (dangerous):**

```sh
#!/bin/sh

/usr/sbin/dseditgroup -o create -r "My App" -t group com.example.myapp
chown -R root:wheel /Library/MyApp
```

**After (safe):**

```sh
#!/bin/sh
set -e

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

trap 'echo "[postinstall] ERROR: command failed at line $LINENO — install may be incomplete." >&2' ERR

/usr/sbin/dseditgroup -o create -r "My App" -t group com.example.myapp
chown -R _myapp:_myapp /Library/MyApp
chmod 0750 /Library/MyApp

trap - ERR
exit 0
```

Three changes are applied together: (1) `set -e` immediately after the shebang so any failing command aborts the script and the macOS Installer receives a non-zero exit code, surfacing the failure in `/var/log/install.log`; (2) `PATH` is clamped to system directories before any external command runs; (3) a `trap ... ERR` emits a human-readable line number to stderr on failure, giving the reviewer a precise location in the install log. The `chown` target is changed from the overly broad `root:wheel` to the service account `_myapp` (CWE-250 mitigation).

Source: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

### Recipe: Replace `SUFeedURL=http://...` with HTTPS and add `SUPublicEDKey` — addresses CWE-319 / CWE-494

**Before (dangerous):**

```xml
<key>SUFeedURL</key>
<string>http://updates.example.com/myapp/appcast.xml</string>
```

**After (safe):**

```xml
<key>SUFeedURL</key>
<string>https://updates.example.com/myapp/appcast.xml</string>

<key>SUPublicEDKey</key>
<string>REPLACE_WITH_OUTPUT_OF_generate_keys</string>
```

Steps to generate the EdDSA key pair and sign update archives:

```sh
# 1. From the Sparkle distribution directory, generate a fresh key pair once.
#    The public key is printed to stdout; store the private key securely (e.g.
#    in a hardware key store or an offline secrets manager — NOT in the repo).
./bin/generate_keys

# 2. Copy the printed public key string into Info.plist as SUPublicEDKey above.

# 3. For each release archive, sign it with the private key:
./bin/sign_update /path/to/MyApp-1.2.3.zip
# Outputs a sparkle:edSignature attribute to embed in the appcast <enclosure>.
```

The `SUFeedURL` scheme change from `http://` to `https://` closes the cleartext transport vector (CWE-319). Adding `SUPublicEDKey` and signing each archive with `sign_update` ensures Sparkle 2.x verifies the EdDSA signature on the payload independently of transport, closing the integrity-check gap (CWE-494).

Source: https://sparkle-project.org/documentation/

### Recipe: Chain `xcrun notarytool submit --wait` + `xcrun stapler staple` in the CI release flow — addresses CWE-693

**Before (dangerous — artifact distributed without notarization ticket):**

```sh
# Release script excerpt — signs but does not notarize or staple.
productsign --sign "Developer ID Installer: Example Corp (TEAMID)" \
    MyApp-unsigned.pkg MyApp.pkg
# Artifact uploaded to release server here with no further checks.
```

**After (safe):**

```sh
#!/bin/sh
set -e

TEAM_ID="TEAMID"
BUNDLE_ID="com.example.myapp"
ARTIFACT="MyApp.pkg"

# 1. Sign the package with the Developer ID Installer certificate.
productsign --sign "Developer ID Installer: Example Corp (${TEAM_ID})" \
    MyApp-unsigned.pkg "${ARTIFACT}"

# 2. Submit to the Apple Notary Service and wait for the result.
#    APPLE_ID and APP_SPECIFIC_PASSWORD must be set in CI secrets (not hardcoded).
xcrun notarytool submit "${ARTIFACT}" \
    --apple-id "${APPLE_ID}" \
    --team-id "${TEAM_ID}" \
    --password "${APP_SPECIFIC_PASSWORD}" \
    --wait

# 3. Staple the notarization ticket to the artifact so Gatekeeper can verify
#    it offline without contacting Apple's servers on the end-user machine.
xcrun stapler staple "${ARTIFACT}"

# 4. Confirm the ticket is present before releasing.
xcrun stapler validate "${ARTIFACT}"
```

`--wait` blocks the CI job until the notarization request resolves; failures are caught immediately rather than discovered after distribution. `xcrun stapler validate` is a mandatory gate: if stapling fails (e.g. the notarytool submission returned an error that was not propagated), the build exits non-zero and the artifact is not released. `APPLE_ID` and `APP_SPECIFIC_PASSWORD` must be stored as masked CI secrets and never hardcoded in the script.

Source: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution

## Version notes

- `xcrun notarytool` is the current submission tool (Xcode 13+, macOS 12+). The legacy `xcrun altool --notarize-app` was deprecated in Xcode 13 and stopped accepting submissions in November 2023; CI pipelines still referencing `altool` will fail and should be migrated to `notarytool`.
- Sparkle 1.x used DSA signatures (`SUPublicDSAKeyFile`). DSA support was removed in Sparkle 2.0 (released 2022-01); `SUPublicEDKey` (Ed25519) is the only supported signing mechanism in Sparkle 2.x. Apps still shipping `SUPublicDSAKeyFile` without `SUPublicEDKey` receive no payload signature verification on Sparkle 2.x and must be migrated.
- Gatekeeper path-randomisation (macOS 10.15+) quarantines `.dmg`-distributed apps and enforces notarization checks on every quarantined launch. The `com.apple.quarantine` extended attribute is set automatically when a user downloads a file via a browser or `curl`; stapled notarization tickets are checked inline without a network round-trip.
- `pkgutil --check-signature` reports signature status for flat packages; `spctl --assess -v --type install <file>.pkg` runs the full Gatekeeper assessment and is the closer proxy to what the OS does at install time.

## Common false positives

- `chown\s+root(:wheel)?\s+` matching inside a comment line or an `echo` / `printf` statement — triage by confirming the line is not prefixed with `#` and is not inside a heredoc or a quoted string argument to `echo`.
- `(curl|wget)[^\n]*\|[^\n]*(bash|sh)` inside a documentation or `README` block embedded in the script as a heredoc example — verify the match is on an executable line, not inside a `cat <<'EOF'` block or a comment.
- `<key>SUAllowsAutomaticUpdates</key><true/>` without `SUAutomaticallyUpdate` — the presence of `SUAllowsAutomaticUpdates=YES` alone only enables the UI preference toggle; it does not enable silent updates. The silent-update finding requires both keys set to `YES` in the same file.
- `<key>SUPublicEDKey</key>` absent in an Info.plist that does NOT contain `SUFeedURL` — the EdDSA key is only relevant when Sparkle is integrated and `SUFeedURL` is configured; flag only when both conditions coexist.
- `productsign` or `pkgbuild --sign` absent from a build script that is clearly a development or debug build (identified by build configuration variables such as `CONFIGURATION=Debug`, `DEBUG=1`, or a non-release lane name in a `Fastfile`) — notarization and signing requirements apply to release/distribution artifacts only.
