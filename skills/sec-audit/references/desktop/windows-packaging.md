# MSI / MSIX / WiX Installer Hygiene + MSIX Manifest Capability Discipline

## Source

- https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security — Microsoft Learn: Custom Action Security (Windows Installer SDK)
- https://learn.microsoft.com/en-us/windows/msix/package/packaging-uwp-apps — Microsoft Learn: Package a UWP app with MSIX
- https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root — Microsoft Learn: Package manifest schema reference (AppxManifest)
- https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview — Microsoft Learn: Microsoft Defender SmartScreen overview
- https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools — Microsoft Learn: Cryptography Tools (signtool, certutil)
- https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html — OWASP Software Supply Chain Security Cheat Sheet

## Scope

In-scope: MSI installer hygiene including `CustomAction` type-flag analysis in WiX `.wxs` authoring files and MSI table dumps, sequencing correctness (Commit/Rollback pairing, deferred-action privilege flags), MSIX manifest capability discipline (`<rescap:Capability>`, `<uap:Capability>`) in `Package.appxmanifest` and `.appxmanifest` files, `Package.Identity` Publisher alignment with the signing certificate subject, and Microsoft Defender SmartScreen reputation-building awareness for new installer certificates. Out of scope: Authenticode signing operations per se (signtool invocation, timestamp authority selection, EV certificate provisioning) covered in `windows-authenticode.md`; AppLocker / Windows Defender Application Control policy authoring covered in `windows-applocker.md`; Microsoft Store submission review (external, policy-driven process); macOS `.pkg` and `.dmg` packaging covered in `macos-packaging.md`; Debian `.deb` installer scripts covered in `linux-packaging.md`.

## Dangerous patterns (regex/AST hints)

### MSI `CustomAction` Type 3426 — deferred + impersonate + exe-from-installed-file — CWE-250

- Why: Type 3426 is the bitwise OR of `msidbCustomActionTypeExe` (0x02) + `msidbCustomActionTypeInstalled` (0x10) + `msidbCustomActionTypeInScript` (0x400) + `msidbCustomActionTypeNoImpersonate` absent, meaning the action runs with impersonation (user token) from a file written to the installation directory during the deferred phase. The critical danger is that the deferred phase executes under the SYSTEM context for per-machine installs, yet the `NoImpersonate` bit is clear, so Windows Installer reverts to the installing user token at execution time — but the source binary was written to a location writable by that user before the deferred phase completes. An attacker who can replace that binary between the copy step and the deferred execution step achieves code execution at the elevated phase. Microsoft SDL explicitly disallows this type combination. CWE-250 (Execution with Unnecessary Privileges) applies because the installer runs with elevated context from a user-writable path.
- Grep: `Type="3426"` or the integer `3426` in a `CustomAction` element; also match sums: `Type="18"` with an `InScript` attribute, or flag-sum literals `0xD62`, `0x0D62`
- File globs: `**/*.wxs`, `**/*.wxi`, `**/CustomAction.idt`, `**/*.msi` (after MSI table dump via `msiinfo` or `lessmsi`)
- Source: https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security

### MSI `CustomAction` Type 18 — exe-in-binary-table without preceding signature verification — CWE-494

- Why: Type 18 (`msidbCustomActionTypeExe` 0x02 + `msidbCustomActionTypeBinaryData` 0x10 = 0x12 = 18) runs an EXE that is stored directly in the MSI `Binary` table. The binary is extracted to a temporary directory and executed. Microsoft SDL requires that any EXE in the Binary table be Authenticode-signed, and that a preceding custom action verifies the signature before execution. When neither condition holds, the MSI can be unpacked with standard tools, the binary swapped for a malicious payload, and the package re-assembled without breaking the outer MSI signature (which covers the stream, not the binary content). CWE-494 (Download of Code Without Integrity Check) applies because the installer executes embedded code without integrity verification.
- Grep: `Type="18"` in a `CustomAction` element, or integer `18`, or hex `0x12`; also absence of a preceding `<Custom Action="...VerifySignature"` or `signtool verify` invocation in the same sequence
- File globs: `**/*.wxs`, `**/*.wxi`, `**/CustomAction.idt`
- Source: https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security

### Missing `Rollback` action for a `Commit` custom action — CWE-459

- Why: The MSI execution model separates deferred actions into three phases: deferred (main transaction), commit (after the transaction succeeds), and rollback (on failure). A `Commit` custom action that has no paired `Rollback` sibling leaves the system in a half-installed state when the installation fails mid-sequence: the commit action has already run (e.g. started a service, written a registry key, provisioned a database row) but no compensating action undoes it on rollback. CWE-459 (Incomplete Cleanup) applies. WiX best practice requires every `Commit` deferred action to have a matching `Rollback` action scheduled in the same sequence.
- Grep: `Execute="commit"` (case-insensitive) in a `CustomAction` element without a corresponding `Execute="rollback"` action referencing the same logical target in the same `.wxs` file or sequence table
- File globs: `**/*.wxs`, `**/*.wxi`, `**/InstallExecuteSequence.idt`
- Source: https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security

### MSIX `<rescap:Capability Name="runFullTrust">` — CWE-250 / CWE-693

- Why: The `runFullTrust` restricted capability grants the packaged application the ability to run as a full-trust process, bypassing the MSIX container sandbox entirely. A packaged Win32 application that declares `runFullTrust` has the same system access as an unpackaged process; the MSIX integrity boundary, AppContainer isolation, and capability-gated API brokering all cease to apply. CWE-250 (Execution with Unnecessary Privileges) applies when the capability is present without documented necessity. CWE-693 (Protection Mechanism Failure) applies because the container sandbox — the primary security control in the MSIX model — is disabled. Reviewers must confirm the capability is required by a specific subsystem (e.g. a COM server, a kernel driver companion, an SMB share provider) and is not used as a blanket workaround to avoid proper capability declarations.
- Grep: `<rescap:Capability[^/]*Name="runFullTrust"`
- File globs: `**/*.appxmanifest`, `**/Package.appxmanifest`, `**/*.appx` (after extraction), `**/*.msix` (after extraction)
- Source: https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root

### MSIX `<rescap:Capability Name="allowElevation">` — CWE-250

- Why: The `allowElevation` restricted capability permits the packaged application to request UAC elevation at runtime, enabling the process to obtain an elevated token with administrator privileges. Like `runFullTrust`, this capability requires explicit justification in the SDL threat model and store submission review. When present without necessity, any vulnerability in the application (e.g. a command injection, a DLL side-load, or an argument injection in a child process) becomes exploitable at administrator level. CWE-250 applies. Reviewers must verify the application's elevation requirement cannot be satisfied by a minimal COM elevation moniker or a Windows service running under a least-privilege account instead.
- Grep: `<rescap:Capability[^/]*Name="allowElevation"`
- File globs: `**/*.appxmanifest`, `**/Package.appxmanifest`
- Source: https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root

### MSIX `Package.Identity Publisher` not matching signing certificate subject — CWE-295

- Why: The `Publisher` attribute of the `<Identity>` element in `Package.appxmanifest` must be the distinguished-name string of the Authenticode certificate subject that signs the package (e.g. `CN=Example Corp, O=Example Corp, L=Seattle, S=WA, C=US`). When the strings do not match, Windows rejects the package during installation with an integrity error; in some older deployment paths the installer surfaces a blank or `-` publisher to the user and may proceed. More critically, a mismatch indicates that the package was either re-signed after manifest assembly (breaking the integrity chain) or that the manifest was authored for a different certificate than is available in CI. CWE-295 (Improper Certificate Validation) applies at the authoring level. Detection: extract the signing certificate subject with `signtool verify /pa /v <package>.msix` and compare to the `Publisher` attribute in `Package.appxmanifest`.
- Grep: `Publisher="CN=` in `Package.appxmanifest` — hint only; reviewer must compare extracted cert subject at runtime
- File globs: `**/*.appxmanifest`, `**/Package.appxmanifest`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### WiX `InstallScope="perUser"` combined with privileged registry or PATH writes — CWE-250

- Why: A WiX package declaring `InstallScope="perUser"` installs without elevation: the MSI runs under the current user token and Windows Installer does not request a SYSTEM context. Any custom action or registry component in the same `.wxs` that writes to `HKLM` (HKEY_LOCAL_MACHINE) or modifies the machine-scope `PATH` environment variable (via `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`) will either silently fail (access denied, no error surfaced to the user) or will require a UAC prompt that contradicts the `perUser` intent. CWE-250 applies when a per-user installer silently escalates scope. Reviewers must confirm that all registry and file components target per-user locations (`HKCU`, `%LOCALAPPDATA%`, `%APPDATA%`) exclusively.
- Grep: `InstallScope="perUser"` in `<Package>` element AND `HKLM` anywhere in the same file, or `RegistryKey Root="HKLM"` in any `<RegistryValue>` element
- File globs: `**/*.wxs`, `**/*.wxi`
- Source: https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security

### Low-volume installer distribution without SmartScreen reputation buildup — operational hygiene

- Why: Microsoft Defender SmartScreen assigns reputation to Authenticode-signed executables and installers based on the signing certificate's hash and the volume of downloads observed from that certificate across the Windows ecosystem. A new certificate (regardless of whether it is a standard OV or EV certificate) starts with zero reputation. Users who download and run the installer before the certificate has accumulated sufficient reputation see a SmartScreen warning ("Windows protected your PC — Unknown Publisher") that they must manually bypass. For EV (Extended Validation) certificates, SmartScreen grants immediate reputation on first use; for standard OV certificates there is a mandatory warm-up period. Absence of a documented SmartScreen reputation plan (EV certificate choice, phased rollout, catalog signing) in the release checklist is an operational security gap because it degrades the user's trust signal on legitimate software and incentivises users to habitually bypass SmartScreen warnings.
- Grep: absence of SmartScreen, EV certificate, or reputation references in `RELEASE.md`, `release-checklist.md`, or CI release workflow annotations
- File globs: `**/RELEASE*.md`, `**/release*.md`, `**/.github/workflows/release*.yml`, `**/release*.sh`
- Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview

### MSI custom-action credential prompts without input constraints — CWE-522 adjacent

- Why: A custom action that calls `MsiProcessMessage` with `INSTALLMESSAGE_ACTIONSTART` plus an embedded dialog, or that shells out to a process that prompts for credentials (username, password, license key) inside the Windows Installer session, is phishing-adjacent: the prompt appears in the context of the trusted installer UI and the user has no reliable way to distinguish a legitimate installer prompt from a malicious one injected by a supply-chain-compromised custom action. Microsoft SDL flags installer-phase credential collection as high-risk. Additionally, credentials collected in a custom action are accessible to other custom actions running in the same MSI session and may be logged to MSI verbose logs if the calling code passes them through `Property` table values. CWE-522 (Insufficiently Protected Credentials) applies when collected credentials are not immediately consumed and discarded within the action boundary, or when they pass through MSI properties.
- Grep: `MsiProcessMessage` in C/C++ custom action source; `Session.Message` in VBScript/JScript custom actions; `MessageBox` or `InputBox` calls inside a DLL or script custom action; `<Property Id="PASSWORD"` or `<Property Id="DB_PASS"` in `.wxs`
- File globs: `**/*.wxs`, `**/*.cpp`, `**/*.cs`, `**/*.vbs`, `**/*.js`, `**/CustomAction*.dll`
- Source: https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security

## Secure patterns

Minimal WiX `.wxs` fragment with a Type 3072 deferred, system-context, script-source custom action, a signed binary table entry guarded by a preceding signature-verification action, and a paired Rollback action:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="ExampleApp" Language="1033"
           Version="1.0.0.0" Manufacturer="Example Corp"
           UpgradeCode="PUT-GUID-HERE">

    <Package InstallerVersion="500" Compressed="yes"
             InstallScope="perMachine" />

    <!--
      Type 3072 = msidbCustomActionTypeScript (0x400)
                + msidbCustomActionTypeInScript (0x400, already set)
                + msidbCustomActionTypeNoImpersonate (0x800)
                + msidbCustomActionTypeSourceFile (0x10)
      In WiX: BinaryKey="..." + Execute="deferred" + Impersonate="no"
      This combination runs the action under the SYSTEM context during the
      deferred phase WITHOUT impersonating the installing user. The source
      is a binary-table entry that must be Authenticode-signed before packaging.
    -->

    <!-- Step 1: Verify the helper binary's Authenticode signature before use. -->
    <CustomAction Id="VerifyHelperSignature"
                  BinaryKey="SetupHelperCA"
                  DllEntry="VerifySignature"
                  Execute="immediate"
                  Return="check" />

    <!-- Step 2: The primary deferred action — runs as SYSTEM, no impersonation. -->
    <CustomAction Id="ConfigureService"
                  BinaryKey="SetupHelperCA"
                  DllEntry="ConfigureServiceEntry"
                  Execute="deferred"
                  Impersonate="no"
                  Return="check" />

    <!-- Step 3: Rollback sibling — MUST be present for every Commit/deferred action. -->
    <CustomAction Id="ConfigureServiceRollback"
                  BinaryKey="SetupHelperCA"
                  DllEntry="ConfigureServiceRollbackEntry"
                  Execute="rollback"
                  Impersonate="no"
                  Return="check" />

    <!--
      Binary table entry. The referenced DLL/EXE MUST be Authenticode-signed
      with an EV or OV certificate before being embedded here. Verify with:
        signtool verify /pa /v SetupHelper.dll
    -->
    <Binary Id="SetupHelperCA" SourceFile="$(var.SetupHelperCA.TargetPath)" />

    <InstallExecuteSequence>
      <!-- Signature verification runs immediate, before deferred phase. -->
      <Custom Action="VerifyHelperSignature" Before="InstallInitialize">NOT Installed</Custom>
      <!-- Rollback scheduled before the primary action so it is registered first. -->
      <Custom Action="ConfigureServiceRollback" Before="ConfigureService">NOT Installed</Custom>
      <Custom Action="ConfigureService" After="InstallFiles">NOT Installed</Custom>
    </InstallExecuteSequence>

  </Product>
</Wix>
```

Key properties: `Execute="deferred"` + `Impersonate="no"` is the WiX spelling of Type 3072 (NoImpersonate bit set, deferred phase). The `VerifySignature` action runs in the `immediate` phase (before elevation) so that if the binary table entry fails signature validation the installation aborts before any SYSTEM-context code runs. The `Rollback` action is scheduled `Before` its primary sibling so it is registered in the rollback script before the primary action executes.

Source: https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security

Minimal `Package.appxmanifest` using only `<uap:Capability>` entries (no `rescap:` namespace), with a `Publisher` value that matches the signing certificate subject:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:uap2="http://schemas.microsoft.com/appx/manifest/uap/windows10/2"
  IgnorableNamespaces="uap uap2">

  <!--
    Publisher MUST match the Subject Distinguished Name of the signing certificate
    exactly, including attribute order and spacing. Obtain the exact string with:
      signtool verify /pa /v MyApp.msix
    or:
      certutil -dump MyCert.cer | findstr "Subject:"
    Any mismatch causes installation failure (or silent blank publisher display
    on older deployment paths).
  -->
  <Identity
    Name="com.example.MyApp"
    Publisher="CN=Example Corp, O=Example Corp, L=Seattle, S=WA, C=US"
    Version="1.0.0.0" />

  <Properties>
    <DisplayName>MyApp</DisplayName>
    <PublisherDisplayName>Example Corp</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>

  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop"
                        MinVersion="10.0.17763.0"
                        MaxVersionTested="10.0.22621.0" />
  </Dependencies>

  <Resources>
    <Resource Language="en-US" />
  </Resources>

  <Applications>
    <Application Id="App"
                 Executable="MyApp.exe"
                 EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="MyApp"
                          Square150x150Logo="Assets\Square150x150Logo.png"
                          Square44x44Logo="Assets\Square44x44Logo.png"
                          Description="MyApp"
                          BackgroundColor="transparent" />
    </Application>
  </Applications>

  <!--
    Only standard uap: capabilities are declared here. No rescap: namespace is
    imported. Add only the capabilities the application's feature set requires;
    request each one individually rather than using runFullTrust as a catch-all.
  -->
  <Capabilities>
    <Capability Name="internetClient" />
    <uap:Capability Name="userAccountInformation" />
    <!-- Add additional uap: or device: capabilities as needed — NOT rescap: -->
  </Capabilities>

</Package>
```

The `rescap:` XML namespace is intentionally absent from the `<Package>` root attributes and the `<Capabilities>` block. Each `<uap:Capability>` entry maps to a documented API surface with a defined broker boundary; none grant full-trust or elevation.

Source: https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root

## Fix recipes

### Recipe: Migrate Type 3426 custom action to Type 3072 with signature verification — addresses CWE-250

**Before (dangerous):**

```xml
<!--
  Type 3426 = 0x2 (exe) + 0x10 (installed file source) + 0x400 (in-script/deferred)
            + 0x800 absent (impersonate bit NOT set = impersonation ON)
  Runs an EXE from the installation directory under the installing user token
  during the deferred SYSTEM-context phase. User-writable source + elevated phase.
-->
<CustomAction Id="RunPostInstallConfig"
              FileKey="PostInstallConfig.exe"
              ExeCommand=""
              Execute="deferred"
              Return="check" />

<InstallExecuteSequence>
  <Custom Action="RunPostInstallConfig" After="InstallFiles">NOT Installed</Custom>
</InstallExecuteSequence>
```

**After (safe):**

```xml
<!--
  Migration: replace file-source EXE (type bits 0x02+0x10) with a binary-table
  DLL entry point (type bits 0x01+0x10 in the numeric model, but expressed in
  WiX as BinaryKey + DllEntry), run deferred with Impersonate="no" (NoImpersonate
  bit 0x800 set). This is the WiX spelling of Type 3072: the action runs under
  the Windows Installer service account (SYSTEM for per-machine) and its source
  is the embedded, signed binary table — not a user-writable directory.
-->

<!-- Step 1 (immediate): verify the binary's Authenticode signature before use. -->
<CustomAction Id="VerifyPostInstallBinarySignature"
              BinaryKey="PostInstallCA"
              DllEntry="VerifySignature"
              Execute="immediate"
              Return="check" />

<!-- Step 2 (deferred, SYSTEM, no impersonation): the main action. -->
<CustomAction Id="RunPostInstallConfig"
              BinaryKey="PostInstallCA"
              DllEntry="PostInstallConfigEntry"
              Execute="deferred"
              Impersonate="no"
              Return="check" />

<!-- Step 3 (rollback): undo whatever RunPostInstallConfig wrote on failure. -->
<CustomAction Id="RunPostInstallConfigRollback"
              BinaryKey="PostInstallCA"
              DllEntry="PostInstallConfigRollbackEntry"
              Execute="rollback"
              Impersonate="no"
              Return="check" />

<!--
  Binary table entry. PostInstallHelper.dll MUST be Authenticode-signed before
  embedding. Confirm with: signtool verify /pa /v PostInstallHelper.dll
-->
<Binary Id="PostInstallCA" SourceFile="$(var.PostInstallCA.TargetPath)" />

<InstallExecuteSequence>
  <Custom Action="VerifyPostInstallBinarySignature" Before="InstallInitialize">NOT Installed</Custom>
  <Custom Action="RunPostInstallConfigRollback" Before="RunPostInstallConfig">NOT Installed</Custom>
  <Custom Action="RunPostInstallConfig" After="InstallFiles">NOT Installed</Custom>
</InstallExecuteSequence>
```

Three changes close the vulnerability: (1) The EXE source is moved from the installation directory (user-writable) into the MSI Binary table, which is part of the signed MSI stream. (2) `Impersonate="no"` sets the NoImpersonate bit, ensuring the action runs under the Windows Installer service identity rather than reverting to the installing user token. (3) A `VerifySignature` immediate action confirms the embedded binary is Authenticode-signed before the deferred phase begins, so a tampered or unsigned binary table entry aborts the installation before any code runs.

Source: https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security

### Recipe: Pair a `Commit` custom action with its `Rollback` sibling — addresses CWE-459

**Before (dangerous — Commit with no Rollback):**

```xml
<!-- Commit action: runs after the transaction commits successfully.
     No Rollback sibling is defined. If a subsequent action fails,
     the service registration is never undone. -->
<CustomAction Id="RegisterWindowsService"
              BinaryKey="ServiceInstallerCA"
              DllEntry="RegisterServiceEntry"
              Execute="commit"
              Impersonate="no"
              Return="check" />

<InstallExecuteSequence>
  <Custom Action="RegisterWindowsService" After="InstallFinalize">NOT Installed</Custom>
</InstallExecuteSequence>
```

**After (safe — Commit paired with Rollback):**

```xml
<!-- Rollback sibling: undoes the service registration on failure.
     MUST be scheduled Before the primary action so that it is registered
     in the rollback script before the primary action fires. -->
<CustomAction Id="RegisterWindowsServiceRollback"
              BinaryKey="ServiceInstallerCA"
              DllEntry="UnregisterServiceEntry"
              Execute="rollback"
              Impersonate="no"
              Return="check" />

<!-- Primary Commit action: unchanged from before. -->
<CustomAction Id="RegisterWindowsService"
              BinaryKey="ServiceInstallerCA"
              DllEntry="RegisterServiceEntry"
              Execute="commit"
              Impersonate="no"
              Return="check" />

<InstallExecuteSequence>
  <!-- Rollback registered first so Windows Installer queues it before the primary. -->
  <Custom Action="RegisterWindowsServiceRollback" Before="RegisterWindowsService">NOT Installed</Custom>
  <Custom Action="RegisterWindowsService" After="InstallFinalize">NOT Installed</Custom>
</InstallExecuteSequence>
```

The rollback action must be scheduled `Before` its primary sibling in the sequence table. Windows Installer processes the rollback script in reverse order, so a rollback action scheduled before the primary is guaranteed to execute after the primary when rolling back. The `DllEntry` for the rollback action should call the inverse operation (e.g. `UnregisterServiceEntry` calls `DeleteService`), not just a no-op, to ensure the system returns to a clean pre-install state.

Source: https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-security

### Recipe: Replace `runFullTrust` with minimal `uap:Capability` entries — addresses CWE-250 / CWE-693

**Before (dangerous):**

```xml
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  IgnorableNamespaces="rescap">

  ...

  <Capabilities>
    <!-- runFullTrust disables the MSIX sandbox entirely. Remove this. -->
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>

</Package>
```

**After (safe — minimal uap: capabilities, no rescap:):**

```xml
<!--
  Migration steps:
  1. Enumerate the Win32 APIs, file paths, registry keys, and network resources
     the application actually accesses at runtime (use Process Monitor or
     Application Verifier to capture the access trace).
  2. Map each access to the narrowest uap: or device: capability that covers it.
     Reference: https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root
  3. Remove the rescap: namespace import from the <Package> root if no other
     rescap: capabilities remain.
  4. Re-test the application in the MSIX container with the new capability set;
     any access that the container blocks will surface as an access-denied error
     in the application log and in the Windows Event Log (AppModel-Runtime).
-->

<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  IgnorableNamespaces="uap">

  ...

  <Capabilities>
    <!-- Replace runFullTrust with only the capabilities the app actually needs. -->
    <Capability Name="internetClient" />
    <uap:Capability Name="userAccountInformation" />
    <!-- Add further uap: or device: entries as confirmed by the access trace. -->
    <!-- Do NOT add rescap:Capability Name="runFullTrust" or "allowElevation"
         unless a documented architectural requirement is approved in threat model review. -->
  </Capabilities>

</Package>
```

If the application uses a Win32 subsystem feature that genuinely requires full trust (e.g. a kernel driver companion, a COM out-of-process server, an SMB redirector), the correct pattern is to isolate that component as a separate packaged COM server or Windows service with its own tightly-scoped manifest rather than granting the entire application package full trust.

Source: https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/schema-root

## Version notes

- WiX 3.x uses `<Package InstallScope="perMachine|perUser">` on the `<Package>` element. WiX 4.x (released 2023) restructures this under `<Package Scope="perMachine|perUser">` with a different element hierarchy; grep patterns above match both `InstallScope=` (v3) and `Scope=` (v4).
- MSIX `rescap:` capabilities require Store submission justification review for apps distributed via the Microsoft Store. Apps distributed via sideload or enterprise deployment bypass that review gate, which is why source-level checks are essential.
- SmartScreen reputation is tied to the Authenticode certificate's thumbprint, not to the publisher name string. Certificate renewal (even for the same legal entity) resets the reputation counter to zero; EV certificates receive expedited reputation treatment. Plan certificate renewals with an overlap period during which both the old and new certificates sign artifacts simultaneously.
- `signtool verify /pa /v` is the authoritative check for Authenticode chain validity and timestamp presence. `certutil -dump` provides certificate subject field extraction for Publisher alignment checks. Both tools are part of the Windows SDK and are available in GitHub Actions runner images (`windows-latest`).
- The `<Package>` manifest schema version determines which `xmlns:uap` sub-namespaces are available. `uap` covers Windows 10 1507+; `uap2` through `uap18` gate progressively newer APIs. Always declare only the `xmlns:uap*` namespaces actually used in the file to avoid the validator accepting elements whose host OS version is unavailable on the declared `MinVersion`.

## Common false positives

- `Type="18"` matching a comment line or a documentation block inside a `.wxs` file — confirm the match is within a `<CustomAction>` element, not inside `<!-- ... -->` or a `<util:XmlFile>` value attribute.
- `InstallScope="perUser"` with `HKLM` matching because a `<RegistrySearch>` (read-only probe) references `HKLM` — read-only searches do not require write access; flag only `<RegistryValue Root="HKLM"` (write) or `<RemoveRegistryValue Root="HKLM"` (delete) entries.
- `<rescap:Capability Name="runFullTrust">` in a manifest that belongs to a test harness or a developer inner-loop package (identified by `Name` ending in `.Debug`, `.Dev`, or `_Test`, or located under a `test\`, `tests\`, or `tools\` directory) — confirm the manifest is a release distribution artifact before escalating.
- `Publisher="CN=` mismatch detection where the compared certificate is from a development self-signed cert used only for local sideload testing — flag only when the mismatch appears in a release signing script or CI workflow referencing the production certificate store.
- `MsiProcessMessage` grep matching inside a custom action that only calls `INSTALLMESSAGE_PROGRESS` (progress bar update) rather than `INSTALLMESSAGE_ACTIONDATA` with user-visible credential fields — confirm the message type constant before flagging as a credential-prompt risk.
