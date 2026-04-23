# AppLocker and Windows Defender Application Control (WDAC) Policy XML Hygiene

## Source

- https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview — Microsoft Docs: AppLocker overview
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/ — Microsoft Docs: Windows Defender Application Control (WDAC) overview
- https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools — Microsoft Docs: Windows Cryptography Tools (signtool, makecert, certutil — cross-reference for signing policy)
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — OWASP Authorization Cheat Sheet

## Scope

In scope: static review of AppLocker policy XML files (exported via `Get-AppLockerPolicy -Effective -Xml` or stored under GPO `SYSVOL`) and WDAC Code Integrity policy XML files (produced by `New-CIPolicy` / `ConvertFrom-CIPolicy`) — covering rule types (path, publisher, hash), policy mode (audit vs. enforced), rule specificity (wildcard subjects), and policy-file NTFS ACL expectations. Also in scope: absence of policy signing markers (`SIPolicy_signed.bin`, `<SigningScenarios>` element completeness). Out of scope: SmartScreen reputation-based controls (covered by `windows-packaging.md` in the release-artifact context); Authenticode signing operations such as `signtool sign` invocations (covered by `windows-authenticode.md`); Windows kernel-driver signing policy and HVCI/KMCI enforcement (live-host configuration territory outside static XML review).

## Dangerous patterns (regex/AST hints)

### AppLocker path rule allowing execution from user-writable directories — CWE-732

- Why: A `<FilePathRule>` whose `Path` attribute resolves to a directory the current user can write (e.g. `%OSDRIVE%\Users\*` or `%USERPROFILE%\*`) allows any binary — including attacker-placed executables — to run without a publisher or hash check. AppLocker path rules grant execution to any file under the matched path regardless of signature. An attacker who can write to `C:\Users\victim\Downloads\` can drop a payload and execute it within policy.
- Grep: `<FilePathRule[^>]*Path="(%OSDRIVE%\\Users|%USERPROFILE%|%LOCALAPPDATA%|%APPDATA%)`
- File globs: `**/*.xml`
- Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview

### AppLocker path rule granting execution from `%TEMP%` or `AppData\Local\Temp` — CWE-732

- Why: Temp directories are writable by the user account and frequently targeted by malware droppers, browser-based exploits, and installer chains that write to temp before execution. Allowing execution from `%TEMP%` (which expands to `%LOCALAPPDATA%\Temp`) effectively creates an unrestricted execution path for any file that transiently lands in the temp tree, regardless of how it arrived there.
- Grep: `Path="(%TEMP%|.*Local\\\\Temp|.*\\\\AppData\\\\Local\\\\Temp)`
- File globs: `**/*.xml`
- Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview

### WDAC policy in Audit-only mode in production — CWE-693

- Why: `<Option>Enabled:Audit Mode</Option>` causes the Code Integrity engine to log violations to the `Microsoft-Windows-CodeIntegrity/Operational` event log but does not block execution. In production this means the policy provides no enforcement: unsigned or untrusted binaries run freely, and the only evidence of policy violations is a log entry. Audit mode is appropriate during policy development and tuning; leaving it enabled in production negates the entire protection goal of application control.
- Grep: `Enabled:Audit Mode`
- File globs: `**/*.xml`
- Source: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/

### AppLocker publisher rule with wildcard subject — CWE-693

- Why: A `<FilePublisherRule>` with `PublisherName="*"` allows any binary signed by any publisher — including self-signed certificates or certificates from any publicly trusted CA — to execute, provided the other conditions (product name, binary name) also match. When combined with wildcard `ProductName="*"` and `BinaryName="*"`, the rule is functionally equivalent to a path rule that allows all signed binaries, granting execution to any attacker-controlled binary that carries a valid (not necessarily trusted) signature.
- Grep: `PublisherName="\*"|ProductName="\*"[^/]*/>[^<]*BinaryName="\*"`
- File globs: `**/*.xml`
- Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview

### AppLocker hash rule without rotation plan — CWE-693

- Why: A `<FileHashRule>` pins execution to the exact SHA-256 (or older SHA-1) hash of a specific binary version. When the application is legitimately updated, the new binary hash does not match and execution is blocked. Operational pressure to restore functionality commonly results in AppLocker being temporarily disabled, set to audit mode, or patched with a catch-all path rule — all of which permanently weaken the policy. Hash rules are appropriate only for controlled executables that change infrequently, and must be accompanied by a hash-rotation procedure. Flag as MEDIUM; the reviewer must confirm whether a documented update procedure exists for each pinned hash.
- Grep: `<FileHashRule`
- File globs: `**/*.xml`
- Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview

### AppLocker or WDAC policy file without restrictive NTFS ACL — CWE-732

- Why: AppLocker policy XML stored under `SYSVOL` or exported to a local path should be owned by `SYSTEM` or `Administrators` with the `Users` group granted read-only access at most. A policy file writable by a standard user or by `Everyone` can be replaced with an attacker-authored policy that permits arbitrary execution. This cannot be detected from the XML content alone — the reviewer must verify the NTFS ACL via `icacls <policy-file>` or `Get-Acl` on the host. Document as a pattern requiring host inspection; treat any path outside `SYSVOL` or `C:\Windows\System32\CodeIntegrity\` as higher risk.
- Grep: (ACL-side detection only; no XML grep applicable — see File globs for candidate paths)
- File globs: `**/*.xml`, `C:\Windows\System32\GroupPolicy\**\*.xml`, `C:\Windows\SYSVOL\**\*.xml`
- Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview

### WDAC unsigned policy in production — CWE-693

- Why: A WDAC Code Integrity policy that has not been signed (i.e. deployed as a raw `.xml`-derived `.bin` rather than a signed `SIPolicy_signed.bin`) can be replaced, removed, or modified by any local Administrator. An attacker who achieves Administrator-level access can deploy a permissive policy or remove enforcement entirely before executing malicious code. The `<SigningScenarios>` element must be present and the deployed policy must be paired with a signed binary (`ConvertFrom-CIPolicy` output submitted to a signing pipeline). Absence of a `SIPolicy_signed.bin` sibling alongside the policy `.bin` is a static indicator that signing was not completed.
- Grep: (absence signal) check that `<SigningScenarios>` is present in the XML AND that a `*_signed.bin` sibling exists alongside the `.bin` policy file; flag when either is absent
- File globs: `**/*.xml`, `**/*.bin`
- Source: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/

### WDAC rule trusting deprecated or revoked CA roots — CWE-693

- Why: WDAC signer-based rules reference certificate thumbprints or subject strings of trusted root CAs. Older trust anchors — for example, legacy Symantec Class 3 roots, VeriSign G1–G4 roots, or other CAs that have been publicly compromised or retired — may still appear in policies migrated from older Windows versions. A binary signed by a certificate chaining to a deprecated or revoked root would satisfy the WDAC signer rule even if the CA is no longer trustworthy. Detection requires cross-referencing subject strings in `<CertRoot>` or `<CertPublisher>` elements against a current CA revocation database; flag for reviewer awareness that this check is out of scope for automated static review and must be performed manually against Microsoft's CTL or the Trusted Root Program participant list.
- Grep: `<CertRoot[^>]*Value="|<CertPublisher[^>]*Value="` — extract thumbprints and cross-reference against known deprecated roots
- File globs: `**/*.xml`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

## Secure patterns

Minimal AppLocker XML policy allowlisting only publisher-signed binaries from `C:\Program Files\` and `C:\Windows\`, with an explicit deny-all default and no path or hash rules:

```xml
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">

  <!-- EXE rules: allow signed binaries from Program Files and Windows only -->
  <RuleCollection Type="Exe" EnforcementMode="Enabled">

    <!-- Allow: binaries signed by Microsoft from Windows directories -->
    <FilePublisherRule
        Id="a1000001-0000-0000-0000-000000000001"
        Name="Allow signed Windows OS binaries"
        Description="Allows binaries under C:\Windows signed by Microsoft"
        UserOrGroupSid="S-1-1-0"
        Action="Allow">
      <Conditions>
        <FilePublisherCondition
            PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
            ProductName="*"
            BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
      <Exceptions>
        <!-- No exceptions: all Microsoft-signed binaries from Windows dirs are permitted -->
      </Exceptions>
    </FilePublisherRule>

    <!-- Allow: binaries signed by a specific internal publisher from Program Files -->
    <FilePublisherRule
        Id="a1000002-0000-0000-0000-000000000002"
        Name="Allow Contoso-signed application binaries"
        Description="Allows binaries under C:\Program Files signed by Contoso"
        UserOrGroupSid="S-1-1-0"
        Action="Allow">
      <Conditions>
        <FilePublisherCondition
            PublisherName="O=Contoso, L=Redmond, S=Washington, C=US"
            ProductName="*"
            BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

    <!-- Deny: execution from user-writable locations (belt-and-suspenders) -->
    <FilePathRule
        Id="a1000003-0000-0000-0000-000000000003"
        Name="Deny execution from user profile tree"
        Description="Explicitly denies execution from %OSDRIVE%\Users"
        UserOrGroupSid="S-1-1-0"
        Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*"/>
      </Conditions>
    </FilePathRule>

  </RuleCollection>

  <!-- Script, MSI, DLL, Appx rule collections should follow the same publisher-only pattern -->

</AppLockerPolicy>
```

`EnforcementMode="Enabled"` on the `<RuleCollection>` element means this is an enforced (not audit) ruleset. No `FilePathRule` with `Action="Allow"` points to a user-writable path. Publisher conditions use a fully qualified distinguished name rather than a wildcard `PublisherName`. The explicit deny path rule at the end provides defense-in-depth even if a publisher condition is inadvertently broadened.

Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview

WDAC Code Integrity policy with `Enabled:Unsigned System Integrity Policy` removed (enforcing signed-policy deployment) and signer-based rules referencing the Microsoft Root Authority:

```xml
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">

  <VersionEx>10.0.0.0</VersionEx>
  <PolicyID>{12345678-1234-1234-1234-123456789abc}</PolicyID>
  <BasePolicyID>{12345678-1234-1234-1234-123456789abc}</BasePolicyID>

  <Rules>
    <!-- Enforce mode: Audit Mode option is intentionally ABSENT -->
    <!-- Unsigned System Integrity Policy option is intentionally ABSENT -->
    <Rule>
      <Option>Enabled:UMCI</Option>
    </Rule>
    <Rule>
      <Option>Enabled:Boot Menu Protection</Option>
    </Rule>
    <Rule>
      <Option>Required:Enforce Store Applications</Option>
    </Rule>
  </Rules>

  <EKUs/>

  <FileRules/>

  <Signers>
    <!-- Trust only Microsoft Root Authority for kernel and user-mode binaries -->
    <Signer ID="ID_SIGNER_MSFT_ROOT" Name="Microsoft Root Authority">
      <CertRoot Type="TBS" Value="4AAABB40D20AB4C8EB9E5E4DEB56ED2D28CE25B8"/>
    </Signer>
    <!-- Internal code-signing CA for organization-produced binaries -->
    <Signer ID="ID_SIGNER_CONTOSO_CA" Name="Contoso Internal CA">
      <CertRoot Type="TBS" Value="<!-- insert CA TBS hash from certutil -dump ca.cer -->"/>
      <CertPublisher Value="Contoso Code Signing"/>
    </Signer>
  </Signers>

  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="Kernel mode">
      <ProductSigners>
        <AllowedSigner SignerId="ID_SIGNER_MSFT_ROOT"/>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User mode">
      <ProductSigners>
        <AllowedSigner SignerId="ID_SIGNER_MSFT_ROOT"/>
        <AllowedSigner SignerId="ID_SIGNER_CONTOSO_CA"/>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>

  <UpdatePolicySigners>
    <!-- Only the Contoso CA may update this policy; prevents Admin-level policy swap -->
    <UpdatePolicySigner SignerId="ID_SIGNER_CONTOSO_CA"/>
  </UpdatePolicySigners>

  <CiSigners>
    <CiSigner SignerId="ID_SIGNER_CONTOSO_CA"/>
  </CiSigners>

  <HvciOptions>0</HvciOptions>

</SiPolicy>
```

`Enabled:Audit Mode` is absent — the policy is enforced. `Enabled:Unsigned System Integrity Policy` is absent — the policy must be signed before deployment via `ConvertFrom-CIPolicy` followed by `signtool sign` with the Contoso CA key. The `<UpdatePolicySigners>` block restricts who can replace the policy, preventing an Administrator from swapping to a permissive policy without the private signing key.

Source: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/

## Fix recipes

### Recipe: Remove `%OSDRIVE%\Users\*` path rule and replace with a publisher rule — addresses CWE-732

**Before (dangerous):**

```xml
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <FilePathRule
      Id="b0000001-0000-0000-0000-000000000001"
      Name="Allow execution from user profile"
      Description=""
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
    <Conditions>
      <FilePathCondition Path="%OSDRIVE%\Users\*"/>
    </Conditions>
  </FilePathRule>
</RuleCollection>
```

**After (safe):**

```xml
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <!-- Removed: FilePathRule allowing %OSDRIVE%\Users\* -->

  <!-- Replaced with: publisher rule scoped to the specific vendor -->
  <FilePublisherRule
      Id="b0000002-0000-0000-0000-000000000002"
      Name="Allow Contoso-signed binaries regardless of install path"
      Description="Replaces broad path rule; requires valid publisher signature"
      UserOrGroupSid="S-1-1-0"
      Action="Allow">
    <Conditions>
      <FilePublisherCondition
          PublisherName="O=Contoso, L=Redmond, S=Washington, C=US"
          ProductName="ContosoCLI"
          BinaryName="*">
        <BinaryVersionRange LowSection="1.0.0.0" HighSection="*"/>
      </FilePublisherCondition>
    </Conditions>
  </FilePublisherRule>

  <!-- Belt-and-suspenders: explicit deny for user-writable paths -->
  <FilePathRule
      Id="b0000003-0000-0000-0000-000000000003"
      Name="Deny execution from user profile tree"
      Description=""
      UserOrGroupSid="S-1-1-0"
      Action="Deny">
    <Conditions>
      <FilePathCondition Path="%OSDRIVE%\Users\*"/>
    </Conditions>
  </FilePathRule>
</RuleCollection>
```

The path-based allow rule is removed entirely. The replacement publisher rule requires the executable to carry a valid Authenticode signature from the named publisher; an attacker-placed unsigned binary in the user profile tree cannot satisfy it. The explicit deny path rule is added as defense-in-depth. `ProductName` and `BinaryName` should be narrowed further to the specific product and binary name where known.

Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview

### Recipe: Switch WDAC policy from Audit Mode to Enforced — addresses CWE-693

**Before (dangerous):**

```xml
<Rules>
  <Rule>
    <Option>Enabled:Audit Mode</Option>
  </Rule>
  <Rule>
    <Option>Enabled:UMCI</Option>
  </Rule>
  <Rule>
    <Option>Enabled:Unsigned System Integrity Policy</Option>
  </Rule>
</Rules>
```

**After (safe):**

```xml
<Rules>
  <!-- Enabled:Audit Mode removed — policy now enforces -->
  <Rule>
    <Option>Enabled:UMCI</Option>
  </Rule>
  <!-- Enabled:Unsigned System Integrity Policy removed — policy must be signed -->
</Rules>
```

Remove the `<Option>Enabled:Audit Mode</Option>` element. Before doing so, review the `Microsoft-Windows-CodeIntegrity/Operational` event log (Event IDs 3076/3077 for audit violations) to confirm no legitimate binaries will be blocked. After removing the option, regenerate the `.bin` policy file with `ConvertFrom-CIPolicy`, sign it with `signtool`, and deploy via MDM or Group Policy. Also remove `Enabled:Unsigned System Integrity Policy` so the signed policy cannot be replaced without the signing key.

Source: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/

### Recipe: Narrow `PublisherName="*"` to a specific publisher DN — addresses CWE-693

**Before (dangerous):**

```xml
<FilePublisherRule
    Id="c0000001-0000-0000-0000-000000000001"
    Name="Allow any signed binary"
    Description=""
    UserOrGroupSid="S-1-1-0"
    Action="Allow">
  <Conditions>
    <FilePublisherCondition
        PublisherName="*"
        ProductName="*"
        BinaryName="*">
      <BinaryVersionRange LowSection="*" HighSection="*"/>
    </FilePublisherCondition>
  </Conditions>
</FilePublisherRule>
```

**After (safe):**

```xml
<FilePublisherRule
    Id="c0000002-0000-0000-0000-000000000002"
    Name="Allow Contoso-signed binaries only"
    Description="Narrowed from wildcard publisher to specific issuer DN"
    UserOrGroupSid="S-1-1-0"
    Action="Allow">
  <Conditions>
    <FilePublisherCondition
        PublisherName="O=Contoso, L=Redmond, S=Washington, C=US"
        ProductName="ContosoCLI"
        BinaryName="contoso-cli.exe">
      <BinaryVersionRange LowSection="2.0.0.0" HighSection="*"/>
    </FilePublisherCondition>
  </Conditions>
</FilePublisherRule>
```

Replace `PublisherName="*"` with the full X.509 distinguished name of the issuing code-signing certificate, obtained by running `Get-AuthenticodeSignature <binary> | Select-Object -ExpandProperty SignerCertificate | Format-List Subject` against a known-good binary. Set `ProductName` and `BinaryName` to the specific product and executable name. Set `LowSection` on `BinaryVersionRange` to the earliest version that should be trusted rather than `*`. One rule per vendor or product line is preferable to a single broadened rule.

Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview

## Version notes

- AppLocker is available on Windows 10/11 Enterprise and Education editions and on Windows Server 2008 R2 and later. It is not available on Windows 10/11 Home or Pro SKUs. Verify the target SKU before treating AppLocker findings as actionable on endpoints — WDAC is the recommended replacement on modern (Windows 11) managed fleets.
- WDAC is available on all Windows 10 and 11 editions (including Home/Pro), which is a key advantage over AppLocker. WDAC policies deployed via MDM (`ApplicationControl` CSP) require Windows 10 1903+ for full multiple-active-policy support.
- The `<ThresholdExtensions>` element (introduced in Windows 10 1511) and `<AuditOptions>` (Windows 10 1903+) are required for certain advanced WDAC features; policies generated by `New-CIPolicy` on older PowerShell / RSAT versions may omit these. Verify the policy was generated on a Windows 10 1903+ or Windows Server 2022 system.
- AppLocker hash rules using SHA-1 (the pre-Windows 8 default) should be flagged unconditionally; SHA-1 is deprecated for code-integrity purposes. Confirm `<FileHashRule>` elements use `Type="SHA256"`.
- WDAC policies signed with certificates chaining to the Microsoft Third Party UEFI CA are subject to Secure Boot enforcement; changes to such policies require a reboot with the new signed `.bin` in place before enforcement takes effect.
- On Windows 11 24H2+, the `ConfigCI` PowerShell module's `New-CIPolicy` cmdlet emits policies with `<ThresholdExtensions>` and XML namespace `urn:schemas-microsoft-com:sipolicy` by default. Policies generated on earlier OS versions may need manual namespace alignment before the WDAC engine on 24H2+ will parse them correctly.

## Common false positives

- `<FilePathRule>` with `Path="%PROGRAMFILES%\*"` or `Path="%WINDIR%\*"` — these are standard allow-path rules targeting non-user-writable system directories; they are the intended pattern, not a finding. Confirm by verifying the path expansion does not resolve into a user-writable subtree on the target OS version.
- `<FileHashRule>` for a small set of well-known utilities (e.g. a pinned version of `sigcheck.exe`) in a controlled tooling context — hash rules can be appropriate for strictly versioned, infrequently updated audit tools. Downgrade to INFORMATIONAL and note the reviewer-must-check caveat about rotation procedures.
- `Enabled:Audit Mode` in a policy file stored under a path that contains `test`, `staging`, or `pilot` — audit mode is expected during policy development and rollout pilots; confirm deployment target before escalating.
- `PublisherName="*"` in a rule with `Action="Deny"` — a wildcard deny publisher rule is a broad block, not a broad allow; it is a restrictive pattern. Confirm the `Action` attribute before treating a wildcard publisher condition as a finding.
- `<CertRoot>` thumbprints matching Microsoft-issued intermediate CAs — these are expected in WDAC policies that use the built-in Microsoft Windows Production PCA or Microsoft UEFI CA trust anchors; they are not an indication of a deprecated root unless the specific thumbprint is confirmed revoked or retired via the Microsoft Trusted Root Program.
- `<FilePublisherCondition BinaryName="*">` without a wildcard on `PublisherName` — a wildcard binary name scoped to a specific publisher is an acceptable pattern when the intent is to trust all executables from that vendor; evaluate in combination with `PublisherName` specificity, not in isolation.
