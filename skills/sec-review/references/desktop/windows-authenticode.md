# Windows Authenticode Signing, Timestamping, and Certificate-Chain Hygiene

## Source

- https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools — Microsoft Cryptography Tools: SignTool, certutil, and MakeCert reference documentation covering all flags, certificate-store interaction, and timestamp-server options
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format — PE Format reference: Authenticode signature embedding layout in the PE optional-header Certificate Table, used to understand what signtool verifies and what binskim inspects
- https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview — Microsoft Defender SmartScreen overview: reputation-based blocking policy, how certificate EV status and accumulated download counts affect the SmartScreen reputation score
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/ — Windows Defender Application Control (WDAC): signing requirements for binaries trusted by WDAC policies, including EV-certificate and WHQL requirements for kernel-mode code
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html — OWASP Authentication Cheat Sheet: credential and secret-management guidance referenced for certificate key storage and PFX hygiene

## Scope

In scope: Windows Authenticode signing discipline for PE binaries (.exe, .dll, .msi, .sys) — covering SignTool and PowerShell `Set-AuthenticodeSignature` invocation hygiene, RFC 3161 trusted timestamping, digest-algorithm selection (SHA-1 vs SHA-256), dual-signing append semantics, certificate type (OV vs EV) requirements for kernel drivers and SmartScreen reputation, PFX/P12 key-material storage and CI secret management, and certificate-chain validation. Out of scope: AppLocker and WDAC policy authoring (`windows-applocker.md`); MSI/MSIX packaging, MSIX signing with the Windows SDK (`windows-packaging.md`); IIS TLS certificate management (`webservers/iis.md`); kernel driver co-signing policy review and WHQL submission (live-host territory).

## Dangerous patterns (regex/AST hints)

### Unsigned PE binary in release distribution — CWE-693

- Why: A PE binary shipped without any Authenticode signature carries no integrity guarantee. Windows SmartScreen blocks or warns on unsigned downloads; WDAC policies that require signed code will refuse to execute the binary; kernel-mode drivers without a valid signature are rejected outright by the kernel integrity check on 64-bit Windows. Absence of signing is detectable at CI time via `signtool verify /pa` or the open-source `binskim` / `osslsigncode` tools. The pattern here flags release pipelines that contain no `signtool sign` invocation at all.
- Grep: `signtool\s+sign` (flag its *absence* in `.yml`/`.ps1`/`.bat` release-job files; any release workflow lacking this call warrants review)
- File globs: `**/*.yml`, `**/*.yaml`, `**/*.ps1`, `**/*.bat`, `**/*.cmd`, `**/build*.xml`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### `signtool sign` without `/tr` timestamp-server flag — CWE-324

- Why: An Authenticode signature without an RFC 3161 countersignature (timestamp) is only valid while the signing certificate is within its validity period. OV certificates have a maximum validity of 3 years; EV certificates 1–2 years. When the certificate expires, Windows will report the signature as invalid on any policy that checks revocation or chain validity — the binary effectively becomes unsigned at that point, even though it was correctly signed at build time. A timestamped signature embeds a cryptographically-bound assertion from a trusted timestamp authority (TSA) recording the exact time the signature was applied; the signature remains valid after certificate expiry because the TSA proves the certificate was valid at signing time.
- Grep: `signtool\s+sign\b(?![^\n]*/tr\s)`
- File globs: `**/*.yml`, `**/*.yaml`, `**/*.ps1`, `**/*.bat`, `**/*.cmd`, `**/build*.xml`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### `signtool sign /fd sha1` — SHA-1 digest deprecated — CWE-327

- Why: The Microsoft Root Certificate Program deprecated SHA-1 Authenticode signatures for code signing. Windows 10 and later versions reject SHA-1-only Authenticode signatures for 64-bit PE binaries, and SmartScreen treats them as untrusted regardless of certificate status. SHA-1 has known collision attacks (SHAttered, 2017); a signature over a SHA-1 digest of a PE binary can in principle be forged against a crafted collision binary. Only SHA-256 (`/fd sha256`) or SHA-384/SHA-512 digests are acceptable for new release artifacts.
- Grep: `signtool\s+sign[^\n]*/fd\s+sha1\b`
- File globs: `**/*.yml`, `**/*.yaml`, `**/*.ps1`, `**/*.bat`, `**/*.cmd`, `**/build*.xml`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### Dual-sign (SHA-1 + SHA-256) second call missing `/as` append flag — CWE-693 (HINT)

- Why: Supporting older Windows versions (Vista/7 without KB3033929) requires dual-signing: first apply a SHA-1 signature, then append a SHA-256 signature. The second `signtool sign` invocation *must* include `/as` (append signature) — without it, the second call replaces the first signature rather than appending, resulting in a single SHA-256 signature only. The binary then fails SHA-1 verification on legacy hosts. This is a correctness concern rather than a security vulnerability, but it often surfaces during legacy-compatibility audits; flag as HINT and request reviewer follow-up.
- Grep: Multiple `signtool\s+sign` calls on the same target file where the second invocation does not include `/as`
- File globs: `**/*.yml`, `**/*.yaml`, `**/*.ps1`, `**/*.bat`, `**/*.cmd`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### Test certificate or self-signed PFX referenced in a release pipeline — CWE-295 / CWE-798

- Why: `MakeCert`-generated certificates and self-signed PFX files are useful during development but must never appear in a release signing pipeline. A binary signed with a test certificate chains to a root that is not trusted by Windows, so SmartScreen blocks it and WDAC policies reject it. More critically, test-certificate PFX files are frequently committed to source control with trivial or empty passwords; an attacker who obtains the PFX can sign arbitrary malware that appears to originate from the affected project's build system.
- Grep: `(?i)(TestCert|DevCert|dev-cert|SelfSigned|makecert)[^\n]*\.pfx`
- File globs: `**/*.yml`, `**/*.yaml`, `**/*.ps1`, `**/*.bat`, `**/*.cmd`, `**/build*.xml`, `**/*.pfx`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### PFX or P12 private-key file committed to the repository — CWE-798

- Why: A `.pfx` or `.p12` file bundles the certificate's private key and is the sole credential needed to produce Authenticode signatures indistinguishable from legitimate releases. If this file is tracked in git — even in a private repository — it is exposed to every person with repository read access, every CI runner with a checkout step, and any future history-scraping attacker who obtains a repository backup. Passphrase protection provides limited defence: PFX encryption uses PKCS#12, and weak passphrases are trivially brute-forced with tools such as `pfx2john` + hashcat. The key must live in an HSM, a TPM-backed Windows certificate store, or a secret manager (Azure Key Vault, GitHub Encrypted Secrets) — not in the repository tree.
- Grep: Presence of `*.pfx` or `*.p12` files tracked by git (`git ls-files "*.pfx" "*.p12"`)
- File globs: `**/*.pfx`, `**/*.p12`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### Cross-signing kernel driver without an EV certificate — CWE-693

- Why: Since Windows 10 version 1607 (Anniversary Update), Microsoft requires that kernel-mode drivers submitted for signing have been signed with an Extended Validation (EV) code-signing certificate before being submitted to the Hardware Dev Center (Sysdev) dashboard. Drivers signed only with an OV (Organisation Validation) certificate are refused by the kernel's Code Integrity check on systems with Secure Boot enabled and on Windows 10/11 1607+ regardless of Secure Boot state. Additionally, SmartScreen assigns a lower reputation score to OV-signed binaries regardless of age, which affects user-land installers that bundle `.sys` files.
- Grep: `.sys` files present in release output directories combined with `signtool sign` invocations where the certificate subject or thumbprint does not reference an EV-labelled identity
- File globs: `**/*.sys`, `**/*.yml`, `**/*.ps1`, `**/*.bat`
- Source: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/

### Certificate private key stored in a file with an inline password — CWE-522

- Why: `signtool sign /f path\to\cert.pfx /p MyPassword` passes the PFX decryption password on the command line. This exposes the credential in process-argument lists visible to other users on the same host (`wmic process`, Task Manager, `/proc`-equivalent tools), in CI log output if the runner echoes commands, and in shell history files. The safe alternatives are: (a) import the PFX into the Windows certificate store once (protected by the machine or user DPAPI key) and reference it by subject name (`/n "Common Name"`) or thumbprint, so no password is required at sign time; or (b) use an HSM or Azure Key Vault-backed signing service so the private key never leaves protected hardware.
- Grep: `signtool[^\n]*/p\s+\S+`
- File globs: `**/*.yml`, `**/*.yaml`, `**/*.ps1`, `**/*.bat`, `**/*.cmd`
- Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

## Secure patterns

Canonical `signtool` invocation for a SHA-256 Authenticode signature with RFC 3161 trusted timestamp. The certificate is referenced by subject-name match from the Windows certificate store — no PFX file or inline password is needed at sign time.

```bat
REM Sign with SHA-256 digest; timestamp via DigiCert RFC 3161 TSA;
REM /td sha256 sets the timestamp-digest algorithm (must match /fd);
REM /a selects the best certificate in the store automatically.
signtool.exe sign ^
    /fd sha256 ^
    /tr http://timestamp.digicert.com ^
    /td sha256 ^
    /a ^
    "path\to\MyApp.exe"

REM Verify the resulting signature (use /pa for Authenticode policy):
signtool.exe verify /pa /v "path\to\MyApp.exe"
```

Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

PowerShell equivalent using `Set-AuthenticodeSignature`. The certificate is loaded from the Windows certificate store by thumbprint; the private key stays in the store (or HSM CSP registered to the store) — no PFX export is required. `-IncludeChain NotRoot` embeds the intermediate CA chain in the signature so chain-building succeeds on hosts that do not have the intermediate cached.

```powershell
# Load the signing certificate from the current-user personal store by thumbprint.
# Replace <THUMBPRINT> with the 40-character hex thumbprint of the EV or OV cert.
$cert = Get-ChildItem -Path Cert:\CurrentUser\My\<THUMBPRINT>

# Sign with SHA-256 and an RFC 3161 timestamp; embed the intermediate chain.
Set-AuthenticodeSignature `
    -FilePath        "path\to\MyApp.exe" `
    -Certificate     $cert `
    -TimestampServer "http://timestamp.digicert.com" `
    -IncludeChain    NotRoot `
    -HashAlgorithm   SHA256

# Verify:
Get-AuthenticodeSignature -FilePath "path\to\MyApp.exe" |
    Select-Object -Property Status, StatusMessage, TimeStamperCertificate
```

Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

## Fix recipes

### Recipe: Add `/tr` and `/td sha256` to an existing signtool command — addresses CWE-324

**Before (dangerous — no timestamp; signature becomes invalid on certificate expiry):**

```bat
signtool.exe sign /fd sha256 /a "dist\MyApp.exe"
```

**After (safe — RFC 3161 countersignature binds signature to sign-time, survives certificate expiry):**

```bat
signtool.exe sign ^
    /fd sha256 ^
    /tr http://timestamp.digicert.com ^
    /td sha256 ^
    /a ^
    "dist\MyApp.exe"
```

The `/tr` flag specifies the RFC 3161 timestamp authority URL. `/td sha256` sets the hash algorithm used inside the timestamp token itself; omitting it defaults to SHA-1 inside the TSA response, which is rejected by strict validators. Both flags must be present together.

Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### Recipe: Migrate from MakeCert test certificate to a store-backed EV certificate — addresses CWE-295 / CWE-798

**Before (dangerous — PFX generated by MakeCert, committed to repo, password inline):**

```bat
REM build\sign-release.bat — test certificate committed as certs\TestCertificate.pfx
signtool.exe sign ^
    /fd sha256 ^
    /f certs\TestCertificate.pfx ^
    /p P@ssw0rd1 ^
    /tr http://timestamp.digicert.com ^
    /td sha256 ^
    "dist\MyApp.exe"
```

**After (safe — EV certificate imported into Windows cert store; no file, no password on command line):**

```bat
REM Pre-requisite (done once on the build machine or CI agent, not in the script):
REM   Import the EV PFX into the machine store:
REM   certutil -importpfx -p "<password>" -f "<path_to_ev_cert.pfx>"
REM   Then discard or vault the PFX — it must not remain on disk.

REM build\sign-release.bat — references cert by subject name; no file or password needed.
signtool.exe sign ^
    /fd sha256 ^
    /n "Example Corp EV Code Signing" ^
    /tr http://timestamp.digicert.com ^
    /td sha256 ^
    "dist\MyApp.exe"
```

Remove `certs\TestCertificate.pfx` (and any `.p12`) from the repository. If the file was ever committed, purge it from git history with `git filter-repo --path certs/TestCertificate.pfx --invert-paths` and rotate the certificate immediately — treat the private key as compromised.

Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

### Recipe: Remove committed PFX from repo and reference it via Azure Key Vault / CI secret manager — addresses CWE-798

**Before (dangerous — PFX committed to repository, loaded from working tree at build time):**

```yaml
# .github/workflows/release.yml (excerpt)
- name: Sign release binary
  run: |
    signtool.exe sign /fd sha256 /f certs\signing.pfx /p "${{ secrets.PFX_PASS }}" `
      /tr http://timestamp.digicert.com /td sha256 dist\MyApp.exe
```

Even with the password in a secret, the PFX file itself is in the repository and is checked out onto every runner.

**After (safe — PFX stored in Azure Key Vault; short-lived token used at sign time via AzureSignTool):**

```yaml
# .github/workflows/release.yml (excerpt)
- name: Sign via Azure Key Vault (AzureSignTool)
  env:
    # AZURE_VAULT_URI, AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET
    # are stored as encrypted repository secrets; none are written to disk.
    AZURE_VAULT_URI:      ${{ secrets.AZURE_VAULT_URI }}
    AZURE_CLIENT_ID:      ${{ secrets.AZURE_CLIENT_ID }}
    AZURE_TENANT_ID:      ${{ secrets.AZURE_TENANT_ID }}
    AZURE_CLIENT_SECRET:  ${{ secrets.AZURE_CLIENT_SECRET }}
  run: |
    # AzureSignTool calls Key Vault's sign API; the private key never leaves the HSM.
    AzureSignTool sign `
      --azure-key-vault-url       "$env:AZURE_VAULT_URI" `
      --azure-key-vault-client-id "$env:AZURE_CLIENT_ID" `
      --azure-key-vault-tenant-id "$env:AZURE_TENANT_ID" `
      --azure-key-vault-client-secret "$env:AZURE_CLIENT_SECRET" `
      --azure-key-vault-certificate "MyCodeSigningCert" `
      --file-digest sha256 `
      --timestamp-rfc3161 http://timestamp.digicert.com `
      --timestamp-digest sha256 `
      dist\MyApp.exe
```

The `certs\signing.pfx` file must be removed from the repository tree and purged from git history. The Azure Key Vault certificate's private key is generated inside the HSM and is non-exportable; the CI identity (service principal) should be granted only the `sign` and `verify` Key Vault permissions — not `get` or `download` of the raw key material.

Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

## Version notes

- SHA-1 Authenticode rejection: Windows 10 (all current servicing branches) rejects SHA-1-only code-signing signatures for 64-bit PE files. Windows 7 and 8.1 with KB3033929 also enforce this. New releases must use `/fd sha256`; SHA-1 should only appear as the *first* signature in a legacy dual-sign pair for genuine Vista/7-RTM compatibility requirements.
- Kernel driver EV requirement: mandatory since Windows 10 version 1607 (build 14393) for drivers loaded on systems with Secure Boot enabled. Drivers submitted to the Hardware Dev Center must carry an EV signature before submission; the portal itself enforces this.
- Certificate maximum validity: CA/Browser Forum Baseline Requirements cap OV code-signing certificates at 3 years and EV certificates at 2 years (as of June 2023 ballot SC-62). Timestamp all signatures; do not rely on certificate validity period as an operational control.
- `MakeCert.exe` was removed from the Windows SDK in version 8.1 and is no longer available as a supported tool. Pipelines referencing `MakeCert` are certainly using legacy infrastructure and should be migrated to proper CA-issued certificates.
- SmartScreen reputation: A newly-issued EV certificate carries an immediate positive reputation signal with SmartScreen; OV certificates must accumulate download volume before SmartScreen stops issuing warnings. EV certificates are therefore strongly preferred for release artifacts that will be distributed to the public.
- AzureSignTool is an open-source community tool (not a Microsoft first-party SDK tool) but is the established pattern for Key Vault-backed CI signing; verify the version pinned in CI against its published release checksums.

## Common false positives

- `signtool sign` invocation without `/tr` inside a test or debug build job — confirm the job is gated on a non-release branch or a `Debug` configuration environment variable; if so, the missing timestamp is expected (test signatures are ephemeral) and is not a finding.
- `*.pfx` file present in the repository under a path like `test/fixtures/` or `tools/test-certs/` — verify via `git log --all --oneline -- "*.pfx"` that the file predates any release pipeline integration and is only used in unit tests that exercise certificate-parsing code; if the file's CN contains "Test" or "Dev" and it is referenced only from test-only scripts, downgrade to INFO.
- Multiple `signtool sign` invocations on the same binary where the second lacks `/as` — if both invocations use the same digest algorithm (`/fd sha256` only, no SHA-1 pair), the dual-sign `/as` pattern does not apply; this is a single-algorithm re-sign, which is unusual but not a vulnerability; request context before flagging.
- `signtool sign /f cert.pfx /p ...` in a script that is explicitly a local-developer convenience wrapper (e.g. `dev-sign.bat`, `local-sign.ps1`) and is not reachable from any CI pipeline — the inline password is still a poor practice, but the risk surface is limited to the developer's own machine; flag as LOW rather than HIGH and recommend migrating to the cert-store pattern.
- `signtool verify /pa` exit-code checks that appear to fail in CI — `signtool verify` returns exit code 1 for any signature issue, including an expired timestamp TSA certificate in the chain (which affects the TSA's own cert, not the binary's signature). Distinguish between a genuinely invalid signature and a TSA-chain validation warning by examining the `signtool` verbose output for `Error information: "The certificate is expired."` vs. `"The digital signature of the object did not verify."`.
