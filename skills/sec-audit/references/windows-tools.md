# windows-tools

<!--
    Tool-lane reference for sec-audit's Desktop Windows lane
    (v0.12.0+). Consumed by the `windows-runner` sub-agent. Documents
    canonical invocations, upstream output → sec-expert finding-schema
    maps, and the three-state-plus-skipped-list sentinel contract for
    three Windows-targeted static-analysis CLIs.
-->

## Source

- https://github.com/microsoft/binskim — BinSkim canonical (Microsoft PE static-analysis scanner, SARIF output)
- https://github.com/mtrojnar/osslsigncode — osslsigncode canonical (cross-platform Authenticode signer/verifier)
- https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck — Sysinternals sigcheck docs (Windows-only)
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format — PE format reference
- https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools — SignTool / certutil context
- https://cwe.mitre.org/

## Scope

In-scope: the three tools invoked by `windows-runner` (the Desktop
Windows lane sub-agent added in v0.12.0) — `binskim`, `osslsigncode`,
and `sigcheck`. Two of the three (`binskim`, `osslsigncode`) run
cross-platform — unlike v0.9's iOS lane where the Apple-binary
subset is macOS-host-gated, the Windows lane produces useful output
on Linux CI. `sigcheck` is Windows-only and clean-skips with
`requires-windows-host` (the THIRD host-OS-gated skip reason in the
plugin, after v0.9's `requires-macos-host` and v0.10's
`requires-systemd-host`).

Out of scope: live-system Windows auditing (registry / WinRM / SMB /
Defender policy — needs host access); .NET source code static
analysis (covered by the existing SAST lane via semgrep); COM
server / kernel driver review.

## Canonical invocations

### binskim

- Install: `dotnet tool install --global Microsoft.CodeAnalysis.BinSkim`
  (requires .NET SDK 6.0+). The `dotnet` runtime is cross-platform
  (Linux/macOS/Windows). Can also be pulled as a standalone release
  binary from the BinSkim GitHub releases page.
- Invocation (SARIF JSON output):
  ```bash
  binskim analyze "$path_to_pe" \
      --output "$TMPDIR/windows-runner-binskim.sarif" \
      --sarif-output-version Current \
      --level Error Warning \
      2> "$TMPDIR/windows-runner-binskim.stderr"
  rc_bs=$?
  ```
- Output: SARIF v2.1.0 JSON. The runner parses `runs[].results[]`;
  each result has `ruleId`, `level`, `message.text`,
  `locations[].physicalLocation.artifactLocation.uri`,
  `locations[].physicalLocation.region.startLine`.
- Tool behaviour: exit code 0 even when findings are present. Treat
  any exit with a valid SARIF file as success.
- Primary source: https://github.com/microsoft/binskim (README +
  `docs/UserGuide.md`).

Source: https://github.com/microsoft/binskim

### osslsigncode

- Install: `apt install osslsigncode` (Debian/Ubuntu);
  `brew install osslsigncode` (macOS); Windows builds on GitHub
  releases. Cross-platform C binary linked against OpenSSL.
- Invocation (verify an existing signature):
  ```bash
  osslsigncode verify \
      -in "$path_to_pe" \
      2> "$TMPDIR/windows-runner-osslsigncode-$(basename "$path_to_pe").stderr"
  rc_os=$?
  ```
- Output: stderr text with structured lines —
  `Signature verification: ok` / `Signature verification: failed`;
  `Timestamp: ok` / `Timestamp: none`; `Number of signers: N`;
  `Subject: CN=<subject>`; `Message digest algorithm: sha256`.
  Parse with regex against these key strings.
- Tool behaviour: exit 0 on successful verification, non-zero on
  verification failure. Non-zero is NOT a crash; it's a finding
  signal.
- Primary source: https://github.com/mtrojnar/osslsigncode

Source: https://github.com/mtrojnar/osslsigncode

### sigcheck  — Windows-host-only

- Install: ships as part of the Sysinternals Suite
  (https://learn.microsoft.com/en-us/sysinternals/). Windows-only
  binary. Non-Windows runners CANNOT execute it — clean-skip with
  `reason: "requires-windows-host"`.
- Invocation (detailed Authenticode info + catalog-signed status):
  ```powershell
  sigcheck.exe -a -q -h -c "$path_to_pe" > "$TMPDIR\\windows-runner-sigcheck.csv"
  ```
  The `-c` flag requests CSV output; `-a` extended; `-h` hashes;
  `-q` suppresses banner.
- Output: CSV with columns for Path, Verified, Date, Publisher,
  Description, Product, Product Version, File Version, MachineType,
  MD5, SHA1, PESHA1, PESHA256, SHA256, IMP.
- Primary source: https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck

Source: https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck

## Output-field mapping

Every finding produced by `windows-runner` carries:

- `origin: "windows"`
- `tool: "binskim" | "osslsigncode" | "sigcheck"`
- `reference: "windows-tools.md"`

### binskim → sec-audit finding

| SARIF field                                | sec-audit field                 |
|--------------------------------------------|----------------------------------|
| `"binskim:" + ruleId`                       | `id`                             |
| `level` remap: `"error"` → HIGH, `"warning"` → MEDIUM, `"note"`/`"none"` → LOW | `severity` |
| Per-rule CWE map (BinSkim BA-series rules): `BA2001 LoadImageAboveFourGigabyteAddress` → CWE-693; `BA2002 DoNotIncorporateVulnerableDependencies` → CWE-1104; `BA2005 DoNotShipVulnerableBinaries` → CWE-1104; `BA2006 BuildWithSecureTools` → CWE-693; `BA2007 EnableCriticalCompilerWarnings` → CWE-693; `BA2008 EnableControlFlowGuard` → CWE-693; `BA2009 EnableAddressSpaceLayoutRandomization` → CWE-693; `BA2010 DoNotMarkImportsSectionAsExecutable` → CWE-119; `BA2011 EnableStackProtection` → CWE-121; `BA2012 DoNotModifyStackProtectionCookie` → CWE-121; `BA2013 InitializeStackProtection` → CWE-121; `BA2014 DoNotDisableStackProtectionForFunctions` → CWE-121; `BA2015 EnableHighEntropyVirtualAddresses` → CWE-693; `BA2016 MarkImageAsNXCompatible` → CWE-119; `BA2018 EnableSafeSEH` → CWE-693; `BA2021 DoNotMarkWritableSectionsAsExecutable` → CWE-266; `BA2024 EnableSpectreMitigations` → CWE-200; `BA2025 EnableShadowStack` → CWE-121. Unmapped rule → null | `cwe` |
| `message.text` (fallback to `ruleId`)       | `title`                          |
| `locations[0].physicalLocation.artifactLocation.uri` | `file`                 |
| `locations[0].physicalLocation.region.startLine` or `0` | `line`               |
| `message.text` (second use) or `help.text`  | `evidence`                       |
| BinSkim rule doc URL `"https://github.com/microsoft/binskim/blob/main/docs/" + ruleId` OR `null` | `reference_url` |
| `help.text` field when present, else null   | `fix_recipe`                     |
| `"high"` (BinSkim rules are deterministic PE-flag matches) | `confidence`     |

### osslsigncode → sec-audit finding

The tool is single-invocation-per-PE; emit findings based on parsed
stderr signals:

| signal                                      | emitted finding                  |
|---------------------------------------------|----------------------------------|
| `Signature verification: failed`            | HIGH, `id: "osslsigncode:signature-invalid"`, CWE-347 Improper Verification of Cryptographic Signature |
| stderr lacks `Signature verification: ok` (no signature present) | HIGH, `id: "osslsigncode:unsigned"`, CWE-693 |
| `Timestamp: none` (present but no timestamp) | MEDIUM, `id: "osslsigncode:no-timestamp"`, CWE-324 |
| `Message digest algorithm: sha1`            | MEDIUM, `id: "osslsigncode:sha1-digest"`, CWE-327 |

`file` is the PE basename; `line` is 0; `evidence` is the verbatim
stderr line; `reference_url` is null; `fix_recipe` synthesised per
finding type (e.g. `"Re-sign the binary with SignTool + /tr <TSA URL> + /fd sha256"`);
`confidence: "high"`.

### sigcheck → sec-audit finding

Windows-only. Parse the CSV line for the target PE. Emit:

| CSV condition                               | emitted finding                  |
|---------------------------------------------|----------------------------------|
| `Verified` column = `Unsigned`              | HIGH, `id: "sigcheck:unsigned"`, CWE-693 |
| `Verified` = `Signed (catalog)` but runner was invoked with expected Authenticode sig | MEDIUM, `id: "sigcheck:catalog-only"`, CWE-295 |
| `Verified` starts with `Signed (expired certificate)` | HIGH, `id: "sigcheck:expired"`, CWE-324 |
| `Publisher` = empty string on signed file   | MEDIUM, `id: "sigcheck:no-publisher"`, CWE-295 |

`file` is the PE basename; `line` 0; `evidence` is the verbatim CSV
row; `confidence: "high"`.

## Degrade rules

The `windows-runner` agent follows the three-state sentinel contract
consistent with the other lanes. `__windows_status__` ∈
{`"ok"`, `"partial"`, `"unavailable"`}. The skipped-list vocabulary
recognises these reasons (some inherited, two new):

- `"requires-windows-host"` — `sigcheck` requires a Windows host.
  Non-Windows runners clean-skip. **NEW in v0.12.** THIRD host-OS-
  gated reason in the plugin, after `requires-macos-host` (v0.9) and
  `requires-systemd-host` (v0.10).
- `"no-pe"` — no `.exe`/`.dll`/`.msi`/`.msix`/`.sys` under target.
  binskim/osslsigncode/sigcheck all need a PE artifact; source-only
  reviews (`.csproj` + `.wxs` + manifests but no compiled output)
  clean-skip. **NEW in v0.12.** Target-shape parallel to
  `no-apk`/`no-bundle`/`no-pkg`/`no-elf`.
- `"tool-missing"` — the binary is absent when host + target
  preconditions held.

Canonical status-line shapes:

```json
{"__windows_status__": "ok", "tools": ["binskim","osslsigncode"], "runs": 2, "findings": 5, "skipped": [{"tool": "sigcheck", "reason": "requires-windows-host"}]}
```

```json
{"__windows_status__": "unavailable", "tools": [], "skipped": [{"tool": "binskim", "reason": "tool-missing"}, {"tool": "osslsigncode", "reason": "tool-missing"}, {"tool": "sigcheck", "reason": "requires-windows-host"}]}
```

## Version pins

- `binskim` ≥ 4.3.1 (SARIF v2.1.0 output, BA2024-BA2025 Spectre +
  shadow-stack rules). Pinned 2026-04.
- `osslsigncode` ≥ 2.6 (stable stderr format with
  `Message digest algorithm` line). Pinned 2026-04.
- `sigcheck` ≥ 2.92 (supports `-c` CSV output). Pinned 2026-04.

## Common false positives

- **binskim** BA2024 (Spectre mitigations) raises false positives on
  CI-compiled assemblies that were built by older toolchains without
  `/Qspectre`; the finding is accurate but the fix is toolchain
  upgrade, not code-level change. Triager should flag `confidence:
  "medium"` when the binary date predates the rule introduction.
- **osslsigncode** occasionally reports `Signature verification:
  failed` on catalog-signed Windows drivers where the signature
  lives in the OS catalog rather than the PE. Pair with sigcheck
  output on a Windows host for disambiguation.
- **sigcheck** `Publisher: <empty>` is expected for OS-shipped
  binaries signed by the Microsoft Root Authority chain; triager
  must ignore for `%WinDir%\System32` paths.

## CI notes

The runner writes all outputs to `$TMPDIR`. Build targets
(`dotnet build`, `msbuild`, `wix build`) are explicitly OUT of scope
for the runner — it reviews already-built artifacts, not build
pipelines. Cross-reference with `windows-authenticode.md` for
signing-recipe guidance beyond tool-produced findings.
