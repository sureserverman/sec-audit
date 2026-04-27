# vulnerable-windows fixture

Minimal Windows desktop project used by the sec-audit Windows lane's
E2E assertions (Stage 2 Task 2.3 of v0.12.0).

## Intentional findings

- `src/VulnerableWin.csproj` — .NET project (triggers `windows`
  inventory detection); pinned old `Newtonsoft.Json 11.0.2` (NuGet
  ecosystem).
- `installer/installer.wxs` — WiX installer with `CustomAction`
  Type 3426 (SDL-disallowed deferred+impersonate+exe-from-installed-
  file pattern, CWE-250) AND a `Commit` custom action with no
  matching `Rollback` (CWE-459).
- `src/Package.appxmanifest` — MSIX manifest requesting `runFullTrust`
  and `allowElevation` rescap capabilities (CWE-250/693).
- `policies/AppLockerPolicy.xml` — AppLocker policy allowing `.exe`
  execution from `%OSDRIVE%\Users\*` (CWE-732) and a wildcard
  `PublisherName="*"` rule (CWE-693).
- NO compiled PE artifacts — exercises the `no-pe` clean-skip path
  for all three Windows tools on any host (binskim + osslsigncode
  can't run without a PE; sigcheck is host-gated separately).

## `.pipeline/`

- `binskim-report.sarif` — synthetic SARIF 2.1.0 output with three
  BinSkim results (BA2009 ASLR missing → CWE-693; BA2008 CFG
  missing → CWE-693; BA2011 stack-protection gap → CWE-121).
- `osslsigncode-report.txt` — synthetic stderr text signalling
  unsigned binary + no-timestamp.
- `windows.jsonl` — expected windows-runner output: 3 binskim + 2
  osslsigncode findings + trailing `__windows_status__: "ok"` with
  `skipped: [{"tool": "sigcheck", "reason": "requires-windows-host"}]`
  (the canonical Linux-CI shape — sigcheck clean-skipped via the
  THIRD host-OS gate added in v0.12).

All `.pipeline/*` files are synthetic so contract-check passes
without binskim / osslsigncode / sigcheck installed. On a Windows
host with binskim+osslsigncode+sigcheck installed AND a compiled
`VulnerableWin.exe`, the skipped list would be empty (or contain
only `tool-missing` entries for any genuinely absent tools).
