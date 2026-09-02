# vulnerable-windows fixture

Windows desktop project used by the sec-audit Windows lane's E2E assertions
and executed for real by `tests/lane-live-gate.sh`.

## Intentional findings

- `src/VulnerableWin.csproj` — .NET project (triggers `windows` inventory
  detection); pinned old `Newtonsoft.Json 11.0.2` (NuGet ecosystem).
- `installer/installer.wxs` — WiX installer with `CustomAction` Type 3426
  (CWE-250) and a `Commit` custom action with no matching `Rollback`
  (CWE-459).
- `src/Package.appxmanifest` — MSIX manifest requesting `runFullTrust` and
  `allowElevation` (CWE-250/693).
- `policies/AppLockerPolicy.xml` — AppLocker policy allowing `.exe` execution
  from `%OSDRIVE%\Users\*` (CWE-732) and a wildcard `PublisherName="*"` rule
  (CWE-693).
- `build/t64.exe` — a real PE: pip's `distlib` script launcher
  (`pip/_vendor/distlib/t64.exe`, PSF licence, 108 KB), unmodified. binskim
  reports `BA2015` (not high-entropy-ASLR compatible); osslsigncode reports
  it unsigned.
- `build/t64-selfsigned-sha1.exe` — the same launcher signed with a
  throwaway self-signed certificate (`osslsigncode sign -h sha1`, no
  timestamp). osslsigncode reports `signature-invalid` (self-signed),
  `no-timestamp` and `sha1-digest`.

Until 2026-09-02 the fixture carried NO PE and its README said so — while its
recording claimed three binskim and two osslsigncode findings. Both PEs are
tracked despite the blanket `build/` ignore (see `.gitignore`).

## `.pipeline/`

Every file is a **capture of a real run** (binskim 4.4.9.11, osslsigncode
2.14, 2026-09-02) replacing synthetic ones:

- `binskim-report.sarif` — `binskim analyze build/t64.exe -o … --sarif-output-version Current`,
  with the staging path rewritten to `file:///fixture/vulnerable-windows/`.
  Note `message.id` + `arguments` instead of `message.text`.
- `osslsigncode-report.txt` — `osslsigncode verify -in` over both PEs,
  stdout and stderr interleaved, exit codes recorded.
- `windows.jsonl` — the engine's output: 2 binskim + 4 osslsigncode findings
  and a `partial` sentinel with sigcheck skipped `requires-windows-host` (the
  Linux/macOS shape; on Windows sigcheck runs or skips `tool-missing`).

Regenerate with
`python3 scripts/secaudit/runner.py windows tests/fixtures/vulnerable-windows`
(a staged copy is not required — no Windows tool ignores `fixtures` paths).
