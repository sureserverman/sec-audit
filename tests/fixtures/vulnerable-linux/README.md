# vulnerable-linux fixture

Minimal Linux-desktop source tree used by the sec-audit Linux lane's
E2E assertions (Stage 2 Task 2.3 of v0.10.0).

## Intentional findings

- `systemd/vulnerableapp.service` — no ProtectSystem / PrivateTmp /
  NoNewPrivileges, `User=root`, `ReadWritePaths=/`,
  `StandardOutput=file:/var/log/vulnerableapp.log` (CWE-732, 377,
  250, 269, 532).
- `debian/control` — missing `Homepage:` and `Vcs-Git:` /
  `Vcs-Browser:` fields (Lintian tags).
- `debian/postinst` — no `set -e` (CWE-390), `chmod 4755` setuid
  (CWE-250), `curl http://... | sh` (CWE-494/829), writes to
  `/etc/cron.d/` with no matching postrm cleanup (CWE-459).
- `debian/rules` — silent `dh_auto_test` suppression (CWE-1295).
- NO ELF binary — exercises the `no-elf` clean-skip path for checksec.

## `.pipeline/`

- `systemd-analyze-report.txt` — synthetic `systemd-analyze security`
  text output with a 9.3 UNSAFE overall score and 13 per-directive
  rows.
- `lintian-report.json` — synthetic `lintian --output-format=json`
  output with 4 tags (no-homepage, missing-vcs-browser, maintainer-
  script-without-set-e, setuid-binary).
- `linux.jsonl` — expected linux-runner output: 5 systemd-analyze
  findings + 4 lintian findings + trailing status with
  `__linux_status__: "ok"` and `skipped: [{"tool": "checksec",
  "reason": "no-elf"}]`.

All synthetic — contract-check passes without systemd-analyze /
lintian / checksec installed on the runner host.


## `build/` (added 2026-09-03)

`build/vulnerableapp_0.1.0_all.deb` is a real package built by
`build/make-deb.sh` (dpkg-deb) from this fixture's own `postinst`, with a
setuid binary under `/usr/local`, a cron.d file not marked as a conffile,
and no copyright or changelog. lintian analyses BUILT packages only, so
this is what gives the linux lane's lintian coverage something to read; the
recording `.pipeline/linux.jsonl` is the engine's real output over it
(lintian 9 findings, systemd-analyze 11, checksec `no-elf`). It replaces a
hand-authored recording in a lintian JSON format no lintian emits.
