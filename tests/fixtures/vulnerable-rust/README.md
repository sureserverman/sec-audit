# vulnerable-rust fixture

Minimal Cargo project used by the sec-audit Rust lane's E2E assertions
(Stage 2 Task 2.3 of v0.7.0).

## Intentional findings

- `Cargo.toml`: `time = "0.1.43"` triggers RUSTSEC-2020-0071 (CVE-2020-26235,
  CWE-476 potential segfault); git-URL dep `serde_gremlin` triggers
  cargo-ecosystem.md's CWE-494 / CWE-1104 patterns; `profile.release`
  with `overflow-checks = false` triggers the CWE-190 pattern.
- `build.rs`: `Command::new("curl")` and `Command::new("sh")` trigger
  the build-script RCE patterns (CWE-78 / CWE-829).
- `src/main.rs`: `mem::transmute` (CWE-843), `mem::forget` (CWE-401),
  null-pointer deref (CWE-476), manual `unsafe impl Send`
  (CWE-362) — all from `unsafe-surface.md`.

## `.pipeline/`

- `cargo-audit-report.json` — synthetic canonical `cargo audit --json`
  output flagging the time 0.1.43 advisory with its CVE alias.
- `cargo-deny-report.json` — synthetic per-line JSON diagnostics
  (advisory / ban / source checks).
- `cargo-geiger-report.json` — synthetic per-package unsafe counts.
- `rust.jsonl` — the JSONL the rust-runner agent should emit after
  consuming the three upstream reports per the mapping in
  `rust-tools.md`. Ends with a `__rust_status__: "ok"` summary line.
  Note that cargo-vet is intentionally NOT in the `tools` list here —
  the fixture exercises the `partial`-state handling (cargo-vet
  skipped-or-not-installed) AS IF the runner consumed it at ok state;
  for a strictly ok run, a vet report would be added.

All `.pipeline/*.json` files are synthetic fixtures, not output from a
live tool run, so the contract tests run without cargo installed.
