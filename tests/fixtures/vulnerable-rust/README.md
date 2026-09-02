# vulnerable-rust fixture

Minimal Cargo project used by the sec-audit Rust lane's E2E assertions and by
`tests/lane-live-gate.sh`, which runs the lane against it for real.

## Intentional findings

- `Cargo.toml`: `time = "0.1.43"` (resolves to 0.1.45) triggers
  RUSTSEC-2020-0071 (CVE-2020-26235, potential segfault) in both cargo-audit
  and cargo-deny's `vulnerability` diagnostic; `profile.release` with
  `overflow-checks = false` triggers cargo-ecosystem.md's CWE-190 pattern.
- `build.rs`: `Command::new("curl")` and `Command::new("sh")` trigger the
  build-script RCE patterns (CWE-78 / CWE-829).
- `src/main.rs`: `mem::transmute` (CWE-843), `mem::forget` (CWE-401),
  null-pointer deref (CWE-476), manual `unsafe impl Send` (CWE-362) — all from
  `unsafe-surface.md` — and enough `unsafe` for cargo-geiger to count.

There is deliberately **no git-URL dependency**. Until 2026-09-02 the fixture
pinned `serde_gremlin = { git = "https://example.com/gremlin.git" }` to
exercise the CWE-494 reference pattern; every cargo tool resolves the
dependency graph before analysing it, so that one line made cargo-audit and
cargo-geiger fail before they scanned anything, and the failure was hidden
until the engine learned to report failed tools. The graph must resolve from
crates.io alone. `Cargo.lock` is committed (un-ignored for `tests/fixtures/`
in `.gitignore`) so cargo-audit has a lockfile to read and the run is
reproducible; cargo-geiger builds into the runner's scratch dir via
`CARGO_TARGET_DIR`, never into this tree.

## `.pipeline/`

Every file here is a **capture of a real run** (cargo-audit 0.22.1,
cargo-deny 0.19.4, cargo-geiger 0.13.0 on 2026-09-02), not a synthetic
stand-in. They replaced hand-authored versions whose shapes matched nothing
the tools emit (cargo-deny codes `B0001`/`A0003`/`S0001` do not exist; the
real diagnostics nest under `fields`, use word codes such as `vulnerability`,
and go to stderr).

- `cargo-audit-report.json` — `cargo audit --json --file Cargo.lock`.
- `cargo-deny-report.json` — stderr of `cargo deny --format json check`
  (no `deny.toml`, so the default config's licence rejections appear; the
  lane filters those out).
- `cargo-geiger-report.json` — `cargo geiger --output-format Json`, with the
  root package's absolute `file://` source path rewritten to
  `file:///fixture/...`.
- `rust.jsonl` — the engine's output for this fixture: 1 cargo-audit,
  1 cargo-deny and 3 cargo-geiger findings plus the `__rust_status__: "ok"`
  sentinel. Regenerate with
  `python3 scripts/secaudit/runner.py rust tests/fixtures/vulnerable-rust`.

The same three captures live in `tests/fixtures/raw-tool-output/rust/` for
the engine parity test (`tests/script-runner.sh rust`).
