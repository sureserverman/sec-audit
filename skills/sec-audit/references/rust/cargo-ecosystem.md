# Rust / Cargo Ecosystem

## Source

- https://doc.rust-lang.org/cargo/reference/manifest.html — Cargo manifest reference (Cargo.toml fields)
- https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html — Dependency specification: git URLs, [patch], version requirements
- https://doc.rust-lang.org/cargo/reference/build-scripts.html — build.rs: capabilities and RCE surface
- https://doc.rust-lang.org/cargo/reference/profiles.html — Compilation profiles: overflow-checks, lto, panic, opt-level
- https://doc.rust-lang.org/cargo/reference/features.html — Feature flags: default features, conditional compilation, unsafe gating
- https://doc.rust-lang.org/cargo/reference/workspaces.html — Workspaces: workspace.dependencies, member inheritance, pin drift
- https://doc.rust-lang.org/cargo/reference/resolver.html — Dependency resolver v2: duplicate versions, feature unification
- https://rustsec.org/ — RustSec advisory database: published CVEs/advisories for Cargo crates
- https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html — OWASP Software Supply Chain Security Cheat Sheet

## Scope

In-scope: Rust projects using Cargo as their build system — binary crates, library crates, and multi-crate workspaces. Covers `Cargo.toml` manifest fields, `Cargo.lock` lockfile hygiene, `build.rs` build scripts, and Cargo-specific configuration (`.cargo/config.toml`). Out of scope: the `unsafe` keyword surface and FFI boundary risks (covered by `unsafe-surface.md`); invocation of Cargo-adjacent security tools such as `cargo-audit`, `cargo-deny`, and `cargo-geiger` (covered by `rust-tools.md`).

## Dangerous patterns (regex/AST hints)

### Git-URL dependency — CWE-494

- Why: A `git = "https://..."` dependency bypasses the crates.io registry; Cargo fetches the tip of the named branch (or a commit SHA if `rev` is given) without any checksum recorded in `Cargo.lock` that ties to a registry-audited artifact, leaving the build vulnerable to branch-force-push or repository takeover.
- Grep: `git\s*=\s*["']https?://`
- File globs: `**/Cargo.toml`
- Source: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html

### [patch] redirecting a published crate to a git or path source — CWE-494 / CWE-1104

- Why: A `[patch.crates-io]` stanza silently overrides the registry version of a crate for the entire workspace; any contributor or CI runner that pulls the repo will build the patched (potentially malicious or unreviewed) source instead of the published artifact, with no diff visible in dependency review tooling that only reads the version field.
- Grep: `^\[patch\..+\]`
- File globs: `**/Cargo.toml`
- Source: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html

### build.rs invoking external commands — CWE-78 / CWE-829

- Why: `build.rs` is executed by `cargo build` with full developer (or CI) privileges before the main crate compiles; a `Command::new("curl")`, `Command::new("sh")`, or similar call can download and execute arbitrary code at build time, turning a dependency compromise or malicious crate into immediate RCE on every developer's machine and in every CI pipeline.
- Grep: `Command::new\s*\(\s*["'](curl|wget|sh|bash|powershell|iex)["']`
- File globs: `**/build.rs`
- Source: https://doc.rust-lang.org/cargo/reference/build-scripts.html

### [profile.release] overflow-checks = false — CWE-190

- Why: Rust's default release profile already disables overflow checks for performance; explicitly setting `overflow-checks = false` documents intent to suppress panics on integer overflow in release builds, which in security-sensitive arithmetic (lengths, offsets, cryptographic counters) can produce silent wrap-around and exploitable logic errors.
- Grep: `overflow-checks\s*=\s*false`
- File globs: `**/Cargo.toml`
- Source: https://doc.rust-lang.org/cargo/reference/profiles.html

### Default-on feature flag gating unsafe or FFI code — CWE-710

- Why: A feature listed in `default = [...]` is activated for every downstream consumer that adds the crate without explicit `default-features = false`; if that feature enables `unsafe` blocks or pulls in a C FFI dependency, all consumers are silently opted into the expanded attack surface without awareness.
- Grep: `default\s*=\s*\[.*["'](unsafe|ffi|native|sys).*["']`
- File globs: `**/Cargo.toml`
- Source: https://doc.rust-lang.org/cargo/reference/features.html

### Unpinned wildcard version requirement on security-sensitive crate — CWE-1104 / CWE-829

- Why: A version requirement of `"*"` instructs Cargo to accept any published version of a crate, including a future malicious or CVE-carrying release; for cryptography, TLS, database, and async-runtime crates this is equivalent to an unconstrained supply-chain dependency.
- Grep: `^(ring|openssl|tokio|rustls|hyper|reqwest|sqlx|diesel|aws-lc-rs|boring)\s*=\s*["']\*["']`
- File globs: `**/Cargo.toml`
- Source: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html

### Workspace pin drift — CWE-1104

- Why: When `[workspace.dependencies]` declares a pinned version of a crate but one or more member `Cargo.toml` files redeclare the same crate with a different (looser or different) version constraint, Cargo's resolver may produce two distinct resolved versions of that crate in `Cargo.lock`; the unpinned instance will not match the workspace-level audit baseline and can quietly pull in a vulnerable version that `cargo audit` checks at the workspace pin miss.
- Grep: Detection is `Cargo.lock`-driven — search for a crate name appearing twice under `[[package]]` blocks with different `version` values; the pattern to grep in member `Cargo.toml` files is a dependency declaration that duplicates a key already present in `[workspace.dependencies]` without `workspace = true`.
- File globs: `**/Cargo.lock`, `**/Cargo.toml`
- Source: https://doc.rust-lang.org/cargo/reference/workspaces.html

## Secure patterns

Safely-pinned `Cargo.toml` using registry-only dependencies, explicit version requirements, and no default unsafe features:

```toml
[package]
name    = "my-service"
version = "0.1.0"
edition = "2021"

[dependencies]
# Registry-only: no git = / path = entries.
# Version requirements use caret (^) or tilde (~) with a minimum patch that
# post-dates any known advisory in the RustSec DB.
tokio    = { version = "1.38", default-features = false, features = ["rt-multi-thread", "macros"] }
reqwest  = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
rustls   = { version = "0.23", default-features = false, features = ["ring"] }
sqlx     = { version = "0.8",  default-features = false, features = ["postgres", "runtime-tokio"] }

[profile.release]
# Retain overflow-checks in release to catch integer wrap-around at runtime.
overflow-checks = true
# Thin LTO is a safe default; "fat" LTO is acceptable but increases build time.
lto             = "thin"
# "abort" on panic minimises binary size and eliminates unwinding gadgets.
panic           = "abort"
```

- All dependencies are resolved from crates.io with version constraints that exclude `*`.
- `default-features = false` with an explicit `features` list ensures no hidden feature-flag expansion.
- `overflow-checks = true` is explicit, overriding the release-profile default of `false`.

Source: https://doc.rust-lang.org/cargo/reference/manifest.html

Minimal `build.rs` that performs only pure-Rust work and emits no network calls:

```rust
// build.rs — pure-Rust codegen; no Command::new, no network I/O.
use std::{env, fs, path::Path};

fn main() {
    // Re-run only when the proto definition changes, not on every build.
    println!("cargo:rerun-if-changed=proto/service.proto");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set by Cargo");
    let dest = Path::new(&out_dir).join("generated.rs");

    // All generation logic is pure Rust — no shell-out, no network fetch.
    let generated = generate_bindings("proto/service.proto");
    fs::write(&dest, generated).expect("failed to write generated bindings");
}

fn generate_bindings(proto: &str) -> String {
    // Placeholder: real impl uses a pure-Rust parser such as `prost-build`.
    format!("// generated from {proto}\n")
}
```

- No `std::process::Command` calls.
- `cargo:rerun-if-changed` limits rebuild triggers to relevant source files.
- All file I/O is within `OUT_DIR`, which Cargo owns and sandboxes from the source tree.

Source: https://doc.rust-lang.org/cargo/reference/build-scripts.html

## Fix recipes

### Recipe: Pin a git-URL dependency to a registry version — addresses CWE-494

**Before (dangerous):**

```toml
[dependencies]
# Fetches tip of main; no integrity guarantee, not auditable via cargo-audit.
serde_with = { git = "https://github.com/jonasbb/serde_with", branch = "main" }
```

**After (safe):**

```toml
[dependencies]
# Registry version with a caret constraint; Cargo.lock records the exact
# resolved version and its checksum, enabling cargo-audit coverage.
serde_with = "3.9"
```

Verify the current advisory-clean release via `cargo audit` after switching. If upstream functionality not yet in a published release is genuinely required, pin to an exact commit SHA (`rev = "abc1234"`) as an interim measure and open a tracking issue to switch to a registry release once one is cut.

Source: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html

### Recipe: Remove or document a [patch.crates-io] redirection — addresses CWE-494 / CWE-1104

**Before (dangerous):**

```toml
# Cargo.toml (workspace root)
[patch.crates-io]
# Silently replaces the published crate with an unreviewed local fork.
hyper = { git = "https://github.com/internal-fork/hyper", branch = "fix-timeouts" }
```

**After (safe — patch removed, upstream version used):**

```toml
[dependencies]
# Use the published release that includes the upstream fix.
hyper = "1.4"
```

**After (safe — patch retained with mandatory justification):**

```toml
[patch.crates-io]
# TEMPORARY: replaces hyper 1.3 pending merge of timeout fix in
# https://github.com/hyperium/hyper/pull/99999 (target: hyper 1.4.1).
# Remove this stanza once hyper >= 1.4.1 is published to crates.io.
# Reviewed and approved by: security@example.com on 2026-04-22.
hyper = { git = "https://github.com/hyperium/hyper", rev = "d3adb33f" }
```

Any retained `[patch]` stanza must reference the upstream PR or issue that will resolve the need, pin to an exact `rev` (not a branch), and carry a review sign-off comment. Add a `cargo deny` rule to alert when the patched crate's published version satisfies the original constraint so the stanza can be dropped.

Source: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html

### Recipe: Replace Command::new("curl") in build.rs with a vendored file — addresses CWE-78 / CWE-829

**Before (dangerous):**

```rust
// build.rs — downloads a header at build time; runs arbitrary network code
// with developer/CI privileges on every `cargo build`.
use std::process::Command;

fn main() {
    Command::new("curl")
        .args(["-sSfL", "https://example.com/schema.json", "-o", "src/schema.json"])
        .status()
        .expect("curl failed");
    println!("cargo:rerun-if-changed=build.rs");
}
```

**After (safe — vendored file, no network call in build.rs):**

```rust
// build.rs — no network I/O; schema is vendored into the repository.
fn main() {
    // The schema is committed at vendor/schema.json and updated deliberately
    // via a separate `scripts/update-schema.sh` run outside of `cargo build`.
    println!("cargo:rerun-if-changed=vendor/schema.json");
}
```

```
# scripts/update-schema.sh — run manually or in a dedicated CI job, NOT during cargo build.
#!/usr/bin/env bash
set -euo pipefail
curl -sSfL "https://example.com/schema.json" -o vendor/schema.json
# Verify the download against a pinned SHA-256 before committing.
echo "expected-sha256  vendor/schema.json" | sha256sum --check
```

Commit `vendor/schema.json` into the repository. If the file must be fetched at build time and vendoring is genuinely impractical, use a `[build-dependencies]` entry for `reqwest` (with `blocking` feature and `rustls-tls`) so the fetch is expressed in auditable Rust code rather than a shell-out — but prefer vendoring for supply-chain auditability.

Source: https://doc.rust-lang.org/cargo/reference/build-scripts.html

## Version notes

- `resolver = "2"` (Cargo's feature resolver v2) is the default for workspaces and 2021-edition packages. It avoids unintentional feature unification across dependencies, which is particularly relevant for features that gate `unsafe` or FFI code. Projects still on resolver v1 (`edition = "2018"` without an explicit `resolver` key) should migrate; see the resolver reference for behavioral differences.
- `overflow-checks` in `[profile.release]` defaults to `false` in all Cargo versions; setting it to `true` has a measurable but typically small runtime cost and is advisable for any crate doing security-sensitive arithmetic. The `[profile.dev]` default is `true`.
- `cargo audit` (from the `cargo-audit` tool maintained by the RustSec project) consumes `Cargo.lock` and cross-references the RustSec advisory database; it does not process `[patch]` overrides or git dependencies beyond checking the resolved crate name and version recorded in the lockfile.
- Workspace `[workspace.dependencies]` inheritance (`dep.workspace = true`) was stabilised in Rust 1.64; projects targeting older toolchains cannot use it and are more prone to pin drift.

## Common false positives

- `git = "..."` with `rev = "<full 40-char SHA>"` — lower severity than a branch or tag reference because the specific commit is immutable; still flag for supply-chain auditability (no crates.io checksum, not covered by `cargo audit`), but confidence is medium rather than high.
- `^\[patch\..+\]` matching `[patch.crates-io]` in a crate's own test fixtures or example workspace — confirm the file is a workspace root or a production manifest, not a test harness; patch stanzas in test-only workspaces (`[workspace] members = ["tests/*"]`) have limited blast radius.
- `overflow-checks\s*=\s*false` in `[profile.bench]` or `[profile.test]` — benchmarks intentionally disable checks to measure real-world performance; flag only in `[profile.release]` or custom release-derived profiles.
- `default\s*=\s*\[.*"ffi".*\]` matching a crate where `ffi` is the only way to call into a required system library (e.g. an OS keychain binding) — the feature itself is not avoidable; flag the lack of `default-features = false` at the consuming crate level instead.
- `Command::new` in `build.rs` calling local compiled tools (e.g. `Command::new(env::var("PROTOC").unwrap())`) — the risk is lower when the binary path comes from an environment variable controlled by the developer rather than a hardcoded name resolved via `$PATH`; still worth noting in a review, but severity is informational rather than high.
