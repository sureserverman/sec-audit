// Intentionally-vulnerable Rust source for fixture purposes.
// Demonstrates unsafe-surface patterns the sec-expert + rust-runner
// lanes are expected to flag.

use std::mem;

fn main() {
    // CWE-843: transmute between incompatible layouts.
    let bytes: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    let n: u32 = unsafe { mem::transmute(bytes) };
    println!("n = {}", n);

    // CWE-401: mem::forget leaks the destructor.
    let leaky = Box::new(vec![1u8; 1024]);
    mem::forget(leaky);

    // CWE-476: FFI-style raw pointer deref without null check.
    let p: *const u32 = std::ptr::null();
    let _v = unsafe { *p }; // would segfault at runtime
}

// CWE-362: manual unsafe Send impl on a non-thread-safe state.
struct NotThreadSafe(*const u8);
unsafe impl Send for NotThreadSafe {}
