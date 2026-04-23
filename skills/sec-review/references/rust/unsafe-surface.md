# Rust Unsafe-Code Surface

## Source

- https://doc.rust-lang.org/nomicon/ — Rustonomicon: The Dark Arts of Unsafe Rust (official guide)
- https://doc.rust-lang.org/nomicon/transmutes.html — Rustonomicon: Transmutes
- https://doc.rust-lang.org/nomicon/ffi.html — Rustonomicon: Working with FFI
- https://doc.rust-lang.org/nomicon/send-and-sync.html — Rustonomicon: Send and Sync
- https://doc.rust-lang.org/std/mem/fn.transmute.html — std::mem::transmute (standard library docs)
- https://doc.rust-lang.org/std/mem/fn.forget.html — std::mem::forget (standard library docs)
- https://doc.rust-lang.org/std/pin/index.html — std::pin (Pin docs)
- https://rust-lang.github.io/rust-clippy/master/index.html — Clippy master lint index

## Scope

In scope: the `unsafe` keyword surface in Rust — transmutes between incompatible layouts, raw pointer arithmetic, FFI boundary handling (`extern "C"` functions and `#[no_mangle]` exports), manual `Send`/`Sync` implementations, `std::mem::forget` and `ManuallyDrop` destructor leakage, `Pin` misuse, and alignment/layout hazards from pointer casts. Out of scope: the Cargo ecosystem, build scripts (`build.rs`), and supply-chain checks (covered by `cargo-ecosystem.md`); tool-lane invocations such as `cargo audit`, `cargo deny`, or `cargo geiger` (covered by `rust-tools.md`).

## Dangerous patterns (regex/AST hints)

### `std::mem::transmute` between incompatible layouts — CWE-843

- Why: Transmuting `&T` to `&U` when the two types differ in size, alignment, or field layout produces a reference to misinterpreted memory; transmuting fat pointers (slices, trait objects) is nearly always undefined behaviour because the metadata word is reinterpreted as data.
- Grep: `std::mem::transmute|mem::transmute|transmute::<`
- File globs: `**/*.rs`
- Source: https://doc.rust-lang.org/nomicon/transmutes.html

### Raw pointer arithmetic without bounds reasoning — CWE-119 / CWE-787 / CWE-125

- Why: Calling `.offset(i)`, `.add(i)`, `.sub(i)`, or `.wrapping_offset(i)` on a raw pointer without proving that `i` stays within the original allocation invokes undefined behaviour; the compiler is free to miscompile or the program to read/write out of bounds.
- Grep: `\.(offset|add|sub|wrapping_offset)\s*\(`
- File globs: `**/*.rs`
- Source: https://doc.rust-lang.org/nomicon/

### FFI `extern "C"` without null-pointer check — CWE-476

- Why: An `unsafe extern "C"` function that immediately dereferences a pointer parameter without a preceding `if p.is_null()` guard will crash or corrupt memory when a C caller passes NULL, which is a valid sentinel in C calling conventions.
- Grep: `extern\s+"C"|#\[no_mangle\]`
- File globs: `**/*.rs`
- Source: https://doc.rust-lang.org/nomicon/ffi.html

### Manual `unsafe impl Send` / `unsafe impl Sync` — CWE-362

- Why: Manually asserting `Send` or `Sync` for a type tells the compiler the type is safe to transfer or share across threads; if the type actually contains non-atomic interior mutability or owning raw pointers, this opens data races that the borrow checker would otherwise have caught.
- Grep: `unsafe\s+impl\s+(Send|Sync)\s+for\s+`
- File globs: `**/*.rs`
- Source: https://doc.rust-lang.org/nomicon/send-and-sync.html

### `std::mem::forget` skipping Drop — CWE-401

- Why: `mem::forget` permanently prevents the destructor from running; when applied to file handles, sockets, mutex guards, or any RAII wrapper that releases a system resource on drop, it leaks that resource for the lifetime of the process.
- Grep: `std::mem::forget|mem::forget\s*\(|ManuallyDrop::new`
- File globs: `**/*.rs`
- Source: https://doc.rust-lang.org/std/mem/fn.forget.html

### Clippy `transmute_ptr_to_ref` — CWE-416

- Why: Transmuting a raw pointer directly to a reference bypasses the borrow checker's lifetime and provenance analysis; if the pointed-to data has been freed or has an incompatible lifetime, the resulting reference is a dangling or aliased borrow that will cause use-after-free or undefined behaviour.
- Grep: `transmute::<\*(const|mut)\s*\w+,\s*&`
- File globs: `**/*.rs`
- Source: https://rust-lang.github.io/rust-clippy/master/index.html

### Misaligned pointer cast (`cast_ptr_alignment`) — CWE-704

- Why: Casting a `*const u8` (alignment 1) to `*const u32` (alignment 4) and then dereferencing it is undefined behaviour on any target that requires natural alignment; even on x86 where hardware tolerates it the compiler may emit instructions that assume the stricter alignment.
- Grep: `as\s+\*(const|mut)\s+(u16|u32|u64|u128|i16|i32|i64|i128|f32|f64|usize|isize)`
- File globs: `**/*.rs`
- Source: https://rust-lang.github.io/rust-clippy/master/index.html

### `Pin` misuse via `into_inner_unchecked` / `get_unchecked_mut` — CWE-763

- Why: Calling `Pin::into_inner_unchecked` or `get_unchecked_mut` on a `Pin<&mut T>` where `T: !Unpin` and then moving the value out violates the pinning contract; self-referential types (futures, async state machines) that hold internal pointers will corrupt those pointers when the value is relocated.
- Grep: `into_inner_unchecked|get_unchecked_mut\s*\(`
- File globs: `**/*.rs`
- Source: https://doc.rust-lang.org/std/pin/index.html

## Secure patterns

Safe FFI wrapper that null-checks an incoming pointer and returns `Option<&T>` — the caller in safe Rust is forced to handle the None case before dereferencing:

```rust
/// # Safety
/// `ptr` must be either null or point to a valid, properly aligned `T`
/// that outlives the returned reference.
pub unsafe fn ffi_ref_from_ptr<T>(ptr: *const T) -> Option<&'static T> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees ptr is non-null, aligned, and valid for 'static
    Some(unsafe { &*ptr })
}

// C-exported entry point: always null-checks before use
#[no_mangle]
pub unsafe extern "C" fn process_record(record: *const Record) -> i32 {
    match ffi_ref_from_ptr(record) {
        None => -1,  // NULL sentinel — return error to caller
        Some(r) => do_work(r),
    }
}
```

Source: https://doc.rust-lang.org/nomicon/ffi.html

Safe replacement for `mem::forget` — use `ManuallyDrop` with an explicit cleanup comment so the intent and the responsibility are both visible at the call site:

```rust
use std::mem::ManuallyDrop;

fn hand_off_to_c(handle: FileHandle) -> *mut FileHandle {
    // SAFETY: Ownership is transferred to the C side. The C caller is
    // responsible for calling `free_file_handle` to release the resource.
    // We use ManuallyDrop so the Rust destructor does not run on drop,
    // and we document the obligation in the public API contract.
    let mut md = ManuallyDrop::new(handle);
    md.as_mut() as *mut FileHandle
}

// Corresponding reclaim function — must be called from C when done
#[no_mangle]
pub unsafe extern "C" fn free_file_handle(ptr: *mut FileHandle) {
    if !ptr.is_null() {
        // Re-box and drop, running the destructor and releasing resources
        drop(unsafe { Box::from_raw(ptr) });
    }
}
```

Source: https://doc.rust-lang.org/std/mem/fn.forget.html

## Fix recipes

### Recipe: Replace `std::mem::transmute::<&T, &U>` with a safe byte-level view — addresses CWE-843

**Before (dangerous):**

```rust
use std::mem;

fn reinterpret(input: &Rgba) -> &[u8; 4] {
    // UB if Rgba is not exactly 4 bytes with no padding
    unsafe { mem::transmute(input) }
}
```

**After (safe):**

```rust
// Use bytemuck::cast_ref — panics at compile time if layout is incompatible.
// Add bytemuck = { version = "1", features = ["derive"] } to Cargo.toml.
use bytemuck::cast_ref;

// Rgba must derive bytemuck::Pod + bytemuck::Zeroable to guarantee layout
#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
struct Rgba { r: u8, g: u8, b: u8, a: u8 }

fn reinterpret(input: &Rgba) -> &[u8; 4] {
    // cast_ref checks size and alignment at compile time; no unsafe required
    cast_ref(input)
}
```

Source: https://doc.rust-lang.org/nomicon/transmutes.html

### Recipe: Guard FFI function body with null-pointer check — addresses CWE-476

**Before (dangerous):**

```rust
#[no_mangle]
pub unsafe extern "C" fn process_config(cfg: *const Config) -> i32 {
    // Dereferences cfg without checking for NULL — crash if C caller passes null
    let config = &*cfg;
    apply(config)
}
```

**After (safe):**

```rust
#[no_mangle]
pub unsafe extern "C" fn process_config(cfg: *const Config) -> i32 {
    // Reject NULL before any dereference; -1 is the conventional error sentinel
    if cfg.is_null() {
        return -1;
    }
    // SAFETY: cfg is non-null; caller guarantees it is aligned and valid
    let config = unsafe { &*cfg };
    apply(config)
}
```

Source: https://doc.rust-lang.org/nomicon/ffi.html

### Recipe: Replace `mem::forget` with `ManuallyDrop::new` and explicit cleanup — addresses CWE-401

**Before (dangerous):**

```rust
use std::mem;

fn register_socket(sock: TcpStream) {
    // Destructor is silently suppressed; the socket fd is leaked
    mem::forget(sock);
    // ... register raw fd with epoll ...
}
```

**After (safe):**

```rust
use std::mem::ManuallyDrop;

fn register_socket(sock: TcpStream) -> ManuallyDrop<TcpStream> {
    // SAFETY: The caller takes ownership of the ManuallyDrop wrapper.
    // It MUST call ManuallyDrop::drop(&mut md) or reconstruct the
    // TcpStream via ManuallyDrop::into_inner to release the fd when done.
    let md = ManuallyDrop::new(sock);
    // Register the raw fd with epoll using md.as_raw_fd()
    md
}

// At cleanup site, explicitly run the destructor:
// unsafe { ManuallyDrop::drop(&mut md); }
```

Source: https://doc.rust-lang.org/std/mem/fn.forget.html

## Version notes

- `std::mem::transmute` has been stable since Rust 1.0; `transmute_copy` (which relaxes the size-equality requirement) was stabilised at the same time and is equally dangerous — treat it identically.
- `Pin::into_inner_unchecked` was stabilised in Rust 1.58.0; code on older toolchains may use equivalent pointer-cast patterns — grep for `get_unchecked_mut` as a broader signal.
- Clippy lints `transmute_ptr_to_ref` and `cast_ptr_alignment` are available in the `clippy` tool component bundled with every stable toolchain; no additional installation is required. Run `cargo clippy -- -W clippy::transmute_ptr_to_ref -W clippy::cast_ptr_alignment` to surface these specifically.
- `bytemuck` (recommended in the transmute fix recipe) requires explicit `#[repr(C)]` or `#[repr(transparent)]` on types deriving `Pod`; the derive macro rejects types with padding at compile time, making the safety guarantee unconditional.

## Common false positives

- `ManuallyDrop::new` — usually safe when the call site is immediately followed by a `Box::from_raw` / `ManuallyDrop::drop` in the same function or is part of a well-documented FFI ownership handoff; flag only when no corresponding reclaim path is visible.
- `mem::forget` on a `std::mem::MaybeUninit` value — forgetting an uninitialised value has no resource-leak consequence; this pattern is idiomatic when using `MaybeUninit` as a stack buffer.
- `unsafe impl Send for X` — lower risk when `X` wraps a type that is `Send` but uses a non-Send interior-mutability primitive only for single-threaded initialisation (e.g. `OnceCell` patterns); verify that no mutable reference escapes to a second thread.
- `extern "C"` grep matches in `extern "C" { fn foo(...); }` blocks (import declarations) — these are linkage annotations, not function definitions; the null-pointer concern applies only to function bodies that dereference incoming pointers.
- `.add(i)` / `.offset(i)` inside iterator adapter implementations from the standard library or well-audited crates (e.g. `slice::Iter`) — these are internal and already verified; flag only user-authored pointer arithmetic in application or library code.
