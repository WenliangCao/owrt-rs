//! The CLI takes `main` from libc directly (`#![no_main]` in `platform/entry.rs`)
//! so a one-shot invocation skips the Rust runtime prologue.  Without that
//! prologue nothing in the program references libc's `getauxval` before the
//! linker reaches `compiler_builtins`, whose outline-atomics initialiser needs
//! it; with the self-contained static musl link order (libc.a first, single
//! pass ld.bfd) that leaves the symbol undefined.  Asking the linker for it up
//! front pulls the libc.a member in time.  glibc and macOS builds link libc
//! dynamically and need nothing.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "linux" && env == "musl" {
        println!("cargo:rustc-link-arg-bins=-Wl,-u,getauxval");
    }
}
