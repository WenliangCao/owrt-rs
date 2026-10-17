//! libc configuration limits whose failure/infinity semantics are not supplied
//! by rustix's getrlimit API.

/// Match the supported libc's _SC_OPEN_MAX, including a negative failure value.
pub fn open_max() -> isize {
    unsafe extern "C" {
        fn sysconf(name: i32) -> isize;
    }
    #[cfg(target_os = "linux")]
    const OPEN_MAX: i32 = 4;
    #[cfg(target_os = "macos")]
    const OPEN_MAX: i32 = 5;
    // SAFETY: sysconf takes a scalar selector, no pointers or ownership. These
    // selectors are from the supported Linux/Darwin headers. Preserve its
    // signed result instead of guessing how RLIM_INFINITY should map to it.
    unsafe { sysconf(OPEN_MAX) }
}
