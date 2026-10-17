//! Only the libc startup ABI lives here; all CLI/business code is in the
//! forbid(unsafe_code) library. Preserve inherited SIGPIPE and avoid adding
//! the Rust runtime prologue to every one-shot command.
#![cfg_attr(not(test), no_main)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(test))]
#[no_mangle]
/// # Safety
/// libc calls this once with argc valid, terminated argument strings.
pub unsafe extern "C" fn main(argc: i32, argv: *const *const std::ffi::c_char) -> i32 {
    let args = (0..argc.max(0) as usize)
        // SAFETY: libc's entry contract supplies each live terminated argument.
        .map(|i| {
            unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }
                .to_bytes()
                .to_vec()
        })
        .collect();
    owrt_uci::cli::run(args)
}
