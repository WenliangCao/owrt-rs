//! libc startup adapter. The ruleset/CLI library forbids unsafe code; keeping
//! this ABI preserves the shell caller's SIGPIPE and the existing startup cost.
#![cfg_attr(not(test), no_main)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(test))]
#[no_mangle]
/// # Safety
/// libc supplies argc valid pointers to terminated argument strings.
pub unsafe extern "C" fn main(argc: i32, argv: *const *const std::ffi::c_char) -> i32 {
    let args = (0..argc.max(0) as usize)
        // SAFETY: the libc main contract supplies live terminated strings.
        .map(|i| {
            unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    owrt_fw4::run(args)
}
