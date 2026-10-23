//! libc startup adapter. The CLI requires sole-thread ownership; keeping
//! this ABI preserves the shell caller's SIGPIPE and the existing startup cost.
#![cfg_attr(not(test), no_main)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(test))]
#[no_mangle]
/// # Safety
/// libc supplies argc valid pointers to terminated argument strings, on the
/// sole startup thread before application threads exist.
pub unsafe extern "C" fn main(argc: i32, argv: *const *const std::ffi::c_char) -> i32 {
    let args = (0..argc.max(0) as usize)
        // SAFETY: the libc main contract supplies live terminated strings.
        .map(|i| {
            unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let owner = owrt_platform::process_owner::ProcessOwner::acquire()
        .unwrap_or_else(|_| std::process::exit(1));
    owrt_fw4::run(args, &owner)
}
