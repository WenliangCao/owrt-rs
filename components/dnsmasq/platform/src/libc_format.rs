//! libc rendering is a compatibility requirement: Rust's IP, time and errno
//! displays do not match the shipped musl text. All buffers stay owned here.
use std::ffi::{c_char, c_int, c_void};
use std::io;
use std::net::SocketAddr;
use std::os::unix::process::CommandExt;
use std::process::Command;

unsafe extern "C" {
    fn inet_ntop(
        family: i32,
        address: *const c_void,
        output: *mut c_char,
        length: u32,
    ) -> *const c_char;
    #[cfg_attr(target_env = "gnu", link_name = "__xpg_strerror_r")]
    fn strerror_r(error: c_int, output: *mut c_char, length: usize) -> c_int;
    #[cfg(target_pointer_width = "64")]
    fn ctime_r(value: *const i64, output: *mut c_char) -> *mut c_char;
    #[cfg(target_pointer_width = "64")]
    fn time(output: *mut i64) -> i64;
    fn signal(number: c_int, handler: usize) -> usize;
}

/// std resets SIGPIPE during spawn; C's popen/exec paths preserve SIG_IGN.
pub fn preserve_ignored_sigpipe(command: &mut Command) {
    // SAFETY: this fixed hook invokes only async-signal-safe signal, with
    // scalar arguments. No caller callback, allocation or lock runs in it.
    unsafe {
        command.pre_exec(|| {
            signal(13, 1);
            Ok(())
        });
    }
}

/// Reentrant strerror keeps musl's exact wording without static-buffer races.
pub fn error_text(error: &io::Error) -> String {
    let Some(code) = error.raw_os_error() else {
        return error.to_string();
    };
    let mut output = [0u8; 1024];
    // SAFETY: the POSIX variant writes no more than this live buffer's size.
    // The explicit GNU symbol avoids its incompatible char* return variant.
    unsafe {
        strerror_r(code, output.as_mut_ptr().cast(), output.len());
    }
    let length = output
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(output.len());
    if length == 0 {
        format!("OS error {code}")
    } else {
        String::from_utf8_lossy(&output[..length]).into_owned()
    }
}

#[cfg(target_pointer_width = "64")]
pub fn local_time(value: i64) -> Option<[u8; 26]> {
    let mut output = [0; 26];
    // SAFETY: supported Linux/Darwin time_t is i64 and ctime_r writes its
    // fixed 26-byte terminated representation into this private buffer.
    if unsafe { ctime_r(&value, output.as_mut_ptr().cast()) }.is_null() {
        None
    } else {
        Some(output)
    }
}

#[cfg(target_pointer_width = "64")]
pub fn log_timestamp() -> [u8; 15] {
    let mut now = 0;
    // SAFETY: the writable time_t lives throughout this synchronous call.
    unsafe {
        time(&mut now);
    }
    let text = local_time(now).unwrap_or([0; 26]);
    text[4..19].try_into().unwrap()
}

/// util.c::prettyprint_addr, excluding the separately formatted port.
pub fn address_text(address: SocketAddr) -> Vec<u8> {
    // ADDRSTRLEN is INET6_ADDRSTRLEN (46). Use the image libc's rendering,
    // including its IPv4-compatible IPv6 spelling.
    let mut output = [0u8; 46];
    match address {
        // SAFETY: each octet array lives through this synchronous libc call;
        // output is writable for INET6_ADDRSTRLEN including its terminating NUL.
        SocketAddr::V4(address) => unsafe {
            inet_ntop(
                2,
                address.ip().octets().as_ptr().cast(),
                output.as_mut_ptr().cast(),
                46,
            );
        },
        SocketAddr::V6(address) => {
            let family = if cfg!(target_os = "macos") { 30 } else { 10 };
            // SAFETY: the IPv6 octets and 46-byte destination remain live for
            // the call; family is the platform's AF_INET6 value.
            unsafe {
                inet_ntop(
                    family,
                    address.ip().octets().as_ptr().cast(),
                    output.as_mut_ptr().cast(),
                    46,
                );
            }
        }
    }
    let mut value = output[..output
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(output.len())]
        .to_vec();
    if let SocketAddr::V6(address) = address {
        if address.scope_id() != 0 {
            if let Ok(name) = crate::interfaces::index_to_name(address.scope_id()) {
                let name = &name[..name
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(name.len())];
                if value.len() + name.len() + 2 <= 46 {
                    value.push(b'%');
                    value.extend_from_slice(name);
                }
            }
        }
    }
    value
}
