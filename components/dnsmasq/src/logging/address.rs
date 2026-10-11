//! Shared C-compatible address rendering for service diagnostics.

use std::ffi::{c_char, c_void};
use std::net::SocketAddr;

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
            let mut name = [0u8; 16];
            // SAFETY: name has the Linux IF_NAMESIZE capacity; libc writes
            // only within it and returns NULL for an absent interface.
            if !unsafe { if_indextoname(address.scope_id(), name.as_mut_ptr().cast()) }.is_null() {
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


unsafe extern "C" {
    fn if_indextoname(index: u32, name: *mut c_char) -> *mut c_char;
    fn inet_ntop(
        family: i32,
        address: *const c_void,
        output: *mut c_char,
        length: u32,
    ) -> *const c_char;
}
