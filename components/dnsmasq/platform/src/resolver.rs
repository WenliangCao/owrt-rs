//! Image-libc DNS name expansion. Returned addresses own all their bytes;
//! ordering, duplicates and AI_ADDRCONFIG are kept at the libc boundary.
use std::ffi::{c_char, c_int, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

#[cfg(target_os = "linux")]
const AF_INET6: c_int = 10;
#[cfg(target_os = "macos")]
const AF_INET6: c_int = 30;
#[cfg(target_os = "linux")]
const AI_ADDRCONFIG: c_int = 0x20;
#[cfg(target_os = "macos")]
const AI_ADDRCONFIG: c_int = 0x400;
#[cfg(target_os = "linux")]
const EAI_AGAIN: c_int = -3;
#[cfg(target_os = "macos")]
const EAI_AGAIN: c_int = 2;

#[repr(C)]
struct AddrInfo {
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    address_length: u32,
    #[cfg(target_os = "macos")]
    canonical: *mut c_char,
    address: *mut u8,
    #[cfg(target_os = "linux")]
    canonical: *mut c_char,
    next: *mut AddrInfo,
}

unsafe extern "C" {
    fn getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const AddrInfo,
        result: *mut *mut AddrInfo,
    ) -> c_int;
    fn freeaddrinfo(result: *mut AddrInfo);
    fn gai_strerror(error: c_int) -> *const c_char;
}

/// Preserve libc ordering and duplicates: option.c iterates every SOCK_DGRAM
/// result once. AI_ADDRCONFIG belongs to the image libc, not a Rust guess at
/// which interface addresses should count.
pub fn addresses(name: &[u8]) -> Result<Vec<IpAddr>, &'static str> {
    let name = CString::new(name).map_err(|_| "Name does not resolve")?;
    let hints = AddrInfo {
        flags: AI_ADDRCONFIG,
        family: 0,
        socktype: 2,
        protocol: 0,
        address_length: 0,
        address: ptr::null_mut(),
        canonical: ptr::null_mut(),
        next: ptr::null_mut(),
    };
    let mut head = ptr::null_mut();
    // SAFETY: all pointers reference live initialized storage; libc owns the
    // returned list until the matching freeaddrinfo below.
    let code = unsafe { getaddrinfo(name.as_ptr(), ptr::null(), &hints, &mut head) };
    if code != 0 {
        if code == EAI_AGAIN {
            return Err("Cannot resolve server name");
        }
        // musl (the deployment libc) and Darwin return static error strings.
        // No DNS input is retained in these strings.
        // SAFETY: supported libcs return a non-null immutable static string
        // for the getaddrinfo error code; no caller buffer is involved.
        let message: &'static CStr = unsafe { CStr::from_ptr(gai_strerror(code)) };
        return Err(message.to_str().unwrap_or("Unknown error"));
    }
    struct List(*mut AddrInfo);
    impl Drop for List {
        fn drop(&mut self) {
            // SAFETY: this guard exclusively owns the successful result list.
            unsafe { freeaddrinfo(self.0) };
        }
    }
    let _list = List(head);
    let mut result = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor walks only links in the live libc result list.
        let entry = unsafe { &*cursor };
        if !entry.address.is_null() && entry.family == 2 && entry.address_length >= 16 {
            // SAFETY: non-null sockaddr_in has at least 16 bytes; its address
            // starts at byte four on both supported ABIs and the list is live.
            let bytes = unsafe { std::slice::from_raw_parts(entry.address.add(4), 4) };
            result.push(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )));
        } else if !entry.address.is_null() && entry.family == AF_INET6 && entry.address_length >= 28
        {
            // SAFETY: the preceding family/length guard proves all 16 IPv6
            // bytes at offset eight are within the live libc-owned sockaddr.
            let bytes = unsafe { std::slice::from_raw_parts(entry.address.add(8), 16) };
            let mut address = [0; 16];
            address.copy_from_slice(bytes);
            result.push(IpAddr::V6(Ipv6Addr::from(address)));
        }
        cursor = entry.next;
    }
    Ok(result)
}
