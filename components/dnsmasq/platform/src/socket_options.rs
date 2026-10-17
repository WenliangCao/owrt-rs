//! Linux socket options absent from rustix 1.1.5's typed socket-option API.
//! Every operation borrows an owned descriptor and passes bounded storage.

use std::io;
use std::os::fd::{AsFd, AsRawFd};

fn set_bytes(fd: impl AsFd, level: i32, option: i32, value: &[u8]) -> io::Result<()> {
    let length =
        u32::try_from(value.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the descriptor is borrowed for this call; value contains length
    // initialized bytes. setsockopt reads this storage synchronously and never
    // retains its pointer. Only the fixed options below can reach this helper.
    let result = unsafe {
        super::setsockopt(
            fd.as_fd().as_raw_fd(),
            level,
            option,
            value.as_ptr().cast(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Linux expects the interface number in network byte order for both options.
pub fn set_unicast_interface(fd: impl AsFd, ipv6: bool, index: u32) -> io::Result<()> {
    let (level, option) = if ipv6 { (41, 76) } else { (0, 50) };
    set_bytes(fd, level, option, &index.to_be_bytes())
}

/// Preserve the caller's exact SO_BINDTODEVICE length, including an empty name.
pub fn bind_to_device(fd: impl AsFd, name: &[u8]) -> io::Result<()> {
    set_bytes(fd, 1, 25, name)
}

pub fn set_dont_route(fd: impl AsFd, enabled: bool) -> io::Result<()> {
    set_bytes(fd, 1, 5, &i32::from(enabled).to_ne_bytes())
}

pub fn enable_packet_info(fd: impl AsFd, ipv6: bool, legacy_ipv6: bool) -> io::Result<()> {
    let (level, option) = if ipv6 {
        (41, if legacy_ipv6 { 2 } else { 49 })
    } else {
        (0, 8)
    };
    set_bytes(fd, level, option, &1i32.to_ne_bytes())
}

/// IP_PKTOPTIONS / legacy IPV6_2292PKTOPTIONS retain the SYN ingress metadata.
pub fn packet_options(fd: impl AsFd, ipv6: bool, bytes: &mut [u8; 64]) -> io::Result<usize> {
    let (level, option) = if ipv6 { (41, 6) } else { (0, 9) };
    let mut length = bytes.len() as u32;
    // SAFETY: getsockopt receives exactly the initialized array's capacity
    // and a live socklen_t. It bounds writes by the input length; the returned
    // length is checked before callers can inspect that portion of the array.
    let result = unsafe {
        super::getsockopt(
            fd.as_fd().as_raw_fd(),
            level,
            option,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize > bytes.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(length as usize)
}

/// Inspect the option for socket-policy tests without leaking a raw pointer.
pub fn packet_info_enabled(fd: impl AsFd, ipv6: bool) -> io::Result<bool> {
    let (level, option) = if ipv6 { (41, 49) } else { (0, 8) };
    let mut value = 0i32;
    let mut length = 4u32;
    // SAFETY: the fixed options write one native int; both output objects
    // have their exact ABI type, size and alignment and live through the call.
    let result = unsafe {
        super::getsockopt(
            fd.as_fd().as_raw_fd(),
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length != 4 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(value != 0)
}

pub fn bound_device(fd: impl AsFd, name: &mut [u8; 16]) -> io::Result<usize> {
    let mut length = name.len() as u32;
    // SAFETY: SO_BINDTODEVICE writes at most the supplied 16-byte capacity.
    // The descriptor, array and socklen_t remain live and no pointer escapes.
    let result = unsafe {
        super::getsockopt(
            fd.as_fd().as_raw_fd(),
            1,
            25,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize > name.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(length as usize)
}
