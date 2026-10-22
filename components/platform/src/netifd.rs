//! Fixed Linux ABI operations used by netifd; policy stays in its main crate.
use std::ffi::{c_char, c_int, c_ulong, CStr};
use std::io;
use std::os::fd::{AsFd, AsRawFd};

mod signals;
pub use signals::ChildSignal;

unsafe extern "C" {
    #[link_name = "atoi"]
    fn libc_atoi(text: *const c_char) -> c_int;
    fn openlog(ident: *const c_char, option: c_int, facility: c_int);
    fn syslog(priority: c_int, format: *const c_char, ...);
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *const std::ffi::c_void,
        len: u32,
    ) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
}

pub fn atoi(text: &CStr) -> i32 {
    // SAFETY: CStr owns a live terminated byte string for libc's image semantics.
    unsafe { libc_atoi(text.as_ptr()) }
}

pub fn open_log() {
    // SAFETY: libc retains this static ident; fixed LOG_DAEMON, no LOG_PID.
    unsafe { openlog(c"netifd".as_ptr(), 0, 3 << 3) }
}

pub fn log(priority: i32, message: &CStr) {
    // SAFETY: fixed format consumes one live terminated string, never a format
    // from a child process. libc serializes its process-global syslog state.
    unsafe { syslog(priority, c"%s".as_ptr(), message.as_ptr()) }
}

pub fn signal_child(pid: u32, signal: i32) -> io::Result<()> {
    let pid = i32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::from_raw_os_error(22))?;
    if !(0..=31).contains(&signal) {
        return Err(io::Error::from_raw_os_error(22));
    }
    // SAFETY: positive PID and checked scalar signal, including signal zero.
    // rustix has no safe constructor for every numeric signal in this API.
    if unsafe { kill(pid, signal) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn enable_netlink_ext_ack(fd: impl AsFd) -> io::Result<()> {
    let value = 1;
    // SAFETY: fixed SOL_NETLINK/NETLINK_EXT_ACK reads exactly one live int.
    // rustix 1.1.5 does not expose this socket option.
    if unsafe {
        setsockopt(
            fd.as_fd().as_raw_fd(),
            270,
            11,
            (&value as *const i32).cast(),
            4,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn ifreq(name: &str) -> [u8; 40] {
    let mut request = [0; 40];
    let len = name.len().min(15);
    request[..len].copy_from_slice(&name.as_bytes()[..len]);
    request
}

fn ethtool_ifreq(name: &str, buffer: &mut [u8]) -> [u8; 40] {
    let mut request = ifreq(name);
    request[16..24].copy_from_slice(&(buffer.as_mut_ptr() as usize).to_ne_bytes());
    request
}

pub fn interface_query(fd: impl AsFd, name: &str, command: u64) -> io::Result<[u8; 40]> {
    if !matches!(command, 0x8913 | 0x8921 | 0x8927 | 0x8942) {
        return Err(io::Error::from_raw_os_error(22));
    }
    let mut request = ifreq(name);
    // SAFETY: these four SIOCGIF* requests read the bounded name and write
    // within a 40-byte Linux64 ifreq. None interprets its union as a pointer.
    if unsafe {
        ioctl(
            fd.as_fd().as_raw_fd(),
            command as c_ulong,
            request.as_mut_ptr(),
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(request)
    }
}

/// The fixed read-only ethtool requests used by this application's status path.
/// Keep command-sized buffers and the ifr_data pointer inside the ABI boundary.
pub fn ethtool_query(fd: impl AsFd, name: &str, buffer: &mut [u8]) -> io::Result<()> {
    let invalid = || io::Error::from_raw_os_error(22);
    let word = |offset: usize| -> io::Result<u32> {
        Ok(u32::from_ne_bytes(
            buffer
                .get(offset..offset + 4)
                .ok_or_else(invalid)?
                .try_into()
                .unwrap(),
        ))
    };
    let required = match word(0)? {
        0x12 => 16, // ethtool_pauseparam
        0x2b => 8,  // ethtool_value, GGRO
        0x4c => {
            // link settings, header plus three requested masks
            let words = *buffer.get(15).ok_or_else(invalid)? as i8;
            48 + 12 * usize::try_from(words.max(0)).unwrap()
        }
        0x37 => {
            // sset_info, one u32 result per requested set bit
            let mask =
                u64::from_ne_bytes(buffer.get(8..16).ok_or_else(invalid)?.try_into().unwrap());
            16 + 4 * mask.count_ones() as usize
        }
        0x1b => {
            // GSTRINGS ignores the input len and writes the kernel's count.
            // Only the fixed feature-name table is used by netifd; unlike
            // driver statistics, its size cannot change between these calls.
            if word(4)? != 4 || buffer.len() < 12 {
                return Err(invalid());
            }
            let mut info = [0u8; 20];
            info[..4].copy_from_slice(&0x37u32.to_ne_bytes());
            info[8..16].copy_from_slice(&(1u64 << 4).to_ne_bytes());
            ethtool_query(fd.as_fd(), name, &mut info)?;
            let count = u32::from_ne_bytes(info[16..20].try_into().unwrap()) as usize;
            12usize
                .checked_add(count.checked_mul(32).ok_or_else(invalid)?)
                .ok_or_else(invalid)?
        }
        0x3a => 8usize
            .checked_add((word(4)? as usize).checked_mul(16).ok_or_else(invalid)?)
            .ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    if buffer.len() < required {
        return Err(invalid());
    }
    let mut request = ethtool_ifreq(name, buffer);
    // SAFETY: supported Linux64 ifreq holds a pointer to this exclusive live
    // command-sized buffer. Commands above have no nested user pointers.
    // GSTRINGS is bounded by the kernel's fixed feature count queried above,
    // not the untrusted input len that the ioctl itself ignores.
    if unsafe {
        ioctl(
            fd.as_fd().as_raw_fd(),
            0x8946 as c_ulong,
            request.as_mut_ptr(),
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ifreq_puts_the_pointer_at_offset_sixteen() {
        let mut buffer = [0u8; 8];
        let request = ethtool_ifreq("br-lan", &mut buffer);
        assert_eq!(&request[..6], b"br-lan");
        assert_eq!(request[6], 0);
        assert_eq!(
            u64::from_ne_bytes(request[16..24].try_into().unwrap()),
            buffer.as_ptr() as u64
        );
    }
    #[test]
    fn a_too_long_name_is_truncated_and_still_terminated() {
        let request = ifreq("0123456789abcdefghij");
        assert_eq!(&request[..15], b"0123456789abcde");
        assert_eq!(request[15], 0);
    }
}
