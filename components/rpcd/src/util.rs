//! Small self-contained helpers: MD5, Base64, file.c path canonicalisation,
//! passwd/group lookups, statvfs/uname via FFI.

use std::ffi::CString;

pub use owrt_ubus::digest::md5;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --------------------------------------------------------------- Base64

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// libubox b64_decode semantics: whitespace is skipped, padding optional,
/// invalid characters fail.
pub fn b64_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    let mut pad = 0;
    let mut ndigit = 0usize; // non-whitespace chars, incl. padding
    for &c in data {
        if c.is_ascii_whitespace() {
            continue;
        }
        ndigit += 1;
        if c == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return None;
        }
        let v = B64.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // libubox b64_decode consumes whole quartets: the non-whitespace
    // length must be a multiple of 4 and at most two `=` may pad the tail.
    if pad > 2 || !ndigit.is_multiple_of(4) {
        return None;
    }
    Some(out)
}

// ------------------------------------------------------- path handling

/// file.c `rpc_canonicalize_path`: collapse `//`, `/./`, `/x/../`, strip a
/// trailing slash (except for `/`). Returns None for an empty path.
#[cfg(test)]
fn canonicalize(path: &str) -> Option<String> {
    String::from_utf8(canonicalize_bytes(path.as_bytes())?).ok()
}

pub fn canonicalize_bytes(p: &[u8]) -> Option<Vec<u8>> {
    if p.is_empty() {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(p.len());
    let mut i = 0;
    while i < p.len() {
        if p[i] != b'/' {
            out.push(p[i]);
            i += 1;
            continue;
        }
        if p.get(i + 1) == Some(&b'/') {
            i += 1;
            continue;
        }
        if p.get(i + 1) == Some(&b'.') {
            if matches!(p.get(i + 2), None | Some(b'/')) {
                i += 2;
                continue;
            }
            if p.get(i + 2) == Some(&b'.') && matches!(p.get(i + 3), None | Some(b'/')) {
                while let Some(last) = out.pop() {
                    if last == b'/' {
                        break;
                    }
                }
                i += 3;
                continue;
            }
        }
        out.push(b'/');
        i += 1;
    }
    if out.len() > 1 && out.last() == Some(&b'/') {
        out.pop();
    } else if out.is_empty() {
        out.push(b'/');
    }
    Some(out)
}

/// Read a text file the way the C code consumes it with fgets/strtok: byte
/// by byte, so one non-UTF-8 byte does not make the whole file unreadable.
/// Invalid sequences become U+FFFD for these text-only consumers. File RPCs
/// use bytes throughout, including blobmsg STRING values.
pub fn read_lossy(path: &str) -> std::io::Result<String> {
    std::fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned())
}

// ---------------------------------------------------- passwd / group

fn lookup_name(file: &str, id: u32) -> Option<String> {
    let text = read_lossy(file).ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 3 && f[2].parse::<u32>().ok() == Some(id) {
            return Some(f[0].to_owned());
        }
    }
    None
}

pub fn user_name(uid: u32) -> Option<String> {
    lookup_name("/etc/passwd", uid)
}

pub fn group_name(gid: u32) -> Option<String> {
    lookup_name("/etc/group", gid)
}

// ----------------------------------------------------------- FFI bits

#[repr(C)]
#[derive(Default)]
pub struct StatVfs {
    pub f_bsize: u64,
    pub f_frsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: u64,
    pub f_flag: u64,
    pub f_namemax: u64,
    _spare: [u32; 6],
}

extern "C" {
    fn statvfs(path: *const std::os::raw::c_char, buf: *mut StatVfs) -> i32;
    fn uname(buf: *mut [u8; 6 * 65]) -> i32;
    fn sync();
}

pub fn statvfs_of(path: &str) -> Option<StatVfs> {
    let c = CString::new(path).ok()?;
    let mut st = StatVfs::default();
    // SAFETY: a NUL-terminated path and a live, correctly sized struct. The
    // layout is asserted against the target's headers by `make check-abi`.
    if unsafe { statvfs(c.as_ptr(), &mut st) } == 0 {
        Some(st)
    } else {
        None
    }
}

/// `uname().machine`
pub fn machine() -> String {
    let mut buf = [0u8; 6 * 65];
    // SAFETY: buf is exactly sizeof(struct utsname) for this target, which
    // `make check-abi` asserts.
    if unsafe { uname(&mut buf) } != 0 {
        return String::new();
    }
    let m = &buf[4 * 65..5 * 65];
    let end = m.iter().position(|&b| b == 0).unwrap_or(m.len());
    String::from_utf8_lossy(&m[..end]).into_owned()
}

pub fn sync_all() {
    // SAFETY: sync(2) takes no arguments and touches no memory of ours.
    unsafe { sync() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"The quick brown fox jumps over the lazy dog")), "9e107d9d372bb6826bd81d3542a419d6");
        assert_eq!(hex(&md5(&[b'a'; 1000])), "cabe45dcc9ae5b66ba86600cca6b8ba8");
    }

    #[test]
    fn base64() {
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_decode(b"aGVsbG8=").unwrap(), b"hello");
        // libubox consumes whole quartets: whitespace is skipped but the
        // non-whitespace length must stay a multiple of 4.
        assert_eq!(b64_decode(b"aGVs\nbG8=").unwrap(), b"hello");
        assert!(b64_decode(b"a$").is_none());
        assert!(b64_decode(b"aGVsbG8").is_none()); // 7 chars, unpadded
        assert!(b64_decode(b"Q").is_none()); // single char
        assert!(b64_decode(b"QQ=").is_none()); // incomplete quartet
        assert_eq!(b64_decode(b"QQ==").unwrap(), b"A");
        assert_eq!(b64_decode(b"QU JD").unwrap(), b"ABC"); // embedded ws
    }

    #[test]
    fn canon() {
        assert_eq!(canonicalize("/etc//config/./firewall/").unwrap(), "/etc/config/firewall");
        assert_eq!(canonicalize("/a/b/../c").unwrap(), "/a/c");
        assert_eq!(canonicalize("/a/../..").unwrap(), "/");
        assert_eq!(canonicalize("/").unwrap(), "/");
        assert_eq!(canonicalize("etc/x").unwrap(), "etc/x");
        assert_eq!(canonicalize(""), None);
    }
}
