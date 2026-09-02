//! Small self-contained helpers: MD5, Base64, file.c path canonicalisation,
//! passwd/group lookups, statvfs/uname via FFI.

use std::ffi::CString;

// ------------------------------------------------------------------ MD5

pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32)
        .collect();
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..].copy_from_slice(&d0.to_le_bytes());
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --------------------------------------------------------------- Base64

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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
    for &c in data {
        if c.is_ascii_whitespace() {
            continue;
        }
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
    Some(out)
}

// ------------------------------------------------------- path handling

/// file.c `rpc_canonicalize_path`: collapse `//`, `/./`, `/x/../`, strip a
/// trailing slash (except for `/`). Returns None for an empty path.
pub fn canonicalize(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let p = path.as_bytes();
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
    Some(String::from_utf8_lossy(&out).into_owned())
}

// ---------------------------------------------------- passwd / group

fn lookup_name(file: &str, id: u32) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
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
    if unsafe { statvfs(c.as_ptr(), &mut st) } == 0 {
        Some(st)
    } else {
        None
    }
}

/// `uname().machine`
pub fn machine() -> String {
    let mut buf = [0u8; 6 * 65];
    if unsafe { uname(&mut buf) } != 0 {
        return String::new();
    }
    let m = &buf[4 * 65..5 * 65];
    let end = m.iter().position(|&b| b == 0).unwrap_or(m.len());
    String::from_utf8_lossy(&m[..end]).into_owned()
}

pub fn sync_all() {
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
        assert_eq!(b64_decode(b"aGVs\nbG8").unwrap(), b"hello");
        assert!(b64_decode(b"a$").is_none());
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
