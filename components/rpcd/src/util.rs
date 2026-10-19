//! Small self-contained helpers: MD5, Base64, file.c path canonicalisation,
//! passwd/group lookups, statvfs/uname via FFI.

use std::io::{BufRead, BufReader};

#[cfg(test)]
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

/// libubox b64_decode semantics: whitespace is skipped, complete quartets and
/// zero padding bits are required, invalid characters fail.
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
    if pad > 2 || !ndigit.is_multiple_of(4) || acc != 0 {
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
    let file = std::fs::File::open(file).ok()?;
    lookup_name_in(&mut BufReader::with_capacity(512, file), id)
}

fn lookup_name_in(reader: &mut impl BufRead, id: u32) -> Option<String> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).ok()? == 0 {
            return None;
        }
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        let mut fields = line.split(|&b| b == b':');
        let name = fields.next()?;
        let found = fields.nth(1).and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|s| s.parse::<u32>().ok());
        if found == Some(id) {
            return Some(String::from_utf8_lossy(name).into_owned());
        }
    }
}

pub fn user_name(uid: u32) -> Option<String> {
    lookup_name("/etc/passwd", uid)
}

pub fn group_name(gid: u32) -> Option<String> {
    lookup_name("/etc/group", gid)
}

/// Display names for one file response. Repeated consecutive IDs use the name
/// observed first in this response; a new response always opens current files.
/// Two slots bound storage independently of directory size. These names are
/// never used for permissions or session identity.
#[derive(Default)]
pub struct IdentityNames {
    user: LastName,
    group: LastName,
}

#[derive(Default)]
struct LastName(Option<(u32, Option<String>)>);

impl LastName {
    fn get(&mut self, id: u32, lookup: impl FnOnce() -> Option<String>) -> Option<&str> {
        if self.0.as_ref().map(|entry| entry.0) != Some(id) {
            self.0 = Some((id, lookup()));
        }
        self.0.as_ref().and_then(|entry| entry.1.as_deref())
    }
}

impl IdentityNames {
    pub fn user(&mut self, uid: u32) -> Option<&str> {
        self.user.get(uid, || user_name(uid))
    }

    pub fn group(&mut self, gid: u32) -> Option<&str> {
        self.group.get(gid, || group_name(gid))
    }
}

// ----------------------------------------------------------- system metadata

pub fn statvfs_of(path: &str) -> Option<rustix::fs::StatVfs> {
    rustix::fs::statvfs(path).ok()
}

/// `uname().machine`
pub fn machine() -> String {
    rustix::system::uname().machine().to_string_lossy().into_owned()
}

pub fn sync_all() { rustix::fs::sync(); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_slots_are_per_response_and_do_not_mix_ids() {
        let mut slot = LastName::default();
        assert_eq!(slot.get(1, || Some("first".into())), Some("first"));
        assert_eq!(slot.get(1, || panic!("same response and ID")), Some("first"));
        assert_eq!(slot.get(2, || None), None);
        assert_eq!(slot.get(2, || panic!("missing identity is also a result")), None);
        assert_eq!(slot.get(1, || Some("changed".into())), Some("changed"));
        let mut next_response = LastName::default();
        assert_eq!(next_response.get(1, || Some("new response".into())), Some("new response"));
    }

    #[test]
    fn identity_lookup_handles_fragmented_lines_raw_names_and_duplicate_ids() {
        let bytes = b"invalid\nwrong:x:not-a-number\nus\xffer:x:41:9::/tmp:/bin/false\r\nlater:x:41:9\nlast:x:42";
        let mut input = BufReader::with_capacity(3, std::io::Cursor::new(bytes));
        assert_eq!(lookup_name_in(&mut input, 41).as_deref(), Some("us\u{fffd}er"));
        let mut input = BufReader::with_capacity(3, std::io::Cursor::new(bytes));
        assert_eq!(lookup_name_in(&mut input, 42).as_deref(), Some("last"));
        assert_eq!(lookup_name_in(&mut std::io::Cursor::new(b"last:x:42\r"), 42), None);
        assert_eq!(lookup_name_in(&mut std::io::Cursor::new(b"last:x:42\r\n"), 42).as_deref(), Some("last"));
    }

    #[test]
    fn identity_lookup_reopens_the_current_file() {
        let path = std::env::temp_dir().join(format!("rpcd-identity-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(&path).unwrap();
        std::io::Write::write_all(&mut file, b"first:x:7\n").unwrap();
        drop(file);
        assert_eq!(lookup_name(path.to_str().unwrap(), 7).as_deref(), Some("first"));
        let mut response = LastName::default();
        assert_eq!(response.get(7, || lookup_name(path.to_str().unwrap(), 7)), Some("first"));
        std::fs::write(&path, b"changed:x:7\n").unwrap();
        assert_eq!(lookup_name(path.to_str().unwrap(), 7).as_deref(), Some("changed"));
        assert_eq!(response.get(7, || lookup_name(path.to_str().unwrap(), 7)), Some("first"));
        let mut next_response = LastName::default();
        assert_eq!(next_response.get(7, || lookup_name(path.to_str().unwrap(), 7)), Some("changed"));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(lookup_name(path.to_str().unwrap(), 7), None);
    }

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
    fn base64_rejects_nonzero_padding_bits() {
        for input in [b"QR==".as_slice(), b"Qf==", b"QUJ=", b"Q U J =", b"////QR=="] {
            assert!(b64_decode(input).is_none(), "{input:?}");
        }
        for (input, expected) in [(b"QQ==".as_slice(), b"A".as_slice()), (b"QUI=", b"AB"), (b"QUJD", b"ABC")] {
            assert_eq!(b64_decode(input).as_deref(), Some(expected));
        }
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
