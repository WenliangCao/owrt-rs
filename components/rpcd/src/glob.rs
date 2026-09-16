//! Minimal glob(3)/fnmatch(3): `*`, `?`, `[...]` per path component, sorted
//! results (GLOB default), no `**`.

use std::path::Path;

// fnmatch(3) comes from the same musl linked into the exact OpenWrt image.
// Keep the allocation-free literal / star path for normal ACL requests.
unsafe extern "C" {
    #[link_name = "fnmatch"]
    fn libc_fnmatch(pattern: *const std::ffi::c_char, name: *const std::ffi::c_char, flags: i32) -> i32;
}

pub fn fnmatch(pattern: &[u8], name: &[u8]) -> bool {
    match_with_flags(pattern, name, 2) // FNM_NOESCAPE: session ACL entries
}

pub fn fnmatch_escaped(pattern: &[u8], name: &[u8]) -> bool {
    match_with_flags(pattern, name, 0) // rpc_login_test_permission / glob
}

fn match_with_flags(pattern: &[u8], name: &[u8], flags: i32) -> bool {
    let pattern = pattern.split(|b| *b == 0).next().unwrap_or_default();
    let name = name.split(|b| *b == 0).next().unwrap_or_default();
    if pattern == b"*" { return true; }
    if !pattern.iter().any(|&b| matches!(b, b'*' | b'?' | b'[') || (flags == 0 && b == b'\\')) {
        return pattern == name;
    }
    // FNM_NOESCAPE makes a wildcard-free prefix literal, and a single trailing
    // star is the usual ACL shape (`net*`, `r*`). Non-ASCII stays with the
    // image libc's multibyte matcher.
    if flags == 2 && pattern.is_ascii() && name.is_ascii() {
        if let Some(prefix) = pattern.strip_suffix(b"*") {
            if !prefix.iter().any(|&b| matches!(b, b'*' | b'?' | b'[')) {
                return name.starts_with(prefix);
            }
        }
    }
    // NUL-terminated copies on the stack: ACL patterns and object names are
    // short, and an authorized request checks several per call.
    const STACK: usize = 256;
    if pattern.len() < STACK && name.len() < STACK {
        let mut p = [0u8; STACK];
        let mut n = [0u8; STACK];
        p[..pattern.len()].copy_from_slice(pattern);
        n[..name.len()].copy_from_slice(name);
        // SAFETY: both arrays are NUL-terminated (zero-filled past the copied
        // bytes, which contain no NUL) and outlive this synchronous call.
        return unsafe { libc_fnmatch(p.as_ptr().cast(), n.as_ptr().cast(), flags) == 0 };
    }
    let pattern = std::ffi::CString::new(pattern).unwrap();
    let name = std::ffi::CString::new(name).unwrap();
    // SAFETY: both NUL-terminated strings live through this synchronous call;
    // flags are the image's FNM_NOESCAPE or zero, with no pointer outputs.
    unsafe { libc_fnmatch(pattern.as_ptr(), name.as_ptr(), flags) == 0 }
}

fn has_magic(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'*' | b'?' | b'[' | b'\\'))
}

/// Expand `pattern` (absolute path) into sorted matching paths.
pub fn glob(pattern: &str) -> Vec<String> {
    let mut results = vec![String::new()];
    let absolute = pattern.starts_with('/');
    for comp in pattern.split('/').filter(|c| !c.is_empty()) {
        let mut next = Vec::new();
        for base in &results {
            let dir = if base.is_empty() { if absolute { "/".to_owned() } else { ".".to_owned() } } else { base.clone() };
            if has_magic(comp) {
                if let Ok(rd) = std::fs::read_dir(&dir) {
                    let mut names: Vec<String> = rd
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .filter(|n| !n.starts_with('.') || comp.starts_with('.') || comp.starts_with("\\."))
                        .filter(|n| fnmatch_escaped(comp.as_bytes(), n.as_bytes()))
                        .collect();
                    names.sort();
                    for n in names {
                        next.push(join(base, &n, absolute));
                    }
                }
            } else {
                let p = join(base, comp, absolute);
                if Path::new(&p).exists() || std::fs::symlink_metadata(&p).is_ok() {
                    next.push(p);
                }
            }
        }
        results = next;
        if results.is_empty() {
            break;
        }
    }
    results.retain(|r| !r.is_empty());
    results
}

fn join(base: &str, name: &str, absolute: bool) -> String {
    if base.is_empty() {
        if absolute { format!("/{name}") } else { name.to_owned() }
    } else {
        format!("{base}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_and_star_fast_paths_agree_with_the_matcher() {
        assert!(fnmatch(b"*", b""));
        assert!(fnmatch(b"*", b"anything/at all"));
        assert!(fnmatch(b"uci", b"uci"));
        assert!(!fnmatch(b"uci", b"uci2"));
        assert!(!fnmatch(b"uci", b"uc"));
        assert!(!fnmatch(b"", b"x"));
        assert!(fnmatch(b"", b""));
        assert!(fnmatch(b"net*", b"network"));
        assert!(!fnmatch(b"net*", b"nat"));
    }

    #[test]
    fn matching() {
        assert!(fnmatch(b"[SK][0-9][0-9]firewall", b"S19firewall"));
        assert!(!fnmatch(b"[SK][0-9][0-9]firewall", b"S1firewall"));
        assert!(fnmatch(b"*-port[0-9]*", b"1-0:1.0-port3"));
        assert!(fnmatch(b"[0-9]*", b"1-1"));
        assert!(!fnmatch(b"[0-9]*", b"usb1"));
        assert!(fnmatch(b"a?c", b"abc"));
    }
}
