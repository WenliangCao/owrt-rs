//! Minimal glob(3)/fnmatch(3): `*`, `?`, `[...]` per path component, sorted
//! results (GLOB default), no `**`.

use std::path::Path;

pub fn fnmatch(pattern: &[u8], name: &[u8]) -> bool {
    fn m(p: &[u8], n: &[u8]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some(b'*') => (0..=n.len()).any(|i| m(&p[1..], &n[i..])),
            Some(b'?') => !n.is_empty() && m(&p[1..], &n[1..]),
            Some(b'[') => {
                let Some(end) = p.iter().skip(1).position(|&c| c == b']') else { return false };
                let class = &p[1..1 + end];
                let rest = &p[2 + end..];
                let Some(&c) = n.first() else { return false };
                let (negate, class) = match class.first() {
                    Some(b'!') | Some(b'^') => (true, &class[1..]),
                    _ => (false, class),
                };
                let mut hit = false;
                let mut i = 0;
                while i < class.len() {
                    if i + 2 < class.len() && class[i + 1] == b'-' {
                        if class[i] <= c && c <= class[i + 2] {
                            hit = true;
                        }
                        i += 3;
                    } else {
                        if class[i] == c {
                            hit = true;
                        }
                        i += 1;
                    }
                }
                hit != negate && m(rest, &n[1..])
            }
            Some(&c) => n.first() == Some(&c) && m(&p[1..], &n[1..]),
        }
    }
    m(pattern, name)
}

fn has_magic(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'*' | b'?' | b'['))
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
                        .filter(|n| !n.starts_with('.') || comp.starts_with('.'))
                        .filter(|n| fnmatch(comp.as_bytes(), n.as_bytes()))
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
    fn matching() {
        assert!(fnmatch(b"[SK][0-9][0-9]firewall", b"S19firewall"));
        assert!(!fnmatch(b"[SK][0-9][0-9]firewall", b"S1firewall"));
        assert!(fnmatch(b"*-port[0-9]*", b"1-0:1.0-port3"));
        assert!(fnmatch(b"[0-9]*", b"1-1"));
        assert!(!fnmatch(b"[0-9]*", b"usb1"));
        assert!(fnmatch(b"a?c", b"abc"));
    }
}
