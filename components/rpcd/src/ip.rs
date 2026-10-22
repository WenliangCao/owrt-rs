//! ucode `iptoarr`/`arrtoip` (glibc inet_pton/inet_ntop semantics), used to
//! normalise conntrack addresses like sys.uc does.

pub fn iptoarr(s: &str) -> Option<Vec<u8>> {
    if let Some(v4) = parse_v4(s) {
        return Some(v4.to_vec());
    }
    parse_v6(s).map(|a| a.to_vec())
}

fn parse_v4(s: &str) -> Option<[u8; 4]> {
    if !s.is_ascii() {
        return None; // inet_pton: not an address; keeps the byte-index slicing below on char boundaries
    }
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        let v: u32 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        out[n] = v as u8;
        n += 1;
    }
    if n == 4 {
        Some(out)
    } else {
        None
    }
}

fn parse_v6(s: &str) -> Option<[u8; 16]> {
    if !s.is_ascii() {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut out = [0u8; 16];
    let mut pos = 0usize; // next byte to write
    let mut gap: Option<usize> = None; // byte position of "::"
    let mut i = 0usize;
    // leading "::"
    if bytes.starts_with(b"::") {
        gap = Some(0);
        i = 2;
        if i == bytes.len() {
            return Some(out);
        }
    } else if bytes[0] == b':' {
        return None;
    }
    loop {
        // parse one group
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let group = &s[start..i];
        if i < bytes.len() && bytes[i] == b'.' {
            // trailing dotted quad
            if pos + 4 > 16 {
                return None;
            }
            let v4 = parse_v4(&s[start..])?;
            out[pos..pos + 4].copy_from_slice(&v4);
            pos += 4;
            break;
        }
        if group.is_empty() || group.len() > 4 {
            return None;
        }
        if pos + 2 > 16 {
            return None;
        }
        let v = u16::from_str_radix(group, 16).ok()?;
        out[pos] = (v >> 8) as u8;
        out[pos + 1] = v as u8;
        pos += 2;
        if i == bytes.len() {
            break;
        }
        if bytes[i] != b':' {
            return None;
        }
        i += 1;
        if i < bytes.len() && bytes[i] == b':' {
            if gap.is_some() {
                return None;
            }
            gap = Some(pos);
            i += 1;
            if i == bytes.len() {
                break;
            }
        } else if i == bytes.len() {
            return None; // trailing single colon
        }
    }
    match gap {
        Some(g) => {
            if pos == 16 {
                return None;
            }
            let tail = pos - g;
            let mut res = [0u8; 16];
            res[..g].copy_from_slice(&out[..g]);
            res[16 - tail..].copy_from_slice(&out[g..pos]);
            Some(res)
        }
        None => {
            if pos == 16 {
                Some(out)
            } else {
                None
            }
        }
    }
}

pub fn arrtoip(a: &[u8]) -> Option<String> {
    match a.len() {
        4 => Some(format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])),
        16 => Some(format_v6(a)),
        _ => None,
    }
}

fn format_v6(a: &[u8]) -> String {
    let words: Vec<u16> = (0..8)
        .map(|i| ((a[2 * i] as u16) << 8) | a[2 * i + 1] as u16)
        .collect();
    // longest run of zero words (len >= 2), leftmost on tie
    let (mut best_base, mut best_len) = (-1i32, 0i32);
    let (mut cur_base, mut cur_len) = (-1i32, 0i32);
    for (i, w) in words.iter().enumerate() {
        if *w == 0 {
            if cur_base == -1 {
                cur_base = i as i32;
                cur_len = 1;
            } else {
                cur_len += 1;
            }
        } else if cur_base != -1 {
            if best_base == -1 || cur_len > best_len {
                best_base = cur_base;
                best_len = cur_len;
            }
            cur_base = -1;
        }
    }
    if cur_base != -1 && (best_base == -1 || cur_len > best_len) {
        best_base = cur_base;
        best_len = cur_len;
    }
    if best_base != -1 && best_len < 2 {
        best_base = -1;
    }
    let mut out = String::new();
    let mut i = 0usize;
    while i < 8 {
        if best_base != -1 && i as i32 >= best_base && (i as i32) < best_base + best_len {
            if i as i32 == best_base {
                out.push(':');
            }
            i += 1;
            continue;
        }
        if i != 0 {
            out.push(':');
        }
        if i == 6 && best_base == 0 && (best_len == 6 || (best_len == 5 && words[5] == 0xffff)) {
            out.push_str(&format!("{}.{}.{}.{}", a[12], a[13], a[14], a[15]));
            break;
        }
        out.push_str(&format!("{:x}", words[i]));
        i += 1;
    }
    if best_base != -1 && best_base + best_len == 8 {
        out.push(':');
    }
    out
}
