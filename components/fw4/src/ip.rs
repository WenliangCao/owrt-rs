//! IP address helpers mirroring ucode's `iptoarr`/`arrtoip` (glibc
//! inet_pton/inet_ntop semantics) and fw4.uc's `to_mask`/`to_bits`/`apply_mask`.

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
    let words: Vec<u16> = (0..8).map(|i| ((a[2 * i] as u16) << 8) | a[2 * i + 1] as u16).collect();
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
        if i == 6
            && best_base == 0
            && (best_len == 6 || (best_len == 5 && words[5] == 0xffff))
        {
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

fn mask_byte(bits: i64, invert: bool) -> u8 {
    // (0xff << (8 - b)) & 0xff with 64-bit shift semantics
    let shifted = 8_i64.checked_sub(bits)
        .filter(|shift| (0..64).contains(shift))
        .map(|shift| 0xff_i64 << shift)
        .unwrap_or(0);
    let v = if invert { !shifted } else { shifted };
    (v & 0xff) as u8
}

/// fw4.uc `to_mask(bits, v6)`: prefix length to dotted/colon mask string.
pub fn to_mask(bits: i64, v6: bool) -> Option<String> {
    let (mut bits, invert) = (bits.checked_abs()?, bits < 0);
    let max = if v6 { 128 } else { 32 };
    if bits > max {
        return None;
    }
    let n = if v6 { 16 } else { 4 };
    let mut m = Vec::with_capacity(n);
    for _ in 0..n {
        let b = if bits < 8 { bits } else { 8 };
        m.push(mask_byte(b, invert));
        bits -= b;
    }
    arrtoip(&m)
}

/// fw4.uc `to_bits(mask)`: contiguous mask string to prefix length.
pub fn to_bits(mask: &str) -> Option<i64> {
    let mut a = iptoarr(mask)?;
    let mut bits = 0i64;
    let mut z = false;
    for byte in a.iter_mut() {
        z = z || *byte == 0;
        while !z && (*byte & 0x80) != 0 {
            *byte <<= 1;
            bits += 1;
        }
        if *byte != 0 {
            return None;
        }
    }
    Some(bits)
}

pub enum Mask<'a> {
    Bits(i64),
    Addr(&'a str),
}

/// fw4.uc `apply_mask(addr, mask)`.
pub fn apply_mask(addr: &str, mask: Mask) -> Option<String> {
    let mut a = iptoarr(addr)?;
    match mask {
        Mask::Bits(mut bits) => {
            for byte in a.iter_mut() {
                let b = if bits < 8 { bits } else { 8 };
                *byte &= mask_byte(b, false);
                bits -= b;
            }
        }
        Mask::Addr(m) => {
            let m = iptoarr(m)?;
            if m.len() != a.len() {
                return None;
            }
            for (byte, mb) in a.iter_mut().zip(m.iter()) {
                *byte &= mb;
            }
        }
    }
    arrtoip(&a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_parse() {
        assert_eq!(iptoarr("1.2.3.4"), Some(vec![1, 2, 3, 4]));
        assert_eq!(iptoarr("01.2.3.4"), None);
        assert_eq!(iptoarr("1.2.3"), None);
        assert_eq!(iptoarr("1.2.3.4/24"), None);
        assert_eq!(iptoarr(" 1.2.3.4"), None);
        assert_eq!(iptoarr("256.1.1.1"), None);
    }

    #[test]
    fn v6_parse_format() {
        let m = iptoarr("::ffff:1.2.3.4").unwrap();
        assert_eq!(&m[10..], &[255, 255, 1, 2, 3, 4]);
        assert_eq!(arrtoip(&m).unwrap(), "::ffff:1.2.3.4");
        assert_eq!(arrtoip(&iptoarr("::1.2.3.4").unwrap()).unwrap(), "::1.2.3.4");
        assert_eq!(arrtoip(&iptoarr("::").unwrap()).unwrap(), "::");
        assert_eq!(arrtoip(&iptoarr("2001:DB8::").unwrap()).unwrap(), "2001:db8::");
        assert_eq!(arrtoip(&iptoarr("0:1::1:0:0").unwrap()).unwrap(), "0:1::1:0:0");
        assert_eq!(arrtoip(&iptoarr("1::1").unwrap()).unwrap(), "1::1");
        assert_eq!(arrtoip(&iptoarr("fd63:e2f:f706::1").unwrap()).unwrap(), "fd63:e2f:f706::1");
        assert_eq!(arrtoip(&iptoarr("0:0:0:0:0:0:0:1").unwrap()).unwrap(), "::1");
        assert_eq!(arrtoip(&iptoarr("1:0:2:0:0:0:3:4").unwrap()).unwrap(), "1:0:2::3:4");
        assert_eq!(iptoarr("fe80::1%eth0"), None);
        assert_eq!(iptoarr("1:2:3:4:5:6:7:8:9"), None);
        assert_eq!(iptoarr("1:2:3:4:5:6:7:"), None);
        assert_eq!(iptoarr(":1::"), None);
        assert_eq!(iptoarr("1::2::3"), None);
        assert!(iptoarr("1:2:3:4:5:6:7:8").is_some());
        assert_eq!(iptoarr("1:2:3:4:5:6:7"), None);
        assert_eq!(iptoarr("::ffff:ffff:ffff:ffff").map(|a| a[8]), Some(255));
    }

    #[test]
    fn extreme_mask_lengths_do_not_overflow() {
        for bits in [i64::MIN, i64::MAX] {
            assert_eq!(to_mask(bits, false), None);
            assert_eq!(to_mask(bits, true), None);
        }
        assert_eq!(apply_mask("10.0.0.77", Mask::Bits(i64::MIN)), Some("0.0.0.0".into()));
        assert_eq!(apply_mask("10.0.0.77", Mask::Bits(i64::MAX)), Some("10.0.0.77".into()));
    }

    #[test]
    fn masks() {
        assert_eq!(to_mask(24, false).unwrap(), "255.255.255.0");
        assert_eq!(to_mask(0, false).unwrap(), "0.0.0.0");
        assert_eq!(to_mask(-8, false).unwrap(), "0.255.255.255");
        assert_eq!(to_mask(60, true).unwrap(), "ffff:ffff:ffff:fff0::");
        assert_eq!(to_mask(33, false), None);
        assert_eq!(to_bits("255.255.255.0"), Some(24));
        assert_eq!(to_bits("255.0.255.0"), None);
        assert_eq!(to_bits("::ffff:ffff:ffff:ffff"), None);
        assert_eq!(to_bits("ffff:ffff:ffff:fff0::"), Some(60));
        assert_eq!(apply_mask("10.0.0.77", Mask::Bits(24)).unwrap(), "10.0.0.0");
        assert_eq!(apply_mask("10.0.0.77", Mask::Addr("255.0.255.0")).unwrap(), "10.0.0.0");
        assert_eq!(apply_mask("2001:db8:1000::1", Mask::Bits(60)).unwrap(), "2001:db8:1000::");
        assert_eq!(apply_mask("2001:db8::1", Mask::Bits(128)).unwrap(), "2001:db8::1");
    }
}
