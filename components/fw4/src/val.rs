//! ucode value semantics needed for a faithful port: loose equality, numeric
//! and string coercion, truthiness, `to_array`.

use owrt_ubus::json::Json;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num {
    Int(i64),
    Dbl(f64),
}

impl Num {
    pub fn is_nan(self) -> bool {
        matches!(self, Num::Dbl(d) if d.is_nan())
    }
    pub fn as_f64(self) -> f64 {
        match self {
            Num::Int(i) => i as f64,
            Num::Dbl(d) => d,
        }
    }
    pub fn as_i64(self) -> i64 {
        match self {
            Num::Int(i) => i,
            Num::Dbl(d) => d as i64,
        }
    }
    /// ucode string conversion of a number ("" + n).
    pub fn to_ucode_string(self) -> String {
        match self {
            Num::Int(i) => i.to_string(),
            Num::Dbl(d) => fmt_double(d),
        }
    }
}

fn fmt_double(d: f64) -> String {
    if d.is_nan() {
        return "NaN".into();
    }
    if d.is_infinite() {
        return if d > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    if d == d.trunc() && d.abs() < 1e14 {
        return format!("{}", d as i64);
    }
    // %.14g
    let s = format!("{:.13e}", d);
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if !(-4..14).contains(&exp) {
        let mant = mant.trim_end_matches('0').trim_end_matches('.');
        return format!(
            "{}e{}{:02}",
            mant,
            if exp < 0 { '-' } else { '+' },
            exp.abs()
        );
    }
    let mut s = format!("{:.*}", (13 - exp).max(0) as usize, d);
    if s.contains('.') {
        s = s.trim_end_matches('0').trim_end_matches('.').to_owned();
    }
    s
}

/// ucode `+str` conversion.
pub fn parse_num_str(s: &str) -> Num {
    let t = s.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r');
    if t.is_empty() {
        return Num::Int(0);
    }
    let (neg, body) = match t.as_bytes()[0] {
        b'-' => (true, &t[1..]),
        b'+' => (false, &t[1..]),
        _ => (false, t),
    };
    if body.is_empty() {
        return Num::Dbl(f64::NAN);
    }
    // prefix test on bytes: `body` may start with a multi-byte character and
    // slicing a &str at byte 2 would panic (found by r29 with '名字')
    let radix = match body.as_bytes().get(..2) {
        Some(b"0x" | b"0X") if body.len() > 2 => Some((16, &body[2..])),
        Some(b"0b" | b"0B") if body.len() > 2 => Some((2, &body[2..])),
        Some(b"0o" | b"0O") if body.len() > 2 => Some((8, &body[2..])),
        _ => None,
    };
    if let Some((radix, digits)) = radix {
        if !digits.is_empty() && digits.chars().all(|c| c.is_digit(radix)) {
            return match i64::from_str_radix(digits, radix) {
                Ok(v) => Num::Int(if neg { -v } else { v }),
                Err(_) => match u64::from_str_radix(digits, radix) {
                    Ok(v) => Num::Dbl(if neg { -(v as f64) } else { v as f64 }),
                    Err(_) => Num::Dbl(f64::NAN),
                },
            };
        }
        return Num::Dbl(f64::NAN);
    }
    if body.bytes().all(|b| b.is_ascii_digit()) {
        return match body.parse::<i64>() {
            Ok(v) => Num::Int(if neg { -v } else { v }),
            Err(_) => Num::Dbl(
                body.parse::<f64>()
                    .map(|v| if neg { -v } else { v })
                    .unwrap_or(f64::NAN),
            ),
        };
    }
    // double: digits [. digits*] [e[+-]digits]
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return Num::Dbl(f64::NAN);
    }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        let mut j = i + 1;
        if j < bytes.len() && (bytes[j] == b'+' || bytes[j] == b'-') {
            j += 1;
        }
        let ds = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j == ds {
            return Num::Dbl(f64::NAN);
        }
        i = j;
    }
    if i != bytes.len() {
        return Num::Dbl(f64::NAN);
    }
    match body.parse::<f64>() {
        Ok(v) => Num::Dbl(if neg { -v } else { v }),
        Err(_) => Num::Dbl(f64::NAN),
    }
}

/// ucode `+val`.
pub fn to_num(v: &Json) -> Num {
    match v {
        Json::Null => Num::Int(0),
        Json::Bool(b) => Num::Int(*b as i64),
        Json::Int(i) => Num::Int(*i),
        Json::Float(f) => Num::Dbl(*f),
        Json::Str(s) => parse_num_str(s),
        Json::Bytes(s) => std::str::from_utf8(s)
            .map(parse_num_str)
            .unwrap_or(Num::Dbl(f64::NAN)),
        Json::Array(_) | Json::Object(_) => Num::Dbl(f64::NAN),
    }
}

/// ucode `"" + val`.
pub fn to_str(v: &Json) -> String {
    match v {
        Json::Null => "null".into(),
        Json::Bool(b) => {
            if *b {
                "true".into()
            } else {
                "false".into()
            }
        }
        Json::Int(i) => i.to_string(),
        Json::Float(f) => fmt_double(*f),
        Json::Str(s) => s.clone(),
        Json::Bytes(s) => String::from_utf8_lossy(s).into_owned(),
        Json::Array(_) | Json::Object(_) => {
            let mut out = String::new();
            ucode_json(v, &mut out);
            out
        }
    }
}

/// ucv_to_string for arrays/objects: JSON with ucode's spacing
/// (`[ "a", "b" ]`, `{ "k": "v" }`, `[ ]`), strings JSON-escaped, non-ASCII raw.
fn ucode_json(v: &Json, out: &mut String) {
    match v {
        Json::Array(a) => {
            out.push_str("[ ");
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                ucode_json(item, out);
            }
            out.push_str(" ]");
        }
        Json::Object(o) => {
            out.push_str("{ ");
            for (i, (k, item)) in o.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                ucode_quote(k, out);
                out.push_str(": ");
                ucode_json(item, out);
            }
            out.push_str(" }");
        }
        Json::Str(s) => ucode_quote(s, out),
        Json::Bytes(s) => ucode_quote(&String::from_utf8_lossy(s), out),
        other => out.push_str(&to_str(other)),
    }
}

fn ucode_quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ucode loose `==` against a string literal.
pub fn loose_eq_str(v: &Json, s: &str) -> bool {
    match v {
        Json::Str(x) => x == s,
        Json::Bytes(x) => x == s.as_bytes(),
        Json::Null => false,
        Json::Array(_) | Json::Object(_) => false,
        _ => {
            let a = to_num(v);
            let b = parse_num_str(s);
            !a.is_nan() && !b.is_nan() && a.as_f64() == b.as_f64()
        }
    }
}

/// ucode truthiness.
pub fn truthy(v: &Json) -> bool {
    match v {
        Json::Null => false,
        Json::Bool(b) => *b,
        Json::Int(i) => *i != 0,
        Json::Float(f) => *f != 0.0 && !f.is_nan(),
        Json::Str(s) => !s.is_empty(),
        Json::Bytes(s) => !s.is_empty(),
        Json::Array(_) | Json::Object(_) => true,
    }
}

/// fw4.uc `to_array(x)`.
pub fn to_array(v: &Json) -> Vec<Json> {
    match v {
        Json::Array(a) => a.clone(),
        Json::Null => Vec::new(),
        Json::Object(_) => vec![v.clone()],
        _ => {
            let s = to_str(v);
            let t = s.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r');
            if t.is_empty() {
                Vec::new()
            } else {
                t.split([' ', '\t'])
                    .filter(|p| !p.is_empty())
                    .map(|p| Json::Str(p.to_owned()))
                    .collect()
            }
        }
    }
}

/// ucode `trim()` (space, tab, CR, LF).
pub fn trim(s: &str) -> &str {
    s.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(parse_num_str("0x10"), Num::Int(16));
        assert_eq!(parse_num_str("010"), Num::Int(10));
        assert_eq!(parse_num_str(" 5 "), Num::Int(5));
        assert!(parse_num_str("abc").is_nan());
        assert_eq!(parse_num_str(""), Num::Int(0));
        assert_eq!(parse_num_str("1.5"), Num::Dbl(1.5));
        assert_eq!(parse_num_str("1e3"), Num::Dbl(1000.0));
        assert_eq!(parse_num_str("-5"), Num::Int(-5));
        assert!(parse_num_str("12abc").is_nan());
        assert_eq!(parse_num_str("0X1f"), Num::Int(31));
        assert_eq!(parse_num_str("+7"), Num::Int(7));
        assert_eq!(parse_num_str("0b11"), Num::Int(3));
        assert_eq!(parse_num_str("0o17"), Num::Int(15));
        assert_eq!(parse_num_str("1."), Num::Dbl(1.0));
        assert!(parse_num_str(".5").is_nan());
        assert!(parse_num_str("Infinity").is_nan());
        assert_eq!(Num::Dbl(1000.0).to_ucode_string(), "1000");
        assert_eq!(Num::Dbl(1.5).to_ucode_string(), "1.5");
        // ucode %.14g: switches to exponent at exp >= 14 or < -4.
        assert_eq!(Num::Dbl(1e14).to_ucode_string(), "1e+14");
        assert_eq!(Num::Dbl(-1e14).to_ucode_string(), "-1e+14");
        assert_eq!(Num::Dbl(1e13).to_ucode_string(), "10000000000000");
        assert_eq!(Num::Dbl(0.00001).to_ucode_string(), "1e-05");
        assert_eq!(Num::Dbl(0.0001).to_ucode_string(), "0.0001");
    }

    #[test]
    fn loose() {
        assert!(loose_eq_str(&Json::Int(0), "0"));
        assert!(loose_eq_str(&Json::Bool(true), "1"));
        assert!(loose_eq_str(&Json::Bool(false), "0"));
        assert!(loose_eq_str(&Json::Int(0), ""));
        assert!(!loose_eq_str(&Json::Int(1), "on"));
        assert!(loose_eq_str(&Json::Str("on".into()), "on"));
        assert_eq!(to_array(&Json::Str(" a  b\tc ".into())).len(), 3);
        assert_eq!(to_array(&Json::Int(0)), vec![Json::Str("0".into())]);
        assert_eq!(to_str(&Json::Float(100.0)), "100");
    }
}
