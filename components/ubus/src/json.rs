//! Minimal JSON value with parser and compact serializer. The parser accepts
//! the json-c leniencies OpenWrt relies on (trailing commas, C/C++ comments);
//! output format matches libubox blobmsg_format_json: no whitespace.

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    /// json-c and blobmsg STRING carry bytes, including non-UTF-8 SSIDs and
    /// file contents. Keep those bytes until a text-only caller asks for text.
    Bytes(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            Json::Bytes(s) => std::str::from_utf8(s).ok(),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Json::Str(s) => Some(s.as_bytes()),
            Json::Bytes(s) => Some(s),
            _ => None,
        }
    }

    pub fn from_string_bytes(bytes: Vec<u8>) -> Self {
        match String::from_utf8(bytes) {
            Ok(s) => Json::Str(s),
            Err(e) => Json::Bytes(e.into_bytes()),
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn to_compact(&self) -> String {
        // For text-only consumers. Wire/file consumers must use to_bytes().
        String::from_utf8_lossy(&self.to_bytes()).into_owned()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    /// Append compact wire JSON without allocating a separate output buffer.
    /// Byte strings and number formatting follow the same rules as to_bytes().
    pub fn append_to(&self, out: &mut Vec<u8>) {
        self.write(out);
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Json::Null => out.extend_from_slice(b"null"),
            Json::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
            Json::Int(i) => append_int(out, *i),
            Json::Float(f) => {
                let mut text = String::new();
                write_double(&mut text, *f);
                out.extend_from_slice(text.as_bytes());
            }
            Json::Str(s) => write_string(out, s.as_bytes()),
            Json::Bytes(s) => write_string(out, s),
            Json::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    item.write(out);
                }
                out.push(b']');
            }
            Json::Object(items) => {
                out.push(b'{');
                for (i, (k, v)) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write_string(out, k.as_bytes());
                    out.push(b':');
                    v.write(out);
                }
                out.push(b'}');
            }
        }
    }
}

// Two decimal digits per step; 20 bytes also hold the sign of i64::MIN.
// Keep formatting on the stack instead of allocating a String per field.
fn append_int(out: &mut Vec<u8>, value: i64) {
    const DIGITS: &[u8; 200] = b"00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899";
    let mut bytes = [0u8; 20];
    let mut end = bytes.len();
    let mut magnitude = value.unsigned_abs();
    while magnitude >= 100 {
        let pair = (magnitude % 100) as usize * 2;
        end -= 2;
        bytes[end..end + 2].copy_from_slice(&DIGITS[pair..pair + 2]);
        magnitude /= 100;
    }
    if magnitude < 10 {
        end -= 1;
        bytes[end] = b'0' + magnitude as u8;
    } else {
        let pair = magnitude as usize * 2;
        end -= 2;
        bytes[end..end + 2].copy_from_slice(&DIGITS[pair..pair + 2]);
    }
    if value < 0 {
        end -= 1;
        bytes[end] = b'-';
    }
    out.extend_from_slice(&bytes[end..]);
}

/// `printf("%.17g", d)` -- what libubox blobmsg_format_json emits for a DOUBLE
/// (blobmsg_json.c: `snprintf(buf, sizeof(buf), "%.17g", ...)`). Not the
/// shortest round-trip form: 0.1 prints as 0.10000000000000001.
fn write_double(out: &mut String, f: f64) {
    if !f.is_finite() {
        // glibc and musl print the sign bit, then inf/nan (invalid JSON, but
        // it is what the C library puts on the wire)
        if f.is_sign_negative() {
            out.push('-');
        }
        out.push_str(if f.is_nan() { "nan" } else { "inf" });
        return;
    }
    const PRECISION: i32 = 17;
    // %g: round to PRECISION significant digits, then pick %e or %f style
    // from the resulting decimal exponent X: %e when X < -4 or X >= P.
    let sci = format!("{:.*e}", (PRECISION - 1) as usize, f);
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let x: i32 = exp.parse().unwrap_or(0);
    if !(-4..PRECISION).contains(&x) {
        out.push_str(trim_fraction(mantissa));
        out.push('e');
        out.push(if x < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", x.abs()));
    } else {
        let fixed = format!("{:.*}", (PRECISION - 1 - x) as usize, f);
        out.push_str(trim_fraction(&fixed));
    }
}

/// %g without the `#` flag: trailing zeros of the fraction go, and so does a
/// decimal point left with nothing after it.
fn trim_fraction(s: &str) -> &str {
    if !s.contains('.') {
        return s;
    }
    let s = s.trim_end_matches('0');
    s.strip_suffix('.').unwrap_or(s)
}

// Detect any control byte, quote or backslash in eight bytes. The subtraction
// tests may also flag a neighbouring byte after a borrow; only the any-bit
// result is used, then the entire flagged block is checked byte by byte.
fn string_needs_escape(word: u64) -> bool {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let below_space = word.wrapping_sub(LO * 0x20) & !word & HI;
    let quote = word ^ (LO * u64::from(b'"'));
    let slash = word ^ (LO * u64::from(b'\\'));
    let quote = quote.wrapping_sub(LO) & !quote & HI;
    let slash = slash.wrapping_sub(LO) & !slash & HI;
    (below_space | quote | slash) != 0
}

pub(crate) fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    let mut start = 0;
    for (block_index, block) in s.chunks(8).enumerate() {
        if block.len() == 8 && !string_needs_escape(u64::from_ne_bytes(block.try_into().unwrap())) {
            continue;
        }
        let index = block_index * 8;
        if index != start {
            out.extend_from_slice(&s[start..index]);
        }
        // Escaped blocks keep the original scalar encoder. This avoids
        // repeated empty-range copies for adjacent escape characters.
        for &c in block {
            match c {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                8 => out.extend_from_slice(b"\\b"),
                c if c < 0x20 => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    out.extend_from_slice(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(c >> 4) as usize],
                        HEX[(c & 15) as usize],
                    ]);
                }
                c => out.push(c),
            }
        }
        start = index + block.len();
    }
    out.extend_from_slice(&s[start..]);
    out.push(b'"');
}

pub fn parse(input: &str) -> Result<Json, String> {
    parse_bytes(input.as_bytes())
}

pub fn parse_bytes(input: &[u8]) -> Result<Json, String> {
    let mut p = Parser {
        bytes: input,
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let value = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err("trailing characters".into());
    }
    Ok(value)
}

/// json_tokener_parse in its default (non-strict) mode: the first complete
/// value is returned and whatever follows it is ignored.
pub fn parse_prefix(input: &str) -> Result<Json, String> {
    parse_prefix_bytes(input.as_bytes())
}

pub fn parse_prefix_bytes(input: &[u8]) -> Result<Json, String> {
    let mut p = Parser {
        bytes: input,
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    p.value()
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        loop {
            while self.pos < self.bytes.len()
                && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
            {
                self.pos += 1;
            }
            if self.bytes[self.pos..].starts_with(b"//") {
                while self.pos < self.bytes.len() && self.bytes[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else if self.bytes[self.pos..].starts_with(b"/*") {
                self.pos += 2;
                while self.pos < self.bytes.len() && !self.bytes[self.pos..].starts_with(b"*/") {
                    self.pos += 1;
                }
                self.pos = (self.pos + 2).min(self.bytes.len());
            } else {
                return;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, literal: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(literal.as_bytes()) {
            self.pos += literal.len();
            Ok(value)
        } else {
            Err(format!("expected {literal}"))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        if self.depth > 64 {
            return Err("nesting too deep".into());
        }
        match self.peek() {
            None => Err("unexpected end".into()),
            Some(b'n') => self.expect("null", Json::Null),
            Some(b't') => self.expect("true", Json::Bool(true)),
            Some(b'f') => self.expect("false", Json::Bool(false)),
            Some(b'"') => self.string().map(Json::from_string_bytes),
            Some(b'[') => {
                self.pos += 1;
                self.depth += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Json::Array(items));
                }
                loop {
                    self.skip_ws();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        break;
                    }
                    items.push(self.value()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            break;
                        }
                        _ => return Err("expected , or ]".into()),
                    }
                }
                self.depth -= 1;
                Ok(Json::Array(items))
            }
            Some(b'{') => {
                self.pos += 1;
                self.depth += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Json::Object(items));
                }
                loop {
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        break;
                    }
                    if self.peek() != Some(b'"') {
                        return Err("expected string key".into());
                    }
                    let key = String::from_utf8(self.string()?).map_err(|_| "bad UTF-8 key")?;
                    self.skip_ws();
                    if self.peek() != Some(b':') {
                        return Err("expected :".into());
                    }
                    self.pos += 1;
                    self.skip_ws();
                    let value = self.value()?;
                    // json-c keeps a single entry per key (last value wins),
                    // preserving the first occurrence's position.
                    if let Some(slot) = items.iter_mut().find(|(k, _)| *k == key) {
                        slot.1 = value;
                    } else {
                        items.push((key, value));
                    }
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            break;
                        }
                        _ => return Err("expected , or }".into()),
                    }
                }
                self.depth -= 1;
                Ok(Json::Object(items))
            }
            Some(_) => self.number(),
        }
    }

    fn string(&mut self) -> Result<Vec<u8>, String> {
        self.pos += 1; // opening quote
        let mut out = Vec::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or("bad escape")?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xD800..0xDC00).contains(&code)
                                && self.bytes[self.pos..].starts_with(b"\\u")
                            {
                                self.pos += 2;
                                let low = self.hex4()?;
                                if (0xDC00..0xE000).contains(&low) {
                                    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                }
                            }
                            let mut bytes = [0; 4];
                            out.extend_from_slice(
                                char::from_u32(code)
                                    .unwrap_or('\u{fffd}')
                                    .encode_utf8(&mut bytes)
                                    .as_bytes(),
                            );
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => out.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let s = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or("bad \\u escape")?;
        self.pos += 4;
        u32::from_str_radix(std::str::from_utf8(s).map_err(|_| "bad hex")?, 16)
            .map_err(|_| "bad hex".into())
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        while self.pos < self.bytes.len()
            && matches!(
                self.bytes[self.pos],
                b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
            )
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| "bad number")?;
        if text.is_empty() {
            return Err("unexpected character".into());
        }
        if let Ok(i) = text.parse::<i64>() {
            return Ok(Json::Int(i));
        }
        text.parse::<f64>()
            .map(Json::Float)
            .map_err(|_| "bad number".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scalar_string(out: &mut Vec<u8>, s: &[u8]) {
        out.push(b'"');
        for &c in s {
            match c {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                8 => out.extend_from_slice(b"\\b"),
                c if c < 0x20 => out.extend_from_slice(format!("\\u{c:04x}").as_bytes()),
                c => out.push(c),
            }
        }
        out.push(b'"');
    }

    #[test]
    fn integer_output_matches_standard_formatting_at_boundaries_and_full_width() {
        let check = |value: i64| {
            let mut out = b"prefix".to_vec();
            Json::Int(value).append_to(&mut out);
            assert_eq!(out, format!("prefix{value}").as_bytes());
        };
        for value in [i64::MIN, i64::MIN + 1, i64::MAX - 1, i64::MAX] {
            check(value);
        }
        for value in -1000..=1000 {
            check(value);
        }
        let mut power = 1i64;
        loop {
            for value in [power - 1, power, power + 1] {
                check(value);
                check(-value);
            }
            let Some(next) = power.checked_mul(10) else {
                break;
            };
            power = next;
        }
        let mut random = 0x0123_4567_89ab_cdefu64;
        for _ in 0..100_000 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            check(random as i64);
        }
    }

    #[test]
    fn word_escape_detection_matches_scalar_bytes() {
        let check = |bytes: [u8; 8]| {
            let expected = bytes.iter().any(|&c| c < 0x20 || c == b'"' || c == b'\\');
            assert_eq!(
                string_needs_escape(u64::from_ne_bytes(bytes)),
                expected,
                "{bytes:?}"
            );
        };
        for background in [
            0, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x5b, 0x5c, 0x5d, 0x7f, 0x80, 0xff,
        ] {
            for lane in 0..8 {
                for byte in 0..=255 {
                    let mut bytes = [background; 8];
                    bytes[lane] = byte;
                    check(bytes);
                }
            }
        }
        let mut word = 0x0123_4567_89ab_cdefu64;
        for _ in 0..100_000 {
            word = word.wrapping_mul(6364136223846793005).wrapping_add(1);
            check(word.to_ne_bytes());
        }
    }

    #[test]
    fn bulk_string_runs_preserve_every_byte_and_append_boundary() {
        for offset in 0..32 {
            for byte in 0..=255u8 {
                let mut input = vec![b'a'; 64];
                input[offset] = byte;
                input[63 - offset] = byte;
                let mut expected = b"prefix".to_vec();
                scalar_string(&mut expected, &input);
                for spare in [0, 1, 7, 64, 128] {
                    let mut actual = Vec::with_capacity(6 + spare);
                    actual.extend_from_slice(b"prefix");
                    write_string(&mut actual, &input);
                    assert_eq!(actual, expected, "offset {offset}, byte {byte}");
                }
            }
        }
        // Exercise every tail length after zero, one and two complete words.
        for len in 1..=24 {
            for byte in [b'a', b'"', b'\\', 0, 0x1f, 0x80, 0xff] {
                let mut input = vec![b'a'; len];
                input[len - 1] = byte;
                let mut expected = Vec::new();
                scalar_string(&mut expected, &input);
                assert_eq!(Json::Bytes(input).to_bytes(), expected);
            }
        }
        for input in [
            vec![],
            (0..=255u8).collect(),
            vec![b'x'; 32768],
            b"\n\t\r\\\"\x08\x00\xff".repeat(100),
        ] {
            let mut expected = Vec::new();
            scalar_string(&mut expected, &input);
            assert_eq!(Json::Bytes(input).to_bytes(), expected);
        }
    }

    #[test]
    fn roundtrip() {
        let v = parse(r#"{"jsonrpc":"2.0","id":1,"method":"call","params":["0000",{"a":[true,null,-2,1.5,"x\"y"]}]}"#).unwrap();
        assert_eq!(v.get("method").and_then(Json::as_str), Some("call"));
        assert_eq!(
            v.to_compact(),
            r#"{"jsonrpc":"2.0","id":1,"method":"call","params":["0000",{"a":[true,null,-2,1.5,"x\"y"]}]}"#
        );
        assert_eq!(parse("[1,]").unwrap(), Json::Array(vec![Json::Int(1)]));
        assert_eq!(parse("{\"a\":1,}").unwrap().get("a"), Some(&Json::Int(1)));
        assert_eq!(
            parse("/* c */ [1, // x\n 2]").unwrap(),
            Json::Array(vec![Json::Int(1), Json::Int(2)])
        );
        assert!(parse("[1,,]").is_err());
        assert_eq!(parse(r#""é😀""#).unwrap(), Json::Str("é😀".into()));
        // libubox emits \u000c for form feed, not \f
        assert_eq!(Json::Str("a\u{0c}b".into()).to_compact(), r#""a\u000cb""#);
        // json-c keeps one entry per key, last value wins, first position
        let dup = parse(r#"{"a":1,"b":2,"a":3}"#).unwrap();
        assert_eq!(dup.to_compact(), r#"{"a":3,"b":2}"#);
    }

    // libubox prints doubles with "%.17g" (blobmsg_json.c). Expected strings
    // are the output of printf("%.17g") on glibc and musl for the same input.
    #[test]
    fn double_formatting_matches_printf_17g() {
        for (v, want) in [
            (0.1, "0.10000000000000001"),
            (1.1, "1.1000000000000001"),
            (0.3, "0.29999999999999999"),
            (0.5, "0.5"),
            (2.5, "2.5"),
            (-2.5, "-2.5"),
            (100.0, "100"),
            (0.0, "0"),
            (-0.0, "-0"),
            (12345.678, "12345.678"),
            (std::f64::consts::PI, "3.1415926535897931"),
            (1e15, "1000000000000000"),
            (1e16, "10000000000000000"),
            (1e17, "1e+17"),
            (1e20, "1e+20"),
            (1e21, "1e+21"),
            (123456789012345678.0, "1.2345678901234568e+17"),
            (9007199254740993.0, "9007199254740992"),
            (0.0001, "0.0001"),
            (0.00001, "1.0000000000000001e-05"),
            (1.5e-7, "1.4999999999999999e-07"),
            (1e-320, "9.9998886718268301e-321"),
            (5e-324, "4.9406564584124654e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (f64::MIN_POSITIVE, "2.2250738585072014e-308"),
            // exact ties at the 18th digit round half to even, as printf does
            (2f64.powi(-25), "2.9802322387695312e-08"),
            (3.0 * 2f64.powi(-25), "8.9406967163085938e-08"),
        ] {
            assert_eq!(Json::Float(v).to_compact(), want, "value {v:e}");
        }
        assert_eq!(Json::Float(f64::INFINITY).to_compact(), "inf");
        assert_eq!(Json::Float(f64::NEG_INFINITY).to_compact(), "-inf");
        assert_eq!(Json::Float(f64::NAN).to_compact(), "nan");
        assert_eq!(Json::Float(-f64::NAN).to_compact(), "-nan");
    }
}
