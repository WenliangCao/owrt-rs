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
            Json::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
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

fn write_string(out: &mut Vec<u8>, s: &[u8]) {
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
                            out.extend_from_slice(char::from_u32(code).unwrap_or('\u{fffd}')
                                .encode_utf8(&mut bytes).as_bytes());
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
        assert_eq!(parse("/* c */ [1, // x\n 2]").unwrap(), Json::Array(vec![Json::Int(1), Json::Int(2)]));
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
