//! Minimal JSON value with parser and compact serializer (RFC 8259 subset,
//! output format matches libubox blobmsg_format_json: no whitespace).

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
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
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn to_compact(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => out.push_str(&i.to_string()),
            Json::Float(f) => {
                if f.is_finite() {
                    let s = format!("{f}");
                    out.push_str(&s);
                } else {
                    out.push_str("null");
                }
            }
            Json::Str(s) => write_string(out, s),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(items) => {
                out.push('{');
                for (i, (k, v)) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn parse(input: &str) -> Result<Json, String> {
    let mut p = Parser {
        bytes: input.as_bytes(),
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

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
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
            Some(b'"') => self.string().map(Json::Str),
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
                    if self.peek() != Some(b'"') {
                        return Err("expected string key".into());
                    }
                    let key = self.string()?;
                    self.skip_ws();
                    if self.peek() != Some(b':') {
                        return Err("expected :".into());
                    }
                    self.pos += 1;
                    self.skip_ws();
                    let value = self.value()?;
                    items.push((key, value));
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

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or("bad escape")?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
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
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => {
                    // copy one UTF-8 sequence
                    let start = self.pos - 1;
                    let len = utf8_len(c);
                    let end = (start + len).min(self.bytes.len());
                    out.push_str(
                        std::str::from_utf8(&self.bytes[start..end]).map_err(|_| "bad utf8")?,
                    );
                    self.pos = end;
                }
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

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

#[allow(dead_code)]
pub type Map = BTreeMap<String, Json>;

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
        assert!(parse("[1,]").is_err());
        assert_eq!(parse(r#""é😀""#).unwrap(), Json::Str("é😀".into()));
    }
}
