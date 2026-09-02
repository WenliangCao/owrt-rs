//! HTTP/1.x request parsing and response writing with uhttpd's exact header
//! conventions (status line, Connection/Keep-Alive, chunked encoding, Date).

use std::io::{self, BufRead, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Head,
    Options,
    Put,
    Patch,
    Delete,
}

impl Method {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "GET" => Method::Get,
            "POST" => Method::Post,
            "HEAD" => Method::Head,
            "OPTIONS" => Method::Options,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "DELETE" => Method::Delete,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    V0_9,
    V1_0,
    V1_1,
}

impl Version {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "HTTP/0.9" => Version::V0_9,
            "HTTP/1.0" => Version::V1_0,
            "HTTP/1.1" => Version::V1_1,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Version::V0_9 => "HTTP/0.9",
            Version::V1_0 => "HTTP/1.0",
            Version::V1_1 => "HTTP/1.1",
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    pub version: Version,
    /// Raw request target as sent (path + query).
    pub url: String,
    /// Lower-cased header names in arrival order.
    pub headers: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub transfer_chunked: bool,
    pub connection_close: bool,
    pub expect_continue: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub enum ParseOutcome {
    Request(Request),
    /// Client closed before sending anything (keep-alive idle).
    Eof,
    /// Malformed request; respond with this status and close.
    Bad(u16, &'static str),
}

/// Outcome of a bounded head-line read.
enum HeadLine {
    /// A complete line (its trailing CRLF/LF included), within the cap.
    Line,
    /// Peer closed before any bytes of this line.
    Eof,
    /// The line exceeded the cap before a newline arrived.
    TooLong,
}

/// Read one line (up to and including LF) into `line`, buffering at most
/// `max` bytes. uhttpd caps the request/header buffer at 4 KiB and answers
/// 413 rather than reading an unbounded line into memory.
fn read_head_line<R: BufRead>(reader: &mut R, line: &mut String, max: usize) -> io::Result<HeadLine> {
    line.clear();
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            if raw.is_empty() {
                return Ok(HeadLine::Eof);
            }
            break;
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            if raw.len() + pos + 1 > max {
                return Ok(HeadLine::TooLong);
            }
            raw.extend_from_slice(&chunk[..=pos]);
            reader.consume(pos + 1);
            break;
        }
        let n = chunk.len();
        if raw.len() + n > max {
            reader.consume(n);
            return Ok(HeadLine::TooLong);
        }
        raw.extend_from_slice(chunk);
        reader.consume(n);
    }
    *line = String::from_utf8_lossy(&raw).into_owned();
    Ok(HeadLine::Line)
}

/// Read and parse one request head from `reader`.
pub fn read_request<R: BufRead>(reader: &mut R, keepalive: bool) -> io::Result<ParseOutcome> {
    let mut line = String::new();
    loop {
        match read_head_line(reader, &mut line, 4096)? {
            HeadLine::Eof => return Ok(ParseOutcome::Eof),
            HeadLine::TooLong => {
                return Ok(ParseOutcome::Bad(413, "Request Entity Too Large"))
            }
            HeadLine::Line => {}
        }
        if line == "\r\n" || line == "\n" {
            continue;
        }
        break;
    }
    let mut parts = line.trim_end_matches(['\r', '\n']).split(' ');
    let (Some(method), Some(url), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Ok(ParseOutcome::Bad(400, "Bad Request"));
    };
    let (Some(method), Some(version)) = (Method::parse(method), Version::parse(version)) else {
        return Ok(ParseOutcome::Bad(400, "Bad Request"));
    };
    let mut request = Request {
        method,
        version,
        url: url.to_owned(),
        headers: Vec::new(),
        content_length: None,
        transfer_chunked: false,
        connection_close: version < Version::V1_1 || !keepalive,
        expect_continue: false,
    };
    let mut content_lengths = 0;
    let mut transfer_encodings = 0;
    loop {
        match read_head_line(reader, &mut line, 4096)? {
            HeadLine::Eof => return Ok(ParseOutcome::Bad(400, "Bad Request")),
            HeadLine::TooLong => {
                return Ok(ParseOutcome::Bad(413, "Request Entity Too Large"))
            }
            HeadLine::Line => {}
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Ok(ParseOutcome::Bad(400, "Bad Request"));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        match name.as_str() {
            "expect" => {
                if value.eq_ignore_ascii_case("100-continue") {
                    request.expect_continue = true;
                } else {
                    return Ok(ParseOutcome::Bad(412, "Precondition Failed"));
                }
            }
            "content-length" => {
                content_lengths += 1;
                match value.parse::<usize>() {
                    Ok(n) if n <= i32::MAX as usize => request.content_length = Some(n),
                    _ => return Ok(ParseOutcome::Bad(400, "Bad Request")),
                }
            }
            "transfer-encoding" => {
                transfer_encodings += 1;
                if value.eq_ignore_ascii_case("chunked") {
                    request.transfer_chunked = true;
                } else {
                    return Ok(ParseOutcome::Bad(501, "Not Implemented"));
                }
            }
            "connection" => {
                if value.eq_ignore_ascii_case("close") {
                    request.connection_close = true;
                }
            }
            "user-agent" if value.contains("Safari/") && value.contains("Mac OS X") => {
                request.connection_close = true;
            }
            _ => {}
        }
        request.headers.push((name, value));
    }
    if content_lengths > 1 || (content_lengths > 0 && transfer_encodings > 0) {
        return Ok(ParseOutcome::Bad(400, "Bad Request"));
    }
    Ok(ParseOutcome::Request(request))
}

/// Read the request body (Content-Length or chunked) fully, bounded by `limit`.
pub fn read_body<R: BufRead>(
    reader: &mut R,
    request: &Request,
    limit: usize,
) -> io::Result<Option<Vec<u8>>> {
    if request.transfer_chunked {
        let mut body = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            let size_text = line.trim().split(';').next().unwrap_or("");
            let size =
                usize::from_str_radix(size_text, 16).map_err(|_| io::Error::other("bad chunk"))?;
            if size == 0 {
                // trailer + final CRLF
                loop {
                    line.clear();
                    if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                return Ok(Some(body));
            }
            if body.len() + size > limit {
                return Ok(None);
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);
            line.clear();
            reader.read_line(&mut line)?;
        }
    }
    let length = request.content_length.unwrap_or(0);
    if length > limit {
        return Ok(None);
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Response writer following uhttpd's framing rules.
pub struct Response<'a, W: Write> {
    out: &'a mut W,
    version: Version,
    method: Method,
    connection_close: bool,
    keepalive_timeout: u32,
    code: u16,
    chunked: bool,
    disable_chunked: bool,
    headers_done: bool,
}

impl<'a, W: Write> Response<'a, W> {
    pub fn new(out: &'a mut W, request: &Request, keepalive_timeout: u32) -> Self {
        Self {
            out,
            version: request.version,
            method: request.method,
            connection_close: request.connection_close,
            keepalive_timeout,
            code: 200,
            chunked: false,
            disable_chunked: false,
            headers_done: false,
        }
    }

    pub fn force_close(&mut self) {
        self.connection_close = true;
    }

    pub fn connection_close(&self) -> bool {
        self.connection_close
    }

    /// Disable chunked framing (the handler sets Content-Length itself).
    pub fn disable_chunked(&mut self) {
        self.disable_chunked = true;
    }

    fn use_chunked(&self) -> bool {
        self.version == Version::V1_1
            && !matches!(self.method, Method::Head | Method::Options)
            && self.code != 204
            && self.code != 304
            && !self.disable_chunked
    }

    /// Status line plus Connection/Transfer-Encoding/Keep-Alive headers.
    pub fn status(&mut self, code: u16, summary: &str) -> io::Result<()> {
        self.code = code;
        self.chunked = self.use_chunked();
        let conn = if self.connection_close {
            "Connection: close"
        } else {
            "Connection: Keep-Alive"
        };
        let enc = if self.chunked {
            "Transfer-Encoding: chunked\r\n"
        } else {
            ""
        };
        write!(
            self.out,
            "{} {:03} {}\r\n{}\r\n{}",
            self.version.name(),
            code,
            summary,
            conn,
            enc
        )?;
        if !self.connection_close {
            write!(
                self.out,
                "Keep-Alive: timeout={}\r\n",
                self.keepalive_timeout
            )?;
        }
        Ok(())
    }

    pub fn header(&mut self, name: &str, value: &str) -> io::Result<()> {
        write!(self.out, "{name}: {value}\r\n")
    }

    /// End of headers.
    pub fn end_headers(&mut self) -> io::Result<()> {
        self.headers_done = true;
        self.out.write_all(b"\r\n")
    }

    pub fn is_head(&self) -> bool {
        self.method == Method::Head
    }

    /// Whether the current response uses chunked framing (valid after `status`).
    pub fn chunked(&self) -> bool {
        self.chunked
    }

    /// Body data (chunk-framed when applicable).
    pub fn body(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.chunked {
            write!(self.out, "{:X}\r\n", data.len())?;
            self.out.write_all(data)?;
            self.out.write_all(b"\r\n")
        } else {
            self.out.write_all(data)
        }
    }

    /// Finish the response.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.chunked {
            self.out.write_all(b"0\r\n\r\n")?;
        }
        self.out.flush()
    }

    /// uhttpd's error page.
    pub fn error(&mut self, code: u16, summary: &str, detail: Option<&str>) -> io::Result<()> {
        self.status(code, summary)?;
        self.header("Content-Type", "text/html")?;
        self.end_headers()?;
        self.body(format!("<h1>{summary}</h1>").as_bytes())?;
        if let Some(detail) = detail {
            self.body(detail.as_bytes())?;
        }
        self.finish()
    }
}

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// RFC 1123 date, e.g. `Mon, 29 Jun 2026 12:59:20 GMT`.
pub fn http_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let weekday = (days + 4).rem_euclid(7) as usize;
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse RFC 1123 / RFC 850 / asctime dates like uhttpd's strptime fallbacks.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let s = s.trim();
    let tokens: Vec<&str> = s
        .split([' ', ',', '-', ':'])
        .filter(|t| !t.is_empty())
        .collect();
    // RFC1123: Sun 06 Nov 1994 08:49:37 GMT  -> [Sun, 06, Nov, 1994, 08, 49, 37, GMT]
    // asctime: Sun Nov  6 08:49:37 1994      -> [Sun, Nov, 6, 08, 49, 37, 1994]
    if tokens.len() < 7 {
        return None;
    }
    let month = |t: &str| {
        MONTHS
            .iter()
            .position(|m| m.eq_ignore_ascii_case(t))
            .map(|i| i as u32 + 1)
    };
    let (d, m, y, hh, mm, ss) = match (month(tokens[2]), month(tokens[1])) {
        (Some(m), _) => {
            let y: i64 = tokens[3].parse().ok()?;
            let y = if y < 100 { y + 1900 } else { y };
            (
                tokens[1].parse().ok()?,
                m,
                y,
                tokens[4],
                tokens[5],
                tokens[6],
            )
        }
        (None, Some(m)) => (
            tokens[2].parse().ok()?,
            m,
            tokens[6].parse().ok()?,
            tokens[3],
            tokens[4],
            tokens[5],
        ),
        (None, None) => return None,
    };
    let hh: i64 = hh.parse().ok()?;
    let mm: i64 = mm.parse().ok()?;
    let ss: i64 = ss.parse().ok()?;
    Some(days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss)
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

/// Percent-decode a URL path component; None on malformed escapes.
pub fn url_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let value = u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_roundtrip() {
        let s = http_date(1782737960);
        assert_eq!(s, "Mon, 29 Jun 2026 12:59:20 GMT");
        assert_eq!(parse_http_date(&s), Some(1782737960));
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(784111777));
    }

    #[test]
    fn parses_request_and_rejects_conflicting_framing() {
        let mut input = io::Cursor::new(b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec());
        match read_request(&mut input, true).unwrap() {
            ParseOutcome::Bad(400, _) => {}
            other => panic!("unexpected {:?}", matches!(other, ParseOutcome::Eof)),
        }
        let mut input = io::Cursor::new(b"HEAD /x HTTP/1.0\r\nHost: y\r\n\r\n".to_vec());
        let ParseOutcome::Request(r) = read_request(&mut input, true).unwrap() else {
            panic!()
        };
        assert_eq!(r.method, Method::Head);
        assert!(r.connection_close);
        assert_eq!(r.header("host"), Some("y"));
    }
}
