//! HTTP/1.x request parsing and response writing with uhttpd's exact header
//! conventions (status line, Connection/Keep-Alive, chunked encoding, Date).

use std::cell::RefCell;
use owrt_ubus::sys::{poll_fds, PollFd, POLLOUT};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::RawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Malformed request; respond with this status and close. `version` is
    /// the one uhttpd would put on the status line (1.0 when the request line
    /// itself was bad, else the parsed one); `body` says whether uhttpd sends
    /// the `<h1>summary</h1>` body (request-line errors) or none (header
    /// errors, `uh_header_error`).
    Bad { code: u16, summary: &'static str, version: Version, body: bool },
}

fn bad_line(code: u16, summary: &'static str) -> ParseOutcome {
    ParseOutcome::Bad { code, summary, version: Version::V1_0, body: true }
}

fn bad_header(code: u16, summary: &'static str, version: Version) -> ParseOutcome {
    ParseOutcome::Bad { code, summary, version, body: false }
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
                return Ok(bad_line(413, "Request Entity Too Large"))
            }
            HeadLine::Line => {}
        }
        if line == "\r\n" || line == "\n" {
            continue;
        }
        break;
    }
    // strtok(data, " "): runs of spaces separate the three tokens, extra tokens are ignored
    let mut parts = line.trim_end_matches(['\r', '\n']).split(' ').filter(|t| !t.is_empty());
    let (Some(method), Some(url), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Ok(bad_line(400, "Bad Request"));
    };
    let (Some(method), Some(version)) = (Method::parse(method), Version::parse(version)) else {
        return Ok(bad_line(400, "Bad Request"));
    };
    // DEVIATION: uhttpd decodes %00 into a NUL that silently truncates the path
    // (C string); a NUL cannot be passed to the CGI environment or the file
    // lookup, so it is rejected instead of truncated.
    if url_decode(url.split('?').next().unwrap_or("")).is_some_and(|d| d.contains(&0)) {
        return Ok(bad_line(400, "Bad Request"));
    }
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
            HeadLine::Eof => return Ok(bad_header(400, "Bad Request", version)),
            HeadLine::TooLong => {
                return Ok(bad_header(413, "Request Entity Too Large", version))
            }
            HeadLine::Line => {}
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Ok(bad_header(400, "Bad Request", version));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        match name.as_str() {
            "expect" => {
                if value.eq_ignore_ascii_case("100-continue") {
                    request.expect_continue = true;
                } else {
                    return Ok(bad_header(412, "Precondition Failed", version));
                }
            }
            "content-length" => {
                content_lengths += 1;
                match value.parse::<usize>() {
                    Ok(n) if n <= i32::MAX as usize => request.content_length = Some(n),
                    _ => return Ok(bad_header(400, "Bad Request", version)),
                }
            }
            "transfer-encoding" => {
                transfer_encodings += 1;
                if value.eq_ignore_ascii_case("chunked") {
                    request.transfer_chunked = true;
                } else {
                    return Ok(bad_header(501, "Not Implemented", version));
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
        // uhttpd reports conflicting framing through uh_client_error, i.e. with a body
        return Ok(ParseOutcome::Bad { code: 400, summary: "Bad Request", version, body: true });
    }
    Ok(ParseOutcome::Request(request))
}

/// Response transport. `Response` itself only needs `Write`; the CGI relay
/// also drives readiness and deadlines itself, so it needs the rest: uhttpd
/// runs the whole exchange on one uloop, and a blocking write anywhere in the
/// relay is what let a stalled client outlive the script timeout.
pub trait Sink: Write {
    /// Bytes buffered here that the transport has not accepted yet.
    fn pending(&self) -> usize;
    /// Hand the transport whatever it will take right now. Never blocks.
    fn drain_ready(&mut self) -> io::Result<()>;
    /// While set, `write` only buffers: the caller owns readiness and calls
    /// `drain_ready` itself. The CGI relay needs this, because a drain inside
    /// `write` is exactly the blocking step that outlives the script deadline.
    fn set_deferred(&mut self, on: bool);
    /// Transport descriptor, for readiness polling.
    fn fd(&self) -> RawFd;
}

/// Response transport: a bounded window in front of the client. One stream
/// carries both directions and the CGI relay alternates between them, so the
/// borrow is taken per operation and never held across one.
///
/// `Write` keeps the window bounded by draining when it fills, which is what
/// the ordinary handlers want. The CGI relay instead polls and calls
/// `drain_ready`, so no write of its can outlast the script deadline.
pub struct Out<'a, T: Read + Write> {
    client: &'a RefCell<BufReader<T>>,
    fd: RawFd,
    buf: Vec<u8>,
    window: usize,
    /// Budget for one blocking drain, from the configured network timeout.
    timeout: Duration,
    deferred: bool,
}

impl<'a, T: Read + Write> Out<'a, T> {
    pub fn new(client: &'a RefCell<BufReader<T>>, fd: RawFd, window: usize, timeout: Duration) -> Self {
        Out { client, fd, buf: Vec::new(), window, timeout, deferred: false }
    }

    /// Push until the window is empty, waiting for writability as needed.
    /// Push until the window is empty. The budget covers the whole drain, not
    /// one write, so many small partial writes cannot extend it.
    fn drain_blocking(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + self.timeout;
        while !self.buf.is_empty() {
            let before = self.buf.len();
            self.drain_ready()?;
            if self.buf.len() == before {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "response write deadline"));
                }
                let mut pfd = [PollFd { fd: self.fd, events: POLLOUT, revents: 0 }];
                if poll_fds(&mut pfd, left.as_millis().min(i32::MAX as u128) as i32)? == 0 {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "response write deadline"));
                }
            }
        }
        Ok(())
    }
}

impl<T: Read + Write> Sink for Out<'_, T> {
    fn pending(&self) -> usize {
        self.buf.len()
    }

    fn drain_ready(&mut self) -> io::Result<()> {
        while !self.buf.is_empty() {
            match borrow(self.client)?.get_mut().write(&self.buf) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "client accepted nothing")),
                Ok(n) => {
                    self.buf.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn set_deferred(&mut self, on: bool) {
        self.deferred = on;
    }

    fn fd(&self) -> RawFd {
        self.fd
    }
}

impl<T: Read + Write> Write for Out<'_, T> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if !self.deferred && self.buf.len() >= self.window {
            self.drain_blocking()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.deferred {
            return Ok(());
        }
        self.drain_blocking()?;
        borrow(self.client)?.get_mut().flush()
    }
}


/// A failed borrow would mean read and write nested, which is a bug here. Turn
/// it into an I/O error rather than panicking a connection thread.
fn borrow<T>(cell: &RefCell<T>) -> io::Result<std::cell::RefMut<'_, T>> {
    cell.try_borrow_mut().map_err(|_| io::Error::other("client stream already borrowed"))
}

/// Where the chunked decoder is between calls, so a client that stops
/// mid-framing pauses the decoder instead of blocking inside it.
enum Stage {
    /// Reading the "<hex>\r\n" size line.
    Size,
    /// Passing chunk data through.
    Data,
    /// Consuming the CRLF that closes a chunk.
    AfterChunk,
    /// Reading the trailer section that follows the 0-size chunk.
    Trailer,
}

/// Incremental request-body decoder: Content-Length or chunked, pulled in
/// bounded steps so a large upload never has to sit in memory.
///
/// Every call is resumable. When the client has sent nothing more, the
/// underlying non-blocking read surfaces as `WouldBlock` and the decoder keeps
/// its partial state, so the caller can go do something else (consume the
/// script's output, check the deadline) and come back.
///
/// It borrows the client through a `RefCell` because the same stream carries
/// the response: the relay alternates between pulling body bytes and pushing
/// relayed output, and each borrow lasts only for one operation.
pub struct BodyReader<'a, R: BufRead> {
    src: &'a RefCell<R>,
    framing: Framing,
    /// Bytes still owed by the current chunk (chunked framing only).
    chunk_left: u64,
    stage: Stage,
    /// Partial size or trailer line carried between calls.
    line: Vec<u8>,
    /// Total trailer bytes and lines, so endless short trailers cannot stall us.
    trailer_bytes: usize,
    trailer_lines: usize,
    done: bool,
    /// Set when framing turned out to be malformed; the connection cannot be
    /// reused because we no longer know where the next request starts.
    bad: bool,
}

enum Framing {
    None,
    Length(u64),
    Chunked,
}

/// Cap on one chunk size line or trailer line.
const CHUNK_LINE_MAX: usize = 4096;
/// Cap on the whole trailer section.
const TRAILER_MAX: usize = 8192;
const TRAILER_LINES_MAX: usize = 64;

impl<'a, R: BufRead> BodyReader<'a, R> {
    pub fn new(src: &'a RefCell<R>, request: &Request) -> Self {
        let framing = if request.transfer_chunked {
            Framing::Chunked
        } else {
            match request.content_length.unwrap_or(0) {
                0 => Framing::None,
                n => Framing::Length(n as u64),
            }
        };
        let done = matches!(framing, Framing::None);
        BodyReader {
            src,
            framing,
            chunk_left: 0,
            stage: Stage::Size,
            line: Vec::new(),
            trailer_bytes: 0,
            trailer_lines: 0,
            done,
            bad: false,
        }
    }

    /// Whether the request carries a body at all.
    pub fn present(&self) -> bool {
        !matches!(self.framing, Framing::None)
    }

    /// Body fully read and framing intact, i.e. the connection may be reused.
    pub fn reusable(&self) -> bool {
        self.done && !self.bad
    }

    /// Next slice of decoded body. `Ok(0)` is the end of the body;
    /// `WouldBlock` means "nothing more from the client yet, ask again".
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        match self.framing {
            Framing::None => Ok(0),
            Framing::Length(left) => {
                let want = buf.len().min(left as usize);
                let n = {
                    let mut src = self.src.borrow_mut();
                    src.read(&mut buf[..want])?
                };
                if n == 0 {
                    return Err(self.fail(io::ErrorKind::UnexpectedEof, "body ended early"));
                }
                let left = left - n as u64;
                self.framing = Framing::Length(left);
                self.done = left == 0;
                Ok(n)
            }
            Framing::Chunked => self.read_chunked(buf),
        }
    }

    fn read_chunked(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.stage {
                Stage::Size => {
                    let Some(line) = self.take_line(CHUNK_LINE_MAX)? else { continue };
                    let text = String::from_utf8_lossy(&line).into_owned();
                    let size_text = text.trim().split(';').next().unwrap_or("");
                    let Ok(size) = u64::from_str_radix(size_text, 16) else {
                        return Err(self.fail(io::ErrorKind::InvalidData, "bad chunk size"));
                    };
                    if size == 0 {
                        self.stage = Stage::Trailer;
                    } else {
                        self.chunk_left = size;
                        self.stage = Stage::Data;
                    }
                }
                Stage::Data => {
                    let want = buf.len().min(self.chunk_left as usize);
                    let n = {
                        let mut src = self.src.borrow_mut();
                        src.read(&mut buf[..want])?
                    };
                    if n == 0 {
                        return Err(self.fail(io::ErrorKind::UnexpectedEof, "truncated chunk"));
                    }
                    self.chunk_left -= n as u64;
                    if self.chunk_left == 0 {
                        self.stage = Stage::AfterChunk;
                    }
                    return Ok(n);
                }
                Stage::AfterChunk => {
                    let Some(line) = self.take_line(2)? else { continue };
                    if !line.is_empty() {
                        return Err(self.fail(io::ErrorKind::InvalidData, "missing chunk terminator"));
                    }
                    self.stage = Stage::Size;
                }
                Stage::Trailer => {
                    let Some(line) = self.take_line(CHUNK_LINE_MAX)? else { continue };
                    if line.is_empty() {
                        self.done = true;
                        return Ok(0);
                    }
                    self.trailer_lines += 1;
                    self.trailer_bytes += line.len();
                    if self.trailer_lines > TRAILER_LINES_MAX || self.trailer_bytes > TRAILER_MAX {
                        return Err(self.fail(io::ErrorKind::InvalidData, "trailer section too large"));
                    }
                }
            }
        }
    }

    /// Pull one CRLF-terminated line without blocking, resuming across calls.
    /// `Ok(None)` means the line is complete and the loop should re-dispatch
    /// (it is returned through `self.line` being taken); `WouldBlock` means the
    /// client owes us more bytes.
    #[allow(clippy::type_complexity)]
    fn take_line(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        loop {
            let (found, used) = {
                let mut src = self.src.borrow_mut();
                let available = src.fill_buf()?;
                if available.is_empty() {
                    return Err(self.fail(io::ErrorKind::UnexpectedEof, "body ended inside framing"));
                }
                match available.iter().position(|&b| b == b'\n') {
                    Some(pos) => {
                        self.line.extend_from_slice(&available[..pos]);
                        (true, pos + 1)
                    }
                    None => {
                        let take = available.len();
                        self.line.extend_from_slice(available);
                        (false, take)
                    }
                }
            };
            self.src.borrow_mut().consume(used);
            if self.line.len() > max {
                return Err(self.fail(io::ErrorKind::InvalidData, "framing line too long"));
            }
            if found {
                let mut line = std::mem::take(&mut self.line);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
        }
    }

    fn fail(&mut self, kind: io::ErrorKind, what: &'static str) -> io::Error {
        self.bad = true;
        self.done = true;
        io::Error::new(kind, what)
    }

    /// Collect the whole body, refusing anything over `limit`. For the small
    /// fixed-size endpoints (`/ubus`); CGI streams instead. Blocking: only used
    /// on paths where the socket is still in blocking mode.
    pub fn read_all(&mut self, limit: usize) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = self.read(&mut buf)?;
            if n == 0 {
                return Ok(Some(out));
            }
            if out.len() + n > limit {
                // reading on is pointless: framing stays unfinished, so the
                // caller must close the connection
                self.bad = true;
                self.done = true;
                return Ok(None);
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    /// Read and discard the rest, up to `limit`, so a keep-alive connection can
    /// survive a body the handler did not want. Returns false if it did not fit.
    pub fn drain(&mut self, limit: usize) -> bool {
        let mut left = limit;
        let mut buf = [0u8; 8192];
        while !self.done {
            match self.read(&mut buf) {
                Ok(0) => break,
                Ok(n) if n <= left => left -= n,
                _ => return false,
            }
        }
        self.reusable()
    }
}

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

    /// The transport underneath, for a handler that drives readiness itself.
    pub fn sink(&mut self) -> &mut W {
        self.out
    }

    /// Finish the response.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.chunked {
            self.out.write_all(b"0\r\n\r\n")?;
        }
        self.out.flush()
    }

    /// uhttpd's error page.
    /// uh_header_error: status + Content-Type, no body.
    pub fn error_no_body(&mut self, code: u16, summary: &str) -> io::Result<()> {
        self.status(code, summary)?;
        self.header("Content-Type", "text/html")?;
        self.end_headers()?;
        self.finish()
    }

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
            ParseOutcome::Bad { code: 400, .. } => {}
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

    #[test]
    fn chunked_body_is_decoded_incrementally_and_rejects_bad_framing() {
        fn drain(input: &[u8], chunked: bool, len: Option<usize>) -> io::Result<Vec<u8>> {
            let request = Request {
                method: Method::Post,
                version: Version::V1_1,
                url: "/".into(),
                headers: Vec::new(),
                content_length: len,
                transfer_chunked: chunked,
                connection_close: false,
                expect_continue: false,
            };
            let cell = RefCell::new(io::BufReader::new(io::Cursor::new(input.to_vec())));
            let mut body = BodyReader::new(&cell, &request);
            let mut out = Vec::new();
            let mut buf = [0u8; 2];
            loop {
                let n = body.read(&mut buf)?;
                if n == 0 {
                    return Ok(out);
                }
                out.extend_from_slice(&buf[..n]);
            }
        }

        assert_eq!(drain(b"3\r\nabc\r\n0\r\n\r\n", true, None).unwrap(), b"abc");
        assert_eq!(drain(b"hello", false, Some(5)).unwrap(), b"hello");
        // several chunks, read through a 2-byte window
        assert_eq!(drain(b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n", true, None).unwrap(), b"abcdef");
        // trailers before the final CRLF
        assert_eq!(drain(b"1\r\nz\r\n0\r\nX-T: v\r\n\r\n", true, None).unwrap(), b"z");

        assert!(drain(b"3\r\nabcX\r\n0\r\n\r\n", true, None).is_err());
        assert!(drain(&format!("{}\n", "a".repeat(CHUNK_LINE_MAX + 1)).into_bytes(), true, None).is_err());
        assert!(drain(b"zz\r\n", true, None).is_err());
        // a Content-Length body that ends early is an error, not a short read
        assert!(drain(b"abc", false, Some(10)).is_err());
    }

    /// Reader that hands over exactly the pieces it was given, returning
    /// WouldBlock in between: the shape a non-blocking socket produces, so the
    /// decoder's resume path is exercised at every split the client can pick.
    struct Segments {
        pieces: std::collections::VecDeque<Vec<u8>>,
        eof_after: bool,
    }

    impl io::Read for Segments {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.pieces.pop_front() {
                Some(p) => {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    if n < p.len() {
                        self.pieces.push_front(p[n..].to_vec());
                    }
                    Ok(n)
                }
                None if self.eof_after => Ok(0),
                None => Err(io::Error::new(io::ErrorKind::WouldBlock, "no more yet")),
            }
        }
    }

    fn chunked_request() -> Request {
        Request {
            method: Method::Post,
            version: Version::V1_1,
            url: "/".into(),
            headers: Vec::new(),
            content_length: None,
            transfer_chunked: true,
            connection_close: false,
            expect_continue: false,
        }
    }

    /// Feed `pieces` one at a time; between pieces the decoder must report
    /// WouldBlock and keep its partial state, never lose or duplicate a byte.
    fn decode_in_pieces(pieces: &[&[u8]]) -> io::Result<Vec<u8>> {
        let src = RefCell::new(io::BufReader::with_capacity(
            16,
            Segments { pieces: pieces.iter().map(|p| p.to_vec()).collect(), eof_after: false },
        ));
        let request = chunked_request();
        let mut body = BodyReader::new(&src, &request);
        let mut out = Vec::new();
        let mut buf = [0u8; 3];
        let mut stalls = 0;
        loop {
            match body.read(&mut buf) {
                Ok(0) => return Ok(out),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    stalls += 1;
                    assert!(stalls < 1000, "decoder spun without progress");
                    // a real relay would poll here; the pieces are already queued
                    if src.borrow().get_ref().pieces.is_empty() {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The client picks the split points, not us: size line, data, CRLF and
    /// trailer must each survive being cut anywhere.
    #[test]
    fn chunked_decoding_resumes_across_every_split() {
        let whole = b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n";
        assert_eq!(decode_in_pieces(&[whole]).unwrap(), b"abcdef");
        // size line cut in half, CRLF cut from its chunk, trailer cut in half
        assert_eq!(
            decode_in_pieces(&[b"4", b"\r\nab", b"cd\r", b"\n2\r\nef\r\n0\r\n\r\n"]).unwrap(),
            b"abcdef"
        );
        assert_eq!(
            decode_in_pieces(&[b"4\r\nabcd\r\n2\r\nef\r\n0\r\nX-A: 1\r", b"\n\r\n"]).unwrap(),
            b"abcdef"
        );
        // one byte at a time
        let single: Vec<&[u8]> = whole.chunks(1).collect();
        assert_eq!(decode_in_pieces(&single).unwrap(), b"abcdef");
    }

    /// A client that keeps sending short trailers must not hold the decoder.
    #[test]
    fn endless_trailers_are_bounded() {
        let mut input = b"1\r\nz\r\n0\r\n".to_vec();
        for i in 0..(TRAILER_LINES_MAX + 5) {
            input.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        input.extend_from_slice(b"\r\n");
        let err = decode_in_pieces(&[&input]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");

        let mut big = b"1\r\nz\r\n0\r\n".to_vec();
        for i in 0..20 {
            big.extend_from_slice(format!("X-{i}: {}\r\n", "v".repeat(600)).as_bytes());
        }
        big.extend_from_slice(b"\r\n");
        assert_eq!(decode_in_pieces(&[&big]).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// A body larger than the caller's limit is refused without collecting it,
    /// and the connection is marked unusable because framing is left mid-body.
    #[test]
    fn read_all_refuses_over_the_limit_and_poisons_reuse() {
        let request = Request {
            method: Method::Post,
            version: Version::V1_1,
            url: "/".into(),
            headers: Vec::new(),
            content_length: Some(100),
            transfer_chunked: false,
            connection_close: false,
            expect_continue: false,
        };
        let cell = RefCell::new(io::BufReader::new(io::Cursor::new(vec![b'x'; 100])));
        let mut body = BodyReader::new(&cell, &request);
        assert!(body.read_all(16).unwrap().is_none());
        assert!(!body.reusable());
    }
}
