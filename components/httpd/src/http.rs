//! HTTP/1.x request parsing and response writing with uhttpd's exact header
//! conventions (status line, Connection/Keep-Alive, chunked encoding, Date).

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::net::TcpStream;
use owrt_ubus::sys::{poll_fds, PollFd, POLLIN, POLLOUT};
use std::io::{self, BufRead, BufReader, Read, Write, IoSlice};
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

pub struct Request {
    pub method: Method,
    pub version: Version,
    /// Raw request target as sent (path + query).
    pub url: String,
    /// Lower-cased header names in arrival order.
    pub headers: Vec<(Cow<'static, str>, String)>,
    /// Original field-line bytes, including line endings, for the shared
    /// request-header and chunk-trailer budget.
    pub header_bytes: usize,
    pub content_length: Option<usize>,
    pub transfer_chunked: bool,
    pub connection_close: bool,
    pub expect_continue: bool,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Targets and arbitrary headers can contain credentials, cookies and
        // query tokens. Keep diagnostics useful without logging their values.
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("version", &self.version)
            .field("header_count", &self.headers.len())
            .field("header_bytes", &self.header_bytes)
            .field("content_length", &self.content_length)
            .field("transfer_chunked", &self.transfer_chunked)
            .field("connection_close", &self.connection_close)
            .field("expect_continue", &self.expect_continue)
            .finish_non_exhaustive()
    }
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn lower_header_name(name: &str) -> Cow<'static, str> {
    // Common protocol names are immutable. Share them between requests;
    // unknown extension headers retain the same ASCII lowercase behavior.
    // Dispatch on length first so a typical head compares each name against
    // at most two candidates instead of the whole table.
    let candidates: &[&'static str] = match name.len() {
        4 => &["host"],
        6 => &["expect", "accept"],
        10 => &["connection", "user-agent"],
        12 => &["content-type"],
        13 => &["authorization"],
        14 => &["content-length"],
        17 => &["transfer-encoding"],
        _ => &[],
    };
    for &known in candidates {
        if name.eq_ignore_ascii_case(known) {
            return Cow::Borrowed(known);
        }
    }
    Cow::Owned(name.to_ascii_lowercase())
}

/// OpenWrt 25.12.6 shares these limits between header fields and trailers.
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_FIELDS: usize = 100;

fn is_header_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
            | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
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
    /// No byte of a head arrived within the deadline's linger: the connection
    /// is idle and may be parked. Only produced with `HeadDeadline::linger`.
    Idle,
}

fn bad_line(code: u16, summary: &'static str) -> ParseOutcome {
    ParseOutcome::Bad { code, summary, version: Version::V1_0, body: true }
}

fn bad_header(code: u16, summary: &'static str, version: Version) -> ParseOutcome {
    ParseOutcome::Bad { code, summary, version, body: false }
}

/// uhttpd's user-agent classes (uhttpd.h:129-139). Only `Safari` and the old
/// MSIE versions change anything; the rest exist because the classification is
/// first-match-wins and the order decides which one a browser lands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UserAgent {
    Opera,
    MsieOld,
    MsieNew,
    Chrome,
    Safari,
    Gecko,
    Konqueror,
}

/// client.c:419-447, in that exact order: Opera, `MSIE `, `Chrome/`,
/// `Safari/` together with `Mac OS X`, `Gecko/`, Konqueror. `None` means no
/// pattern matched, which in C leaves the previous value in place.
///
/// The order is the point: Chrome and Edge on macOS carry both `Chrome/` and
/// `Safari/ ... Mac OS X`, and are Chrome, so they keep keep-alive.
fn classify_ua(value: &str) -> Option<UserAgent> {
    if value.contains("Opera") {
        return Some(UserAgent::Opera);
    }
    if let Some(at) = value.find("MSIE ") {
        let rest = &value[at..];
        let bytes = rest.as_bytes();
        // C reads str[5] (the major version) and str[6] (the dot after it);
        // 4, 5 and 6-without-SV1 are the agents that cannot do keep-alive POST.
        let old = bytes.len() > 6
            && bytes[6] == b'.'
            && match bytes[5] {
                b'6' => !rest.contains("SV1"),
                b'4' | b'5' => true,
                _ => false,
            };
        return Some(if old { UserAgent::MsieOld } else { UserAgent::MsieNew });
    }
    if value.contains("Chrome/") {
        return Some(UserAgent::Chrome);
    }
    if value.contains("Safari/") && value.contains("Mac OS X") {
        return Some(UserAgent::Safari);
    }
    if value.contains("Gecko/") {
        return Some(UserAgent::Gecko);
    }
    if value.contains("Konqueror") {
        return Some(UserAgent::Konqueror);
    }
    None
}

/// What a blocking client read does when the socket's 50 ms receive timeout
/// (`LINGER`, set once at accept) expires with nothing read. The connection
/// thread sets the mode for the phase it is in; the socket option itself is
/// never touched again, so the hot path is one `recv` per request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadWait {
    /// Report `WouldBlock` at once: the first byte of a head, so the caller
    /// can park the idle connection.
    Linger,
    /// Wait up to this much longer with poll(2), then read again. Later head
    /// lines and request bodies use it; a client that pauses for more than
    /// 50 ms pays the poll, a prompt one never does.
    Budget(Duration),
    /// Hand every result through unchanged: a nonblocking relay owns the
    /// socket's readiness itself.
    Passthrough,
}

thread_local! {
    /// One connection per thread, so the mode is per connection.
    static READ_WAIT: Cell<ReadWait> = const { Cell::new(ReadWait::Passthrough) };
}

pub fn read_wait() -> ReadWait {
    READ_WAIT.with(Cell::get)
}

pub fn set_read_wait(wait: ReadWait) {
    READ_WAIT.with(|cell| cell.set(wait));
}

/// How long a connection keeps its thread waiting for the first byte of a
/// request before it is parked. A client in a request loop answers well
/// inside this and never pays for a handoff; a browser between clicks does
/// not, and gives the stack back. Must stay well under the 200 ms at which
/// the resident memory check samples. It is also the socket's fixed receive
/// timeout, see `Sock`.
pub const LINGER: Duration = Duration::from_millis(50);

/// The client socket. Reads honour `ReadWait`; writes and everything else
/// are the stream's own. TLS wraps this too, so its record reads follow the
/// same rules without any socket option changing under rustls.
pub struct Sock(pub TcpStream);

impl Sock {
    /// Wrap an accepted stream: its receive timeout becomes `LINGER` for the
    /// connection's life, the one socket option a request never touches.
    pub fn new(stream: TcpStream) -> Sock {
        let _ = stream.set_read_timeout(Some(LINGER));
        Sock(stream)
    }
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let mut until: Option<Instant> = None;
        loop {
            match self.0.read(buf) {
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    match read_wait() {
                        ReadWait::Passthrough => return Err(error),
                        ReadWait::Linger => return Err(io::Error::new(io::ErrorKind::WouldBlock, "no request bytes within the linger")),
                        ReadWait::Budget(budget) => {
                            let deadline = *until.get_or_insert_with(|| Instant::now() + budget);
                            let left = deadline.saturating_duration_since(Instant::now());
                            if left.is_zero() {
                                return Err(io::Error::new(io::ErrorKind::TimedOut, "client read deadline"));
                            }
                            let mut fds = [PollFd { fd: self.0.as_raw_fd(), events: POLLIN, revents: 0 }];
                            let ms = left.as_millis().saturating_add(1).min(i32::MAX as u128) as i32;
                            if poll_fds(&mut fds, ms)? == 0 {
                                return Err(io::Error::new(io::ErrorKind::TimedOut, "client read deadline"));
                            }
                        }
                    }
                }
                result => return result,
            }
        }
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.0.write_vectored(bufs)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Overall deadline for one request head, mirroring uhttpd's client timeout:
/// armed at accept and after every completed request (client.c:721, 137), and
/// cancelled by the blank line that ends the head (client.c:372). uhttpd runs
/// it on uloop; here it also shortens the socket read timeout, so no single
/// read can carry the head past the deadline either.
pub struct HeadDeadline {
    fd: RawFd,
    at: Instant,
    /// How long the first read of a head may wait before the caller is told
    /// the connection is idle. The deadline itself is unchanged by it.
    linger: Option<Duration>,
    /// The socket's receive timeout is the linger, fixed at accept, and the
    /// thread's `ReadWait` mode decides what a timed-out read means. No
    /// socket option is changed per request. Off for the profiler and tests
    /// that drive a socket without a `Sock` wrapper.
    linger_socket: bool,
}

impl HeadDeadline {
    /// A budget counted from now. The server itself always resumes an
    /// earlier instant (`until`); the profiler and tests start fresh.
    #[allow(dead_code)]
    pub fn new(fd: RawFd, budget: Duration) -> Self {
        Self::until(fd, Instant::now() + budget)
    }

    /// A deadline that started earlier: a keep-alive wait that began before
    /// the connection was parked keeps its original end.
    pub fn until(fd: RawFd, at: Instant) -> Self {
        HeadDeadline { fd, at, linger: None, linger_socket: false }
    }

    /// The connection's socket already times out reads at the linger; the
    /// deadline only sets the thread's `ReadWait` mode, never a socket option.
    pub fn linger_socket(mut self) -> Self {
        self.linger_socket = true;
        self
    }

    /// Report `ParseOutcome::Idle` instead of waiting the whole budget when
    /// no byte arrives within `linger`. Costs nothing extra: the first read
    /// already arms the socket timeout, it is just armed shorter.
    pub fn with_linger(mut self, linger: Duration) -> Self {
        self.linger = Some(linger);
        self
    }

    fn remaining(&self) -> io::Result<Duration> {
        let left = self.at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            // uhttpd closes without answering (client_timeout, client.c:95).
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request header timeout"));
        }
        Ok(left)
    }

    /// Make the next transport read honour the remaining budget: set the
    /// thread's `ReadWait` mode (linger socket), or arm the socket timeout.
    fn arm(&self, first_byte: bool) -> io::Result<()> {
        let mut wait = self.remaining()?;
        if let (true, Some(linger)) = (first_byte, self.linger) {
            wait = wait.min(linger);
        }
        if self.linger_socket {
            set_read_wait(if first_byte && self.linger.is_some() { ReadWait::Linger } else { ReadWait::Budget(wait) });
            return Ok(());
        }
        crate::set_read_timeout(self.fd, wait)
    }

    /// A read timed out before any byte of the head: idle if budget remains,
    /// the usual timeout error otherwise.
    fn idle(&self) -> io::Result<HeadLine> {
        if self.linger.is_none() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request header timeout"));
        }
        self.remaining()?;
        Ok(HeadLine::Idle)
    }
}

/// Outcome of a bounded head-line read.
enum HeadLine {
    /// A complete line (its trailing CRLF/LF included), within the cap.
    Line,
    /// Peer closed before any bytes of this line.
    Eof,
    /// The line exceeded the cap before a newline arrived.
    TooLong,
    /// Nothing arrived within the deadline's linger (first line only).
    Idle,
}

/// Read one line (up to and including LF) into `raw`, buffering at most
/// `max` bytes. uhttpd caps the request/header buffer at 4 KiB and answers
/// 413 rather than reading an unbounded line into memory.
fn read_head_line<R: Read>(
    reader: &mut BufReader<R>,
    raw: &mut Vec<u8>,
    max: usize,
    deadline: Option<&HeadDeadline>,
    first_line: bool,
) -> io::Result<HeadLine> {
    raw.clear();
    loop {
        // No byte of this head has arrived yet: the linger, if any, applies.
        let first_byte = first_line && raw.is_empty();
        if let Some(deadline) = deadline {
            if reader.buffer().is_empty() {
                // Only fill_buf on an empty buffer can read the transport.
                deadline.arm(first_byte)?;
            } else {
                // Buffered or pipelined input must still obey the same
                // whole-head deadline; it just needs no socket option.
                deadline.remaining()?;
            }
        }
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            // Concurrent CGI activity can interrupt a socket read. Keep the
            // partial line and recheck the original deadline before retrying.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if first_byte
                    && matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
            {
                return match deadline {
                    Some(deadline) => deadline.idle(),
                    None => Err(error),
                };
            }
            Err(error) => return Err(error),
        };
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
    Ok(HeadLine::Line)
}

/// Rejectable header bytes: control characters other than HTAB, and DEL.
/// Byte lanes remain independent so HTAB cannot hide a neighbouring control.
#[inline]
fn has_forbidden_ctl(bytes: &[u8]) -> bool {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    const LOW: u64 = !HIGH;
    #[inline]
    fn zero_byte(x: u64) -> u64 {
        // Each lane adds at most 0x7f + 0x7f, with no carry into its neighbour.
        // Unlike subtracting ONES, this identifies *only* the zero lanes.
        !((x & LOW).wrapping_add(LOW) | x) & HIGH
    }
    let (chunks, remainder) = bytes.as_chunks::<8>();
    for chunk in chunks {
        let x = u64::from_le_bytes(*chunk);
        // Adding 0x60 sets the high bit exactly for low-seven-bit values
        // >= 0x20; including x excludes non-ASCII bytes from the complement.
        let ctl = !((x & LOW).wrapping_add(ONES * 0x60) | x) & HIGH;
        let tab = zero_byte(x ^ (ONES * u64::from(b'\t')));
        let del = zero_byte(x ^ (ONES * 0x7f));
        if (ctl & !tab) | del != 0 {
            return true;
        }
    }
    remainder.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

#[cfg(test)]
mod ctl_scan_tests {
    use super::has_forbidden_ctl;

    #[test]
    fn swar_scan_matches_the_scalar_predicate() {
        let scalar = |bytes: &[u8]| bytes.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f);
        for value in 0u8..=255 {
            for position in [0usize, 3, 7, 8, 12, 15, 16] {
                let mut line = vec![b'a'; 17];
                line[position] = value;
                assert_eq!(
                    has_forbidden_ctl(&line),
                    scalar(&line),
                    "byte {value:#x} at {position}"
                );
            }
        }
        assert!(!has_forbidden_ctl(b""));
        assert!(!has_forbidden_ctl(b"Host:\tlocalhost"));
        assert!(has_forbidden_ctl(b"Host: a\rb"));
        assert!(has_forbidden_ctl(&[0u8]));
    }

    #[test]
    fn swar_scan_keeps_all_adjacent_byte_lanes_independent() {
        for first in 0u8..=255 {
            for second in 0u8..=255 {
                let forbidden = |byte: u8| (byte < 0x20 && byte != b'\t') || byte == 0x7f;
                for position in 0..16 {
                    let mut bytes = [b'a'; 17];
                    bytes[position] = first;
                    bytes[position + 1] = second;
                    assert_eq!(has_forbidden_ctl(&bytes), forbidden(first) || forbidden(second),
                        "adjacent bytes {first:#x}, {second:#x} at {position}");
                }
            }
        }
    }

    #[test]
    fn header_parser_accepts_tab_space_and_rejects_tab_backspace() {
        use super::{read_request, ParseOutcome};
        use std::io::BufReader;

        for whitespace in [b"\t ".as_slice(), b"\t\x08"] {
            let mut wire = b"GET / HTTP/1.1\r\nHost:".to_vec();
            wire.extend_from_slice(whitespace);
            wire.extend_from_slice(b"x\r\n\r\n");
            let outcome = read_request(&mut BufReader::new(wire.as_slice()), true, None).unwrap();
            if whitespace == b"\t " {
                assert!(matches!(outcome, ParseOutcome::Request(ref request) if request.header("host") == Some("x")));
            } else {
                assert!(matches!(outcome, ParseOutcome::Bad { code: 400, .. }));
            }
        }
    }

    #[test]
    fn request_debug_omits_targets_and_header_values() {
        let wire = b"GET /?token=query-secret HTTP/1.1\r\nAuthorization: Basic auth-secret\r\nCookie: cookie-secret\r\nX-Token: custom-secret\r\n\r\n";
        let super::ParseOutcome::Request(request) = super::read_request(
            &mut std::io::BufReader::new(wire.as_slice()), true, None,
        ).unwrap() else { panic!("valid request rejected") };
        for debug in [format!("{request:?}"), format!("{request:#?}")] {
            assert!(debug.contains("Request"));
            assert!(debug.contains("Get"));
            for secret in ["query-secret", "auth-secret", "cookie-secret", "custom-secret"] {
                assert!(!debug.contains(secret));
            }
        }
    }
}

/// Read and parse one request head from `reader`.
#[allow(dead_code)] // Also used by standalone callers and the stage profiler.
pub fn read_request<R: Read>(
    reader: &mut BufReader<R>,
    keepalive: bool,
    deadline: Option<&HeadDeadline>,
) -> io::Result<ParseOutcome> {
    HeadBuffer::default().read_request(reader, keepalive, deadline)
}

/// Worker-local parser storage. Reuse allocations, never parsed decisions:
/// every field and flag is replaced before a request can reach a handler.
#[derive(Default)]
pub struct HeadBuffer {
    line: Vec<u8>,
    spare: Option<Request>,
}

impl HeadBuffer {
    pub fn read_request<R: Read>(
        &mut self,
        reader: &mut BufReader<R>,
        keepalive: bool,
        deadline: Option<&HeadDeadline>,
    ) -> io::Result<ParseOutcome> {
        read_request_into(reader, keepalive, deadline, &mut self.line, &mut self.spare)
    }

    /// Large headers must not pin their peak capacity while a connection is
    /// idle. This limits retained storage, not which requests are accepted.
    pub fn recycle(&mut self, request: Request) {
        self.spare = Some(request);
        self.trim();
    }

    fn retained_bytes(&self) -> usize {
        let mut bytes = self.line.capacity();
        if let Some(request) = &self.spare {
            bytes = bytes.saturating_add(request.url.capacity())
                .saturating_add(request.headers.capacity().saturating_mul(
                    std::mem::size_of::<(Cow<'static, str>, String)>()));
            for (name, value) in &request.headers {
                bytes = bytes.saturating_add(value.capacity());
                if let Cow::Owned(name) = name {
                    bytes = bytes.saturating_add(name.capacity());
                }
            }
        }
        bytes
    }

    /// Called before a worker becomes idle, including after parser errors.
    /// At most four idle workers retain at most 8 KiB each; idle sockets keep
    /// neither this storage nor the reader's separate 8 KiB allocation.
    pub fn trim(&mut self) {
        if self.retained_bytes() > 8192 {
            self.spare = None;
            self.line = Vec::new();
        } else {
            self.line.clear();
        }
    }
}

fn read_request_into<R: Read>(
    reader: &mut BufReader<R>,
    keepalive: bool,
    deadline: Option<&HeadDeadline>,
    raw: &mut Vec<u8>,
    spare: &mut Option<Request>,
) -> io::Result<ParseOutcome> {
    // Bound leading blank lines separately; uhttpd's field budget excludes
    // the request line and the terminating empty line.
    let mut head_bytes = 0;
    let mut first_line = true;
    loop {
        match read_head_line(reader, raw, 4096, deadline, first_line)? {
            HeadLine::Eof => return Ok(ParseOutcome::Eof),
            HeadLine::Idle => return Ok(ParseOutcome::Idle),
            HeadLine::TooLong => {
                return Ok(bad_line(413, "Request Entity Too Large"))
            }
            HeadLine::Line => {}
        }
        head_bytes += raw.len();
        if head_bytes > MAX_HEADER_BYTES {
            return Ok(bad_line(413, "Request Entity Too Large"));
        }
        // A stray blank line is input: from here on the whole budget applies.
        first_line = false;
        if raw.as_slice() == b"\r\n" || raw.as_slice() == b"\n" {
            continue;
        }
        break;
    }
    let line = String::from_utf8_lossy(raw);
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
    let path = url.split('?').next().unwrap_or("");
    let has_nul = if path.contains('%') {
        url_decode(path).is_some_and(|decoded| decoded.contains(&0))
    } else {
        path.as_bytes().contains(&0)
    };
    if has_nul {
        return Ok(bad_line(400, "Bad Request"));
    }
    // Idle/EOF/bad request lines must not consume reusable storage.
    // Take it only when a new request can reset every field below.
    let mut request = spare.take().unwrap_or_else(|| Request {
        method,
        version,
        url: String::new(),
        headers: Vec::new(),
        header_bytes: 0,
        content_length: None,
        transfer_chunked: false,
        connection_close: false,
        expect_continue: false,
    });
    request.method = method;
    request.version = version;
    request.url.clear();
    request.url.push_str(url);
    request.content_length = None;
    request.transfer_chunked = false;
    request.connection_close = version < Version::V1_1 || !keepalive;
    request.expect_continue = false;
    request.header_bytes = 0;
    let mut used_headers = 0;
    let mut content_lengths = 0;
    let mut transfer_encodings = 0;
    let mut ua = None;
    loop {
        match read_head_line(reader, raw, 4096, deadline, false)? {
            HeadLine::Eof => return Ok(bad_header(400, "Bad Request", version)),
            HeadLine::TooLong => {
                return Ok(bad_header(413, "Request Entity Too Large", version))
            }
            HeadLine::Line | HeadLine::Idle => {}
        }
        let line = String::from_utf8_lossy(raw);
        let trimmed = line.strip_suffix('\n').unwrap_or(&line);
        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
        if trimmed.is_empty() {
            break;
        }
        request.header_bytes += raw.len();
        if used_headers == MAX_HEADER_FIELDS || request.header_bytes > MAX_HEADER_BYTES {
            return Ok(bad_header(431, "Request Header Fields Too Large", version));
        }
        // A NUL/control byte cannot be represented in a CGI environment
        // and must not be silently accepted or truncate a header in C.
        if has_forbidden_ctl(trimmed.as_bytes()) {
            return Ok(bad_header(400, "Bad Request", version));
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Ok(bad_header(400, "Bad Request", version));
        };
        if name.is_empty() || !name.bytes().all(is_header_token) {
            return Ok(bad_header(400, "Bad Request", version));
        }
        let name = lower_header_name(name);
        let value = value.trim_matches([' ', '\t']);
        match name.as_ref() {
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
            "user-agent" => {
                if let Some(class) = classify_ua(value) {
                    ua = Some(class);
                }
            }
            _ => {}
        }
        if let Some((old_name, old_value)) = request.headers.get_mut(used_headers) {
            *old_name = name;
            old_value.clear();
            old_value.push_str(value);
        } else {
            request.headers.push((name, value.to_owned()));
        }
        used_headers += 1;
    }
    request.headers.truncate(used_headers);
    if content_lengths > 1 || (content_lengths > 0 && transfer_encodings > 0) {
        // uhttpd reports conflicting framing through uh_client_error, i.e. with a body
        return Ok(ParseOutcome::Bad { code: 400, summary: "Bad Request", version, body: true });
    }
    // client_header_complete (client.c:348-358), after the framing check and in
    // this order: Safari always forces a close, old MSIE only on POST.
    match ua {
        Some(UserAgent::Safari) => request.connection_close = true,
        Some(UserAgent::MsieOld) if request.method == Method::Post => {
            request.connection_close = true
        }
        _ => {}
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
    /// Copy an unframed file body of exactly `length` bytes, the value the
    /// Content-Length header announced. A file that grew after lookup is
    /// cut there: bytes past the announced length would be parsed by the
    /// client as the next response (uhttpd streams through EOF and has
    /// that framing fault). A file that shrank ends early, as in uhttpd.
    /// Stopping at the length also spares the read that would only return
    /// EOF on every static response.
    fn copy_from(&mut self, source: &mut dyn Read, length: u64) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        let mut remaining = length;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = match source.read(&mut buf[..want]) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            self.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        Ok(())
    }
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
    /// Initialized storage; only start..end contains queued response bytes.
    /// Keeping the initialized tail lets file reads reuse it without zeroing
    /// or copying a separate staging buffer for every read.
    buf: Vec<u8>,
    start: usize,
    end: usize,
    window: usize,
    /// Budget for one blocking drain, from the configured network timeout.
    timeout: Duration,
    deferred: bool,
    plain_vectored: bool,
}

impl<'a, T: Read + Write> Out<'a, T> {
    pub fn new(client: &'a RefCell<BufReader<T>>, fd: RawFd, window: usize, timeout: Duration) -> Self {
        // Ordinary response headers fit here. Avoid growing through many
        // tiny allocations before the first body write fills the window.
        Self::with_buffer(client, fd, window, timeout, Vec::with_capacity(window.min(512)))
    }

    pub fn with_buffer(client: &'a RefCell<BufReader<T>>, fd: RawFd, window: usize,
                       timeout: Duration, buf: Vec<u8>) -> Self {
        Out { client, fd, buf, start: 0, end: 0,
              window, timeout, deferred: false, plain_vectored: false }
    }

    /// Plain sockets can combine queued headers and a borrowed large body in
    /// one transport write. TLS keeps the ordinary buffered path.
    pub fn enable_plain_vectored(&mut self) {
        self.plain_vectored = true;
    }

    /// Return initialized storage only after a completed response. The next
    /// owner starts at 0..0 and must overwrite bytes before sending them.
    pub fn into_buffer(self) -> Vec<u8> {
        self.buf
    }

    /// Finish one response before reusing its allocation for the next one.
    /// Retain at most two windows, so an unusually large CGI header cannot
    /// pin its peak allocation for the rest of a keep-alive connection.
    pub fn finish_request(&mut self) -> io::Result<()> {
        self.flush()?;
        if self.deferred || self.pending() != 0 {
            return Err(io::Error::other("response relay did not finish"));
        }
        if self.buf.capacity() > self.window.saturating_mul(2) {
            self.buf = Vec::with_capacity(self.window.min(512));
        }
        Ok(())
    }

    fn compact(&mut self) {
        if self.start != 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    /// Push until the window is empty. The budget covers the whole drain, not
    /// one write, so many small partial writes cannot extend it.
    fn drain_blocking(&mut self) -> io::Result<()> {
        self.drain_until(Instant::now() + self.timeout)
    }

    fn drain_until(&mut self, deadline: Instant) -> io::Result<()> {
        while self.pending() != 0 {
            let before = self.pending();
            self.drain_ready()?;
            if self.pending() == before {
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
        self.end - self.start
    }

    fn drain_ready(&mut self) -> io::Result<()> {
        while self.pending() != 0 {
            match borrow(self.client)?.get_mut().write(&self.buf[self.start..self.end]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "client accepted nothing")),
                Ok(n) => {
                    self.start += n;
                    if self.start == self.end {
                        self.start = 0;
                        self.end = 0;
                    }
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

    fn copy_from(&mut self, source: &mut dyn Read, length: u64) -> io::Result<()> {
        if self.deferred {
            return Err(io::Error::other("file copy cannot own deferred relay readiness"));
        }
        self.compact();
        let mut remaining = length;
        while remaining > 0 {
            let want = remaining.min(self.window as u64) as usize;
            let limit = self.end + want;
            if self.buf.len() < limit {
                self.buf.resize(limit, 0);
            }
            let n = match source.read(&mut self.buf[self.end..limit]) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            self.end += n;
            remaining -= n as u64;
            // Push this batch before reading more, so no second window is
            // ever reserved beyond a partial batch.
            self.drain_blocking()?;
        }
        Ok(())
    }
}

impl<T: Read + Write> Write for Out<'_, T> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let length = data.len();
        let deadline = if self.plain_vectored && !self.deferred && length >= self.window {
            let deadline = Instant::now() + self.timeout;
            let queued = self.pending();
            let result = borrow(self.client)?.get_mut().write_vectored(&[
                IoSlice::new(&self.buf[self.start..self.end]), IoSlice::new(data),
            ]);
            match result {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "client accepted nothing")),
                Ok(n) => {
                    self.start += n.min(queued);
                    data = &data[n.saturating_sub(queued)..];
                    if self.start == self.end {
                        self.start = 0;
                        self.end = 0;
                    }
                    if data.is_empty() {
                        return Ok(length);
                    }
                }
                // One optimistic attempt only. EINTR has consumed no bytes;
                // both transient errors fall back using the original budget.
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                Err(e) => return Err(e),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "response write deadline"));
            }
            Some(deadline)
        } else {
            None
        };
        self.compact();
        let initialized = (self.buf.len() - self.end).min(data.len());
        self.buf[self.end..self.end + initialized].copy_from_slice(&data[..initialized]);
        self.buf.extend_from_slice(&data[initialized..]);
        self.end += data.len();
        if let Some(deadline) = deadline {
            // The original large write crossed the window: even a short
            // suffix must drain before this call reports success.
            self.drain_until(deadline)?;
        } else if !self.deferred && self.pending() >= self.window {
            self.drain_blocking()?;
        }
        Ok(length)
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
    /// Header and trailer totals, so trailers share the original request's cap.
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

/// Parse the exact chunk-size grammar of uhttpd 373145f7: hexadecimal size,
/// followed by zero or more semicolon extensions with ASCII alphanumeric
/// names and values. Empty extension names/values remain accepted upstream.
fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    let digits = line.iter().take_while(|byte| byte.is_ascii_hexdigit()).count();
    if digits == 0 {
        return None;
    }
    let mut size = 0u64;
    for &byte in &line[..digits] {
        let digit = if byte.is_ascii_digit() { byte - b'0' } else { byte.to_ascii_lowercase() - b'a' + 10 };
        size = size.checked_mul(16)?.checked_add(u64::from(digit))?;
        if size > i32::MAX as u64 {
            return None;
        }
    }
    let mut rest = &line[digits..];
    while let Some(extension) = rest.strip_prefix(b";") {
        let name = extension.iter().take_while(|byte| byte.is_ascii_alphanumeric()).count();
        rest = &extension[name..];
        if let Some(value) = rest.strip_prefix(b"=") {
            let length = value.iter().take_while(|byte| byte.is_ascii_alphanumeric()).count();
            rest = &value[length..];
        }
    }
    rest.is_empty().then_some(size)
}

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
            trailer_bytes: request.header_bytes,
            trailer_lines: request.headers.len(),
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
                    let Some(size) = parse_chunk_size(&line) else {
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
                    self.trailer_bytes += line.len() + 2;
                    if self.trailer_lines > MAX_HEADER_FIELDS || self.trailer_bytes > MAX_HEADER_BYTES {
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
                if line.pop() != Some(b'\r') {
                    return Err(self.fail(io::ErrorKind::InvalidData, "framing line requires CRLF"));
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
    code: i32,
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
    pub fn status(&mut self, code: impl Into<i32>, summary: &str) -> io::Result<()> {
        let code = code.into();
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

    pub fn header(&mut self, name: &str, value: impl std::fmt::Display) -> io::Result<()> {
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

    /// Static Content-Length bodies may read straight into the output window;
    /// exactly `length` bytes are sent, see `Sink::copy_from`.
    pub fn copy_unchunked(&mut self, source: &mut dyn Read, length: u64) -> io::Result<()>
    where W: Sink {
        if self.is_head() {
            return Ok(());
        }
        if self.chunked {
            return Err(io::Error::other("direct file copy requires unchunked framing"));
        }
        self.out.copy_from(source, length)
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
    HttpDate(unix).to_string()
}

/// A date written directly into a response, without an intermediate String.
pub struct HttpDate(pub i64);

impl std::fmt::Display for HttpDate {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let days = self.0.div_euclid(86_400);
        let secs = self.0.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let weekday = (days + 4).rem_euclid(7) as usize;
        write!(
            out,
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            DAYS[weekday], d, MONTHS[(m - 1) as usize], y,
            secs / 3600, (secs % 3600) / 60, secs % 60
        )
    }
}

fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era.checked_mul(146_097)?.checked_add(doe)?.checked_sub(719_468)
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
    days_from_civil(y, m, d)?.checked_mul(86_400)?
        .checked_add(hh.checked_mul(3600)?)?
        .checked_add(mm.checked_mul(60)?)?
        .checked_add(ss)
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

/// uh_htmlescape (utils.c:260-299): the same five characters uhttpd treats as
/// special, each written as `&#x<lower hex>;` -- not as a named entity, which
/// is what the error pages and directory listings have to reproduce byte for
/// byte.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '&' | '\'' | '<' | '>' => {
                out.push_str(&format!("&#x{:02x};", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflowing_http_dates_are_rejected_without_panicking() {
        for date in [
            "Sun, 06 Nov 9223372036854775807 08:49:37 GMT",
            "Sun, 06 Nov 1994 9223372036854775807:49:37 GMT",
            "Sun, 06 Nov 1994 08:9223372036854775807:37 GMT",
            "Sun, 06 Nov 1994 08:49:9223372036854775807 GMT",
        ] {
            assert_eq!(parse_http_date(date), None, "overflowing date: {date}");
        }
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784111777));
    }

    fn head_with_size(size: usize) -> Vec<u8> {
        let mut head = b"GET / HTTP/1.1\r\n".to_vec();
        let size = head.len() + size + 2;
        while size - head.len() - 2 > 4096 {
            let line_size = (size - head.len() - 6).min(4096);
            head.extend_from_slice(b"X:");
            head.extend(std::iter::repeat_n(b'a', line_size - 4));
            head.extend_from_slice(b"\r\n");
        }
        let last = size - head.len() - 2;
        assert!(last >= 4);
        head.extend_from_slice(b"X:");
        head.extend(std::iter::repeat_n(b'a', last - 4));
        head.extend_from_slice(b"\r\n\r\n");
        assert_eq!(head.len(), size);
        head
    }

    #[test]
    fn request_header_limits_bound_bytes_and_count() {
        for size in [16383, 16384, 16385] {
            let mut input = BufReader::new(io::Cursor::new(head_with_size(size)));
            let result = read_request(&mut input, true, None).unwrap();
            if size <= 16384 {
                assert!(matches!(result, ParseOutcome::Request(_)), "size {size}");
            } else {
                assert!(matches!(result, ParseOutcome::Bad { code: 431, .. }), "size {size}");
            }
        }
        for count in [100, 101] {
            let mut head = b"GET / HTTP/1.1\r\n".to_vec();
            for _ in 0..count { head.extend_from_slice(b"X:\r\n"); }
            head.extend_from_slice(b"\r\n");
            let mut input = BufReader::new(io::Cursor::new(head));
            let result = read_request(&mut input, true, None).unwrap();
            if count == 100 {
                assert!(matches!(result, ParseOutcome::Request(_)));
            } else {
                assert!(matches!(result, ParseOutcome::Bad { code: 431, .. }));
            }
        }
        // Leading blank lines have a separate bounded budget.
        let mut head = b"\r\n".repeat(8192);
        head.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        let mut input = BufReader::new(io::Cursor::new(head));
        assert!(matches!(read_request(&mut input, true, None).unwrap(), ParseOutcome::Bad { code: 413, .. }));
    }

    #[test]
    fn request_header_limits_reset_only_after_one_complete_request() {
        let mut input = head_with_size(16384);
        input.extend_from_slice(&head_with_size(16384));
        let mut reader = BufReader::new(io::Cursor::new(input));
        let mut heads = HeadBuffer::default();
        for _ in 0..2 {
            let ParseOutcome::Request(request) = heads.read_request(&mut reader, true, None).unwrap() else {
                panic!("each complete pipelined head has its own budget");
            };
            heads.recycle(request);
        }
        assert!(matches!(heads.read_request(&mut reader, true, None).unwrap(), ParseOutcome::Eof));
        let mut input = head_with_size(16385);
        input.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        let mut reader = BufReader::new(io::Cursor::new(input));
        assert!(matches!(heads.read_request(&mut reader, true, None).unwrap(), ParseOutcome::Bad { code: 431, .. }));
    }

    #[test]
    fn header_names_are_nonempty_ascii_tokens_and_values_trim_only_ows() {
        for field in [": value", " Host: value", "Host : value", "Host\t: value",
            "X Name: value", "X@Name: value", "X(Name): value", "Höst: value", "X: value\r"] {
            let raw = format!("GET / HTTP/1.1\r\n{field}\r\n\r\n");
            let mut input = BufReader::new(io::Cursor::new(raw));
            assert!(matches!(read_request(&mut input, true, None).unwrap(),
                ParseOutcome::Bad { code: 400, .. }), "{field:?}");
        }
        let raw = b"GET / HTTP/1.1\r\nX-!#$%&'*+.^_`|~: \tvalue\t \r\nX-Obs: \xc2\xa0value\xc2\xa0 \r\n\r\n";
        let mut input = BufReader::new(io::Cursor::new(raw));
        let ParseOutcome::Request(request) = read_request(&mut input, true, None).unwrap() else {
            panic!("valid token rejected");
        };
        assert_eq!(request.header("x-!#$%&'*+.^_`|~"), Some("value"));
        assert_eq!(request.header("x-obs"), Some("\u{a0}value\u{a0}"));
    }

    #[test]
    fn trailers_share_header_limits_and_never_become_pipelined_requests() {
        for (headers, trailers, accepted) in [(99, 1, true), (99, 2, false)] {
            let mut raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n".to_vec();
            for _ in 1..headers { raw.extend_from_slice(b"X: v\r\n"); }
            raw.extend_from_slice(b"\r\n0\r\n");
            for _ in 0..trailers { raw.extend_from_slice(b"GET /hidden HTTP/1.1\r\n"); }
            raw.extend_from_slice(b"\r\nGET /next HTTP/1.1\r\n\r\n");
            let cell = RefCell::new(BufReader::new(io::Cursor::new(raw)));
            let ParseOutcome::Request(request) = read_request(&mut cell.borrow_mut(), true, None).unwrap() else {
                panic!("valid head rejected");
            };
            let mut body = BodyReader::new(&cell, &request);
            assert_eq!(body.read_all(0).is_ok(), accepted);
            assert_eq!(body.reusable(), accepted);
            if accepted {
                let ParseOutcome::Request(next) = read_request(&mut cell.borrow_mut(), true, None).unwrap() else {
                    panic!("next request lost");
                };
                assert_eq!(next.url, "/next");
            }
        }
        // Header fields have 4 bytes left; a six-byte trailer crosses the
        // shared wire-byte budget even though its payload is only 4 bytes.
        let mut raw = head_with_size(16380 - b"Transfer-Encoding: chunked\r\n".len());
        raw.truncate(raw.len() - 2);
        raw.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n0\r\nX: v\r\n\r\n");
        let cell = RefCell::new(BufReader::new(io::Cursor::new(raw)));
        let ParseOutcome::Request(request) = read_request(&mut cell.borrow_mut(), true, None).unwrap() else {
            panic!("valid head rejected");
        };
        let mut body = BodyReader::new(&cell, &request);
        assert_eq!(body.read_all(0).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(!body.reusable());
    }

    #[test]
    fn date_roundtrip() {
        let s = http_date(1782737960);
        assert_eq!(s, "Mon, 29 Jun 2026 12:59:20 GMT");
        assert_eq!(parse_http_date(&s), Some(1782737960));
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(784111777));
    }

    #[test]
    fn parses_request_and_rejects_conflicting_framing() {
        let mut input = BufReader::new(io::Cursor::new(b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n"));
        match read_request(&mut input, true, None).unwrap() {
            ParseOutcome::Bad { code: 400, .. } => {}
            other => panic!("unexpected {:?}", matches!(other, ParseOutcome::Eof)),
        }
        let mut input = BufReader::new(io::Cursor::new(b"HEAD /x HTTP/1.0\r\nHost: y\r\n\r\n"));
        let ParseOutcome::Request(r) = read_request(&mut input, true, None).unwrap() else {
            panic!()
        };
        assert_eq!(r.method, Method::Head);
        assert!(r.connection_close);
        assert_eq!(r.header("host"), Some("y"));
    }

    #[test]
    fn header_controls_cannot_reach_dispatch() {
        for byte in (0..=31).chain([127]).filter(|b| *b != b'\t' && *b != b'\n' && *b != b'\r') {
            let mut raw = b"GET / HTTP/1.1\r\nX-Test: a".to_vec();
            raw.push(byte);
            raw.extend_from_slice(b"b\r\n\r\n");
            let mut input = BufReader::new(io::Cursor::new(raw));
            assert!(matches!(read_request(&mut input, true, None).unwrap(), ParseOutcome::Bad { code: 400, .. }));
        }
        let mut input = BufReader::new(io::Cursor::new(b"GET / HTTP/1.1\r\nX-Test: a\tb\r\n\r\n"));
        assert!(matches!(read_request(&mut input, true, None).unwrap(), ParseOutcome::Request(_)));
    }

    #[test]
    fn chunk_length_boundary_is_checked_before_reading_payload() {
        for (size, valid) in [("7fffffff", true), ("80000000", false), ("ffffffffffffffff", false)] {
            let raw = format!("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nx");
            let mut input = BufReader::new(io::Cursor::new(raw));
            let ParseOutcome::Request(request) = read_request(&mut input, true, None).unwrap() else { panic!() };
            let input = RefCell::new(input);
            let mut body = BodyReader::new(&input, &request);
            let result = body.read(&mut [0; 1]);
            if valid { assert_eq!(result.unwrap(), 1); }
            else { assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData); }
        }
    }

    #[test]
    fn fragmented_head_leaves_body_and_next_request_intact() {
        let raw = "POST /路径 HTTP/1.1\r\nX-Test: a€\r\nContent-Length: 3\r\n\r\nxyzGET /next HTTP/1.1\r\nX-Test: b\r\n\r\n";
        for capacity in [1, 2, 7, 4096] {
            let mut input = BufReader::with_capacity(capacity, io::Cursor::new(raw.as_bytes()));
            let ParseOutcome::Request(first) = read_request(&mut input, true, None).unwrap() else {
                panic!("fragmented first head rejected")
            };
            assert_eq!(first.url, "/路径");
            assert_eq!(first.header("x-test"), Some("a€"));
            assert_eq!(first.content_length, Some(3));
            let mut body = [0; 3];
            input.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"xyz");
            let ParseOutcome::Request(next) = read_request(&mut input, true, None).unwrap() else {
                panic!("pipelined head rejected")
            };
            assert_eq!(next.url, "/next");
            assert_eq!(next.header("x-test"), Some("b"));
            assert_eq!(first.header("x-test"), Some("a€"));
        }
    }

    #[test]
    fn expired_head_deadline_also_rejects_already_buffered_input() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut input = BufReader::new(io::Cursor::new(raw));
        assert_eq!(input.fill_buf().unwrap(), raw);
        let deadline = HeadDeadline::until(-1, Instant::now() - Duration::from_secs(1));
        let error = read_request(&mut input, true, Some(&deadline)).err().expect("deadline ignored");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(input.buffer(), raw);
    }

    #[test]
    fn a_timed_out_first_read_is_idle_only_with_a_linger_and_budget_left() {
        /// Times out on every read until `bytes` is set, then serves it.
        struct Quiet { bytes: &'static [u8], timeouts: usize }
        impl Read for Quiet {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.timeouts > 0 {
                    self.timeouts -= 1;
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let n = out.len().min(self.bytes.len());
                out[..n].copy_from_slice(&self.bytes[..n]);
                self.bytes = &self.bytes[n..];
                Ok(n)
            }
        }
        let head: &[u8] = b"GET /q HTTP/1.1\r\nHost: x\r\n\r\n";
        // With a linger and budget left: idle, and nothing consumed.
        let mut input = BufReader::new(Quiet { bytes: head, timeouts: 1 });
        let deadline = HeadDeadline::new(-1, Duration::from_secs(30)).with_linger(Duration::from_millis(50));
        assert!(matches!(read_request(&mut input, true, Some(&deadline)).unwrap(), ParseOutcome::Idle));
        assert!(input.buffer().is_empty());
        // The same reader then delivers the request normally.
        let ParseOutcome::Request(r) = read_request(&mut input, true, Some(&deadline)).unwrap() else { panic!() };
        assert_eq!(r.url, "/q");
        // Without a linger the timeout is the head timeout, as before.
        let mut input = BufReader::new(Quiet { bytes: head, timeouts: 1 });
        let deadline = HeadDeadline::new(-1, Duration::from_secs(30));
        assert_eq!(read_request(&mut input, true, Some(&deadline)).err().expect("timeout ignored").kind(), io::ErrorKind::TimedOut);
        // With a linger but the budget gone: still the head timeout.
        let mut input = BufReader::new(Quiet { bytes: head, timeouts: 1 });
        let deadline = HeadDeadline::until(-1, Instant::now() - Duration::from_secs(1)).with_linger(Duration::from_millis(50));
        assert_eq!(read_request(&mut input, true, Some(&deadline)).err().expect("timeout ignored").kind(), io::ErrorKind::TimedOut);
        // A timeout after part of the head arrived is never idle.
        struct Partial { sent: bool }
        impl Read for Partial {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.sent {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                self.sent = true;
                out[..4].copy_from_slice(b"GET ");
                Ok(4)
            }
        }
        let mut input = BufReader::new(Partial { sent: false });
        let deadline = HeadDeadline::new(-1, Duration::from_secs(30)).with_linger(Duration::from_millis(50));
        assert_eq!(read_request(&mut input, true, Some(&deadline)).err().expect("timeout ignored").kind(), io::ErrorKind::WouldBlock);
        // No deadline at all: the error passes through untouched.
        let mut input = BufReader::new(Quiet { bytes: head, timeouts: 1 });
        assert_eq!(read_request(&mut input, true, None).err().expect("timeout ignored").kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn linger_socket_idles_then_reads_and_times_out_partial_heads() {
        use std::net::TcpListener;
        use std::os::fd::AsRawFd;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        // The connection's fixed receive timeout stands in for LINGER.
        server.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let fd = server.as_raw_fd();
        let mut input = BufReader::new(Sock(server));
        // Nothing arrives within the linger: idle, nothing consumed, no socket option touched.
        let deadline = HeadDeadline::new(fd, Duration::from_secs(30)).with_linger(Duration::from_millis(30)).linger_socket();
        let started = Instant::now();
        assert!(matches!(read_request(&mut input, true, Some(&deadline)).unwrap(), ParseOutcome::Idle));
        assert!(started.elapsed() >= Duration::from_millis(25) && started.elapsed() < Duration::from_secs(2));
        assert!(input.buffer().is_empty());
        assert_eq!(read_wait(), ReadWait::Linger);
        // Input present: served without waiting.
        peer.write_all(b"GET /q HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let ParseOutcome::Request(r) = read_request(&mut input, true, Some(&deadline)).unwrap() else { panic!() };
        assert_eq!(r.url, "/q");
        // A head that stalls after its first bytes gets the head budget (poll
        // after the 30 ms socket timeout), then the head timeout; never idle.
        peer.write_all(b"GET /p HTTP/1.1\r\nHo").unwrap();
        let deadline = HeadDeadline::new(fd, Duration::from_millis(90)).with_linger(Duration::from_millis(30)).linger_socket();
        let started = Instant::now();
        let kind = read_request(&mut input, true, Some(&deadline)).err().expect("stalled head accepted").kind();
        assert_eq!(kind, io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(80) && started.elapsed() < Duration::from_secs(2));
        // A body read waits its budget through the short socket timeout.
        set_read_wait(ReadWait::Budget(Duration::from_millis(200)));
        let started = Instant::now();
        let mut sock = input.into_inner();
        let writer = std::thread::spawn(move || { std::thread::sleep(Duration::from_millis(60)); peer.write_all(b"late").unwrap(); peer });
        let mut buf = [0u8; 8];
        let n = sock.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"late");
        assert!(started.elapsed() >= Duration::from_millis(50));
        // Budget exhausted with the peer still open: a timeout, not a hang.
        let _peer = writer.join().unwrap();
        set_read_wait(ReadWait::Budget(Duration::from_millis(50)));
        assert_eq!(sock.read(&mut buf).unwrap_err().kind(), io::ErrorKind::TimedOut);
        set_read_wait(ReadWait::Passthrough);
    }

    #[test]
    fn interrupted_head_reads_preserve_partial_lines_and_deadline() {
        struct InterruptedInput<'a> { bytes: &'a [u8], interrupt: bool }
        impl Read for InterruptedInput<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                let n = out.len().min(self.bytes.len()).min(3);
                out[..n].copy_from_slice(&self.bytes[..n]);
                self.bytes = &self.bytes[n..];
                Ok(n)
            }
        }
        let raw = b"GET /interrupted HTTP/1.1\r\nHost: x\r\nX-Test: intact\r\n\r\n";
        let mut input = BufReader::new(InterruptedInput { bytes: raw, interrupt: false });
        let deadline = HeadDeadline::new(-1, Duration::from_secs(1));
        let ParseOutcome::Request(request) = read_request(&mut input, true, Some(&deadline)).unwrap() else {
            panic!("interrupted head rejected")
        };
        assert_eq!(request.url, "/interrupted");
        assert_eq!(request.header("x-test"), Some("intact"));

        struct AlwaysInterrupted;
        impl Read for AlwaysInterrupted {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::Interrupted.into())
            }
        }
        let mut input = BufReader::new(AlwaysInterrupted);
        let deadline = HeadDeadline::new(-1, Duration::from_millis(5));
        let error = read_request(&mut input, true, Some(&deadline)).err().expect("deadline ignored");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn reused_head_resets_credentials_framing_and_connection_flags() {
        let raw = concat!(
            "POST /first HTTP/1.1\r\nHost: old\r\nAuthorization: Bearer fixture\r\n",
            "Content-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nabc",
            "GET /second?new=1 HTTP/1.1\r\nAccept: text/plain\r\nHost: new\r\n\r\n"
        );
        let mut input = BufReader::with_capacity(17, io::Cursor::new(raw.as_bytes()));
        let mut heads = HeadBuffer::default();
        let ParseOutcome::Request(first) = heads.read_request(&mut input, true, None).unwrap() else {
            panic!("first head rejected")
        };
        assert!(first.expect_continue && first.connection_close);
        assert_eq!(first.content_length, Some(3));
        let mut body = [0; 3];
        input.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"abc");
        heads.recycle(first);
        assert!(heads.spare.is_some());
        let ParseOutcome::Request(second) = heads.read_request(&mut input, true, None).unwrap() else {
            panic!("second head rejected")
        };
        assert_eq!(second.method, Method::Get);
        assert_eq!(second.url, "/second?new=1");
        assert_eq!(second.header("host"), Some("new"));
        assert_eq!(second.header("accept"), Some("text/plain"));
        assert_eq!(second.headers.len(), 2);
        assert_eq!(second.header("authorization"), None);
        assert_eq!(second.content_length, None);
        assert!(!second.transfer_chunked && !second.expect_continue && !second.connection_close);
    }

    #[test]
    fn reused_head_drops_large_storage_without_rejecting_the_request() {
        let raw = format!("GET /large HTTP/1.1\r\nX-First: {}\r\nX-Second: {}\r\n\r\n",
                          "a".repeat(4000), "b".repeat(4000));
        let mut input = BufReader::new(io::Cursor::new(raw.as_bytes()));
        let mut heads = HeadBuffer::default();
        let ParseOutcome::Request(request) = heads.read_request(&mut input, true, None).unwrap() else {
            panic!("valid large headers rejected")
        };
        assert_eq!(request.header("x-first").unwrap().len(), 4000);
        assert_eq!(request.header("x-second").unwrap().len(), 4000);
        heads.recycle(request);
        assert!(heads.spare.is_none());
        assert_eq!(heads.line.capacity(), 0);
    }

    // The transport script covers slice boundaries independently of sockets.
    // Real readiness / TLS / batch recovery stay in the integration gates.
    enum FirstWrite {
        Accept(usize),
        Error(io::ErrorKind),
    }
    struct VectorWrites {
        first: FirstWrite,
        delay: Duration,
        bytes: Vec<u8>,
        vectors: usize,
        scalars: usize,
        scalar_limit: usize,
        scalar_error: Option<io::ErrorKind>,
    }
    impl VectorWrites {
        fn new(first: FirstWrite) -> Self {
            Self { first, delay: Duration::ZERO, bytes: Vec::new(), vectors: 0,
                scalars: 0, scalar_limit: 7, scalar_error: None }
        }
    }
    impl Read for VectorWrites {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { Ok(0) }
    }
    impl Write for VectorWrites {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.scalars += 1;
            if let Some(error) = self.scalar_error.take() { return Err(error.into()); }
            let n = data.len().min(self.scalar_limit);
            self.bytes.extend_from_slice(&data[..n]);
            Ok(n)
        }
        fn write_vectored(&mut self, parts: &[IoSlice<'_>]) -> io::Result<usize> {
            self.vectors += 1;
            assert_eq!(self.vectors, 1, "optimistic attempt repeated");
            std::thread::sleep(self.delay);
            let mut left = match self.first {
                FirstWrite::Accept(n) => n.min(parts.iter().map(|p| p.len()).sum()),
                FirstWrite::Error(error) => return Err(error.into()),
            };
            let total = left;
            for part in parts {
                let n = left.min(part.len());
                self.bytes.extend_from_slice(&part[..n]);
                left -= n;
            }
            Ok(total)
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn large_vectored_write_accounts_for_every_prefix_body_boundary() {
        let header = b"head:";
        let body: Vec<_> = (0..129).map(|i| (i % 251) as u8).collect();
        let total = header.len() + body.len();
        for accepted in [1, header.len() - 1, header.len(), header.len() + 1, total - 1, total] {
            let client = RefCell::new(BufReader::new(VectorWrites::new(FirstWrite::Accept(accepted))));
            let mut out = Out::new(&client, -1, 64, Duration::from_secs(1));
            out.enable_plain_vectored();
            out.write_all(header).unwrap();
            let capacity = out.buf.capacity();
            assert_eq!(out.write(&body).unwrap(), body.len());
            assert_eq!(out.pending(), 0, "even a short fallback tail must drain");
            if accepted == total {
                assert_eq!(out.buf.capacity(), capacity, "complete write copied or grew output storage");
                assert_eq!(client.borrow().get_ref().scalars, 0);
            }
            let mut expected = header.to_vec();
            expected.extend_from_slice(&body);
            assert_eq!(client.borrow().get_ref().bytes, expected);
            out.write_all(b"tail").unwrap();
            out.finish_request().unwrap();
            expected.extend_from_slice(b"tail");
            assert_eq!(client.borrow().get_ref().bytes, expected);
            assert_eq!(client.borrow().get_ref().vectors, 1);
            assert!(out.buf.capacity() <= 128);
        }
    }

    #[test]
    fn large_vectored_transient_errors_fall_back_without_another_attempt() {
        for error in [io::ErrorKind::WouldBlock, io::ErrorKind::Interrupted] {
            let mut writer = VectorWrites::new(FirstWrite::Error(error));
            writer.scalar_error = Some(io::ErrorKind::Interrupted);
            let client = RefCell::new(BufReader::new(writer));
            let mut out = Out::new(&client, -1, 64, Duration::from_secs(1));
            out.enable_plain_vectored();
            out.write_all(b"head:").unwrap();
            out.write_all(&[42; 129]).unwrap();
            assert_eq!(out.pending(), 0);
            let writer = client.borrow();
            let writer = writer.get_ref();
            assert_eq!(writer.vectors, 1);
            assert!(writer.scalars > 1);
            assert_eq!(writer.bytes, [b"head:".as_slice(), &[42; 129]].concat());
        }
    }

    #[test]
    fn large_vectored_errors_propagate_and_do_not_write_later_bytes() {
        for (first, expected) in [
            (FirstWrite::Accept(0), io::ErrorKind::WriteZero),
            (FirstWrite::Error(io::ErrorKind::BrokenPipe), io::ErrorKind::BrokenPipe),
        ] {
            let client = RefCell::new(BufReader::new(VectorWrites::new(first)));
            let mut out = Out::new(&client, -1, 64, Duration::from_secs(1));
            out.enable_plain_vectored();
            out.write_all(b"head:").unwrap();
            assert_eq!(out.write_all(&[42; 129]).unwrap_err().kind(), expected);
            assert!(client.borrow().get_ref().bytes.is_empty());
            assert_eq!(client.borrow().get_ref().scalars, 0);
        }
        let mut writer = VectorWrites::new(FirstWrite::Accept(7));
        writer.scalar_error = Some(io::ErrorKind::BrokenPipe);
        let client = RefCell::new(BufReader::new(writer));
        let mut out = Out::new(&client, -1, 64, Duration::from_secs(1));
        out.enable_plain_vectored();
        out.write_all(b"head:").unwrap();
        assert_eq!(out.write_all(&[42; 129]).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(client.borrow().get_ref().bytes, b"head:**");
        assert_eq!(client.borrow().get_ref().scalars, 1);
    }

    #[test]
    fn large_vectored_attempt_cannot_start_a_fresh_fallback_deadline() {
        for first in [FirstWrite::Accept(7), FirstWrite::Error(io::ErrorKind::WouldBlock),
                      FirstWrite::Error(io::ErrorKind::Interrupted)] {
            let mut writer = VectorWrites::new(first);
            writer.delay = Duration::from_millis(20);
            let client = RefCell::new(BufReader::new(writer));
            let mut out = Out::new(&client, -1, 64, Duration::from_millis(5));
            out.enable_plain_vectored();
            out.write_all(b"head:").unwrap();
            assert_eq!(out.write_all(&[42; 129]).unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert_eq!(client.borrow().get_ref().vectors, 1);
            assert_eq!(client.borrow().get_ref().scalars, 0);
        }
    }

    #[test]
    fn large_vectored_path_requires_plain_opt_in_and_defers_to_cgi_readiness() {
        // TLS does not opt in, and even an opted-in plain CGI sink defers.
        for (plain, deferred) in [(false, false), (true, true)] {
            let client = RefCell::new(BufReader::new(VectorWrites::new(FirstWrite::Accept(usize::MAX))));
            let mut out = Out::new(&client, -1, 64, Duration::from_secs(1));
            if plain { out.enable_plain_vectored(); }
            out.set_deferred(deferred);
            out.write_all(b"head:").unwrap();
            out.write_all(&[42; 129]).unwrap();
            assert_eq!(client.borrow().get_ref().vectors, 0);
            if deferred {
                assert_eq!(out.pending(), 134);
                assert!(client.borrow().get_ref().bytes.is_empty());
                assert_eq!(client.borrow().get_ref().scalars, 0);
                out.drain_ready().unwrap();
                assert_eq!(out.pending(), 0);
            }
            assert_eq!(client.borrow().get_ref().bytes, [b"head:".as_slice(), &[42; 129]].concat());
        }
    }

    #[test]
    fn large_vectored_opt_in_leaves_direct_file_reads_unchanged() {
        let client = RefCell::new(BufReader::new(VectorWrites::new(FirstWrite::Accept(usize::MAX))));
        let mut out = Out::new(&client, -1, 64, Duration::from_secs(1));
        out.enable_plain_vectored();
        out.write_all(b"head:").unwrap();
        let source = [42; 257];
        out.copy_from(&mut io::Cursor::new(source), 129).unwrap();
        out.finish_request().unwrap();
        assert_eq!(client.borrow().get_ref().vectors, 0);
        assert_eq!(client.borrow().get_ref().bytes, [b"head:".as_slice(), &[42; 129]].concat());
    }

    #[test]
    fn reused_output_preserves_bytes_and_bounds_retained_capacity() {
        struct ShortWrites(Vec<u8>);
        impl Read for ShortWrites {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { Ok(0) }
        }
        impl Write for ShortWrites {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                let n = data.len().min(31);
                self.0.extend_from_slice(&data[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let client = RefCell::new(BufReader::new(ShortWrites(Vec::new())));
        let mut out = Out::new(&client, -1, 64, Duration::from_secs(1));
        let mut expected = Vec::new();
        for (value, length) in [(1, 65), (2, 63), (3, 512)] {
            let bytes = vec![value; length];
            out.write_all(&bytes).unwrap();
            out.finish_request().unwrap();
            expected.extend_from_slice(&bytes);
            assert_eq!(out.pending(), 0);
            assert!(out.buf.capacity() <= 128);
            assert_eq!(client.borrow().get_ref().0, expected);
        }
        struct ShortReads<'a> { bytes: &'a [u8], interrupt: bool }
        impl Read for ShortReads<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let n = out.len().min(self.bytes.len()).min(7);
                out[..n].copy_from_slice(&self.bytes[..n]);
                self.bytes = &self.bytes[n..];
                Ok(n)
            }
        }
        for length in [0, 1, 63, 64, 65, 257] {
            let bytes: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            out.write_all(b"next:").unwrap();
            let mut source = ShortReads { bytes: &bytes, interrupt: false };
            // Exactly the announced length is sent even when the file grew
            // after lookup, and no old initialized tail is exposed.
            let announced = length / 2;
            out.copy_from(&mut source, announced as u64).unwrap();
            out.finish_request().unwrap();
            expected.extend_from_slice(b"next:");
            expected.extend_from_slice(&bytes[..announced]);
            assert_eq!(client.borrow().get_ref().0, expected);
            assert_eq!(out.pending(), 0);
            assert!(out.buf.capacity() <= 128);
        }
        out.set_deferred(true);
        out.write_all(b"unfinished").unwrap();
        assert!(out.finish_request().is_err());
        assert_eq!(out.pending(), 10);
        assert_eq!(client.borrow().get_ref().0, expected);
        out.set_deferred(false);
        out.finish_request().unwrap();
        expected.extend_from_slice(b"unfinished");
        assert_eq!(client.borrow().get_ref().0, expected);

        // Transfer initialized storage to a different connection. A shorter
        // response, a header-only response and a file copy must never expose
        // bytes left by the previous client.
        let next = RefCell::new(BufReader::new(ShortWrites(Vec::new())));
        let mut out = Out::with_buffer(&next, -1, 64, Duration::from_secs(1), out.into_buffer());
        out.write_all(b"new").unwrap();
        out.finish_request().unwrap();
        out.finish_request().unwrap();
        out.copy_from(&mut io::Cursor::new(b"file"), 4).unwrap();
        out.finish_request().unwrap();
        assert_eq!(next.borrow().get_ref().0, b"newfile");
    }

    #[test]
    fn chunked_body_is_decoded_incrementally_and_rejects_bad_framing() {
        fn drain(input: &[u8], chunked: bool, len: Option<usize>) -> io::Result<Vec<u8>> {
            let request = Request {
                method: Method::Post,
                version: Version::V1_1,
                url: "/".into(),
                headers: Vec::new(),
                header_bytes: 0,
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
        // 25.12.6 rejects strtol-style prefixes, whitespace and unparsed
        // extension garbage instead of interpreting them as another size.
        for size in ["", " ", " 1", "+1", "0x1", "1 ", "1;name=bad!", "1;name=\"quoted\"", "1;x=y garbage", "80000000"] {
            let wire = format!("{size}\r\nx\r\n0\r\n\r\n");
            assert!(drain(wire.as_bytes(), true, None).is_err(), "{size:?}");
        }
        assert_eq!(drain(b"01;name=value;flag\r\nx\r\n0\r\n\r\n", true, None).unwrap(), b"x");
        // Every framing boundary requires CRLF, including the separator
        // after data and the terminating blank line after trailers.
        for wire in [b"1\nx\r\n0\r\n\r\n".as_slice(), b"1\r\nx\n0\r\n\r\n",
            b"0\n\r\n", b"0\r\nX: y\n\r\n", b"0\r\n\n"] {
            assert!(drain(wire, true, None).is_err(), "{wire:?}");
        }
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
            header_bytes: 0,
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
        for i in 0..(MAX_HEADER_FIELDS + 5) {
            input.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        input.extend_from_slice(b"\r\n");
        let err = decode_in_pieces(&[&input]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");

        let mut big = b"1\r\nz\r\n0\r\n".to_vec();
        for i in 0..30 {
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
            header_bytes: 0,
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
    /// Ask read_request what it made of one User-Agent.
    fn ua_closes(ua: &str, method: &str) -> bool {
        let raw = format!("{method} /cgi-bin/luci HTTP/1.1\r\nHost: x\r\nUser-Agent: {ua}\r\n\r\n");
        let mut input = BufReader::new(io::Cursor::new(raw.into_bytes()));
        let ParseOutcome::Request(r) = read_request(&mut input, true, None).unwrap() else {
            panic!("{ua} did not parse")
        };
        r.connection_close
    }

    /// client.c:419-447 classifies in the order Opera, MSIE, Chrome/,
    /// Safari/+Mac OS X, Gecko/, Konqueror, and client_header_complete
    /// (client.c:348-358) closes only for UH_UA_SAFARI and for old MSIE on
    /// POST. Chrome and Edge on macOS carry both "Chrome/" and
    /// "Safari/ ... Mac OS X" and are UH_UA_CHROME: keep-alive stays on.
    #[test]
    fn user_agent_close_policy_follows_uhttpd_classification_order() {
        let chrome_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let edge_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        let safari_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        let safari_ios = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        let chrome_linux = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let firefox = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0";
        for ua in [chrome_mac, edge_mac, chrome_linux, firefox, "curl/8.4.0"] {
            assert!(!ua_closes(ua, "GET"), "must keep keep-alive: {ua}");
            assert!(!ua_closes(ua, "POST"), "must keep keep-alive: {ua}");
        }
        // UH_UA_SAFARI: closes for every method
        for ua in [safari_mac, safari_ios] {
            assert!(ua_closes(ua, "GET"), "Safari must close: {ua}");
            assert!(ua_closes(ua, "POST"), "Safari must close: {ua}");
        }
        // "Opera" wins over everything after it
        assert!(!ua_closes("Opera/9.80 (Macintosh; Intel Mac OS X) Safari/537.36", "GET"));
        // UH_UA_MSIE_OLD: 4/5/6-without-SV1, and only on POST
        for old in ["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)", "Mozilla/4.0 (compatible; MSIE 4.0; Windows 95)"] {
            assert!(ua_closes(old, "POST"), "old MSIE POST must close: {old}");
            assert!(!ua_closes(old, "GET"), "old MSIE GET must not close: {old}");
        }
        // SV1 keeps MSIE 6 in UH_UA_MSIE_NEW, and 7+ is new anyway
        for new in ["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)", "Mozilla/4.0 (compatible; MSIE 60; Windows)"] {
            assert!(!ua_closes(new, "POST"), "new MSIE must keep keep-alive: {new}");
        }
    }

    /// uh_htmlescape writes numeric entities, not named ones (utils.c:292-296).
    #[test]
    fn html_escape_matches_uh_htmlescape() {
        assert_eq!(
            html_escape("<a href='x'>&\"</a>"),
            "&#x3c;a href=&#x27;x&#x27;&#x3e;&#x26;&#x22;&#x3c;/a&#x3e;"
        );
        assert_eq!(html_escape("/nope.txt?a=1"), "/nope.txt?a=1");
    }
}

#[cfg(test)]
#[path = "head_cache_tests.rs"]
mod head_cache_tests;
