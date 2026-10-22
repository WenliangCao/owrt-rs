//! Inline service of parked plain-HTTP connections on their listener thread.
//!
//! A connection that went quiet for LINGER lives in its listener's readiness
//! set. A complete small GET/HEAD head for a regular file is answered from
//! bounded per-listener scratch, with the socket never leaving the poll set.
//!
//! Ownership contract:
//! nothing is consumed from the socket and nothing is sent until a complete
//! response has been generated into memory. Every ineligible or uncertain
//! request falls back to the existing thread path with the socket bytes
//! untouched. After the head is consumed, the only
//! remaining outcomes are delivering the bytes or closing the connection;
//! there is no re-parse and no second handler run.

use crate::files::{self, Lookup};
use crate::http::{self, Method, ParseOutcome, Response};
use crate::{is_rfc1918, path_matches, Parked, Server, Transport};
use std::io::{self, BufReader, Cursor, Write};
use std::os::fd::{AsFd, RawFd};
use rustix::net::{self, RecvFlags, SendFlags};
use std::os::unix::fs::MetadataExt;

/// Largest file body served inline. Covers LuCI's small assets and the
/// device's 16 KiB benchmark lane; bigger transfers keep their thread and
/// its backpressure-aware relay.
const MAX_BODY: u64 = 32 * 1024;
/// Response budget: body plus generous head room for the header block.
const MAX_RESPONSE: usize = MAX_BODY as usize + 1024;
/// At most this many connections may hold a partially-sent response. The
/// budget bounds retained buffers; at the cap new requests take a thread.
pub const MAX_PENDING: usize = 4;
/// Peek window. A head that does not end inside it is not judged here.
const PEEK: usize = 4096;

/// A committed response the socket has not fully accepted yet. The head is
/// already consumed; the listener keeps POLLOUT interest until `off` reaches
/// the end, then closes or returns the connection to keep-alive parking.
pub struct PendingReply {
    buf: Vec<u8>,
    off: usize,
    close: bool,
}

/// Per-listener working storage. Bounded and reused; parked connections
/// themselves keep no buffers.
pub struct Scratch {
    peek: Box<[u8; PEEK]>,
    heads: http::HeadBuffer,
    resp: Option<Vec<u8>>,
}

impl Default for Scratch {
    fn default() -> Self {
        Scratch { peek: Box::new([0; PEEK]), heads: http::HeadBuffer::default(), resp: None }
    }
}

impl Scratch {
    fn take_resp(&mut self) -> Vec<u8> {
        let mut buf = self.resp.take().unwrap_or_default();
        buf.clear();
        buf
    }

    fn return_resp(&mut self, buf: Vec<u8>) {
        if buf.capacity() <= 2 * MAX_RESPONSE {
            self.resp = Some(buf);
        }
    }
}

/// What the listener should do with the connection after one event.
#[derive(Debug)]
pub enum Event {
    /// Nothing was consumed or sent; the connection stays parked unchanged.
    Spurious,
    /// One response fully delivered; keep-alive continues.
    Served,
    /// One response fully delivered; the request or policy closes the
    /// connection.
    ServedClose,
    /// Peer gone or transport failed; close and release the slot.
    Close,
    /// Not eligible here. The socket is untouched: hand it a thread.
    Handoff,
    /// Response committed but not fully accepted; poll for POLLOUT.
    Writing,
}

/// The response sink for inline service: plain memory with a hard budget.
/// Exceeding the budget aborts response generation before anything has been
/// consumed or sent, so the request falls back to the thread path whole.
struct MemSink {
    buf: Vec<u8>,
    cap: usize,
}

impl Write for MemSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.cap {
            return Err(io::Error::other("inline response over budget"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl http::Sink for MemSink {
    fn pending(&self) -> usize {
        0
    }
    fn drain_ready(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn set_deferred(&mut self, _on: bool) {}
    fn fd(&self) -> RawFd {
        -1
    }
}

/// Byte offset one past the blank line that ends a request head, when the
/// whole head lies within `buf`. Leading blank lines are not handled here:
/// the parser tolerates them, but their length would not be counted in the
/// consumed head, so such input reports no end and falls back.
fn head_end(buf: &[u8]) -> Option<usize> {
    if matches!(buf.first(), Some(b'\r' | b'\n')) {
        return None;
    }
    let mut i = 0;
    while i < buf.len() {
        let nl = i + buf[i..].iter().position(|&b| b == b'\n')?;
        if nl == i || (nl == i + 1 && buf[i] == b'\r') {
            return Some(nl + 1);
        }
        i = nl + 1;
    }
    None
}

fn peek_bytes(fd: impl AsFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match net::recv(&fd, &mut *buf, RecvFlags::PEEK | RecvFlags::DONTWAIT) {
            Ok((_, size)) => return Ok(size),
            Err(rustix::io::Errno::INTR) => (),
            Err(error) => return Err(error.into()),
        }
    }
}

/// Consume exactly the already-peeked head. Never reparse after consumption.
fn consume(fd: impl AsFd, scratch: &mut [u8], mut len: usize) -> io::Result<()> {
    while len > 0 {
        let want = len.min(scratch.len());
        match net::recv(&fd, &mut scratch[..want], RecvFlags::DONTWAIT) {
            Ok((_, 0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok((_, size)) => len -= size,
            Err(rustix::io::Errno::INTR) => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

enum SendOutcome { Complete, Blocked(usize) }
fn send_some(fd: impl AsFd, buf: &[u8], mut off: usize) -> io::Result<SendOutcome> {
    while off < buf.len() {
        match net::send(&fd, &buf[off..], SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(size) => off += size,
            Err(rustix::io::Errno::INTR) => (),
            Err(rustix::io::Errno::AGAIN) => return Ok(SendOutcome::Blocked(off)),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(SendOutcome::Complete)
}

/// A parked plain connection reported input. Serve one eligible request
/// without moving the socket; report anything else for the caller to hand
/// off, close or ignore. `writing` is how many connections already hold a
/// pending reply on this listener.
pub fn on_readable(server: &Server, p: &mut Parked, s: &mut Scratch, writing: usize) -> Event {
    let peeked = match peek_bytes(p.transport.tcp(), &mut s.peek[..]) {
        Ok(0) => return Event::Close,
        Ok(n) => n,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Event::Spurious,
        Err(_) => return Event::Close,
    };
    let Some(head_len) = head_end(&s.peek[..peeked]) else {
        // Incomplete within the window, oversized, or leading blank lines.
        return Event::Handoff;
    };
    if head_len < peeked {
        // Pipelined input: keep the exact consumption behavior of the
        // sequential reader on a thread.
        return Event::Handoff;
    }
    if writing >= MAX_PENDING {
        return Event::Handoff;
    }
    let config = &server.config;
    let mut reader = BufReader::new(Cursor::new(&s.peek[..head_len]));
    let request = match s.heads.read_request(&mut reader, config.http_keepalive > 0, None) {
        Ok(ParseOutcome::Request(request)) => request,
        // Bad heads keep their existing thread-generated responses; Eof and
        // Idle cannot happen on a complete in-memory head.
        _ => return Event::Handoff,
    };
    let eligible = matches!(request.method, Method::Get | Method::Head)
        && !request.expect_continue
        && !request.transfer_chunked
        && !request.content_length.is_some_and(|n| n > 0)
        // Policy handled before lookup on the thread path; any configured
        // rewrite or filter that would apply falls back whole.
        && !(config.rfc1918_filter
            && is_rfc1918(p.conn.remote.ip())
            && !is_rfc1918(p.conn.local.ip()))
        && !config.tls_redirect
        && config.aliases.is_empty()
        && config.auth.is_empty()
        && !config
            .ubus_prefix
            .as_deref()
            .is_some_and(|prefix| path_matches(prefix, &request.url));
    if !eligible {
        return Event::Handoff;
    }
    let pi = match files::lookup(&config.docroot, &request.url, config.no_symlinks, &config.index_files) {
        Lookup::Found(pi) => pi,
        Lookup::Redirect(_) | Lookup::NotFound => return Event::Handoff,
    };
    let physical = pi.phys.as_str();
    if pi.info.is_some()
        || !pi.meta.is_file()
        || pi.meta.size() > MAX_BODY
        || config.interpreters.iter().any(|(ext, _)| physical.len() > ext.len() && physical.ends_with(ext.as_str()))
        || server
            .cgi_physical_prefix
            .as_deref()
            .is_some_and(|prefix| path_matches(prefix, physical))
    {
        return Event::Handoff;
    }
    // Generate the complete response into bounded memory before touching the
    // socket. files::serve is the same code the thread path runs, so status,
    // conditionals, ETag, MIME, HEAD handling and bodies stay byte-identical.
    let mut sink = MemSink { buf: s.take_resp(), cap: MAX_RESPONSE };
    let close;
    {
        let mut resp = Response::new(&mut sink, &request, config.http_keepalive);
        // The listener serves many connections; a file kept open here would
        // outlive the connection, so it never reuses descriptors.
        match files::serve(&request, &mut resp, &pi, config.no_dirlists, &config.dirlist_charset, false) {
            Ok(files::Served::Complete) => {}
            Ok(files::Served::Forbidden) | Err(_) => {
                s.return_resp(sink.buf);
                return Event::Handoff;
            }
        }
        close = resp.connection_close();
    }
    s.heads.recycle(request);
    // Commit: consume exactly the parsed head, then deliver.
    let buf = sink.buf;
    if consume(p.transport.tcp(), &mut s.peek[..], head_len).is_err() {
        s.return_resp(buf);
        return Event::Close;
    }
    match send_some(p.transport.tcp(), &buf, 0) {
        Ok(SendOutcome::Complete) => {
            s.return_resp(buf);
            if close {
                Event::ServedClose
            } else {
                Event::Served
            }
        }
        Ok(SendOutcome::Blocked(off)) => {
            p.writing = Some(PendingReply { buf, off, close });
            Event::Writing
        }
        Err(_) => {
            s.return_resp(buf);
            Event::Close
        }
    }
}

/// A connection holding a pending reply reported output readiness.
pub fn on_writable(p: &mut Parked, s: &mut Scratch) -> Event {
    let Some(w) = p.writing.as_mut() else {
        return Event::Spurious;
    };
    match send_some(p.transport.tcp(), &w.buf, w.off) {
        Ok(SendOutcome::Complete) => {
            let w = p.writing.take().expect("checked above");
            s.return_resp(w.buf);
            if w.close {
                Event::ServedClose
            } else {
                Event::Served
            }
        }
        Ok(SendOutcome::Blocked(off)) => {
            w.off = off;
            Event::Writing
        }
        Err(_) => {
            p.writing = None;
            Event::Close
        }
    }
}

/// Whether this parked connection is eligible for inline events at all.
pub fn wants_inline(p: &Parked) -> bool {
    p.writing.is_some() || matches!(p.transport, Transport::Plain(_))
}

/// Test-only: place a committed reply on a connection as if its send had
/// blocked at offset zero, so the drain path can be driven deterministically.
#[cfg(test)]
pub fn inject_pending(p: &mut Parked, buf: Vec<u8>, close: bool) {
    p.writing = Some(PendingReply { buf, off: 0, close });
}

#[cfg(test)]
mod tests {
    use super::head_end;

    #[test]
    fn head_end_finds_the_blank_line_and_rejects_partial_or_leading_blank() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET"), Some(27));
        assert_eq!(head_end(b"GET / HTTP/1.1\nHost: a\n\n"), Some(24));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: a\r\n"), None);
        assert_eq!(head_end(b"GET / HTTP/1.1"), None);
        assert_eq!(head_end(b"\r\nGET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(head_end(b"\nGET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(head_end(b""), None);
    }
}
