//! CGI execution with uhttpd's environment, header relay and chunked body
//! forwarding. One child per request; stdin gets the request body.

use crate::files::PathInfo;
use crate::http::{Request, Response, Sink};
use owrt_ubus::sys::{poll_fds, PollFd, POLLERR, POLLHUP, POLLIN, POLLOUT};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Cap on the CGI header block, counting every byte up to and including the
/// terminating blank line, and nothing after it. uhttpd lets the relay ustream
/// grow instead; DEVIATION: a bound keeps a runaway script from consuming
/// router RAM, and no real CGI emits 64 KiB of headers.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Upper bound on how late we notice the direct script exiting while a
/// descendant still holds stdout. Only reached when the pipes are quiet.
const CHILD_TICK_MS: u64 = 50;

/// Queued response bytes above which we stop reading the script: back-pressure
/// from a slow client through to the CGI.
const OUT_WINDOW: usize = 16 * 1024;

// poll slots
const OUT_PIPE: usize = 0;
const IN_PIPE: usize = 1;
const CLIENT: usize = 2;

/// Puts the client socket in non-blocking mode while a handler drives its own
/// readiness, and restores blocking mode on every exit path.
struct NonBlockingFor(RawFd, crate::http::ReadWait);

impl NonBlockingFor {
    fn new(fd: RawFd) -> io::Result<Self> {
        crate::set_nonblocking(fd, true)?;
        // The relay owns readiness: a WouldBlock must reach it unchanged.
        let previous = crate::http::read_wait();
        crate::http::set_read_wait(crate::http::ReadWait::Passthrough);
        Ok(NonBlockingFor(fd, previous))
    }
}

impl Drop for NonBlockingFor {
    fn drop(&mut self) {
        let _ = crate::set_nonblocking(self.0, false);
        crate::http::set_read_wait(self.1);
    }
}

/// uh_relay_free() SIGKILLs a script that is still running when the relay is
/// torn down, and uloop_process reaps it. Do both on every exit from `run`, so
/// no path (timeout, malformed header, early EOF, write error) leaves a zombie
/// or blocks on a descendant that inherited the pipe.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct CgiContext<'a> {
    pub docroot: &'a str,
    pub cgi_path: &'a str,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub tls: bool,
    pub script_timeout: u64,
    pub interpreter: Option<&'a str>,
    pub redirect_status: u16,
    /// `req->realm->user`: the Basic-auth user that authenticated this
    /// request, exported as `REMOTE_USER` (uhttpd proc.c VAR_USER).
    pub remote_user: Option<&'a str>,
}

const HEADER_ENV: &[(&str, &str)] = &[
    ("HTTP_ACCEPT", "accept"),
    ("HTTP_ACCEPT_CHARSET", "accept-charset"),
    ("HTTP_ACCEPT_ENCODING", "accept-encoding"),
    ("HTTP_ACCEPT_LANGUAGE", "accept-language"),
    ("HTTP_AUTHORIZATION", "authorization"),
    ("HTTP_CONNECTION", "connection"),
    ("HTTP_COOKIE", "cookie"),
    ("HTTP_HOST", "host"),
    ("HTTP_ORIGIN", "origin"),
    ("HTTP_REFERER", "referer"),
    ("HTTP_USER_AGENT", "user-agent"),
    ("HTTP_X_HTTP_METHOD_OVERRIDE", "x-http-method-override"),
    ("HTTP_AUTH_USER", "http-auth-user"),
    ("HTTP_AUTH_PASS", "http-auth-pass"),
    ("CONTENT_TYPE", "content-type"),
    ("CONTENT_LENGTH", "content-length"),
];

pub fn is_executable(pi: &PathInfo) -> bool {
    pi.meta.is_file() && pi.meta.permissions().mode() & 0o001 != 0
}

/// uh_client_error, proc.c:195: the relay closing with the header block still
/// unfinished is the one CGI failure uhttpd reports, whatever caused it --
/// no output at all, a partial header block, a header line without a colon,
/// or the script timeout killing it before it finished its headers.
const NO_RESPONSE: &str = "The process did not produce any response";

/// The bare `strerror(errno)` text uhttpd puts in its CGI failure pages;
/// std's Display appends " (os error N)", which C never prints.
fn strerror(error: &io::Error) -> String {
    let text = error.to_string();
    match text.rfind(" (os error ") {
        Some(cut) => text[..cut].to_owned(),
        None => text,
    }
}

/// uh_client_error drops keep-alive only when a request body is still
/// outstanding -- `r->transfer_chunked || r->content_length > 0`
/// (client.c:157-164). On the CGI path it never is: proc_data_send has already
/// decremented the declared length, and it does so even when the write to the
/// script fails ("consume all data", proc.c:302-303). So a CGI error keeps the
/// connection alive and only the caller's drain has to catch up.
fn cgi_error<W: Sink>(
    resp: &mut Response<W>,
    code: u16,
    summary: &str,
    detail: &str,
) -> io::Result<()> {
    resp.error(code, summary, Some(detail))
}

/// What uhttpd answers when the CGI process could not be started.
///
/// C splits this in two: pipe(2)/fork(2) failing never reaches a child, and
/// cgi_handle_request answers 500 with an HTML page (cgi.c:91-95); an exec
/// failure happens *inside* the child, which prints its own `Status: 500`
/// header block plus a plain-text explanation (cgi.c:68-70) that then travels
/// back through the ordinary header relay. `Command::spawn` reports both as
/// one error, so the errno decides which page this is.
fn spawn_failed<W: Sink>(
    resp: &mut Response<W>,
    request: &Request,
    pi: &PathInfo,
    error: &io::Error,
    interpreter: Option<&str>,
) -> io::Result<()> {
    const EAGAIN: i32 = 11;
    const ENOMEM: i32 = 12;
    const ENFILE: i32 = 23;
    const EMFILE: i32 = 24;
    let reason = strerror(error);
    if matches!(
        error.raw_os_error(),
        Some(EAGAIN | ENOMEM | ENFILE | EMFILE)
    ) {
        resp.error(
            500,
            "Internal Server Error",
            Some(&format!("Failed to create CGI process: {reason}")),
        )?;
        // uh_create_process failed before proc_data_send was installed, so the
        // body really is still outstanding and uh_client_error drops the
        // connection -- after the header, which still says Keep-Alive.
        if request.transfer_chunked || request.content_length.is_some_and(|n| n > 0) {
            resp.force_close();
        }
        return Ok(());
    }
    // The child's own output: a Status line, no other header, then the text.
    resp.status(500, "Internal Server Error")?;
    resp.end_headers()?;
    if !resp.is_head() {
        resp.body(
            format!(
                "Unable to launch the requested CGI program:\n  {}: {reason}\n",
                interpreter
                    .map(str::to_owned)
                    .unwrap_or_else(|| pi.phys.clone())
            )
            .as_bytes(),
        )?;
    }
    resp.finish()
}

pub fn run<W: Sink, R: io::BufRead>(
    ctx: &CgiContext,
    request: &Request,
    body: &mut crate::http::BodyReader<'_, R>,
    resp: &mut Response<W>,
    pi: &PathInfo,
) -> io::Result<()> {
    let mut command = Command::new(
        ctx.interpreter
            .map(std::path::Path::new)
            .unwrap_or(pi.path()),
    );
    if ctx.interpreter.is_some() {
        command.arg(pi.path());
    }
    command
        .env_clear()
        .env("PATH", ctx.cgi_path)
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .env("SERVER_SOFTWARE", "uhttpd")
        .env("SCRIPT_NAME", pi.name())
        .env("SCRIPT_FILENAME", &pi.phys)
        .env("DOCUMENT_ROOT", ctx.docroot)
        .env("QUERY_STRING", pi.query.as_deref().unwrap_or(""))
        .env("REQUEST_URI", &request.url)
        .env("SERVER_PROTOCOL", request.version.name())
        .env("REQUEST_METHOD", request.method.name())
        .env("REDIRECT_STATUS", ctx.redirect_status.to_string())
        .env("SERVER_NAME", ctx.local.ip().to_string())
        .env("SERVER_ADDR", ctx.local.ip().to_string())
        .env("SERVER_PORT", ctx.local.port().to_string())
        .env("REMOTE_HOST", ctx.remote.ip().to_string())
        .env("REMOTE_ADDR", ctx.remote.ip().to_string())
        .env("REMOTE_PORT", ctx.remote.port().to_string())
        .current_dir(ctx.docroot)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(info) = &pi.info {
        command.env("PATH_INFO", info);
    }
    if ctx.tls {
        command.env("HTTPS", "on");
    }
    if let Some(user) = ctx.remote_user {
        command.env("REMOTE_USER", user);
    }
    for (env, header) in HEADER_ENV {
        if let Some(value) = request.header(header) {
            command.env(env, value);
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => ChildGuard(child),
        Err(error) => return spawn_failed(resp, request, pi, &error, ctx.interpreter),
    };
    // ChildStdin/ChildStdout as plain files so both ends, plus the client
    // socket, can be driven by one poll(2) loop on this thread. uhttpd runs the
    // whole exchange on one uloop; anything that blocks here -- a stalled
    // uploader, a client that stopped reading -- would otherwise outlive the
    // script timeout and hide output the script already produced.
    let mut stdin = child.0.stdin.take().map(|s| File::from(OwnedFd::from(s)));
    let mut stdout = child
        .0
        .stdout
        .take()
        .map(|s| File::from(OwnedFd::from(s)))
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let client_fd = resp.sink().fd();
    // Everything below polls for readiness, so the socket must not block. The
    // guard restores the connection's normal mode on every exit path.
    let _blocking = NonBlockingFor::new(client_fd)?;
    // From here the relay owns readiness: `write` only queues.
    resp.sink().set_deferred(true);
    // proc.c arms the timeout only when -t is positive; zero disables it.
    let deadline =
        (ctx.script_timeout > 0).then(|| Instant::now() + Duration::from_secs(ctx.script_timeout));
    // One small staging window between the client and the script: the body is
    // pulled only when the script's stdin has room, so an upload of any size
    // costs this buffer, and a script that stops reading back-pressures the
    // client instead of being buffered in our memory.
    let mut stage = [0u8; 4096];
    let mut staged = 0usize;
    let mut stage_pos = 0usize;
    let mut status_code = 200i32;
    let mut status_text = String::from("OK");
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut disable_chunked = false;
    let mut header_buf: Vec<u8> = Vec::new();
    let mut header_bytes = 0usize;
    let mut headers_done = false;
    let mut script_done = false;
    let mut relay_eof = false;
    let mut body_failed = false;
    let mut aborted = false;
    let mut buf = [0u8; 16384];
    loop {
        // relay_proc_cb() marks process_done and schedules relay_close_if_done,
        // so the *direct* script exiting ends the request even while a
        // descendant still holds stdout.
        if !script_done && matches!(child.0.try_wait(), Ok(Some(_))) {
            script_done = true;
        }
        // proc_timeout_cb: at the deadline the script is SIGKILLed (the guard
        // does it) and the relay ends where it stands.
        let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        if remaining.is_some_and(|left| left.is_zero()) {
            break;
        }
        // Read the script only while the response window has room: that is the
        // back-pressure path from a slow client all the way to the script.
        let want_stdout = !relay_eof && resp.sink().pending() < OUT_WINDOW;
        // Refill the stage before choosing what to wait on. Doing it here also
        // consumes what BufReader (or rustls) already holds, which no socket
        // event would ever announce.
        if stdin.is_some() && stage_pos == staged && !body_failed {
            stage_pos = 0;
            staged = 0;
            match body.read(&mut stage) {
                // whole body delivered: closing stdin is the script's EOF
                Ok(0) => stdin = None,
                Ok(got) => staged = got,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    // truncated or malformed upload: the script sees EOF and
                    // decides, but the connection is no longer reusable
                    body_failed = true;
                    stdin = None;
                }
            }
        }
        let have_staged = stage_pos < staged;
        // Waiting for stdin to be writable when we have nothing to write spins:
        // a pipe with room is always writable, so poll returns at once and the
        // loop burns a core until the deadline. Register it for writability
        // only with bytes in hand; otherwise keep it in the set with no events
        // so HUP/ERR still arrive, and wait on the client instead.
        let want_body = stdin.is_some() && !have_staged && !body_failed;
        let want_write = resp.sink().pending() > 0;
        let mut fds = [PollFd {
            fd: -1,
            events: 0,
            revents: 0,
        }; 4];
        let mut slot = [usize::MAX; 4];
        let mut n = 0;
        let add = |fd: RawFd,
                   events: i16,
                   which: usize,
                   fds: &mut [PollFd; 4],
                   slot: &mut [usize; 4],
                   n: &mut usize| {
            fds[*n] = PollFd {
                fd,
                events,
                revents: 0,
            };
            slot[*n] = which;
            *n += 1;
        };
        if want_stdout {
            add(
                stdout.as_raw_fd(),
                POLLIN,
                OUT_PIPE,
                &mut fds,
                &mut slot,
                &mut n,
            );
        }
        if let Some(f) = &stdin {
            let events = if have_staged { POLLOUT } else { 0 };
            add(f.as_raw_fd(), events, IN_PIPE, &mut fds, &mut slot, &mut n);
        }
        if want_body || want_write {
            let events =
                (if want_body { POLLIN } else { 0 }) | (if want_write { POLLOUT } else { 0 });
            add(client_fd, events, CLIENT, &mut fds, &mut slot, &mut n);
        }
        if n == 0 {
            break;
        }
        // A finished script gets one non-blocking pass (the ustream_poll in
        // relay_proc_cb), never a wait on a descendant's EOF. Otherwise cap the
        // wait at one tick: uloop learns of the exit from SIGCHLD, we re-check
        // try_wait, so the exit is noticed within CHILD_TICK_MS.
        let wait_ms = if script_done && !want_write {
            0
        } else {
            remaining.map_or(CHILD_TICK_MS as i32, |left| {
                left.as_millis().min(CHILD_TICK_MS as u128) as i32
            })
        };
        if poll_fds(&mut fds[..n], wait_ms).is_err() {
            break;
        }
        let mut ready = 0;
        let mut client_ready = 0i16;
        for i in 0..n {
            if fds[i].revents == 0 {
                continue;
            }
            ready += 1;
            match slot[i] {
                CLIENT => client_ready = fds[i].revents,
                // HUP/ERR: the script closed stdin. Drop the write end first,
                // so we never read the client on its behalf.
                IN_PIPE if fds[i].revents & (POLLERR | POLLHUP) != 0 => stdin = None,
                _ => {}
            }
        }
        // Push queued response bytes first: it frees the window that gates
        // reading the script, and it is what an early rejection needs to reach
        // a client that is still uploading.
        if client_ready & POLLOUT != 0 && resp.sink().drain_ready().is_err() {
            break;
        }
        // Feed stdin with what the refill above staged.
        if have_staged
            && stdin.is_some()
            && fds[..n].iter().any(|f| {
                f.fd == stdin.as_ref().map_or(-1, |s| s.as_raw_fd()) && f.revents & POLLOUT != 0
            })
        {
            match stdin
                .as_mut()
                .expect("checked")
                .write(&stage[stage_pos..staged])
            {
                Ok(0) | Err(_) => stdin = None,
                Ok(w) => stage_pos += w,
            }
        }
        // Consume the script's output. This happens in the same round as the
        // upload, so an early "Status: 403" is never lost behind a stalled body.
        let stdout_ready = fds[..n]
            .iter()
            .any(|f| f.fd == stdout.as_raw_fd() && f.revents != 0);
        if want_stdout && stdout_ready {
            let got = match stdout.read(&mut buf) {
                // relay EOF: relay_close_if_done() finishes the request here
                // even when the script is still alive; the guard kills it.
                Ok(0) => {
                    relay_eof = true;
                    0
                }
                Ok(got) => got,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    relay_eof = true;
                    0
                }
            };
            if got > 0
                && !relay(
                    &buf[..got],
                    resp,
                    &mut headers_done,
                    &mut header_buf,
                    &mut header_bytes,
                    &mut headers,
                    &mut status_code,
                    &mut status_text,
                    &mut disable_chunked,
                )?
            {
                // the relay wrote its own error page and is finished
                aborted = true;
                break;
            }
        }
        if relay_eof && resp.sink().pending() == 0 {
            break;
        }
        if script_done && ready == 0 && resp.sink().pending() == 0 {
            break;
        }
    }
    // One exit: whatever the tail decides, the queued bytes still have to reach
    // the client and the sink has to go back to draining itself. An early
    // `return` here would leave a 504 sitting in the buffer.
    let outcome = (|| -> io::Result<()> {
        if aborted {
            return Ok(());
        }
        if !headers_done {
            // proc_handle_close (proc.c:192-198): the relay closed with
            // r->header_cb still set. Every route here is the same 502 in C --
            // a script that printed nothing, one that printed a partial header
            // block, and proc_timeout_cb SIGKILLing one that had not finished
            // its headers (proc.c:322-328 -> relay.c:181-188 -> 151-162).
            // uhttpd has no 504 anywhere, and never promotes a half-written
            // header block to a 200.
            return cgi_error(resp, 502, "Bad Gateway", NO_RESPONSE);
        }
        resp.finish()
    })();
    // Bounded by whatever is left of the script budget, with a floor so a
    // response that is ready right at the deadline still gets out.
    let flushed = outcome.and_then(|()| match deadline {
        Some(deadline) => {
            let left = deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(CHILD_TICK_MS));
            flush_within(resp.sink(), left)
        }
        None => {
            // With no script budget, use the sink's configured network budget.
            resp.sink().set_deferred(false);
            resp.sink().flush()
        }
    });
    resp.sink().set_deferred(false);
    flushed
}

/// Push the queued response out, polling for writability, within `budget`.
fn flush_within<S: Sink>(sink: &mut S, budget: Duration) -> io::Result<()> {
    let deadline = Instant::now() + budget;
    while sink.pending() > 0 {
        let before = sink.pending();
        sink.drain_ready()?;
        if sink.pending() == before {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "client stopped reading",
                ));
            }
            let mut pfd = [PollFd {
                fd: sink.fd(),
                events: POLLOUT,
                revents: 0,
            }];
            if poll_fds(&mut pfd, left.as_millis().min(i32::MAX as u128) as i32)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "client stopped reading",
                ));
            }
        }
    }
    Ok(())
}

/// One chunk of script output: parse the header block, then relay the body.
/// `Ok(false)` means the relay wrote an error page and the request is over.
#[allow(clippy::too_many_arguments)]
fn relay<W: Sink>(
    chunk: &[u8],
    resp: &mut Response<W>,
    headers_done: &mut bool,
    header_buf: &mut Vec<u8>,
    header_bytes: &mut usize,
    headers: &mut Vec<(String, String)>,
    status_code: &mut i32,
    status_text: &mut String,
    disable_chunked: &mut bool,
) -> io::Result<bool> {
    if *headers_done {
        if !resp.is_head() {
            resp.body(chunk)?;
        }
        return Ok(true);
    }
    header_buf.extend_from_slice(chunk);
    while let Some(pos) = header_buf.iter().position(|&b| b == b'\n') {
        let mut line: Vec<u8> = header_buf.drain(..=pos).collect();
        // Only bytes up to and including the terminating blank line are header;
        // body sharing that read must never count against the cap.
        *header_bytes += line.len();
        if *header_bytes > MAX_HEADER_BYTES {
            // DEVIATION, no C counterpart: reading stops here, so what is
            // left of the body would desynchronise the connection.
            resp.force_close();
            cgi_error(
                resp,
                500,
                "Internal Server Error",
                "CGI header block too large",
            )?;
            return Ok(false);
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            *headers_done = true;
            if *disable_chunked {
                resp.disable_chunked();
            }
            resp.status(*status_code, status_text)?;
            for (name, value) in headers.iter() {
                resp.header(name, value)?;
            }
            resp.end_headers()?;
            if !resp.is_head() && !header_buf.is_empty() {
                let rest = std::mem::take(header_buf);
                resp.body(&rest)?;
            }
            return Ok(true);
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        let Some((name, value)) = text.split_once(':') else {
            // uh_split_header returns NULL, relay_error() aborts the relay
            // (relay.c:101-104) and the close callback answers 502 with the
            // same message as any other unfinished header block (proc.c:195).
            // DEVIATION (kept): C only sends it once the script actually dies,
            // i.e. at the script timeout for a script that keeps running;
            // this answers immediately and the guard kills the script.
            cgi_error(resp, 502, "Bad Gateway", NO_RESPONSE)?;
            return Ok(false);
        };
        let name = name.trim();
        let value = value.trim();
        if name == "Status" {
            if let Some((code, rest)) = value.split_once(' ') {
                if code.len() == 3 {
                    // proc.c applies atoi() to exactly three bytes, even
                    // for "abc", "+12" or "-12". The range is bounded.
                    let (sign, digits) = match code.as_bytes() {
                        [b'-', tail @ ..] => (-1, tail),
                        [b'+', tail @ ..] => (1, tail),
                        bytes => (1, bytes),
                    };
                    *status_code = sign
                        * digits
                            .iter()
                            .take_while(|b| b.is_ascii_digit())
                            .fold(0, |n, b| n * 10 + i32::from(b - b'0'));
                    *status_text = rest.to_owned();
                }
            }
            continue;
        }
        if name.eq_ignore_ascii_case("Content-Length")
            || name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            *disable_chunked = true;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    // Headers still unfinished: what is buffered is all header, so it counts.
    if *header_bytes + header_buf.len() > MAX_HEADER_BYTES {
        resp.force_close();
        cgi_error(
            resp,
            500,
            "Internal Server Error",
            "CGI header block too large",
        )?;
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Method, Version};
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn script_fixture(script: &str) -> (std::path::PathBuf, PathInfo) {
        script_fixture_raw(&format!("#!/bin/sh\n{script}"))
    }

    /// Same, but the caller writes the whole file -- shebang included, so a
    /// missing interpreter can be tested.
    fn script_fixture_raw(content: &str) -> (std::path::PathBuf, PathInfo) {
        let dir = std::env::temp_dir().join(format!(
            "owrt-cgi-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let phys = dir.join("script");
        fs::write(&phys, content).unwrap();
        fs::set_permissions(&phys, fs::Permissions::from_mode(0o755)).unwrap();
        let meta = fs::metadata(&phys).unwrap();
        let pi = PathInfo::for_test(
            phys.to_str().unwrap().to_owned(),
            dir.to_str().unwrap().len(),
            meta,
        );
        assert_eq!(pi.name(), "/script");
        (dir, pi)
    }

    type TestSource = std::cell::RefCell<io::BufReader<io::Cursor<Vec<u8>>>>;

    /// Sink that keeps everything in memory: fd -1 is ignored by poll(2), so
    /// the relay simply never sees the client as ready.
    struct VecSink(Vec<u8>);

    impl Write for VecSink {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Sink for VecSink {
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

    fn empty_source() -> TestSource {
        std::cell::RefCell::new(io::BufReader::new(io::Cursor::new(Vec::new())))
    }

    fn get_request() -> Request {
        Request {
            method: Method::Get,
            version: Version::V1_0,
            url: "/script".into(),
            headers: Vec::new(),
            header_bytes: 0,
            content_length: None,
            transfer_chunked: false,
            connection_close: true,
            expect_continue: false,
        }
    }

    /// Run one throwaway CGI script and report (response bytes, elapsed ms).
    fn run_script(script: &str, script_timeout: u64) -> (String, u128) {
        run_fixture(script_fixture(script), script_timeout)
    }

    fn run_raw(content: &str, script_timeout: u64) -> (String, u128) {
        run_fixture(script_fixture_raw(content), script_timeout)
    }

    fn run_fixture(
        (dir, pi): (std::path::PathBuf, PathInfo),
        script_timeout: u64,
    ) -> (String, u128) {
        let request = get_request();
        let local = "127.0.0.1:80".parse().unwrap();
        let ctx = CgiContext {
            interpreter: None,
            redirect_status: 200,
            remote_user: None,
            docroot: dir.to_str().unwrap(),
            cgi_path: "/bin:/usr/bin",
            local,
            remote: local,
            tls: false,
            script_timeout,
        };
        let mut out = VecSink(Vec::new());
        let src = empty_source();
        let started = Instant::now();
        {
            let mut resp = Response::new(&mut out, &request, 0);
            run(
                &ctx,
                &request,
                &mut crate::http::BodyReader::new(&src, &request),
                &mut resp,
                &pi,
            )
            .unwrap();
        }
        let elapsed = started.elapsed().as_millis();
        let _ = fs::remove_dir_all(&dir);
        (String::from_utf8_lossy(&out.0).into_owned(), elapsed)
    }

    /// relay_close_if_done() finishes on stdout EOF and uh_relay_free() kills
    /// the script that is still running; we must not wait out its lifetime.
    /// No header block was produced, so this is proc_handle_close's 502.
    #[test]
    fn stdout_eof_finishes_the_request_without_waiting_for_the_script() {
        let (out, ms) = run_script("exec 1>&-\nsleep 5\n", 1);
        assert!(out.starts_with("HTTP/1.0 502 Bad Gateway"), "{out:?}");
        assert!(ms < 1000, "took {ms} ms, should end at relay EOF");
    }

    /// proc_timeout_cb() SIGKILLs and marks the relay EOF itself, so a
    /// descendant still holding the pipe cannot extend the request.
    #[test]
    fn descendant_holding_stdout_cannot_outlive_the_script_timeout() {
        let (out, ms) = run_script("sleep 5 &\nwait\n", 1);
        assert!(out.starts_with("HTTP/1.0 502 Bad Gateway"), "{out:?}");
        assert!((900..3000).contains(&ms), "took {ms} ms, expected ~1000");
    }

    /// relay_proc_cb(): the direct script exiting ends the request, even with a
    /// descendant still holding stdout. This used to answer 504 at the deadline
    /// for a script that had already succeeded.
    #[test]
    fn direct_exit_with_a_descendant_on_stdout_is_not_a_timeout() {
        let (out, ms) = run_script(
            "sleep 5 &\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok'\nexit 0\n",
            1,
        );
        assert!(out.starts_with("HTTP/1.0 200 OK"), "{out:?}");
        assert!(out.ends_with("ok"), "{out:?}");
        assert!(ms < 900, "took {ms} ms, should end when the script exits");
    }

    /// The header cap must not count body bytes that share the final read.
    #[test]
    fn body_arriving_with_the_last_header_line_is_not_charged_to_the_header_cap() {
        let (out, _) = run_script(
            "i=0; while [ $i -lt 700 ]; do printf 'X-Pad-%s: %s\\r\\n' $i              aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;              i=$((i+1)); done\nprintf '\\r\\n'\nhead -c 16384 /dev/zero | tr '\\0' 'b'\n",
            5,
        );
        assert!(
            out.starts_with("HTTP/1.0 200 OK"),
            "{}",
            &out[..out.len().min(120)]
        );
        assert!(out.contains('b'), "body missing");
    }

    /// The cap counts header bytes only. 65535/65536/65537 must land on the
    /// right side of it regardless of how the pipe split the writes, and a body
    /// sharing the terminator's read must never count.
    #[test]
    fn header_cap_counts_only_header_bytes() {
        // one padding header line of `pad` bytes plus CRLFCRLF, then a body
        let build = |pad: usize, body: usize| {
            format!(
                "printf 'X-Pad: %s\\r\\n' {}\nsleep 0.1\nprintf '\\r\\n'\nhead -c {body} /dev/zero | tr '\\0' 'b'\n",
                "a".repeat(pad)
            )
        };
        // "X-Pad: " (7) + pad + CRLF (2) + CRLF (2) == total header bytes
        for (total, want_ok) in [
            (super::MAX_HEADER_BYTES - 1, true),
            (super::MAX_HEADER_BYTES, true),
            (super::MAX_HEADER_BYTES + 1, false),
        ] {
            let pad = total - 11;
            let (out, _) = run_script(&build(pad, 16384), 5);
            let line = out.lines().next().unwrap_or("");
            if want_ok {
                assert!(
                    line.starts_with("HTTP/1.0 200"),
                    "header total {total}: {line}"
                );
                assert!(out.contains('b'), "header total {total}: body missing");
            } else {
                assert!(
                    line.starts_with("HTTP/1.0 500"),
                    "header total {total}: {line}"
                );
            }
        }
    }

    /// uhttpd's script timeout runs on uloop, so a client that stops reading
    /// cannot extend the script's life. The relay drives the socket through the
    /// same poll loop, so the write never outlasts the budget.
    #[test]
    fn a_client_that_never_reads_cannot_outlive_the_script_timeout() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // held open, never read from
        let _client = TcpStream::connect(addr).unwrap();
        let (sock, _) = listener.accept().unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let fd = sock.as_raw_fd();
        let cell = std::cell::RefCell::new(io::BufReader::new(sock));
        let (dir, pi) = script_fixture(
            "printf 'Content-Type: application/octet-stream\\r\\n\\r\\n'\nhead -c 33554432 /dev/zero\n",
        );
        let request = get_request();
        let local = "127.0.0.1:80".parse().unwrap();
        let ctx = CgiContext {
            interpreter: None,
            redirect_status: 200,
            remote_user: None,
            docroot: dir.to_str().unwrap(),
            cgi_path: "/bin:/usr/bin",
            local,
            remote: local,
            tls: false,
            script_timeout: 1,
        };
        let src = empty_source();
        let started = Instant::now();
        {
            let mut out = crate::http::Out::new(&cell, fd, 16 * 1024, Duration::from_secs(30));
            let mut resp = Response::new(&mut out, &request, 0);
            let _ = run(
                &ctx,
                &request,
                &mut crate::http::BodyReader::new(&src, &request),
                &mut resp,
                &pi,
            );
        }
        let ms = started.elapsed().as_millis();
        let _ = fs::remove_dir_all(&dir);
        assert!(
            ms < 2500,
            "took {ms} ms with -t 1; the stalled client held the script"
        );
    }

    /// relay.c:101-104 + proc.c:195: a header line without a colon aborts the
    /// relay, and the close callback answers the same 502 as any other
    /// unfinished header block.
    #[test]
    fn malformed_header_aborts_the_relay_promptly() {
        let (out, ms) = run_script("printf 'invalid\\r\\n'\nsleep 5\n", 5);
        assert!(out.starts_with("HTTP/1.0 502 Bad Gateway"), "{out:?}");
        assert!(out.contains(NO_RESPONSE), "{out:?}");
        assert!(ms < 1000, "took {ms} ms, should not wait for the script");
    }

    /// proc.c:192-201 proc_handle_close: when the relay closes and the header
    /// block was never completed, uhttpd answers 502 Bad Gateway "The process
    /// did not produce any response" -- never a 200 carrying the half-written
    /// header block as its body.
    #[test]
    fn script_that_exits_without_headers_is_502() {
        for script in [
            "exit 1\n",
            "exit 0\n",
            "printf 'Content-Type: text/plain\\r\\n'\nexit 0\n",
        ] {
            let (out, _) = run_script(script, 5);
            assert!(
                out.starts_with("HTTP/1.0 502 Bad Gateway"),
                "{script:?}: {out:?}"
            );
            assert!(out.contains(NO_RESPONSE), "{script:?}: {out:?}");
        }
    }

    /// proc.c:322-328 proc_timeout_cb -> uh_relay_kill -> relay_close_if_done
    /// -> proc_handle_close: a script killed at the deadline before finishing
    /// its headers also gets 502. uhttpd has no 504 anywhere.
    #[test]
    fn script_timeout_before_headers_is_502() {
        let (out, ms) = run_script("sleep 5\n", 1);
        assert!(out.starts_with("HTTP/1.0 502 Bad Gateway"), "{out:?}");
        assert!((900..3000).contains(&ms), "took {ms} ms, expected ~1000");
    }

    /// cgi.c:68-70: exec failing is reported by the child itself, as a CGI
    /// `Status: 500` header block plus a plain-text explanation -- so no
    /// Content-Type, and the connection is not simply dropped.
    #[test]
    fn missing_interpreter_is_the_cgi_launch_failure_page() {
        let (out, _) = run_raw("#!/usr/bin/definitely-missing-interpreter\ntrue\n", 5);
        assert!(
            out.starts_with("HTTP/1.0 500 Internal Server Error"),
            "{out:?}"
        );
        assert!(
            out.contains("Unable to launch the requested CGI program:\n  "),
            "{out:?}"
        );
        assert!(out.contains("No such file or directory"), "{out:?}");
        assert!(
            !out.to_ascii_lowercase().contains("content-type"),
            "{out:?}"
        );
        assert!(!out.contains("os error"), "strerror only: {out:?}");
    }

    /// uh_client_error's close rule reads `r->content_length`, which
    /// proc_data_send has already spent by the time the relay fails
    /// (proc.c:286-320) -- so a CGI error on a request that carried a body
    /// still answers Connection: Keep-Alive.
    #[test]
    fn cgi_error_keeps_keep_alive_even_with_a_request_body() {
        let (dir, pi) = script_fixture("exit 1\n");
        let mut request = get_request();
        request.version = Version::V1_1;
        request.connection_close = false;
        request.content_length = Some(4);
        let local = "127.0.0.1:80".parse().unwrap();
        let ctx = CgiContext {
            interpreter: None,
            redirect_status: 200,
            remote_user: None,
            docroot: dir.to_str().unwrap(),
            cgi_path: "/bin:/usr/bin",
            local,
            remote: local,
            tls: false,
            script_timeout: 5,
        };
        let mut out = VecSink(Vec::new());
        let src = std::cell::RefCell::new(io::BufReader::new(io::Cursor::new(b"body".to_vec())));
        let close;
        {
            let mut resp = Response::new(&mut out, &request, 20);
            run(
                &ctx,
                &request,
                &mut crate::http::BodyReader::new(&src, &request),
                &mut resp,
                &pi,
            )
            .unwrap();
            close = resp.connection_close();
        }
        let _ = fs::remove_dir_all(&dir);
        let text = String::from_utf8_lossy(&out.0).into_owned();
        assert!(!close, "{text:?}");
        assert!(text.starts_with("HTTP/1.1 502 Bad Gateway"), "{text:?}");
        assert!(text.contains("Connection: Keep-Alive"), "{text:?}");
    }
}
