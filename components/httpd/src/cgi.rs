//! CGI execution with uhttpd's environment, header relay and chunked body
//! forwarding. One child per request; stdin gets the request body.

use crate::files::PathInfo;
use crate::http::{Request, Response};
use owrt_ubus::sys::{poll_fds, PollFd, POLLIN, POLLOUT};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Cap on the CGI header block. uhttpd lets the relay ustream grow instead;
/// DEVIATION: a bound keeps a runaway script from consuming router RAM, and no
/// real CGI emits 64 KiB of headers.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Upper bound on how late we notice the direct script exiting while a
/// descendant still holds stdout. Only reached when the pipe is quiet.
const CHILD_TICK_MS: u64 = 50;

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
    pub network_timeout: u64,
    /// Client TCP socket, for bounding a relay write by the script deadline.
    pub client_fd: RawFd,
}

/// Set SO_SNDTIMEO on the borrowed client socket. `ManuallyDrop` because the
/// fd stays owned by the connection.
fn set_send_timeout(fd: RawFd, timeout: Duration) {
    if fd < 0 {
        return;
    }
    // SAFETY: `fd` is the live client socket owned by the calling connection;
    // ManuallyDrop keeps this borrow from closing it.
    let sock = ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(fd) });
    let _ = sock.set_write_timeout(Some(timeout.max(Duration::from_millis(1))));
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

pub fn run<W: Write, R: io::BufRead>(
    ctx: &CgiContext,
    request: &Request,
    body: &mut crate::http::BodyReader<'_, R>,
    resp: &mut Response<W>,
    pi: &PathInfo,
) -> io::Result<()> {
    let mut command = Command::new(&pi.phys);
    command
        .env_clear()
        .env("PATH", ctx.cgi_path)
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .env("SERVER_SOFTWARE", "uhttpd")
        .env("SCRIPT_NAME", &pi.name)
        .env("SCRIPT_FILENAME", &pi.phys)
        .env("DOCUMENT_ROOT", ctx.docroot)
        .env("QUERY_STRING", pi.query.as_deref().unwrap_or(""))
        .env("REQUEST_URI", &request.url)
        .env("SERVER_PROTOCOL", request.version.name())
        .env("REQUEST_METHOD", request.method.name())
        .env("REDIRECT_STATUS", "200")
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
    for (env, header) in HEADER_ENV {
        if let Some(value) = request.header(header) {
            command.env(env, value);
        }
    }
    let mut child = ChildGuard(command.spawn()?);
    // ChildStdin/ChildStdout as plain files so both sides can be driven by one
    // poll(2) loop on this thread: no relay threads to join, and the deadline
    // below bounds the whole request the way proc.c's script_timeout does.
    let mut stdin = child.0.stdin.take().map(|s| File::from(OwnedFd::from(s)));
    let mut stdout = child
        .0
        .stdout
        .take()
        .map(|s| File::from(OwnedFd::from(s)))
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let deadline = Instant::now() + Duration::from_secs(ctx.script_timeout.max(1));
    // One small staging window between the client and the script: the body is
    // pulled only when the script's stdin has room, so an upload of any size
    // costs this buffer, and a script that stops reading back-pressures the
    // client instead of being buffered in our memory.
    let mut stage = [0u8; 4096];
    let mut staged = 0usize;
    let mut stage_pos = 0usize;
    let mut status_code = 200u16;
    let mut status_text = String::from("OK");
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut disable_chunked = false;
    let mut header_buf: Vec<u8> = Vec::new();
    let mut header_bytes = 0usize;
    let mut headers_done = false;
    let mut timed_out = false;
    let mut script_done = false;
    let mut buf = [0u8; 16384];
    loop {
        // relay_proc_cb() marks process_done and schedules relay_close_if_done,
        // so the *direct* script exiting ends the request even while a
        // descendant still holds stdout. Without this, such a request ran to
        // the deadline and answered 504 for a script that succeeded.
        if !script_done && matches!(child.0.try_wait(), Ok(Some(_))) {
            script_done = true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        let mut fds = [
            PollFd { fd: stdout.as_raw_fd(), events: POLLIN, revents: 0 },
            PollFd { fd: -1, events: POLLOUT, revents: 0 },
        ];
        let count = match &stdin {
            Some(f) => {
                fds[1].fd = f.as_raw_fd();
                2
            }
            None => 1,
        };
        // A finished script gets one non-blocking drain pass (the ustream_poll
        // in relay_proc_cb), never a wait on a descendant's EOF. Otherwise cap
        // the wait at one tick: uloop learns of the exit from SIGCHLD, we
        // re-check try_wait instead, so the exit is noticed within CHILD_TICK_MS.
        let wait_ms = if script_done {
            0
        } else {
            remaining.as_millis().min(CHILD_TICK_MS as u128) as i32
        };
        match poll_fds(&mut fds[..count], wait_ms) {
            Ok(0) if script_done => break,
            Ok(_) => {}
            Err(_) => break,
        }
        // POLLOUT on a pipe means at least PIPE_BUF is writable, so a bounded
        // write cannot block. A script that never reads gets EPIPE and we
        // simply close stdin, as uhttpd's relay does.
        if count == 2 && fds[1].revents != 0 {
            if stage_pos == staged {
                stage_pos = 0;
                // a truncated or malformed body ends the upload as EOF; the
                // script decides what to do with what it got
                staged = body.read(&mut stage).unwrap_or(0);
            }
            if staged == 0 {
                // whole body delivered: closing stdin is the script's EOF
                stdin = None;
            } else {
                match stdin.as_mut().expect("polled").write(&stage[stage_pos..staged]) {
                    Ok(0) | Err(_) => stdin = None,
                    Ok(n) => stage_pos += n,
                }
            }
        }
        if fds[0].revents == 0 {
            continue;
        }
        let n = match stdout.read(&mut buf) {
            // relay EOF: relay_close_if_done() finishes the request here even
            // when the script is still alive; the guard kills it.
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let chunk = &buf[..n];
        if headers_done {
            if !resp.is_head() {
                // uhttpd's script timeout runs on uloop, so a client that stops
                // reading cannot keep the script alive. Our write is blocking,
                // so shrink the socket's send timeout to what is left of the
                // script budget: a stalled client then fails the write instead
                // of parking the relay (and the child) for -T seconds.
                set_send_timeout(ctx.client_fd, deadline.saturating_duration_since(Instant::now()));
                let sent = resp.body(chunk).and_then(|()| resp.flush());
                set_send_timeout(ctx.client_fd, Duration::from_secs(ctx.network_timeout.max(1)));
                sent?;
            }
            continue;
        }
        header_buf.extend_from_slice(chunk);
        // Count only bytes that are actually part of the header block: the read
        // that carries the terminating blank line usually carries body too, and
        // charging that to the header made the cap depend on pipe chunking.
        if header_bytes + header_buf.len() > MAX_HEADER_BYTES {
            return resp.error(500, "Internal Server Error", Some("CGI header block too large"));
        }
        // parse complete lines
        while let Some(pos) = header_buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = header_buf.drain(..=pos).collect();
            header_bytes += line.len();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                headers_done = true;
                if disable_chunked {
                    resp.disable_chunked();
                }
                resp.status(status_code, &status_text)?;
                for (name, value) in &headers {
                    resp.header(name, value)?;
                }
                resp.end_headers()?;
                if !resp.is_head() && !header_buf.is_empty() {
                    let rest = std::mem::take(&mut header_buf);
                    resp.body(&rest)?;
                }
                resp.flush()?;
                break;
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            let Some((name, value)) = text.split_once(':') else {
                // malformed header: uhttpd aborts the relay
                return resp.error(500, "Internal Server Error", Some("Invalid CGI response header"));
            };
            let name = name.trim();
            let value = value.trim();
            if name == "Status" {
                if let Some((code, text)) = value.split_once(' ') {
                    if code.len() == 3 {
                        if let Ok(code) = code.parse() {
                            status_code = code;
                            status_text = text.to_owned();
                        }
                    }
                }
                continue;
            }
            if name.eq_ignore_ascii_case("Content-Length")
                || name.eq_ignore_ascii_case("Transfer-Encoding")
            {
                disable_chunked = true;
            }
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    if !headers_done {
        if timed_out && !script_done {
            return resp.error(
                504,
                "Gateway Timeout",
                Some("The CGI script did not respond in time"),
            );
        }
        // script exited without producing a header block
        resp.status(status_code, &status_text)?;
        for (name, value) in &headers {
            resp.header(name, value)?;
        }
        resp.end_headers()?;
        if !header_buf.is_empty() && !resp.is_head() {
            resp.body(&header_buf)?;
        }
    }
    resp.finish()
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Method, Version};
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn script_fixture(script: &str) -> (std::path::PathBuf, PathInfo) {
        let dir = std::env::temp_dir().join(format!(
            "owrt-cgi-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let phys = dir.join("script");
        fs::write(&phys, format!("#!/bin/sh\n{script}")).unwrap();
        fs::set_permissions(&phys, fs::Permissions::from_mode(0o755)).unwrap();
        let pi = PathInfo {
            meta: fs::metadata(&phys).unwrap(),
            phys,
            name: "/script".into(),
            info: None,
            query: None,
        };
        (dir, pi)
    }

    type TestSource = std::cell::RefCell<io::BufReader<io::Cursor<Vec<u8>>>>;

    fn empty_source() -> TestSource {
        std::cell::RefCell::new(io::BufReader::new(io::Cursor::new(Vec::new())))
    }

    fn get_request() -> Request {
        Request {
            method: Method::Get,
            version: Version::V1_0,
            url: "/script".into(),
            headers: Vec::new(),
            content_length: None,
            transfer_chunked: false,
            connection_close: true,
            expect_continue: false,
        }
    }

    /// Run one throwaway CGI script and report (response bytes, elapsed ms).
    fn run_script(script: &str, script_timeout: u64) -> (String, u128) {
        let (dir, pi) = script_fixture(script);
        let request = get_request();
        let local = "127.0.0.1:80".parse().unwrap();
        let ctx = CgiContext {
            docroot: dir.to_str().unwrap(),
            cgi_path: "/bin:/usr/bin",
            local,
            remote: local,
            tls: false,
            script_timeout,
            network_timeout: 5,
            client_fd: -1,
        };
        let mut out: Vec<u8> = Vec::new();
        let src = empty_source();
        let started = Instant::now();
        {
            let mut resp = Response::new(&mut out, &request, 0);
            run(&ctx, &request, &mut crate::http::BodyReader::new(&src, &request), &mut resp, &pi).unwrap();
        }
        let elapsed = started.elapsed().as_millis();
        let _ = fs::remove_dir_all(&dir);
        (String::from_utf8_lossy(&out).into_owned(), elapsed)
    }

    /// relay_close_if_done() finishes on stdout EOF and uh_relay_free() kills
    /// the script that is still running; we must not wait out its lifetime.
    #[test]
    fn stdout_eof_finishes_the_request_without_waiting_for_the_script() {
        let (out, ms) = run_script("exec 1>&-\nsleep 5\n", 1);
        assert!(out.starts_with("HTTP/1.0 200 OK"), "{out:?}");
        assert!(ms < 1000, "took {ms} ms, should end at relay EOF");
    }

    /// proc_timeout_cb() SIGKILLs and marks the relay EOF itself, so a
    /// descendant still holding the pipe cannot extend the request.
    #[test]
    fn descendant_holding_stdout_cannot_outlive_the_script_timeout() {
        let (out, ms) = run_script("sleep 5 &\nwait\n", 1);
        assert!(out.starts_with("HTTP/1.0 504 Gateway Timeout"), "{out:?}");
        assert!((900..3000).contains(&ms), "took {ms} ms, expected ~1000");
    }

    /// relay_proc_cb(): the direct script exiting ends the request, even with a
    /// descendant still holding stdout. This used to answer 504 at the deadline
    /// for a script that had already succeeded.
    #[test]
    fn direct_exit_with_a_descendant_on_stdout_is_not_a_timeout() {
        let (out, ms) = run_script("sleep 5 &\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok'\nexit 0\n", 1);
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
        assert!(out.starts_with("HTTP/1.0 200 OK"), "{}", &out[..out.len().min(120)]);
        assert!(out.contains('b'), "body missing");
    }

    /// uhttpd's script timeout runs on uloop, so a client that stops reading
    /// cannot extend the script's life. Ours writes synchronously, so the send
    /// timeout has to shrink to the remaining script budget.
    #[test]
    fn a_client_that_never_reads_cannot_outlive_the_script_timeout() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // held open, never read from
        let _client = TcpStream::connect(addr).unwrap();
        let (mut sock, _) = listener.accept().unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        let fd = sock.as_raw_fd();
        let (dir, pi) = script_fixture(
            "printf 'Content-Type: application/octet-stream\\r\\n\\r\\n'\nhead -c 33554432 /dev/zero\n",
        );
        let request = get_request();
        let local = "127.0.0.1:80".parse().unwrap();
        let ctx = CgiContext {
            docroot: dir.to_str().unwrap(),
            cgi_path: "/bin:/usr/bin",
            local,
            remote: local,
            tls: false,
            script_timeout: 1,
            network_timeout: 30,
            client_fd: fd,
        };
        let src = empty_source();
        let started = Instant::now();
        {
            let mut resp = Response::new(&mut sock, &request, 0);
            let _ = run(&ctx, &request, &mut crate::http::BodyReader::new(&src, &request), &mut resp, &pi);
        }
        let ms = started.elapsed().as_millis();
        let _ = fs::remove_dir_all(&dir);
        assert!(ms < 4000, "took {ms} ms with -t 1 / -T 30; the stalled client held the script");
    }

    #[test]
    fn malformed_header_aborts_the_relay_promptly() {
        let (out, ms) = run_script("printf 'invalid\\r\\n'\nsleep 5\n", 5);
        assert!(out.starts_with("HTTP/1.0 500 Internal Server Error"), "{out:?}");
        assert!(ms < 1000, "took {ms} ms, should not wait for the script");
    }
}
