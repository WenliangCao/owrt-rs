//! CGI execution with uhttpd's environment, header relay and chunked body
//! forwarding. One child per request; stdin gets the request body.

use crate::files::PathInfo;
use crate::http::{Request, Response};
use owrt_ubus::sys::{poll_fds, PollFd, POLLIN, POLLOUT};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Cap on the CGI header block. uhttpd lets the relay ustream grow instead;
/// DEVIATION: a bound keeps a runaway script from consuming router RAM, and no
/// real CGI emits 64 KiB of headers.
const MAX_HEADER_BYTES: usize = 64 * 1024;

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

pub fn run<W: Write>(
    ctx: &CgiContext,
    request: &Request,
    body: &[u8],
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
    let mut sent = 0usize;
    let mut status_code = 200u16;
    let mut status_text = String::from("OK");
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut disable_chunked = false;
    let mut header_buf: Vec<u8> = Vec::new();
    let mut header_bytes = 0usize;
    let mut headers_done = false;
    let mut timed_out = false;
    let mut buf = [0u8; 16384];
    loop {
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
        let wait_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        if poll_fds(&mut fds[..count], wait_ms).is_err() {
            break;
        }
        // POLLOUT on a pipe means at least PIPE_BUF is writable, so a bounded
        // write cannot block. A script that never reads gets EPIPE and we
        // simply close stdin, as uhttpd's relay does.
        if count == 2 && fds[1].revents != 0 {
            let end = body.len().min(sent + 4096);
            match stdin.as_mut().expect("polled").write(&body[sent..end]) {
                Ok(0) | Err(_) => stdin = None,
                Ok(n) => {
                    sent += n;
                    if sent == body.len() {
                        stdin = None;
                    }
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
                resp.body(chunk)?;
                resp.flush()?;
            }
            continue;
        }
        header_bytes += n;
        if header_bytes > MAX_HEADER_BYTES {
            return resp.error(500, "Internal Server Error", Some("CGI header block too large"));
        }
        header_buf.extend_from_slice(chunk);
        // parse complete lines
        while let Some(pos) = header_buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = header_buf.drain(..=pos).collect();
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
        if timed_out {
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

    /// Run one throwaway CGI script and report (response bytes, elapsed ms).
    fn run_script(script: &str, script_timeout: u64) -> (String, u128) {
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
        let request = Request {
            method: Method::Get,
            version: Version::V1_0,
            url: "/script".into(),
            headers: Vec::new(),
            content_length: None,
            transfer_chunked: false,
            connection_close: true,
            expect_continue: false,
        };
        let local = "127.0.0.1:80".parse().unwrap();
        let ctx = CgiContext {
            docroot: dir.to_str().unwrap(),
            cgi_path: "/bin:/usr/bin",
            local,
            remote: local,
            tls: false,
            script_timeout,
        };
        let mut out: Vec<u8> = Vec::new();
        let started = Instant::now();
        {
            let mut resp = Response::new(&mut out, &request, 0);
            run(&ctx, &request, b"", &mut resp, &pi).unwrap();
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

    #[test]
    fn malformed_header_aborts_the_relay_promptly() {
        let (out, ms) = run_script("printf 'invalid\\r\\n'\nsleep 5\n", 5);
        assert!(out.starts_with("HTTP/1.0 500 Internal Server Error"), "{out:?}");
        assert!(ms < 1000, "took {ms} ms, should not wait for the script");
    }
}
