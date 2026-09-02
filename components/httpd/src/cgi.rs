//! CGI execution with uhttpd's environment, header relay and chunked body
//! forwarding. One child per request; stdin gets the request body.

use crate::files::PathInfo;
use crate::http::{Request, Response};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    // feed the body from a helper thread so a script that writes before
    // reading cannot deadlock us
    let body_owned = body.to_vec();
    let feeder = std::thread::spawn(move || {
        if let Some(mut stdin) = stdin.take() {
            let _ = stdin.write_all(&body_owned);
        }
    });
    // relay in a thread with a deadline
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader_thread = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut buf = [0u8; 16384];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(ctx.script_timeout.max(1));
    let mut status_code = 200u16;
    let mut status_text = String::from("OK");
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut disable_chunked = false;
    let mut header_buf: Vec<u8> = Vec::new();
    let mut headers_done = false;
    let mut timed_out = false;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        let chunk = match rx.recv_timeout(remaining) {
            Ok(chunk) => chunk,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timed_out = true;
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if headers_done {
            if !resp.is_head() {
                resp.body(&chunk)?;
            }
            continue;
        }
        header_buf.extend_from_slice(&chunk);
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
                break;
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            let Some((name, value)) = text.split_once(':') else {
                // malformed header: uhttpd aborts the relay
                let _ = child.kill();
                return resp.error(
                    500,
                    "Internal Server Error",
                    Some("Invalid CGI response header"),
                );
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
    if timed_out {
        let _ = child.kill();
    }
    let _ = child.wait();
    let _ = feeder.join();
    let _ = reader_thread.join();
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

#[allow(dead_code)]
fn _read_all<R: BufRead>(r: &mut R) -> Vec<u8> {
    let mut v = Vec::new();
    let _ = r.read_to_end(&mut v);
    v
}
