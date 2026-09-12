//! httpd-rs: contract C3 compatible uhttpd replacement.
//!
//! Accepts uhttpd's command line so the stock init script arguments work
//! unchanged. One thread per connection; blocking I/O; TLS via rustls.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

mod bridge;
mod auth;
mod cgi;
mod files;
mod http;
mod tls;

use bridge::Bridge;
use http::{Method, ParseOutcome, Request, Response};
use std::borrow::Cow;
use std::io::{self, BufReader, Read, Write};
use std::cell::RefCell;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

struct Config {
    docroot: String,
    cgi_prefix: Option<String>,
    cgi_path: String,
    ubus_prefix: Option<String>,
    ubus_socket: Option<String>,
    ubus_noauth: bool,
    ubus_cors: bool,
    script_timeout: u64,
    network_timeout: u64,
    http_keepalive: u32,
    tcp_keepalive: u64,
    max_connections: usize,
    max_script_requests: usize,
    rfc1918_filter: bool,
    no_dirlists: bool,
    no_symlinks: bool,
    index_files: Vec<String>,
    interpreters: Vec<(String, String)>,
    aliases: Vec<(String, Option<String>)>,
    dirlist_charset: String,
    realm: String,
    auth: Vec<auth::Realm>,
    config_file: String,
    tls_redirect: bool,
    tls_ciphers: Option<String>,
    events_retry: i32,
    error_handler: Option<String>,
    http: Vec<String>,
    https: Vec<String>,
    cert: Option<String>,
    key: Option<String>,
    call_log: Option<String>,
}

fn usage() -> &'static str {
    "usage: httpd-rs -p [addr:]port -h docroot [uhttpd options]\n\
     accepted: -f -h -x -u -U -a -X -t -T -k -A -n -N -R -D -S -E -I -r -p -s -C -K -q -i -y -e --call-log FILE"
}

/// uhttpd fixup_prefix: drop a single trailing slash (keep a bare "/").
fn trim_prefix(mut p: String) -> String {
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

fn path_matches(prefix: &str, url: &str) -> bool {
    prefix == "/" || url.strip_prefix(prefix).is_some_and(|tail|
        tail.is_empty() || tail.starts_with('/') || tail.starts_with('?'))
}

fn parse_args() -> Result<Config, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(mut args: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut c = Config {
        docroot: ".".into(),
        cgi_prefix: Some("/cgi-bin".into()),
        cgi_path: "/sbin:/usr/sbin:/bin:/usr/bin".into(),
        ubus_prefix: None,
        ubus_socket: None,
        ubus_noauth: false,
        ubus_cors: false,
        script_timeout: 60,
        network_timeout: 30,
        http_keepalive: 20,
        tcp_keepalive: 0,
        max_connections: 100,
        max_script_requests: 3,
        rfc1918_filter: false,
        no_dirlists: false,
        no_symlinks: false,
        index_files: Vec::new(),
        interpreters: Vec::new(),
        aliases: Vec::new(),
        dirlist_charset: "UTF-8".into(),
        realm: "Protected Area".into(),
        auth: Vec::new(),
        config_file: "/etc/httpd.conf".into(),
        tls_redirect: false,
        tls_ciphers: None,
        events_retry: 0,
        error_handler: None,
        http: Vec::new(),
        https: Vec::new(),
        cert: None,
        key: None,
        call_log: None,
    };
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or(format!("{flag} requires a value"));
        match arg.as_str() {
            "-f" | "-a" | "-X" | "-R" | "-D" | "-S" | "-q" => match arg.as_str() {
                "-a" => c.ubus_noauth = true,
                "-X" => c.ubus_cors = true,
                "-R" => c.rfc1918_filter = true,
                "-D" => c.no_dirlists = true,
                "-S" => c.no_symlinks = true,
                "-q" => c.tls_redirect = true,
                _ => {}
            },
            "-h" => c.docroot = value("-h")?.trim_end_matches('/').to_owned(),
            // uhttpd fixup_prefix strips a trailing slash so the prefix
            // still matches; without it "/cgi-bin/" would serve the script
            // source instead of executing it.
            "-x" => c.cgi_prefix = Some(trim_prefix(value("-x")?)),
            "-u" => c.ubus_prefix = Some(trim_prefix(value("-u")?)),
            "-U" => c.ubus_socket = Some(value("-U")?),
            "-t" => c.script_timeout = value("-t")?.parse().map_err(|_| "-t must be a number")?,
            "-T" => c.network_timeout = value("-T")?.parse().map_err(|_| "-T must be a number")?,
            "-k" => c.http_keepalive = value("-k")?.parse().map_err(|_| "-k must be a number")?,
            "-A" => c.tcp_keepalive = value("-A")?.parse().map_err(|_| "-A must be a number")?,
            "-n" => c.max_script_requests = value("-n")?.parse().map_err(|_| "-n must be a number")?,
            "-N" => c.max_connections = value("-N")?.parse().map_err(|_| "-N must be a number")?,
            "-E" => c.error_handler = Some(value("-E")?),
            "-I" => {
                let name = value("-I")?;
                if name.starts_with('/') { return Err("-I must be a relative index name".into()); }
                c.index_files.push(name);
            }
            "-r" => c.realm = value("-r")?,
            "-i" => {
                let spec = value("-i")?;
                let Some((ext, path)) = spec.split_once('=') else { return Err("invalid -i interpreter".into()) };
                if !ext.starts_with('.') { return Err("invalid -i extension".into()); }
                c.interpreters.push((ext.into(), path.into()));
            }
            "-y" => {
                let spec = value("-y")?;
                let (alias, path) = spec.split_once('=').map(|(a,p)| (a, Some(p.to_owned())))
                    .unwrap_or((&spec, None));
                c.aliases.insert(0, (alias.into(), path));
            }
            "-e" => c.events_retry = value("-e")?.parse().map_err(|_| "-e must be a number")?,
            "-b" => c.dirlist_charset = value("-b")?,
            "-c" => c.config_file = value("-c")?,
            "-P" => c.tls_ciphers = Some(value("-P")?),
            "-p" => c.http.push(value("-p")?),
            "-s" => c.https.push(value("-s")?),
            "-C" => c.cert = Some(value("-C")?),
            "-K" => c.key = Some(value("-K")?),
            "--call-log" => c.call_log = Some(value("--call-log")?),
            "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}\n{}", usage())),
        }
    }
    if c.docroot.is_empty() {
        c.docroot = "/".into();
    }
    if c.http.is_empty() && c.https.is_empty() {
        return Err(format!("no listen address\n{}", usage()));
    }
    c.docroot = std::fs::canonicalize(&c.docroot)
        .map_err(|e| format!("invalid document root: {e}"))?.to_string_lossy().into_owned();
    c.load_file()?;
    if c.index_files.is_empty() {
        c.index_files = ["index.html", "index.htm", "default.html", "default.htm"].map(str::to_owned).to_vec();
    }
    Ok(c)
}

impl Config {
    fn load_file(&mut self) -> Result<(), String> {
        let bytes = match std::fs::read(&self.config_file) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("cannot read HTTP configuration: {e}")),
        };
        // main.c fgets(line, sizeof(line)-1): at most 510 bytes per chunk;
        // records without a newline are ignored by the reference parser.
        for line in bytes.split_inclusive(|&b| b == b'\n') {
            for chunk in line.chunks(510) {
                let Some(chunk) = chunk.strip_suffix(b"\n") else { continue };
                let line = std::str::from_utf8(chunk).map_err(|_| "HTTP configuration is not UTF-8")?;
                if line.starts_with('/') {
                    let mut parts = line.splitn(3, ':');
                    if let (Some(path), Some(user), Some(pass)) = (parts.next(), parts.next(), parts.next()) {
                        if let Some(realm) = auth::Realm::new(path.into(), user.into(), pass.into()) {
                            self.auth.insert(0, realm);
                        }
                    }
                } else if let Some(index) = line.strip_prefix("I:") {
                    self.index_files.push(index.into());
                } else if let Some(handler) = line.strip_prefix("E404:") {
                    self.error_handler = Some(handler.into());
                } else if let Some((ext, path)) = line.strip_prefix('*').and_then(|s| s.split_once(':')) {
                    self.interpreters.push((ext.into(), path.into()));
                }
            }
        }
        Ok(())
    }
}

/// A script waits for a free execution slot while other client threads can
/// still serve static files and JSON-RPC, like uh_invoke_handler's queue.
struct ScriptSlots {
    count: Mutex<usize>,
    ready: Condvar,
    limit: usize,
}

struct ScriptPermit<'a>(&'a ScriptSlots);

impl ScriptSlots {
    fn acquire(&self, fd: RawFd) -> io::Result<ScriptPermit<'_>> {
        let mut count = self.count.lock().unwrap_or_else(|e| e.into_inner());
        while *count >= self.limit {
            // A queued request owns a connection thread, but must release it
            // if the client leaves before a script slot becomes available.
            let (next, _) = self.ready.wait_timeout(count, Duration::from_millis(250))
                .unwrap_or_else(|e| e.into_inner());
            count = next;
            const POLLRDHUP: i16 = 0x2000;
            let mut fds = [owrt_ubus::sys::PollFd { fd, events: POLLRDHUP, revents: 0 }];
            owrt_ubus::sys::poll_fds(&mut fds, 0)?;
            if fds[0].revents & (POLLRDHUP | owrt_ubus::sys::POLLHUP | owrt_ubus::sys::POLLERR) != 0 {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "queued client disconnected"));
            }
        }
        *count += 1;
        Ok(ScriptPermit(self))
    }
}

impl Drop for ScriptPermit<'_> {
    fn drop(&mut self) {
        *self.0.count.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        self.0.ready.notify_one();
    }
}

fn bind(spec: &str) -> io::Result<TcpListener> {
    // uhttpd accepts "port", "addr:port", "[v6]:port"
    let addr: SocketAddr = if let Ok(port) = spec.parse::<u16>() {
        SocketAddr::from(([0, 0, 0, 0], port))
    } else if let Some(rest) = spec.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| io::Error::other("bad listen spec"))?;
        SocketAddr::new(
            host.parse()
                .map_err(|_| io::Error::other("bad v6 address"))?,
            port.parse().map_err(|_| io::Error::other("bad port"))?,
        )
    } else {
        spec.parse()
            .map_err(|_| io::Error::other(format!("bad listen spec {spec}")))?
    };
    match addr {
        SocketAddr::V4(_) => TcpListener::bind(addr),
        SocketAddr::V6(v6) => bind_v6only(v6),
    }
}

/// Like uhttpd (usock with USOCK_IPV6ONLY): a v6 listener that does not claim
/// the v4 wildcard, so "-p 0.0.0.0:80 -p [::]:80" can coexist.
fn bind_v6only(addr: std::net::SocketAddrV6) -> io::Result<TcpListener> {
    use std::os::fd::FromRawFd;
    #[repr(C)]
    struct SockAddrIn6 {
        family: u16,
        port: u16,
        flowinfo: u32,
        addr: [u8; 16],
        scope_id: u32,
    }
    extern "C" {
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        fn setsockopt(fd: i32, level: i32, name: i32, value: *const i32, len: u32) -> i32;
        fn bind(fd: i32, addr: *const SockAddrIn6, len: u32) -> i32;
        fn listen(fd: i32, backlog: i32) -> i32;
        fn close(fd: i32) -> i32;
    }
    const AF_INET6: i32 = 10;
    const SOCK_STREAM: i32 = 1;
    const SOCK_CLOEXEC: i32 = 0o2000000;
    const SOL_SOCKET: i32 = 1;
    const SO_REUSEADDR: i32 = 2;
    const IPPROTO_IPV6: i32 = 41;
    const IPV6_V6ONLY: i32 = 26;
    // SAFETY: plain socket(2); it touches no memory of ours.
    let fd = unsafe { socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let one: i32 = 1;
    let sa = SockAddrIn6 {
        family: AF_INET6 as u16,
        port: addr.port().to_be(),
        flowinfo: 0,
        addr: addr.ip().octets(),
        scope_id: addr.scope_id(),
    };
    // SAFETY: setsockopt(2) with a live i32 and its exact size. IPV6_V6ONLY has
    // to be set before bind, which is why std's TcpListener cannot be used here.
    let ok = unsafe {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, 4) == 0
            && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, 4) == 0
            && bind(fd, &sa, std::mem::size_of::<SockAddrIn6>() as u32) == 0
            && listen(fd, 128) == 0
    };
    if !ok {
        let error = io::Error::last_os_error();
        // SAFETY: fd came from socket(2) above, setup failed, and nothing else has
        // taken ownership of it yet.
        unsafe {
            close(fd);
        }
        return Err(error);
    }
    // SAFETY: fd is a bound, listening socket this function owns and does not
    // use again; TcpListener takes over closing it.
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

fn is_rfc1918(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_rfc1918(IpAddr::V4(v4)),
            None => false,
        },
    }
}

/// Everything about the accepted connection that a handler may need. Kept
/// together so `serve`/`dispatch` take one parameter instead of four.
#[derive(Clone, Copy)]
struct Conn {
    local: SocketAddr,
    remote: SocketAddr,
    tls: bool,
    fd: RawFd,
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

type Client = BufReader<Box<dyn Stream>>;

/// Put the client socket in (non-)blocking mode for the duration of a handler
/// that drives readiness itself. The fd stays owned by the connection.
fn set_nonblocking(fd: RawFd, on: bool) -> io::Result<()> {
    with_socket(fd, |sock| sock.set_nonblocking(on))
}

/// Shorten (or restore) the socket receive timeout. The request-head deadline
/// uses it so a single read cannot carry the head past its budget.
fn set_read_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    with_socket(fd, |sock| sock.set_read_timeout(Some(timeout)))
}

fn with_socket<T>(fd: RawFd, f: impl FnOnce(&std::net::TcpStream) -> io::Result<T>) -> io::Result<T>
where
    T: Default,
{
    if fd < 0 {
        return Ok(T::default());
    }
    // SAFETY: `fd` is the live client socket owned by this connection;
    // ManuallyDrop keeps this borrow from closing it.
    let sock = std::mem::ManuallyDrop::new(unsafe { std::net::TcpStream::from_raw_fd(fd) });
    f(&sock)
}



/// Most a keep-alive connection will discard from an unwanted body before
/// closing instead.
const MAX_DRAIN: usize = 64 * 1024;

/// Response bytes held before the transport has to take some. Also the CGI
/// relay's back-pressure mark: above it we stop reading the script's stdout.
const OUT_WINDOW: usize = 16 * 1024;

struct Server {
    config: Config,
    cgi_physical_prefix: Option<String>,
    bridge: Bridge,
    connections: AtomicUsize,
    accept_lock: Mutex<()>,
    scripts: ScriptSlots,
    output_buffers: Mutex<Vec<Vec<u8>>>,
    inventory: Option<Mutex<std::fs::File>>,
}

impl Server {
    fn serve(&self, stream: Box<dyn Stream>, conn: Conn) {
        // Keep the established read-ahead at oversized request boundaries;
        // reducing it can leave unread TCP bytes and turn a 413 into a reset.
        let client = RefCell::new(BufReader::new(stream));
        let network_timeout = Duration::from_secs(self.config.network_timeout.max(1));
        let mut heads = http::HeadBuffer::default();
        let mut requests = 0u64;
        loop {
            // uh_keepalive_poll_cb (client.c:110-117): one deadline covers the
            // whole head, network_timeout for the first request on the
            // connection and http_keepalive for the ones after it. Without it
            // a client that dribbles one byte per read holds its slot forever.
            let budget = if requests == 0 {
                network_timeout
            } else {
                Duration::from_secs(u64::from(self.config.http_keepalive).max(1))
            };
            let deadline = http::HeadDeadline::new(conn.fd, budget);
            // Bind the outcome first: a `borrow_mut()` in the scrutinee stays
            // alive for the whole match, and the reject arm needs the stream.
            let outcome = heads.read_request(
                &mut *client.borrow_mut(),
                self.config.http_keepalive > 0,
                Some(&deadline),
            );
            // client_parse_header cancels the timeout on the blank line
            // (client.c:372): the body and the response get the full budget.
            let _ = set_read_timeout(conn.fd, network_timeout);
            requests += 1;
            let mut request = match outcome {
                Ok(ParseOutcome::Request(r)) => r,
                Ok(ParseOutcome::Eof) | Err(_) => return,
                Ok(ParseOutcome::Bad { code, summary, version, body }) => {
                    let mut out = http::Out::new(&client, conn.fd, OUT_WINDOW, network_timeout);
                    self.reject(&mut out, code, summary, version, body);
                    let _ = Write::flush(&mut out);
                    return;
                }
            };
            // Idle connections hold no response window. Share a small bounded
            // set between active requests, retaining initialized storage for
            // file reads without allocating it per request or per idle client.
            let buffer = self.output_buffers.lock().unwrap_or_else(|e| e.into_inner())
                .pop().unwrap_or_else(|| Vec::with_capacity(512));
            let mut out = http::Out::with_buffer(&client, conn.fd, OUT_WINDOW, network_timeout, buffer);
            if request.expect_continue && client.borrow_mut().get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
                return;
            }
            // The body is decoded on demand: CGI streams it straight to the
            // script's stdin, so an upload never has to fit in memory first.
            let mut body = http::BodyReader::new(&client, &request);
            // finish_request drains every byte and bounds retained capacity
            // before this window can be returned to the shared free list.
            let close;
            {
                let mut resp = Response::new(&mut out, &request, self.config.http_keepalive);
                if self.dispatch(&mut request, &mut body, &mut resp, conn).is_err() {
                    return;
                }
                close = resp.connection_close();
            }
            if out.finish_request().is_err() {
                return;
            }
            {
                let buffer = out.into_buffer();
                let mut buffers = self.output_buffers.lock().unwrap_or_else(|e| e.into_inner());
                if buffers.len() < 8 {
                    buffers.push(buffer);
                }
            }
            // A handler that ignored the body leaves the connection out of sync
            // unless the rest is drained; give up on anything larger.
            if close
                || self.config.http_keepalive == 0
                || (!body.reusable() && !body.drain(MAX_DRAIN))
            {
                return;
            }
            heads.recycle(request);
        }
    }

    /// Error response for a request that never reached a handler.
    fn reject(&self, out: &mut dyn Write, code: u16, summary: &str, version: http::Version, body: bool) {
        let dummy = Request {
            method: Method::Get,
            version,
            url: String::new(),
            headers: Vec::new(),
            content_length: None,
            transfer_chunked: false,
            connection_close: true,
            expect_continue: false,
        };
        let mut buf = Vec::new();
        {
            let mut resp = Response::new(&mut buf, &dummy, self.config.http_keepalive);
            let _ = if body { resp.error(code, summary, None) } else { resp.error_no_body(code, summary) };
        }
        let _ = out.write_all(&buf);
    }

    fn dispatch<W: http::Sink>(
        &self,
        request: &mut Request,
        body: &mut http::BodyReader<'_, Client>,
        resp: &mut Response<W>,
        conn: Conn,
    ) -> io::Result<()> {
        if self.config.tls_redirect && !conn.tls {
            let port = self.config.https.iter().find_map(|spec| {
                let (host, port) = spec.rsplit_once(':').unwrap_or(("", spec));
                (host.contains(':') == conn.local.is_ipv6()).then(|| port.parse::<u16>().ok()).flatten()
            });
            if let (Some(port), Some(host)) = (port, request.header("host")) {
                let host = if let Some(end) = host.find(']') { &host[..=end] }
                    else { host.split(':').next().unwrap_or(host) };
                let port = if port == 443 { String::new() } else { format!(":{port}") };
                resp.force_close();
                resp.disable_chunked();
                resp.status(307, "Temporary Redirect")?;
                resp.header("Location", &format!("https://{host}{port}{}", request.url))?;
                resp.end_headers()?;
                return resp.finish();
            }
        }
        if self.config.rfc1918_filter
            && is_rfc1918(conn.remote.ip())
            && !is_rfc1918(conn.local.ip())
            && !conn.local.ip().is_loopback()
        {
            return resp.error(
                403,
                "Forbidden",
                Some("Rejected request from RFC1918 IP to public server address"),
            );
        }
        let path = request.url.split('?').next().unwrap_or("");
        if let Some(prefix) = &self.config.ubus_prefix {
            if path == prefix || path.strip_prefix(prefix).is_some_and(|tail| tail.starts_with('/')) {
                // UH_UBUS_MAX_POST_SIZE (ubus.c:37, 937-952): over the cap,
                // uh_ubus_data_send stops parsing, closes the connection and
                // answers 200 with the JSON-RPC parse error -- never an HTML
                // error page, which a JSON client could not read. Read one
                // byte past the cap so the bridge sees the overrun itself.
                let collected = match body.read_all(bridge::MAX_POST + 1) {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        resp.force_close();
                        return bridge::parse_error(&self.bridge, request, resp);
                    }
                    Err(_) => {
                        resp.force_close();
                        return resp.error(400, "Bad Request", Some("Malformed request body"));
                    }
                };
                let slice = if body.present() { Some(collected.as_slice()) } else { None };
                let result = bridge::handle(&self.bridge, prefix, request, slice, resp);
                self.flush_inventory();
                return result;
            }
        }
        let mut url = Cow::Borrowed(request.url.as_str());
        for (alias, target) in &self.config.aliases {
            if path_matches(alias, &url) {
                url = Cow::Owned(format!("{}{}", target.as_deref().or(self.config.cgi_prefix.as_deref()).unwrap_or(""), url));
                break;
            }
        }
        let mut redirect_status = 200;
        loop {
            match files::lookup(&self.config.docroot, &url, self.config.no_symlinks, &self.config.index_files) {
                files::Lookup::Redirect(location) => {
                    resp.status(302, "Found")?;
                    if !resp.chunked() { resp.header("Content-Length", "0")?; }
                    resp.header("Location", &location)?;
                    resp.end_headers()?;
                    return resp.finish();
                }
                files::Lookup::Found(pi) => {
                    match auth::check(&self.config.auth, &pi.name, request.header("authorization")) {
                        Err(()) => {
                            resp.status(401, "Authorization Required")?;
                            resp.header("WWW-Authenticate", &format!("Basic realm=\"{}\"", self.config.realm))?;
                            resp.header("Content-Type", "text/plain")?;
                            resp.end_headers()?;
                            resp.body(b"Authorization Required\n")?;
                            return resp.finish();
                        }
                        Ok(Some((user, pass))) => {
                            request.headers.retain(|(k, _)| k != "http-auth-user" && k != "http-auth-pass");
                            request.headers.push(("http-auth-user".into(), user));
                            request.headers.push(("http-auth-pass".into(), pass));
                        }
                        Ok(None) => {}
                    }
                    let physical = pi.phys.to_string_lossy();
                    let interpreter = self.config.interpreters.iter()
                        .find(|(ext, _)| physical.len() > ext.len() && physical.ends_with(ext))
                        .map(|(_, path)| path.as_str());
                    let is_cgi = interpreter.is_some() || self.cgi_physical_prefix.as_ref()
                        .is_some_and(|prefix| path_matches(prefix, &physical));
                    if is_cgi {
                        if interpreter.is_none() && !cgi::is_executable(&pi) {
                            return files::forbidden(resp, request, &url);
                        }
                        let _permit = self.scripts.acquire(conn.fd)?;
                        let ctx = cgi::CgiContext {
                            docroot: &self.config.docroot,
                            cgi_path: &self.config.cgi_path,
                            local: conn.local,
                            remote: conn.remote,
                            tls: conn.tls,
                            script_timeout: self.config.script_timeout,
                            interpreter,
                            redirect_status,
                        };
                        return cgi::run(&ctx, request, body, resp, &pi);
                    }
                    return files::serve(request, resp, &pi, self.config.no_dirlists, &self.config.dirlist_charset);
                }
                files::Lookup::NotFound => {
                    if redirect_status == 200 {
                        if let Some(handler) = &self.config.error_handler {
                            url = Cow::Borrowed(handler.as_str());
                            redirect_status = 404;
                            continue;
                        }
                    }
                    return files::not_found(resp, request, &request.url);
                }
            }
        }
    }

    fn flush_inventory(&self) {
        use std::io::Seek;
        let Some(inventory) = &self.inventory else { return };
        if let Ok(mut file) = inventory.lock() {
            let text = self.bridge.call_inventory();
            let _ = file.seek(std::io::SeekFrom::Start(0));
            let _ = file.write_all(text.as_bytes());
            let _ = file.set_len(text.len() as u64);
            let _ = file.flush();
        }
    }
}

fn accept_loop(server: Arc<Server>, listener: TcpListener, tls: Option<Arc<rustls::ServerConfig>>) {
    let local = listener.local_addr().ok();
    if listener.set_nonblocking(true).is_err() { return; }
    set_tcp_keepalive(listener.as_raw_fd(), server.config.tcp_keepalive);
    loop {
        // listen.c:95 + uh_poll_listeners: at the cap uhttpd takes the listener
        // out of uloop and re-arms it once a client goes away, so further
        // connection attempts wait in the backlog instead of being accepted and
        // dropped. `-N 0` disables the cap entirely (`conf.max_connections &&`).
        if server.config.max_connections > 0
            && server.connections.load(Ordering::Relaxed) >= server.config.max_connections
        {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let mut fds = [owrt_ubus::sys::PollFd {
            fd: listener.as_raw_fd(), events: owrt_ubus::sys::POLLIN, revents: 0,
        }];
        if owrt_ubus::sys::poll_fds(&mut fds, -1).is_err() { continue; }
        // All listeners share the cap. The lock covers nonblocking accept and
        // increment together, so HTTP and HTTPS cannot both claim the last slot.
        let guard = server.accept_lock.lock().unwrap_or_else(|e| e.into_inner());
        if server.config.max_connections > 0
            && server.connections.load(Ordering::Relaxed) >= server.config.max_connections {
            continue;
        }
        let (stream, remote) = match listener.accept() {
            Ok(pair) => pair,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        server.connections.fetch_add(1, Ordering::Relaxed);
        drop(guard);
        let worker = Arc::clone(&server);
        let tls = tls.clone();
        let local = stream
            .local_addr()
            .or(local.ok_or(io::Error::other("no local addr")))
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        if let Err(error) = std::thread::Builder::new().spawn(move || {
            let server = worker;
            let fd = stream.as_raw_fd();
            let timeout = Duration::from_secs(server.config.network_timeout.max(1));
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let _ = stream.set_nodelay(true);
            match tls {
                None => server.serve(Box::new(stream), Conn { local, remote, tls: false, fd }),
                Some(config) => {
                    if let Ok(mut conn) = rustls::ServerConnection::new(config) {
                        conn.set_buffer_limit(Some(16 * 1024));
                        let tls_stream = rustls::StreamOwned::new(conn, stream);
                        server.serve(Box::new(tls_stream), Conn { local, remote, tls: true, fd });
                    }
                }
            }
            server.connections.fetch_sub(1, Ordering::Relaxed);
        }) {
            // The failed spawn drops its closure and accepted socket. Release
            // the reserved slot too, and keep the listener alive under pressure.
            server.connections.fetch_sub(1, Ordering::Relaxed);
            let _ = writeln!(std::io::stderr().lock(), "httpd-rs: cannot create connection thread: {error}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn set_tcp_keepalive(fd: RawFd, interval: u64) {
    if interval == 0 { return; }
    unsafe extern "C" {
        fn setsockopt(fd: i32, level: i32, opt: i32, value: *const i32, len: u32) -> i32;
    }
    // uhttpd listen.c: idle 1 s, three probes, configured interval, TFO 5.
    for (level, opt, value) in [(6, 4, 1), (6, 5, interval.min(i32::MAX as u64) as i32),
        (6, 6, 3), (6, 23, 5), (1, 9, 1)] {
        // SAFETY: listener is live, value is an i32 and optlen matches it.
        unsafe { setsockopt(fd, level, opt, &value, 4); }
    }
}

fn main() {
    let config = match parse_args() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("httpd-rs: {error}");
            std::process::exit(64);
        }
    };
    owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
    let tls_config = match (&config.cert, &config.key, config.https.is_empty()) {
        (Some(cert), Some(key), false) => match tls::server_config(cert, key, config.tls_ciphers.as_deref()) {
            Ok(cfg) => Some(cfg),
            Err(error) => {
                eprintln!("httpd-rs: cannot initialize TLS: {error}");
                std::process::exit(1);
            }
        },
        (_, _, false) => {
            eprintln!("httpd-rs: HTTPS requires a certificate and key");
            std::process::exit(1);
        }
        _ => None,
    };
    let inventory = config
        .call_log
        .as_ref()
        .and_then(|path| std::fs::File::create(path).ok());
    let server = Arc::new(Server {
        cgi_physical_prefix: config.cgi_prefix.as_ref().map(|prefix| format!("{}{}", config.docroot, prefix)),
        bridge: Bridge {
            socket: config.ubus_socket.clone(),
            noauth: config.ubus_noauth,
            cors: config.ubus_cors,
            timeout_ms: config.script_timeout.saturating_mul(1000).min(i32::MAX as u64) as i32,
            events_retry: config.events_retry,
            record_calls: config.call_log.is_some(),
            idle: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        },
        connections: AtomicUsize::new(0),
        accept_lock: Mutex::new(()),
        scripts: ScriptSlots { count: Mutex::new(0), ready: Condvar::new(), limit: config.max_script_requests },
        output_buffers: Mutex::new(Vec::new()),
        inventory: inventory.map(Mutex::new),
        config,
    });
    let mut handles = Vec::new();
    for spec in &server.config.http {
        match bind(spec) {
            Ok(listener) => {
                let server = Arc::clone(&server);
                handles.push(std::thread::spawn(move || {
                    accept_loop(server, listener, None)
                }));
            }
            Err(error) => {
                eprintln!("httpd-rs: cannot bind {spec}: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Some(tls_config) = tls_config {
        for spec in &server.config.https {
            match bind(spec) {
                Ok(listener) => {
                    let server = Arc::clone(&server);
                    let tls_config = Arc::clone(&tls_config);
                    handles.push(std::thread::spawn(move || {
                        accept_loop(server, listener, Some(tls_config))
                    }));
                }
                Err(error) => {
                    eprintln!("httpd-rs: cannot bind {spec}: {error}");
                    std::process::exit(1);
                }
            }
        }
    }
    if handles.is_empty() {
        eprintln!("httpd-rs: nothing to listen on");
        std::process::exit(1);
    }
    for handle in handles {
        let _ = handle.join();
    }
}
