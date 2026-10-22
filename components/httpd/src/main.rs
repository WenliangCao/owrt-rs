//! httpd-rs: contract C3 compatible uhttpd replacement.
//!
//! Accepts uhttpd's command line so the stock init script arguments work
//! unchanged. Blocking I/O on one thread per *active* connection; a keep-alive
//! connection that goes quiet is parked on its listener's poll set and its
//! thread released, so idle clients cost a descriptor and a few bytes rather
//! than a stack. TLS via rustls.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]
#![forbid(unsafe_code)]

mod bridge;
mod auth;
mod cgi;
mod fast;
mod files;
mod http;
mod tls;

use bridge::Bridge;
use http::{Method, ParseOutcome, Request, Response};
use std::borrow::Cow;
use std::io::{self, BufReader, Read, Write};
use std::cell::RefCell;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

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
                let _ = writeln!(std::io::stdout(), "{}", usage());
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

fn bind(spec: &str) -> io::Result<Vec<TcpListener>> {
    // uhttpd accepts "port", "addr:port", "[v6]:port"
    let addresses: Vec<SocketAddr> = if let Ok(port) = spec.parse::<u16>() {
        vec![SocketAddr::from(([0, 0, 0, 0], port)), SocketAddr::from(([0u16; 8], port))]
    } else {
        spec.to_socket_addrs()?.collect()
    };
    let mut listeners = Vec::new();
    let mut last_error = io::Error::other(format!("no address for {spec}"));
    for addr in addresses {
        match match addr {
            SocketAddr::V4(_) => TcpListener::bind(addr),
            SocketAddr::V6(v6) => bind_v6only(v6),
        } {
            Ok(listener) => listeners.push(listener),
            Err(error) => last_error = error,
        }
    }
    // Like getaddrinfo(AF_UNSPEC, AI_PASSIVE), keep successful families even
    // when IPv6 is unavailable or another address is already bound.
    if listeners.is_empty() { Err(last_error) } else { Ok(listeners) }
}

/// Like uhttpd (usock with USOCK_IPV6ONLY): a v6 listener that does not claim
/// the v4 wildcard, so "-p 0.0.0.0:80 -p [::]:80" can coexist.
fn bind_v6only(addr: std::net::SocketAddrV6) -> io::Result<TcpListener> {
    use rustix::net::{self, sockopt, AddressFamily, SocketFlags, SocketType};
    let fd = net::socket_with(AddressFamily::INET6, SocketType::STREAM, SocketFlags::CLOEXEC, None)?;
    sockopt::set_ipv6_v6only(&fd, true)?;
    sockopt::set_socket_reuseaddr(&fd, true)?;
    net::bind(&fd, &addr)?;
    net::listen(&fd, 128)?;
    Ok(TcpListener::from(fd))
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

/// The client socket, plain or wrapped in TLS. An enum rather than a trait
/// object so a parked connection can be inspected: whether TLS still holds
/// decrypted bytes or owes the peer a write decides if it may be parked.
/// The TLS variant is large; boxing it would only add an allocation to a
/// connection that already owns rustls's buffers.
#[allow(clippy::large_enum_variant)]
enum Transport {
    Plain(http::Sock),
    Tls(rustls::StreamOwned<rustls::ServerConnection, http::Sock>),
}

impl Transport {
    fn tcp(&self) -> &TcpStream {
        match self {
            Transport::Plain(s) => &s.0,
            Transport::Tls(s) => &s.sock.0,
        }
    }

    /// True when a read would not have to touch the socket first -- TLS
    /// plaintext already decrypted -- or when TLS still has records to send.
    /// Such a connection must stay on its thread; the poll set only watches
    /// the socket.
    fn busy(&mut self) -> bool {
        match self {
            Transport::Plain(_) => false,
            Transport::Tls(s) => {
                s.conn.wants_write()
                    || s.conn.process_new_packets().map(|st| st.plaintext_bytes_to_read() > 0).unwrap_or(true)
            }
        }
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
        }
    }
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write_vectored(bufs),
            // The TLS Out never opts in; preserve Write's scalar fallback.
            Transport::Tls(s) => s.write_vectored(bufs),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

type Client = BufReader<Transport>;

use http::LINGER;

/// A keep-alive connection between requests, held by its listener's poll set
/// with no thread, read buffer or parser storage attached.
struct Parked {
    transport: Transport,
    conn: Conn,
    /// End of the keep-alive wait that began when the last response was
    /// sent (uh_keepalive_poll_cb's timer). The head deadline resumes here.
    /// While a fastpath reply is draining, this is its write deadline.
    deadline: Instant,
    /// A committed inline response the socket has not fully accepted yet
    /// (fast.rs). The listener holds POLLOUT interest until it drains.
    writing: Option<fast::PendingReply>,
}

/// Where connection threads leave parked connections for their listener.
struct Parking {
    inbox: Mutex<Vec<Parked>>,
    /// Non-blocking write end of the listener's wake pipe; a byte interrupts
    /// its poll.
    wake: std::fs::File,
}

impl Parking {
    fn wake(&self) {
        loop {
            match (&self.wake).write(&[1]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // A full nonblocking pipe already guarantees a wakeup.
                _ => return,
            }
        }
    }

    fn park(&self, parked: Parked) {
        self.inbox.lock().unwrap_or_else(|e| e.into_inner()).push(parked);
        self.wake();
    }
}

/// What a connection thread did with its connection when it returned.
enum Outcome {
    Closed,
    Parked,
}

/// Put the client socket in (non-)blocking mode for the duration of a handler
/// that drives readiness itself. The fd stays owned by the connection.
fn set_nonblocking(fd: RawFd, on: bool) -> io::Result<()> {
    owrt_platform::httpd::set_nonblocking(fd, on)
}
fn set_read_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    owrt_platform::httpd::set_read_timeout(fd, timeout)
}



/// Most a keep-alive connection will discard from an unwanted body before
/// closing instead.
const MAX_DRAIN: usize = 64 * 1024;

/// Response bytes held before the transport has to take some. Also the CGI
/// relay's back-pressure mark: above it we stop reading the script's stdout.
const OUT_WINDOW: usize = 16 * 1024;

struct Server {
    config: Config,
    tls_addresses: Vec<SocketAddr>,
    cgi_physical_prefix: Option<String>,
    bridge: Bridge,
    connections: AtomicUsize,
    accept_lock: Mutex<()>,
    /// The connection cap covers every listener, so releasing its last slot
    /// must wake HTTP, HTTPS and both address families together.
    listeners: Mutex<Vec<Weak<Parking>>>,
    scripts: ScriptSlots,
    output_buffers: Mutex<Vec<Vec<u8>>>,
    inventory: Option<Mutex<std::fs::File>>,
}

impl Server {
    fn release_connection(&self) {
        let before = self.connections.fetch_sub(1, Ordering::Relaxed);
        if self.config.max_connections == 0 || before != self.config.max_connections {
            return;
        }
        // Never take an inbox or accept lock here: a listener can release a
        // slot while draining its inbox, and these writes cannot block.
        self.listeners.lock().unwrap_or_else(|e| e.into_inner()).retain(|listener| {
            if let Some(listener) = listener.upgrade() {
                listener.wake();
                true
            } else {
                false
            }
        });
    }

    /// Drive one connection until it closes or is parked. `resume` is the
    /// keep-alive deadline of a connection taken back from the poll set.
    fn run_connection(&self, transport: Transport, conn: Conn, parking: &Parking, resume: Option<Instant>, heads: &mut http::HeadBuffer) -> Outcome {
        // Keep the established read-ahead at oversized request boundaries;
        // reducing it can leave unread TCP bytes and turn a 413 into a reset.
        let client = RefCell::new(BufReader::new(transport));
        let network_timeout = Duration::from_secs(self.config.network_timeout.max(1));
        let keepalive = Duration::from_secs(u64::from(self.config.http_keepalive).max(1));
        // uh_keepalive_poll_cb (client.c:110-117): one deadline covers the
        // whole head, network_timeout for the first request on the
        // connection and http_keepalive for the ones after it. Without it
        // a client that dribbles one byte per read holds its slot forever.
        let mut head_deadline = resume.unwrap_or_else(|| Instant::now() + network_timeout);
        // The socket's receive timeout is LINGER for the connection's whole
        // life (set at accept); the thread's ReadWait mode says what a timed
        // out read means in each phase. Handshake and bodies get the network
        // budget, the first byte of a head parks the connection.
        http::set_read_wait(http::ReadWait::Budget(network_timeout));
        loop {
            // The first read of every head waits at most LINGER on this
            // thread; an idle connection is then parked with its deadline.
            let deadline = http::HeadDeadline::until(conn.fd, head_deadline).with_linger(LINGER).linger_socket();
            // Bind the outcome first: a `borrow_mut()` in the scrutinee stays
            // alive for the whole match, and the reject arm needs the stream.
            let outcome = heads.read_request(
                &mut *client.borrow_mut(),
                self.config.http_keepalive > 0,
                Some(&deadline),
            );
            // client_parse_header cancels the timeout on the blank line
            // (client.c:372): the body and the response get the full budget.
            http::set_read_wait(http::ReadWait::Budget(network_timeout));
            let mut request = match outcome {
                Ok(ParseOutcome::Request(r)) => r,
                Ok(ParseOutcome::Eof) | Err(_) => return Outcome::Closed,
                Ok(ParseOutcome::Idle) => {
                    // TLS may still owe the peer a write or hold plaintext
                    // that the socket cannot signal; keep such a connection.
                    if client.borrow_mut().get_mut().busy() {
                        continue;
                    }
                    // No byte was read, so no read-ahead is lost with the reader.
                    let transport = client.into_inner().into_inner();
                    parking.park(Parked { transport, conn, deadline: head_deadline, writing: None });
                    return Outcome::Parked;
                }
                Ok(ParseOutcome::Bad { code, summary, version, body }) => {
                    let mut out = http::Out::new(&client, conn.fd, OUT_WINDOW, network_timeout);
                    self.reject(&mut out, code, summary, version, body);
                    let _ = Write::flush(&mut out);
                    return Outcome::Closed;
                }
            };
            // Idle connections hold no response window. Share a small bounded
            // set between active requests, retaining initialized storage for
            // file reads without allocating it per request or per idle client.
            let buffer = self.output_buffers.lock().unwrap_or_else(|e| e.into_inner())
                .pop().unwrap_or_else(|| Vec::with_capacity(512));
            let mut out = http::Out::with_buffer(&client, conn.fd, OUT_WINDOW, network_timeout, buffer);
            if !conn.tls {
                out.enable_plain_vectored();
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
                    return Outcome::Closed;
                }
                close = resp.connection_close();
            }
            if out.finish_request().is_err() {
                return Outcome::Closed;
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
                return Outcome::Closed;
            }
            heads.recycle(request);
            head_deadline = Instant::now() + keepalive;
        }
    }

    /// Error response for a request that never reached a handler.
    fn reject(&self, out: &mut dyn Write, code: u16, summary: &str, version: http::Version, body: bool) {
        let dummy = Request {
            method: Method::Get,
            version,
            url: String::new(),
            headers: Vec::new(),
            header_bytes: 0,
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
        // client_header_complete: policy filters precede interim responses.
        if self.config.rfc1918_filter
            && is_rfc1918(conn.remote.ip())
            && !is_rfc1918(conn.local.ip())
        {
            return resp.error(
                403,
                "Forbidden",
                Some("Rejected request from RFC1918 IP to public server address"),
            );
        }
        if self.config.tls_redirect && !conn.tls {
            let port = self.tls_addresses.iter()
                .filter(|addr| addr.is_ipv6() == conn.local.is_ipv6())
                .map(SocketAddr::port)
                .fold(None, |first, port| if first.is_none() || port == 443 { Some(port) } else { first });
            if let (Some(port), Some(host)) = (port, request.header("host")) {
                let host = if let Some(end) = host.find(']') { &host[..=end] }
                    else { host.split(':').next().unwrap_or(host) };
                let port = if port == 443 { String::new() } else { format!(":{port}") };
                resp.force_close();
                resp.disable_chunked();
                resp.status(307, "Temporary Redirect")?;
                resp.header("Location", format!("https://{host}{port}{}", request.url))?;
                resp.end_headers()?;
                return resp.finish();
            }
        }
        if request.expect_continue {
            resp.sink().write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            resp.sink().flush()?;
        }
        let path = request.url.split('?').next().unwrap_or("");
        if let Some(prefix) = &self.config.ubus_prefix {
            if path == prefix || path.strip_prefix(prefix).is_some_and(|tail| tail.starts_with('/')) {
                // URL-prefix handlers bypass file lookup; enforce their realm
                // before reading a body or invoking ubus (uhttpd 3aa7e1c).
                if auth::check(&self.config.auth, &request.url, request.header("authorization")).is_err() {
                    return self.require_authorization(resp);
                }
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
        let mut remote_user: Option<String> = None;
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
                    match auth::check(&self.config.auth, pi.name(), request.header("authorization")) {
                        Err(()) => {
                            return self.require_authorization(resp);
                        }
                        Ok(Some((user, pass))) => {
                            request.headers.retain(|(k, _)| k != "http-auth-user" && k != "http-auth-pass");
                            request.headers.push(("http-auth-user".into(), user.clone()));
                            request.headers.push(("http-auth-pass".into(), pass));
                            remote_user = Some(user);
                        }
                        Ok(None) => {}
                    }
                    let physical = pi.phys.as_str();
                    let interpreter = self.config.interpreters.iter()
                        .find(|(ext, _)| physical.len() > ext.len() && physical.ends_with(ext))
                        .map(|(_, path)| path.as_str());
                    let is_cgi = interpreter.is_some() || self.cgi_physical_prefix.as_ref()
                        .is_some_and(|prefix| path_matches(prefix, physical));
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
                            remote_user: remote_user.as_deref(),
                        };
                        return cgi::run(&ctx, request, body, resp, &pi);
                    }
                    match files::serve(request, resp, &pi, self.config.no_dirlists, &self.config.dirlist_charset, true)? {
                        files::Served::Complete => return Ok(()),
                        files::Served::Forbidden => {
                            if redirect_status != 403 {
                                if let Some(handler) = &self.config.error_handler {
                                    url = Cow::Borrowed(handler.as_str());
                                    redirect_status = 403;
                                    continue;
                                }
                            }
                            return files::forbidden(resp, request, &request.url);
                        }
                    }
                }
                files::Lookup::NotFound => {
                    if redirect_status == 403 {
                        return files::forbidden(resp, request, &request.url);
                    }
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

    fn require_authorization<W: Write>(&self, resp: &mut Response<W>) -> io::Result<()> {
        resp.status(401, "Authorization Required")?;
        resp.header("WWW-Authenticate", format!("Basic realm=\"{}\"", self.config.realm))?;
        resp.header("Content-Type", "text/plain")?;
        resp.end_headers()?;
        resp.body(b"Authorization Required\n")?;
        resp.finish()
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

/// One listener: accepts, and holds the keep-alive connections its threads
/// have parked, waking one only when its socket reports input, a hangup or
/// its keep-alive deadline. The parked set is a readiness set (epoll on
/// Linux), so a wake costs the same with two parked sockets or two thousand.
fn accept_loop(server: Arc<Server>, listener: TcpListener, tls: Option<Arc<rustls::ServerConfig>>) {
    use owrt_ubus::readiness::{Poller, Ready};
    const TOKEN_WAKE: u64 = u64::MAX;
    const TOKEN_LISTENER: u64 = u64::MAX - 1;

    let local = listener.local_addr().ok();
    if listener.set_nonblocking(true).is_err() { return; }
    set_tcp_keepalive(&listener, server.config.tcp_keepalive);
    let Ok((wake_r, wake_w)) = owrt_ubus::sys::pipe() else { return };
    if owrt_ubus::sys::set_nonblocking(wake_r.as_raw_fd()).is_err()
        || owrt_ubus::sys::set_nonblocking(wake_w.as_raw_fd()).is_err() {
        return;
    }
    let (wake_r, wake_w): (std::fs::File, std::fs::File) = (wake_r.into(), wake_w.into());
    let Ok(mut poller) = Poller::new() else { return };
    if poller.add(wake_r.as_raw_fd(), TOKEN_WAKE, false).is_err() { return; }
    let parking = Arc::new(Parking { inbox: Mutex::new(Vec::new()), wake: wake_w });
    server.listeners.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::downgrade(&parking));
    // Parked connections by token; tokens are never reused within a listener.
    let mut parked: std::collections::HashMap<u64, Parked> = std::collections::HashMap::new();
    let mut next_token: u64 = 0;
    let mut listening = false;
    let mut ready: Vec<Ready> = Vec::new();
    // Bounded working storage for inline service of parked connections.
    let mut scratch = fast::Scratch::default();
    let keepalive = Duration::from_secs(u64::from(server.config.http_keepalive).max(1));
    let write_budget = Duration::from_secs(server.config.network_timeout.max(1));
    loop {
        for p in parking.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            let token = next_token;
            next_token += 1;
            if poller.add(p.conn.fd, token, false).is_ok() {
                parked.insert(token, p);
            } else {
                // Cannot watch it: treat as closed rather than leak the slot.
                server.release_connection();
            }
        }
        // uhttpd closes a keep-alive connection whose timer ran out without
        // answering (client_timeout, client.c:95).
        let now = Instant::now();
        let expired: Vec<u64> = parked.iter().filter(|(_, p)| p.deadline <= now).map(|(t, _)| *t).collect();
        for token in expired {
            if let Some(p) = parked.remove(&token) {
                let _ = poller.remove(p.conn.fd);
                server.release_connection();
            }
        }
        // listen.c:95 + uh_poll_listeners: at the cap uhttpd takes the listener
        // out of uloop and re-arms it once a client goes away, so further
        // connection attempts wait in the backlog instead of being accepted and
        // dropped. `-N 0` disables the cap entirely (`conf.max_connections &&`).
        let at_cap = server.config.max_connections > 0
            && server.connections.load(Ordering::Relaxed) >= server.config.max_connections;
        if at_cap && listening {
            listening = poller.remove(listener.as_raw_fd()).is_err();
        } else if !at_cap && !listening {
            listening = poller.add(listener.as_raw_fd(), TOKEN_LISTENER, false).is_ok();
        }
        let mut timeout = parked
            .values()
            .map(|p| p.deadline.saturating_duration_since(now).as_millis().clamp(1, i32::MAX as u128) as i32)
            .min()
            .unwrap_or(-1);
        if at_cap || !listening {
            // Retain a bounded retry if registration failed, as well as a
            // defensive cap recheck. Normal slot releases wake every listener.
            timeout = if timeout < 0 { 50 } else { timeout.min(50) };
        }
        if poller.wait(timeout, &mut ready).is_err() {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let mut accept_ready = false;
        for r in &ready {
            match r.token {
                TOKEN_WAKE => {
                    let mut drain = [0u8; 64];
                    while matches!((&wake_r).read(&mut drain), Ok(n) if n > 0) {}
                }
                TOKEN_LISTENER => accept_ready = r.revents & owrt_ubus::sys::POLLIN != 0,
                token => {
                    // Serve eligible requests here, on the thread that already
                    // owns the socket's registration: no epoll DEL/ADD, no
                    // handoff wake, no fresh reader per parked request.
                    let (event, was_writing) = {
                        let writing = parked.values().filter(|q| q.writing.is_some()).count();
                        let Some(p) = parked.get_mut(&token) else { continue };
                        if !fast::wants_inline(p) {
                            // TLS keeps its existing resume path whole.
                            let p = parked.remove(&token).expect("checked above");
                            let _ = poller.remove(p.conn.fd);
                            resume(&server, &parking, p);
                            continue;
                        }
                        let was_writing = p.writing.is_some();
                        let event = if was_writing {
                            fast::on_writable(p, &mut scratch)
                        } else {
                            fast::on_readable(&server, p, &mut scratch, writing)
                        };
                        (event, was_writing)
                    };
                    match event {
                        fast::Event::Spurious => {}
                        fast::Event::Writing => {
                            let p = parked.get_mut(&token).expect("entry retained");
                            if !was_writing {
                                p.deadline = Instant::now() + write_budget;
                                if poller.set_interest(p.conn.fd, token, false, true).is_err() {
                                    // Cannot watch for output: drop the reply.
                                    let p = parked.remove(&token).expect("entry retained");
                                    let _ = poller.remove(p.conn.fd);
                                    server.release_connection();
                                }
                            }
                        }
                        fast::Event::Served => {
                            let p = parked.get_mut(&token).expect("entry retained");
                            p.deadline = Instant::now() + keepalive;
                            if was_writing
                                && poller.set_interest(p.conn.fd, token, true, false).is_err()
                            {
                                let p = parked.remove(&token).expect("entry retained");
                                let _ = poller.remove(p.conn.fd);
                                server.release_connection();
                            }
                        }
                        fast::Event::ServedClose | fast::Event::Close => {
                            if let Some(p) = parked.remove(&token) {
                                let _ = poller.remove(p.conn.fd);
                                drop(p);
                                server.release_connection();
                            }
                        }
                        fast::Event::Handoff => {
                            if let Some(p) = parked.remove(&token) {
                                let _ = poller.remove(p.conn.fd);
                                spawn_connection(&server, &parking, p.transport, p.conn, Some(p.deadline));
                            }
                        }
                    }
                }
            }
        }
        if at_cap || !accept_ready {
            continue;
        }
        // All listeners share the cap. The lock covers nonblocking accept and
        // increment together, so HTTP and HTTPS cannot both claim the last slot.
        let guard = server.accept_lock.lock().unwrap_or_else(|e| e.into_inner());
        if server.config.max_connections > 0
            && server.connections.load(Ordering::Relaxed) >= server.config.max_connections {
            continue;
        }
        let (stream, remote) = match listener.accept() {
            Ok(pair) => pair,
            Err(error) => {
                // An exhausted listener must not hold the shared admission
                // lock while backing off and delay healthy listeners too.
                drop(guard);
                if !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                continue;
            }
        };
        server.connections.fetch_add(1, Ordering::Relaxed);
        drop(guard);
        let local = stream
            .local_addr()
            .or(local.ok_or(io::Error::other("no local addr")))
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let fd = stream.as_raw_fd();
        let timeout = Duration::from_secs(server.config.network_timeout.max(1));
        // http::Sock fixes the receive timeout at LINGER for the connection's
        // life and turns it into idle detection or a polled wait per phase,
        // so no request ever pays a setsockopt.
        let _ = stream.set_write_timeout(Some(timeout));
        let _ = stream.set_nodelay(true);
        let conn = Conn { local, remote, tls: tls.is_some(), fd };
        let transport = match &tls {
            None => Transport::Plain(http::Sock::new(stream)),
            Some(config) => match rustls::ServerConnection::new(Arc::clone(config)) {
                Ok(mut c) => {
                    c.set_buffer_limit(Some(16 * 1024));
                    Transport::Tls(rustls::StreamOwned::new(c, http::Sock::new(stream)))
                }
                Err(_) => {
                    server.release_connection();
                    continue;
                }
            },
        };
        spawn_connection(&server, &parking, transport, conn, None);
    }
}

/// A parked connection's socket reported something. A closed peer is the
/// usual reason and is answered here; anything else gets a thread again.
fn resume(server: &Arc<Server>, parking: &Arc<Parking>, p: Parked) {
    match p.transport.tcp().peek(&mut [0u8; 1]) {
        Ok(0) | Err(_) => {
            server.release_connection();
        }
        Ok(_) => spawn_connection(server, parking, p.transport, p.conn, Some(p.deadline)),
    }
}

/// One thread per active connection. A keep-alive connection that goes quiet
/// is parked without a thread, and the fastpath serves its next small static
/// request on the listener itself, so the common paced case never spawns a
/// thread on resume. Requests that fall back keep a fresh thread each -- as
/// uhttpd does not, but idle connections then cost only a descriptor, which
/// is the memory contract the R85/R93 gates hold to.
fn spawn_connection(server: &Arc<Server>, parking: &Arc<Parking>, transport: Transport, conn: Conn, resume: Option<Instant>) {
    let worker = Arc::clone(server);
    let parking = Arc::clone(parking);
    if let Err(error) = std::thread::Builder::new().spawn(move || {
        let mut heads = http::HeadBuffer::default();
        if let Outcome::Closed = worker.run_connection(transport, conn, &parking, resume, &mut heads) {
            worker.release_connection();
        }
    }) {
        // The failed spawn drops its closure and the socket. Release the
        // reserved slot too, and keep the listener alive under pressure.
        server.release_connection();
        let _ = writeln!(std::io::stderr().lock(), "httpd-rs: cannot create connection thread: {error}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
#[path = "fast_tests.rs"]
mod fast_tests;

fn set_tcp_keepalive(fd: impl AsFd, interval: u64) {
    if interval == 0 { return; }
    use rustix::net::sockopt;
    let _ = sockopt::set_tcp_keepidle(&fd, Duration::from_secs(1));
    let _ = sockopt::set_tcp_keepintvl(&fd, Duration::from_secs(interval.min(i32::MAX as u64)));
    let _ = sockopt::set_tcp_keepcnt(&fd, 3);
    let _ = owrt_platform::httpd::set_tcp_fastopen(&fd, 5);
    let _ = sockopt::set_socket_keepalive(&fd, true);
}

fn main() {
    let config = match parse_args() {
        Ok(config) => config,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "httpd-rs: {error}");
            std::process::exit(64);
        }
    };
    owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
    let tls_config = match (&config.cert, &config.key, config.https.is_empty()) {
        (Some(cert), Some(key), false) => match tls::server_config(cert, key, config.tls_ciphers.as_deref()) {
            Ok(cfg) => Some(cfg),
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "httpd-rs: cannot initialize TLS: {error}");
                std::process::exit(1);
            }
        },
        (_, _, false) => {
            let _ = writeln!(std::io::stderr(), "httpd-rs: HTTPS requires a certificate and key");
            std::process::exit(1);
        }
        _ => None,
    };
    let inventory = config
        .call_log
        .as_ref()
        .and_then(|path| std::fs::File::create(path).ok());
    let mut listeners = Vec::new();
    let mut tls_addresses = Vec::new();
    for spec in &config.http {
        match bind(spec) {
            Ok(bound) => listeners.extend(bound.into_iter().map(|listener| (listener, None))),
            Err(error) => { let _ = writeln!(std::io::stderr(), "httpd-rs: cannot bind {spec}: {error}"); },
        }
    }
    if let Some(tls_config) = tls_config {
        for spec in &config.https {
            match bind(spec) {
                Ok(bound) => {
                    for listener in bound {
                        if let Ok(addr) = listener.local_addr() { tls_addresses.push(addr); }
                        listeners.push((listener, Some(Arc::clone(&tls_config))));
                    }
                }
                Err(error) => { let _ = writeln!(std::io::stderr(), "httpd-rs: cannot bind {spec}: {error}"); },
            }
        }
    }
    let server = Arc::new(Server {
        tls_addresses,
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
        listeners: Mutex::new(Vec::new()),
        scripts: ScriptSlots { count: Mutex::new(0), ready: Condvar::new(), limit: config.max_script_requests },
        output_buffers: Mutex::new(Vec::new()),
        inventory: inventory.map(Mutex::new),
        config,
    });
    let Some(last) = listeners.pop() else {
        let _ = writeln!(std::io::stderr(), "httpd-rs: nothing to listen on");
        std::process::exit(1);
    };
    let mut handles = Vec::new();
    for (listener, tls) in listeners {
        let server = Arc::clone(&server);
        handles.push(std::thread::spawn(move || accept_loop(server, listener, tls)));
    }
    // The main thread serves the last listener itself rather than only
    // waiting: one thread fewer at idle, as uhttpd's single loop has.
    accept_loop(Arc::clone(&server), last.0, last.1);
    for handle in handles {
        let _ = handle.join();
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    pub(super) fn server(limit: usize) -> Server {
        let config = parse_args_from(["-p", "127.0.0.1:0", "-c", "/r93-no-httpd-config", "-N"]
            .into_iter().map(str::to_owned).chain([limit.to_string()])).unwrap();
        Server {
            config, tls_addresses: Vec::new(), cgi_physical_prefix: None,
            bridge: Bridge {
                socket: None, noauth: false, cors: false, timeout_ms: 1000,
                events_retry: 0, record_calls: false,
                idle: Mutex::new(Vec::new()), calls: Mutex::new(Vec::new()),
            },
            connections: AtomicUsize::new(0), accept_lock: Mutex::new(()),
            listeners: Mutex::new(Vec::new()),
            scripts: ScriptSlots { count: Mutex::new(0), ready: Condvar::new(), limit: 1 },
            output_buffers: Mutex::new(Vec::new()), inventory: None,
        }
    }

    pub(super) fn listener(server: &Server) -> (Arc<Parking>, UnixStream) {
        // UnixStream gives both host tests and Linux a nonblocking writable
        // descriptor without depending on Linux's pipe2 flag constants.
        let (read, write) = UnixStream::pair().unwrap();
        read.set_nonblocking(true).unwrap();
        write.set_nonblocking(true).unwrap();
        let owned: std::os::fd::OwnedFd = write.into();
        let parking = Arc::new(Parking { inbox: Mutex::new(Vec::new()), wake: owned.into() });
        server.listeners.lock().unwrap().push(Arc::downgrade(&parking));
        (parking, read)
    }

    #[test]
    fn large_vectored_plain_transport_forwards_both_slices() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut transport = Transport::Plain(http::Sock::new(socket));
        let written = transport.write_vectored(&[
            io::IoSlice::new(b"header:"), io::IoSlice::new(b"body"),
        ]).unwrap();
        assert_eq!(written, 11);
        let mut received = [0; 11];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"header:body");
    }

    #[test]
    fn freeing_the_shared_last_slot_wakes_every_listener_even_before_wait() {
        let server = server(2);
        let (_first, mut first) = listener(&server);
        let (_second, mut second) = listener(&server);
        let (retired, _read) = listener(&server);
        drop(retired);
        server.connections.store(2, Ordering::Relaxed);
        server.release_connection();
        assert_eq!(server.connections.load(Ordering::Relaxed), 1);
        // The wake remains queued if release raced ahead of the next wait.
        let mut poller = owrt_ubus::readiness::Poller::new().unwrap();
        poller.add(first.as_raw_fd(), 1, false).unwrap();
        poller.add(second.as_raw_fd(), 2, false).unwrap();
        let mut ready = Vec::new();
        poller.wait(0, &mut ready).unwrap();
        assert_eq!(ready.len(), 2);
        assert_eq!(first.read(&mut [0]).unwrap(), 1);
        assert_eq!(second.read(&mut [0]).unwrap(), 1);
        assert_eq!(server.listeners.lock().unwrap().len(), 2);
        // Closing below the cap adds no broadcast work or stray wake bytes.
        server.release_connection();
        assert_eq!(server.connections.load(Ordering::Relaxed), 0);
        poller.wait(0, &mut ready).unwrap();
        assert!(ready.is_empty());
    }

    #[test]
    fn a_full_wake_descriptor_does_not_block_shared_slot_release() {
        let server = server(1);
        let (parking, _read) = listener(&server);
        loop {
            match (&parking.wake).write(&[0; 4096]) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                result => panic!("filling wake descriptor: {result:?}"),
            }
        }
        server.connections.store(1, Ordering::Relaxed);
        server.release_connection();
        assert_eq!(server.connections.load(Ordering::Relaxed), 0);
    }
}
