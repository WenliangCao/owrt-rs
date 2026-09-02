//! httpd-rs: contract C3 compatible uhttpd replacement.
//!
//! Accepts uhttpd's command line so the stock init script arguments work
//! unchanged. One thread per connection; blocking I/O; TLS via rustls.

mod bridge;
mod cgi;
mod files;
mod http;
mod json;
mod tls;

use bridge::Bridge;
use http::{Method, ParseOutcome, Request, Response};
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
    rfc1918_filter: bool,
    no_dirlists: bool,
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

fn parse_args() -> Result<Config, String> {
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
        rfc1918_filter: false,
        no_dirlists: false,
        error_handler: None,
        http: Vec::new(),
        https: Vec::new(),
        cert: None,
        key: None,
        call_log: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or(format!("{flag} requires a value"));
        match arg.as_str() {
            "-f" | "-a" | "-X" | "-R" | "-D" | "-S" | "-q" => match arg.as_str() {
                "-a" => c.ubus_noauth = true,
                "-X" => c.ubus_cors = true,
                "-R" => c.rfc1918_filter = true,
                "-D" => c.no_dirlists = true,
                _ => {}
            },
            "-h" => c.docroot = value("-h")?.trim_end_matches('/').to_owned(),
            "-x" => c.cgi_prefix = Some(value("-x")?),
            "-u" => c.ubus_prefix = Some(value("-u")?),
            "-U" => c.ubus_socket = Some(value("-U")?),
            "-t" => c.script_timeout = value("-t")?.parse().map_err(|_| "-t must be a number")?,
            "-T" => c.network_timeout = value("-T")?.parse().map_err(|_| "-T must be a number")?,
            "-k" => c.http_keepalive = value("-k")?.parse().map_err(|_| "-k must be a number")?,
            "-A" => c.tcp_keepalive = value("-A")?.parse().map_err(|_| "-A must be a number")?,
            "-n" => {
                value("-n")?;
            }
            "-N" => c.max_connections = value("-N")?.parse().map_err(|_| "-N must be a number")?,
            "-E" => c.error_handler = Some(value("-E")?),
            "-I" | "-r" | "-i" | "-y" | "-e" | "-b" | "-c" | "-P" => {
                value(&arg)?;
            }
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
    Ok(c)
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
    let ok = unsafe {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, 4) == 0
            && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, 4) == 0
            && bind(fd, &sa, std::mem::size_of::<SockAddrIn6>() as u32) == 0
            && listen(fd, 128) == 0
    };
    if !ok {
        let error = io::Error::last_os_error();
        unsafe {
            close(fd);
        }
        return Err(error);
    }
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

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

struct Server {
    config: Config,
    bridge: Bridge,
    connections: AtomicUsize,
    inventory: Mutex<Option<std::fs::File>>,
}

impl Server {
    fn serve(&self, stream: Box<dyn Stream>, local: SocketAddr, remote: SocketAddr, is_tls: bool) {
        let mut reader = BufReader::new(stream);
        loop {
            let request = match http::read_request(&mut reader, self.config.http_keepalive > 0) {
                Ok(ParseOutcome::Request(r)) => r,
                Ok(ParseOutcome::Eof) | Err(_) => return,
                Ok(ParseOutcome::Bad(code, summary)) => {
                    let dummy = Request {
                        method: Method::Get,
                        version: http::Version::V1_0,
                        url: String::new(),
                        headers: Vec::new(),
                        content_length: None,
                        transfer_chunked: false,
                        connection_close: true,
                        expect_continue: false,
                    };
                    let mut out = Vec::new();
                    {
                        let mut resp = Response::new(&mut out, &dummy, self.config.http_keepalive);
                        let _ = resp.error(code, summary, None);
                    }
                    let _ = reader.get_mut().write_all(&out);
                    return;
                }
            };
            if request.expect_continue {
                let _ = reader.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            }
            let body_needed = request.content_length.unwrap_or(0) > 0 || request.transfer_chunked;
            let body = if body_needed {
                match http::read_body(&mut reader, &request, 4 * 1024 * 1024) {
                    Ok(Some(b)) => Some(b),
                    _ => return,
                }
            } else {
                None
            };
            let mut out = Vec::new();
            let close;
            {
                let mut resp = Response::new(&mut out, &request, self.config.http_keepalive);
                if let Err(_e) =
                    self.dispatch(&request, body.as_deref(), &mut resp, local, remote, is_tls)
                {
                    return;
                }
                close = resp.connection_close();
            }
            if reader.get_mut().write_all(&out).is_err() || reader.get_mut().flush().is_err() {
                return;
            }
            if close || self.config.http_keepalive == 0 {
                return;
            }
        }
    }

    fn dispatch<W: Write>(
        &self,
        request: &Request,
        body: Option<&[u8]>,
        resp: &mut Response<W>,
        local: SocketAddr,
        remote: SocketAddr,
        is_tls: bool,
    ) -> io::Result<()> {
        if self.config.rfc1918_filter
            && is_rfc1918(remote.ip())
            && !is_rfc1918(local.ip())
            && !local.ip().is_loopback()
        {
            return resp.error(
                403,
                "Forbidden",
                Some("Rejected request from RFC1918 IP to public server address"),
            );
        }
        if body.is_some() && request.method != Method::Post {
            // uhttpd drains bodies for any method; we only forward them to POST handlers
        }
        let path = request.url.split('?').next().unwrap_or("");
        if let Some(prefix) = &self.config.ubus_prefix {
            if path == prefix || path.starts_with(&format!("{prefix}/")) {
                let result = bridge::handle(&self.bridge, prefix, request, body, resp);
                self.flush_inventory();
                return result;
            }
        }
        match files::lookup(&self.config.docroot, &request.url) {
            files::Lookup::Redirect(location) => {
                resp.status(302, "Found")?;
                if !resp.chunked() {
                    resp.header("Content-Length", "0")?;
                }
                resp.header("Location", &location)?;
                resp.end_headers()?;
                resp.finish()
            }
            files::Lookup::Found(pi) => {
                let cgi_root = self
                    .config
                    .cgi_prefix
                    .as_ref()
                    .map(|p| format!("{}{}", self.config.docroot, p));
                let is_cgi = cgi_root
                    .as_ref()
                    .map(|root| {
                        let phys = pi.phys.to_string_lossy();
                        phys.as_ref() == root.as_str() || phys.starts_with(&format!("{root}/"))
                    })
                    .unwrap_or(false);
                if is_cgi {
                    if !cgi::is_executable(&pi) {
                        return files::forbidden(resp, &pi.name);
                    }
                    let ctx = cgi::CgiContext {
                        docroot: &self.config.docroot,
                        cgi_path: &self.config.cgi_path,
                        local,
                        remote,
                        tls: is_tls,
                        script_timeout: self.config.script_timeout,
                    };
                    return cgi::run(&ctx, request, body.unwrap_or(&[]), resp, &pi);
                }
                files::serve(request, resp, &pi, self.config.no_dirlists)
            }
            files::Lookup::NotFound => {
                if let Some(handler) = &self.config.error_handler {
                    if let files::Lookup::Found(pi) = files::lookup(&self.config.docroot, handler) {
                        return files::serve(request, resp, &pi, self.config.no_dirlists);
                    }
                }
                files::not_found(resp, path)
            }
        }
    }

    fn flush_inventory(&self) {
        use std::io::Seek;
        if let Ok(mut guard) = self.inventory.lock() {
            if let Some(file) = guard.as_mut() {
                let text = self.bridge.call_inventory();
                let _ = file.seek(std::io::SeekFrom::Start(0));
                let _ = file.write_all(text.as_bytes());
                let _ = file.set_len(text.len() as u64);
                let _ = file.flush();
            }
        }
    }
}

fn accept_loop(server: Arc<Server>, listener: TcpListener, tls: Option<Arc<rustls::ServerConfig>>) {
    let local = listener.local_addr().ok();
    loop {
        let (stream, remote) = match listener.accept() {
            Ok(pair) => pair,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        if server.connections.load(Ordering::Relaxed) >= server.config.max_connections {
            drop(stream);
            continue;
        }
        let server = Arc::clone(&server);
        let tls = tls.clone();
        let local = stream
            .local_addr()
            .or(local.ok_or(io::Error::other("no local addr")))
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        server.connections.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            let timeout = Duration::from_secs(server.config.network_timeout.max(1));
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let _ = stream.set_nodelay(true);
            match tls {
                None => server.serve(Box::new(stream), local, remote, false),
                Some(config) => {
                    if let Ok(conn) = rustls::ServerConnection::new(config) {
                        let tls_stream = rustls::StreamOwned::new(conn, stream);
                        server.serve(Box::new(tls_stream), local, remote, true);
                    }
                }
            }
            server.connections.fetch_sub(1, Ordering::Relaxed);
        });
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
        (Some(cert), Some(key), false) => match tls::server_config(cert, key) {
            Ok(cfg) => Some(cfg),
            Err(error) => {
                eprintln!("httpd-rs: TLS disabled: {error}");
                None
            }
        },
        _ => None,
    };
    let inventory = config
        .call_log
        .as_ref()
        .and_then(|path| std::fs::File::create(path).ok());
    let server = Arc::new(Server {
        bridge: Bridge {
            socket: config.ubus_socket.clone(),
            noauth: config.ubus_noauth,
            cors: config.ubus_cors,
            timeout_ms: (config.script_timeout as i32).max(1) * 1000,
            calls: Mutex::new(Vec::new()),
        },
        connections: AtomicUsize::new(0),
        inventory: Mutex::new(inventory),
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
