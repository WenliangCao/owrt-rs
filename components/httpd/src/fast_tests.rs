//! The inline fastpath must be invisible: every served response is
//! byte-identical to the thread path's, every fallback leaves the socket
//! untouched, and a blocked send drains through POLLOUT without loss.

use super::*;
use std::io::Read;
use std::net::{TcpListener as StdListener, TcpStream};
use std::thread;

struct Fixture {
    server: Arc<Server>,
    parking: Arc<Parking>,
    _wake_reader: std::os::unix::net::UnixStream,
    docroot: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.docroot);
    }
}

fn fixture() -> Fixture {
    let docroot = std::env::temp_dir().join(format!(
        "httpd-fast-{}-{:?}",
        std::process::id(),
        thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&docroot);
    std::fs::create_dir_all(docroot.join("cgi-bin")).unwrap();
    std::fs::write(docroot.join("hello.txt"), b"hello fastpath\n").unwrap();
    std::fs::write(docroot.join("big.dat"), vec![0x5a; 16 * 1024]).unwrap();
    std::fs::write(docroot.join("huge.dat"), vec![0x5a; 48 * 1024]).unwrap();
    std::fs::write(docroot.join("cgi-bin").join("script"), b"#!/bin/sh\n").unwrap();
    let config = parse_args_from(
        [
            "-p", "127.0.0.1:0",
            "-h", docroot.to_str().unwrap(),
            "-x", "/cgi-bin",
            "-u", "/ubus",
            "-c", "/r94-no-httpd-config",
        ]
        .into_iter()
        .map(str::to_owned),
    )
    .unwrap();
    let cgi_physical_prefix = config
        .cgi_prefix
        .as_ref()
        .map(|prefix| format!("{}{}", config.docroot, prefix));
    let server = Arc::new(Server {
        config,
        tls_addresses: Vec::new(),
        cgi_physical_prefix,
        bridge: Bridge {
            socket: None,
            noauth: false,
            cors: false,
            timeout_ms: 1000,
            events_retry: 0,
            record_calls: false,
            idle: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        },
        connections: AtomicUsize::new(0),
        accept_lock: Mutex::new(()),
        listeners: Mutex::new(Vec::new()),
        scripts: ScriptSlots { count: Mutex::new(0), ready: Condvar::new(), limit: 1 },
        output_buffers: Mutex::new(Vec::new()),
        inventory: None,
    });
    let (read, write) = std::os::unix::net::UnixStream::pair().unwrap();
    read.set_nonblocking(true).unwrap();
    write.set_nonblocking(true).unwrap();
    let owned: std::os::fd::OwnedFd = write.into();
    let parking = Arc::new(Parking { inbox: Mutex::new(Vec::new()), wake: owned.into() });
    server.listeners.lock().unwrap().push(Arc::downgrade(&parking));
    Fixture { server, parking, _wake_reader: read, docroot }
}

/// A connected pair with the server side wrapped as a parked connection.
fn parked_pair(f: &Fixture) -> (Parked, TcpStream) {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (stream, remote) = listener.accept().unwrap();
    let conn = Conn {
        local: stream.local_addr().unwrap(),
        remote,
        tls: false,
        fd: stream.as_raw_fd(),
    };
    f.server.connections.fetch_add(1, Ordering::Relaxed);
    (
        Parked {
            transport: Transport::Plain(http::Sock::new(stream)),
            conn,
            deadline: Instant::now() + Duration::from_secs(20),
            writing: None,
        },
        peer,
    )
}

fn wait_readable(fd: RawFd) {
    let mut fds = [owrt_ubus::sys::PollFd { fd, events: owrt_ubus::sys::POLLIN, revents: 0 }];
    assert!(owrt_ubus::sys::poll_fds(&mut fds, 2000).unwrap() > 0, "no input within deadline");
}

/// One event against a freshly parked connection carrying `request`.
fn fast_event(
    f: &Fixture,
    scratch: &mut fast::Scratch,
    request: &[u8],
) -> (fast::Event, Parked, TcpStream) {
    let (mut parked, mut peer) = parked_pair(f);
    peer.write_all(request).unwrap();
    wait_readable(parked.conn.fd);
    let event = fast::on_readable(&f.server, &mut parked, scratch, 0);
    (event, parked, peer)
}

/// Read one header block (through the blank line) from `peer`.
fn read_headers(peer: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1024];
    while !bytes.ends_with(b"\r\n\r\n") {
        let n = peer.read(&mut buf).unwrap();
        assert!(n > 0, "peer closed before a full header block");
        bytes.extend_from_slice(&buf[..n]);
    }
    bytes
}

/// Read one HTTP response with a Content-Length body from `peer`.
fn read_response(peer: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let head_end = bytes.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
        if let Some(head_end) = head_end {
            let head = std::str::from_utf8(&bytes[..head_end]).unwrap();
            let length: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .expect("static responses carry Content-Length")
                .parse()
                .unwrap();
            if bytes.len() >= head_end + length {
                assert_eq!(bytes.len(), head_end + length, "read past one response");
                return bytes;
            }
        }
        let n = peer.read(&mut buf).unwrap();
        assert!(n > 0, "peer closed before a full response");
        bytes.extend_from_slice(&buf[..n]);
    }
}

fn mask_date(response: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(response);
    text.lines()
        .map(|l| if l.starts_with("Date: ") { "Date: MASKED" } else { l })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

/// The same request through the existing thread path, for byte comparison.
/// `with_body` says whether the response carries a Content-Length body.
fn thread_response(f: &Fixture, request: &[u8], with_body: bool) -> Vec<u8> {
    let (parked, mut peer) = parked_pair(f);
    let server = Arc::clone(&f.server);
    let parking = Arc::clone(&f.parking);
    let handle = thread::spawn(move || {
        let mut heads = http::HeadBuffer::default();
        server.run_connection(parked.transport, parked.conn, &parking, None, &mut heads)
    });
    peer.write_all(request).unwrap();
    let response = if with_body { read_response(&mut peer) } else { read_headers(&mut peer) };
    drop(peer);
    let _ = handle.join().unwrap();
    f.server.connections.store(0, Ordering::Relaxed);
    response
}

#[test]
fn ubus_prefix_requires_basic_auth_before_dispatch() {
    let mut f = fixture();
    Arc::get_mut(&mut f.server).unwrap().config.auth.push(
        auth::Realm::new("/ubus".into(), "user".into(), "secret".into()).unwrap(),
    );
    for (path, authorization, expected) in [
        ("/ubus", "", 401),
        ("/ubus/list", "", 401),
        ("/ubus/subscribe/test", "", 401),
        ("/ubus/call/test", "Basic dXNlcjp3cm9uZw==", 401),
        ("/ubus?query=1", "Bearer unrelated-session", 401),
        ("/ubus", "Basic dXNlcjpzZWNyZXQ=", 200),
        ("/ubus-other", "", 404),
    ] {
        let (parked, mut peer) = parked_pair(&f);
        let server = Arc::clone(&f.server);
        let parking = Arc::clone(&f.parking);
        let worker = thread::spawn(move || {
            server.run_connection(parked.transport, parked.conn, &parking, None, &mut http::HeadBuffer::default())
        });
        peer.write_all(format!("OPTIONS {path} HTTP/1.0\r\nAuthorization: {authorization}\r\n\r\n").as_bytes()).unwrap();
        let mut response = String::new();
        peer.read_to_string(&mut response).unwrap();
        worker.join().unwrap();
        assert!(response.starts_with(&format!("HTTP/1.0 {expected} ")), "{path}: {response}");
        assert_eq!(response.contains("WWW-Authenticate: Basic realm=\""), expected == 401);
    }
}

#[test]
fn served_bytes_match_the_thread_path_for_get_head_and_conditionals() {
    let f = fixture();
    let mut scratch = fast::Scratch::default();
    let get = b"GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let reference = thread_response(&f, get, true);
    let (event, _parked, mut peer) = fast_event(&f, &mut scratch, get);
    assert!(matches!(event, fast::Event::Served), "eligible GET must serve inline");
    let inline = read_response(&mut peer);
    assert_eq!(mask_date(&inline), mask_date(&reference));

    // HEAD: identical header block, no body.
    let head = b"HEAD /hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let head_reference = thread_response(&f, head, false);
    let (event, _parked, mut peer) = fast_event(&f, &mut scratch, head);
    assert!(matches!(event, fast::Event::Served));
    let inline = read_headers(&mut peer);
    assert_eq!(mask_date(&inline), mask_date(&head_reference));

    // A matching If-None-Match takes the same 304 the thread path produces.
    let etag = String::from_utf8_lossy(&reference)
        .lines()
        .find_map(|l| l.strip_prefix("ETag: ").map(str::to_owned))
        .unwrap();
    let conditional =
        format!("GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {etag}\r\n\r\n");
    let reference = thread_response(&f, conditional.as_bytes(), false);
    assert!(reference.starts_with(b"HTTP/1.1 304 "));
    let (event, _parked, mut peer) = fast_event(&f, &mut scratch, conditional.as_bytes());
    assert!(matches!(event, fast::Event::Served));
    let inline = read_headers(&mut peer);
    assert_eq!(mask_date(&inline), mask_date(&reference));
}

#[test]
fn ineligible_requests_hand_off_with_the_socket_untouched() {
    let f = fixture();
    let mut scratch = fast::Scratch::default();
    let cases: &[&[u8]] = &[
        b"POST /hello.txt HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n",
        b"GET /ubus HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /ubus/list HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /cgi-bin/script HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /huge.dat HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /missing HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /cgi-bin HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET /hello.txt HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
        b"BOGUS /hello.txt HTTP/1.1\r\nHost: a\r\n\r\n",
        // Pipelined pair and an incomplete head.
        b"GET /hello.txt HTTP/1.1\r\nHost: a\r\n\r\nGET /x HTTP/1.1\r\n",
        b"GET /hello.txt HTTP/1.1\r\nHost: a\r\n",
        b"\r\nGET /hello.txt HTTP/1.1\r\nHost: a\r\n\r\n",
    ];
    for request in cases {
        let (event, parked, _peer) = fast_event(&f, &mut scratch, request);
        assert!(
            matches!(event, fast::Event::Handoff),
            "expected handoff for {:?}",
            String::from_utf8_lossy(request)
        );
        // Every byte the client sent is still in the socket for the thread.
        let mut pending = vec![0u8; request.len() + 16];
        let stream = parked.transport.tcp();
        stream.set_nonblocking(true).unwrap();
        let n = stream.peek(&mut pending).unwrap();
        assert_eq!(&pending[..n], *request, "fastpath consumed bytes before handoff");
        f.server.connections.store(0, Ordering::Relaxed);
    }
}

#[test]
fn keepalive_serves_repeatedly_and_close_variants_end_the_connection() {
    let f = fixture();
    let mut scratch = fast::Scratch::default();
    let (mut parked, mut peer) = parked_pair(&f);
    for _ in 0..3 {
        peer.write_all(b"GET /hello.txt HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        wait_readable(parked.conn.fd);
        let event = fast::on_readable(&f.server, &mut parked, &mut scratch, 0);
        assert!(matches!(event, fast::Event::Served));
        let response = read_response(&mut peer);
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        assert!(String::from_utf8_lossy(&response).contains("Connection: Keep-Alive"));
    }
    peer.write_all(b"GET /hello.txt HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    wait_readable(parked.conn.fd);
    let event = fast::on_readable(&f.server, &mut parked, &mut scratch, 0);
    assert!(matches!(event, fast::Event::ServedClose));
    let response = read_response(&mut peer);
    assert!(String::from_utf8_lossy(&response).contains("Connection: close"));

    // HTTP/1.0 closes; EOF from the peer closes without a response.
    let (event, _parked, mut peer) = fast_event(&f, &mut scratch, b"GET /hello.txt HTTP/1.0\r\n\r\n");
    assert!(matches!(event, fast::Event::ServedClose));
    assert!(read_response(&mut peer).starts_with(b"HTTP/1.0 200 "));
    let (mut parked, peer) = parked_pair(&f);
    drop(peer);
    wait_readable(parked.conn.fd);
    let event = fast::on_readable(&f.server, &mut parked, &mut scratch, 0);
    assert!(matches!(event, fast::Event::Close));
}

#[test]
fn blocked_send_drains_through_writable_events_without_corruption() {
    let f = fixture();
    let mut scratch = fast::Scratch::default();
    let (mut parked, mut peer) = parked_pair(&f);
    // Fill the kernel buffers so the first drain attempt cannot complete,
    // then inject a committed reply as a blocked send would leave it.
    // Loopback keeps moving bytes into the peer's receive buffer for a while
    // after the first WouldBlock; only a quiet round means actually full.
    let junk_len = {
        let stream = parked.transport.tcp();
        stream.set_nonblocking(true).unwrap();
        let mut written = 0usize;
        let junk = [0u8; 4096];
        let mut quiet_rounds = 0;
        while quiet_rounds < 3 {
            let before = written;
            loop {
                match (&*stream).write(&junk) {
                    Ok(n) => written += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("prefill failed: {e}"),
                }
            }
            if written == before {
                quiet_rounds += 1;
            } else {
                quiet_rounds = 0;
            }
            thread::sleep(Duration::from_millis(20));
        }
        stream.set_nonblocking(false).unwrap();
        written
    };
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    fast::inject_pending(&mut parked, payload.clone(), false);
    let mut event = fast::on_writable(&mut parked, &mut scratch);
    assert!(
        matches!(event, fast::Event::Writing),
        "expected Writing on a full socket, got {event:?} (junk_len={junk_len})"
    );
    let expected = junk_len + payload.len();
    let reader = thread::spawn(move || {
        let mut bytes = Vec::with_capacity(expected);
        let mut buf = [0u8; 4096];
        while bytes.len() < expected {
            let n = peer.read(&mut buf).unwrap();
            assert!(n > 0, "peer saw EOF before the reply drained");
            bytes.extend_from_slice(&buf[..n]);
        }
        (bytes, peer)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while matches!(event, fast::Event::Writing) {
        assert!(Instant::now() < deadline, "pending reply never drained");
        let mut fds = [owrt_ubus::sys::PollFd {
            fd: parked.conn.fd,
            events: owrt_ubus::sys::POLLOUT,
            revents: 0,
        }];
        owrt_ubus::sys::poll_fds(&mut fds, 2000).unwrap();
        event = fast::on_writable(&mut parked, &mut scratch);
    }
    assert!(matches!(event, fast::Event::Served), "drain ended without completion");
    let (bytes, _peer) = reader.join().unwrap();
    assert_eq!(bytes.len(), expected);
    assert_eq!(&bytes[junk_len..], &payload[..], "reply bytes reordered or lost");
}
