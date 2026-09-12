//! Stage profiler for HTTPD's actual parser and file handler, not a server
//! throughput benchmark. Run a release build with [iterations] [stage filter].
//! Timing runs with allocation counting disabled; a separate invocation of
//! each stage counts allocations, timeout syscalls and transport writes.
#![allow(dead_code)]

#[path = "../src/files.rs"]
mod files;
#[path = "../src/http.rs"]
mod http;
#[path = "../src/bridge.rs"]
mod bridge;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::hint::black_box;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct CountingAllocator;
static COUNT: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);

// SAFETY: every operation delegates unchanged to the System allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size() as u64, Relaxed);
        }
        // SAFETY: the caller supplies the GlobalAlloc layout contract unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size() as u64, Relaxed);
        }
        // SAFETY: the caller supplies the GlobalAlloc layout contract unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller supplies the matching live System allocation.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNT.load(Relaxed) {
            REALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(size as u64, Relaxed);
        }
        // SAFETY: the caller supplies the live allocation and valid new size.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn set_read_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    if fd < 0 {
        return Ok(());
    }
    if COUNT.load(Relaxed) {
        TIMEOUTS.fetch_add(1, Relaxed);
    }
    // SAFETY: main owns the live socket; this temporary borrow never closes it.
    let socket = std::mem::ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(fd) });
    socket.set_read_timeout(Some(timeout))
}

struct Discard;
impl Read for Discard {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl Write for Discard {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        black_box(data);
        if COUNT.load(Relaxed) {
            WRITES.fetch_add(1, Relaxed);
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn measure(name: &str, n: u64, filter: &str, mut run: impl FnMut()) {
    if !name.contains(filter) {
        return;
    }
    for _ in 0..100 {
        run();
    }
    let start = Instant::now();
    for _ in 0..n {
        run();
    }
    let ns = start.elapsed().as_nanos() as f64 / n as f64;
    for counter in [&ALLOCS, &REALLOCS, &BYTES, &TIMEOUTS, &WRITES] {
        counter.store(0, Relaxed);
    }
    COUNT.store(true, Relaxed);
    run();
    COUNT.store(false, Relaxed);
    println!(
        "{name},{n},{ns:.2},{},{},{},{},{}",
        ALLOCS.load(Relaxed), REALLOCS.load(Relaxed), BYTES.load(Relaxed),
        TIMEOUTS.load(Relaxed), WRITES.load(Relaxed)
    );
}

const REQUEST: &[u8] = b"GET /static.dat HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n";

fn parse(input: &mut BufReader<Cursor<&[u8]>>, fd: Option<RawFd>) -> http::Request {
    assert!(input.buffer().is_empty());
    input.get_mut().set_position(0);
    let deadline = fd.map(|fd| http::HeadDeadline::new(fd, Duration::from_secs(30)));
    match http::read_request(input, true, deadline.as_ref()).unwrap() {
        http::ParseOutcome::Request(request) => request,
        _ => panic!("profile request rejected"),
    }
}

fn lookup(root: &str) -> Box<files::PathInfo> {
    match files::lookup(black_box(root), black_box("/static.dat"), false, &[]) {
        files::Lookup::Found(pi) => pi,
        _ => panic!("profile file not found"),
    }
}

fn serve(client: &RefCell<BufReader<Discard>>, request: &http::Request, pi: &files::PathInfo) {
    let mut output = http::Out::new(client, -1, 16384, Duration::from_secs(30));
    serve_to(&mut output, request, pi);
}

fn serve_to(output: &mut http::Out<'_, Discard>, request: &http::Request, pi: &files::PathInfo) {
    let mut response = http::Response::new(output, request, 20);
    files::serve(request, &mut response, pi, false, "UTF-8").unwrap();
    output.finish_request().unwrap();
}

fn profile_rpc(n: u64, filter: &str, fixture: &str) -> io::Result<()> {
    let body = std::fs::read(fixture)?;
    let mut head = BufReader::new(Cursor::new(REQUEST));
    let mut request = parse(&mut head, None);
    request.method = http::Method::Post;
    request.url = "/ubus".into();
    request.content_length = Some(body.len());
    let bridge = bridge::Bridge {
        socket: None, noauth: false, cors: false, timeout_ms: 30000,
        events_retry: 1000, record_calls: false, idle: Mutex::new(Vec::new()),
        calls: Mutex::new(Vec::new()),
    };
    // Validate a real authorized call before profiling. Never print the session
    // fixture; this mode runs with the exact image's disposable ubusd/rpcd.
    let recorded = RefCell::new(BufReader::new(Cursor::new(Vec::new())));
    {
        let mut out = http::Out::new(&recorded, -1, 16384, Duration::from_secs(30));
        let mut response = http::Response::new(&mut out, &request, 20);
        bridge::handle(&bridge, "/ubus", &request, Some(&body), &mut response)?;
        out.finish_request()?;
    }
    let bytes = recorded.borrow();
    let expected = b"\"result\":[0,{\"configs\":";
    assert!(bytes.get_ref().get_ref().windows(expected.len()).any(|part| part == expected),
            "RPC profiling fixture did not produce a successful UCI result");
    drop(bytes);
    let input = RefCell::new(BufReader::new(Cursor::new(body.as_slice())));
    measure("rpc_body_collect", n, filter, || {
        assert!(input.borrow().buffer().is_empty());
        input.borrow_mut().get_mut().set_position(0);
        let mut reader = http::BodyReader::new(&input, &request);
        black_box(reader.read_all(bridge::MAX_POST + 1).unwrap().unwrap());
        assert!(reader.reusable());
    });
    measure("rpc_json_parse", n, filter, || {
        black_box(owrt_ubus::json::parse_prefix_bytes(black_box(&body)).unwrap());
    });
    let client = RefCell::new(BufReader::new(Discard));
    let mut out = http::Out::new(&client, -1, 16384, Duration::from_secs(30));
    measure("rpc_handle_reused", n, filter, || {
        let mut response = http::Response::new(&mut out, &request, 20);
        bridge::handle(&bridge, "/ubus", &request, Some(&body), &mut response).unwrap();
        out.finish_request().unwrap();
    });
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let n: u64 = args.get(1).map(|s| s.parse().expect("iterations")).unwrap_or(20000);
    assert!(n > 0);
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes,timeout_syscalls,transport_writes");
    if let Some(fixture) = args.get(3) {
        return profile_rpc(n, filter, fixture);
    }
    let root = format!("/tmp/owrt-httpd-profile-{}", std::process::id());
    std::fs::create_dir(&root)?;
    std::fs::write(format!("{root}/static.dat"), [0u8; 16384])?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let socket = TcpStream::connect(listener.local_addr()?)?;
    let (_peer, _) = listener.accept()?;
    let client = RefCell::new(BufReader::new(Discard));
    let mut input = BufReader::new(Cursor::new(black_box(REQUEST)));
    let request = parse(&mut input, None);
    let pi = lookup(&root);
    for (name, path) in [
        ("mime_dat", "/static.dat"),
        ("mime_css", "/luci-static/bootstrap/cascade.css"),
        ("mime_html", "/index.html"),
        ("mime_tar_gz", "/archive.tar.gz"),
    ] {
        measure(name, n, filter, || { black_box(files::mime_type(black_box(path))); });
    }
    measure("parse_buffered", n, filter, || { black_box(parse(&mut input, None)); });
    measure("parse_buffered_deadline", n, filter, || { black_box(parse(&mut input, Some(socket.as_raw_fd()))); });
    measure("lookup", n, filter, || { black_box(lookup(&root)); });
    measure("date", n, filter, || { black_box(http::http_date(black_box(1789038000))); });
    measure("serve_static", n, filter, || serve(&client, &request, &pi));
    measure("lookup_serve_static", n, filter, || serve(&client, &request, &lookup(&root)));
    measure("parse_lookup_serve_static", n, filter, || {
        serve(&client, &parse(&mut input, Some(socket.as_raw_fd())), &lookup(&root));
    });
    let mut output = http::Out::new(&client, -1, 16384, Duration::from_secs(30));
    measure("serve_static_reused", n, filter, || serve_to(&mut output, &request, &pi));
    measure("parse_lookup_serve_static_reused", n, filter, || {
        serve_to(&mut output, &parse(&mut input, Some(socket.as_raw_fd())), &lookup(&root));
    });
    let mut heads = http::HeadBuffer::default();
    measure("parse_reused_deadline", n, filter, || {
        assert!(input.buffer().is_empty());
        input.get_mut().set_position(0);
        let deadline = http::HeadDeadline::new(socket.as_raw_fd(), Duration::from_secs(30));
        let http::ParseOutcome::Request(request) = heads.read_request(&mut input, true, Some(&deadline)).unwrap() else {
            panic!("profile request rejected")
        };
        heads.recycle(black_box(request));
    });
    measure("parse_reused_lookup_serve_static_reused", n, filter, || {
        assert!(input.buffer().is_empty());
        input.get_mut().set_position(0);
        let deadline = http::HeadDeadline::new(socket.as_raw_fd(), Duration::from_secs(30));
        let http::ParseOutcome::Request(request) = heads.read_request(&mut input, true, Some(&deadline)).unwrap() else {
            panic!("profile request rejected")
        };
        serve_to(&mut output, &request, &lookup(&root));
        heads.recycle(request);
    });
    std::fs::remove_dir_all(root)?;
    Ok(())
}
