use super::*;

fn parse(heads: &mut HeadBuffer, raw: &[u8]) -> Request {
    let mut reader = BufReader::new(io::Cursor::new(raw));
    let ParseOutcome::Request(request) = heads.read_request(&mut reader, true, None).unwrap() else {
        panic!("valid request rejected")
    };
    request
}

fn prime(heads: &mut HeadBuffer) -> (*const u8, *const (Cow<'static, str>, String)) {
    let first = parse(heads, b"POST /first-with-room HTTP/1.1\r\nHost: old\r\nAuthorization: Bearer private\r\nContent-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n");
    let storage = (first.url.as_ptr(), first.headers.as_ptr());
    heads.recycle(first);
    storage
}

fn storage(heads: &HeadBuffer) -> (*const u8, *const (Cow<'static, str>, String)) {
    let request = heads.spare.as_ref().expect("idle discarded parser capacity");
    (request.url.as_ptr(), request.headers.as_ptr())
}

struct Quiet;
impl Read for Quiet {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

#[test]
fn idle_keeps_capacity_then_new_transport_resets_credentials_and_framing() {
    let mut heads = HeadBuffer::default();
    let old_storage = prime(&mut heads);
    let retained = heads.retained_bytes();
    let deadline = HeadDeadline::new(-1, Duration::from_secs(10))
        .with_linger(Duration::from_millis(50));
    let mut quiet = BufReader::new(Quiet);
    for _ in 0..3 {
        assert!(matches!(heads.read_request(&mut quiet, true, Some(&deadline)).unwrap(), ParseOutcome::Idle));
        heads.trim();
        assert_eq!(storage(&heads), old_storage);
        assert_eq!(heads.retained_bytes(), retained);
    }
    // A different transport starts a different connection. No old credentials,
    // body framing, request target, or connection-close state may carry over.
    let second = parse(&mut heads, b"GET /next HTTP/1.1\r\nHost: new\r\n\r\n");
    assert_eq!((second.url.as_ptr(), second.headers.as_ptr()), old_storage);
    assert_eq!(second.url, "/next");
    assert_eq!(second.header("host"), Some("new"));
    assert_eq!(second.headers.len(), 1);
    assert_eq!(second.header("authorization"), None);
    assert_eq!(second.content_length, None);
    assert!(!second.expect_continue && !second.transfer_chunked && !second.connection_close);
}

#[test]
fn preserved_spare_never_bypasses_expired_deadline_or_bad_input() {
    let mut heads = HeadBuffer::default();
    let original = prime(&mut heads);
    let mut quiet = BufReader::new(Quiet);
    let deadline = HeadDeadline::until(-1, Instant::now() - Duration::from_secs(1))
        .with_linger(Duration::from_millis(50));
    assert_eq!(heads.read_request(&mut quiet, true, Some(&deadline)).err().unwrap().kind(), io::ErrorKind::TimedOut);
    assert_eq!(storage(&heads), original);
    let mut malformed = BufReader::new(io::Cursor::new(b"NOT HTTP\r\n"));
    assert!(matches!(heads.read_request(&mut malformed, true, None).unwrap(), ParseOutcome::Bad { code: 400, .. }));
    assert_eq!(storage(&heads), original);
    let mut closed = BufReader::new(io::empty());
    assert!(matches!(heads.read_request(&mut closed, true, None).unwrap(), ParseOutcome::Eof));
    assert_eq!(storage(&heads), original);
    let request = parse(&mut heads, b"GET / HTTP/1.0\r\n\r\n");
    assert!(request.connection_close);
    assert_eq!(request.headers.len(), 0);
    assert_eq!(request.content_length, None);
}

#[test]
fn idle_trim_bounds_old_spare_plus_failed_request_line_capacity() {
    let mut heads = HeadBuffer::default();
    let request = parse(&mut heads, format!("GET / HTTP/1.1\r\nX-One: {}\r\nX-Two: {}\r\n\r\n", "a".repeat(2000), "b".repeat(2000)).as_bytes());
    heads.recycle(request);
    assert!(heads.spare.is_some());
    // A bad new first line leaves the old spare intact while growing line.
    let malformed = format!("INVALID {}\r\n", "b".repeat(4000));
    let mut reader = BufReader::new(io::Cursor::new(malformed.as_bytes()));
    assert!(matches!(heads.read_request(&mut reader, true, None).unwrap(), ParseOutcome::Bad { .. }));
    assert!(heads.retained_bytes() > 8192, "fixture must exceed the idle cache budget");
    heads.trim();
    assert_eq!(heads.retained_bytes(), 0);
    let request = parse(&mut heads, format!("GET / HTTP/1.1\r\nX-One: {}\r\nX-Two: {}\r\n\r\n", "a".repeat(4000), "b".repeat(4000)).as_bytes());
    assert_eq!(request.header("x-two").unwrap().len(), 4000);
    heads.recycle(request);
    assert_eq!(heads.retained_bytes(), 0);
    let request = parse(&mut heads, b"GET /small HTTP/1.1\r\n\r\n");
    assert_eq!(request.url, "/small");
    assert!(request.headers.is_empty());
}

#[test]
fn cached_parser_does_not_steal_body_or_next_pipelined_head() {
    let mut heads = HeadBuffer::default();
    prime(&mut heads);
    let raw = b"POST /one HTTP/1.1\r\nContent-Length: 4\r\n\r\nbodyGET /two HTTP/1.1\r\n\r\n";
    let mut reader = BufReader::with_capacity(17, io::Cursor::new(raw));
    let ParseOutcome::Request(first) = heads.read_request(&mut reader, true, None).unwrap() else { panic!() };
    assert_eq!(first.content_length, Some(4));
    assert_eq!(first.header("authorization"), None);
    let mut body = [0; 4];
    reader.read_exact(&mut body).unwrap();
    assert_eq!(&body, b"body");
    heads.recycle(first);
    let ParseOutcome::Request(second) = heads.read_request(&mut reader, true, None).unwrap() else { panic!() };
    assert_eq!(second.url, "/two");
    assert_eq!(second.content_length, None);
    assert!(second.headers.is_empty());
}
