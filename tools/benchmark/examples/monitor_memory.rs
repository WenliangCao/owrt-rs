//! Isolated monitor residency probe, never a latency benchmark.
//! Usage: monitor_memory SOCKET DAEMON_PID sample|smoke
//! A missing-object INVOKE creates one large mirror and a small STATUS. This
//! avoids overflowing the monitor queue with two large PING mirror frames.
use owrt_ubus::blob::BlobBuf;
use owrt_ubus::msg::{attr, status, ty, Header, MAX_MSGLEN};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

const MONITOR: u32 = 3;
const MISSING: u32 = u32::MAX - 1;

struct Conn {
    stream: UnixStream,
    id: u32,
}

impl Conn {
    fn open(socket: &str) -> Self {
        let stream = UnixStream::connect(socket).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Self { stream, id: 0 };
        let (header, _) = conn.recv();
        assert_eq!(header.ty, ty::HELLO);
        assert_ne!(header.peer, 0);
        conn.id = header.peer;
        conn
    }

    fn send(&mut self, header: Header, body: &[u8]) {
        assert!(body.len() <= MAX_MSGLEN);
        self.stream.write_all(&header.encode()).unwrap();
        self.stream.write_all(body).unwrap();
    }

    fn recv(&mut self) -> (Header, Vec<u8>) {
        let mut prefix = [0; 12];
        self.stream
            .read_exact(&mut prefix)
            .expect("complete frame prefix");
        let header = Header::decode(prefix[..8].try_into().unwrap()).expect("valid header");
        let size = (u32::from_be_bytes(prefix[8..].try_into().unwrap()) & 0x00ff_ffff) as usize;
        assert!((4..=MAX_MSGLEN).contains(&size));
        let mut body = vec![0; size];
        body[..4].copy_from_slice(&prefix[8..]);
        self.stream
            .read_exact(&mut body[4..])
            .expect("complete body");
        (header, body)
    }

    fn expect_status(&mut self, seq: u16, code: i32) -> Vec<u8> {
        let (header, body) = self.recv();
        assert_eq!(
            header,
            Header {
                ty: ty::STATUS,
                seq,
                peer: 0
            }
        );
        let mut expected = BlobBuf::new();
        expected.put_u32(attr::STATUS, code as u32);
        assert_eq!(body, expected.as_bytes());
        body
    }
}

fn monitor_command(method: &str) -> Vec<u8> {
    let mut b = BlobBuf::new();
    b.put_u32(attr::OBJID, MONITOR);
    b.put_string(attr::METHOD, method);
    b.as_bytes().to_vec()
}

fn expect_mirror(
    monitor: &mut Conn,
    next: &mut u16,
    client: u32,
    original: Header,
    body: &[u8],
    send: bool,
) {
    let (header, actual) = monitor.recv();
    *next = next.wrapping_add(1);
    assert_eq!(
        header,
        Header {
            ty: ty::MONITOR,
            seq: *next,
            peer: 0
        }
    );
    let mut expected = BlobBuf::new();
    expected.put_u32(0, client);
    expected.put_u32(1, original.peer);
    expected.put_u32(3, original.seq as u32);
    expected.put_u32(4, original.ty as u32);
    expected.put_u8(2, u8::from(send));
    expected.put(5, &body[4..]);
    assert_eq!(
        actual,
        expected.as_bytes(),
        "complete monitor envelope and payload"
    );
}

fn missing_request(sender: &mut Conn, seq: u16, bytes: usize) -> (Header, Vec<u8>, Vec<u8>) {
    let payload: Vec<u8> = (0..bytes).map(|n| b'A' + (n % 23) as u8).collect();
    let mut data = BlobBuf::new();
    data.msg_string_bytes("bytes", &payload);
    let mut request = BlobBuf::new();
    request.put_u32(attr::OBJID, MISSING);
    request.put_string(attr::METHOD, "r142.memory");
    request.put(attr::DATA, data.payload());
    let body = request.as_bytes().to_vec();
    // Full monitor blob adds 44 bytes to the original blob, not just payload.
    assert!(body.len() + 44 <= MAX_MSGLEN);
    let header = Header {
        ty: ty::INVOKE,
        seq,
        peer: 0,
    };
    sender.send(header, &body);
    let reply = sender.expect_status(seq, status::NOT_FOUND);
    (header, body, reply)
}

fn fd_count(pid: u32) -> usize {
    fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .map(Result::unwrap)
        .count()
}

fn start_ticks(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap()
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_owned()
}

fn sample(
    pid: u32,
    identity: &str,
    phase: &str,
    bytes: usize,
    expected_fds: usize,
    smoke: bool,
    started: Instant,
) {
    for delay_ms in [1000u64, 5000] {
        if !smoke {
            thread::sleep(Duration::from_millis(if delay_ms == 1000 {
                1000
            } else {
                4000
            }));
        }
        assert_eq!(start_ticks(pid), identity, "daemon identity changed");
        assert_eq!(
            fd_count(pid),
            expected_fds,
            "daemon connection count differs"
        );
        let text = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let field = |key: &str| -> u64 {
            text.lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap()
        };
        assert_eq!(
            text.lines()
                .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
                .unwrap()
                .trim(),
            "1"
        );
        println!("{{\"phase\":\"{phase}\",\"payload_bytes\":{bytes},\"delay_ms\":{},\"elapsed_ms\":{},\"subject_pid\":{pid},\"start_ticks\":\"{identity}\",\"fds\":{expected_fds},\"rss_kib\":{},\"rssanon_kib\":{},\"vmdata_kib\":{},\"vmhwm_kib\":{}}}",
                 if smoke { 0 } else { delay_ms }, started.elapsed().as_millis(),
                 field("VmRSS:"), field("RssAnon:"), field("VmData:"), field("VmHWM:"));
        std::io::stdout().flush().unwrap();
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "monitor_memory SOCKET DAEMON_PID sample|smoke"
    );
    assert!(matches!(args[3].as_str(), "sample" | "smoke"));
    let own_status = fs::read_to_string("/proc/self/status").unwrap();
    assert_eq!(
        own_status
            .lines()
            .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
            .unwrap()
            .trim(),
        "0",
        "pin helper to CPU0 before launch"
    );
    let smoke = args[3] == "smoke";
    let pid: u32 = args[2].parse().unwrap();
    let identity = start_ticks(pid);
    let base_fds = fd_count(pid);
    let started = Instant::now();
    sample(pid, &identity, "empty", 0, base_fds, smoke, started);
    let mut sender = Conn::open(&args[1]);
    let mut monitor = Conn::open(&args[1]);
    // A STATUS barrier makes both accepted connections observable in /proc.
    let _ = missing_request(&mut sender, 1, 16);
    sample(pid, &identity, "connected", 0, base_fds + 2, smoke, started);
    let command = monitor_command("add");
    let header = Header {
        ty: ty::INVOKE,
        seq: 1,
        peer: 0,
    };
    monitor.send(header, &command);
    let mut next_monitor = 0;
    let mut ok = BlobBuf::new();
    ok.put_u32(attr::STATUS, status::OK as u32);
    let monitor_id = monitor.id;
    expect_mirror(
        &mut monitor,
        &mut next_monitor,
        monitor_id,
        Header {
            ty: ty::STATUS,
            ..header
        },
        ok.as_bytes(),
        true,
    );
    monitor.expect_status(1, status::OK);
    for (seq, (phase, bytes)) in [
        ("monitored_small", 16),
        ("large_32768", 32768),
        ("large_262144", 262144),
        ("large_786432", 786432),
    ]
    .into_iter()
    .enumerate()
    {
        let (header, body, reply) = missing_request(&mut sender, seq as u16 + 2, bytes);
        expect_mirror(
            &mut monitor,
            &mut next_monitor,
            sender.id,
            header,
            &body,
            false,
        );
        expect_mirror(
            &mut monitor,
            &mut next_monitor,
            sender.id,
            Header {
                ty: ty::STATUS,
                ..header
            },
            &reply,
            true,
        );
        sample(pid, &identity, phase, bytes, base_fds + 2, smoke, started);
    }
    let command = monitor_command("remove");
    let header = Header {
        ty: ty::INVOKE,
        seq: 2,
        peer: 0,
    };
    monitor.send(header, &command);
    expect_mirror(
        &mut monitor,
        &mut next_monitor,
        monitor_id,
        header,
        &command,
        false,
    );
    monitor.expect_status(2, status::OK);
    let _ = missing_request(&mut sender, 6, 16);
    monitor
        .stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut byte = [0];
    let error = monitor
        .stream
        .read(&mut byte)
        .expect_err("stopped monitor emitted data or closed");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    sample(
        pid,
        &identity,
        "stopped_connected",
        0,
        base_fds + 2,
        smoke,
        started,
    );
    drop(monitor);
    drop(sender);
    let deadline = Instant::now() + Duration::from_secs(5);
    while fd_count(pid) != base_fds {
        assert!(
            Instant::now() < deadline,
            "daemon retained closed connections"
        );
        thread::sleep(Duration::from_millis(5));
    }
    sample(pid, &identity, "disconnected", 0, base_fds, smoke, started);
    assert_eq!(next_monitor, 10);
    // Count and byte checks succeeded; snapshots are not latency or peak data.
    println!("{{\"phase\":\"COMPLETE\",\"full_mirror_bytes_checked\":true,\"mirror_frames\":10,\"subject_pid\":{pid},\"smoke\":{smoke}}}");
}
