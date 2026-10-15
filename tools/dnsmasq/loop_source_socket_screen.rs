//! Counts the actual library factory and validates its externally relevant flags.
use dnsmasq_rs::dns::forward::Random;
use dnsmasq_rs::dns::upstream::source_sockets::{udp, SocketSettings, SourceSpec};
use std::io;
use std::os::fd::AsRawFd;

struct Counter(u32);
impl Random for Counter {
    fn next_u32(&mut self) -> io::Result<u32> {
        self.0 += 1;
        Ok(self.0)
    }
}
unsafe extern "C" { fn fcntl(fd: i32, command: i32, ...) -> i32; }
/* ALLOCATION_METER */

fn receive_screen(case: &str, count: usize, burst: usize) {
    use dnsmasq_rs::config::dns::DnsConfig;
    use dnsmasq_rs::listeners::{self, DnsSocket};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;
    unsafe extern "C" {
        fn getsockopt(fd: i32, level: i32, option: i32, value: *mut i32, length: *mut u32) -> i32;
    }
    assert!(matches!(case, "receive-bound4" | "receive-generic4"));
    assert!(matches!(burst, 1 | 16));
    let initial_fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let interfaces = listeners::snapshot().unwrap();
    let config = DnsConfig { bind_interfaces: true, ..Default::default() };
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let before_bind = allocation_counts();
    let server = if case == "receive-bound4" {
        /* DNS_RECEIVE_BIND */
    } else { DnsSocket::bind(address).unwrap() };
    let after_bind = allocation_counts();
    let bind_counts: [u64; 3] = std::array::from_fn(|i| after_bind[i] - before_bind[i]);
    let target = server.local_addr().unwrap();
    let (mut pktinfo, mut length) = (-1_i32, 4_u32);
    // SAFETY: a live borrowed socket and initialized native-int storage.
    assert_eq!(unsafe { getsockopt(server.as_raw_fd(), 0, 8, &mut pktinfo, &mut length) }, 0);
    assert_eq!(pktinfo, if case == "receive-bound4" && /* CONFIGURED_BIND */ { 0 } else { 1 });
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let peer = sender.local_addr().unwrap();
    let query = [7_u8; 32];
    let mut buffer = [0_u8; 65_535];
    let mut answer = [0_u8; 32];
    let mut received = 0_usize;
    let mut would_block = 0_usize;
    let mut receive_calls = 0_usize;
    eprintln!("SOCKET_RECEIVE_LOOP_BEGIN");
    let before = allocation_counts();
    for _ in 0..count {
        for _ in 0..burst { assert_eq!(sender.send_to(&query, target).unwrap(), query.len()); }
        // Preserve the existing 16-packet budget, including terminal EAGAIN
        // for one-packet bursts and no speculative receive after a full batch.
        for _ in 0..16 {
            receive_calls += 1;
            let incoming = match server.receive(&mut buffer) {
                Ok(Some(incoming)) => incoming,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    would_block += 1;
                    break;
                }
                result => panic!("unexpected receive result: {}", result.is_ok()),
            };
            assert_eq!(incoming.peer, peer);
            assert_eq!(incoming.destination, IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(incoming.interface == 0, pktinfo == 0);
            assert_eq!(&buffer[..incoming.len], &query);
            server.send(&buffer[..incoming.len], incoming.peer, None).unwrap();
            received += 1;
        }
        for _ in 0..burst {
            let (size, source) = sender.recv_from(&mut answer).unwrap();
            assert_eq!(source, target);
            assert_eq!(&answer[..size], &query);
        }
    }
    let after = allocation_counts();
    eprintln!("SOCKET_RECEIVE_LOOP_END");
    let loop_counts: [u64; 3] = std::array::from_fn(|i| after[i] - before[i]);
    assert_eq!(received, count * burst);
    assert_eq!(would_block, if burst == 1 { count } else { 0 });
    assert_eq!(receive_calls, count * (burst + usize::from(burst == 1)));
    drop(server);
    drop(sender);
    let final_fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
    assert_eq!(initial_fds, final_fds);
    println!("{{\"case\":\"{case}\",\"iterations\":{count},\"burst\":{burst},\"packets\":{received},\"receive_calls\":{receive_calls},\"would_block\":{would_block},\"pktinfo_enabled\":{pktinfo},\"payload_bytes\":32,\"scratch_bytes\":65535,\"bind_alloc_realloc_bytes\":{bind_counts:?},\"loop_alloc_realloc_bytes\":{loop_counts:?},\"fds_before\":{initial_fds},\"fds_after\":{final_fds}}}");
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let case = &args[1];
    let count: usize = args[2].parse().unwrap();
    assert!(count > 0 && count <= 10000);
    if case.starts_with("receive-") {
        receive_screen(case, count, args[3].parse().unwrap());
        return;
    }
    let ipv6 = case.ends_with('6');
    let mut source = SourceSpec::wildcard(
        if ipv6 { "[::1]:53" } else { "127.0.0.1:53" }.parse().unwrap(), 0);
    let mut settings = SocketSettings::default();
    if case.starts_with("bound") {
        source.address.set_ip(if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap());
    } else if case == "range4" || case == "invalid4" {
        settings.min_port = 60000;
        settings.max_port = if case == "range4" { 60001 } else { 59000 };
    } else {
        assert!(case == "wild4" || case == "wild6");
    }
    let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let mut random = Counter(0);
    for _ in 0..count {
        let result = udp(&source, settings, &mut random);
        if case == "invalid4" {
            let error = result.unwrap_err();
            assert_eq!(error.error.kind(), io::ErrorKind::InvalidInput);
            assert!(!error.binding);
            continue;
        }
        let socket = result.unwrap();
        // SAFETY: queries inspect the newly owned live fd, no mutation.
        let status = unsafe { fcntl(socket.as_raw_fd(), 3) };
        let descriptor = unsafe { fcntl(socket.as_raw_fd(), 1) };
        assert!(status >= 0 && status & 0o4000 != 0);
        assert!(descriptor >= 0 && descriptor & 1 != 0);
        let actual = socket.local_addr().unwrap();
        assert_eq!(actual.ip(), source.address.ip());
        if case == "range4" { assert!((60000..=60001).contains(&actual.port())); }
        else if case.starts_with("bound") { assert_ne!(actual.port(), 0); }
        else { assert_eq!(actual.port(), 0); }
        assert_eq!(socket.recv_from(&mut [0; 1]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
    let after = std::fs::read_dir("/proc/self/fd").unwrap().count();
    assert_eq!(before, after);
    assert_eq!(random.0 as usize, if case == "range4" { count } else { 0 });
    println!("{{\"case\":\"{case}\",\"calls\":{count},\"fds_before\":{before},\"fds_after\":{after},\"random_calls\":{}}}", random.0);
}
