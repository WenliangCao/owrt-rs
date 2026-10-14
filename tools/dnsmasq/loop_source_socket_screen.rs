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
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let case = &args[1];
    let count: usize = args[2].parse().unwrap();
    assert!(count > 0 && count <= 10000);
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
