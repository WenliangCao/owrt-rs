//! Bounded construction of a new bus transport. Existing connections are
//! never touched when admission or the initial HELLO fails.
use std::io;
use std::os::unix::net::UnixStream;
use std::time::Instant;

pub(crate) fn stream(
    path: &str,
    deadline: Instant,
    cancelled: Option<fn() -> bool>,
) -> io::Result<UnixStream> {
    #[cfg(target_os = "linux")]
    {
        linux::stream(path, deadline, cancelled)
    }
    // The client targets Linux. Preserve the existing host-only transport
    // behavior; its HELLO read still uses the shared absolute deadline.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = deadline;
        crate::sys::check_cancelled(cancelled)?;
        UnixStream::connect(path)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::fd::AsRawFd;
    use rustix::net;
    use std::time::Duration;
    use crate::sys::{PollFd, POLLOUT};

    fn remaining(deadline: Instant, cancelled: Option<fn() -> bool>) -> io::Result<Duration> {
        crate::sys::check_cancelled(cancelled)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "ubus connect deadline elapsed"))
        } else { Ok(remaining) }
    }

    pub(super) fn stream(
        path: &str,
        deadline: Instant,
        cancelled: Option<fn() -> bool>,
    ) -> io::Result<UnixStream> {
        if path.as_bytes().contains(&0) || path.len() >= 108 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid unix socket path"));
        }
        let address = net::SocketAddrUnix::new(path)?;
        let socket = net::socket_with(net::AddressFamily::UNIX, net::SocketType::STREAM,
            net::SocketFlags::NONBLOCK | net::SocketFlags::CLOEXEC, None)?;
        loop {
            remaining(deadline, cancelled)?;
            let error = match net::connect(&socket, &address) {
                Ok(()) => break,
                Err(error) => io::Error::from(error),
            };
            match error.raw_os_error() {
                Some(4) => continue, // EINTR
                Some(11) => {
                    // AF_UNIX returns EAGAIN for a full accept backlog. It has
                    // not started connecting: POLLOUT alone is not success.
                    std::thread::sleep(
                        remaining(deadline, cancelled)?.min(Duration::from_millis(1)),
                    );
                }
                Some(115) | Some(114) => { // EINPROGRESS / EALREADY
                    let mut fd = PollFd { fd: socket.as_raw_fd(), events: POLLOUT, revents: 0 };
                    loop {
                        let mut timeout = remaining(deadline, cancelled)?
                            .as_millis()
                            .clamp(1, i32::MAX as u128)
                            as i32;
                        if cancelled.is_some() {
                            timeout = timeout.min(10);
                        }
                        match owrt_platform::unix::poll_once(std::slice::from_mut(&mut fd), timeout) {
                            Ok(0) => continue,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) => return Err(error),
                            _ => (),
                        }
                        net::sockopt::socket_error(&socket)??;
                        break;
                    }
                    break;
                }
                Some(106) => break, // EISCONN after an interrupted connect
                _ => return Err(error),
            }
        }
        let stream = UnixStream::from(socket);
        stream.set_nonblocking(false)?;
        Ok(stream)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{Connection, Header, BlobBuf, ty};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture { path: PathBuf, listener: UnixListener }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("r93-connect-{}-{}.sock", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            Self { listener: UnixListener::bind(&path).unwrap(), path }
        }
        fn path(&self) -> &str { self.path.to_str().unwrap() }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = std::fs::remove_file(&self.path); }
    }

    fn hello() -> Vec<u8> {
        let mut wire = Header { ty: ty::HELLO, seq: 0, peer: 1234 }.encode().to_vec();
        wire.extend_from_slice(BlobBuf::new().as_bytes());
        wire
    }

    #[test]
    fn cancellation_interrupts_hello_prefixes_and_full_backlog() {
        use std::sync::atomic::AtomicBool;
        static CANCEL: AtomicBool = AtomicBool::new(false);
        fn cancelled() -> bool {
            CANCEL.load(Ordering::Relaxed)
        }
        for prefix in [0, 1, 12] {
            CANCEL.store(false, Ordering::Relaxed);
            let fixture = Fixture::new();
            let listener = fixture.listener.try_clone().unwrap();
            let peer = std::thread::spawn(move || {
                let (mut accepted, _) = listener.accept().unwrap();
                let mut blob = BlobBuf::new();
                blob.put_u32(crate::attr::STATUS, 0);
                let mut wire = Header {
                    ty: ty::HELLO,
                    seq: 0,
                    peer: 1234,
                }
                .encode()
                .to_vec();
                wire.extend_from_slice(blob.as_bytes());
                accepted.write_all(&wire[..prefix]).unwrap();
                std::thread::sleep(Duration::from_millis(20));
                CANCEL.store(true, Ordering::Relaxed);
                accepted
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                assert_eq!(accepted.read(&mut [0]).unwrap(), 0);
            });
            let start = Instant::now();
            let error = Connection::connect_interruptible(
                Some(fixture.path()),
                start + Duration::from_secs(2),
                cancelled,
            )
            .err()
            .expect("HELLO must be cancelled");
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(start.elapsed() < Duration::from_millis(300));
            peer.join().unwrap();
        }
        CANCEL.store(false, Ordering::Relaxed);
        let fixture = Fixture::new();
        rustix::net::listen(&fixture.listener, 0).unwrap();
        let filler = UnixStream::connect(fixture.path()).unwrap();
        let cancel = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
            CANCEL.store(true, Ordering::Relaxed);
        });
        let start = Instant::now();
        let error = Connection::connect_interruptible(
            Some(fixture.path()),
            start + Duration::from_secs(2),
            cancelled,
        )
        .err()
        .expect("admission must be cancelled");
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(start.elapsed() < Duration::from_millis(300));
        cancel.join().unwrap();
        drop(filler);
    }

    #[test]
    fn hello_deadline_bounds_absent_partial_header_and_partial_body() {
        for prefix in [0, 1, 12] {
            let fixture = Fixture::new();
            let listener = fixture.listener.try_clone().unwrap();
            let peer = std::thread::spawn(move || {
                let (mut accepted, _) = listener.accept().unwrap();
                let mut blob = BlobBuf::new();
                blob.put_u32(crate::attr::STATUS, 0);
                let mut wire = Header { ty: ty::HELLO, seq: 0, peer: 1234 }.encode().to_vec();
                wire.extend_from_slice(blob.as_bytes());
                accepted.write_all(&wire[..prefix]).unwrap();
                // The timed-out constructor owns no live connection after
                // returning: the accepted peer must see EOF without cleanup.
                accepted.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
                assert_eq!(accepted.read(&mut [0]).unwrap(), 0);
            });
            let started = Instant::now();
            let error = Connection::connect_timeout(Some(fixture.path()), Duration::from_millis(30))
                .err().expect("HELLO must time out");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(started.elapsed() < Duration::from_millis(200));
            peer.join().unwrap();
        }
    }

    #[test]
    fn fragmented_hello_succeeds_and_normal_socket_errors_are_preserved() {
        let fixture = Fixture::new();
        let listener = fixture.listener.try_clone().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut accepted, _) = listener.accept().unwrap();
            for part in hello().chunks(3) {
                accepted.write_all(part).unwrap();
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        let connection = Connection::connect_timeout(Some(fixture.path()), Duration::from_millis(200)).unwrap();
        assert_eq!(connection.local_id(), 1234);
        peer.join().unwrap();
        assert_eq!(Connection::connect_timeout(Some(fixture.path()), Duration::ZERO).err().unwrap().kind(), io::ErrorKind::TimedOut);
        assert_eq!(Connection::connect(Some("invalid\0path")).err().unwrap().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(Connection::connect(Some(&"x".repeat(108))).err().unwrap().kind(), io::ErrorKind::InvalidInput);
        let missing = fixture.path.with_extension("missing");
        assert_eq!(Connection::connect(Some(missing.to_str().unwrap())).err().unwrap().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn full_backlog_times_out_and_recovers_with_the_same_total_budget() {
        let fixture = Fixture::new();
        rustix::net::listen(&fixture.listener, 0).unwrap();
        let filler = UnixStream::connect(fixture.path()).unwrap();
        let started = Instant::now();
        let error = Connection::connect_timeout(Some(fixture.path()), Duration::from_millis(30))
            .err().expect("full backlog must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(200));
        // Free the backlog while another connect is retrying, then send a
        // fragmented HELLO. Admission and HELLO share its original deadline.
        let listener = fixture.listener.try_clone().unwrap();
        let peer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(listener.accept().unwrap());
            let (mut accepted, _) = listener.accept().unwrap();
            accepted.write_all(&hello()).unwrap();
        });
        assert_eq!(Connection::connect_timeout(Some(fixture.path()), Duration::from_millis(200)).unwrap().local_id(), 1234);
        peer.join().unwrap();
        drop(filler);

        // Admission time must count against HELLO's budget. A fresh HELLO
        // deadline after connect would incorrectly accept this delayed reply.
        let filler = UnixStream::connect(fixture.path()).unwrap();
        let listener = fixture.listener.try_clone().unwrap();
        let peer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            drop(listener.accept().unwrap());
            let (mut accepted, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let _ = accepted.write_all(&hello());
        });
        let error = Connection::connect_timeout(Some(fixture.path()), Duration::from_millis(60))
            .err().expect("HELLO must share admission's deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        peer.join().unwrap();
        drop(filler);
    }
}
