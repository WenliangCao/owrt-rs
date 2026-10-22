//! Bounded ubus I/O and deadline policy over rustix and the shared ABI boundary.

use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::time::Instant;

#[derive(Debug)]
struct PartialTimeout;
impl std::fmt::Display for PartialTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ubus deadline elapsed inside a frame")
    }
}
impl std::error::Error for PartialTimeout {}

pub(crate) fn partial_timeout(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::TimedOut {
        io::Error::new(io::ErrorKind::TimedOut, PartialTimeout)
    } else {
        error
    }
}

pub(crate) fn is_partial_timeout(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<PartialTimeout>())
}

pub(crate) fn after_progress(error: io::Error, started: bool) -> io::Error {
    if started {
        partial_timeout(error)
    } else {
        error
    }
}

/// How long an I/O primitive may wait. `Within` starts its budget at the
/// first wait, so a call that never blocks never reads the clock.
#[derive(Clone, Copy)]
pub(crate) enum Bound {
    Forever,
    At(Instant),
    Within(std::time::Duration),
}

impl From<Option<Instant>> for Bound {
    fn from(deadline: Option<Instant>) -> Self {
        deadline.map_or(Bound::Forever, Bound::At)
    }
}

impl Bound {
    pub(crate) fn nonblocking(self) -> bool {
        !matches!(self, Bound::Forever)
    }

    /// The deadline to wait against; a budget is fixed the first time.
    pub(crate) fn deadline(self, fixed: &mut Option<Instant>) -> Option<Instant> {
        match self {
            Bound::Forever => None,
            Bound::At(deadline) => Some(deadline),
            Bound::Within(budget) => Some(*fixed.get_or_insert_with(|| Instant::now() + budget)),
        }
    }
}

pub use owrt_platform::unix::{drop_privileges, poll_fds, set_nonblocking, PollFd};
pub const POLLIN: i16 = 0x001;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;
pub const SIGPIPE: i32 = 13;
pub const SIGTERM: i32 = 15;
pub const SIGINT: i32 = 2;
pub fn ignore_signal(signum: i32) {
    let _ = owrt_platform::unix::ignore_signal(signum);
}
#[doc(inline)]
pub use owrt_platform::unix::set_signal_handler;

/// Send `header` followed by `body` on a unix socket, optionally attaching `fd`
/// as SCM_RIGHTS on the first chunk. Retries on partial writes and EINTR/EAGAIN.
pub fn send_with_fd(sock: RawFd, header: &[u8], body: &[u8], fd: Option<RawFd>) -> io::Result<()> {
    send_parts(sock, [header, body], fd)
}

/// Send fixed borrowed pieces without collecting them into a second buffer.
pub(crate) fn send_parts<const N: usize>(
    sock: RawFd,
    parts: [&[u8]; N],
    fd: Option<RawFd>,
) -> io::Result<()> {
    send_parts_until(sock, parts, fd, Bound::Forever)
}

pub(crate) fn send_parts_until<const N: usize>(
    sock: RawFd,
    parts: [&[u8]; N],
    fd: Option<RawFd>,
    bound: Bound,
) -> io::Result<()> {
    send_parts_until_cancelled(sock, parts, fd, bound, None)
}

pub(crate) fn send_parts_until_cancelled<const N: usize>(
    sock: RawFd,
    parts: [&[u8]; N],
    fd: Option<RawFd>,
    bound: Bound,
    cancelled: Option<fn() -> bool>,
) -> io::Result<()> {
    let mut vectors = parts.map(std::io::IoSlice::new);
    let mut remaining = vectors.as_mut_slice();
    let mut attach = fd;
    let mut started = false;
    let mut deadline = if let Bound::At(deadline) = bound {
        Some(deadline)
    } else {
        None
    };
    while !remaining.is_empty() {
        check_cancelled(cancelled)?;
        check_deadline(deadline).map_err(|e| after_progress(e, started))?;
        let sent = match owrt_platform::ipc::send_slices(
            sock,
            remaining,
            attach,
            bound.nonblocking() || cancelled.is_some(),
        ) {
            Ok(sent) => sent,
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    wait_until_cancelled(sock, POLLOUT, bound.deadline(&mut deadline), cancelled)
                        .map_err(|e| after_progress(e, started))?;
                    continue;
                }
                _ => return Err(error),
            },
        };
        if sent == 0 && remaining.iter().any(|part| !part.is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "ubus send made no progress",
            ));
        }
        attach = None;
        started |= sent > 0;
        std::io::IoSlice::advance_slices(&mut remaining, sent);
    }
    Ok(())
}

/// Receive exactly `buf.len()` bytes; the first recvmsg may deliver one fd.
pub fn recv_exact(sock: RawFd, buf: &mut [u8], want_fd: bool) -> io::Result<Option<OwnedFd>> {
    recv_exact_until(sock, buf, want_fd, None)
}

pub(crate) fn recv_exact_until(
    sock: RawFd,
    buf: &mut [u8],
    want_fd: bool,
    deadline: Option<Instant>,
) -> io::Result<Option<OwnedFd>> {
    recv_exact_until_cancelled(sock, buf, want_fd, deadline, None)
}

pub(crate) fn recv_exact_until_cancelled(
    sock: RawFd,
    buf: &mut [u8],
    want_fd: bool,
    deadline: Option<Instant>,
    cancelled: Option<fn() -> bool>,
) -> io::Result<Option<OwnedFd>> {
    let mut received_fd = None;
    let mut offset = 0;
    let mut first = want_fd;
    while offset < buf.len() {
        check_cancelled(cancelled)?;
        check_deadline(deadline).map_err(|e| after_progress(e, offset > 0))?;
        match recv_into(
            sock,
            &mut buf[offset..],
            first,
            deadline.is_some() || cancelled.is_some(),
        ) {
            Ok((0, _)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ubus connection closed",
                ));
            }
            Ok((got, fd)) => {
                received_fd = received_fd.or(fd);
                first = false;
                offset += got;
            }
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    wait_until_cancelled(sock, POLLIN, deadline, cancelled)
                        .map_err(|e| after_progress(e, offset > 0))?;
                }
                _ => return Err(error),
            },
        }
    }
    Ok(received_fd)
}

/// One recvmsg into `buf`: bytes received (0 at end of stream) and any
/// SCM_RIGHTS descriptor that came with them. Errors are returned raw so the
/// caller decides how to retry EINTR and EAGAIN.
pub(crate) fn recv_into(
    sock: RawFd,
    buf: &mut [u8],
    want_fd: bool,
    nonblocking: bool,
) -> io::Result<(usize, Option<OwnedFd>)> {
    owrt_platform::ipc::recv_into(sock, buf, want_fd, nonblocking)
}

pub(crate) fn check_deadline(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "ubus I/O deadline elapsed",
        ));
    }
    Ok(())
}

pub(crate) fn check_cancelled(cancelled: Option<fn() -> bool>) -> io::Result<()> {
    if cancelled.is_some_and(|check| check()) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "ubus operation cancelled",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn wait_until_cancelled(
    fd: RawFd,
    events: i16,
    deadline: Option<Instant>,
    cancelled: Option<fn() -> bool>,
) -> io::Result<()> {
    let mut pfd = [PollFd {
        fd,
        events,
        revents: 0,
    }];
    if deadline.is_none() && cancelled.is_none() {
        return poll_fds(&mut pfd, -1).map(|_| ());
    }
    loop {
        check_cancelled(cancelled)?;
        check_deadline(deadline)?;
        let mut timeout = deadline
            .map(|end| {
                end.saturating_duration_since(Instant::now())
                    .as_millis()
                    .clamp(1, i32::MAX as u128) as i32
            })
            .unwrap_or(-1);
        if cancelled.is_some() {
            timeout = if timeout < 0 { 10 } else { timeout.min(10) };
        }
        match owrt_platform::unix::poll_once(&mut pfd, timeout) {
            Ok(ready) if ready > 0 => return Ok(()),
            Err(error) if error.kind() != io::ErrorKind::Interrupted => return Err(error),
            _ => (),
        }
    }
}

/// Wait until `fd` is readable or the timeout elapses. Returns false on timeout.
pub fn wait_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = [PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    }];
    Ok(poll_fds(&mut pfd, timeout_ms)? > 0)
}

pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?)
}
/// Create both ends nonblocking before either descriptor can be published.
pub fn nonblocking_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::pipe::pipe_with(
        rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
    )?)
}
/// Preserve the stream socketpair used for a complete logd backlog write.
pub fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn ordinary_pipe_keeps_blocking_ends() {
        let (reader, writer) = pipe().unwrap();
        for fd in [&reader, &writer] {
            let flags = rustix::fs::fcntl_getfl(fd).unwrap();
            assert!(!flags.contains(rustix::fs::OFlags::NONBLOCK));
        }
    }

    #[test]
    fn nonblocking_pipe_handles_empty_reads_and_full_writes() {
        let (reader, writer) = nonblocking_pipe().unwrap();
        for fd in [&reader, &writer] {
            let flags = rustix::fs::fcntl_getfl(fd).unwrap();
            assert!(flags.contains(rustix::fs::OFlags::NONBLOCK));
        }
        let mut reader = std::fs::File::from(reader);
        let mut writer = std::fs::File::from(writer);
        assert_eq!(
            reader.read(&mut [0; 64]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let bytes = [1; 4096];
        let mut written = 0;
        loop {
            match writer.write(&bytes) {
                Ok(count) => {
                    assert!(count > 0);
                    written += count;
                }
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    break;
                }
            }
            assert!(
                written < 2 * 1024 * 1024,
                "default pipe must reach backpressure"
            );
        }
        let mut drained = 0;
        loop {
            match reader.read(&mut [0; 64]) {
                Ok(count) => {
                    assert!(count > 0);
                    drained += count;
                }
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    break;
                }
            }
        }
        assert_eq!(drained, written);
    }

    #[test]
    fn body_without_ancillary_storage_closes_discarded_descriptor() {
        let (send, receive) = UnixStream::pair().unwrap();
        let (passed, mut watch) = UnixStream::pair().unwrap();
        send_with_fd(send.as_raw_fd(), b"bo", b"dy", Some(passed.as_raw_fd())).unwrap();
        drop(passed);
        let mut body = [0; 4];
        assert!(recv_exact(receive.as_raw_fd(), &mut body, false)
            .unwrap()
            .is_none());
        assert_eq!(&body, b"body");
        watch.set_nonblocking(true).unwrap();
        assert_eq!(
            watch.read(&mut [0]).unwrap(),
            0,
            "discarded SCM_RIGHTS must not leak"
        );

        let (passed, mut watch) = UnixStream::pair().unwrap();
        send_with_fd(send.as_raw_fd(), b"ne", b"xt", Some(passed.as_raw_fd())).unwrap();
        drop(passed);
        let fd = recv_exact(receive.as_raw_fd(), &mut body, true)
            .unwrap()
            .unwrap();
        assert_eq!(&body, b"next");
        let mut received = UnixStream::from(fd);
        received.write_all(b"x").unwrap();
        watch.read_exact(&mut [0]).unwrap();
    }

    #[test]
    fn nonblocking_fragments_keep_exact_boundaries_and_eof() {
        let (mut send, receive) = UnixStream::pair().unwrap();
        receive.set_nonblocking(true).unwrap();
        let producer = std::thread::spawn(move || {
            for part in [b"a".as_slice(), b"bc", b"defgh"] {
                send.write_all(part).unwrap();
                std::thread::yield_now();
            }
        });
        let mut first = [0; 3];
        recv_exact(receive.as_raw_fd(), &mut first, true).unwrap();
        assert_eq!(&first, b"abc");
        let mut body = [0; 5];
        recv_exact(receive.as_raw_fd(), &mut body, false).unwrap();
        assert_eq!(&body, b"defgh");
        producer.join().unwrap();
        assert_eq!(
            recv_exact(receive.as_raw_fd(), &mut [0], false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
