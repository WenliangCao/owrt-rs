//! Hand-written Linux FFI for the few calls std does not expose:
//! sendmsg/recvmsg with SCM_RIGHTS, poll, pipe2, setuid/setgid.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
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
    } else { error }
}

pub(crate) fn is_partial_timeout(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<PartialTimeout>())
}

pub(crate) fn after_progress(error: io::Error, started: bool) -> io::Error {
    if started { partial_timeout(error) } else { error }
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

#[repr(C)]
pub struct IoVec {
    pub base: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct MsgHdr {
    pub name: *mut u8,
    pub namelen: u32,
    pub iov: *mut IoVec,
    pub iovlen: usize,
    pub control: *mut u8,
    pub controllen: usize,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

pub const POLLIN: i16 = 0x001;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;
pub const POLLHUP: i16 = 0x010;

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const CMSG_HDR: usize = 16; // sizeof(struct cmsghdr) on 64-bit Linux
const CMSG_SPACE_FD: usize = 24; // CMSG_SPACE(sizeof(int)) buffer size
const CMSG_LEN_FD: usize = 20; // CMSG_LEN(sizeof(int)); one fd, as libubus asks
const O_CLOEXEC: i32 = 0o2000000;
const MSG_DONTWAIT: i32 = 0x40;

extern "C" {
    fn sendmsg(fd: i32, msg: *const MsgHdr, flags: i32) -> isize;
    fn recvmsg(fd: i32, msg: *mut MsgHdr, flags: i32) -> isize;
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
    fn pipe2(fds: *mut i32, flags: i32) -> i32;
    #[link_name = "socketpair"]
    fn libc_socketpair(domain: i32, ty: i32, protocol: i32, fds: *mut i32) -> i32;
    fn setuid(uid: u32) -> i32;
    fn setgid(gid: u32) -> i32;
    fn signal(signum: i32, handler: usize) -> usize;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
}

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl(2) with F_GETFL takes no argument beyond the command and
    // only reads the caller's descriptor.
    let flags = unsafe { fcntl(fd, F_GETFL, 0) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL with the flags just read back, on the same descriptor.
    if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub const SIGPIPE: i32 = 13;
pub const SIGTERM: i32 = 15;
pub const SIGINT: i32 = 2;

pub fn ignore_signal(signum: i32) {
    // SAFETY: SIG_IGN (1) is a valid disposition for any catchable signal.
    unsafe {
        signal(signum, 1);
    }
}

pub fn set_signal_handler(signum: i32, handler: extern "C" fn(i32)) {
    // SAFETY: `handler` is an extern "C" fn(i32), which is the shape signal(2)
    // dispatches to. Keeping the handler async-signal-safe is the caller's job.
    unsafe {
        signal(signum, handler as usize);
    }
}

/// Send `header` followed by `body` on a unix socket, optionally attaching `fd`
/// as SCM_RIGHTS on the first chunk. Retries on partial writes and EINTR/EAGAIN.
pub fn send_with_fd(sock: RawFd, header: &[u8], body: &[u8], fd: Option<RawFd>) -> io::Result<()> {
    send_parts(sock, [header, body], fd)
}

/// Send fixed borrowed pieces without collecting them into a second buffer.
pub(crate) fn send_parts<const N: usize>(sock: RawFd, parts: [&[u8]; N], fd: Option<RawFd>) -> io::Result<()> {
    send_parts_until(sock, parts, fd, Bound::Forever)
}

pub(crate) fn send_parts_until<const N: usize>(sock: RawFd, parts: [&[u8]; N], fd: Option<RawFd>, bound: Bound) -> io::Result<()> {
    send_parts_until_cancelled(sock, parts, fd, bound, None)
}

pub(crate) fn send_parts_until_cancelled<const N: usize>(sock: RawFd, parts: [&[u8]; N], fd: Option<RawFd>, bound: Bound, cancelled: Option<fn() -> bool>) -> io::Result<()> {
    let mut iov = parts.map(|part| IoVec { base: part.as_ptr() as *mut u8, len: part.len() });
    let mut control = [0u8; CMSG_SPACE_FD];
    let mut attach = fd;
    let mut index = 0;
    let mut started = false;
    let mut deadline = if let Bound::At(deadline) = bound { Some(deadline) } else { None };
    while index < iov.len() {
        check_cancelled(cancelled)?;
        check_deadline(deadline).map_err(|e| after_progress(e, started))?;
        let mut hdr = MsgHdr {
            name: std::ptr::null_mut(),
            namelen: 0,
            iov: iov[index..].as_mut_ptr(),
            iovlen: iov.len() - index,
            control: std::ptr::null_mut(),
            controllen: 0,
            flags: 0,
        };
        if let Some(fd) = attach {
            // struct cmsghdr { size_t len; int level; int type; } + int fd
            control[..8].copy_from_slice(&(CMSG_HDR + 4).to_ne_bytes());
            control[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
            control[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
            control[16..20].copy_from_slice(&fd.to_ne_bytes());
            hdr.control = control.as_mut_ptr();
            hdr.controllen = CMSG_HDR + 4;
        }
        // SAFETY: hdr, the iovec array it points at and the control buffer all
        // outlive this call, and their lengths describe them.
        let sent = unsafe { sendmsg(sock, &hdr, if bound.nonblocking() { MSG_DONTWAIT } else { 0 }) };
        if sent < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    wait_until_cancelled(sock, POLLOUT, bound.deadline(&mut deadline), cancelled).map_err(|e| after_progress(e, started))?;
                    continue;
                }
                _ => return Err(error),
            }
        }
        if sent == 0 && iov[index..].iter().any(|part| part.len != 0) {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "ubus send made no progress"));
        }
        attach = None;
        started |= sent > 0;
        let mut remaining = sent as usize;
        while index < iov.len() && remaining >= iov[index].len {
            remaining -= iov[index].len;
            index += 1;
        }
        if index < iov.len() {
            // SAFETY: the loop above consumed every iovec fully covered by `sent`, so
            // `remaining` is strictly less than this entry's length and the advanced
            // pointer stays inside the same buffer.
            iov[index].base = unsafe { iov[index].base.add(remaining) };
            iov[index].len -= remaining;
        }
    }
    Ok(())
}

/// Receive exactly `buf.len()` bytes; the first recvmsg may deliver one fd.
pub fn recv_exact(sock: RawFd, buf: &mut [u8], want_fd: bool) -> io::Result<Option<OwnedFd>> {
    recv_exact_until(sock, buf, want_fd, None)
}

pub(crate) fn recv_exact_until(sock: RawFd, buf: &mut [u8], want_fd: bool, deadline: Option<Instant>) -> io::Result<Option<OwnedFd>> {
    recv_exact_until_cancelled(sock, buf, want_fd, deadline, None)
}

pub(crate) fn recv_exact_until_cancelled(sock: RawFd, buf: &mut [u8], want_fd: bool, deadline: Option<Instant>, cancelled: Option<fn() -> bool>) -> io::Result<Option<OwnedFd>> {
    let mut received_fd = None;
    let mut offset = 0;
    let mut first = want_fd;
    while offset < buf.len() {
        check_cancelled(cancelled)?;
        check_deadline(deadline).map_err(|e| after_progress(e, offset > 0))?;
        match recv_into(sock, &mut buf[offset..], first, deadline.is_some()) {
            Ok((0, _)) => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ubus connection closed"));
            }
            Ok((got, fd)) => {
                received_fd = received_fd.or(fd);
                first = false;
                offset += got;
            }
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    wait_until_cancelled(sock, POLLIN, deadline, cancelled).map_err(|e| after_progress(e, offset > 0))?;
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
pub(crate) fn recv_into(sock: RawFd, buf: &mut [u8], want_fd: bool, nonblocking: bool) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = IoVec { base: buf.as_mut_ptr(), len: buf.len() };
    let mut control = [0u8; CMSG_SPACE_FD];
    let mut hdr = MsgHdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &mut iov,
        iovlen: 1,
        control: if want_fd { control.as_mut_ptr() } else { std::ptr::null_mut() },
        controllen: if want_fd { CMSG_LEN_FD } else { 0 },
        flags: 0,
    };
    // SAFETY: hdr, its iovec and the control buffer are live for the call and
    // sized by the lengths hdr carries.
    let got = unsafe { recvmsg(sock, &mut hdr, if nonblocking { MSG_DONTWAIT } else { 0 }) };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fd = None;
    if want_fd && hdr.controllen >= CMSG_HDR + 4 {
        let level = i32::from_ne_bytes(control[8..12].try_into().unwrap());
        let kind = i32::from_ne_bytes(control[12..16].try_into().unwrap());
        if level == SOL_SOCKET && kind == SCM_RIGHTS {
            let raw = i32::from_ne_bytes(control[16..20].try_into().unwrap());
            if raw >= 0 {
                // SAFETY: the kernel installed this descriptor for this process as part of
                // the SCM_RIGHTS message, and nothing else refers to it, so OwnedFd may
                // take over closing it.
                fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
    }
    Ok((got as usize, fd))
}

pub fn poll_fds(fds: &mut [PollFd], timeout_ms: i32) -> io::Result<usize> {
    loop {
        // SAFETY: fds is a live slice and its length is passed alongside.
        let ready = unsafe { poll(fds.as_mut_ptr(), fds.len() as u64, timeout_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        return Ok(ready as usize);
    }
}

fn check_deadline(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "ubus I/O deadline elapsed"));
    }
    Ok(())
}

pub(crate) fn check_cancelled(cancelled: Option<fn() -> bool>) -> io::Result<()> {
    if cancelled.is_some_and(|check| check()) {
        Err(io::Error::new(io::ErrorKind::Interrupted, "ubus operation cancelled"))
    } else {
        Ok(())
    }
}

pub(crate) fn wait_until_cancelled(fd: RawFd, events: i16, deadline: Option<Instant>, cancelled: Option<fn() -> bool>) -> io::Result<()> {
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
        let mut timeout = deadline.map(|end| end.saturating_duration_since(Instant::now()).as_millis().clamp(1, i32::MAX as u128) as i32).unwrap_or(-1);
        if cancelled.is_some() { timeout = if timeout < 0 { 10 } else { timeout.min(10) }; }
        // SAFETY: pfd is one live pollfd. Recompute the deadline after EINTR
        // instead of restarting the full timeout under repeated signals.
        let ready = unsafe { poll(pfd.as_mut_ptr(), 1, timeout) };
        if ready > 0 { return Ok(()); }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
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
    let mut fds = [-1i32; 2];
    // SAFETY: fds is a live two-element array, which is what pipe2 fills.
    if unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded, so both entries are fresh descriptors owned by
    // this process and held nowhere else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC): what logd uses for stream
/// clients (a unix stream socket's send buffer, ~200 KiB by default, takes a
/// whole ring-buffer backlog in one write; a pipe holds 64 KiB).
pub fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    const AF_UNIX: i32 = 1;
    const SOCK_STREAM: i32 = 1;
    const SOCK_CLOEXEC: i32 = 0o2000000;
    let mut fds = [-1i32; 2];
    // SAFETY: fds is a live two-element array, which is what socketpair fills.
    if unsafe { libc_socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair succeeded, so both entries are fresh descriptors owned
    // by this process and held nowhere else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub fn drop_privileges(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: setgid(2) takes a plain id and touches no memory. It must come
    // before setuid, which the next statement does.
    if unsafe { setgid(gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: setuid(2) takes a plain id and touches no memory.
    if unsafe { setuid(uid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn body_without_ancillary_storage_closes_discarded_descriptor() {
        let (send, receive) = UnixStream::pair().unwrap();
        let (passed, mut watch) = UnixStream::pair().unwrap();
        send_with_fd(send.as_raw_fd(), b"bo", b"dy", Some(passed.as_raw_fd())).unwrap();
        drop(passed);
        let mut body = [0; 4];
        assert!(recv_exact(receive.as_raw_fd(), &mut body, false).unwrap().is_none());
        assert_eq!(&body, b"body");
        watch.set_nonblocking(true).unwrap();
        assert_eq!(watch.read(&mut [0]).unwrap(), 0, "discarded SCM_RIGHTS must not leak");

        let (passed, mut watch) = UnixStream::pair().unwrap();
        send_with_fd(send.as_raw_fd(), b"ne", b"xt", Some(passed.as_raw_fd())).unwrap();
        drop(passed);
        let fd = recv_exact(receive.as_raw_fd(), &mut body, true).unwrap().unwrap();
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
        assert_eq!(recv_exact(receive.as_raw_fd(), &mut [0], false).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
