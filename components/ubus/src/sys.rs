//! Hand-written Linux FFI for the few calls std does not expose:
//! sendmsg/recvmsg with SCM_RIGHTS, poll, pipe2, setuid/setgid.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

#[repr(C)]
struct IoVec {
    base: *mut u8,
    len: usize,
}

#[repr(C)]
struct MsgHdr {
    name: *mut u8,
    namelen: u32,
    iov: *mut IoVec,
    iovlen: usize,
    control: *mut u8,
    controllen: usize,
    flags: i32,
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
    let mut iov = [
        IoVec {
            base: header.as_ptr() as *mut u8,
            len: header.len(),
        },
        IoVec {
            base: body.as_ptr() as *mut u8,
            len: body.len(),
        },
    ];
    let mut control = [0u8; CMSG_SPACE_FD];
    let mut attach = fd;
    let mut index = 0;
    while index < iov.len() {
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
        let sent = unsafe { sendmsg(sock, &hdr, 0) };
        if sent < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => {
                    wait(sock, POLLOUT)?;
                    continue;
                }
                _ => return Err(error),
            }
        }
        attach = None;
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
    let mut received_fd = None;
    let mut offset = 0;
    let mut first = want_fd;
    while offset < buf.len() {
        let mut iov = IoVec {
            // SAFETY: the enclosing loop runs only while offset < buf.len(), so this
            // stays within the buffer.
            base: unsafe { buf.as_mut_ptr().add(offset) },
            len: buf.len() - offset,
        };
        let mut control = [0u8; CMSG_SPACE_FD];
        let mut hdr = MsgHdr {
            name: std::ptr::null_mut(),
            namelen: 0,
            iov: &mut iov,
            iovlen: 1,
            control: if first {
                control.as_mut_ptr()
            } else {
                std::ptr::null_mut()
            },
            controllen: if first { CMSG_LEN_FD } else { 0 },
            flags: 0,
        };
        // SAFETY: hdr, its iovec and the control buffer are live for the call and
        // sized by the lengths hdr carries.
        let got = unsafe { recvmsg(sock, &mut hdr, 0) };
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ubus connection closed",
            ));
        }
        if got < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => {
                    wait(sock, POLLIN)?;
                    continue;
                }
                _ => return Err(error),
            }
        }
        if first && hdr.controllen >= CMSG_HDR + 4 {
            let level = i32::from_ne_bytes(control[8..12].try_into().unwrap());
            let kind = i32::from_ne_bytes(control[12..16].try_into().unwrap());
            if level == SOL_SOCKET && kind == SCM_RIGHTS {
                let fd = i32::from_ne_bytes(control[16..20].try_into().unwrap());
                if fd >= 0 {
                    // SAFETY: the kernel installed this descriptor for this process as part of
                    // the SCM_RIGHTS message, and nothing else refers to it, so OwnedFd may
                    // take over closing it.
                    received_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }
        first = false;
        offset += got as usize;
    }
    Ok(received_fd)
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

fn wait(fd: RawFd, events: i16) -> io::Result<()> {
    let mut pfd = [PollFd {
        fd,
        events,
        revents: 0,
    }];
    poll_fds(&mut pfd, -1).map(|_| ())
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
