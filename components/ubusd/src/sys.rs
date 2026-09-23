//! The syscalls ubusd needs that std does not expose: unix socket server
//! setup, non-blocking accept, SO_PEERCRED, getpwuid/getgrgid,
//! and partial-progress sendmsg/recvmsg with SCM_RIGHTS.
//!
//! Layout of every #[repr(C)] struct here is asserted against the target's
//! real musl headers by `tools/abi_assert.c` (see `make check-abi`).

use std::ffi::CStr;
use std::os::raw::c_char;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub const AF_UNIX: i32 = 1;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_CLOEXEC: i32 = 0o2000000;
pub const SOCK_NONBLOCK: i32 = 0o4000;
const SOL_SOCKET: i32 = 1;
const SO_PEERCRED: i32 = 17;
const SCM_RIGHTS: i32 = 1;
/// sizeof(struct cmsghdr) on 64-bit Linux.
const CMSG_HDR: usize = 16;
/// CMSG_SPACE(sizeof(int)).
const CMSG_SPACE_FD: usize = 24;
/// CMSG_LEN(sizeof(int)).
const CMSG_LEN_FD: usize = 20;

/// struct sockaddr_un
#[repr(C)]
struct SockaddrUn {
    family: u16,
    path: [u8; 108],
}

/// struct ucred
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Ucred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

// The client library and daemon use the same wire ABI and readiness helpers.
pub use owrt_ubus::sys::{ignore_signal, set_signal_handler, POLLIN, POLLOUT, POLLERR, POLLHUP, SIGPIPE, SIGTERM, SIGINT};
use owrt_ubus::sys::{IoVec, MsgHdr};

/// struct passwd -- only pw_name is read.
#[repr(C)]
struct Passwd {
    name: *const c_char,
    passwd: *const c_char,
    uid: u32,
    gid: u32,
    gecos: *const c_char,
    dir: *const c_char,
    shell: *const c_char,
}

/// struct group -- only gr_name is read.
#[repr(C)]
struct Group {
    name: *const c_char,
    passwd: *const c_char,
    gid: u32,
    mem: *const *const c_char,
}

/// struct stat, aarch64/musl. Only mode/uid/gid are read; the tail is padding.
#[repr(C)]
#[derive(Default)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    _pad0: u64,
    pub size: i64,
    pub blksize: i32,
    _pad1: i32,
    pub blocks: i64,
    _rest: [u64; 8],
}

pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IWGRP: u32 = 0o020;
pub const S_IWOTH: u32 = 0o002;
pub const S_IXOTH: u32 = 0o001;

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockaddrUn, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    #[cfg(target_os = "linux")]
    fn accept4(fd: i32, addr: *mut u8, len: *mut u32, flags: i32) -> i32;
    #[cfg(not(target_os = "linux"))]
    #[link_name = "accept"]
    fn libc_accept(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    #[cfg(not(target_os = "linux"))]
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    fn getsockopt(fd: i32, level: i32, name: i32, val: *mut Ucred, len: *mut u32) -> i32;
    fn sendmsg(fd: i32, msg: *const MsgHdr, flags: i32) -> isize;
    fn recvmsg(fd: i32, msg: *mut MsgHdr, flags: i32) -> isize;
    fn pipe2(fds: *mut i32, flags: i32) -> i32;
    fn getpwuid(uid: u32) -> *const Passwd;
    fn getgrgid(gid: u32) -> *const Group;
    fn getpwnam(name: *const u8) -> *const Passwd;
    fn getgrnam(name: *const u8) -> *const Group;
    fn umask(mask: u32) -> u32;
    fn mkdir(path: *const u8, mode: u32) -> i32;
    fn unlink(path: *const u8) -> i32;
    fn stat(path: *const u8, buf: *mut Stat) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
}

pub const SIGHUP: i32 = 1;
/// A u32 that is hard to guess. ubusd_id.c asks getrandom(2) for every id;
/// here each id is the keyed SipHash of a counter, with the key drawn from
/// the OS once (std's RandomState; like C's GRND_INSECURE it never blocks on
/// a board whose entropy pool seeds late), so allocating an id costs no
/// syscall and is just as unpredictable without the key. Like C, retry until the value is
/// at least `min`, so ids never collide with the reserved system objects; the
/// registry retries on a collision with a live id.
pub fn random_id(min: u32) -> io::Result<u32> {
    use std::cell::Cell;
    use std::hash::{BuildHasher, RandomState};
    thread_local! {
        static KEY: RandomState = RandomState::new();
        static NEXT: Cell<u64> = const { Cell::new(0) };
    }
    loop {
        let n = NEXT.with(|c| {
            let n = c.get();
            c.set(n.wrapping_add(1));
            n
        });
        let v = KEY.with(|k| k.hash_one(n)) as u32;
        if v >= min {
            return Ok(v);
        }
    }
}

fn sockaddr(path: &str) -> io::Result<(SockaddrUn, u32)> {
    let bytes = path.as_bytes();
    if bytes.len() >= 108 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
    }
    let mut addr = SockaddrUn { family: AF_UNIX as u16, path: [0; 108] };
    addr.path[..bytes.len()].copy_from_slice(bytes);
    // sizeof(sa_family_t) + strlen(path) + 1, the length usock() passes.
    Ok((addr, (2 + bytes.len() + 1) as u32))
}

/// Create the listening socket exactly as ubusd_main.c does: mkdir the parent
/// 0755, unlink a stale socket, bind under umask(0111) so the node is 0666,
/// then listen non-blocking.
pub fn listen_unix(path: &str) -> io::Result<OwnedFd> {
    if let Some(dir) = path.rfind('/').map(|i| &path[..i]) {
        if !dir.is_empty() {
            let c = cstring(dir);
            // SAFETY: NUL-terminated path; EEXIST is handled by the caller's bind.
            unsafe { mkdir(c.as_ptr(), 0o755) };
        }
    }
    let c = cstring(path);
    // SAFETY: NUL-terminated path. Removing a stale socket is what ubusd does.
    unsafe { unlink(c.as_ptr()) };

    let (addr, len) = sockaddr(path)?;
    // SAFETY: plain socket(2).
    let fd = unsafe { socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is ours from here; wrap it so every early return closes it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // SAFETY: umask(2) has no preconditions. Single-threaded at this point.
    let prev = unsafe { umask(0o111) };
    // SAFETY: addr lives across the call and len describes it.
    let rc = unsafe { bind(fd, &addr, len) };
    // SAFETY: restoring the umask we just replaced.
    unsafe { umask(prev) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a bound unix socket.
    if unsafe { listen(fd, 64) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

pub fn remove_file(path: &str) {
    let c = cstring(path);
    // SAFETY: NUL-terminated path.
    unsafe { unlink(c.as_ptr()) };
}

/// accept4 with CLOEXEC|NONBLOCK. `Ok(None)` means the backlog is drained.
pub fn accept(fd: RawFd) -> io::Result<Option<OwnedFd>> {
    #[cfg(target_os = "linux")]
    // SAFETY: null addr/len is the documented way to ignore the peer address.
    let c = unsafe {
        accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), SOCK_CLOEXEC | SOCK_NONBLOCK)
    };
    // Host-only shim: no accept4 off Linux, so set the flags afterwards. The
    // device always takes the atomic path above.
    #[cfg(not(target_os = "linux"))]
    let c = {
        const F_SETFD: i32 = 2;
        const F_SETFL: i32 = 4;
        const FD_CLOEXEC: i32 = 1;
        const O_NONBLOCK_HOST: i32 = 0o4000;
        // SAFETY: null addr/len ignores the peer address.
        let c = unsafe { libc_accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if c >= 0 {
            // SAFETY: c is a descriptor we just received.
            unsafe {
                fcntl(c, F_SETFD, FD_CLOEXEC);
                fcntl(c, F_SETFL, O_NONBLOCK_HOST);
            }
        }
        c
    };
    if c >= 0 {
        // SAFETY: accept4 returned a fresh owned descriptor.
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(c) }));
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(11) | Some(0) => Ok(None), // EAGAIN
        _ => Err(err),
    }
}

pub fn peer_cred(fd: RawFd) -> io::Result<Ucred> {
    let mut cred = Ucred::default();
    let mut len = std::mem::size_of::<Ucred>() as u32;
    // SAFETY: cred and len are live and correctly sized for SO_PEERCRED.
    if unsafe { getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &mut cred, &mut len) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred)
}

fn cstring(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

/// getpwuid(3). `None` when the uid has no passwd entry -- ubusd rejects the
/// connection in that case rather than guessing a name.
pub fn user_name(uid: u32) -> Option<String> {
    // SAFETY: getpwuid returns NULL or a pointer to a static passwd entry.
    let p = unsafe { getpwuid(uid) };
    if p.is_null() {
        return None;
    }
    // SAFETY: p is non-null; pw_name is a NUL-terminated string owned by libc.
    unsafe { CStr::from_ptr((*p).name) }.to_str().ok().map(str::to_owned)
}

pub fn group_name(gid: u32) -> Option<String> {
    // SAFETY: getgrgid returns NULL or a pointer to a static group entry.
    let p = unsafe { getgrgid(gid) };
    if p.is_null() {
        return None;
    }
    // SAFETY: p is non-null; gr_name is a NUL-terminated string owned by libc.
    unsafe { CStr::from_ptr((*p).name) }.to_str().ok().map(str::to_owned)
}

pub fn user_id(name: &str) -> Option<u32> {
    let c = cstring(name);
    // SAFETY: NUL-terminated name; the result is libc-owned or NULL.
    let p = unsafe { getpwnam(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        // SAFETY: p is non-null.
        Some(unsafe { (*p).uid })
    }
}

pub fn group_id(name: &str) -> Option<u32> {
    let c = cstring(name);
    // SAFETY: NUL-terminated name; the result is libc-owned or NULL.
    let p = unsafe { getgrnam(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        // SAFETY: p is non-null.
        Some(unsafe { (*p).gid })
    }
}

pub fn stat_of(path: &str) -> Option<Stat> {
    let c = cstring(path);
    let mut st = Stat::default();
    // SAFETY: NUL-terminated path, st is live and correctly sized.
    if unsafe { stat(c.as_ptr(), &mut st) } == 0 {
        Some(st)
    } else {
        None
    }
}

/// The supplementary groups of `pid`, from /proc/<pid>/status, capped the way
/// ubusd caps them (UBUS_CLIENT_MAX_EXTRA_GID).
pub const MAX_EXTRA_GID: usize = 64;

pub fn extra_gids(pid: i32) -> Vec<u32> {
    let path = format!("/proc/{pid}/status");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Groups:") {
            return rest
                .split_whitespace()
                .filter_map(|t| t.parse::<u32>().ok())
                .take(MAX_EXTRA_GID)
                .collect();
        }
    }
    Vec::new()
}

/// One sendmsg of `head` then `tail`, attaching `fd` when given. Returns the
/// byte count written, which may be short: the caller resumes at that offset.
pub fn sendmsg_two(sock: RawFd, head: &[u8], tail: &[u8], fd: Option<RawFd>) -> io::Result<usize> {
    let mut iov = [
        IoVec { base: head.as_ptr() as *mut u8, len: head.len() },
        IoVec { base: tail.as_ptr() as *mut u8, len: tail.len() },
    ];
    let iovlen = if tail.is_empty() { 1 } else { 2 };
    sendmsg_iov(sock, &mut iov[..iovlen], fd)
}

/// Submit three byte slices as one stream write, without copying the payload.
pub fn sendmsg_three(sock: RawFd, parts: [&[u8]; 3]) -> io::Result<usize> {
    let mut iov = parts.map(|part| IoVec { base: part.as_ptr() as *mut u8, len: part.len() });
    sendmsg_iov(sock, &mut iov, None)
}

fn sendmsg_iov(sock: RawFd, iov: &mut [IoVec], fd: Option<RawFd>) -> io::Result<usize> {
    let mut control = [0u8; CMSG_SPACE_FD];
    let mut hdr = MsgHdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: iov.as_mut_ptr(),
        iovlen: iov.len(),
        control: std::ptr::null_mut(),
        controllen: 0,
        flags: 0,
    };
    if let Some(fd) = fd {
        control[0..8].copy_from_slice(&(CMSG_LEN_FD as u64).to_ne_bytes());
        control[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
        control[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
        control[16..20].copy_from_slice(&fd.to_ne_bytes());
        hdr.control = control.as_mut_ptr();
        hdr.controllen = CMSG_LEN_FD;
    }
    // SAFETY: iov, control and hdr all outlive the call; lengths describe them.
    let n = unsafe { sendmsg(sock, &hdr, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// One recvmsg into `buf`, optionally accepting a single SCM_RIGHTS fd.
/// `Ok((0, _))` means the peer closed. Short reads are normal.
pub fn recvmsg_fd(sock: RawFd, buf: &mut [u8], want_fd: bool) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = [IoVec { base: buf.as_mut_ptr(), len: buf.len() }];
    let mut control = [0u8; CMSG_SPACE_FD];
    let mut hdr = MsgHdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: iov.as_mut_ptr(),
        iovlen: 1,
        control: if want_fd { control.as_mut_ptr() } else { std::ptr::null_mut() },
        controllen: if want_fd { CMSG_LEN_FD } else { 0 },
        flags: 0,
    };
    // SAFETY: iov, control and hdr outlive the call; lengths describe them.
    let n = unsafe { recvmsg(sock, &mut hdr, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut got = None;
    if want_fd && hdr.controllen >= CMSG_LEN_FD {
        let level = i32::from_ne_bytes(control[8..12].try_into().unwrap());
        let ty = i32::from_ne_bytes(control[12..16].try_into().unwrap());
        if level == SOL_SOCKET && ty == SCM_RIGHTS {
            let raw = i32::from_ne_bytes(control[16..20].try_into().unwrap());
            if raw >= 0 {
                // SAFETY: the kernel installed this descriptor for us; taking
                // ownership here is what closes it on drop.
                got = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
    }
    let _ = CMSG_HDR;
    Ok((n as usize, got))
}

pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buf is live and len describes it.
    let n = unsafe { read(fd, buf.as_mut_ptr(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

pub fn write_fd(fd: RawFd, buf: &[u8]) -> isize {
    // SAFETY: buf is live and len describes it. Used from a signal handler,
    // where write(2) is async-signal-safe.
    unsafe { write(fd, buf.as_ptr(), buf.len()) }
}

/// pipe2(O_NONBLOCK | O_CLOEXEC) for the SIGHUP self-pipe.
pub fn nonblocking_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    const O_NONBLOCK: i32 = 0o4000;
    const O_CLOEXEC: i32 = 0o2000000;
    let mut fds = [0i32; 2];
    // SAFETY: fds is a live 2-element array, which is what pipe2 fills.
    if unsafe { pipe2(fds.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two fresh owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}
