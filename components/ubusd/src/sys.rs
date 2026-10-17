//! ubusd's OS adapters. Framing, ACLs, IDs and lifecycle policy remain here;
//! owned syscalls use rustix and raw message snapshots use the shared ABI.
use std::io::{self, IoSlice};
use std::os::fd::{AsFd, OwnedFd, RawFd};

pub type Ucred = owrt_platform::ubusd::Ucred;

/// Only the owned metadata fields consumed by ACL policy, not a foreign ABI.
pub struct Stat { pub mode: u32, pub uid: u32, pub gid: u32 }
pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IWGRP: u32 = 0o020;
pub const S_IWOTH: u32 = 0o002;
pub const S_IXOTH: u32 = 0o001;

pub const SIGHUP: i32 = 1;
/// Generate ID candidates with a thread-local keyed counter hash
/// (RandomState uses SipHash-1-3 in pinned Rust 1.98.1). On Linux, std seeds
/// its thread-local cache without waiting for CRNG initialization; subsequent
/// candidates need no randomness syscall. This is not a cryptographic RNG:
/// output quality depends on the retained initial seed. Reject values below
/// `min` to exclude reserved system IDs; the registry separately retries
/// collisions with live IDs, as C does.
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

/// Create the listening socket exactly as ubusd_main.c does: mkdir the parent
/// 0755, unlink a stale socket, bind under umask(0111) so the node is 0666,
/// then listen non-blocking.
pub fn listen_unix(path: &str) -> io::Result<OwnedFd> {
    if let Some(dir) = path.rfind('/').map(|i| &path[..i]) {
        if !dir.is_empty() {
            let _ = rustix::fs::mkdirat(rustix::fs::CWD, c_prefix(dir), rustix::fs::Mode::from_raw_mode(0o755));
        }
    }
    remove_file(path);
    if path.len() >= 108 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
    }
    let address = rustix::net::SocketAddrUnix::new(path)?;
    let socket = rustix::net::socket_with(rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK, None)?;
    // This is still single-threaded daemon startup; retain bind's mask scope.
    let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o111));
    let bound = rustix::net::bind(&socket, &address);
    rustix::process::umask(previous);
    bound?;
    rustix::net::listen(&socket, 64)?;
    Ok(socket)
}

fn c_prefix(value: &str) -> &str { value.split('\0').next().unwrap_or_default() }

pub fn remove_file(path: &str) {
    let _ = rustix::fs::unlinkat(rustix::fs::CWD, c_prefix(path), rustix::fs::AtFlags::empty());
}

/// accept4 with CLOEXEC|NONBLOCK. `Ok(None)` means the backlog is drained.
pub fn accept(fd: impl AsFd) -> io::Result<Option<OwnedFd>> {
    match rustix::net::accept_with(fd, rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK) {
        Ok(client) => Ok(Some(client)),
        Err(rustix::io::Errno::AGAIN) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn user_id(name: &str) -> Option<u32> {
    owrt_platform::identity::lookup_user(c_prefix(name)).map(|(uid, _)| uid)
}
pub fn group_id(name: &str) -> Option<u32> {
    owrt_platform::identity::lookup_group(c_prefix(name))
}
pub fn stat_of(path: &str) -> Option<Stat> {
    let stat = rustix::fs::stat(c_prefix(path)).ok()?;
    Some(Stat { mode: stat.st_mode, uid: stat.st_uid, gid: stat.st_gid })
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
    let vectors = [IoSlice::new(head), IoSlice::new(tail)];
    let count = if tail.is_empty() { 1 } else { 2 };
    owrt_platform::ipc::send_slices(sock, &vectors[..count], fd, false)
}

/// Submit three byte slices as one stream write, without copying the payload.
pub fn sendmsg_three(sock: RawFd, parts: [&[u8]; 3]) -> io::Result<usize> {
    owrt_platform::ipc::send_slices(sock, &parts.map(IoSlice::new), None, false)
}

/// One recvmsg; caller retains the original short-read/EINTR/backpressure policy.
pub fn recvmsg_fd(sock: RawFd, buf: &mut [u8], want_fd: bool) -> io::Result<(usize, Option<OwnedFd>)> {
    owrt_platform::ipc::recv_into(sock, buf, want_fd, false)
}
