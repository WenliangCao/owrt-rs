//! The two libc calls libuci needs that std does not expose: flock(2) and
//! fsync via std, plus a mkstemp equivalent built on O_EXCL.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

extern "C" {
    fn flock(fd: i32, op: i32) -> i32;
}

pub const LOCK_SH: i32 = 1;
pub const LOCK_EX: i32 = 2;
pub const LOCK_NB: i32 = 4;
pub const LOCK_UN: i32 = 8;

/// flock(fd, op). ENOSYS is treated as success like libuci does.
pub fn lock(file: &File, op: i32) -> io::Result<()> {
    // SAFETY: plain syscall on a valid, owned descriptor; no memory is passed.
    let rc = unsafe { flock(file.as_raw_fd(), op) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(38) {
            return Err(e);
        }
    }
    Ok(())
}

pub fn unlock(file: &File) {
    // SAFETY: as above; result ignored like libuci's uci_close_stream.
    unsafe {
        flock(file.as_raw_fd(), LOCK_UN);
    }
}

/// mkstemp(3) equivalent: create `<template minus XXXXXX><6 chars>` with
/// O_CREAT|O_EXCL|O_RDWR and mode 0600; returns the file and its path.
pub fn mkstemp(template: &str) -> io::Result<(File, String)> {
    let Some(stem) = template.strip_suffix("XXXXXX") else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "template"));
    };
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed = std::process::id() as u64 ^ {
        
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    };
    for _ in 0..100 {
        let mut suffix = String::with_capacity(6);
        for _ in 0..6 {
            // xorshift64*
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            let r = seed.wrapping_mul(0x2545_F491_4F6C_DD1D);
            suffix.push(CHARS[(r >> 58) as usize % CHARS.len()] as char);
        }
        let path = format!("{stem}{suffix}");
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "mkstemp exhausted"))
}
