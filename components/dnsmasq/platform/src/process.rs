//! Narrow libc exceptions for process-wide credentials, NSS and exec hooks.
//! Ordinary descriptor ownership and I/O belong to rustix/std.

use std::ffi::{c_char, c_int, CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::IntoRawFd;

#[repr(C)]
struct Passwd {
    name: *mut c_char,
    password: *mut c_char,
    uid: u32,
    gid: u32,
    gecos: *mut c_char,
    directory: *mut c_char,
    shell: *mut c_char,
}
#[repr(C)]
struct Group {
    name: *mut c_char,
    password: *mut c_char,
    gid: u32,
    members: *mut *mut c_char,
}

unsafe extern "C" {
    fn getpwnam_r(
        name: *const c_char,
        entry: *mut Passwd,
        buffer: *mut c_char,
        length: usize,
        result: *mut *mut Passwd,
    ) -> c_int;
    fn getgrnam_r(
        name: *const c_char,
        entry: *mut Group,
        buffer: *mut c_char,
        length: usize,
        result: *mut *mut Group,
    ) -> c_int;
    fn getgrgid_r(
        gid: u32,
        entry: *mut Group,
        buffer: *mut c_char,
        length: usize,
        result: *mut *mut Group,
    ) -> c_int;
    fn setuid(uid: u32) -> c_int;
    fn setgid(gid: u32) -> c_int;
    fn setgroups(count: usize, groups: *const u32) -> c_int;
    fn fork() -> c_int;
    fn _exit(code: c_int) -> !;
}

/// Reentrant lookup owns every returned value and never exposes NSS storage.
pub fn user_ids(name: &[u8]) -> Option<(u32, u32)> {
    let name = CString::new(name).ok()?;
    let mut length = 1024;
    loop {
        let mut buffer = vec![0; length];
        let mut entry = std::mem::MaybeUninit::<Passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: libc initializes entry and points its strings into this live
        // buffer on success. Only scalar IDs are copied before storage drops.
        let code = unsafe {
            getpwnam_r(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if code == 34 {
            length = length.checked_mul(2)?;
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        // SAFETY: successful non-null result initializes our entry.
        let entry = unsafe { entry.assume_init() };
        return Some((entry.uid, entry.gid));
    }
}

pub fn group_by_name(name: &[u8]) -> Option<(u32, Vec<u8>)> {
    group(Some(CString::new(name).ok()?), 0)
}
pub fn group_by_id(gid: u32) -> Option<(u32, Vec<u8>)> {
    group(None, gid)
}
fn group(name: Option<CString>, gid: u32) -> Option<(u32, Vec<u8>)> {
    let mut length = 1024;
    loop {
        let mut buffer = vec![0; length];
        let mut entry = std::mem::MaybeUninit::<Group>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: both APIs receive one writable record and buffer. The name
        // is terminated; returned record/string storage is copied while live.
        let code = unsafe {
            match &name {
                Some(name) => getgrnam_r(
                    name.as_ptr(),
                    entry.as_mut_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut result,
                ),
                None => getgrgid_r(
                    gid,
                    entry.as_mut_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut result,
                ),
            }
        };
        if code == 34 {
            length = length.checked_mul(2)?;
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        // SAFETY: the successful record is initialized and owns a terminated
        // name in buffer; no concurrent lookup can alter this private storage.
        let entry = unsafe { entry.assume_init() };
        let name = unsafe { CStr::from_ptr(entry.name) }.to_bytes().to_vec();
        return Some((entry.gid, name));
    }
}

/// libc deliberately changes credentials of every thread, unlike rustix's
/// Linux set_thread_* APIs. Preserve that process-wide startup contract.
pub fn set_process_group(gid: u32) -> io::Result<()> {
    // SAFETY: zero groups permits NULL; gid is a scalar kernel identifier.
    if unsafe { setgroups(0, std::ptr::null()) } < 0 || unsafe { setgid(gid) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn set_process_user(uid: u32) -> io::Result<()> {
    // SAFETY: libc accepts every scalar uid and reports kernel errors.
    if unsafe { setuid(uid) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Consume ownership exactly once while retaining Linux close's error report.
/// Never retry EINTR: Linux has already released the descriptor.
pub fn close_file(file: File) -> io::Result<()> {
    // SAFETY: into_raw_fd transfers the sole live descriptor obligation.
    // try_close reports errors while consuming it; never retry a Linux close.
    unsafe { rustix::io::try_close(file.into_raw_fd()) }.map_err(Into::into)
}

pub use crate::libc_format::preserve_ignored_sigpipe;

#[path = "process_fork.rs"]
mod worker;
pub use worker::{spawn_helper, spawn_lookup};

/// A dedicated daemon startup fork: only the detached child can return. The
/// parent executes a noncapturing startup-report function and then _exit;
/// it cannot run destructors from the service's copied ownership graph.
///
/// Runtime checks reject threads and shared writable mappings. The service
/// must call this during startup, before installing handlers that execute
/// Rust code or registering third-party atfork callbacks. Its only installed
/// handlers store signal flags. This crate's libc fork (not kernel_fork) keeps
/// libc's own atfork bookkeeping. The checks fail closed when /proc is absent.
/// This applies only to background daemonization. Foreground procd/ujail
/// invocations, including a jail without procfs, never call this function;
/// independent background invocations still require procfs for these proofs.
///
/// # Safety
///
/// The caller must ensure a single-threaded process without application atfork
/// callbacks, shared writable mappings or locks acquired by either callback.
/// The callbacks may access only their supplied pipe, ordinary private data
/// and standard streams; they must not reach other inherited resource owners.
/// Inherited signal handlers and panic hooks must satisfy the same restriction;
/// a panic hook executes before the terminating branch can catch its payload.
/// The `/proc` checks are a diagnostic guard, not a proof of these conditions.
pub unsafe fn background_startup(
    reader: File,
    writer: File,
    report: fn(File) -> i32,
    fork_failed: fn(File, io::Error),
) -> io::Result<File> {
    if std::fs::read_dir("/proc/self/task")?
        .collect::<io::Result<Vec<_>>>()?
        .len()
        != 1
        || std::fs::read_to_string("/proc/self/maps")?
            .lines()
            .any(|line| {
                line.split_whitespace().nth(1).is_some_and(|permissions| {
                    permissions.as_bytes().get(1) == Some(&b'w')
                        && permissions.as_bytes().get(3) == Some(&b's')
                })
            })
    {
        return Err(io::Error::other(
            "background startup requires one thread and private writable mappings",
        ));
    }
    // SAFETY: checked single-thread/private-memory startup plus the restricted
    // parent path above prevents concurrent Rust ownership after libc fork.
    let pid = unsafe { fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        drop(writer);
        let status = worker::exit_status(std::panic::catch_unwind(|| report(reader)));
        // SAFETY: the parent must never unwind/return into service state.
        unsafe { _exit(status) }
    }
    drop(reader);
    let _ = rustix::process::setsid();
    // SAFETY: the first child remains single-threaded, with private memory;
    // its parent cannot resume the copied service ownership graph.
    let pid = unsafe { fork() };
    if pid < 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(5);
        let _ = worker::exit_status(std::panic::catch_unwind(|| {
            fork_failed(writer, io::Error::from_raw_os_error(errno));
            0
        }));
        // SAFETY: report only through the startup pipe, as in C; the first
        // child must not return into the service after failing its detach.
        unsafe { _exit(0) }
    }
    if pid > 0 {
        // SAFETY: the intermediate child must not run service destructors.
        unsafe { _exit(0) }
    }
    Ok(writer)
}
