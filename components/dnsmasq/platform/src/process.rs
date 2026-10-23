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
        // SAFETY: the successful non-null result initializes our record.
        let entry = unsafe { entry.assume_init() };
        // SAFETY: the successful lookup stores a terminated name in buffer;
        // it remains live and no concurrent lookup can alter this private storage.
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
pub use worker::{spawn_helper, spawn_lookup, AuditedWorker};

pub type StartupCallbacks = AuditedWorker<(fn(File) -> i32, fn(File, io::Error))>;

/// Detach with the executable's registered startup-report callbacks.
/// Only the final service child returns. The original parent reports through
/// its pipe and exits without running the service's copied destructors.
/// The kernel thread check needs no procfs; callback/memory restrictions are
/// established by the unsafe registration, independently of this runtime check.
pub fn background_startup(
    reader: File,
    writer: File,
    callbacks: &StartupCallbacks,
) -> io::Result<File> {
    let (report, fork_failed) = callbacks.entry;
    if std::thread::panicking() {
        return Err(io::Error::other("cannot fork from a panic handler"));
    }
    let owner = owrt_platform::process_owner::ProcessOwner::acquire()?;
    // SAFETY: the final thread/signal check is followed only by the fixed fork;
    // registration guarantees the executable's callback and memory policy.
    let guard = unsafe { owner.enter()? };
    // SAFETY: the guard excludes concurrent threads and signal callbacks; only
    // the registered report path runs in the terminating original parent.
    let pid = unsafe { fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        worker::replace_panic_hook();
        drop(writer);
        drop(guard);
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
        worker::replace_panic_hook();
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
    drop(guard);
    Ok(writer)
}
