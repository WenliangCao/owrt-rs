//! Narrow libc exceptions for process-wide credentials, NSS and exec hooks.
//! Ordinary descriptor ownership and I/O belong to rustix/std.

use std::ffi::{c_char, c_int, c_long, CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

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
    fn close(fd: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn signal(number: c_int, handler: usize) -> usize;
    fn syscall(number: c_long, ...) -> c_long;
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
    // SAFETY: into_raw_fd transfers the sole descriptor obligation to close.
    if unsafe { close(file.into_raw_fd()) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub use crate::libc_format::preserve_ignored_sigpipe;

/// Keep exactly the two owned IPC pipes across exec, preserving standard IO.
/// Their numbers remain unchanged, so std's private exec-error pipe cannot be
/// overwritten. CLOEXEC closes all other inherited descriptors at exec.
pub fn isolated_pipe_command(
    command: &mut Command,
    commands: OwnedFd,
    events: OwnedFd,
) -> io::Result<()> {
    let maximum = rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .unwrap_or(i32::MAX as u64)
        .min(i32::MAX as u64) as i32;
    // SAFETY: the closure owns both pipes until exec/Command drop. It calls
    // only async-signal-safe syscalls, with no allocation or Rust locks.
    unsafe {
        command.pre_exec(move || {
            // __NR_close_range=436 on both supported Linux64 ABIs. Flag4 marks
            // CLOEXEC instead of closing std's exec-error pipe before exec.
            if syscall(436, 3u32, u32::MAX, 4u32) < 0 {
                let error = io::Error::last_os_error();
                if !matches!(error.raw_os_error(), Some(22 | 38)) {
                    return Err(error);
                }
                for fd in 3..maximum {
                    fcntl(fd, 2, 1);
                }
            }
            for fd in [commands.as_raw_fd(), events.as_raw_fd()] {
                if fcntl(fd, 2, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for sig in [2, 13, 14, 15] {
                signal(sig, 1);
            }
            signal(17, 0);
            Ok(())
        });
    }
    Ok(())
}

/// Duplicate an inherited IPC descriptor instead of claiming arbitrary raw
/// ownership. This remains safe even for a malformed private invocation: an
/// invalid descriptor fails, and a valid one produces a fresh owned FD.
/// Original inherited descriptors stay open until process exit, but CLOEXEC
/// keeps them out of scripts. They have no Rust owner in the fresh exec image.
pub fn inherited_pipe(fd: i32, reading: bool) -> io::Result<File> {
    if fd <= 2 {
        return Err(io::Error::from_raw_os_error(22));
    }
    // SAFETY: fcntl accepts any scalar descriptor, returning a newly owned
    // descriptor on success. No pointer or borrowed Rust owner is fabricated.
    let duplicate = unsafe { fcntl(fd, 1030, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_DUPFD_CLOEXEC just created this uniquely owned descriptor.
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let stat = rustix::fs::fstat(&duplicate)?;
    let flags = rustix::fs::fcntl_getfl(&duplicate)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Fifo
        || (flags & rustix::fs::OFlags::ACCMODE)
            != if reading {
                rustix::fs::OFlags::RDONLY
            } else {
                rustix::fs::OFlags::WRONLY
            }
    {
        return Err(io::Error::from_raw_os_error(22));
    }
    // SAFETY: setting a descriptor flag cannot invalidate any Rust owner.
    if unsafe { fcntl(fd, 2, 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(File::from(duplicate))
}

/// A dedicated daemon startup fork: only the detached child can return. The
/// parent executes a noncapturing startup-report function and then _exit;
/// it cannot run destructors from the service's copied ownership graph.
///
/// Runtime checks reject threads and shared writable mappings. The service
/// must call this during startup, before installing handlers that execute
/// Rust code or registering third-party atfork callbacks. Its only installed
/// handlers store signal flags. This crate's libc fork (not kernel_fork) keeps
/// libc's own atfork bookkeeping. The checks fail closed when /proc is absent.
pub fn background_startup(
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
        let status = std::panic::catch_unwind(|| report(reader)).unwrap_or(5);
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
        let _ =
            std::panic::catch_unwind(|| fork_failed(writer, io::Error::from_raw_os_error(errno)));
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
