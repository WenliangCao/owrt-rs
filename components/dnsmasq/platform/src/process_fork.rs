//! Restricted workers for this fixed dnsmasq application, not a general fork API.
//!
//! The two callers pass only owned Config/scalar or Vec<ServerRule> snapshots.
//! Send + 'static and noncapturing fn are interface bounds, not a proof of
//! ownership or fork safety. The actual production owner is single-threaded;
//! registration audits private snapshots, fixed child entries and the
//! executable's atfork/mapping/handler policy. Each fork independently verifies
//! exclusive address-space ownership with signal delivery blocked. libc fork retains libc's
//! own atfork bookkeeping; no worker can return into the parent owner graph.

use rustix::process::Pid;
use std::ffi::{c_int, c_long};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;

// Linux musl/glibc sigset_t: 128 bytes, native unsigned-long alignment.
// A usize array must retain the byte width even on 32-bit build hosts.
const SIGNAL_WORDS: usize = 128 / std::mem::size_of::<usize>();
#[repr(C)]
#[derive(Clone, Copy)]
struct SignalSet([usize; SIGNAL_WORDS]);

unsafe extern "C" {
    fn sigemptyset(set: *mut SignalSet) -> c_int;
    fn sigaddset(set: *mut SignalSet, number: c_int) -> c_int;
    fn sigprocmask(how: c_int, set: *const SignalSet, old: *mut SignalSet) -> c_int;
    fn signal(number: c_int, handler: usize) -> usize;
    fn syscall(number: c_long, ...) -> c_long;
    fn fork() -> c_int;
    fn _exit(code: c_int) -> !;
}

struct SignalMask {
    previous: SignalSet,
    active: bool,
}
impl SignalMask {
    fn block() -> io::Result<Self> {
        let mut set = SignalSet([0; SIGNAL_WORDS]);
        let mut previous = SignalSet([0; SIGNAL_WORDS]);
        // SAFETY: both sets have the supported libc ABI and remain writable
        // throughout these calls. Only fixed daemon/worker signals are added.
        unsafe {
            if sigemptyset(&mut set) != 0 {
                return Err(io::Error::last_os_error());
            }
            for number in [1, 2, 10, 12, 13, 14, 15, 17] {
                if sigaddset(&mut set, number) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if sigprocmask(0, &set, &mut previous) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            previous,
            active: true,
        })
    }
    fn restore(&mut self) {
        if !self.active {
            return;
        }
        // SAFETY: restore the complete mask returned by libc in this process.
        // If a valid restoration is refused, continuing with blocked service
        // signals is unsafe operationally: terminate rather than conceal it.
        unsafe {
            if sigprocmask(2, &self.previous, std::ptr::null_mut()) != 0 {
                _exit(5);
            }
        }
        self.active = false;
    }
}
impl Drop for SignalMask {
    fn drop(&mut self) {
        self.restore();
    }
}

fn nonblocking(fd: impl AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    Ok(rustix::fs::fcntl_setfl(
        fd,
        flags | rustix::fs::OFlags::NONBLOCK,
    )?)
}

pub type HelperProcess<T> = (T, Pid, File, File);

/// A fixed fork entry audited by the executable's platform adapter.
///
/// Construction is restricted to that adapter. Safe callers cannot replace
/// the function or use an arbitrary closure as a fork entry.
pub struct AuditedWorker<F> {
    pub(super) entry: F,
}

impl<F> std::fmt::Debug for AuditedWorker<F> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditedWorker")
    }
}

impl<F> AuditedWorker<F> {
    /// Register a fixed entry whose complete child call graph was reviewed.
    ///
    /// # Safety
    ///
    /// For every accepted input, the complete entry call graph (including
    /// destructors, allocator and NSS callbacks) may use only owned private data,
    /// the supplied pipes and standard streams. It must not access abandoned
    /// descriptor owners or shared writable mappings, or reacquire a lock held
    /// across fork. Operations before the platform releases its signal/thread
    /// guard must not create threads or restore signal delivery early.
    /// The executable must keep application atfork callbacks absent and retain
    /// the audited signal-handler/resource policy throughout this registration's
    /// lifetime. A per-fork thread check does not establish these requirements.
    pub unsafe fn new(entry: F) -> Self {
        Self { entry }
    }
}

/// Start a fixed helper entry registered by the executable's platform adapter.
/// The parent retains its snapshot and nonblocking command/event channels.
/// A fresh kernel check rejects a shared address space before every fork.
pub fn spawn_helper<T: Send + 'static>(
    snapshot: T,
    worker: &AuditedWorker<fn(T, File, File) -> i32>,
) -> io::Result<HelperProcess<T>> {
    let mask = SignalMask::block()?;
    let (commands, command_writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let (event_reader, events) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    nonblocking(&command_writer)?;
    nonblocking(&event_reader)?;
    fn enter<T>(
        (snapshot, entry): (T, fn(T, File, File) -> i32),
        [commands, events]: [File; 2],
    ) -> i32 {
        entry(snapshot, commands, events)
    }
    // SAFETY: the registered worker guarantees every input and child operation;
    // fork_worker performs a fresh thread check. These pipes are disjoint owners.
    let ((snapshot, _), pid, [command_writer, event_reader]) = unsafe {
        fork_worker(
            (snapshot, worker.entry),
            [File::from(commands), File::from(events)],
            [File::from(command_writer), File::from(event_reader)],
            enter::<T>,
            true,
            mask,
        )
    }?;
    Ok((snapshot, pid, command_writer, event_reader))
}

/// Start a fixed resolver entry registered by the platform adapter.
/// The parent retains its snapshot and one nonblocking result channel.
pub fn spawn_lookup<T: Send + 'static>(
    snapshot: T,
    worker: &AuditedWorker<fn(T, File) -> i32>,
) -> io::Result<(T, Pid, File)> {
    let mask = SignalMask::block()?;
    let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    nonblocking(&reader)?;
    fn enter<T>((snapshot, entry): (T, fn(T, File) -> i32), [writer]: [File; 1]) -> i32 {
        entry(snapshot, writer)
    }
    // SAFETY: the registered worker guarantees every input and child operation;
    // fork_worker performs a fresh thread check and the pipe owners are distinct.
    let ((snapshot, _), pid, [reader]) = unsafe {
        fork_worker(
            (snapshot, worker.entry),
            [File::from(writer)],
            [File::from(reader)],
            enter::<T>,
            false,
            mask,
        )
    }?;
    Ok((snapshot, pid, reader))
}

unsafe fn fork_worker<T: Send + 'static, const CHILD: usize, const PARENT: usize>(
    snapshot: T,
    child_files: [File; CHILD],
    parent_files: [File; PARENT],
    entry: fn(T, [File; CHILD]) -> i32,
    helper: bool,
    mut mask: SignalMask,
) -> io::Result<(T, Pid, [File; PARENT])> {
    if std::thread::panicking() {
        return Err(io::Error::other("cannot fork from a panic handler"));
    }
    let mut keep = child_files.each_ref().map(AsRawFd::as_raw_fd);
    keep.sort_unstable();
    if keep.iter().any(|fd| *fd <= 2) || parent_files.iter().any(|fd| fd.as_raw_fd() <= 2) {
        return Err(io::Error::other(
            "worker requires valid inherited standard streams",
        ));
    }
    let owner = owrt_platform::process_owner::ProcessOwner::acquire()?;
    // SAFETY: only the fixed libc fork follows the final signal/thread check.
    // Registration establishes the separate callback and snapshot contract.
    let guard = unsafe { owner.enter()? };
    // SAFETY: the guard verifies exclusive address-space ownership with signals
    // blocked. The registered entry owns only its permitted private snapshot;
    // libc fork preserves libc bookkeeping and the child cannot return here.
    let pid = unsafe { fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        drop(child_files);
        drop(guard);
        mask.restore();
        return Ok((snapshot, Pid::from_raw(pid).unwrap(), parent_files));
    }

    replace_panic_hook();

    // Before closing anything, sever the only inherited signal-to-FD edge.
    // Remaining HUP/USR handlers touch only copied numeric atomics. No worker
    // entry installs parent handlers or accesses abandoned parent FD owners.
    crate::signals::SIGNAL_WAKE_WRITE.store(-1, Ordering::Release);
    // SAFETY: fixed scalar dispositions, with all affected signals blocked.
    unsafe {
        if helper {
            for number in [2, 13, 14, 15] {
                if signal(number, 1) == usize::MAX {
                    _exit(5);
                }
            }
            if signal(17, 0) == usize::MAX {
                _exit(5);
            }
        } else {
            for number in [2, 13, 15] {
                if signal(number, 0) == usize::MAX {
                    _exit(5);
                }
            }
        }
    }
    // These are the only parent-side File owners held by this boundary, and
    // their descriptors are still live. Drop them before the raw close sweep.
    drop(parent_files);
    if !close_other_fds(&keep) {
        // SAFETY: never unwind into or drop the abandoned parent state.
        unsafe { _exit(5) }
    }
    // Standard streams 0/1/2 stay valid for std I/O and panic/OOM paths. This
    // matches helper behavior; resolver retains three more descriptors than K.
    drop(guard);
    mask.restore();
    let status = exit_status(catch_unwind(AssertUnwindSafe(|| {
        entry(snapshot, child_files)
    })));
    // SAFETY: only this child reaches _exit; no inherited parent destructor or
    // Rust frame can run after the audited entry completes or panics.
    unsafe { _exit(status) }
}

/// Sever a copied hook before closing inherited descriptors. Taking the hook
/// moves its captures without dropping them; the child exits without running
/// those destructors. The replacement is zero-sized and touches no parent state.
pub(super) fn replace_panic_hook() {
    std::mem::forget(std::panic::take_hook());
    std::panic::set_hook(Box::new(|_| {}));
}

/// A terminating fork branch must not run an arbitrary panic payload's Drop:
/// that destructor could panic again and unwind into the inherited owner graph.
pub(super) fn exit_status(result: std::thread::Result<i32>) -> i32 {
    match result {
        Ok(status) => status,
        Err(payload) => {
            // The process immediately exits; leaking this payload is deliberate.
            std::mem::forget(payload);
            5
        }
    }
}

fn close_other_fds(keep: &[i32]) -> bool {
    fn close_range(first: u32, last: u32) -> bool {
        // SAFETY: Linux64 close_range syscall 436 uses scalar bounds and flags.
        // All six native-long argument slots are supplied. The child abandons
        // the inaccessible parent FD graph; only listed owned IPC FDs survive.
        unsafe {
            syscall(
                436,
                first as c_long,
                last as c_long,
                0 as c_long,
                0 as c_long,
                0 as c_long,
                0 as c_long,
            ) == 0
        }
    }
    let mut first = 3u32;
    for &fd in keep {
        let fd = fd as u32;
        if first < fd && !close_range(first, fd - 1) {
            return false;
        }
        first = fd + 1;
    }
    close_range(first, u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{exit_status, SignalSet};

    #[test]
    fn signal_storage_matches_linux_libc_sigset_t() {
        assert_eq!(std::mem::size_of::<SignalSet>(), 128);
        assert_eq!(
            std::mem::align_of::<SignalSet>(),
            std::mem::align_of::<usize>()
        );
    }

    #[test]
    fn terminating_branch_never_drops_a_panicking_payload() {
        struct PanicOnDrop;
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("panic payload must not unwind into the copied process state");
            }
        }
        assert_eq!(exit_status(Err(Box::new(PanicOnDrop))), 5);
        assert_eq!(exit_status(Ok(7)), 7);
    }
}
