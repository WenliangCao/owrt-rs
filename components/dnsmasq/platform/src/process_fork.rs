//! Restricted workers for this fixed dnsmasq application, not a general fork API.
//!
//! The two callers pass only owned Config/scalar or Vec<ServerRule> snapshots.
//! Send + 'static and noncapturing fn are interface bounds, not a proof of
//! ownership or fork safety. The actual production owner is single-threaded;
//! the audited call graph has no shared writable mmap, external atfork callback
//! or held lock/stdio guard which either worker reacquires. These are this
//! application's premises, as in K, not new runtime proof gates. Changes to
//! these callers or dependencies must review them. libc fork retains libc's
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

/// Only helper::process's audited pure-data startup snapshot/entry may call
/// this application boundary. Return the original snapshot, PID, command
/// writer and event reader to the parent; the child receives its own copies.
///
/// # Safety
///
/// The process must be single-threaded, with no shared writable mappings or
/// application atfork callbacks. Neither the snapshot nor the child entry may
/// access inherited descriptor owners, locks or parent state. The entry may
/// use only its owned snapshot, the supplied pipes and valid standard streams.
/// In particular, `Send` does not prove that a snapshot is safe to duplicate.
/// Any inherited signal handler or panic hook reachable by the child must also
/// avoid abandoned parent descriptor owners, shared state and held locks. The
/// panic hook runs before `catch_unwind` can catch the payload.
pub unsafe fn spawn_helper<T: Send + 'static>(
    snapshot: T,
    entry: fn(T, File, File) -> i32,
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
    // SAFETY: the caller supplies the process and snapshot guarantees above;
    // both pipe pairs are fresh, disjoint owners created in this function.
    let ((snapshot, _), pid, [command_writer, event_reader]) = unsafe {
        fork_worker(
            (snapshot, entry),
            [File::from(commands), File::from(events)],
            [File::from(command_writer), File::from(event_reader)],
            enter::<T>,
            true,
            mask,
        )
    }?;
    Ok((snapshot, pid, command_writer, event_reader))
}

/// Only config::dns::lookup's owned (Vec<ServerRule>, bool) snapshot and fixed
/// resolver entry may call this boundary. No input encoding or extra request
/// pipe is needed; the parent's original rules remain available for decoding.
///
/// # Safety
///
/// The process, snapshot and entry must meet [`spawn_helper`]'s requirements.
/// Only the supplied result writer and valid standard streams remain open in
/// the child; the snapshot must not contain any descriptor owner or borrower.
pub unsafe fn spawn_lookup<T: Send + 'static>(
    snapshot: T,
    entry: fn(T, File) -> i32,
) -> io::Result<(T, Pid, File)> {
    let mask = SignalMask::block()?;
    let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    nonblocking(&reader)?;
    fn enter<T>((snapshot, entry): (T, fn(T, File) -> i32), [writer]: [File; 1]) -> i32 {
        entry(snapshot, writer)
    }
    // SAFETY: the caller supplies the process and snapshot guarantees above;
    // the result pipe has fresh, distinct descriptor owners.
    let ((snapshot, _), pid, [reader]) = unsafe {
        fork_worker(
            (snapshot, entry),
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
    let mut keep = child_files.each_ref().map(AsRawFd::as_raw_fd);
    keep.sort_unstable();
    if keep.iter().any(|fd| *fd <= 2) || parent_files.iter().any(|fd| fd.as_raw_fd() <= 2) {
        return Err(io::Error::other(
            "worker requires valid inherited standard streams",
        ));
    }
    // SAFETY: these two audited entries run from the fixed production owner,
    // with the single-thread/no-shared-mapping/no-held-lock premises above.
    // Daemon signals are blocked. libc fork preserves libc/TLS bookkeeping.
    // Only the parent returns to its graph; the child owns its copied pure
    // snapshot and terminates inside this boundary. This is not a generic
    // guarantee supplied by T: Send or the function-pointer type.
    let pid = unsafe { fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        drop(child_files);
        mask.restore();
        return Ok((snapshot, Pid::from_raw(pid).unwrap(), parent_files));
    }

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
    mask.restore();
    let status = exit_status(catch_unwind(AssertUnwindSafe(|| {
        entry(snapshot, child_files)
    })));
    // SAFETY: only this child reaches _exit; no inherited parent destructor or
    // Rust frame can run after the audited entry completes or panics.
    unsafe { _exit(status) }
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
