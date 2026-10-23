//! Main-thread process operations with a fresh Linux single-thread check.
//!
//! An owner identifies its acquiring process and thread; it does not prevent
//! later thread creation. Every operation blocks signals and asks the kernel
//! to verify exclusive address-space ownership before touching global state.
//! The guard does not establish the separate memory, callback or descriptor
//! invariants required by a fork worker.

use std::ffi::{c_char, c_int, c_long, CString, OsStr};
use std::io;
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt;
use std::rc::Rc;

// Linux rt_sigprocmask uses the kernel's 64-signal mask, not libc sigset_t.
// Going directly to the kernel also blocks libc's reserved thread signals.
#[cfg(target_arch = "aarch64")]
const RT_SIGPROCMASK: c_long = 135;
#[cfg(target_arch = "x86_64")]
const RT_SIGPROCMASK: c_long = 14;
const SIG_BLOCK: c_long = 0;
const SIG_SETMASK: c_long = 2;
const CLONE_VM: c_int = 0x100;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn unshare(flags: c_int) -> c_int;
    fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    fn unsetenv(name: *const c_char) -> c_int;
    fn _exit(status: c_int) -> !;
}

/// Process identity for guarded operations from the daemon's main thread.
///
/// This value cannot be sent or shared with another thread. It remains usable
/// after a joined thread exits, but every operation rejects a currently shared
/// address space. A child process must acquire its own owner after a fork.
#[derive(Debug)]
pub struct ProcessOwner {
    pid: u32,
    tid: u32,
    not_send_sync: PhantomData<Rc<()>>,
}

impl ProcessOwner {
    /// Acquire an owner after checking the current process and signal context.
    ///
    /// # Errors
    ///
    /// Returns an error outside the main thread, while another thread or process
    /// shares this address space, or when the kernel refuses the check. No `/proc`
    /// mount is required. A successful check does not forbid future threads.
    pub fn acquire() -> io::Result<Self> {
        let owner = Self {
            pid: rustix::process::getpid().as_raw_nonzero().get() as u32,
            tid: rustix::thread::gettid().as_raw_nonzero().get() as u32,
            not_send_sync: PhantomData,
        };
        // SAFETY: this preflight executes no callback or thread creation and
        // immediately restores its signal mask; no permanent proof is retained.
        drop(unsafe { owner.enter()? });
        Ok(owner)
    }

    /// Set an environment variable while no other thread can access it.
    ///
    /// # Errors
    ///
    /// Rejects empty names, `=` in names, and interior NUL bytes. Also returns
    /// the error from acquiring the temporary guard or updating the environment.
    pub fn set_var(&self, name: &OsStr, value: &OsStr) -> io::Result<()> {
        // Allocation and argument conversion happen before the critical section.
        let name = environment_name(name)?;
        let value = CString::new(value.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "environment value contains NUL",
            )
        })?;
        // SAFETY: only this fixed libc operation runs before the guard drops;
        // it cannot invoke a caller-provided Rust callback or create a thread.
        let _guard = unsafe { self.enter()? };
        // SAFETY: both strings are terminated and live. The guard excludes
        // concurrent threads and signal handlers that could access environ.
        if unsafe { setenv(name.as_ptr(), value.as_ptr(), 1) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Remove an environment variable under a fresh single-thread guard.
    ///
    /// # Errors
    ///
    /// Rejects empty names, `=` in names, and interior NUL bytes. Also returns
    /// the error from acquiring the temporary guard or updating the environment.
    pub fn remove_var(&self, name: &OsStr) -> io::Result<()> {
        let name = environment_name(name)?;
        // SAFETY: no callback or thread creation occurs during this operation.
        let _guard = unsafe { self.enter()? };
        // SAFETY: name is terminated and live; the guard excludes concurrent
        // threads and signal handlers that could access environ.
        if unsafe { unsetenv(name.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Block signals and verify exclusive address-space ownership for an operation.
    ///
    /// # Errors
    ///
    /// Rejects a different process or thread, non-main threads, shared address
    /// spaces, and denied kernel checks. Failure restores the previous mask.
    ///
    /// # Safety
    ///
    /// Until the guard is dropped, execute only reviewed operations that cannot
    /// create threads, restore signal delivery early, or invoke unreviewed code
    /// (including callbacks, allocator hooks and destructors). Do not retain the
    /// guard as proof across arbitrary application code. Fork operations must
    /// separately establish their worker, inherited-memory, signal/panic-hook,
    /// atfork and descriptor-ownership requirements; this guard proves none of
    /// those properties. Drop the guard on the entering thread.
    pub unsafe fn enter(&self) -> io::Result<SingleThreadGuard<'_>> {
        let mut previous = 0u64;
        let all = u64::MAX;
        signal_mask(SIG_BLOCK, &all, Some(&mut previous))?;
        let guard = SingleThreadGuard {
            previous,
            _owner: self,
            not_send_sync: PhantomData,
        };
        let pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
        let tid = rustix::thread::gettid().as_raw_nonzero().get() as u32;
        if pid != self.pid || tid != self.tid || pid != tid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // SAFETY: CLONE_VM alone is a no-op on the supported Linux kernels
        // when mm/signal state is unshared; check_unshare_flags rejects shared
        // state instead of changing it. No namespace or FD-table flag is set.
        // Once it succeeds, only this thread can create another user thread;
        // all signal delivery is blocked until the guard is dropped.
        if unsafe { unshare(CLONE_VM) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(guard)
    }
}

/// A temporary single-thread check and blocked signal mask for platform code.
///
/// Dropping this guard restores the complete previous kernel signal mask. A
/// restoration failure terminates the process with status 5; continuing with
/// an unknown mask would conceal a broken process boundary.
#[must_use = "the signal mask is restored when the guard is dropped"]
#[derive(Debug)]
pub struct SingleThreadGuard<'a> {
    previous: u64,
    // Tie the guard to the identity whose operation it protects.
    _owner: &'a ProcessOwner,
    not_send_sync: PhantomData<Rc<()>>,
}

impl SingleThreadGuard<'_> {
    /// Capture the mask an exec child must restore after its fixed setup hook.
    ///
    /// The parent retains its guard until `Command::spawn` returns. The child's
    /// final pre-exec operation restores this mask so the executed program does
    /// not inherit the guard's temporary signal blocking.
    pub fn child_mask(&self) -> ChildSignalMask {
        ChildSignalMask(self.previous)
    }
}

/// An immutable signal-mask snapshot for a fixed platform pre-exec hook.
#[derive(Clone, Copy, Debug)]
pub struct ChildSignalMask(u64);

impl ChildSignalMask {
    /// Restore the spawning thread's original mask in the exec child.
    ///
    /// # Errors
    ///
    /// Returns the kernel error if mask restoration fails. The platform hook
    /// must propagate it to abort the spawn before exec. Calling this in the
    /// parent while its guard is active violates [`ProcessOwner::enter`]'s
    /// requirement to keep signal delivery blocked throughout the operation.
    pub fn restore(&self) -> io::Result<()> {
        signal_mask(SIG_SETMASK, &self.0, None)
    }
}

impl Drop for SingleThreadGuard<'_> {
    fn drop(&mut self) {
        if signal_mask(SIG_SETMASK, &self.previous, None).is_err() {
            // SAFETY: a failed restoration cannot unwind into application code
            // with an unknown signal mask. _exit runs no Rust destructors.
            unsafe { _exit(5) }
        }
    }
}

fn environment_name(name: &OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&b'=') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "environment name is empty or contains '='",
        ));
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "environment name contains NUL"))
}

fn signal_mask(how: c_long, set: &u64, previous: Option<&mut u64>) -> io::Result<()> {
    let previous = previous.map_or(std::ptr::null_mut(), |mask| mask as *mut u64);
    // SAFETY: the kernel reads one initialized 64-bit mask. The private callers
    // pass either one writable u64 for the old mask or NULL. Six native syscall
    // argument slots are supplied; the kernel ignores SIGKILL/SIGSTOP mask bits.
    let result = unsafe {
        syscall(
            RT_SIGPROCMASK,
            how,
            set as *const u64,
            previous,
            std::mem::size_of::<u64>() as c_long,
            0 as c_long,
            0 as c_long,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
