//! Existing procd process transitions and fixed child setup hooks.
//! No generic captured callback or replacement fork/exec model is introduced.
use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

use crate::process_owner::ProcessOwner;

pub fn inherit_ignored_sigpipe(command: &mut Command) {
    unsafe extern "C" {
        fn signal(number: i32, handler: usize) -> usize;
    }
    // SAFETY: fixed pre_exec only restores SIGPIPE=SIG_IGN; no allocation or
    // user callback occurs in this small hook, preserving the old model.
    unsafe {
        command.pre_exec(|| {
            signal(13, 1);
            Ok(())
        });
    }
}

pub struct InstanceSetup {
    pub cgroup: Option<CString>,
    pub cgroup_warning: String,
    pub nice: i32,
    pub limits: std::collections::BTreeMap<String, String>,
    pub user_groups: Option<(String, u32)>,
    pub gid: Option<u32>,
    pub uid: Option<u32>,
}

/// The fixed firmware worker's owned input, with no borrowed parent state.
#[derive(Debug)]
pub struct FirmwareRequest {
    pub directory: String,
    pub variables: std::collections::BTreeMap<String, String>,
}

/// Audited procd process operations bound to fixed startup callbacks.
pub struct Process {
    owner: ProcessOwner,
    warning: fn(&str, &io::Error),
    apply_limit: fn(&str, &str) -> io::Result<()>,
    firmware: fn(FirmwareRequest),
}

impl Process {
    /// Register procd's fixed child operations from its platform startup adapter.
    ///
    /// # Safety
    /// Every callback must be valid after a checked single-threaded fork for
    /// every possible argument. It must not create threads, access abandoned
    /// parent descriptor owners or shared mutable mappings, run arbitrary user
    /// callbacks, or unwind out of child setup. Captured data is restricted to
    /// the owned fields of `InstanceSetup` and `FirmwareRequest`. Throughout
    /// this capability's lifetime, application atfork handlers, signal handlers,
    /// allocator/runtime hooks and NSS providers must not create threads during
    /// a guarded operation or access parent-only mutable/shared state in a child.
    /// No application-owned lock may be held across an operation when a fixed
    /// callback could access that lock. Child panic hooks are replaced without
    /// running or dropping the inherited hook before any registered callback.
    pub unsafe fn new(
        owner: ProcessOwner,
        warning: fn(&str, &io::Error),
        apply_limit: fn(&str, &str) -> io::Result<()>,
        firmware: fn(FirmwareRequest),
    ) -> Self {
        Self {
            owner,
            warning,
            apply_limit,
            firmware,
        }
    }

    /// The process environment owner; each mutation rechecks kernel exclusivity.
    pub fn owner(&self) -> &ProcessOwner {
        &self.owner
    }

    /// Spawn a command with the registered cgroup, scheduling and identity setup.
    ///
    /// A configured command cannot escape this operation. The checked process
    /// guard remains live from hook registration through the actual spawn.
    pub fn spawn_instance(&self, mut command: Command, setup: InstanceSetup) -> io::Result<Child> {
        if std::thread::panicking() {
            return Err(io::Error::other("cannot spawn instance while unwinding"));
        }
        // SAFETY: only the fixed callbacks registered under new's contract run
        // while exclusivity is held. No command or hook escapes to a caller.
        let guard = unsafe { self.owner.enter()? };
        let child_mask = guard.child_mask();
        let warning = self.warning;
        let apply_limit = self.apply_limit;
        // SAFETY: kernel-checked single-thread ownership and the registered
        // callbacks uphold the inherited post-fork operation requirements.
        unsafe {
            command.pre_exec(move || {
                exit_on_child_panic(127);
                if let Some(group) = &setup.cgroup {
                    if let Err(error) = cgroup_add_self(group) {
                        warning(&setup.cgroup_warning, &error);
                    }
                }
                if setup.nice != 0 {
                    let _ = rustix::process::setpriority_process(None, setup.nice);
                }
                for (name, value) in &setup.limits {
                    let _ = apply_limit(name, value);
                }
                if let Some((user, gid)) = &setup.user_groups {
                    if !super::identity::init_groups(user, *gid) {
                        return Err(io::Error::other("initgroups failed"));
                    }
                }
                if let Some(gid) = setup.gid {
                    super::identity::set_gid(gid)?;
                }
                if let Some(uid) = setup.uid {
                    super::identity::set_uid(uid)?;
                }
                child_mask.restore()
            });
        }
        command.spawn()
    }

    /// Fork the registered firmware worker, always terminating its child.
    pub fn spawn_firmware(&self, request: FirmwareRequest) -> io::Result<i32> {
        unsafe extern "C" {
            fn fork() -> i32;
            fn _exit(status: i32) -> !;
        }
        if std::thread::panicking() {
            return Err(io::Error::other(
                "cannot fork firmware worker while unwinding",
            ));
        }
        // SAFETY: the fixed callback is registered under new's requirements;
        // the argument owns only strings and a map, never parent resources.
        let guard = unsafe { self.owner.enter()? };
        // SAFETY: the guard checks exclusivity with all signals blocked and
        // remains live across fork; neither branch leaks inherited Rust frames.
        match unsafe { fork() } {
            0 => {
                exit_on_child_panic(1);
                drop(guard);
                (self.firmware)(request);
                // SAFETY: this child never returns or runs inherited atexit
                // callbacks, including when the fixed worker panics.
                unsafe { _exit(1) }
            }
            pid if pid > 0 => Ok(pid),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

// Called only after a checked sole-thread fork and before application work.
// The previous hook can capture parent resources; neither call nor drop it.
fn exit_on_child_panic(status: i32) {
    std::mem::forget(std::panic::take_hook());
    std::panic::set_hook(Box::new(move |_| {
        unsafe extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: terminate this child immediately without inherited teardown.
        unsafe { _exit(status) }
    }));
}

fn cgroup_add_self(dir: &CStr) -> io::Result<()> {
    let bytes = dir.to_bytes();
    if bytes.len() + 14 > 272 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut buffer = [0u8; 272];
    for (i, byte) in bytes.iter().enumerate() {
        buffer[i] = *byte;
        let last = i + 1 == bytes.len();
        if (*byte == b'/' && i > 0) || last {
            let mut part = buffer;
            let end = if last { i + 1 } else { i };
            part[end] = 0;
            let part = CStr::from_bytes_with_nul(&part[..=end])
                .map_err(|_| io::ErrorKind::InvalidInput)?;
            match rustix::fs::mkdirat(
                rustix::fs::CWD,
                part,
                rustix::fs::Mode::from_raw_mode(0o700),
            ) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    let tail = b"/cgroup.procs\0";
    buffer[bytes.len()..bytes.len() + tail.len()].copy_from_slice(tail);
    let path = CStr::from_bytes_with_nul(&buffer[..bytes.len() + tail.len()])
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    let file = rustix::fs::open(path, rustix::fs::OFlags::WRONLY, rustix::fs::Mode::empty())?;
    let mut pid = rustix::process::getpid().as_raw_pid();
    let mut digits = [0u8; 12];
    let mut start = digits.len();
    while pid > 0 {
        start -= 1;
        digits[start] = b'0' + (pid % 10) as u8;
        pid /= 10;
    }
    rustix::io::write(&file, &digits[start..])?;
    Ok(())
}

/// Install fixed inittab session and terminal setup before exec.
/// All path conversion occurs in the parent; the hook uses only system calls.
pub fn configure_tty(command: &mut Command, device: Option<&str>) {
    let path = match device {
        None => "/dev/null".to_owned(),
        Some(path) if path.starts_with('/') => path.to_owned(),
        Some(name) => format!("/dev/{name}"),
    };
    let path = CString::new(path).ok();
    // SAFETY: the child borrows an owned terminated path and performs only
    // setsid/open/dup2/close/ioctl/tcsetpgrp. No allocation or callback occurs.
    unsafe {
        command.pre_exec(move || {
            let _ = rustix::process::setsid();
            if let Some(path) = &path {
                patch_standard(path, 0, false);
                patch_standard(path, 1, true);
                patch_standard(path, 2, true);
            }
            // TIOCSCTTY takes the scalar force flag 1, not a pointer payload.
            let _ = rustix::ioctl::ioctl(
                rustix::stdio::stdin(),
                rustix::ioctl::IntegerSetter::<0x540e>::new_usize(1),
            );
            let _ = rustix::termios::tcsetpgrp(rustix::stdio::stdin(), rustix::process::getpid());
            Ok(())
        });
    }
}

fn patch_standard(path: &CStr, target: i32, write: bool) {
    use std::os::fd::{AsRawFd, IntoRawFd};
    let flags = (if write {
        rustix::fs::OFlags::WRONLY
    } else {
        rustix::fs::OFlags::RDONLY
    }) | rustix::fs::OFlags::NOCTTY;
    let file = rustix::fs::open(path, flags, rustix::fs::Mode::empty()).or_else(|error| {
        if path != c"/dev/null" {
            rustix::fs::open(c"/dev/null", flags, rustix::fs::Mode::empty())
        } else {
            Err(error)
        }
    });
    let Ok(file) = file else { return };
    match target {
        0 => {
            let _ = rustix::stdio::dup2_stdin(&file);
        }
        1 => {
            let _ = rustix::stdio::dup2_stdout(&file);
        }
        2 => {
            let _ = rustix::stdio::dup2_stderr(&file);
        }
        _ => return,
    }
    // An open which filled an already closed stdio slot must remain attached.
    if file.as_raw_fd() <= 2 {
        let _ = file.into_raw_fd();
    }
}

pub fn send_signal(pid: i32, number: i32) -> io::Result<()> {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    // SAFETY: scalar libc interface preserves signal 0, invalid-signal errors
    // and negative-PID broadcast semantics not represented by typed Signal.
    if unsafe { kill(pid, number) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn execvp(program: &CStr, args: &[CString]) -> io::Error {
    unsafe extern "C" {
        fn execvp(file: *const std::ffi::c_char, argv: *const *const std::ffi::c_char) -> i32;
    }
    let mut pointers: Vec<_> = args.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // SAFETY: all argv strings and the terminated pointer array remain owned
    // and live until exec succeeds or returns errno. No raw pointer escapes.
    unsafe {
        execvp(program.as_ptr(), pointers.as_ptr());
    }
    io::Error::last_os_error()
}

pub fn halt_forever(event: i32) -> ! {
    unsafe extern "C" {
        fn fork() -> i32;
        fn _exit(status: i32) -> !;
    }
    // SAFETY: unchanged PID1 shutdown fork: parent remains alive forever;
    // child only requests reboot then exits, preserving the existing model.
    if unsafe { fork() } == 0 {
        reboot_cmd(event);
        // SAFETY: a forked shutdown child must not run inherited atexit hooks
        // or Rust/libc teardown which may depend on vanished parent threads.
        unsafe { _exit(0) }
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

pub fn reboot_cmd(command: i32) -> bool {
    use rustix::system::RebootCommand;
    let command = match command {
        0 => RebootCommand::CadOff,
        0x01234567 => RebootCommand::Restart,
        value if value == 0xcdef0123u32 as i32 => RebootCommand::Halt,
        0x4321fedc => RebootCommand::PowerOff,
        _ => return false,
    };
    rustix::system::reboot(command).is_ok()
}
