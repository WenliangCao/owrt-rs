//! Existing procd process transitions and fixed child setup hooks.
//! No generic captured callback or replacement fork/exec model is introduced.
use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

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

/// Install the instance's cgroup, scheduling and credential setup before exec.
///
/// # Safety
/// The caller must uphold `CommandExt::pre_exec`'s requirements when spawning
/// this command, including for `warning`, `apply_limit`, and NSS group lookup.
/// No inherited lock may be held and all post-fork operations must be valid in
/// the child. A noncapturing function pointer alone does not ensure this.
pub unsafe fn configure_instance(
    command: &mut Command,
    setup: InstanceSetup,
    warning: fn(&str, &io::Error),
    apply_limit: fn(&str, &str) -> io::Result<()>,
) {
    // SAFETY: this is the existing owned instance setup, not a general child
    // hook API. Its fixed caller supplies owned strings/scalars and no parent
    // lock/stdio guard. libc credential/NSS semantics are preserved.
    unsafe {
        command.pre_exec(move || {
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
            Ok(())
        });
    }
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

/// Install the inittab session and terminal setup before exec.
///
/// # Safety
/// The caller must uphold `CommandExt::pre_exec`'s post-fork requirements when
/// spawning the command, including every operation performed by `patch`.
pub unsafe fn configure_tty(
    command: &mut Command,
    device: Option<String>,
    patch: fn(Option<&str>, i32, bool) -> bool,
) {
    // SAFETY: preserve the existing single-threaded child setup and ordering;
    // only this owned device name and the fixed patch function are captured.
    unsafe {
        command.pre_exec(move || {
            let _ = rustix::process::setsid();
            patch(device.as_deref(), 0, false);
            patch(device.as_deref(), 1, true);
            patch(device.as_deref(), 2, true);
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

/// Fork a firmware worker that exits after running `entry`.
///
/// # Safety
/// The process must be single-threaded at the fork. `input`, `entry`, and their
/// destructors must not depend on parent locks or share mutable memory with the
/// parent. The child must not unwind back into inherited application state.
pub unsafe fn spawn_firmware<T: Send + 'static>(input: T, entry: fn(T)) -> Option<i32> {
    unsafe extern "C" {
        fn fork() -> i32;
    }
    // SAFETY: preserve procd's audited single-threaded firmware fork. No
    // captured parent owner is exposed; the child does not return to its caller.
    match unsafe { fork() } {
        0 => {
            entry(input);
            std::process::exit(1);
        }
        pid if pid > 0 => Some(pid),
        _ => None,
    }
}

pub fn halt_forever(event: i32) -> ! {
    unsafe extern "C" {
        fn fork() -> i32;
    }
    // SAFETY: unchanged PID1 shutdown fork: parent remains alive forever;
    // child only requests reboot then exits, preserving the existing model.
    if unsafe { fork() } == 0 {
        reboot_cmd(event);
        std::process::exit(0);
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
