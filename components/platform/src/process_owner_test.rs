//! Standalone process-owner checks; no libtest worker threads may run here.

use owrt_platform::process_owner::ProcessOwner;
use std::ffi::{c_long, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;

#[cfg(target_arch = "aarch64")]
const RT_SIGPROCMASK: c_long = 135;
#[cfg(target_arch = "x86_64")]
const RT_SIGPROCMASK: c_long = 14;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

fn read_mask() -> u64 {
    let mut previous = 0u64;
    // SAFETY: NULL leaves the mask unchanged; previous covers the kernel's
    // eight-byte result. Only scalar arguments and initialized storage cross FFI.
    let result = unsafe {
        syscall(
            RT_SIGPROCMASK,
            2 as c_long,
            std::ptr::null::<u64>(),
            &mut previous as *mut u64,
            8 as c_long,
            0 as c_long,
            0 as c_long,
        )
    };
    assert_eq!(result, 0, "reading the kernel signal mask failed");
    previous
}

fn replace_mask(mask: u64) {
    // SAFETY: this standalone runner has one thread and calls only reviewed
    // checks while the fixture mask is installed. Its original mask is restored.
    let result = unsafe {
        syscall(
            RT_SIGPROCMASK,
            2 as c_long,
            &mask as *const u64,
            std::ptr::null_mut::<u64>(),
            8 as c_long,
            0 as c_long,
            0 as c_long,
        )
    };
    assert_eq!(result, 0, "installing the fixture signal mask failed");
}

fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(OsStr::new("--print-mask")) {
        println!("{}", read_mask());
        return;
    }
    let original_mask = read_mask();
    // Exercise exact restoration of a non-default mask, including a realtime
    // signal; the guard must restore rather than simply unblock everything.
    let fixture_mask = original_mask | (1 << (10 - 1)) | (1 << (40 - 1));
    replace_mask(fixture_mask);

    let owner = ProcessOwner::acquire().expect("single main thread must acquire an owner");
    assert_eq!(read_mask(), fixture_mask);
    // SAFETY: only a raw mask query runs in this scope. No thread or callback
    // is started, and the guard is dropped before the remaining tests execute.
    let guard = unsafe { owner.enter() }.unwrap();
    let during = read_mask();
    drop(guard);
    // Linux does not allow SIGKILL (9) or SIGSTOP (19) to be blocked.
    assert_eq!(during, u64::MAX & !(1 << (9 - 1)) & !(1 << (19 - 1)));
    assert_eq!(read_mask(), fixture_mask);

    let name = OsStr::new("OWRT_PROCESS_OWNER_REGRESSION_20261023");
    owner.remove_var(name).unwrap();
    let value = OsStr::from_bytes(b"non-UTF8-\xff");
    owner.set_var(name, value).unwrap();
    assert_eq!(std::env::var_os(name).as_deref(), Some(value));
    assert_eq!(read_mask(), fixture_mask);

    for name in [
        OsStr::new(""),
        OsStr::new("a=b"),
        OsStr::from_bytes(b"a\0b"),
    ] {
        assert_eq!(
            owner.set_var(name, value).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            owner.remove_var(name).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(
        owner
            .set_var(name, OsStr::from_bytes(b"a\0b"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(std::env::var_os(name).as_deref(), Some(value));

    let (ready_tx, ready_rx) = mpsc::sync_channel(0);
    let (stop_tx, stop_rx) = mpsc::sync_channel(0);
    let thread = std::thread::spawn(move || {
        let denied = ProcessOwner::acquire().unwrap_err().kind();
        ready_tx.send(denied).unwrap();
        stop_rx.recv().unwrap();
    });
    assert_eq!(ready_rx.recv().unwrap(), io::ErrorKind::PermissionDenied);
    assert!(ProcessOwner::acquire().is_err());
    assert!(owner.set_var(name, OsStr::new("must-not-replace")).is_err());
    assert!(owner.remove_var(name).is_err());
    assert_eq!(std::env::var_os(name).as_deref(), Some(value));
    assert_eq!(
        read_mask(),
        fixture_mask,
        "rejected operations must restore their mask"
    );
    stop_tx.send(()).unwrap();
    thread.join().unwrap();

    // A credential is not invalidated permanently by transient thread creation.
    // pthread_join can observe cleared child_tid just before the kernel removes
    // the exiting task from its thread group. Wait for that actual condition.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while ProcessOwner::acquire().is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "exited thread remains visible to the kernel"
        );
        std::thread::yield_now();
    }
    owner.set_var(name, OsStr::new("after-join")).unwrap();
    assert_eq!(
        std::env::var_os(name).as_deref(),
        Some(OsStr::new("after-join"))
    );
    owner.remove_var(name).unwrap();
    assert!(std::env::var_os(name).is_none());
    assert_eq!(read_mask(), fixture_mask);

    let mut command = Command::new(std::env::current_exe().unwrap());
    command.arg("--print-mask").stdout(Stdio::piped());
    // SAFETY: no foreign callbacks or atfork hooks are registered in this
    // runner. The only child hook is the fixed syscall below; spawn completes
    // before the parent guard drops and only then does the test wait/read.
    let guard = unsafe { owner.enter() }.unwrap();
    let child_mask = guard.child_mask();
    // SAFETY: restoring the immutable kernel mask invokes no allocation or
    // Rust callbacks. It is this test's final pre-exec operation.
    unsafe { command.pre_exec(move || child_mask.restore()) };
    let child = command.spawn();
    drop(guard);
    let output = child.unwrap().wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap(),
        fixture_mask
    );
    assert_eq!(read_mask(), fixture_mask);
    replace_mask(original_mask);
    assert_eq!(read_mask(), original_mask);
    println!("process owner: single-thread acceptance, live-thread rejection, revalidation, environment bytes, and parent/exec-child signal-mask restoration passed");
}
