//! Existing child-setup assertions run on a standalone process main thread.
use crate::instance::Instance;
use crate::proc::{reap_any, spawn_tty, start, try_reap, SETLBF};

/// # Safety
/// The calling process must have one thread and no held application locks.
#[expect(
    unsafe_code,
    reason = "the runner must establish post-fork prerequisites"
)]
pub(super) unsafe fn run() {
    reap_any_collects_an_exited_inittab_session();
    a_child_inherits_sigpipe_ignored_like_the_c_child();
    a_piped_stdout_gets_libsetlbf_preloaded();
    an_unpiped_stdout_preserves_the_inherited_preload();
}

fn reap_any_collects_an_exited_inittab_session() {
    // No libtest worker or sibling test owns children in this process.
    #[expect(
        unsafe_code,
        reason = "standalone main verifies the terminal fork prerequisites"
    )]
    // SAFETY: run is entered by the sole process thread and holds no locks.
    let pid = unsafe { spawn_tty(&["/bin/sh".into(), "-c".into(), "exit 23".into()], "null") }
        .expect("start the actual inittab child setup");
    // Wait for this child to exit without consuming its status. The
    // production nonblocking reaper must then collect the new session.
    use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};
    waitid(
        WaitId::Pid(Pid::from_raw(pid).unwrap()),
        WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
    )
    .unwrap()
    .expect("child exit status");
    let group = rustix::process::getpgid(Pid::from_raw(pid)).unwrap();
    assert_eq!(
        group.as_raw_pid(),
        pid,
        "inittab child must lead its session"
    );
    assert_ne!(group, rustix::process::getpgrp());
    let reaped = reap_any();
    if reaped.is_none() {
        // Reap the owned child even when the regression is present.
        let _ = try_reap(pid);
    }
    assert_eq!(reaped, Some((pid, 23 << 8)));
}

/// Run `script` through start() with a piped stdout and return what it
/// printed, reaping the child.
fn run_piped(script: &str) -> Vec<String> {
    let mut i = Instance::new("one");
    i.valid = true;
    i.command = vec!["/bin/sh".into(), "-c".into(), script.into()];
    i.stdout_to_log = true;
    #[expect(
        unsafe_code,
        reason = "standalone main verifies the instance fork prerequisites"
    )]
    // SAFETY: run is entered by the sole process thread and holds no locks.
    let (pid, out, err) = unsafe { start(&i, "svc") }.expect("spawn /bin/sh");
    assert!(err.is_none(), "stderr was not asked for");
    let mut out = out.expect("stdout pipe");
    // These fixed grep/echo fixtures emit less than one pipe buffer. Wait for
    // the owned child before draining, so EOF cannot race its exit status.
    let child = rustix::process::Pid::from_raw(pid).unwrap();
    let (_, status) = rustix::process::waitpid(Some(child), rustix::process::WaitOptions::empty())
        .unwrap()
        .expect("owned child exited");
    assert_eq!(status.exit_status(), Some(0));
    let mut lines = Vec::new();
    assert!(
        !out.poll_lines(|_, line| {
            lines.push(String::from_utf8_lossy(line).into_owned());
        }),
        "fixed child output should reach EOF within one read budget"
    );
    lines
}

/// R81 F21 (second half): the C child inherits SIGPIPE ignored from
/// procd_signal(); std resets it to SIG_DFL, which this puts back.
fn a_child_inherits_sigpipe_ignored_like_the_c_child() {
    owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
    let lines = run_piped("grep SigIgn /proc/self/status");
    let mask = lines
        .iter()
        .find_map(|l| l.strip_prefix("SigIgn:"))
        .map(|h| u64::from_str_radix(h.trim(), 16).expect("hex mask"))
        .expect("SigIgn line");
    let bit = 1u64 << (owrt_ubus::sys::SIGPIPE - 1);
    assert_ne!(mask & bit, 0, "SIGPIPE not ignored: {mask:#x}");
}

/// R81 F22: `setlbf = _stdout >= 0` -- a piped stdout gets the preload.
fn a_piped_stdout_gets_libsetlbf_preloaded() {
    let lines = run_piped("echo LD_PRELOAD=$LD_PRELOAD");
    let want = format!("LD_PRELOAD={SETLBF}");
    assert!(lines.iter().any(|l| l == &want), "{lines:?}");
}

fn an_unpiped_stdout_preserves_the_inherited_preload() {
    use std::os::unix::ffi::OsStrExt;
    let directory = std::env::temp_dir().join(format!("procd-unpiped-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let output = directory.join("environment");
    let mut i = Instance::new("one");
    i.valid = true;
    i.command = vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf %s \"$LD_PRELOAD\" > \"$1\"".into(),
        "preload-test".into(),
        output.to_str().unwrap().into(),
    ];
    #[expect(
        unsafe_code,
        reason = "standalone main verifies the instance fork prerequisites"
    )]
    // SAFETY: run is entered by the sole process thread and holds no locks.
    let (pid, out, err) = unsafe { start(&i, "svc") }.expect("start unpiped child");
    assert!(out.is_none() && err.is_none());
    let child = rustix::process::Pid::from_raw(pid).unwrap();
    let (_, status) = rustix::process::waitpid(Some(child), rustix::process::WaitOptions::empty())
        .unwrap()
        .expect("owned child exited");
    assert_eq!(status.exit_status(), Some(0));
    let inherited = std::env::var_os("LD_PRELOAD").unwrap_or_default();
    assert_eq!(std::fs::read(&output).unwrap(), inherited.as_bytes());
    std::fs::remove_dir_all(directory).unwrap();
}
