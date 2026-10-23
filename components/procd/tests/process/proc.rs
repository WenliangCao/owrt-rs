//! Existing child-setup assertions run on a standalone process main thread.
#![forbid(unsafe_code)]
use crate::instance::Instance;
use crate::proc::{reap_any, spawn_tty, start, try_reap, SETLBF};

pub(super) fn run(process: &owrt_platform::procd::process::Process) {
    reap_any_collects_an_exited_inittab_session();
    a_child_inherits_sigpipe_ignored_like_the_c_child(process);
    a_piped_stdout_gets_libsetlbf_preloaded(process);
    an_unpiped_stdout_preserves_the_inherited_preload(process);
}

fn reap_any_collects_an_exited_inittab_session() {
    // No libtest worker or sibling test owns children in this process.
    let pid = spawn_tty(&["/bin/sh".into(), "-c".into(), "exit 23".into()], "null")
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
    // The runner may be PID 1 with an inherited process group outside its
    // namespace, whose ID is reported as zero. Inspect the child's session
    // directly instead of assuming the runner has a visible process group.
    assert_eq!(
        rustix::process::getsid(Pid::from_raw(pid))
            .unwrap()
            .as_raw_pid(),
        pid,
        "inittab child must create its own session"
    );
    let reaped = reap_any();
    if reaped.is_none() {
        // Reap the owned child even when the regression is present.
        let _ = try_reap(pid);
    }
    assert_eq!(reaped, Some((pid, 23 << 8)));
}

/// Run `script` through start() with a piped stdout and return what it
/// printed, reaping the child.
fn run_piped(script: &str, process: &owrt_platform::procd::process::Process) -> Vec<String> {
    let mut i = Instance::new("one");
    i.valid = true;
    i.command = vec!["/bin/sh".into(), "-c".into(), script.into()];
    i.stdout_to_log = true;
    let (pid, out, err) = start(&i, "svc", process).expect("spawn /bin/sh");
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
fn a_child_inherits_sigpipe_ignored_like_the_c_child(
    process: &owrt_platform::procd::process::Process,
) {
    owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
    let lines = run_piped("grep -E 'Sig(Ign|Blk)' /proc/self/status", process);
    let mask = lines
        .iter()
        .find_map(|l| l.strip_prefix("SigIgn:"))
        .map(|h| u64::from_str_radix(h.trim(), 16).expect("hex mask"))
        .expect("SigIgn line");
    let bit = 1u64 << (owrt_ubus::sys::SIGPIPE - 1);
    assert_ne!(mask & bit, 0, "SIGPIPE not ignored: {mask:#x}");
    let blocked = lines
        .iter()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .map(|mask| u64::from_str_radix(mask.trim(), 16).unwrap())
        .unwrap();
    let parent = std::fs::read_to_string("/proc/self/status").unwrap();
    let parent_blocked = parent
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .map(|mask| u64::from_str_radix(mask.trim(), 16).unwrap())
        .unwrap();
    assert_eq!(
        blocked, parent_blocked,
        "exec inherited the temporary guard mask"
    );
}

/// R81 F22: `setlbf = _stdout >= 0` -- a piped stdout gets the preload.
fn a_piped_stdout_gets_libsetlbf_preloaded(process: &owrt_platform::procd::process::Process) {
    let lines = run_piped("echo LD_PRELOAD=$LD_PRELOAD", process);
    let want = format!("LD_PRELOAD={SETLBF}");
    assert!(lines.iter().any(|l| l == &want), "{lines:?}");
}

fn an_unpiped_stdout_preserves_the_inherited_preload(
    process: &owrt_platform::procd::process::Process,
) {
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
    let (pid, out, err) = start(&i, "svc", process).expect("start unpiped child");
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
