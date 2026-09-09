//! R81 procd audit: executable demonstrations of two findings. Not run
//! (no cargo on the audit host); each test is self-contained and needs no
//! root, no sockets, no router.
//!
//! F1: `eprintln!` on a non-blocking stderr panics on EAGAIN. procd-rs's
//! `sys::set_stdio()` sets O_NONBLOCK on fd 2 as PID 1 (sys.rs:561-566) and
//! the binary then logs everything through `eprintln!`; with
//! `panic = "abort"` (components/procd/Cargo.toml) that is a PID 1 abort.
//!
//! F2: `Instance::take_config()` (instance.rs:284-325) does `*self = new`
//! without carrying `log_out`/`log_err`, so the running child's pipe read
//! ends are closed on every `service set`. This test is meant to be pasted
//! into `components/procd/src/instance.rs`'s test module (it needs
//! `Instance` and `proc::LogPipe`); it is kept here as the patch text.

extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    fn dup2(old: i32, new: i32) -> i32;
    fn dup(fd: i32) -> i32;
}
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;

/// F1. Fill a non-blocking pipe, point fd 2 at its write end, and show that
/// `eprintln!` panics ("failed printing to stderr") instead of dropping the
/// line. This is exactly the state PID 1 is in after set_stdio("console")
/// once the serial console stops draining (XOFF, or >4 KiB burst at 115200).
#[test]
fn r81_eprintln_panics_on_a_full_nonblocking_stderr() {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let (r, w) = (fds[0], fds[1]);
    unsafe {
        let fl = fcntl(w, F_GETFL);
        assert!(fcntl(w, F_SETFL, fl | O_NONBLOCK) >= 0);
        // Fill the pipe until EAGAIN.
        let junk = [b'x'; 4096];
        loop {
            if write(w, junk.as_ptr(), junk.len()) < 0 {
                break;
            }
        }
    }
    let saved = unsafe { dup(2) };
    assert!(saved >= 0);
    assert!(unsafe { dup2(w, 2) } >= 0);

    let res = std::panic::catch_unwind(|| {
        eprintln!("procd: - init -");
    });

    unsafe {
        dup2(saved, 2);
    }
    let _ = r;
    assert!(
        res.is_err(),
        "eprintln! on an O_NONBLOCK stderr that returns EAGAIN must panic for this finding to hold"
    );
}

// F2 (patch for components/procd/src/instance.rs `mod tests`):
//
// #[test]
// fn take_config_must_keep_the_running_childs_log_pipes() {
//     use std::os::fd::AsRawFd;
//     let (r, _w) = owrt_ubus::sys::pipe().unwrap();
//     let raw = r.as_raw_fd();
//     let mut live = Instance::new("a");
//     live.valid = true;
//     live.command = vec!["/bin/true".into()];
//     live.state = Run::Running;
//     live.pid = 12345;
//     live.log_out = Some(crate::proc::LogPipe::new(r, crate::sys::LOG_INFO).unwrap());
//
//     let mut fresh = Instance::new("a");
//     fresh.valid = true;
//     fresh.command = vec!["/bin/true".into()];
//     live.take_config(fresh);
//
//     // The C's instance_config_move never touches in->_stdout/_stderr.
//     assert!(live.log_out.is_some(), "log pipe dropped by take_config");
//     // And the fd must still be open (fcntl succeeds), i.e. not closed.
//     extern "C" { fn fcntl(fd: i32, cmd: i32, ...) -> i32; }
//     assert!(unsafe { fcntl(raw, 1 /* F_GETFD */) } >= 0, "read end was closed");
// }
