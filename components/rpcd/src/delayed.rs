//! Delayed actions outlive rpcd's HUP re-exec, like rpcd's fork/sleep/exec.
//! Reap only our own PIDs: waitpid(-1) would race the exec worker's Child::wait.

use std::ffi::{c_char, CString};

pub const REEXEC_ENV: &str = "OWRT_RPCD_DELAYED_PIDS";

extern "C" {
    fn fork() -> i32;
    fn sleep(secs: u32) -> u32;
    fn execv(path: *const c_char, argv: *const *const c_char) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
}

#[derive(Default)]
pub struct Children {
    pids: Vec<i32>,
}

impl Children {
    /// Re-exec preserves parenthood, but not Rust memory. Carry only the PIDs
    /// through that exec, and remove the variable before spawning any work.
    pub fn inherit() -> Self {
        let saved = std::env::var(REEXEC_ENV).unwrap_or_default();
        std::env::remove_var(REEXEC_ENV);
        let mut pids: Vec<i32> = saved.split(',').filter_map(|p| p.parse().ok())
            .filter(|p| *p > 0).collect();
        pids.sort_unstable();
        pids.dedup();
        Self { pids }
    }

    pub fn reexec_pids(&self) -> String {
        self.pids.iter().map(i32::to_string).collect::<Vec<_>>().join(",")
    }

    pub fn track(&mut self, pid: i32) {
        if pid > 0 {
            self.pids.push(pid);
        }
    }

    pub fn exec(&mut self, argv: &[&str]) {
        let Ok(args) = argv.iter().map(|a| CString::new(*a)).collect::<Result<Vec<_>, _>>() else {
            return;
        };
        if args.is_empty() {
            return;
        }
        let mut ptrs: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        // SAFETY: the child only calls async-signal-safe functions with argv
        // allocated before fork. It never touches the parent's Rust locks.
        let pid = unsafe {
            let pid = fork();
            if pid == 0 {
                sleep(2);
                execv(ptrs[0], ptrs.as_ptr());
                _exit(127);
            }
            pid
        };
        self.track(pid);
    }

    pub fn reap(&mut self) {
        self.pids.retain(|pid| {
            let mut status = 0;
            // SAFETY: a positive, specifically tracked child PID and a live
            // status buffer. WNOHANG never waits in the request loop.
            let result = unsafe { waitpid(*pid, &mut status, 1) };
            result == 0 || (result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted)
        });
    }
}
