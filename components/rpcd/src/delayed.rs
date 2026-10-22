//! Delayed actions outlive rpcd's HUP re-exec, like rpcd's fork/sleep/exec.
//! Reap only our own PIDs: waitpid(-1) would race the exec worker's Child::wait.

use std::ffi::CString;

pub const REEXEC_ENV: &str = "OWRT_RPCD_DELAYED_PIDS";

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
        let mut pids: Vec<i32> = saved
            .split(',')
            .filter_map(|p| p.parse().ok())
            .filter(|p| *p > 0)
            .collect();
        pids.sort_unstable();
        pids.dedup();
        Self { pids }
    }

    pub fn reexec_pids(&self) -> String {
        self.pids
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn track(&mut self, pid: i32) {
        if pid > 0 {
            self.pids.push(pid);
        }
    }

    pub fn exec(&mut self, argv: &[&str]) {
        let Ok(args) = argv
            .iter()
            .map(|a| CString::new(*a))
            .collect::<Result<Vec<_>, _>>()
        else {
            return;
        };
        if args.is_empty() {
            return;
        }
        let pid = owrt_platform::rpcd::delayed_exec(&args);
        self.track(pid);
    }

    pub fn reap(&mut self) {
        self.pids.retain(|pid| {
            matches!(
                rustix::process::waitpid(
                    rustix::process::Pid::from_raw(*pid),
                    rustix::process::WaitOptions::NOHANG
                ),
                Ok(None) | Err(rustix::io::Errno::INTR)
            )
        });
    }
}
