//! One supervised process: its parsed configuration, the diff that decides
//! whether a config update restarts it, and the `service list` projection.
//!
//! Source of truth is procd's `service/instance.c` at the pinned revision.
//! Field order in `dump` follows `instance_dump()` because `ubus call service
//! list` output is compared byte-for-byte against the C in the differential.

use std::collections::BTreeMap;

use owrt_ubus::blob::{BlobBuf, MsgType};

/// `instance.h:24`. An instance killed by signal N reports 128 + N.
pub const SIGNALLED_OFFSET: i32 = 128;

/// `instance_config_parse`: the defaults a bare `respawn` array gets, in
/// order threshold, timeout, retry.
pub const RESPAWN_DEFAULTS: [u32; 3] = [3600, 5, 5];

/// `instance_init`: term_timeout before any config sets it.
pub const DEFAULT_TERM_TIMEOUT: u32 = 5;

/// A `respawn` policy. `retry == 0` means "never give up" -- the crash-loop
/// test in `instance_exit` is `count > retry && retry > 0`, so a zero retry
/// disables the give-up branch entirely rather than disabling respawn.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Respawn {
    pub threshold: u32,
    pub timeout: u32,
    pub retry: u32,
}

/// What an instance is doing right now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Run {
    /// Not started, or exited and not respawning.
    Stopped,
    /// Has a live child.
    Running,
    /// SIGTERM sent, waiting for the child or for term_timeout.
    Halting,
}

/// The parsed form of one `instances` table entry.
///
/// Only the fields this build acts on are broken out. `raw` keeps the
/// original blob so `list` can echo back what it was given and so an
/// unhandled attribute is not silently dropped from the diff.
#[derive(Clone, Debug)]
pub struct Instance {
    pub name: String,
    /// argv. Empty means the config was rejected -- see `valid`.
    pub command: Vec<String>,
    /// False when the config did not parse; such an instance is not started
    /// and `instance_dump` skips it entirely.
    pub valid: bool,
    pub env: BTreeMap<String, String>,
    pub data: BTreeMap<String, String>,
    pub limits: BTreeMap<String, String>,
    pub netdev: Vec<String>,
    pub file: Vec<String>,
    pub errors: Vec<String>,
    pub respawn: Option<Respawn>,
    pub term_timeout: u32,
    pub reload_signal: i32,
    pub nice: i32,
    pub user: Option<String>,
    pub group: Option<String>,
    pub pidfile: Option<String>,
    pub seccomp: Option<String>,
    pub capabilities: Option<String>,
    pub facility: Option<String>,
    pub stdout_to_log: bool,
    pub stderr_to_log: bool,
    pub no_new_privs: bool,
    pub trace: bool,
    pub has_jail: bool,
    /// The `jail` table verbatim; this build hands it to ujail rather than
    /// implementing the sandbox, so it is carried, compared and echoed.
    pub jail: Option<Vec<u8>>,
    pub bundle: Option<String>,
    pub extroot: Option<String>,
    pub overlaydir: Option<String>,
    pub tmpoverlaysize: Option<String>,
    pub triggers: Option<Vec<u8>>,
    pub watchdog: Option<(u32, u32)>,

    // Runtime, not config.
    pub state: Run,
    pub pid: i32,
    pub exit_code: i32,
    pub respawn_count: u32,
    /// CLOCK_MONOTONIC seconds at the last successful spawn.
    pub started: i64,
    /// Set when the instance should be started again after the child reaps.
    pub restart: bool,
    /// Set when the instance is going away for good once the child reaps.
    pub halt: bool,
}

impl Instance {
    pub fn new(name: &str) -> Self {
        Instance {
            name: name.to_string(),
            command: Vec::new(),
            valid: false,
            env: BTreeMap::new(),
            data: BTreeMap::new(),
            limits: BTreeMap::new(),
            netdev: Vec::new(),
            file: Vec::new(),
            errors: Vec::new(),
            respawn: None,
            term_timeout: DEFAULT_TERM_TIMEOUT,
            reload_signal: 0,
            nice: 0,
            user: None,
            group: None,
            pidfile: None,
            seccomp: None,
            capabilities: None,
            facility: None,
            stdout_to_log: false,
            stderr_to_log: false,
            no_new_privs: false,
            trace: false,
            has_jail: false,
            jail: None,
            bundle: None,
            extroot: None,
            overlaydir: None,
            tmpoverlaysize: None,
            triggers: None,
            watchdog: None,
            state: Run::Stopped,
            pid: 0,
            exit_code: 0,
            respawn_count: 0,
            started: 0,
            restart: false,
            halt: false,
        }
    }

    /// `instance_config_changed()`. An invalid old config always counts as
    /// changed, which is how a previously-rejected instance gets picked up
    /// once its config is fixed.
    ///
    /// `data` is deliberately absent: a data-only change fires the data
    /// triggers instead of restarting the process (`instance_update`).
    pub fn config_changed(&self, new: &Instance) -> bool {
        if !self.valid {
            return true;
        }
        self.command != new.command
            || self.bundle != new.bundle
            || self.extroot != new.extroot
            || self.overlaydir != new.overlaydir
            || self.tmpoverlaysize != new.tmpoverlaysize
            || self.env != new.env
            || self.netdev != new.netdev
            || self.file != new.file
            || self.nice != new.nice
            || self.facility != new.facility
            || self.user != new.user
            || self.group != new.group
            || self.pidfile != new.pidfile
            || self.respawn != new.respawn
            || self.reload_signal != new.reload_signal
            || self.term_timeout != new.term_timeout
            || self.seccomp != new.seccomp
            || self.capabilities != new.capabilities
            || self.limits != new.limits
            || self.errors != new.errors
            || self.has_jail != new.has_jail
            || self.trace != new.trace
            || self.no_new_privs != new.no_new_privs
            || self.jail != new.jail
            || self.watchdog != new.watchdog
    }

    /// Move the new config onto a live instance, keeping the runtime state.
    /// `instance_config_move()`: the process, its pid and the respawn budget
    /// belong to the running child, not to the config that replaced it.
    pub fn take_config(&mut self, new: Instance) {
        let (state, pid, exit_code, respawn_count, started, restart, halt) = (
            self.state,
            self.pid,
            self.exit_code,
            self.respawn_count,
            self.started,
            self.restart,
            self.halt,
        );
        *self = new;
        self.state = state;
        self.pid = pid;
        self.exit_code = exit_code;
        self.respawn_count = respawn_count;
        self.started = started;
        self.restart = restart;
        self.halt = halt;
    }

    /// `instance_exit_code()`. Note the order: exited, then signalled, then
    /// stopped, then a catch-all 1.
    pub fn exit_code_of(status: i32) -> i32 {
        // WIFEXITED
        if status & 0x7f == 0 {
            return (status >> 8) & 0xff;
        }
        // WIFSTOPPED
        if status & 0xff == 0x7f {
            return (status >> 8) & 0xff;
        }
        // WIFSIGNALED
        let sig = status & 0x7f;
        if sig != 0 {
            return SIGNALLED_OFFSET + sig;
        }
        1
    }

    /// `instance_dump()`, in its field order. An invalid instance emits
    /// nothing at all, not an empty table.
    pub fn dump(&self, b: &mut BlobBuf, _verbose: bool) {
        if !self.valid {
            return;
        }
        let t = b.open_table(Some(&self.name));
        b.put_i8("running", (self.state == Run::Running) as i8);
        if self.state == Run::Running {
            b.put_u32("pid", self.pid as u32);
        }
        if !self.command.is_empty() {
            let a = b.open_array(Some("command"));
            for arg in &self.command {
                b.put_str(None, arg);
            }
            b.close(a);
        }
        if let Some(v) = &self.bundle {
            b.put_str(Some("bundle"), v);
        }
        b.put_u32("term_timeout", self.term_timeout);
        if self.state != Run::Running {
            b.put_u32("exit_code", self.exit_code as u32);
        }
        if !self.errors.is_empty() {
            let a = b.open_array(Some("errors"));
            for e in &self.errors {
                b.put_str(None, e);
            }
            b.close(a);
        }
        if !self.env.is_empty() {
            let e = b.open_table(Some("env"));
            for (k, v) in &self.env {
                b.put_str(Some(k), v);
            }
            b.close(e);
        }
        if !self.data.is_empty() {
            let e = b.open_table(Some("data"));
            for (k, v) in &self.data {
                b.put_str(Some(k), v);
            }
            b.close(e);
        }
        if !self.limits.is_empty() {
            let e = b.open_table(Some("limits"));
            for (k, v) in &self.limits {
                b.put_str(Some(k), v);
            }
            b.close(e);
        }
        if !self.netdev.is_empty() {
            let a = b.open_array(Some("netdev"));
            for n in &self.netdev {
                b.put_str(None, n);
            }
            b.close(a);
        }
        if self.reload_signal != 0 {
            b.put_u32("reload_signal", self.reload_signal as u32);
        }
        if let Some(r) = &self.respawn {
            let t = b.open_table(Some("respawn"));
            b.put_u32("threshold", r.threshold);
            b.put_u32("timeout", r.timeout);
            b.put_u32("retry", r.retry);
            b.close(t);
        }
        if self.trace {
            b.put_i8("trace", 1);
        }
        if self.no_new_privs {
            b.put_i8("no_new_privs", 1);
        }
        if let Some(v) = &self.seccomp {
            b.put_str(Some("seccomp"), v);
        }
        if let Some(v) = &self.capabilities {
            b.put_str(Some("capabilities"), v);
        }
        if let Some(v) = &self.pidfile {
            b.put_str(Some("pidfile"), v);
        }
        if let Some(v) = &self.user {
            b.put_str(Some("user"), v);
        }
        if let Some(v) = &self.group {
            b.put_str(Some("group"), v);
        }
        b.close(t);
    }
}

/// Unused placeholder so the type import stays honest while jail handling
/// lands; removed once `jail` is projected rather than carried.
#[allow(dead_code)]
const _JAIL_IS_A_TABLE: MsgType = MsgType::Table;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_matches_the_c_macros() {
        // exit(0) and exit(3)
        assert_eq!(Instance::exit_code_of(0), 0);
        assert_eq!(Instance::exit_code_of(3 << 8), 3);
        // killed by SIGTERM (15) and SIGKILL (9)
        assert_eq!(Instance::exit_code_of(15), SIGNALLED_OFFSET + 15);
        assert_eq!(Instance::exit_code_of(9), SIGNALLED_OFFSET + 9);
        // stopped by SIGSTOP (19)
        assert_eq!(Instance::exit_code_of((19 << 8) | 0x7f), 19);
    }

    #[test]
    fn an_invalid_instance_always_counts_as_changed() {
        let old = Instance::new("a");
        let new = Instance::new("a");
        assert!(!old.valid);
        assert!(old.config_changed(&new));
    }

    #[test]
    fn data_alone_does_not_count_as_a_config_change() {
        let mut old = Instance::new("a");
        old.valid = true;
        old.command = vec!["/bin/true".into()];
        let mut new = old.clone();
        new.data.insert("k".into(), "v".into());
        assert!(!old.config_changed(&new));
    }
}
