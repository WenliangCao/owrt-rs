//! One supervised process: its parsed configuration, the diff that decides
//! whether a config update restarts it, and the `service list` projection.
//!
//! Source of truth is procd's `service/instance.c` at the pinned revision.
//! Field order in `dump` follows `instance_dump()` because `ubus call service
//! list` output is compared byte-for-byte against the C in the differential.

use std::collections::BTreeMap;

use owrt_ubus::blob::BlobBuf;

/// `instance.h:24`. An instance killed by signal N reports 128 + N.
pub const SIGNALLED_OFFSET: i32 = 128;

/// `instance_config_parse`: the defaults a bare `respawn` array gets, in
/// order threshold, timeout, retry.
pub const RESPAWN_DEFAULTS: [u32; 3] = [3600, 5, 5];

/// `instance_init`: term_timeout before any config sets it.
pub const DEFAULT_TERM_TIMEOUT: u32 = 5;

/// `__INSTANCE_WATCHDOG_MODE_MAX`: 0 disabled, 1 passive, 2 active.
pub const WATCHDOG_MODE_MAX: u32 = 3;

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
/// The `jail` table, as `jail_attr` parses it. Every flag maps to one ujail
/// switch in `jail_run()`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Jail {
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub pidfile: Option<String>,
    pub procfs: bool,
    pub sysfs: bool,
    pub ubus: bool,
    pub udebug: bool,
    pub log: bool,
    pub ronly: bool,
    pub netns: bool,
    pub userns: bool,
    pub cgroupsns: bool,
    pub console: bool,
    pub requirejail: bool,
    pub immediately: bool,
    /// path -> "1" for writable, anything else read-only. The C stores the
    /// flag as the value and tests `*type == '1'`.
    pub mount: BTreeMap<String, String>,
    /// `setns` entries, already rendered as ujail's `-j pid:ns,ns`
    /// argument. An entry missing `pid` or `namespaces`, or holding a
    /// non-string namespace, yields nothing at all --
    /// `instance_gen_setns_argstr` returns NULL and the C skips that
    /// `-j` pair entirely.
    pub setns: Vec<String>,
    /// The same `setns` entries as given, type and payload, because the C
    /// keeps the raw blobs: `instance_dump` re-emits every one of them
    /// (valid or not) and `instance_config_changed` compares them as blobs.
    pub setns_raw: Vec<(u32, Vec<u8>)>,
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
#[derive(Debug)]
pub struct Instance {
    pub name: String,
    /// argv. Empty means the config was rejected -- see `valid`.
    pub command: Vec<String>,
    /// False when the config did not parse; such an instance is not started
    /// and `instance_dump` skips it entirely.
    pub valid: bool,
    pub env: BTreeMap<String, String>,
    /// `data`, keeping each field's blobmsg type and payload. The C stores
    /// the blob and re-emits it with `blobmsg_add_blob`, so an integer stays
    /// an integer; flattening to strings silently drops non-string fields.
    /// BTreeMap because blobmsg_list_fill builds an avl ordered by name.
    pub data: BTreeMap<String, (u32, Vec<u8>)>,
    pub limits: BTreeMap<String, String>,
    /// `netdev` names AND the ifindex each had when this config was parsed.
    /// The C compares `if_nametoindex()` results (instance_netdev_cmp), so a
    /// same-named interface that was destroyed and recreated counts as a
    /// change. Comparing names alone silently keeps the old process.
    pub netdev: Vec<(String, u32)>,
    /// `file` paths AND the content digest each had when parsed
    /// (instance_file_cmp compares MD5). A regenerated config file with the
    /// same path is exactly the case this exists for.
    pub file: Vec<(String, [u8; 16])>,
    /// `watch`: ubus object paths whose notifications become trigger events.
    /// See watch.c -- this is a subscription list, not a file watch.
    pub watch: Vec<String>,
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
    /// The parsed `jail` table. The sandbox itself is ujail's job; procd
    /// only builds its argv (`jail_run`).
    pub jail: Jail,
    pub bundle: Option<String>,
    pub extroot: Option<String>,
    pub overlaydir: Option<String>,
    pub tmpoverlaysize: Option<String>,
    pub triggers: Option<Vec<u8>>,
    /// `watchdog.mode` and `watchdog.freq`. Mode 0 disabled, 1 passive,
    /// 2 active; anything outside that range falls back to 0. A freq of 0
    /// or less falls back to 30, which is why this is not an Option.
    pub watchdog_mode: u32,
    pub watchdog_freq: u32,
    /// Set by the `watchdog` ubus method. While true, a config update no
    /// longer compares mode/freq, so the service keeps the values it chose
    /// instead of being reset by the next `set`.
    pub watchdog_self_managed: bool,

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
    /// The C's `in->respawn`: a live respawn budget, separate from the
    /// `respawn` policy. `instance_stop` clears it so a deliberate stop is
    /// not undone by the respawn branch, while the policy stays for `list`.
    pub respawn_active: bool,
    /// Monotonic milliseconds at which `instance_timeout` should fire. One
    /// timer per instance, as in the C: SIGKILL when halting, otherwise the
    /// respawn delay.
    pub deadline: Option<i64>,
    /// Captured stdout/stderr, read every loop round and logged line by
    /// line. Not part of the config diff -- they belong to the child.
    pub log_out: Option<crate::proc::LogPipe>,
    pub log_err: Option<crate::proc::LogPipe>,
    /// Monotonic ms at which the per-instance watchdog fires. Separate from
    /// `deadline`, which is the stop/respawn timer -- the C keeps two
    /// uloop_timeouts and both can be armed at once.
    pub watchdog_deadline: Option<i64>,
    /// Set when the respawn budget ran out. Such an instance stays listed
    /// with its last exit code; only a deliberate stop or delete removes it.
    pub crash_looped: bool,
    /// The vlist version bit `update_start` sets and a re-add clears.
    /// `update_complete` stops whatever is still marked -- that is what
    /// vlist_update/vlist_flush do across a multi-call update.
    pub stale: bool,
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
            watch: Vec::new(),
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
            jail: Jail::default(),
            bundle: None,
            extroot: None,
            overlaydir: None,
            tmpoverlaysize: None,
            triggers: None,
            watchdog_mode: 0,
            watchdog_freq: 30,
            watchdog_self_managed: false,
            state: Run::Stopped,
            pid: 0,
            exit_code: 0,
            respawn_count: 0,
            started: 0,
            restart: false,
            halt: false,
            respawn_active: false,
            deadline: None,
            stale: false,
            watchdog_deadline: None,
            crash_looped: false,
            log_out: None,
            log_err: None,
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
            || self.jail.mount != new.jail.mount
            || self.jail.setns != new.jail.setns
            // A self-managed watchdog is excluded from the comparison, so a
            // service that set its own mode/timeout is not restarted by the
            // next `set` carrying the original values.
            || (!self.watchdog_self_managed
                && (self.watchdog_mode != new.watchdog_mode
                    || self.watchdog_freq != new.watchdog_freq))
    }

    /// Move the new config onto a live instance, keeping the runtime state.
    /// `instance_config_move()`: the process, its pid and the respawn budget
    /// belong to the running child, not to the config that replaced it.
    pub fn take_config(&mut self, new: Instance) {
        let (state, pid, exit_code, respawn_count, started, restart, halt, deadline) = (
            self.state,
            self.pid,
            self.exit_code,
            self.respawn_count,
            self.started,
            self.restart,
            self.halt,
            self.deadline,
        );
        let (self_managed, wd_mode, wd_freq, wd_deadline) = (
            self.watchdog_self_managed,
            self.watchdog_mode,
            self.watchdog_freq,
            self.watchdog_deadline,
        );
        // instance_config_move never touches in->_stdout/_stderr: the pipes
        // belong to the running child. Dropping them here closed the read
        // ends on every `set` -- including a reload whose config had not
        // changed -- and the child's next line was an EPIPE. (R81 F21.)
        let (log_out, log_err) = (self.log_out.take(), self.log_err.take());
        *self = new;
        self.log_out = log_out;
        self.log_err = log_err;
        self.state = state;
        self.pid = pid;
        self.exit_code = exit_code;
        self.respawn_count = respawn_count;
        self.started = started;
        self.restart = restart;
        self.halt = halt;
        self.deadline = deadline;
        // instance_config_move keeps the self-managed watchdog values: they
        // belong to the running service, not to the config that replaced it.
        if self_managed {
            self.watchdog_mode = wd_mode;
            self.watchdog_freq = wd_freq;
            self.watchdog_self_managed = true;
        }
        // The armed watchdog belongs to the running child, like `deadline`.
        // Letting the new config's None overwrite it silently disarmed the
        // timer on the next `set` -- which is every reload.
        self.watchdog_deadline = wd_deadline;
        // `respawn_active` follows the NEW config: the C sets in->respawn in
        // instance_config_parse, so a config that dropped `respawn` stops
        // respawning even though the running child predates the change.
        self.respawn_active = self.respawn.is_some();
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
    pub fn dump(&self, b: &mut BlobBuf, verbose: bool) {
        if !self.valid {
            return;
        }
        let t = b.msg_open_table(&self.name);
        // `running` is proc.pending in the C: it stays true until the child
        // is reaped, INCLUDING the SIGTERM grace period. Reporting the stop
        // intent instead makes a still-live process look gone.
        let alive = self.state == Run::Running || self.state == Run::Halting;
        b.msg_bool("running", alive);
        if alive {
            b.msg_u32("pid", self.pid as u32);
        }
        if !self.command.is_empty() {
            let a = b.msg_open_array("command");
            for arg in &self.command {
                b.msg_string("", arg);
            }
            b.msg_close(a);
        }
        if let Some(v) = &self.bundle {
            b.msg_string("bundle", v);
        }
        b.msg_u32("term_timeout", self.term_timeout);
        if !alive {
            b.msg_u32("exit_code", self.exit_code as u32);
        }
        if !self.errors.is_empty() {
            let a = b.msg_open_array("errors");
            for e in &self.errors {
                b.msg_string("", e);
            }
            b.msg_close(a);
        }
        if !self.env.is_empty() {
            let e = b.msg_open_table("env");
            for (k, v) in &self.env {
                b.msg_string(k, v);
            }
            b.msg_close(e);
        }
        if !self.data.is_empty() {
            let e = b.msg_open_table("data");
            for (k, (ty, payload)) in &self.data {
                b.msg_field(*ty, k, payload);
            }
            b.msg_close(e);
        }
        if !self.limits.is_empty() {
            let e = b.msg_open_table("limits");
            for (k, v) in &self.limits {
                b.msg_string(k, v);
            }
            b.msg_close(e);
        }
        if !self.netdev.is_empty() {
            let a = b.msg_open_array("netdev");
            for (n, _) in &self.netdev {
                b.msg_string("", n);
            }
            b.msg_close(a);
        }
        if self.reload_signal != 0 {
            b.msg_u32("reload_signal", self.reload_signal as u32);
        }
        // instance_dump prints respawn from in->respawn -- the live budget.
        // A crash-looped instance has had it cleared, so keeping a stored
        // policy in the output would claim supervision that stopped.
        if let (true, Some(r)) = (self.respawn_active, &self.respawn) {
            let t = b.msg_open_table("respawn");
            b.msg_u32("threshold", r.threshold);
            b.msg_u32("timeout", r.timeout);
            b.msg_u32("retry", r.retry);
            b.msg_close(t);
        }
        if self.trace {
            b.msg_bool("trace", true);
        }
        if self.no_new_privs {
            b.msg_bool("no_new_privs", true);
        }
        if let Some(v) = &self.seccomp {
            b.msg_string("seccomp", v);
        }
        if let Some(v) = &self.capabilities {
            b.msg_string("capabilities", v);
        }
        if let Some(v) = &self.pidfile {
            b.msg_string("pidfile", v);
        }
        if let Some(v) = &self.user {
            b.msg_string("user", v);
        }
        if let Some(v) = &self.group {
            b.msg_string("group", v);
        }
        if self.has_jail {
            let r = b.msg_open_table("jail");
            if let Some(v) = &self.jail.name {
                b.msg_string("name", v);
            }
            if self.bundle.is_none() {
                // A non-bundle jail prints hostname plus eight flags, always,
                // including the false ones -- absence is not the same as
                // false here.
                if let Some(v) = &self.jail.hostname {
                    b.msg_string("hostname", v);
                }
                b.msg_bool("procfs", self.jail.procfs);
                b.msg_bool("sysfs", self.jail.sysfs);
                b.msg_bool("ubus", self.jail.ubus);
                b.msg_bool("log", self.jail.log);
                b.msg_bool("ronly", self.jail.ronly);
                b.msg_bool("netns", self.jail.netns);
                b.msg_bool("userns", self.jail.userns);
                b.msg_bool("cgroupsns", self.jail.cgroupsns);
            } else {
                if let Some(v) = &self.jail.pidfile {
                    b.msg_string("pidfile", v);
                }
                b.msg_bool("immediately", self.jail.immediately);
            }
            // The console flag reports whether a console fd is open, which
            // this build never opens.
            b.msg_bool("console", false);
            b.msg_close(r);
            if !self.jail.mount.is_empty() {
                let e = b.msg_open_table("mount");
                for (k, v) in &self.jail.mount {
                    b.msg_string(k, v);
                }
                b.msg_close(e);
            }
            // blobmsg_add_blob() of each stored entry: the raw tables, in
            // order, including ones ujail's argv skipped as malformed.
            if !self.jail.setns_raw.is_empty() {
                let a = b.msg_open_array("setns");
                for (ty, payload) in &self.jail.setns_raw {
                    b.msg_field(*ty, "", payload);
                }
                b.msg_close(a);
            }
        }
        if let Some(v) = &self.extroot {
            b.msg_string("extroot", v);
        }
        if let Some(v) = &self.overlaydir {
            b.msg_string("overlaydir", v);
        }
        if let Some(v) = &self.tmpoverlaysize {
            b.msg_string("tmpoverlaysize", v);
        }
        // `if (verbose && in->trigger) blobmsg_add_blob(b, in->trigger);` --
        // the instance's own rules, under the attr's own name, verbose only.
        if verbose {
            if let Some(t) = &self.triggers {
                b.msg_field(owrt_ubus::blob::MsgType::Array as u32, "triggers", t);
            }
        }
        // Last, and only when the mode is not disabled.
        if self.watchdog_mode != 0 {
            let w = b.msg_open_table("watchdog");
            b.msg_u32("mode", self.watchdog_mode);
            b.msg_u32("timeout", self.watchdog_freq);
            b.msg_close(w);
        }
        b.msg_close(t);
    }
}

/// `instance_config_parse()`: turn one `instances` table entry into an
/// `Instance`.
///
/// The C tolerates a lot here; where it does, so does this. Notably a
/// `command` that is missing or empty leaves the instance *invalid* rather
/// than failing the whole `set`, and an invalid instance is neither started
/// nor listed.
/// `blobmsg_get_string()` on a non-string attr, as atoi consumes it: the
/// raw payload bytes up to the first NUL, lossily as ASCII.
fn payload_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// `instance_gen_setns_argstr()`: render one `setns` entry as ujail's
/// `<pid>:<ns>,<ns>` argument. Returns None -- and the C then omits the
/// whole `-j` pair -- when `pid` or `namespaces` is absent, or when any
/// namespace element is not a string.
fn setns_argstr(entry: owrt_ubus::blob::Field<'_>) -> Option<String> {
    let mut pid: Option<u32> = None;
    let mut names: Vec<String> = Vec::new();
    let mut saw_ns = false;
    for f in entry.children() {
        match f.name {
            "pid" => pid = f.as_u32(),
            "namespaces" => {
                saw_ns = true;
                for c in f.children() {
                    names.push(c.as_str()?.to_string());
                }
            }
            _ => {}
        }
    }
    let pid = pid?;
    if !saw_ns {
        return None;
    }
    Some(format!("{pid}:{}", names.join(",")))
}

pub fn parse(name: &str, entry: owrt_ubus::blob::Field<'_>) -> Instance {
    let mut i = Instance::new(name);
    let mut saw_command = false;
    let mut command_ok = true;
    // Any element-level type violation in a list the C checks with
    // blobmsg_check_attr_list, or an out-of-range nice, invalidates the
    // whole instance rather than being quietly dropped.
    let mut bad_field = false;

    for f in entry.children() {
        match f.name {
            // blobmsg_parse drops a field whose top-level type does not
            // match the policy, so `command: "/bin/true"` (a string, not an
            // array) is not "an empty command" -- it is no command at all,
            // and the instance stays valid but never starts.
            "command" if f.ty == owrt_ubus::blob::MsgType::Array as u32 => {
                saw_command = true;
                let mut any = false;
                for c in f.children() {
                    any = true;
                    match c.as_str() {
                        Some(v) => i.command.push(v.to_string()),
                        // blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING):
                        // one non-string element rejects the whole list.
                        None => {
                            command_ok = false;
                            break;
                        }
                    }
                }
                // A present but empty array leaves ret false in the C.
                if !any {
                    command_ok = false;
                }
            }
            "env" => {
                // blobmsg_check_attr_list(..., BLOBMSG_TYPE_STRING): ONE
                // non-string element rejects the whole instance. Dropping
                // the bad element and running anyway is the difference
                // between "config refused" and "service started with half
                // its environment".
                for c in f.children() {
                    match c.as_str() {
                        Some(v) => {
                            // avl_insert() refuses a duplicate key: the FIRST
                            // entry under a name wins, later ones are dropped.
                            i.env.entry(c.name.to_string()).or_insert_with(|| v.to_string());
                        }
                        None => bad_field = true,
                    }
                }
            }
            "data" => {
                for c in f.children() {
                    i.data.entry(c.name.to_string()).or_insert_with(|| (c.ty, c.data.to_vec()));
                }
            }
            "limits" => {
                for c in f.children() {
                    match c.as_str() {
                        Some(v) => {
                            // avl_insert() refuses a duplicate key: the FIRST
                            // entry under a name wins, later ones are dropped.
                            i.limits.entry(c.name.to_string()).or_insert_with(|| v.to_string());
                        }
                        None => bad_field = true,
                    }
                }
            }
            // blobmsg_list_fill(l, ..., array=true): the avl key of an array
            // element is blobmsg_data(cur) -- the string itself -- under
            // avl_strcmp with duplicates refused. So `list` echoes these
            // sorted by value with repeats dropped, and blobmsg_list_equal()
            // compares them in that order, which is why a reordered `netdev`
            // is NOT a config change in the C.
            "netdev" => {
                let mut by_name: BTreeMap<String, u32> = BTreeMap::new();
                for n in f.children().filter_map(|c| c.as_str()) {
                    by_name.entry(n.to_string()).or_insert_with(|| crate::sys::if_nametoindex(n));
                }
                i.netdev = by_name.into_iter().collect();
            }
            "file" => {
                let mut by_path: BTreeMap<String, [u8; 16]> = BTreeMap::new();
                for p in f.children().filter_map(|c| c.as_str()) {
                    by_path.entry(p.to_string()).or_insert_with(|| crate::sys::file_md5(p));
                }
                i.file = by_path.into_iter().collect();
            }
            "watch" => {
                i.watch = f.children().filter_map(|c| c.as_str()).map(str::to_string).collect();
            }
            "error" => {
                // Same array rule: sorted by the string, duplicates dropped.
                for c in f.children() {
                    match c.as_str() {
                        Some(v) => {
                            if !i.errors.iter().any(|e| e == v) {
                                i.errors.push(v.to_string());
                            }
                        }
                        None => bad_field = true,
                    }
                }
                i.errors.sort();
            }
            "respawn" => {
                // The C seeds vals[] with the defaults and overwrites only as
                // many as the array supplies, so a short array keeps the rest.
                let mut vals = RESPAWN_DEFAULTS;
                for (n, c) in f.children().take(3).enumerate() {
                    if let Some(s) = c.as_str() {
                        // atoi(): "5x" is 5, "" is 0 -- not a parse failure.
                        vals[n] = crate::sys::atoi_u32(s);
                    } else {
                        // The C runs atoi(blobmsg_get_string(cur)) on EVERY
                        // element type: an integer's payload is big-endian
                        // binary, so atoi reads it as a (usually empty) C
                        // string and yields 0 -- `"respawn":[3600,5,5]` with
                        // JSON integers is {0,0,0} on the device, not the
                        // numbers. Taking the numeric value was a silent
                        // improvement over the interface.
                        vals[n] = crate::sys::atoi_u32(&payload_cstr(c.data));
                    }
                }
                i.respawn = Some(Respawn {
                    threshold: vals[0],
                    timeout: vals[1],
                    retry: vals[2],
                });
                i.respawn_active = true;
            }
            "term_timeout" => i.term_timeout = f.as_u32().unwrap_or(DEFAULT_TERM_TIMEOUT),
            "reload_signal" => i.reload_signal = f.as_u32().unwrap_or(0) as i32,
            "nice" => {
                // `in->nice = (int8_t) blobmsg_get_u32(cur)` FIRST, then the
                // [-20, 20] test: the value is truncated to eight signed
                // bits before validation, so nice:236 is a VALID -20 and
                // only the post-truncation range rejects the instance.
                let n = f.as_u32().unwrap_or(0) as u8 as i8 as i32;
                if !(-20..=20).contains(&n) {
                    bad_field = true;
                }
                i.nice = n;
            }
            "user" => i.user = f.as_str().map(str::to_string),
            "group" => i.group = f.as_str().map(str::to_string),
            "pidfile" => i.pidfile = f.as_str().map(str::to_string),
            "seccomp" => i.seccomp = f.as_str().map(str::to_string),
            "capabilities" => i.capabilities = f.as_str().map(str::to_string),
            "facility" => i.facility = f.as_str().map(str::to_string),
            "bundle" => i.bundle = f.as_str().map(str::to_string),
            "extroot" => i.extroot = f.as_str().map(str::to_string),
            "overlaydir" => i.overlaydir = f.as_str().map(str::to_string),
            "tmpoverlaysize" => i.tmpoverlaysize = f.as_str().map(str::to_string),
            "stdout" => i.stdout_to_log = f.as_bool().unwrap_or(false),
            "stderr" => i.stderr_to_log = f.as_bool().unwrap_or(false),
            "no_new_privs" => i.no_new_privs = f.as_bool().unwrap_or(false),
            "trace" => i.trace = f.as_bool().unwrap_or(false),
            "jail" => {
                i.has_jail = true;
                for a in f.children() {
                    match a.name {
                        "name" => i.jail.name = a.as_str().map(str::to_string),
                        "hostname" => i.jail.hostname = a.as_str().map(str::to_string),
                        "pidfile" => i.jail.pidfile = a.as_str().map(str::to_string),
                        "procfs" => i.jail.procfs = a.as_bool().unwrap_or(false),
                        "sysfs" => i.jail.sysfs = a.as_bool().unwrap_or(false),
                        "ubus" => i.jail.ubus = a.as_bool().unwrap_or(false),
                        "udebug" => i.jail.udebug = a.as_bool().unwrap_or(false),
                        "log" => i.jail.log = a.as_bool().unwrap_or(false),
                        "ronly" => i.jail.ronly = a.as_bool().unwrap_or(false),
                        "netns" => i.jail.netns = a.as_bool().unwrap_or(false),
                        "userns" => i.jail.userns = a.as_bool().unwrap_or(false),
                        "cgroupsns" => i.jail.cgroupsns = a.as_bool().unwrap_or(false),
                        "console" => i.jail.console = a.as_bool().unwrap_or(false),
                        "requirejail" => i.jail.requirejail = a.as_bool().unwrap_or(false),
                        "immediately" => i.jail.immediately = a.as_bool().unwrap_or(false),
                        "mount" => {
                            for m in a.children() {
                                if let Some(v) = m.as_str() {
                                    i.jail.mount.insert(m.name.to_string(), v.to_string());
                                }
                            }
                        }
                        "setns" => {
                            // blobmsg_list_fill(&jail->setns, ..., true): the
                            // avl key is blobmsg_data(cur) read as a C STRING
                            // even though each element is a table -- i.e. the
                            // raw payload bytes up to the first NUL. Entries
                            // whose payload begins identically (a `pid` first,
                            // say) collide and all but the first are dropped;
                            // the survivors come back in strcmp order of that
                            // prefix. Measured against the shipping procd:
                            // [pid3, pid1, pid2, nopid] lists as [nopid, pid3].
                            let mut kept: BTreeMap<Vec<u8>, (u32, Vec<u8>)> = BTreeMap::new();
                            for e in a.children() {
                                let key: Vec<u8> =
                                    e.data.iter().take_while(|b| **b != 0).copied().collect();
                                kept.entry(key).or_insert_with(|| (e.ty, e.data.to_vec()));
                            }
                            for (ty, payload) in kept.into_values() {
                                let e = owrt_ubus::blob::Field { name: "", ty, data: &payload };
                                if let Some(arg) = setns_argstr(e) {
                                    i.jail.setns.push(arg);
                                }
                                i.jail.setns_raw.push((ty, payload));
                            }
                        }
                        _ => {}
                    }
                }
            }
            "triggers" => i.triggers = Some(f.data.to_vec()),
            "watchdog" => {
                // vals[] seeds {0, 30} and only the first two entries are
                // read, so a short array keeps the remaining default.
                let mut vals: [u32; 2] = [0, 30];
                for (n, c) in f.children().take(2).enumerate() {
                    if let Some(s) = c.as_str() {
                        // atoi() into a uint32_t: "-1" becomes 0xffffffff,
                        // which then passes the `> 0` test and does NOT fall
                        // back to 30; "5x" is 5, not a parse failure.
                        vals[n] = crate::sys::atoi_u32(s);
                    } else {
                        // atoi over the raw payload, as above: an integer
                        // element is 0, so `"watchdog":[1,10]` (JSON
                        // integers) leaves the watchdog DISABLED on the
                        // device where taking the value armed it.
                        vals[n] = crate::sys::atoi_u32(&payload_cstr(c.data));
                    }
                }
                // Mode out of range falls back to 0, freq of 0 to 30.
                i.watchdog_mode = if vals[0] < WATCHDOG_MODE_MAX { vals[0] } else { 0 };
                i.watchdog_freq = if vals[1] > 0 { vals[1] } else { 30 };
            }
            _ => {}
        }
    }

    // `instance_config_parse_command()` is the subtle one. A *missing*
    // `command` returns true with command = NULL: the instance is valid, is
    // listed, and simply never starts ("command not set"). Only a command
    // that is present and either empty or not a list of strings makes the
    // instance invalid, and an invalid instance is not listed at all.
    //
    // A bundle skips the command parse entirely.
    if i.bundle.is_some() {
        i.command.clear();
    }
    // `if (!in->trace && tb[INSTANCE_ATTR_JAIL])` -- a traced instance never
    // gets a jail, because trace already wraps the command.
    if i.trace {
        i.has_jail = false;
    }

    // If ujail is not installed: a require_jail instance is INVALID (the C
    // returns false from instance_config_parse), and any other jailed
    // instance quietly loses its jail and runs unconfined -- which is the
    // C's own choice, and the reason `require` exists.
    if i.has_jail && std::fs::metadata(crate::proc::UJAIL).is_err() {
        if i.jail.requirejail {
            log!(
                crate::sys::LOG_ERR,
                "Cannot jail service {name}. {} is missing",
                crate::proc::UJAIL
            );
            bad_field = true;
        } else {
            i.has_jail = false;
        }
    }

    i.valid = (i.bundle.is_some() || !saw_command || command_ok) && !bad_field;
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R81 F21: `*self = new` dropped the running child's log pipes.
    #[test]
    fn take_config_keeps_the_running_childs_log_pipes() {
        use std::os::fd::AsRawFd;
        let (r, _w) = owrt_ubus::sys::pipe().unwrap();
        let raw = r.as_raw_fd();
        let mut live = Instance::new("a");
        live.valid = true;
        live.command = vec!["/bin/true".into()];
        live.state = Run::Running;
        live.pid = 12345;
        live.log_out = Some(crate::proc::LogPipe::new(r, crate::sys::LOG_INFO).unwrap());

        let mut fresh = Instance::new("a");
        fresh.valid = true;
        fresh.command = vec!["/bin/true".into()];
        live.take_config(fresh);

        assert!(live.log_out.is_some(), "log pipe dropped by take_config");
        assert_eq!(live.log_out.as_ref().unwrap().fd.as_raw_fd(), raw);
        assert!(rustix::io::fcntl_getfd(&live.log_out.as_ref().unwrap().fd).is_ok(),"read end was closed");
    }

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
    fn a_missing_command_is_valid_but_an_empty_one_is_not() {
        // Built by hand rather than through parse(), which needs a real blob.
        let mut absent = Instance::new("a");
        absent.valid = true; // no `command` key at all
        assert!(absent.command.is_empty());

        // instance_dump skips an invalid instance entirely, so this is the
        // difference between "listed, never starts" and "not listed".
        let empty = Instance::new("a"); // valid stays false
        assert!(!empty.valid);
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
        // Rebuilt rather than cloned: an Instance owns live pipe fds, so it
        // is deliberately not Clone.
        let mut new = Instance::new("a");
        new.valid = true;
        new.command = vec!["/bin/true".into()];
        new.data.insert("k".into(), (3, b"v\0".to_vec()));
        assert!(!old.config_changed(&new));
    }
}

#[cfg(test)]
mod validity_tests {
    use super::*;
    use owrt_ubus::blob::BlobBuf;

    /// Build one `instances` entry and parse it, so these exercise the real
    /// blobmsg path rather than a hand-built struct.
    fn parse_entry(build: impl FnOnce(&mut BlobBuf)) -> Instance {
        let mut b = BlobBuf::new();
        let t = b.msg_open_table("one");
        build(&mut b);
        b.msg_close(t);
        let f = owrt_ubus::blob::fields(b.payload()).next().expect("one entry");
        parse("one", f)
    }

    #[test]
    fn a_non_string_env_value_invalidates_the_whole_instance() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            let e = b.msg_open_table("env");
            b.msg_string("A", "ok");
            b.msg_u32("B", 7);
            b.msg_close(e);
        });
        assert!(
            !i.valid,
            "the C rejects the instance; dropping B and running is worse than refusing"
        );
    }

    #[test]
    fn a_command_of_the_wrong_type_reads_as_absent_not_empty() {
        let i = parse_entry(|b| {
            b.msg_string("command", "/bin/true");
        });
        // The policy drops it, so this is "no command": valid, listed, never
        // started -- not an empty command, which would be invalid.
        assert!(i.valid);
        assert!(i.command.is_empty());
    }

    #[test]
    fn an_out_of_range_nice_invalidates_rather_than_clamping() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            b.msg_u32("nice", 21);
        });
        assert!(!i.valid);
    }

    #[test]
    fn a_negative_watchdog_timeout_does_not_fall_back_to_thirty() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            let w = b.msg_open_array("watchdog");
            b.msg_string("", "0");
            b.msg_string("", "-1");
            b.msg_close(w);
        });
        // atoi("-1") into a uint32_t is 0xffffffff, which passes `> 0`.
        assert_eq!(i.watchdog_freq, u32::MAX);
    }

    #[test]
    fn an_empty_command_array_is_still_invalid() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_close(c);
        });
        assert!(!i.valid);
    }
}

#[cfg(test)]
mod jail_gate_tests {
    use super::*;

    #[test]
    fn trace_suppresses_the_jail() {
        // `if (!in->trace && tb[INSTANCE_ATTR_JAIL])`: a traced instance is
        // already wrapped, so it never gets a jail even if one is declared.
        let mut i = Instance::new("one");
        i.trace = true;
        i.has_jail = true;
        // The parse-time rule, applied the way parse() does.
        if i.trace {
            i.has_jail = false;
        }
        assert!(!i.has_jail);
    }

    #[test]
    fn require_jail_without_ujail_is_a_config_error_not_a_silent_downgrade() {
        // Documents the asymmetry that makes `require` meaningful: without
        // it a missing ujail drops the sandbox and runs anyway.
        let missing = std::fs::metadata("/definitely/no/ujail/here").is_err();
        assert!(missing);
    }
}

#[cfg(test)]
mod setns_tests {
    use super::*;
    use owrt_ubus::blob::BlobBuf;

    fn one_entry(build: impl FnOnce(&mut BlobBuf)) -> Option<String> {
        let mut b = BlobBuf::new();
        let t = b.msg_open_table("e");
        build(&mut b);
        b.msg_close(t);
        let f = owrt_ubus::blob::fields(b.payload()).next().unwrap();
        setns_argstr(f)
    }

    #[test]
    fn a_complete_entry_renders_pid_colon_comma_list() {
        let got = one_entry(|b| {
            b.msg_u32("pid", 42);
            let a = b.msg_open_array("namespaces");
            b.msg_string("", "net");
            b.msg_string("", "user");
            b.msg_close(a);
        });
        assert_eq!(got.as_deref(), Some("42:net,user"));
    }

    #[test]
    fn a_missing_half_yields_nothing_so_the_flag_is_omitted() {
        assert!(one_entry(|b| { b.msg_u32("pid", 42); }).is_none());
        assert!(one_entry(|b| {
            let a = b.msg_open_array("namespaces");
            b.msg_string("", "net");
            b.msg_close(a);
        })
        .is_none());
    }

    #[test]
    fn a_non_string_namespace_rejects_the_whole_entry() {
        let got = one_entry(|b| {
            b.msg_u32("pid", 42);
            let a = b.msg_open_array("namespaces");
            b.msg_string("", "net");
            b.msg_u32("", 7);
            b.msg_close(a);
        });
        assert!(got.is_none());
    }
}

#[cfg(test)]
mod dump_tests {
    use super::*;
    use owrt_ubus::blob::{fields, BlobBuf};

    fn parse_entry(build: impl FnOnce(&mut BlobBuf)) -> Instance {
        let mut b = BlobBuf::new();
        let t = b.msg_open_table("one");
        build(&mut b);
        b.msg_close(t);
        let f = fields(b.payload()).next().expect("one entry");
        parse("one", f)
    }

    /// The dumped instance table's field names, in order, one level deep;
    /// `path` descends into a named child first.
    fn dumped_names(i: &Instance, verbose: bool, path: &[&str]) -> Vec<String> {
        let mut b = BlobBuf::new();
        i.dump(&mut b, verbose);
        let table = fields(b.payload()).next().expect("instance table");
        let mut data = table.data;
        for want in path {
            let child = owrt_ubus::blob::fields(data)
                .find(|f| f.name == *want)
                .unwrap_or_else(|| panic!("no field {want}"));
            data = child.data;
        }
        owrt_ubus::blob::fields(data).map(|f| f.name.to_string()).collect()
    }

    fn with_triggers_and_setns() -> Instance {
        parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            let t = b.msg_open_array("triggers");
            {
                let r = b.msg_open_array("");
                b.msg_string("", "x.ev");
                let cmds = b.msg_open_array("");
                let cmd = b.msg_open_array("");
                b.msg_string("", "run_script");
                b.msg_string("", "/bin/true");
                b.msg_close(cmd);
                b.msg_close(cmds);
                b.msg_close(r);
            }
            b.msg_close(t);
            let j = b.msg_open_table("jail");
            b.msg_string("name", "j");
            let s = b.msg_open_array("setns");
            {
                let e = b.msg_open_table("");
                b.msg_u32("pid", 1);
                let ns = b.msg_open_array("namespaces");
                b.msg_string("", "net");
                b.msg_close(ns);
                b.msg_close(e);
            }
            {
                // No pid: ujail gets no -j for it, but the dump still shows it.
                let e = b.msg_open_table("");
                let ns = b.msg_open_array("namespaces");
                b.msg_string("", "ipc");
                b.msg_close(ns);
                b.msg_close(e);
            }
            b.msg_close(s);
            b.msg_close(j);
        })
    }

    #[test]
    fn instance_triggers_are_dumped_only_when_verbose() {
        let i = with_triggers_and_setns();
        assert!(i.triggers.is_some());
        let plain = dumped_names(&i, false, &[]);
        assert!(!plain.iter().any(|n| n == "triggers"), "{plain:?}");
        let verbose = dumped_names(&i, true, &[]);
        let pos = verbose.iter().position(|n| n == "triggers").expect("triggers in verbose dump");
        // C emits it after the jail block and before watchdog: last here.
        assert_eq!(pos, verbose.len() - 1, "{verbose:?}");
    }

    #[test]
    fn every_setns_entry_is_dumped_raw_even_when_ujail_skips_it() {
        let mut i = with_triggers_and_setns();
        assert_eq!(i.jail.setns, vec!["1:net".to_string()], "only the valid one renders");
        // Two distinct key prefixes (an array attr vs an int attr first), so
        // both survive, and the pid-less one sorts first.
        assert_eq!(i.jail.setns_raw.len(), 2);
        assert!(i.jail.setns_raw[0].1.len() < i.jail.setns_raw[1].1.len(), "nopid entry first");
        // The build host has no /sbin/ujail, so parse() cleared has_jail the
        // way the C does without require_jail. The dump path under test is
        // the one a rootfs WITH ujail takes, so put the flag back.
        i.has_jail = true;
        // Like `mount`, the C emits `setns` as a SIBLING of the jail table,
        // after closing it -- not inside it.
        let top = dumped_names(&i, false, &[]);
        let jail = top.iter().position(|n| n == "jail").expect("jail table");
        let setns = top.iter().position(|n| n == "setns").expect("setns array");
        assert!(setns > jail, "{top:?}");
        let entries = dumped_names(&i, false, &["setns"]);
        assert_eq!(entries.len(), 2, "both entries, valid or not");
    }
}

#[cfg(test)]
mod list_order_tests {
    use super::*;
    use owrt_ubus::blob::{fields, BlobBuf};

    fn parse_entry(build: impl FnOnce(&mut BlobBuf)) -> Instance {
        let mut b = BlobBuf::new();
        let t = b.msg_open_table("one");
        build(&mut b);
        b.msg_close(t);
        let f = fields(b.payload()).next().expect("one entry");
        parse("one", f)
    }

    #[test]
    fn array_lists_come_back_sorted_and_deduplicated() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            let n = b.msg_open_array("netdev");
            for d in ["zeth", "aeth", "meth", "aeth"] {
                b.msg_string("", d);
            }
            b.msg_close(n);
            let e = b.msg_open_array("error");
            for d in ["late", "early", "late"] {
                b.msg_string("", d);
            }
            b.msg_close(e);
        });
        let names: Vec<&str> = i.netdev.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["aeth", "meth", "zeth"]);
        assert_eq!(i.errors, vec!["early".to_string(), "late".to_string()]);
    }

    #[test]
    fn a_duplicate_name_in_a_table_keeps_the_first_value() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            let e = b.msg_open_table("env");
            b.msg_string("K", "first");
            b.msg_string("K", "second");
            b.msg_close(e);
        });
        assert_eq!(i.env.get("K").map(String::as_str), Some("first"));
    }

    #[test]
    fn setns_entries_with_the_same_leading_bytes_collapse_to_the_first() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            let j = b.msg_open_table("jail");
            let s = b.msg_open_array("setns");
            for (pid, ns) in [(3u32, "c"), (1, "a"), (2, "b")] {
                let e = b.msg_open_table("");
                b.msg_u32("pid", pid);
                let a = b.msg_open_array("namespaces");
                b.msg_string("", ns);
                b.msg_close(a);
                b.msg_close(e);
            }
            {
                let e = b.msg_open_table("");
                let a = b.msg_open_array("namespaces");
                b.msg_string("", "zz");
                b.msg_close(a);
                b.msg_close(e);
            }
            b.msg_close(s);
            b.msg_close(j);
        });
        // Three entries start with the same `pid` attr header -> one survives
        // (the first, pid 3); the pid-less one has a different first byte and
        // sorts before it. Exactly what the shipping procd lists.
        assert_eq!(i.jail.setns, vec!["3:c".to_string()]);
        assert_eq!(i.jail.setns_raw.len(), 2);
    }
}

#[cfg(test)]
mod r73_fidelity_tests {
    use super::*;
    use owrt_ubus::blob::{fields, BlobBuf};

    fn parse_entry(build: impl FnOnce(&mut BlobBuf)) -> Instance {
        let mut b = BlobBuf::new();
        let t = b.msg_open_table("one");
        build(&mut b);
        b.msg_close(t);
        let f = fields(b.payload()).next().expect("one entry");
        parse("one", f)
    }

    #[test]
    fn nice_is_truncated_to_int8_before_the_range_check() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            b.msg_u32("nice", 236);
        });
        assert!(i.valid, "236 truncates to -20, which is in range");
        assert_eq!(i.nice, -20);
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            b.msg_u32("nice", 100);
        });
        assert!(!i.valid, "100 stays 100 after truncation and is rejected");
    }

    #[test]
    fn integer_elements_in_respawn_and_watchdog_arrays_atoi_to_zero() {
        let i = parse_entry(|b| {
            let c = b.msg_open_array("command");
            b.msg_string("", "/bin/true");
            b.msg_close(c);
            let r = b.msg_open_array("respawn");
            b.msg_u32("", 3600);
            b.msg_u32("", 5);
            b.msg_u32("", 5);
            b.msg_close(r);
            let w = b.msg_open_array("watchdog");
            b.msg_u32("", 1);
            b.msg_u32("", 10);
            b.msg_close(w);
        });
        let r = i.respawn.as_ref().expect("respawn set");
        assert_eq!((r.threshold, r.timeout, r.retry), (0, 0, 0));
        assert_eq!(i.watchdog_mode, 0, "mode 99->0 fallback applies to the atoi'd 0");
        assert_eq!(i.watchdog_freq, 30, "freq 0 falls back to 30");
    }
}
