//! procd-rs: service supervision.
//!
//! Stage P3.1: the supervision core, running as an ordinary daemon against an
//! existing ubusd. It is deliberately not PID 1 and does not pretend to be --
//! inittab, rcS, hotplug and the watchdog are P3.2, and the on-device PID 1
//! switch is P3.3 and needs a boot window.
//!
//! Behaviour is transcribed from procd at the pinned revision
//! 58eb263d5abe03f8c1280bdfa65a3b052614215d, mainly `service/service.c` and
//! `service/instance.c`.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![cfg_attr(target_os = "linux", deny(warnings))]

/// procd's `LOG()`/`ERROR()`/`ULOG_WARN()`: one line through `sys::ulog`,
/// the single sink that never panics (see sys.rs, R81 F01). `log!(prio, ..)`
/// takes a syslog priority; `debug!(level, ..)` is `DEBUG(level, ..)`,
/// printed at LOG_NOTICE only when the debug level allows.
macro_rules! log {
    ($prio:expr, $($arg:tt)*) => {
        $crate::sys::ulog($prio, &format!($($arg)*))
    };
}
macro_rules! debug {
    ($level:expr, $($arg:tt)*) => {
        if $crate::sys::debug_level() >= $level {
            $crate::sys::ulog($crate::sys::LOG_NOTICE, &format!($($arg)*))
        }
    };
}

mod dispatch;
mod hotplug;
mod inittab;
mod instance;
mod jsonscript;
mod proc;
mod rcs;
mod service;
mod sysobj;
mod sysupgrade;
mod watchdog;
mod trigger;
mod sys;
mod ubus;

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::time::Instant;

use owrt_ubus::blob::BlobBuf;
use owrt_ubus::conn::{Connection, Incoming, Request};
use owrt_ubus::msg::status;

use instance::{Instance, Run};
use proc::{SIGHUP, SIGKILL, SIGTERM};
use service::Service;
use ubus::Target;

/// Registered object ids, so an incoming invoke can be routed.
#[derive(Default)]
struct Objects {
    service: u32,
    container: u32,
    system: u32,
}

/// `state.c`'s states. `NotPid1` is the supervisor-only mode (`getpid() !=
/// 1`), which never enters the machine.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Boot {
    NotPid1,
    /// EARLY and UBUS run inside `run()` before `Procd` exists; the field
    /// therefore starts at `Ubus` on PID 1 and `Early` is only the C's name
    /// for that pre-bus phase.
    #[allow(dead_code)]
    Early,
    Ubus,
    Init,
    Running,
    Shutdown,
    Halt,
}

/// One set/add reply held until this service's initial watch attempts finish.
/// Later business requests stay in Connection's FIFO until this completes.
struct PendingSet {
    request: Request,
    paths: VecDeque<String>,
    service: String,
    new_service: bool,
}

struct Procd {
    conn: Connection,
    objects: Objects,
    services: BTreeMap<String, Service>,
    /// Storage only: list/info values are rebuilt for each request. Bounded
    /// after sending so an unusually large list is not retained indefinitely.
    read_reply: BlobBuf,
    /// `/proc/meminfo`, kept open for `system info`.
    meminfo: sysobj::Meminfo,
    base: Instant,
    /// Next `Validator::seq`; see its doc comment.
    validator_seq: u64,
    /// `rc()`'s run queue, and where its scripts live. `-I` overrides the
    /// path exactly as the C's option does.
    rc: rcs::RunQueue,
    init_d: String,
    /// `watch.c`: an anonymous object that exists only to receive other
    /// objects' notifications, plus the ubus paths instances asked to watch.
    watch_obj: u32,
    /// Watched path -> which service asked for it. `watch_add`/`watch_del`.
    watches: BTreeMap<String, Vec<String>>,
    /// Paths we have already subscribed to, so a re-announce is a no-op.
    subscribed: BTreeMap<String, u32>,
    /// At most one queued retry per watched path; each loop processes one.
    watch_pending: VecDeque<(String, i64)>,
    pending_set: Option<PendingSet>,
    triggers: trigger::Triggers,
    // -- the PID 1 half (state.c / inittab.c), inert when boot == NotPid1 --
    boot: Boot,
    inittab: Vec<inittab::Action>,
    /// `rcS()`'s width-1 queue. Its drain is what advances Init -> Running
    /// and Shutdown -> Halt.
    serial: rcs::RunQueue,
    /// True while a state is waiting on `serial` (rcdone()).
    serial_awaited: bool,
    /// `console` from askconsole, used by askfirst's skip test.
    console: Option<String>,
    rc_d: String,
    reboot_event: i32,
    wdt: watchdog::Wdt,
    /// The uevent listener + rule queue; PID 1 only.
    hotplug: Option<hotplug::Hotplug>,
    /// The `hotplug.<subsys>` objects; registered in BOTH modes, like the C.
    dispatch: dispatch::Dispatch,
    /// Read end of the SIGCHLD self-pipe: a child exit wakes the poll.
    wakeup: std::os::fd::OwnedFd,
    /// Rebuilt from the current owners on every wait; no descriptor ownership
    /// or kernel registration persists in this storage.
    wait_fds: Vec<owrt_ubus::sys::PollFd>,
    inotify_ready: bool,
}

/// What one wait returned: bus input, and anything else that calls for the
/// maintenance pass (another descriptor, the tick, or a failed poll).
#[derive(Clone, Copy)]
struct Activity {
    bus: bool,
    other: bool,
}

impl Procd {
    fn now_ms(&self) -> i64 {
        self.base.elapsed().as_millis() as i64
    }

    // -- supervision -------------------------------------------------------

    /// `instance_start()`. A config that never parsed is not started, and an
    /// instance that already has a child is left alone.
    fn instance_start(&mut self, svc: &str, name: &str) {
        let now = self.now_ms();
        let mut failed_exec = false;
        let Some(inst) = self.services.get_mut(svc).and_then(|s| s.instances.get_mut(name)) else {
            return;
        };
        // instance_start()'s early returns, in order. Each returns without
        // touching exit_code, which is why a never-started instance lists
        // exit_code 0 rather than a spawn failure code.
        if !inst.valid {
            return;
        }
        if !inst.errors.is_empty() {
            log!(
                sys::LOG_INFO,
                "Not starting instance {svc}::{name}, an error was indicated"
            );
            return;
        }
        if inst.bundle.is_none() && inst.command.is_empty() {
            log!(sys::LOG_INFO, "Not starting instance {svc}::{name}, command not set");
            return;
        }
        if inst.state == Run::Running || inst.state == Run::Halting {
            // Already has a child. A halting one is asked to come back.
            if inst.halt {
                inst.restart = true;
            }
            return;
        }
        inst.halt = false;
        inst.restart = false;
        // A successful start ends the crash loop; leaving the flag set would
        // also make the instance un-deletable, since collect_stopped uses it
        // to tell "ran out of retries" from "was asked to go away".
        inst.crash_looped = false;
        #[expect(unsafe_code, reason = "the private supervisor owner controls its single-threaded lifecycle")]
        // SAFETY: run owns this supervisor and starts no threads. This private
        // owner path holds no application lock while spawning the instance.
        let started = unsafe { proc::start(inst, svc) };
        match started {
            Ok((pid, out, err)) => {
                inst.pid = pid;
                inst.log_out = out;
                inst.log_err = err;
                // instance_writepid(): the parent writes the child's pid
                // once it has it. External callers read this file, so
                // parsing `pidfile` and never writing it is a silent
                // interface break rather than a missing nicety.
                if let Some(path) = &inst.pidfile {
                    if let Err(e) = std::fs::write(path, format!("{pid}\n")) {
                        log!(
                            sys::LOG_ERR,
                            "failed to open pidfile for writing: {path}: {e}"
                        );
                    }
                }
                // instance_start() arms the watchdog timer whenever the mode
                // is not disabled.
                inst.watchdog_deadline = if inst.watchdog_mode != 0 {
                    Some(now + inst.watchdog_freq as i64 * 1000)
                } else {
                    None
                };
                inst.state = Run::Running;
                inst.started = now;
                inst.deadline = None;
                self.service_event("instance.start", svc, name);
            }
            Err(e) => {
                // The C forks first, so an exec failure is the CHILD exiting
                // 127 and it goes through instance_exit -- which means the
                // respawn budget applies and a command that appears later is
                // retried. Recording 127 and stopping there looks identical
                // in `list` and behaves completely differently.
                // Rust-only line: the C's child fails execvp silently and
                // exits 127.
                log!(sys::LOG_ERR, "{svc}::{name} failed to start: {e}");
                inst.pid = 0;
                inst.state = Run::Stopped;
                inst.started = now;
                failed_exec = true;
            }
        }
        if failed_exec {
            // The C has already forked by the time exec fails, so
            // `instance.start` went out for the attempt; the child's 127 then
            // arrives as an ordinary exit. A subscriber counts one start per
            // attempt, not one per success.
            self.service_event("instance.start", svc, name);
            // WIFEXITED with status 127, the way the C's child reports it.
            if self.instance_exited(svc, name, 127 << 8) {
                self.instance_start(svc, name);
            } else {
                self.collect_stopped(svc, name);
            }
        }
    }

    /// `instance_stop()`. SIGTERM now; only a halt escalates to SIGKILL after
    /// term_timeout. A jailed instance has no timer: ujail owns its teardown.
    fn instance_stop(&mut self, svc: &str, name: &str, halt: bool) {
        let now = self.now_ms();
        let Some(inst) = self.services.get_mut(svc).and_then(|s| s.instances.get_mut(name)) else {
            return;
        };
        // C tests `in->proc.pending` -- the child still exists -- which is
        // true in the TERM grace period too. Testing Run::Running instead
        // returned early for a Halting instance and left `restart` set, so
        // deleting a service while one of its instances was restarting had
        // the instance come back with a new pid instead of going away.
        if inst.state != Run::Running && inst.state != Run::Halting {
            if halt {
                inst.halt = true;
                // Already stopped and being deleted: let it be collected.
                inst.crash_looped = false;
            }
            return;
        }
        inst.halt = halt;
        // `in->restart = in->respawn = false` -- both, in one statement.
        inst.restart = false;
        // A deliberate stop outranks the crash-loop state: the instance was
        // asked to go away, so it goes.
        if halt {
            inst.crash_looped = false;
        }
        // Clearing respawn here is what stops a deliberate stop from being
        // undone by the respawn branch in instance_exit.
        inst.respawn_active = false;
        inst.state = Run::Halting;
        proc::signal(inst.pid, SIGTERM);
        if !inst.has_jail {
            inst.deadline = Some(now + inst.term_timeout as i64 * 1000);
        }
    }

    /// `instance_restart()`. With a reload_signal set, this sends that signal
    /// and returns -- the process is NOT restarted. That asymmetry is real
    /// and is why a service with reload_signal keeps its pid across a reload.
    fn instance_restart(&mut self, svc: &str, name: &str) {
        let now = self.now_ms();
        let Some(inst) = self.services.get_mut(svc).and_then(|s| s.instances.get_mut(name)) else {
            return;
        };
        // `if (!in->proc.pending) return;` -- Halting counts as pending.
        if inst.state != Run::Running && inst.state != Run::Halting {
            return;
        }
        if inst.reload_signal != 0 {
            proc::signal(inst.pid, inst.reload_signal);
            return;
        }
        inst.halt = true;
        inst.restart = true;
        inst.state = Run::Halting;
        proc::signal(inst.pid, SIGTERM);
        if !inst.has_jail {
            inst.deadline = Some(now + inst.term_timeout as i64 * 1000);
        }
    }

    /// `instance_exit()`. Returns true when the caller should start it again.
    fn instance_exited(&mut self, svc: &str, name: &str, wstatus: i32) -> bool {
        let now = self.now_ms();
        let Some(inst) = self.services.get_mut(svc).and_then(|s| s.instances.get_mut(name)) else {
            return false;
        };
        // A child can write and exit after this iteration's earlier pipe
        // scan (including while procd is stopped). Drain again only once
        // waitpid has confirmed the exit, before clearing the old pid/pipes.
        Self::pump_instance_logs(inst);
        let runtime = (now - inst.started) / 1000;
        inst.exit_code = Instance::exit_code_of(wstatus);
        inst.pid = 0;
        inst.state = Run::Stopped;
        inst.deadline = None;
        // The confirmed-exit drain above preserves output that arrived
        // between the earlier scan and waitpid.
        inst.log_out = None;
        inst.log_err = None;
        inst.watchdog_deadline = None;

        let mut restart = false;
        let mut event: Option<&'static str> = None;

        if inst.halt {
            // instance_removepid() runs on the halt path only, not on every
            // exit -- a respawning instance keeps its file across restarts.
            if let Some(path) = &inst.pidfile {
                let _ = std::fs::remove_file(path);
            }
            if inst.restart {
                restart = true;
            }
            // Deleting a halted instance happens in the caller, which can see
            // the whole service.
        } else if inst.restart {
            restart = true;
        } else if inst.respawn_active {
            let r = inst.respawn.clone().expect("respawn_active implies a policy");
            if runtime < r.threshold as i64 {
                inst.respawn_count += 1;
            } else {
                inst.respawn_count = 0;
            }
            // The give-up test is strictly greater, and only when retry > 0.
            // A retry of 0 therefore means "respawn forever".
            if inst.respawn_count > r.retry && r.retry > 0 {
                log!(
                    sys::LOG_INFO,
                    "Instance {svc}::{name} s in a crash loop {} crashes, {runtime} seconds since last crash",
                    inst.respawn_count
                );
                inst.restart = false;
                inst.respawn_active = false;
                // The C sets in->halt here too, but that flag is read by
                // instance_exit's ALREADY-TAKEN branch; it does not send the
                // instance back through the delete path in this callback.
                // Deleting it loses the last failure -- the C keeps it
                // listed as running=false with its exit_code, minus the
                // respawn block.
                inst.crash_looped = true;
                event = Some("instance.fail");
            } else {
                event = Some("instance.respawn");
                inst.deadline = Some(now + r.timeout as i64 * 1000);
            }
        }
        inst.restart = false;

        self.service_event("instance.stop", svc, name);
        if let Some(e) = event {
            self.service_event(e, svc, name);
        }
        restart
    }

    /// `instance_timeout()`: only the halt flag authorizes SIGKILL. A
    /// `service state {spawn:false}` stop keeps halt=false even while the
    /// child is in Run::Halting, so an ignored SIGTERM does not escalate.
    fn fire_timeouts(&mut self) {
        let now = self.now_ms();
        let mut kill: Vec<(String, i32)> = Vec::new();
        let mut start: Vec<(String, String)> = Vec::new();

        // instance_watchdog(): on expiry, restart when the instance respawns
        // and stop it outright otherwise.
        let mut wd_restart: Vec<(String, String)> = Vec::new();
        let mut wd_stop: Vec<(String, String)> = Vec::new();
        for (sname, s) in self.services.iter_mut() {
            for (iname, inst) in s.instances.iter_mut() {
                let Some(wd) = inst.watchdog_deadline else { continue };
                if now < wd {
                    continue;
                }
                inst.watchdog_deadline = None;
                if inst.respawn_active {
                    wd_restart.push((sname.clone(), iname.clone()));
                } else {
                    wd_stop.push((sname.clone(), iname.clone()));
                }
            }
        }
        for (s, i) in wd_restart {
            debug!(3, "instance {s}::{i} watchdog timer expired");
            self.instance_restart(&s, &i);
        }
        for (s, i) in wd_stop {
            debug!(3, "instance {s}::{i} watchdog timer expired");
            self.instance_stop(&s, &i, true);
        }

        for (sname, s) in self.services.iter_mut() {
            for (iname, inst) in s.instances.iter_mut() {
                let Some(d) = inst.deadline else { continue };
                if now < d {
                    continue;
                }
                inst.deadline = None;
                if inst.halt {
                    kill.push((format!("{sname}::{iname}"), inst.pid));
                } else if inst.restart || inst.respawn_active {
                    start.push((sname.clone(), iname.clone()));
                }
            }
        }

        for (who, pid) in kill {
            log!(
                sys::LOG_INFO,
                "Instance {who} pid {pid} not stopped on SIGTERM, sending SIGKILL instead"
            );
            proc::signal(pid, SIGKILL);
        }
        for (s, i) in start {
            self.instance_start(&s, &i);
            // instance_timeout()'s respawn branch calls rc(srv, "running")
            // after starting, exactly as the direct-restart path does.
            self.run_init_script(&s);
        }
    }

    /// How long the loop may sleep before the maintenance pass must run
    /// again. While anything time-based is pending (a stop or respawn
    /// deadline, an instance watchdog, a queued trigger, an rc or hotplug
    /// job, an inittab respawn, coldplug) it keeps the 200 ms tick the
    /// deadlines were written against. Otherwise it sleeps until the next
    /// watchdog ping, capped at 5 s as a safety net; child exits, uevents,
    /// pipe output, inotify, bus traffic and signals all wake it through
    /// descriptors. The C's uloop only wakes for armed timers.
    fn next_tick_ms(&self) -> i32 {
        let pending = self.services.values().any(|s| {
            s.instances.values().any(|i| i.deadline.is_some() || i.watchdog_deadline.is_some())
        }) || !self.triggers.pending.is_empty()
            || !self.rc.jobs.is_empty()
            || !self.serial.jobs.is_empty()
            || !self.dispatch.is_idle()
            || self.hotplug.as_ref().is_some_and(|h| !h.is_idle())
            || self.inittab.iter().any(|a| a.respawn_at.is_some());
        if pending {
            return 200;
        }
        let ping = self.wdt.next_ping_in(self.now_ms()).unwrap_or(5000);
        ping.clamp(1, 5000) as i32
    }

    /// Registration retries are maintenance deadlines even while a stream
    /// of read-only bus requests keeps poll continuously readable.
    fn maintenance_delay_ms(&self, now: i64, maintenance_at: i64) -> i32 {
        let regular = (maintenance_at - now).clamp(0, i64::from(i32::MAX)) as i32;
        regular.min(self.dispatch.next_registration_ms(now).unwrap_or(regular))
    }

    /// One poll() over everything the loop reacts to, so a child exit, a
    /// uevent, a script's output or an inotify event is handled when it
    /// happens rather than at the next tick -- the C's uloop wakes on each of
    /// these. `timeout_ms` is the timer tick that stays for deadlines.
    /// (R81 F22.) Returns whether the bus is readable and whether anything
    /// else (another descriptor, or the tick itself) asks for a maintenance
    /// pass.
    fn wait_activity(&mut self, timeout_ms: i32, connected: bool) -> io::Result<Activity> {
        use owrt_ubus::sys::{PollFd, POLLIN};
        use std::os::fd::AsRawFd;
        let pfd = |fd: i32| PollFd { fd, events: POLLIN, revents: 0 };
        let mut fds = std::mem::take(&mut self.wait_fds);
        fds.clear();
        // poll ignores negative fds. A disconnected bus must not wake the
        // pipe/timer loop continuously while its reconnect timer is armed.
        fds.push(pfd(if connected { self.conn.as_raw_fd() } else { -1 }));
        fds.push(pfd(self.wakeup.as_raw_fd()));
        if let Some(h) = &self.hotplug {
            fds.push(pfd(h.raw_fd()));
        }
        let inotify_index = self.dispatch.inotify_fd().map(|fd| {
            let index = fds.len();
            fds.push(pfd(fd));
            index
        });
        for s in self.services.values() {
            for inst in s.instances.values() {
                for p in [&inst.log_out, &inst.log_err].into_iter().flatten() {
                    fds.push(pfd(p.fd.as_raw_fd()));
                }
            }
        }
        for j in self.rc.jobs.iter().chain(self.serial.jobs.iter()) {
            if let Some(p) = &j.out {
                fds.push(pfd(p.fd.as_raw_fd()));
            }
        }
        // Synchronous calls in the maintenance work may have queued a bus
        // message. Still check the other descriptors, but do not sleep on it.
        let pending = connected && self.conn.has_pending();
        let result = owrt_ubus::sys::poll_fds(&mut fds, if pending { 0 } else { timeout_ms });
        let other = match &result {
            Ok(ready) => {
                if fds[1].revents != 0 {
                    sys::drain_wakeup(self.wakeup.as_raw_fd());
                }
                self.inotify_ready |= inotify_index.is_some_and(|i| fds[i].revents != 0);
                // The tick elapsed, or something other than the bus is ready.
                (*ready == 0 && !pending) || fds[1..].iter().any(|p| p.revents != 0)
            }
            Err(_) => {
                // If polling failed, preserve the old nonblocking maintenance
                // read rather than depending on an absent readiness result.
                self.inotify_ready = true;
                true
            }
        };
        let bus = pending || fds[0].revents != 0;
        if fds.capacity() <= 256 {
            fds.clear();
            self.wait_fds = fds;
        }
        result.map(|_| Activity { bus, other })
    }

    /// Drain every live instance's captured output. `instance_stdio` builds
    /// the ident as `basename(argv[0])[pid]` and logs with the instance's
    /// own facility, restoring procd/LOG_DAEMON afterwards.
    fn pump_logs(&mut self) {
        for s in self.services.values_mut() {
            for inst in s.instances.values_mut() {
                Self::pump_instance_logs(inst);
            }
        }
    }

    fn pump_instance_logs(inst: &mut Instance) {
        if inst.log_out.is_none() && inst.log_err.is_none() {
            return;
        }
        let arg0 = inst
            .command
            .first()
            .map(|c| c.rsplit('/').next().unwrap_or(c))
            .unwrap_or("");
        // snprintf(ident, 32, "%s[%d]", ...): the WHOLE ident is
        // capped at 31 bytes, basename and pid included.
        let ident = syslog_ident(arg0, inst.pid);
        // instance_config_parse keeps LOG_DAEMON when
        // syslog_facility_str_to_int() finds nothing (-1).
        let facility = inst
            .facility
            .as_deref()
            .map(sys::facility_from_str)
            .filter(|f| *f != -1)
            .unwrap_or(sys::LOG_DAEMON);
        for pipe in [&mut inst.log_out, &mut inst.log_err] {
            let Some(p) = pipe.as_mut() else { continue };
            let alive = p.poll_lines(|prio, line| {
                sys::log_instance_line(&ident, facility, prio, line);
            });
            if !alive {
                *pipe = None;
            }
        }
    }

    /// Poll for exited children and drive each through `instance_exited`.
    fn reap(&mut self) {
        // Clear before draining: SIGCHLD may coalesce several exits, or
        // arrive while we process one. Drain all statuses, leaving any new
        // signal armed for the next pass. pump_logs still runs first.
        if !owrt_platform::procd::signals::take_child_exit_pending() {
            return;
        }
        while let Some((pid, wstatus)) = proc::reap_any() {
            let mut found = None;
            for (sname, s) in self.services.iter() {
                for (iname, inst) in s.instances.iter() {
                    if inst.state != Run::Stopped && inst.pid == pid {
                        found = Some((sname.clone(), iname.clone()));
                    }
                }
            }
            let Some((sname, iname)) = found else {
                // Not an instance. It may be a trigger command -- reap_any()
                // consumes the status for the whole process, so the trigger
                // table has to be told here rather than polling waitpid
                // itself, or the exit would be lost.
                if let Some(c) =
                    self.triggers.pending.iter_mut().find(|c| c.pid == Some(pid))
                {
                    c.pid = None;
                    c.finished = true;
                    continue;
                }
                if self.rc.reaped(pid) {
                    continue;
                }
                if self.serial.reaped(pid) {
                    continue;
                }
                if self.inittab_exited(pid) {
                    continue;
                }
                if self.hotplug.as_mut().is_some_and(|h| h.reaped(pid, wstatus)) {
                    continue;
                }
                {
                    let now = self.now_ms();
                    if self.dispatch.reaped(pid, now) {
                        continue;
                    }
                }
                // Otherwise an orphan we never started. PID 1 must reap
                // these; as an ordinary daemon we rarely see them.
                let _ = wstatus;
                continue;
            };
            if self.instance_exited(&sname, &iname, wstatus) {
                self.instance_start(&sname, &iname);
                // instance_exit()'s restart branch calls rc(srv, "running").
                self.run_init_script(&sname);
            } else {
                self.collect_stopped(&sname, &iname);
            }
        }
    }

    /// `instance_delete()` and `service_stopped()`: a halted instance goes
    /// away once its child has reaped, and a deleted service goes away once
    /// none of its instances is left running.
    fn collect_stopped(&mut self, svc: &str, name: &str) {
        let Some(s) = self.services.get_mut(svc) else {
            return;
        };
        // A crash-looped instance stays listed: it was never asked to go
        // away, it just ran out of retries.
        let drop_instance = s
            .instances
            .get(name)
            .map(|i| i.halt && !i.crash_looped && i.state == Run::Stopped)
            .unwrap_or(false);
        if drop_instance {
            // instance_free() calls service_data_trigger on the instance's
            // own data before releasing it.
            let keys: Vec<String> = s
                .instances
                .get(name)
                .map(|i| i.data.keys().cloned().collect())
                .unwrap_or_default();
            if let Some(s) = self.services.get_mut(svc) {
                s.instances.remove(name);
            }
            // instance_free() -> trigger_del(in)
            self.triggers
                .del(&trigger::Owner::Instance(svc.to_string(), name.to_string()));
            self.data_trigger_keys(&keys);
        }
        let Some(s) = self.services.get_mut(svc) else {
            return;
        };
        let freed_service = s.can_be_freed();
        if freed_service {
            // service_stopped(): `service.stop` goes out first, then the
            // service is unlinked and trigger_del(s) drops its rules. The
            // instances' rules go with their instances, but a service freed
            // while some were never individually collected must not leave
            // rules behind.
            self.service_only_event("service.stop", svc);
            self.triggers.del_service(svc);
            self.services.remove(svc);
        }
        // instance_free() -> watch_del(in), and a freed service takes its
        // instances' watches with it. Without this the ubus subscription and
        // the path mapping outlive the thing that asked for them: a deleted
        // service kept firing its rules, and a reconnect resubscribed a
        // watch nothing wanted any more. refresh_watches() rebuilds from
        // whatever is left, so an emptied service drops out on its own.
        if (drop_instance || freed_service) && self.watches.contains_key(svc) {
            self.refresh_watches(svc);
        }
    }

    // -- PID 1: state.c and inittab.c ---------------------------------------

    /// `procd_state_next()`.
    fn state_next(&mut self) {
        self.boot = match self.boot {
            Boot::NotPid1 => return,
            Boot::Early => Boot::Ubus,
            Boot::Ubus => Boot::Init,
            Boot::Init => Boot::Running,
            Boot::Running | Boot::Shutdown | Boot::Halt => Boot::Halt,
        };
        self.state_enter();
    }

    /// `state_enter()` for the states reachable AFTER the bus exists. EARLY
    /// and UBUS run before `Procd` can be built and live in `pid1_boot`.
    fn state_enter(&mut self) {
        match self.boot {
            Boot::Init => {
                log!(sys::LOG_INFO, "- init -");
                self.inittab = inittab::parse("/etc/inittab");
                self.inittab_run(inittab::Kind::Respawn);
                self.inittab_run(inittab::Kind::Askconsole);
                self.inittab_run(inittab::Kind::Askfirst);
                self.inittab_run(inittab::Kind::Sysinit);
                // "switch to syslog log channel": ulog_open(ULOG_SYSLOG).
                sys::ulog_open(sys::LogChannel::Syslog);
            }
            Boot::Running => {
                log!(sys::LOG_INFO, "- init complete -");
                self.inittab_run(inittab::Kind::Respawnlate);
                self.inittab_run(inittab::Kind::Askconsolelate);
            }
            Boot::Shutdown => {
                sys::set_console();
                log!(sys::LOG_INFO, "- shutdown -");
                self.inittab_run(inittab::Kind::Shutdown);
                sys::sync_fs();
            }
            Boot::Halt => {
                log!(sys::LOG_INFO, "- SIGTERM processes -");
                proc::signal(-1, SIGTERM);
                sys::sync_fs();
                std::thread::sleep(std::time::Duration::from_secs(1));
                log!(sys::LOG_INFO, "- SIGKILL processes -");
                proc::signal(-1, SIGKILL);
                sys::sync_fs();
                std::thread::sleep(std::time::Duration::from_secs(1));
                if self.reboot_event == sys::RB_POWER_OFF {
                    log!(sys::LOG_INFO, "- power down -");
                } else {
                    log!(sys::LOG_INFO, "- reboot -");
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
                if sys::is_container() {
                    owrt_platform::procd::process::reboot_cmd(self.reboot_event);
                    std::process::exit(0);
                }
                owrt_platform::procd::process::halt_forever(self.reboot_event);
            }
            _ => {}
        }
    }

    /// `procd_shutdown()`: jump the machine to SHUTDOWN once.
    fn procd_shutdown(&mut self, event: i32) {
        if self.boot == Boot::NotPid1 || self.boot >= Boot::Shutdown {
            return;
        }
        self.reboot_event = event;
        self.boot = Boot::Shutdown;
        self.state_enter();
    }

    /// `procd_inittab_run(name)`.
    fn inittab_run(&mut self, kind: inittab::Kind) {
        let idxs: Vec<usize> = self
            .inittab
            .iter()
            .enumerate()
            .filter(|(_, a)| a.kind == kind)
            .map(|(i, _)| i)
            .collect();
        for i in idxs {
            self.run_action(i);
            if !kind.multi() {
                break;
            }
        }
    }

    /// One handler dispatch (`handlers[]`).
    fn run_action(&mut self, i: usize) {
        let kind = self.inittab[i].kind;
        match kind {
            inittab::Kind::Sysinit | inittab::Kind::Shutdown => {
                // runrc(): argv is [rcS-path, pattern, param]; a short line
                // logs and does nothing. The serial queue's drain is
                // rcdone() -> procd_state_next().
                let (pat, param) = {
                    let a = &self.inittab[i];
                    match (a.argv.get(1), a.argv.get(2)) {
                        (Some(p), Some(q)) => (p.clone(), q.clone()),
                        _ => {
                            log!(sys::LOG_ERR, "valid format is rcS <S|K> <param>");
                            return;
                        }
                    }
                };
                let rc_d = self.rc_d.clone();
                self.serial.queue_all(&rc_d, &pat, &param);
                self.serial_awaited = true;
                if self.serial.is_idle() {
                    // `if (rcS(...)) rcdone(NULL);` -- nothing to run still
                    // advances the state.
                    self.serial_awaited = false;
                    self.state_next();
                }
            }
            inittab::Kind::Askfirst => {
                let skip = {
                    let a = &self.inittab[i];
                    !sys::dev_exist(&a.id) || self.console.as_deref() == Some(a.id.as_str())
                };
                if skip {
                    return;
                }
                inittab::prepend_ask(&mut self.inittab[i].argv);
                self.inittab[i].respawn_ms = inittab::RESPAWN_MS;
                self.fork_action(i);
            }
            inittab::Kind::Askconsole | inittab::Kind::Askconsolelate => {
                match inittab::resolve_console() {
                    Some(tty) => {
                        if !sys::dev_exist(&tty) {
                            return;
                        }
                        self.console = Some(tty.clone());
                        self.inittab[i].id = tty;
                    }
                    None => {
                        self.console = None;
                        self.inittab[i].id = String::new();
                    }
                }
                inittab::prepend_ask(&mut self.inittab[i].argv);
                self.inittab[i].respawn_ms = inittab::RESPAWN_MS;
                self.fork_action(i);
            }
            inittab::Kind::Respawn | inittab::Kind::Respawnlate => {
                self.inittab[i].respawn_ms = inittab::RESPAWN_MS;
                self.fork_action(i);
            }
        }
    }

    /// `fork_worker()`, guarded like `if (!a->proc.pid)`.
    fn fork_action(&mut self, i: usize) {
        if self.inittab[i].pid.is_some() {
            return;
        }
        let (argv, id, kind, respawn_ms) = {
            let a = &self.inittab[i];
            (a.argv.clone(), a.id.clone(), a.kind, a.respawn_ms)
        };
        #[expect(unsafe_code, reason = "inittab runs on the sole supervisor thread")]
        // SAFETY: this private inittab owner is entered only by the supervisor
        // lifecycle, which starts no threads and holds no lock across spawn.
        let spawned = unsafe { proc::spawn_tty(&argv, &id) };
        match spawned {
            Ok(pid) => {
                debug!(4, "Launched new {kind:?} action, pid={pid}");
                self.inittab[i].pid = Some(pid);
            }
            Err(e) => {
                log!(sys::LOG_ERR, "Failed to execute {}: {e}",
                    argv.first().map(String::as_str).unwrap_or("<empty command>"));
                // The C has forked by the time execvp fails, so the failure
                // is a child exit and child_exit() re-arms the 500 ms
                // respawn -- a command that appears later gets picked up.
                // (R81 F22.)
                if respawn_ms >= 0 && sys::dev_exist(&id) {
                    let now = self.now_ms();
                    self.inittab[i].respawn_at = Some(now + respawn_ms);
                }
            }
        }
    }

    /// `child_exit()`: respawn only while the device still exists.
    fn inittab_exited(&mut self, pid: i32) -> bool {
        let now = self.now_ms();
        let Some(a) = self.inittab.iter_mut().find(|a| a.pid == Some(pid)) else {
            return false;
        };
        a.pid = None;
        if a.respawn_ms < 0 {
            return true;
        }
        if !sys::dev_exist(&a.id) {
            debug!(4, "Skipping respawn: device '{}' does not exist anymore", a.id);
            return true;
        }
        a.respawn_at = Some(now + a.respawn_ms);
        true
    }

    /// Supervision between initial hotplug object registrations, before
    /// rcS can enqueue dispatch jobs. No bus dispatch/registration reentry.
    fn maintain_initial_registration(&mut self) {
        self.pump_logs();
        self.reap();
        self.fire_timeouts();
        self.wdt.pump(self.now_ms());
    }

    /// The per-loop PID 1 work: respawn timers, the serial queue, and its
    /// state advance; plus the shutdown signals and the watchdog feed.
    fn pump_pid1(&mut self) {
        // The hotplug.<subsys> script queue and the /etc/hotplug.d inotify
        // run in BOTH modes -- the supervisor answers `hotplug.* call` too.
        {
            let now = self.now_ms();
            let mut d = std::mem::take(&mut self.dispatch);
            let ready = std::mem::replace(&mut self.inotify_ready, false);
            d.pump(&mut self.conn, now, ready);
            self.dispatch = d;
        }
        let now = self.now_ms();
        self.wdt.pump(now);
        if self.boot == Boot::NotPid1 {
            return;
        }
        if let Some(mut hp) = self.hotplug.take() {
            #[expect(unsafe_code, reason = "firmware workers are owned by the single-threaded supervisor")]
            // SAFETY: the private event owner starts no threads and holds no
            // application lock while hotplug may fork its firmware worker.
            let (console, events) = unsafe { hp.pump(now) };
            if console {
                // start-console: run the console handlers again for a tty
                // that appeared late (ttyGS). Done here, in the parent, so
                // the respawn pids stay supervised.
                self.inittab_run(inittab::Kind::Respawn);
                self.inittab_run(inittab::Kind::Askfirst);
            }
            // hotplug_ubus_event(): a uevent whose SUBSYSTEM has a
            // hotplug.<subsys> object is notified to its subscribers.
            for vars in events {
                let Some(subsys) = vars.get("SUBSYSTEM") else { continue };
                let Some(id) = self.dispatch.objects.get(subsys).copied() else { continue };
                let mut b = BlobBuf::new();
                for (k, v) in &vars {
                    b.msg_string(k, v);
                }
                let _ = self.conn.notify(id, "event", b.payload());
            }
            self.hotplug = Some(hp);
        }
        let event = owrt_platform::procd::signals::SHUTDOWN_EVENT.swap(0, std::sync::atomic::Ordering::SeqCst);
        if event != 0 {
            self.procd_shutdown(event);
        }
        let due: Vec<usize> = self
            .inittab
            .iter()
            .enumerate()
            .filter(|(_, a)| a.respawn_at.is_some_and(|at| now >= at))
            .map(|(i, _)| i)
            .collect();
        for i in due {
            self.inittab[i].respawn_at = None;
            self.fork_action(i);
        }
        self.serial.pump(now);
        if self.serial_awaited && self.serial.is_idle() {
            self.serial_awaited = false;
            self.state_next();
        }
    }

    /// `watchdog_set()`: the clamp arithmetic runs on the METHOD side; the
    /// module stores what it is finally told.
    fn handle_system_watchdog(&mut self, req: &Request) -> i32 {
        let now = self.now_ms();
        let mut frequency: Option<u32> = None;
        let mut timeout: Option<u32> = None;
        let mut magicclose: Option<bool> = None;
        let mut stop: Option<bool> = None;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "frequency" => frequency = f.as_u32(),
                "timeout" => timeout = f.as_u32(),
                "magicclose" => magicclose = f.as_bool(),
                "stop" => stop = f.as_bool(),
                _ => {}
            }
        }
        if let Some(freq) = frequency {
            if freq != 0 {
                let t = timeout.unwrap_or(self.wdt.timeout(0) as u32);
                let freq = freq.min(t / 2);
                if freq != 0 {
                    self.wdt.frequency(freq as i32);
                }
            }
        }
        if let Some(mut t) = timeout {
            let freq = self.wdt.frequency(0) as u32;
            if t <= freq {
                t = freq * 2;
            }
            self.wdt.timeout(t as i32);
        }
        if let Some(v) = magicclose {
            self.wdt.set_magicclose(v);
        }
        if let Some(v) = stop {
            self.wdt.set_stopped(v, now);
        }
        let status_str = if !self.wdt.is_open() {
            "offline"
        } else if self.wdt.stopped() {
            "stopped"
        } else {
            "running"
        };
        let mut b = BlobBuf::new();
        b.msg_string("status", status_str);
        b.msg_u32("timeout", self.wdt.timeout(0) as u32);
        b.msg_u32("frequency", self.wdt.frequency(0) as u32);
        b.msg_bool("magicclose", self.wdt.magicclose());
        let _ = self.conn.reply_data(req, b.payload());
        status::OK
    }

    // -- events ------------------------------------------------------------

    /// `service_event()`: a notification on the `service` object carrying the
    /// service and instance names.
    fn service_event(&mut self, kind: &str, svc: &str, name: &str) {
        let mut b = BlobBuf::new();
        b.msg_string("service", svc);
        b.msg_string("instance", name);
        let _ = self.conn.notify(self.objects.service, kind, b.payload());
    }

    /// `service_event(type, name, NULL)`: ubus_event_bcast() skips a NULL
    /// value, so `service.start`/`service.stop` carry only the service.
    fn service_only_event(&mut self, kind: &str, svc: &str) {
        let mut b = BlobBuf::new();
        b.msg_string("service", svc);
        let _ = self.conn.notify(self.objects.service, kind, b.payload());
    }

    /// Re-open the bus and re-register everything that lived on it: the
    /// three objects, the event handler and every watch subscription. An
    /// object id is only meaningful to one connection, so the old ids and
    /// the subscription set have to be discarded first.
    fn reconnect(&mut self) -> io::Result<()> {
        // Reply coordinates belong to the old connection generation.
        self.pending_set = None;
        let mut conn = Connection::connect(None)?;
        conn.set_server_io_timeout(std::time::Duration::from_secs(1));
        self.conn = conn;
        self.objects.service = self.conn.add_object("service", ubus::SERVICE_METHODS, 1000)?;
        self.objects.container =
            self.conn.add_object("container", ubus::CONTAINER_METHODS, 1000)?;
        self.objects.system = self.conn.add_object("system", ubus::SYSTEM_METHODS, 1000)?;
        {
            let mut d = std::mem::take(&mut self.dispatch);
            d.reregister();
            self.dispatch = d;
        }
        if self.boot == Boot::Ubus {
            self.register_initial_hotplug();
        }
        self.watch_obj = self.conn.add_anonymous_object(1000)?;
        self.conn
            .register_event_handler(self.watch_obj, Some("ubus.object.add"), 1000)?;
        // Subscriptions belonged to the old connection; re-establish them
        // against whatever exists on the new bus.
        self.subscribed.clear();
        self.watch_pending.clear();
        self.resubscribe();
        Ok(())
    }

    fn register_initial_hotplug(&mut self) {
        let count = self.dispatch.register_all();
        for _ in 0..count {
            let now = self.now_ms();
            self.dispatch.pump_registration(&mut self.conn, now);
            self.maintain_initial_registration();
        }
    }

    fn boot_bus_ready(&mut self) {
        if self.boot == Boot::Ubus {
            self.run_init_script("ubus");
            self.state_next();
        }
    }

    // -- ubus --------------------------------------------------------------

    /// Handle one bus message. Returns true when it may have changed
    /// something the maintenance pass (timers, triggers, queues) acts on;
    /// read-only queries return false so the pass can be skipped for them.
    fn dispatch(&mut self, msg: Incoming) -> bool {
        let Incoming::Invoke(req) = msg else { return false };
        // watch_notify_cb(): a notification delivered to our subscriber
        // object arrives as an INVOKE whose method is the notification type.
        // ubusd's own event object announces new objects the same way.
        if req.objid == self.watch_obj {
            let now = self.now_ms();
            let mut vars: BTreeMap<String, String> = BTreeMap::new();
            for f in owrt_ubus::blob::fields(&req.data) {
                if let Some(v) = f.as_str() {
                    vars.insert(f.name.to_string(), v.to_string());
                }
            }
            if req.method == "ubus.object.add" {
                // watch_subscribe_cb only looks up the announced path when
                // an instance watches it. Unrelated object churn must not
                // turn into N synchronous calls that stall supervision.
                if let Some(path) = vars.get("path") {
                    if self.watches.values().flatten().any(|wanted| wanted == path) {
                        let id = owrt_ubus::blob::fields(&req.data)
                            .find(|f| f.name == "id").and_then(|f| f.as_u32());
                        if id.is_none_or(|id| self.subscribed.get(path) != Some(&id)) {
                            self.queue_watch(path);
                        }
                    }
                }
            } else {
                self.triggers.fire(&req.method, &vars, now);
            }
            let _ = self.conn.reply_status(&req, status::OK, None);
            self.conn.recycle_request(req);
            return true;
        }
        let target = if req.objid == self.objects.service {
            Target::Service
        } else if req.objid == self.objects.container {
            Target::Container
        } else if req.objid == self.objects.system {
            Target::System
        } else if let Some(subsys) = self.dispatch.subsystem_of(req.objid).map(str::to_string) {
            let now = self.now_ms();
            let mut d = std::mem::take(&mut self.dispatch);
            let code = if req.method == "call" {
                d.call(&subsys, &req.data, now)
            } else {
                status::NOT_SUPPORTED
            };
            self.dispatch = d;
            let _ = self.conn.reply_status(&req, code, None);
            self.conn.recycle_request(req);
            return true;
        } else {
            let _ = self.conn.reply_status(&req, status::NOT_FOUND, None);
            self.conn.recycle_request(req);
            return false;
        };
        if matches!((target, req.method.as_str()), (Target::Service, "set" | "add")) {
            let mut name = None;
            let mut instances = false;
            for field in owrt_ubus::blob::fields(&req.data) {
                match field.name {
                    "name" => name = field.as_str(),
                    "instances" => instances = true,
                    _ => {}
                }
            }
            let new_service = name.is_some_and(|name| !self.services.contains_key(name));
            let name = name.map(str::to_owned);
            let code = self.handle_set(&req, req.method == "add");
            if code == status::OK && instances {
                let name = name.expect("successful set has a service name");
                let paths = self.watches.get(&name).cloned().unwrap_or_default();
                if !paths.is_empty() {
                    self.pending_set = Some(PendingSet { request: req, paths: paths.into(),
                        service: name, new_service });
                    return true;
                }
                self.finish_set(&name, new_service);
            }
            let _ = self.conn.reply_status(&req, code, None);
            self.conn.recycle_request(req);
            return true;
        }
        // Pure reads: nothing for the maintenance pass to pick up afterwards.
        let read_only = matches!(
            (target, req.method.as_str()),
            (Target::Service, "list" | "get_data" | "validate") | (Target::System, "info" | "board")
        );
        self.handle(target, &req);
        self.conn.recycle_request(req);
        !read_only
    }

    fn handle(&mut self, target: Target, req: &Request) {
        let code = match (target, req.method.as_str()) {
            (Target::Service, "list") => {
                service::dump_list(&self.services, &req.data, &mut self.read_reply);
                let _ = self.conn.reply_data_status(req, self.read_reply.payload(), status::OK);
                self.read_reply.reset_bounded(16 * 1024);
                return;
            }
            (Target::Service, "delete") => self.handle_delete(req),
            (Target::Service, "signal") => self.handle_signal(req),
            (Target::Service, "state") => self.handle_state(req),
            (Target::Service, "update_start") => self.handle_update(req, true),
            (Target::Service, "update_complete") => self.handle_update(req, false),
            (Target::Service, "get_data") => self.handle_get_data(req),
            (Target::Service, "set_data") => self.handle_set_data(req),
            (Target::Service, "event") => self.handle_event(req),
            (Target::Service, "validate") => self.handle_validate(req),
            (Target::Service, "watchdog") => self.handle_watchdog(req),
            // system_reboot(): procd_shutdown(RB_AUTOBOOT). Only PID 1 has a
            // machine to advance; the supervisor-only mode keeps rejecting.
            (Target::System, "reboot") if self.boot != Boot::NotPid1 => {
                self.procd_shutdown(sys::RB_AUTOBOOT);
                status::OK
            }
            (Target::System, "board") => {
                let mut b = BlobBuf::new();
                sysobj::build_board(&mut b);
                let _ = self.conn.reply_data(req, b.payload());
                status::OK
            }
            (Target::System, "info") => {
                if sysobj::build_info(&mut self.read_reply, &mut self.meminfo) {
                    let _ = self.conn.reply_data_status(req, self.read_reply.payload(), status::OK);
                } else {
                    let _ = self.conn.reply_status(req, status::UNKNOWN_ERROR, None);
                }
                self.read_reply.reset_bounded(16 * 1024);
                return;
            }
            (Target::System, "watchdog") => self.handle_system_watchdog(req),
            (Target::System, "signal") => {
                // proc_signal(): both fields required, the kill() result is
                // deliberately not checked.
                let mut pid: Option<u32> = None;
                let mut signum: Option<u32> = None;
                for f in owrt_ubus::blob::fields(&req.data) {
                    match f.name {
                        "pid" => pid = f.as_u32(),
                        "signum" => signum = f.as_u32(),
                        _ => {}
                    }
                }
                let (Some(pid), Some(signum)) = (pid, signum) else {
                    return {
                        let _ = self.conn.reply_status(req, status::INVALID_ARGUMENT, None);
                    };
                };
                proc::signal(pid as i32, signum as i32);
                status::OK
            }
            (Target::System, "validate_firmware_image") => {
                let mut path = None;
                for f in owrt_ubus::blob::fields(&req.data) {
                    if f.name == "path" {
                        path = f.as_str().map(str::to_string);
                    }
                }
                match path {
                    None => status::INVALID_ARGUMENT,
                    Some(p) => match sysupgrade::validate_call(&p) {
                        Ok(payload) => {
                            let _ = self.conn.reply_data(req, &payload);
                            status::OK
                        }
                        // The C only returns the status here; the error text
                        // is a sysupgrade-reply thing.
                        Err(_) => status::UNKNOWN_ERROR,
                    },
                }
            }
            (Target::System, "sysupgrade") => self.handle_sysupgrade(req),
            _ => status::NOT_SUPPORTED,
        };
        let _ = self.conn.reply_status(req, code, None);
    }

    /// `sysupgrade_error()`: the reply is a table {"error": {"message": m}}.
    fn sysupgrade_error(&mut self, req: &Request, message: &str) {
        let mut b = BlobBuf::new();
        let t = b.msg_open_table("error");
        b.msg_string("message", message);
        b.msg_close(t);
        let _ = self.conn.reply_data(req, b.payload());
    }

    /// `sysupgrade()` (system.c). On the success path exec_upgraded replaces
    /// this process and nothing returns; every other path answers a status
    /// (with an error table for everything past argument validation).
    fn handle_sysupgrade(&mut self, req: &Request) -> i32 {
        use owrt_ubus::msg::status;
        let (mut path, mut prefix, mut backup, mut command) = (None, None, None, None);
        let mut force = false;
        let mut options: Vec<(String, String)> = Vec::new();
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "path" => path = f.as_str().map(str::to_string),
                "prefix" => prefix = f.as_str().map(str::to_string),
                "backup" => backup = f.as_str().map(str::to_string),
                "command" => command = f.as_str().map(str::to_string),
                "force" => force = f.as_bool().unwrap_or(false),
                "options" => {
                    for c in f.children() {
                        options.extend(sysupgrade::option_env(c.name, c.ty, c.data));
                    }
                }
                _ => {}
            }
        }
        let (Some(path), Some(prefix)) = (path, prefix) else {
            return status::INVALID_ARGUMENT;
        };

        let payload = match sysupgrade::validate_call(&path) {
            Ok(p) => p,
            Err(msg) => {
                self.sysupgrade_error(req, &msg);
                return status::UNKNOWN_ERROR;
            }
        };
        // blobmsg_parse with a BOOL policy: only bool-typed fields count.
        let (mut valid, mut forceable, mut allow_backup) = (None, None, None);
        for f in owrt_ubus::blob::fields(&payload) {
            match f.name {
                "valid" => valid = f.as_bool(),
                "forceable" => forceable = f.as_bool(),
                "allow_backup" => allow_backup = f.as_bool(),
                _ => {}
            }
        }
        let (Some(valid), Some(forceable), Some(allow_backup)) = (valid, forceable, allow_backup)
        else {
            self.sysupgrade_error(req, "Validation script provided invalid input");
            return status::INVALID_ARGUMENT;
        };
        if !valid {
            if !forceable {
                self.sysupgrade_error(req, "Firmware image is broken and cannot be installed");
                return status::NOT_SUPPORTED;
            } else if !force {
                self.sysupgrade_error(req, "Firmware image is invalid");
                return status::NOT_SUPPORTED;
            }
        } else if !allow_backup && backup.is_some() {
            self.sysupgrade_error(req, "Firmware image doesn't allow preserving a backup");
            return status::NOT_SUPPORTED;
        }

        self.service_stop_all();
        sysupgrade::exec_upgraded(
            &prefix,
            &path,
            backup.as_deref(),
            command.as_deref(),
            &options,
            &mut self.wdt,
        );
        // exec_upgraded only returns on failure.
        status::UNKNOWN_ERROR
    }

    /// `service_stop_all()`: halt every instance, kill the inittab children
    /// with respawn disabled, and give the stopping instances their longest
    /// term_timeout before the exec that follows.
    fn service_stop_all(&mut self) {
        let mut term: u32 = 0;
        let pairs: Vec<(String, String)> = self
            .services
            .iter()
            .flat_map(|(s, svc)| svc.instances.keys().map(move |i| (s.clone(), i.clone())))
            .collect();
        for (s, i) in &pairs {
            if let Some(inst) = self.services.get(s).and_then(|v| v.instances.get(i)) {
                term = term.max(inst.term_timeout);
            }
            self.instance_stop(s, i, true);
        }
        // procd_inittab_kill(): respawn off, SIGKILL what runs.
        for a in &mut self.inittab {
            a.respawn_at = None;
            a.respawn_ms = -1;
            if let Some(pid) = a.pid {
                proc::signal(pid, proc::SIGKILL);
            }
        }
        // The C sleeps synchronously here; the exec follows immediately.
        std::thread::sleep(std::time::Duration::from_secs(term as u64));
    }

    /// `service_handle_set()`. `add` merges into the existing instance set;
    /// `set` replaces it, which is the vlist update/flush pair.
    fn handle_set(&mut self, req: &Request, add: bool) -> i32 {
        let mut name: Option<String> = None;
        let mut autostart: Option<bool> = None;
        let mut fresh: BTreeMap<String, Instance> = BTreeMap::new();
        let mut trigger: Option<Vec<u8>> = None;
        let mut validate: Option<Vec<service::Validator>> = None;
        let mut data: BTreeMap<String, (u32, Vec<u8>)> = BTreeMap::new();
        let mut saw_instances = false;
        let mut saw_data = false;

        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "autostart" => autostart = f.as_bool(),
                "triggers" => trigger = Some(f.data.to_vec()),
                "validate" => {
                    // service_validate_del() then one add per entry, so a
                    // `set` carrying `validate` replaces the whole set.
                    let mut v = Vec::new();
                    for e in f.children() {
                        let mut package = None;
                        let mut kind = None;
                        let mut rules = BTreeMap::new();
                        let mut saw_data = false;
                        for a in e.children() {
                            match a.name {
                                "package" => package = a.as_str().map(str::to_string),
                                "type" => kind = a.as_str().map(str::to_string),
                                "data" => {
                                    saw_data = true;
                                    for r in a.children() {
                                        if let Some(rv) = r.as_str() {
                                            rules.insert(r.name.to_string(), rv.to_string());
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        // All three are required; the C returns early
                        // without adding anything otherwise.
                        if let (Some(package), Some(kind), true) = (package, kind, saw_data) {
                            v.push(service::Validator {
                                package,
                                kind,
                                seq: self.validator_seq,
                                rules,
                            });
                            self.validator_seq += 1;
                        }
                    }
                    validate = Some(v);
                }
                "instances" => {
                    saw_instances = true;
                    for e in f.children().filter(|e| e.ty == owrt_ubus::MsgType::Table as u32) {
                        let iname = e.name.to_string();
                        fresh.insert(iname.clone(), instance::parse(&iname, e));
                    }
                }
                "data" => {
                    saw_data = true;
                    for c in f.children() {
                        data.insert(c.name.to_string(), (c.ty, c.data.to_vec()));
                    }
                }
                _ => {}
            }
        }

        let Some(name) = name else {
            return status::INVALID_ARGUMENT;
        };

        let init = !self.services.contains_key(&name);
        let s = self
            .services
            .entry(name.clone())
            .or_insert_with(|| Service::new(&name));
        if let Some(a) = autostart {
            s.autostart = a;
        } else if init {
            s.autostart = true;
        }
        if let Some(t) = trigger {
            // service_update(): the old rules go before the new ones are
            // added, so a `set` that changes triggers does not accumulate.
            s.trigger = Some(t);
            let raw = s.trigger.clone().expect("just assigned");
            self.triggers.del(&trigger::Owner::Service(name.clone()));
            let f = owrt_ubus::blob::Field {
                name: "",
                ty: owrt_ubus::blob::MsgType::Array as u32,
                data: &raw,
            };
            self.triggers.add(f, trigger::Owner::Service(name.clone()));
        }
        // Re-borrowed: the trigger update above needed `self`, not just `s`.
        let s = self.services.get_mut(&name).expect("service exists");
        if let Some(v) = validate {
            s.validate = v;
        }
        let data_changed = saw_data && s.data != data;
        // service_update_data() fires for the OLD keys before replacing, and
        // for the new ones after. Capture the old snapshot first.
        let old_data_keys: Vec<String> = if data_changed {
            s.data.keys().cloned().collect()
        } else {
            Vec::new()
        };
        if saw_data {
            s.data = data;
        }
        s.deleted = false;
        let autostart = s.autostart;

        if !saw_instances {
            if data_changed {
                self.data_trigger_keys(&old_data_keys);
                let fresh = self.data_keys(&name);
                self.data_trigger_keys(&fresh);
            }
            if init {
                self.run_init_script(&name);
                // service_handle_set(): after service_update() returns for a
                // NEWLY created service, `service.start` goes out. An update
                // of an existing one notifies nothing at the service level.
                self.service_only_event("service.start", &name);
            }
            return status::OK;
        }

        // instance_init() ends with service_data_trigger(&in->data) for EVERY
        // instance in the message -- before the vlist diff decides whether it
        // is new, changed or the same. (R81 F22.)
        let fresh_keys: Vec<Vec<String>> = fresh
            .values()
            .map(|i| i.data.keys().cloned().collect())
            .collect();
        for keys in &fresh_keys {
            self.data_trigger_keys(keys);
        }
        let s = self.services.get_mut(&name).expect("service exists");

        // The plan has to be computed before anything mutates, because the C
        // walks the vlist diff once and acts on each entry as it goes.
        let plan = s.plan(&fresh);

        for (iname, change) in plan {
            match change {
                service::InstanceChange::Start => {
                    let inst = fresh.remove(&iname).expect("plan named a fresh instance");
                    let valid = inst.valid;
                    self.services
                        .get_mut(&name)
                        .expect("service was just inserted")
                        .instances
                        .insert(iname.clone(), inst);
                    if autostart && valid {
                        self.instance_start(&name, &iname);
                    }
                    self.register_instance_triggers(&name, &iname);
                }
                service::InstanceChange::Stop => {
                    // `add` leaves untouched names alone; only `set` flushes.
                    if add {
                        continue;
                    }
                    self.instance_stop(&name, &iname, true);
                    self.collect_stopped(&name, &iname);
                }
                service::InstanceChange::Update => {
                    let new = fresh.remove(&iname).expect("plan named a fresh instance");
                    self.instance_update(&name, &iname, new);
                    // A re-add during an update_start/update_complete window
                    // is what keeps the instance alive past the flush.
                    if let Some(i) =
                        self.services.get_mut(&name).and_then(|s| s.instances.get_mut(&iname))
                    {
                        i.stale = false;
                    }
                    self.register_instance_triggers(&name, &iname);
                }
            }
            self.instance_update_trigger();
        }

        if data_changed {
            self.data_trigger_keys(&old_data_keys);
            let fresh = self.data_keys(&name);
            self.data_trigger_keys(&fresh);
        }
        self.refresh_watches(&name);
        // The dispatcher finishes rc("running") and service.start after
        // this service's initial watch attempts, preserving their old order.
        status::OK
    }

    fn finish_set(&mut self, name: &str, new_service: bool) {
        self.run_init_script(name);
        if new_service {
            self.service_only_event("service.start", name);
        }
    }

    /// `instance_update()`. Not running (or already stopping) means take the
    /// new config and start; running means restart only on a real config
    /// change, and a data-only change fires the data triggers instead.
    fn instance_update(&mut self, svc: &str, name: &str, new: Instance) {
        let Some(inst) = self.services.get_mut(svc).and_then(|s| s.instances.get_mut(name)) else {
            return;
        };
        // C: `running = in->proc.pending; stopping = in->halt;`
        // A child in the TERM grace period is still running. The halt flag
        // is independent: state(spawn=false) sets Run::Halting but halt=false.
        let running = inst.state == Run::Running || inst.state == Run::Halting;
        let stopping = inst.halt;
        let changed = inst.config_changed(&new);
        let data_changed = inst.data != new.data;

        if !running || stopping {
            inst.take_config(new);
            self.instance_start(svc, name);
            return;
        }
        // instance_update() calls instance_restart() FIRST and moves the
        // config afterwards, so the stop uses the OLD reload_signal,
        // term_timeout and has_jail. Doing it the other way round sends a
        // signal the running process was never configured for -- measured:
        // it kills it.
        // The data-only branch fires for the OLD instance data and then the
        // NEW instance data. Passing the service's keys was wrong twice
        // over: wrong owner, and taken after the swap.
        let old_keys: Vec<String> = inst.data.keys().cloned().collect();
        let new_keys: Vec<String> = new.data.keys().cloned().collect();
        if changed {
            self.instance_restart(svc, name);
        }
        if let Some(inst) = self.services.get_mut(svc).and_then(|s| s.instances.get_mut(name)) {
            inst.take_config(new);
        }
        if !changed && data_changed {
            self.data_trigger_keys(&old_keys);
            self.data_trigger_keys(&new_keys);
        }
    }

    /// `watch_add()`: remember which ubus paths a service's instances want,
    /// and subscribe to any that already exist. `watch_del()` first, so a
    /// `set` replaces rather than accumulates.
    fn refresh_watches(&mut self, svc: &str) {
        self.watches.remove(svc);
        let mut paths: Vec<String> = Vec::new();
        if let Some(s) = self.services.get(svc) {
            for i in s.instances.values() {
                for w in &i.watch {
                    if !paths.contains(w) {
                        paths.push(w.clone());
                    }
                }
            }
        }
        if paths.is_empty() {
            self.resubscribe();
            return;
        }
        self.watches.insert(svc.to_string(), paths);
        self.resubscribe();
    }

    /// Reconcile pending work without resetting its order or retry times.
    /// Deleted watches drop out; newly wanted paths join the tail. No bus
    /// call runs on the config/collection/reconnect stack.
    fn resubscribe(&mut self) {
        let mut wanted: Vec<String> = self.watches.values().flatten().cloned().collect();
        wanted.sort();
        wanted.dedup();
        self.watch_pending.retain(|(path, _)| wanted.binary_search(path).is_ok());
        for path in wanted {
            self.queue_watch(&path);
        }
    }

    fn queue_watch(&mut self, path: &str) {
        if !self.watch_pending.iter().any(|(queued, _)| queued == path) {
            self.watch_pending.push_back((path.to_owned(), self.now_ms()));
        }
    }

    /// One path costs at most a 1 s lookup plus a 1 s subscription. Return
    /// to the main loop's maintenance before starting another; do not call
    /// reap/timeouts here (collection can itself change watch ownership).
    fn pump_watch(&mut self) -> bool {
        let now = self.now_ms();
        let Some(index) = self.watch_pending.iter().position(|(_, at)| *at <= now) else {
            return false;
        };
        let (path, _) = self.watch_pending.remove(index).unwrap();
        if !self.watches.values().flatten().any(|wanted| wanted == &path) {
            return true;
        }
        let _ = self.attempt_watch(&path);
        true
    }

    fn attempt_watch(&mut self, path: &str) -> io::Result<()> {
        let result = self.resubscribe_path(path);
        if let Err(error) = &result {
            // Missing paths wait for object.add. Other failures rotate back
            // into the asynchronous queue, after this attempt has completed.
            if owrt_ubus::conn::error_status(error).is_none_or(|code| {
                !matches!(code, status::NOT_FOUND | status::INVALID_ARGUMENT | status::PERMISSION_DENIED)
            }) && !self.watch_pending.iter().any(|(queued, _)| queued == path) {
                self.watch_pending.push_back((path.to_owned(), self.now_ms() + 1000));
            }
        }
        result
    }

    /// Preserve R89's set-return boundary, but service deadlines between
    /// attempts. A missing/failed path completes this attempt; background
    /// retries must never hold the reply indefinitely.
    fn pump_pending_set(&mut self) -> io::Result<()> {
        let Some(mut pending) = self.pending_set.take() else { return Ok(()) };
        if let Some(path) = pending.paths.pop_front() {
            if let Err(error) = self.attempt_set_watch(&path) {
                // Configuration is already applied. R89 still ran the local
                // running hook after failed lookups. Keep it exactly once,
                // without replaying old bus ids/replies on a new generation.
                self.run_init_script(&pending.service);
                return Err(error);
            }
        }
        if pending.paths.is_empty() {
            self.finish_set(&pending.service, pending.new_service);
            self.conn.reply_status(&pending.request, status::OK, None)?;
            self.conn.recycle_request(pending.request);
        } else {
            self.pending_set = Some(pending);
        }
        Ok(())
    }

    fn attempt_set_watch(&mut self, path: &str) -> io::Result<()> {
        self.watch_pending.retain(|(queued, _)| queued != path);
        if !self.watches.values().flatten().any(|wanted| wanted == path) {
            return Ok(());
        }
        if let Err(error) = self.attempt_watch(path) {
            if owrt_ubus::conn::error_status(&error).is_none() {
                return Err(error);
            }
            // A clean timeout preserves framing; a partial one shuts the
            // socket down. Do not retain or reply to an old request then.
            use owrt_ubus::sys::{PollFd, POLLERR, POLLHUP};
            let mut fd = [PollFd { fd: self.conn.as_raw_fd(), events: 0, revents: 0 }];
            owrt_ubus::sys::poll_fds(&mut fd, 0)?;
            if fd[0].revents & (POLLERR | POLLHUP) != 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "watch connection closed"));
            }
        }
        Ok(())
    }

    /// The normal supervision pass, also used between deferred set attempts.
    /// No business request dispatch occurs here.
    fn maintain(&mut self) {
        self.pump_logs();
        self.reap();
        self.fire_timeouts();
        self.pump_triggers();
        self.pump_pid1();
        self.rc.pump(self.now_ms());
    }

    fn resubscribe_path(&mut self, path: &str) -> io::Result<()> {
        // NOT unsubscribing here is deliberate, and it is what C does.
        // watch.c's watch_del() only unlinks the entry from watch_objects --
        // it never calls ubus_unsubscribe. So after an instance is freed:
        //
        //   * the object is RECREATED with a new id -> nothing re-attaches
        //     to it, because the path is no longer wanted, and no rule fires;
        //   * the object is STILL ALIVE and keeps notifying -> the old
        //     subscription is still registered with ubusd, watch_notify_cb
        //     still turns the notification into a trigger event, and another
        //     service's rule for that type still fires.
        //
        // Dropping the subscription here would make the second case fire
        // less often than C. The stale entry in `subscribed` is harmless: it
        // is only consulted if the path becomes wanted again, and then a
        // recreated object's new id makes it resubscribe anyway.
        // A path that does not exist yet is not an error: the
        // ubus.object.add event brings us back here when it appears.
        let id = self.conn.lookup_id(path, 1000)?;
        // An object that was destroyed and recreated comes back with a NEW
        // id, so a remembered old id must not suppress its subscription.
        if self.subscribed.get(path) == Some(&id) {
            return Ok(());
        }
        self.conn.subscribe(self.watch_obj, id, 1000)?;
        self.subscribed.insert(path.to_owned(), id);
        Ok(())
    }

    /// `trigger_add(in->trigger, in)`: an instance's own `triggers` array is
    /// registered with the instance as owner, so it is released when the
    /// instance is, independently of the service's rules. This was parsed
    /// and then dropped on the floor.
    fn register_instance_triggers(&mut self, svc: &str, name: &str) {
        let owner = trigger::Owner::Instance(svc.to_string(), name.to_string());
        self.triggers.del(&owner);
        let raw = self
            .services
            .get(svc)
            .and_then(|s| s.instances.get(name))
            .and_then(|i| i.triggers.clone());
        let Some(raw) = raw else { return };
        let f = owrt_ubus::blob::Field {
            name: "",
            ty: owrt_ubus::blob::MsgType::Array as u32,
            data: &raw,
        };
        self.triggers.add(f, owner);
    }

    /// `rc(name, "running")`: queue `<init.d>/<name> running` if that script
    /// exists. A service with no init script queues nothing, which is the
    /// normal case for anything registered straight over the bus.
    fn run_init_script(&mut self, name: &str) {
        let now = self.now_ms();
        let dir = self.init_d.clone();
        self.rc.queue(&dir, name, "running", now);
    }

    /// `service_data_trigger()`: one `service.data.update` event per key in
    /// the GIVEN snapshot.
    ///
    /// Two things here are easy to get wrong and both were:
    ///
    /// - it runs the INTERNAL rule engine (`trigger_event`), not a ubus
    ///   notification. A notification on the service object reaches ubus
    ///   subscribers; it does not run the service's own `triggers`, which is
    ///   what `procd_add_reload_data_trigger` registers.
    /// - it is called with the OLD keys and then the NEW ones, so it needs a
    ///   snapshot rather than "whatever the service holds right now".
    fn data_trigger_keys(&mut self, keys: &[String]) {
        let now = self.now_ms();
        for k in keys {
            let mut vars = BTreeMap::new();
            vars.insert("name".to_string(), k.clone());
            // And nothing on the bus: service_data_trigger() is trigger_event()
            // only. A subscriber of the service object never sees a
            // `service.data.update` from the C, so it must not see one here --
            // case 28 of r65 now compares exactly that stream.
            self.triggers.fire("service.data.update", &vars, now);
        }
    }

    /// The keys a service's data currently has, for use as a snapshot.
    fn data_keys(&self, svc: &str) -> Vec<String> {
        self.services
            .get(svc)
            .map(|s| s.data.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// service_instance_update emits this internal event for every vlist diff,
    /// including unchanged replacements and deletion. There is no ubus notify.
    fn instance_update_trigger(&mut self) {
        let now = self.now_ms();
        self.triggers.fire("instance.update", &BTreeMap::new(), now);
    }

    /// `service_handle_delete()`. Without `instance`, the whole service goes;
    /// with it, only that instance.
    fn handle_delete(&mut self, req: &Request) -> i32 {
        let mut name: Option<String> = None;
        let mut inst: Option<String> = None;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "instance" => inst = f.as_str().map(str::to_string),
                _ => {}
            }
        }
        // service_handle_delete(): a missing `name` is NOT_FOUND, unlike
        // `set`. (R81 F22.)
        let Some(name) = name else {
            return status::NOT_FOUND;
        };
        if !self.services.contains_key(&name) {
            return status::NOT_FOUND;
        }
        match inst {
            Some(i) => {
                if !self.services[&name].instances.contains_key(&i) {
                    return status::NOT_FOUND;
                }
                self.instance_stop(&name, &i, true);
                self.collect_stopped(&name, &i);
                self.instance_update_trigger();
            }
            None => {
                let names: Vec<String> =
                    self.services[&name].instances.keys().cloned().collect();
                if let Some(s) = self.services.get_mut(&name) {
                    s.data.clear();
                }
                for i in names {
                    self.instance_stop(&name, &i, true);
                    self.collect_stopped(&name, &i);
                    self.instance_update_trigger();
                }
                // C marks the service deleted only after vlist_flush_all.
                // Keep its own triggers alive through the last instance event.
                if let Some(s) = self.services.get_mut(&name) {
                    s.deleted = true;
                }
                if self.services.get(&name).is_some_and(|s| s.can_be_freed()) {
                    self.service_only_event("service.stop", &name);
                    self.triggers.del_service(&name);
                    self.services.remove(&name);
                }
            }
        }
        status::OK
    }

    /// `service_handle_watchdog()`. Both `name` and `instance` are required
    /// and a missing one is NOT_FOUND, not INVALID_ARGUMENT. Supplying
    /// either `mode` or `timeout` marks the instance self-managed, which
    /// takes those two fields out of the config-change comparison.
    fn handle_watchdog(&mut self, req: &Request) -> i32 {
        let now = self.now_ms();
        let mut name: Option<String> = None;
        let mut instance: Option<String> = None;
        let mut mode: Option<u32> = None;
        let mut timeout: Option<u32> = None;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "instance" => instance = f.as_str().map(str::to_string),
                "mode" => mode = f.as_u32(),
                "timeout" => timeout = f.as_u32(),
                _ => {}
            }
        }
        let (Some(name), Some(instance)) = (name, instance) else {
            return status::NOT_FOUND;
        };
        let Some(inst) = self
            .services
            .get_mut(&name)
            .and_then(|s| s.instances.get_mut(&instance))
        else {
            return status::NOT_FOUND;
        };
        if let Some(m) = mode {
            inst.watchdog_mode = m;
        }
        if let Some(t) = timeout {
            inst.watchdog_freq = t;
        }
        // service_handle_watchdog arms or cancels the per-instance timer
        // right here. This is a software timer in the supervisor, reachable
        // when getpid() != 1 -- it is not the system /dev/watchdog, and
        // deferring it to the PID 1 stage was wrong.
        if inst.watchdog_mode == 0 {
            inst.watchdog_deadline = None;
        } else {
            inst.watchdog_deadline = Some(now + inst.watchdog_freq as i64 * 1000);
        }
        let (m, t) = (inst.watchdog_mode, inst.watchdog_freq);
        if mode.is_some() || timeout.is_some() {
            inst.watchdog_self_managed = true;
        }

        let mut b = BlobBuf::new();
        b.msg_string("name", &name);
        b.msg_string("instance", &instance);
        b.msg_u32("mode", m);
        b.msg_u32("timeout", t);
        let _ = self.conn.reply_data(req, b.payload());
        status::OK
    }

    /// `service_handle_validate()`. Grouped package -> type -> option -> rule
    /// across every service, filtered by `package` and `type`. A `service`
    /// argument short-circuits with an empty reply, which is what the C does
    /// before it looks at anything else.
    fn handle_validate(&mut self, req: &Request) -> i32 {
        let mut package: Option<String> = None;
        let mut kind: Option<String> = None;
        let mut saw_service = false;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "package" => package = f.as_str().map(str::to_string),
                "type" => kind = f.as_str().map(str::to_string),
                "service" => saw_service = true,
                _ => {}
            }
        }
        if saw_service {
            return status::OK;
        }
        // The C walks one global avl keyed by package (duplicates allowed)
        // and builds a json_object, so: packages in strcmp order, types in
        // insertion order within a package, options in strcmp order (their
        // own avl). Sorting by (package, seq) reproduces that walk.
        let mut all: Vec<&service::Validator> = self
            .services
            .values()
            .flat_map(|s| s.validate.iter())
            .filter(|v| package.as_ref().is_none_or(|p| *p == v.package))
            .filter(|v| kind.as_ref().is_none_or(|t| *t == v.kind))
            .collect();
        all.sort_by(|a, b| a.package.cmp(&b.package).then(a.seq.cmp(&b.seq)));

        let mut b = BlobBuf::new();
        let mut i = 0;
        while i < all.len() {
            let pkg = &all[i].package;
            let p = b.msg_open_table(pkg);
            // Types in first-seen order; a repeated type merges its options.
            let mut seen: Vec<&str> = Vec::new();
            let start = i;
            while i < all.len() && all[i].package == *pkg {
                if !seen.contains(&all[i].kind.as_str()) {
                    seen.push(all[i].kind.as_str());
                }
                i += 1;
            }
            for ty in seen {
                let t = b.msg_open_table(ty);
                // Each validator contributes its OWN rules in avl (name)
                // order; merging several into one json_object keeps the
                // order keys were first added, it does not re-sort globally.
                // A second validator's `a` therefore lands after the first's
                // `z`.
                let mut emitted: Vec<&str> = Vec::new();
                for v in &all[start..i] {
                    if v.kind != ty {
                        continue;
                    }
                    for (o, r) in &v.rules {
                        if emitted.contains(&o.as_str()) {
                            continue;
                        }
                        emitted.push(o.as_str());
                        b.msg_string(o, r);
                    }
                }
                b.msg_close(t);
            }
            b.msg_close(p);
        }
        let _ = self.conn.reply_data(req, b.payload());
        status::OK
    }

    /// `service_handle_event()`. Both `type` and `data` are required. The
    /// event fires matching triggers, then goes out as an `event.trigger`
    /// notification; a `config.change` additionally broadcasts on the bus so
    /// non-procd listeners see it.
    fn handle_event(&mut self, req: &Request) -> i32 {
        let now = self.now_ms();
        let mut kind: Option<String> = None;
        let mut vars: BTreeMap<String, String> = BTreeMap::new();
        let mut data: Option<Vec<u8>> = None;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "type" => kind = f.as_str().map(str::to_string),
                "data" => {
                    data = Some(f.data.to_vec());
                    for c in f.children() {
                        if let Some(v) = c.as_str() {
                            vars.insert(c.name.to_string(), v.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        let (Some(kind), Some(data)) = (kind, data) else {
            return status::INVALID_ARGUMENT;
        };

        self.triggers.fire(&kind, &vars, now);

        let mut b = BlobBuf::new();
        b.msg_string("type", &kind);
        b.msg_field(owrt_ubus::blob::MsgType::Table as u32, "data", &data);
        let _ = self.conn.notify(self.objects.service, "event.trigger", b.payload());
        // A `config.change` event with a `package` is additionally announced
        // as its own notification, `config.change` {"config": <package>}
        // (ubus_event_bcast in service_handle_event).
        if kind == "config.change" {
            if let Some(pkg) = vars.get("package") {
                let mut b = BlobBuf::new();
                b.msg_string("config", pkg);
                let _ = self.conn.notify(self.objects.service, "config.change", b.payload());
            }
        }
        status::OK
    }

    /// Start whatever queued trigger commands are due, and reap the ones
    /// that finished. The runqueue is width one, so at most one command runs
    /// at a time and an identical command that arrived meanwhile requeues.
    fn pump_triggers(&mut self) {
        let now = self.now_ms();

        // `reap()` has already cleared `pid` and set `finished` for anything
        // that exited. A finished command either requeues once or goes away.
        let mut i = 0;
        while i < self.triggers.pending.len() {
            if !self.triggers.pending[i].finished {
                i += 1;
                continue;
            }
            if self.triggers.pending[i].requeue {
                let c = &mut self.triggers.pending[i];
                c.requeue = false;
                c.finished = false;
                c.due = now;
                i += 1;
            } else {
                self.triggers.pending.remove(i);
            }
        }

        // A set's data updates may have queued commands that notify its
        // watched objects. Keep their old ordering behind initial watch
        // attempts; already running children and their reap bookkeeping
        // above continue while the reply is deferred.
        if self.pending_set.is_some() || self.triggers.pending.iter().any(|c| c.pid.is_some()) {
            return;
        }
        let Some(slot) = self
            .triggers
            .pending
            .iter()
            .position(|c| c.pid.is_none() && now >= c.due)
        else {
            return;
        };
        let argv = self.triggers.pending[slot].argv.clone();
        if argv.is_empty() {
            self.triggers.pending.remove(slot);
            return;
        }
        // stdio to /dev/null, as trigger_command_run does below debug level 3.
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        proc::inherit_ignored_sigpipe(&mut cmd);
        match cmd.spawn() {
            Ok(child) => self.triggers.pending[slot].pid = Some(child.id() as i32),
            // The C forks and the child exits 1 when exec fails; either way
            // the queue entry goes away.
            Err(_) => {
                self.triggers.pending.remove(slot);
            }
        }
    }

    /// `service_handle_state()`. `spawn` is a target state for every
    /// instance of the service: those already in it are skipped, the rest are
    /// started or stopped. The stop is `halt = false`, so the instance stays
    /// in the list rather than being deleted.
    fn handle_state(&mut self, req: &Request) -> i32 {
        let mut spawn: Option<bool> = None;
        let mut name: Option<String> = None;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "spawn" => spawn = f.as_bool(),
                "name" => name = f.as_str().map(str::to_string),
                _ => {}
            }
        }
        // The order matters: a missing `spawn` is INVALID_ARGUMENT, a missing
        // `name` is NOT_FOUND. Both are checked before the lookup.
        let Some(spawn) = spawn else {
            return status::INVALID_ARGUMENT;
        };
        let Some(name) = name else {
            return status::NOT_FOUND;
        };
        let Some(s) = self.services.get(&name) else {
            return status::NOT_FOUND;
        };
        let todo: Vec<(String, bool)> = s
            .instances
            .iter()
            .map(|(n, i)| (n.clone(), i.state == Run::Running || i.state == Run::Halting))
            .filter(|(_, running)| *running != spawn)
            .collect();
        for (iname, running) in todo {
            if running {
                self.instance_stop(&name, &iname, false);
            } else {
                self.instance_start(&name, &iname);
            }
        }
        status::OK
    }

    /// `service_handle_update()`: `update_start` is vlist_update (mark every
    /// instance stale) and `update_complete` is vlist_flush (stop whatever is
    /// still marked). A `set` or `add` in between clears the mark for the
    /// names it names, which is how a multi-call update expresses "these are
    /// the instances that survive".
    fn handle_update(&mut self, req: &Request, start: bool) -> i32 {
        let mut name: Option<String> = None;
        for f in owrt_ubus::blob::fields(&req.data) {
            if f.name == "name" {
                name = f.as_str().map(str::to_string);
            }
        }
        let Some(name) = name else {
            return status::INVALID_ARGUMENT;
        };
        let Some(s) = self.services.get_mut(&name) else {
            return status::NOT_FOUND;
        };
        if start {
            s.update_pending = true;
            for i in s.instances.values_mut() {
                i.stale = true;
            }
            return status::OK;
        }
        s.update_pending = false;
        let doomed: Vec<String> = s
            .instances
            .iter()
            .filter(|(_, i)| i.stale)
            .map(|(n, _)| n.clone())
            .collect();
        for iname in doomed {
            self.instance_stop(&name, &iname, true);
            self.collect_stopped(&name, &iname);
            self.instance_update_trigger();
        }
        status::OK
    }

    /// `service_get_data()`. Service-level data is reported under the
    /// instance key `*`; instance data under the instance's own name. A
    /// service or instance with nothing matching emits no table at all.
    fn handle_get_data(&mut self, req: &Request) -> i32 {
        let mut name: Option<String> = None;
        let mut instance: Option<String> = None;
        let mut ty: Option<String> = None;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "instance" => instance = f.as_str().map(str::to_string),
                "type" => ty = f.as_str().map(str::to_string),
                _ => {}
            }
        }
        let want = |k: &str| ty.as_ref().is_none_or(|t| t == k);

        let mut b = BlobBuf::new();
        for (sname, s) in self.services.iter() {
            if name.as_ref().is_some_and(|n| n != sname) {
                continue;
            }
            let svc_hits: Vec<(&String, &(u32, Vec<u8>))> =
                s.data.iter().filter(|(k, _)| want(k)).collect();
            let mut cs = None;
            if !svc_hits.is_empty() {
                cs = Some(b.msg_open_table(sname));
                let ci = b.msg_open_table("*");
                for (k, (ty, payload)) in svc_hits {
                    b.msg_field(*ty, k, payload);
                }
                b.msg_close(ci);
            }
            for (iname, inst) in s.instances.iter() {
                if instance.as_ref().is_some_and(|n| n != iname) {
                    continue;
                }
                let hits: Vec<(&String, &(u32, Vec<u8>))> =
                    inst.data.iter().filter(|(k, _)| want(k)).collect();
                if hits.is_empty() {
                    continue;
                }
                if cs.is_none() {
                    cs = Some(b.msg_open_table(sname));
                }
                let ci = b.msg_open_table(iname);
                for (k, (ty, payload)) in hits {
                    b.msg_field(*ty, k, payload);
                }
                b.msg_close(ci);
            }
            if let Some(c) = cs {
                b.msg_close(c);
            }
        }
        let _ = self.conn.reply_data(req, b.payload());
        status::OK
    }

    /// `service_handle_set_data()`. With `instance`, the instance's data is
    /// replaced and NO trigger fires; without it, the service's data is
    /// replaced through service_update_data, which fires the data triggers
    /// for the old keys and then for the new.
    fn handle_set_data(&mut self, req: &Request) -> i32 {
        let mut name: Option<String> = None;
        let mut instance: Option<String> = None;
        let mut data: BTreeMap<String, (u32, Vec<u8>)> = BTreeMap::new();
        let mut saw_data = false;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "instance" => instance = f.as_str().map(str::to_string),
                "data" => {
                    saw_data = true;
                    for c in f.children() {
                        data.insert(c.name.to_string(), (c.ty, c.data.to_vec()));
                    }
                }
                _ => {}
            }
        }
        let (Some(name), true) = (name, saw_data) else {
            return status::INVALID_ARGUMENT;
        };
        let Some(s) = self.services.get_mut(&name) else {
            return status::NOT_FOUND;
        };
        match instance {
            Some(i) => {
                let Some(inst) = s.instances.get_mut(&i) else {
                    return status::NOT_FOUND;
                };
                inst.data = data;
            }
            None => {
                if s.data == data {
                    return status::OK;
                }
                // service_update_data fires for the OLD keys, then the new.
                let old_keys: Vec<String> = s.data.keys().cloned().collect();
                let new_keys: Vec<String> = data.keys().cloned().collect();
                self.data_trigger_keys(&old_keys);
                if let Some(s) = self.services.get_mut(&name) {
                    s.data = data;
                }
                self.data_trigger_keys(&new_keys);
            }
        }
        status::OK
    }

    /// `service_handle_signal()`. Signals the named instance, or every
    /// instance of the service when none is named.
    fn handle_signal(&mut self, req: &Request) -> i32 {
        let mut name: Option<String> = None;
        let mut inst: Option<String> = None;
        // `int sig = SIGHUP;` -- not SIGKILL. Getting this wrong turns every
        // unqualified `ubus call service signal` into a kill.
        let mut sig = SIGHUP;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "instance" => inst = f.as_str().map(str::to_string),
                "signal" => sig = f.as_u32().unwrap_or(SIGHUP as u32) as i32,
                _ => {}
            }
        }
        // A missing `name` is NOT_FOUND here, not INVALID_ARGUMENT: this
        // handler returns UBUS_STATUS_NOT_FOUND for it, unlike its siblings.
        let Some(name) = name else {
            return status::NOT_FOUND;
        };
        let Some(s) = self.services.get(&name) else {
            return status::NOT_FOUND;
        };
        // A named instance that does not exist is NOT_FOUND.
        if let Some(want) = inst.as_ref() {
            if !s.instances.contains_key(want) {
                return status::NOT_FOUND;
            }
        }
        // service_handle_kill() does NOT test proc.pending -- it calls kill()
        // and maps errno. So signalling an instance whose child is gone gives
        // ESRCH -> NOT_FOUND, where filtering on state silently returned OK.
        // With no instance named, the LAST instance's result is returned.
        let targets: Vec<(String, i32)> = s
            .instances
            .iter()
            .filter(|(iname, _)| inst.as_ref().is_none_or(|want| want == *iname))
            .map(|(iname, i)| (iname.clone(), i.pid))
            .collect();
        let mut rv = status::OK;
        for (_, pid) in targets {
            rv = proc::signal_status(pid, sig);
        }
        rv
    }
}

/// snprintf(ident, 32, "%s[%d]", ...): the WHOLE ident is capped at 31
/// bytes, basename and pid included. String::truncate panics inside a
/// multibyte character, so back off to the boundary instead of taking PID 1
/// down (R88 procd F4); the C keeps the partial bytes, which no reader of
/// the ident can tell apart from a shorter one.
fn syslog_ident(arg0: &str, pid: i32) -> String {
    let mut ident = format!("{arg0}[{pid}]");
    let mut cut = ident.len().min(31);
    while !ident.is_char_boundary(cut) {
        cut -= 1;
    }
    ident.truncate(cut);
    ident
}

fn main() {
    if let Err(e) = run() {
        log!(sys::LOG_ERR, "{e}");
        std::process::exit(1);
    }
}

/// `-S` and friends: a flag with no argument.
fn arg_flag(flag: &str) -> bool {
    std::env::args().skip(1).any(|a| a == flag)
}

/// The C's `-I` / `-R <path>` options.
fn arg_path(flag: &str, default: &str) -> String {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == flag {
            if let Some(p) = args.next() {
                return p;
            }
        }
    }
    default.to_string()
}

/// `procd -h <rules>`: the standalone hotplug daemon preinit runs
/// (`hotplug_run()`) -- the uevent loop and nothing else, no ubus, no
/// supervision, until the parent kills it.
fn run_hotplug_daemon(rules: &str) -> io::Result<()> {
    owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
    let base = Instant::now();
    let Some(mut hp) = hotplug::Hotplug::new(rules) else {
        // hotplug() exits 1 when the socket or rules cannot be had.
        std::process::exit(1);
    };
    loop {
        let now = base.elapsed().as_millis() as i64;
        #[expect(unsafe_code, reason = "standalone hotplug owns the sole event thread")]
        // SAFETY: this standalone loop starts no threads and holds no
        // application lock while processing the firmware queue.
        let _ = unsafe { hp.pump(now) };
        while let Some((pid, st)) = proc::reap_any() {
            hp.reaped(pid, st);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn run() -> io::Result<()> {
    // procd.c main(): setsid() before anything else, in every mode.
    proc::become_session_leader();
    // `-h <path>`: run as hotplug daemon (procd.c's getopt case 'h').
    {
        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
            if a == "-h" {
                if let Some(rules) = args.next() {
                    return run_hotplug_daemon(&rules);
                }
            }
        }
    }
    owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);

    let pid1 = std::process::id() == 1;
    // procd.c main(): DBGLVL from the environment (then unset), `-d <level>`,
    // and ulog_open(): kmsg by default, stderr with `-S`; STATE_INIT moves
    // PID 1 to syslog. The supervisor mode -- a test-only mode on OpenWrt --
    // keeps stderr, so a namespace probe's daemon log never lands in the
    // host's kernel log.
    if let Some(l) = std::env::var_os("DBGLVL") {
        sys::set_debug_level(sys::atoi_u32(&l.to_string_lossy()) as i32);
        std::env::remove_var("DBGLVL");
    }
    if arg_flag("-d") {
        sys::set_debug_level(sys::atoi_u32(&arg_path("-d", "0")) as i32);
    }
    let channel = if pid1 && !arg_flag("-S") { sys::LogChannel::Kmsg } else { sys::LogChannel::Stdio };
    sys::ulog_open(channel);
    sys::install_panic_hook();
    let wakeup = owrt_platform::procd::signals::install_sigchld_wakeup()?;
    let base = Instant::now();
    let mut wdt = watchdog::Wdt::default();
    let mut hp: Option<hotplug::Hotplug> = None;
    let mut early_ubus: Option<(instance::Instance, i32)> = None;
    // Exits of children other than ubusd seen during the connect retry.
    let mut early_reaps: Vec<(i32, i32)> = Vec::new();

    let mut conn = if pid1 {
        // procd.c: `procd_state_next()` -- STATE_EARLY, then STATE_UBUS.
        // Everything up to the working bus connection happens here, because
        // Procd cannot exist without one.
        sys::procd_signal_pid1();

        // STATE_EARLY. watchdog_init(0) opens /dev/watchdog and starts the
        // keep-alive; hotplug("/etc/hotplug.json") and procd_coldplug() are
        // the remaining P3.2 pieces and their absence is logged, not hidden.
        log!(sys::LOG_INFO, "- early -");
        #[expect(unsafe_code, reason = "adopt the preinit-owned watchdog at PID 1 startup")]
        // SAFETY: PID 1 has not started any threads. WDTFD, when present, is
        // the live descriptor transferred by preinit across exec, with no Rust
        // owner in this process. Consume it once before normal supervision.
        let inherited = unsafe { owrt_platform::procd::watchdog::take_inherited_watchdog(sys::atoi_u32) };
        wdt.init(base.elapsed().as_millis() as i64, false, inherited);
        if !wdt.is_open() {
            debug!(4, "Watchdog does not exist");
        }
        // hotplug("/etc/hotplug.json") + procd_coldplug(): EARLY -> UBUS is
        // driven by udevtrigger finishing and the rules staying quiet for
        // 500 ms, exactly the C's coldplug_complete path. The uevent storm
        // this pumps through the rules is what populates /dev before UBUS
        // needs a console.
        hp = hotplug::Hotplug::new("/etc/hotplug.json");
        match hp.as_mut() {
            Some(h) => {
                h.coldplug(sys::is_container());
                loop {
                    let now = base.elapsed().as_millis() as i64;
                    #[expect(unsafe_code, reason = "PID 1 coldplug runs before any threads exist")]
                    // SAFETY: this early-boot owner has one thread and holds
                    // no application lock while processing firmware requests.
                    let _ = unsafe { h.pump(now) };
                    while let Some((pid, st)) = proc::reap_any() {
                        h.reaped(pid, st);
                    }
                    wdt.pump(now);
                    if h.coldplug_done(now) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
            None => log!(sys::LOG_ERR, "hotplug disabled: no socket or no rules"),
        }

        // STATE_UBUS. watchdog_init(0) runs AGAIN: coldplug replaced /dev,
        // so a watchdog that was absent before it may exist now, and a
        // first-open failure must not leave the hardware WDT unarmed
        // forever.
        wdt.init(base.elapsed().as_millis() as i64, false, None);
        sys::set_stdio("console");
        let ubus_user = owrt_platform::procd::identity::lookup_user_home("ubus");
        match &ubus_user {
            Some((uid, gid, home)) => {
                log!(sys::LOG_INFO, "- ubus -");
                let _ = std::fs::create_dir_all(home);
                if !sys::chown_path(home, *uid, *gid) {
                    log!(sys::LOG_INFO, "- ubus - failed to chown({home})");
                }
            }
            None => log!(sys::LOG_INFO, "- ubus (running as root!) -"),
        }
        // service_start_early("ubus", "/sbin/ubusd", ...): the same instance
        // shape the C builds -- respawn {3600, 1, 0}, the ubus user when it
        // exists -- started through the normal instance path, then connect
        // with the retry the C's timer provides. Supervision of that one
        // child runs inline here until the bus is up.
        let mut inst = instance::Instance::new("instance1");
        inst.valid = true;
        inst.command = vec!["/sbin/ubusd".to_string()];
        inst.respawn = Some(instance::Respawn { threshold: 3600, timeout: 1, retry: 0 });
        inst.respawn_active = true;
        if ubus_user.is_some() {
            inst.user = Some("ubus".to_string());
            inst.group = Some("ubus".to_string());
        }
        let mut pid = 0;
        let mut spawn_at = Instant::now();
        let conn = loop {
            if pid == 0 && Instant::now() >= spawn_at {
                #[expect(unsafe_code, reason = "PID 1 owns single-threaded early ubus startup")]
                // SAFETY: early boot has started no threads and holds no
                // application locks; this owner retains the instance state.
                let started = unsafe { proc::start(&inst, "ubus") };
                pid = match started {
                    Ok((pid, _, _)) => pid,
                    Err(error) => {
                        log!(sys::LOG_ERR, "failed to start ubusd: {error}");
                        0
                    }
                };
                // Command::spawn can fail without leaving a child to reap.
                // Retry those failures as well as exited children, while
                // keeping the watchdog serviced between attempts.
                spawn_at = Instant::now() + std::time::Duration::from_secs(1);
            }
            match Connection::connect(None) {
                Ok(c) => break c,
                Err(_) => {
                    while let Some((dead, wstatus)) = proc::reap_any() {
                        if dead == pid {
                            pid = 0;
                            spawn_at = Instant::now() + std::time::Duration::from_secs(1);
                        } else {
                            // A coldplug command may still be running here;
                            // its exit belongs to the hotplug queue, or the
                            // queue would stall for the whole uptime (R88
                            // procd F2).
                            early_reaps.push((dead, wstatus));
                        }
                    }
                    wdt.pump(base.elapsed().as_millis() as i64);
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        };
        inst.state = if pid > 0 { Run::Running } else { Run::Stopped };
        inst.pid = pid;
        inst.started = base.elapsed().as_millis() as i64;
        if pid == 0 {
            inst.deadline = Some(inst.started + 1000);
        }
        early_ubus = Some((inst, pid));
        conn
    } else {
        Connection::connect(None)?
    };
    // Partial bus frames and stalled replies must return control to service
    // deadlines and the hardware watchdog before recovery reconnects.
    conn.set_server_io_timeout(std::time::Duration::from_secs(1));

    let mut p = Procd {
        conn,
        objects: Objects::default(),
        services: BTreeMap::new(),
        read_reply: BlobBuf::new(),
        meminfo: sysobj::Meminfo::open(),
        base,
        validator_seq: 0,
        rc: rcs::RunQueue::default(),
        init_d: arg_path("-I", "/etc/init.d"),
        watch_obj: 0,
        watches: BTreeMap::new(),
        subscribed: BTreeMap::new(),
        watch_pending: VecDeque::new(),
        pending_set: None,
        triggers: trigger::Triggers::default(),
        boot: if pid1 { Boot::Ubus } else { Boot::NotPid1 },
        inittab: Vec::new(),
        serial: rcs::RunQueue::serial(),
        serial_awaited: false,
        console: None,
        rc_d: arg_path("-R", "/etc/rc.d"),
        reboot_event: 0,
        wdt,
        hotplug: hp,
        dispatch: dispatch::Dispatch::new(),
        wakeup,
        wait_fds: Vec::with_capacity(8),
        inotify_ready: true,
    };
    if let Some((inst, _)) = early_ubus.take() {
        let mut svc = Service::new("ubus");
        svc.instances.insert("instance1".to_string(), inst);
        p.services.insert("ubus".to_string(), svc);
    }
    for (dead, wstatus) in early_reaps.drain(..) {
        if let Some(h) = p.hotplug.as_mut() {
            h.reaped(dead, wstatus);
        }
    }

    // HELLO is not a completed registration. A bus failure here must enter
    // the same recovery loop as a later disconnect, never return from PID 1.
    let registered = (|| -> io::Result<()> {
        p.objects.service = p.conn.add_object("service", ubus::SERVICE_METHODS, 1000)?;
        p.objects.container = p.conn.add_object("container", ubus::CONTAINER_METHODS, 1000)?;
        p.objects.system = p.conn.add_object("system", ubus::SYSTEM_METHODS, 1000)?;
        p.register_initial_hotplug();
        p.watch_obj = p.conn.add_anonymous_object(1000)?;
        p.conn.register_event_handler(p.watch_obj, Some("ubus.object.add"), 1000)
    })();
    let mut connected = match registered {
        Ok(()) => {
            p.boot_bus_ready();
            true
        }
        Err(error) => {
            log!(sys::LOG_ERR, "initial ubus registration failed: {error}; reconnecting");
            let _ = p.conn.shutdown();
            false
        }
    };

    // Bus connection state, kept separate from supervision state. procd
    // reconnects with a 50ms..1s backoff (ubus.c); losing ubusd must not
    // take the supervisor -- and every child it is responsible for -- down
    // with it.
    let mut backoff_ms: i32 = 50;
    let mut reconnect_at: i64 = 0;
    // The maintenance pass runs on every wake that is not a pure read on the
    // bus: timers, child exits, pipe output, uevents, inotify, signals, and
    // any bus method that changes supervised state. It starts armed.
    let mut maintenance_due = true;
    // The timer tick is anchored at the last maintenance pass, not at the
    // last wake: a bus client that keeps the socket readable would otherwise
    // push the deadline out forever and starve every timer, including the
    // hardware watchdog feed (R88 procd F1).
    let mut maintenance_at: i64 = 0;

    loop {
        if !connected {
            p.pending_set = None;
            // Keep supervising while the bus is gone: children still exit,
            // stop timeouts still expire, respawns still come due.
            p.pump_logs();
            p.reap();
            p.fire_timeouts();
            p.pump_triggers();
            // Reconnect backoff has no poll set. Keep checking inotify on
            // these maintenance ticks, as before.
            p.inotify_ready = true;
            p.pump_pid1();
            let now = p.now_ms();
            p.rc.pump(now);
            let remaining = (reconnect_at - p.now_ms()).clamp(0, i64::from(p.next_tick_ms())) as i32;
            if remaining > 0 {
                let _ = p.wait_activity(remaining, false);
                continue;
            }
            match p.reconnect() {
                Ok(()) => {
                    debug!(2, "Connected to ubus");
                    p.boot_bus_ready();
                    connected = true;
                    backoff_ms = 50;
                    maintenance_due = true;
                }
                Err(_) => {
                    backoff_ms = (backoff_ms * 2).min(1000);
                    reconnect_at = p.now_ms() + i64::from(backoff_ms);
                }
            }
            continue;
        }

        if p.pending_set.is_some() {
            p.maintain();
            if let Err(error) = p.pump_pending_set() {
                debug!(2, "lost ubus during service watch setup ({error}); reconnecting");
                let _ = p.conn.shutdown();
                p.pending_set = None;
                connected = false;
                backoff_ms = 50;
                reconnect_at = p.now_ms() + i64::from(backoff_ms);
            }
            maintenance_due = true;
            // Synchronous watch calls already buffer interleaved traffic.
            // Do not separately read/dispatch later calls before the reply.
            continue;
        }

        // Drain anything already buffered before blocking: a poll on the
        // socket does not see bytes already read out of it. The netifd loop
        // needed exactly this fix.
        maintenance_due |= p.maintenance_delay_ms(p.now_ms(), maintenance_at) == 0;
        for _ in 0..32 {
            if !p.conn.has_pending() { break; }
            match p.conn.read_incoming() {
                Ok(msg) => maintenance_due |= p.dispatch(msg),
                Err(_) => break,
            }
            maintenance_due |= p.maintenance_delay_ms(p.now_ms(), maintenance_at) == 0;
            if maintenance_due { break; }
        }
        if p.pending_set.is_some() { continue; }
        if maintenance_due {
            // Drain output BEFORE reaping: a child that just exited may have
            // left its last lines in the pipe, and closing it on reap would
            // lose them.
            p.maintain();
            maintenance_due = false;
            maintenance_at = p.now_ms() + i64::from(p.next_tick_ms());
        }

        // One queued path per turn. A slow batch must not postpone child
        // deadlines or watchdog pings by N times the request timeout.
        if p.pump_watch() {
            maintenance_due = true;
            maintenance_at = p.now_ms();
        }

        // uloop_run(): sleep until ANY of the fds this loop reacts to is
        // ready -- the bus, the uevent socket, a child's output, a child
        // exit -- or the timer tick for deadlines and respawns, which is
        // 200 ms while anything is pending and the watchdog interval otherwise.
        let watch_at = p.watch_pending.iter().map(|(_, at)| *at).min().unwrap_or(maintenance_at);
        let now = p.now_ms();
        let remaining = p.maintenance_delay_ms(now, maintenance_at.min(watch_at));
        let incoming = match p.wait_activity(remaining, true) {
            Ok(Activity { bus: true, other }) => {
                maintenance_due |= other || p.maintenance_delay_ms(p.now_ms(), maintenance_at) == 0;
                p.conn.read_incoming().map(Some)
            }
            Ok(Activity { bus: false, other }) => {
                maintenance_due |= other || p.maintenance_delay_ms(p.now_ms(), maintenance_at) == 0;
                Ok(None)
            }
            // Preserve the old nonblocking bus probe if the shared wait
            // fails; never block on an unverified socket in that case.
            Err(_) => {
                maintenance_due = true;
                p.conn.next_incoming(0)
            }
        };
        match incoming {
            Ok(Some(msg)) => maintenance_due |= p.dispatch(msg),
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                debug!(2, "lost the ubus connection ({e}); reconnecting");
                connected = false;
                backoff_ms = 50;
                reconnect_at = p.now_ms() + i64::from(backoff_ms);
            }
        }
    }
}

#[cfg(test)]
mod r88_tests {
    use super::*;

    #[test]
    fn syslog_ident_caps_at_31_bytes_on_a_char_boundary() {
        assert_eq!(syslog_ident("sh", 7), "sh[7]");
        let long = "a".repeat(40);
        assert_eq!(syslog_ident(&long, 12345).len(), 31);
        // 17 x 'é' = 34 bytes; byte 31 falls inside a character.
        let accented = "é".repeat(17);
        let ident = syslog_ident(&accented, 1);
        assert!(ident.len() <= 31 && ident.is_char_boundary(ident.len()));
        assert_eq!(ident, "é".repeat(15));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod watch_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::{atomic::{AtomicU32, Ordering}, Arc, Mutex};
    use owrt_ubus::msg::{attr, ty, Header};

    pub(super) fn supervisor(conn: Connection) -> Procd {
        let (wakeup, _write) = owrt_ubus::sys::pipe().unwrap();
        Procd {
            conn, objects: Objects::default(), services: BTreeMap::new(), read_reply: BlobBuf::new(),
            meminfo: sysobj::Meminfo::open(), base: Instant::now(), validator_seq: 0, rc: rcs::RunQueue::default(), init_d: String::new(),
            watch_obj: 1001, watches: BTreeMap::new(),
            subscribed: BTreeMap::new(), watch_pending: VecDeque::new(), pending_set: None, triggers: trigger::Triggers::default(), boot: Boot::NotPid1,
            inittab: Vec::new(), serial: rcs::RunQueue::serial(), serial_awaited: false, console: None,
            rc_d: String::new(), reboot_event: 0, wdt: watchdog::Wdt::default(), hotplug: None,
            dispatch: dispatch::Dispatch::default(), wakeup, wait_fds: Vec::new(), inotify_ready: false,
        }
    }

    // The wire peer records real LOOKUP/SUBSCRIBE requests rather than
    // duplicating the path-selection logic under test.
    fn peer(stream: UnixStream, calls: Arc<Mutex<Vec<(u8, String)>>>, alpha: Arc<AtomicU32>) {
        delayed_peer(stream, calls, alpha, 0, false);
    }

    fn delayed_peer(mut stream: UnixStream, calls: Arc<Mutex<Vec<(u8, String)>>>, alpha: Arc<AtomicU32>, delay_ms: u64, mut drop_lookup: bool) {
        stream.write_all(&[0, ty::HELLO, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4]).unwrap();
        loop {
            let mut head = [0; 12];
            if stream.read_exact(&mut head).is_err() { return; }
            let header = Header::decode(head[..8].try_into().unwrap()).unwrap();
            let len = (u32::from_be_bytes(head[8..].try_into().unwrap()) & 0xffffff) as usize;
            let mut body = vec![0; len - 4];
            stream.read_exact(&mut body).unwrap();
            if header.ty == ty::STATUS { continue; } // Event acknowledgement.
            let attrs: Vec<_> = owrt_ubus::blob::iter(&body).collect();
            let mut reply = BlobBuf::new();
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            match header.ty {
                ty::LOOKUP => {
                    let path = attrs.iter().find(|a| a.id == attr::OBJPATH).unwrap();
                    let path = std::str::from_utf8(&path.payload[..path.payload.len() - 1]).unwrap();
                    calls.lock().unwrap().push((ty::LOOKUP, path.to_owned()));
                    if drop_lookup { drop_lookup = false; continue; }
                    reply.put_string(attr::OBJPATH, path);
                    reply.put_u32(attr::OBJID, if path == "watched.alpha" { alpha.load(Ordering::Relaxed) } else { 2002 });
                    stream.write_all(&Header { ty: ty::DATA, seq: header.seq, peer: header.peer }.encode()).unwrap();
                    stream.write_all(reply.as_bytes()).unwrap();
                }
                ty::SUBSCRIBE => {
                    let id = attrs.iter().find(|a| a.id == attr::TARGET).unwrap().as_u32().unwrap();
                    calls.lock().unwrap().push((ty::SUBSCRIBE, id.to_string()));
                }
                _ => panic!("unexpected request {}", header.ty),
            }
            let mut status = BlobBuf::new();
            status.put_u32(attr::STATUS, 0);
            stream.write_all(&Header { ty: ty::STATUS, seq: header.seq, peer: header.peer }.encode()).unwrap();
            stream.write_all(status.as_bytes()).unwrap();
        }
    }

    #[test]
    fn object_add_only_checks_its_path_and_full_resubscribe_still_replays_watches() {
        let path = format!("/tmp/procd-watch-r93-{}.sock", std::process::id());
        let listener = UnixListener::bind(&path).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let alpha = Arc::new(AtomicU32::new(2001));
        let peer_calls = Arc::clone(&calls);
        let peer_alpha = Arc::clone(&alpha);
        let worker = std::thread::spawn(move || peer(listener.accept().unwrap().0, peer_calls, peer_alpha));
        let conn = Connection::connect(Some(&path)).unwrap();
        std::fs::remove_file(&path).unwrap();
        let mut p = supervisor(conn);
        p.watches.insert("svc".into(), vec!["watched.alpha".into(), "watched.beta".into()]);
        let event = |path: Option<&str>| {
            let mut data = BlobBuf::new();
            if let Some(path) = path { data.msg_string("path", path); }
            Incoming::Invoke(Request { peer: 0, seq: 0, objid: 1001, method: "ubus.object.add".into(),
                user: None, group: None, data: data.into_payload(), fd: None, no_reply: true })
        };
        p.dispatch(event(Some("unrelated")));
        p.dispatch(event(None));
        p.pump_watch();
        assert!(calls.lock().unwrap().is_empty(), "unrelated/missing paths must not issue lookups");
        p.dispatch(event(Some("watched.alpha")));
        p.pump_watch();
        assert_eq!(*calls.lock().unwrap(), [(ty::LOOKUP, "watched.alpha".into()), (ty::SUBSCRIBE, "2001".into())]);
        calls.lock().unwrap().clear();
        p.dispatch(event(Some("watched.alpha")));
        p.pump_watch();
        assert_eq!(*calls.lock().unwrap(), [(ty::LOOKUP, "watched.alpha".into())], "same id must not be subscribed twice");
        calls.lock().unwrap().clear();
        alpha.store(3001, Ordering::Relaxed);
        p.dispatch(event(Some("watched.alpha")));
        p.pump_watch();
        assert_eq!(*calls.lock().unwrap(), [(ty::LOOKUP, "watched.alpha".into()), (ty::SUBSCRIBE, "3001".into())]);
        calls.lock().unwrap().clear();
        for _ in 0..100 {
            let mut data = BlobBuf::new();
            data.msg_string("path", "watched.alpha");
            data.msg_u32("id", 3001);
            p.dispatch(Incoming::Invoke(Request { peer: 0, seq: 0, objid: 1001, method: "ubus.object.add".into(),
                user: None, group: None, data: data.into_payload(), fd: None, no_reply: true }));
        }
        assert!(p.watch_pending.is_empty(), "same-id announcement floods need no lookup");
        assert!(calls.lock().unwrap().is_empty());
        // reconnect() clears connection-owned subscriptions, then calls this
        // same full replay; it must still cover paths without new events.
        p.subscribed.clear();
        p.resubscribe();
        while p.pump_watch() {}
        assert_eq!(*calls.lock().unwrap(), [(ty::LOOKUP, "watched.alpha".into()), (ty::SUBSCRIBE, "3001".into()),
            (ty::LOOKUP, "watched.beta".into()), (ty::SUBSCRIBE, "2002".into())]);
        drop(p);
        worker.join().unwrap();
    }

    #[test]
    fn slow_watch_batch_services_child_deadline_before_finishing_all_paths() {
        use std::os::unix::process::ExitStatusExt;
        use std::time::Duration;
        let path = format!("/tmp/procd-watch-batch-{}.sock", std::process::id());
        let listener = UnixListener::bind(&path).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let peer_calls = Arc::clone(&calls);
        let worker = std::thread::spawn(move || delayed_peer(listener.accept().unwrap().0,
            peer_calls, Arc::new(AtomicU32::new(2001)), 300, false));
        let conn = Connection::connect(Some(&path)).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut p = supervisor(conn);
        let mut child = std::process::Command::new("/bin/sleep").arg("10").spawn().unwrap();
        let mut instance = Instance::new("batch-child");
        instance.pid = child.id() as i32;
        instance.halt = true;
        instance.state = Run::Halting;
        instance.deadline = Some(p.now_ms() + 50);
        let mut service = Service::new("batch-service");
        service.instances.insert(instance.name.clone(), instance);
        p.services.insert(service.name.clone(), service);
        p.watches.insert("batch-service".into(), (0..6).map(|n| format!("watched.{n}")).collect());
        let start = Instant::now();
        p.resubscribe();
        let mut stopped_at = None;
        while start.elapsed() < Duration::from_secs(8) {
            p.pump_watch();
            p.fire_timeouts();
            if stopped_at.is_none() {
                if let Some(status) = child.try_wait().unwrap() {
                    assert_eq!(status.signal(), Some(SIGKILL));
                    stopped_at = Some(start.elapsed());
                }
            }
            if stopped_at.is_some() && p.subscribed.len() == 6 { break; }
            std::thread::sleep(Duration::from_millis(10));
        }
        if stopped_at.is_none() { let _ = child.kill(); }
        child.wait().unwrap();
        let stop = stopped_at.expect("owned child must be killed");
        eprintln!("watch batch: child stopped at {stop:?}, all paths at {:?}", start.elapsed());
        assert!(stop < Duration::from_millis(1800), "child deadline waited for entire batch: {stop:?}");
        assert_eq!(p.subscribed.len(), 6, "yielding must preserve every pending subscription");
        assert_eq!(calls.lock().unwrap().len(), 12);
        drop(p);
        worker.join().unwrap();
    }

    #[test]
    fn watch_timeout_retries_without_event_and_pending_paths_follow_configuration() {
        use std::time::Duration;
        let path = format!("/tmp/procd-watch-retry-{}.sock", std::process::id());
        let listener = UnixListener::bind(&path).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let peer_calls = Arc::clone(&calls);
        let worker = std::thread::spawn(move || delayed_peer(listener.accept().unwrap().0,
            peer_calls, Arc::new(AtomicU32::new(2001)), 0, true));
        let conn = Connection::connect(Some(&path)).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut p = supervisor(conn);
        p.watches.insert("svc".into(), vec!["watched.alpha".into(), "removed".into()]);
        p.resubscribe();
        // Repeated announcements cannot fill/reset the queue or delay retries.
        for _ in 0..100 { p.queue_watch("watched.alpha"); }
        assert_eq!(p.watch_pending.len(), 2);
        p.watches.insert("svc".into(), vec!["watched.alpha".into()]);
        p.resubscribe();
        assert_eq!(p.watch_pending.len(), 1);
        assert!(p.pump_watch()); // A full clean timeout; connection stays usable.
        assert!(p.subscribed.is_empty());
        assert_eq!(p.watch_pending.len(), 1);
        assert!(!p.pump_watch(), "retry must back off");
        std::thread::sleep(Duration::from_millis(1050));
        assert!(p.pump_watch());
        assert_eq!(p.subscribed.get("watched.alpha"), Some(&2001));
        assert!(p.watch_pending.is_empty());
        assert_eq!(*calls.lock().unwrap(), [(ty::LOOKUP, "watched.alpha".into()),
            (ty::LOOKUP, "watched.alpha".into()), (ty::SUBSCRIBE, "2001".into())]);
        drop(p);
        worker.join().unwrap();
    }

    #[test]
    fn deferred_set_replies_after_attempts_and_keeps_stop_maintenance() {
        use std::os::unix::process::ExitStatusExt;
        use std::time::Duration;
        let path = format!("/tmp/procd-set-defer-{}.sock", std::process::id());
        let listener = UnixListener::bind(&path).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let peer_calls = Arc::clone(&calls);
        let worker = std::thread::spawn(move || delayed_peer(listener.accept().unwrap().0,
            peer_calls, Arc::new(AtomicU32::new(2001)), 300, false));
        let conn = Connection::connect(Some(&path)).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut p = supervisor(conn);
        let mut child = std::process::Command::new("/bin/sleep").arg("10").spawn().unwrap();
        let mut instance = Instance::new("deferred-child");
        instance.pid = child.id() as i32;
        instance.halt = true;
        instance.state = Run::Halting;
        instance.deadline = Some(50);
        let mut service = Service::new("deferred-service");
        service.instances.insert(instance.name.clone(), instance);
        p.services.insert(service.name.clone(), service);
        let paths: Vec<_> = (0..6).map(|n| format!("watched.{n}")).collect();
        p.watches.insert("watched-service".into(), paths.clone());
        p.pending_set = Some(PendingSet { request: Request { peer: 10, seq: 99, objid: 1001,
            method: "set".into(), user: None, group: None, data: vec![], fd: None, no_reply: false },
            paths: paths.into(), service: "watched-service".into(), new_service: false });
        let marker = format!("/tmp/procd-set-trigger-{}", std::process::id());
        p.triggers.pending.push(trigger::Pending {
            argv: vec!["/bin/sh".into(), "-c".into(), format!("echo done > {marker}")],
            due: 0, requeue: false, pid: None, finished: false,
        });
        let start = Instant::now();
        let mut stopped_at = None;
        let mut turns = 0;
        while p.pending_set.is_some() {
            // Same maintenance order as the main loop, without reap taking
            // the wait status owned by this test's Child handle.
            p.pump_logs();
            p.fire_timeouts();
            p.wdt.pump(p.now_ms());
            p.pump_triggers();
            assert!(p.triggers.pending[0].pid.is_none(), "trigger started before watch attempts finished");
            assert!(!std::path::Path::new(&marker).exists());
            p.pump_pending_set().unwrap();
            turns += 1;
            if stopped_at.is_none() && child.try_wait().unwrap().is_some() {
                stopped_at = Some(start.elapsed());
            }
            assert!(turns <= 6);
            if turns < 6 { assert!(p.pending_set.is_some()); }
        }
        if stopped_at.is_none() { let _ = child.kill(); }
        assert_eq!(child.wait().unwrap().signal(), Some(SIGKILL));
        assert!(stopped_at.unwrap() < Duration::from_millis(1800));
        assert_eq!(p.subscribed.len(), 6);
        assert_eq!(turns, 6);
        p.pump_triggers();
        assert!(p.triggers.pending[0].pid.is_some(), "trigger starts after completion");
        let until = Instant::now() + Duration::from_secs(1);
        while !std::path::Path::new(&marker).exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(std::path::Path::new(&marker).exists());
        std::fs::remove_file(marker).unwrap();
        // Reap this test-owned trigger directly (no global signal handler).
        let pid = rustix::process::Pid::from_raw(p.triggers.pending[0].pid.unwrap()).unwrap();
        let reaped = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
            .unwrap().unwrap().0;
        assert_eq!(reaped, pid);
        drop(p);
        worker.join().unwrap();
    }

    #[test]
    fn deferred_set_timeout_finishes_attempt_and_keeps_background_retry() {
        let path = format!("/tmp/procd-set-timeout-{}.sock", std::process::id());
        let listener = UnixListener::bind(&path).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let peer_calls = Arc::clone(&calls);
        let worker = std::thread::spawn(move || delayed_peer(listener.accept().unwrap().0,
            peer_calls, Arc::new(AtomicU32::new(2001)), 0, true));
        let conn = Connection::connect(Some(&path)).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut p = supervisor(conn);
        p.watches.insert("svc".into(), vec!["watched.alpha".into()]);
        p.pending_set = Some(PendingSet { request: Request { peer: 10, seq: 99, objid: 1001,
            method: "set".into(), user: None, group: None, data: vec![], fd: None, no_reply: true },
            paths: ["watched.alpha".into()].into(), service: "svc".into(), new_service: false });
        p.pump_pending_set().unwrap();
        assert!(p.pending_set.is_none(), "one failed attempt must release the request");
        assert_eq!(p.watch_pending.len(), 1, "retry proceeds separately");
        assert!(p.subscribed.is_empty());
        drop(p);
        worker.join().unwrap();
    }

    #[test]
    fn deferred_set_disconnect_drops_owned_request_fd_without_reply() {
        use std::os::fd::AsRawFd;
        use std::time::Duration;
        let path = format!("/tmp/procd-set-disconnect-{}.sock", std::process::id());
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[0, ty::HELLO, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4]).unwrap();
            let mut head = [0; 12];
            stream.read_exact(&mut head).unwrap();
            // A started request and a truncated reply lose the transport.
            stream.write_all(&[0]).unwrap();
            std::thread::sleep(Duration::from_millis(1300));
        });
        let conn = Connection::connect(Some(&path)).unwrap();
        std::fs::remove_file(path).unwrap();
        let mut p = supervisor(conn);
        p.watches.insert("svc".into(), vec!["watched.alpha".into()]);
        let init_dir = format!("/tmp/procd-disconnect-init-{}", std::process::id());
        std::fs::create_dir(&init_dir).unwrap();
        let completed = format!("{init_dir}/completed");
        std::fs::write(format!("{init_dir}/svc"), format!("#!/bin/sh\necho done > {completed}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(format!("{init_dir}/svc"), std::fs::Permissions::from_mode(0o755)).unwrap();
        p.init_d = init_dir.clone();
        let file = std::fs::File::open("/dev/null").unwrap();
        // Keep a high descriptor so unrelated tests cannot reuse its slot.
        let duplicate = rustix::io::fcntl_dupfd_cloexec(&file, 1000).unwrap();
        let raw = duplicate.as_raw_fd();
        assert!(raw >= 1000);
        p.pending_set = Some(PendingSet { request: Request { peer: 10, seq: 99, objid: 1001,
            method: "set".into(), user: None, group: None, data: vec![],
            fd: Some(duplicate), no_reply: false },
            paths: ["watched.alpha".into()].into(), service: "svc".into(), new_service: false });
        assert!(p.pump_pending_set().is_err());
        assert!(p.pending_set.is_none());
        assert_eq!(p.rc.jobs.len(), 1, "lost transport must not discard the local running hook");
        assert_eq!(p.rc.jobs[0].param, "running");
        p.rc.pump(p.now_ms());
        let until = Instant::now() + Duration::from_secs(1);
        while !std::path::Path::new(&completed).exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(std::path::Path::new(&completed).exists());
        let pid = rustix::process::Pid::from_raw(p.rc.jobs[0].pid.unwrap()).unwrap();
        let reaped = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
            .unwrap().unwrap().0;
        assert_eq!(reaped, pid);
        std::fs::remove_dir_all(init_dir).unwrap();
        assert_eq!(
            owrt_platform::unix::set_nonblocking(raw).unwrap_err().raw_os_error(),
            Some(9),
        );
        drop(p);
        worker.join().unwrap();
    }

    #[test]
    fn partial_frame_and_reply_backpressure_return_to_stop_deadlines() {
        use std::time::Duration;
        use std::os::unix::process::ExitStatusExt;
        for partial_input in [true, false] {
            let path = format!("/tmp/procd-io-r93-{}-{partial_input}.sock", std::process::id());
            let listener = UnixListener::bind(&path).unwrap();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.write_all(&[0, ty::HELLO, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4]).unwrap();
                if partial_input { stream.write_all(&[0]).unwrap(); }
                // The bus stays connected beyond the one-second I/O budget.
                std::thread::sleep(Duration::from_millis(2200));
            });
            let mut conn = Connection::connect(Some(&path)).unwrap();
            std::fs::remove_file(path).unwrap();
            conn.set_server_io_timeout(Duration::from_secs(1));
            let mut p = supervisor(conn);
            let mut child = std::process::Command::new("/bin/sleep").arg("10").spawn().unwrap();
            let mut instance = Instance::new("owned-child");
            instance.pid = child.id() as i32;
            instance.halt = true;
            instance.state = Run::Halting;
            instance.deadline = Some(p.now_ms() + 50);
            let mut service = Service::new("owned-service");
            service.instances.insert(instance.name.clone(), instance);
            p.services.insert(service.name.clone(), service);
            let start = Instant::now();
            let result = if partial_input {
                p.conn.read_incoming().map(|_| ())
            } else {
                let req = Request { peer: 0, seq: 0, objid: 1001, method: "list".into(),
                    user: None, group: None, data: Vec::new(), fd: None, no_reply: false };
                p.conn.reply_data_status(&req, &vec![0; 1_000_000], 0)
            };
            let elapsed = start.elapsed();
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(elapsed >= Duration::from_millis(800) && elapsed < Duration::from_millis(1800), "{elapsed:?}");
            // This is the maintenance branch entered after the bus error.
            p.fire_timeouts();
            let status = child.wait().unwrap();
            assert_eq!(status.signal(), Some(SIGKILL));
            drop(p);
            worker.join().unwrap();
        }
    }
}
