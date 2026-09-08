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

mod instance;
mod jsonscript;
mod proc;
mod rcs;
mod service;
mod trigger;
mod sys;
mod ubus;

use std::collections::BTreeMap;
use std::io;
use std::time::Instant;

use owrt_ubus::blob::BlobBuf;
use owrt_ubus::conn::{Connection, Incoming, Request};
use owrt_ubus::msg::status;

use instance::{Instance, Run};
use proc::{SIGKILL, SIGTERM};
use service::Service;
use ubus::Target;

/// Registered object ids, so an incoming invoke can be routed.
#[derive(Default)]
struct Objects {
    service: u32,
    container: u32,
    system: u32,
}

struct Procd {
    conn: Connection,
    objects: Objects,
    services: BTreeMap<String, Service>,
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
    triggers: trigger::Triggers,
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
            eprintln!("procd-rs: not starting {svc}::{name}, an error was indicated");
            return;
        }
        if inst.bundle.is_none() && inst.command.is_empty() {
            eprintln!("procd-rs: not starting {svc}::{name}, command not set");
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
        match proc::start(inst) {
            Ok((pid, out, err)) => {
                inst.pid = pid;
                inst.log_out = out;
                inst.log_err = err;
                inst.state = Run::Running;
                inst.started = now;
                inst.deadline = None;
                self.service_event("instance.start", svc, name);
            }
            Err(e) => {
                // The C's fork/exec failure surfaces as the child exiting 127.
                // Reproduce the observable part rather than inventing a state.
                inst.pid = 0;
                inst.state = Run::Stopped;
                inst.exit_code = 127;
                eprintln!("procd-rs: {svc}::{name} failed to start: {e}");
            }
        }
    }

    /// `instance_stop()`. SIGTERM now, SIGKILL after term_timeout -- except
    /// for a jailed instance, where the C never arms the kill timer because
    /// ujail owns the teardown.
    fn instance_stop(&mut self, svc: &str, name: &str, halt: bool) {
        let now = self.now_ms();
        let Some(inst) = self.services.get_mut(svc).and_then(|s| s.instances.get_mut(name)) else {
            return;
        };
        if inst.state != Run::Running {
            if halt {
                inst.halt = true;
            }
            return;
        }
        inst.halt = halt;
        inst.restart = false;
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
        if inst.state != Run::Running {
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
        let runtime = (now - inst.started) / 1000;
        inst.exit_code = Instance::exit_code_of(wstatus);
        inst.pid = 0;
        inst.state = Run::Stopped;
        inst.deadline = None;
        // pump_logs ran just before the reap, so anything left here is a
        // pipe whose writer is gone; dropping it closes our read end.
        inst.log_out = None;
        inst.log_err = None;

        let mut restart = false;
        let mut event: Option<&'static str> = None;

        if inst.halt {
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
                eprintln!(
                    "procd-rs: {svc}::{name} is in a crash loop, {} crashes, {runtime}s since last",
                    inst.respawn_count
                );
                inst.respawn_active = false;
                inst.halt = true;
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

    /// `instance_timeout()`: halting means the child ignored SIGTERM, so
    /// SIGKILL; otherwise the respawn delay just elapsed.
    fn fire_timeouts(&mut self) {
        let now = self.now_ms();
        let mut kill: Vec<(String, i32)> = Vec::new();
        let mut start: Vec<(String, String)> = Vec::new();

        for (sname, s) in self.services.iter_mut() {
            for (iname, inst) in s.instances.iter_mut() {
                let Some(d) = inst.deadline else { continue };
                if now < d {
                    continue;
                }
                inst.deadline = None;
                if inst.state == Run::Halting {
                    kill.push((format!("{sname}::{iname}"), inst.pid));
                } else if inst.restart || inst.respawn_active {
                    start.push((sname.clone(), iname.clone()));
                }
            }
        }

        for (who, pid) in kill {
            eprintln!("procd-rs: {who} pid {pid} not stopped on SIGTERM, sending SIGKILL instead");
            proc::signal(pid, SIGKILL);
        }
        for (s, i) in start {
            self.instance_start(&s, &i);
        }
    }

    /// Drain every live instance's captured output. `instance_stdio` builds
    /// the ident as `basename(argv[0])[pid]` and logs with the instance's
    /// own facility, restoring procd/LOG_DAEMON afterwards.
    fn pump_logs(&mut self) {
        for s in self.services.values_mut() {
            for inst in s.instances.values_mut() {
                if inst.log_out.is_none() && inst.log_err.is_none() {
                    continue;
                }
                let arg0 = inst
                    .command
                    .first()
                    .map(|c| c.rsplit('/').next().unwrap_or(c))
                    .unwrap_or("");
                let ident = format!("{arg0}[{}]", inst.pid);
                let facility = inst
                    .facility
                    .as_deref()
                    .map(sys::facility_from_str)
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
        }
    }

    /// Poll for exited children and drive each through `instance_exited`.
    fn reap(&mut self) {
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
                // Otherwise an orphan we never started. PID 1 must reap
                // these; as an ordinary daemon we rarely see them.
                let _ = wstatus;
                continue;
            };
            if self.instance_exited(&sname, &iname, wstatus) {
                self.instance_start(&sname, &iname);
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
        let drop_instance = s
            .instances
            .get(name)
            .map(|i| i.halt && i.state == Run::Stopped)
            .unwrap_or(false);
        if drop_instance {
            s.instances.remove(name);
        }
        if s.can_be_freed() {
            self.services.remove(svc);
        }
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

    // -- ubus --------------------------------------------------------------

    fn dispatch(&mut self, msg: Incoming) {
        let Incoming::Invoke(req) = msg else { return };
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
                // A watched path may have just appeared.
                self.resubscribe();
            } else {
                self.triggers.fire(&req.method, &vars, now);
            }
            let _ = self.conn.reply_status(&req, status::OK, None);
            return;
        }
        let target = if req.objid == self.objects.service {
            Target::Service
        } else if req.objid == self.objects.container {
            Target::Container
        } else if req.objid == self.objects.system {
            Target::System
        } else {
            let _ = self.conn.reply_status(&req, status::NOT_FOUND, None);
            return;
        };
        self.handle(target, req);
    }

    fn handle(&mut self, target: Target, req: Request) {
        let code = match (target, req.method.as_str()) {
            (Target::Service, "set") => self.handle_set(&req, false),
            (Target::Service, "add") => self.handle_set(&req, true),
            (Target::Service, "list") => self.handle_list(&req),
            (Target::Service, "delete") => self.handle_delete(&req),
            (Target::Service, "signal") => self.handle_signal(&req),
            (Target::Service, "state") => self.handle_state(&req),
            (Target::Service, "update_start") => self.handle_update(&req, true),
            (Target::Service, "update_complete") => self.handle_update(&req, false),
            (Target::Service, "get_data") => self.handle_get_data(&req),
            (Target::Service, "set_data") => self.handle_set_data(&req),
            (Target::Service, "event") => self.handle_event(&req),
            (Target::Service, "validate") => self.handle_validate(&req),
            (Target::Service, "watchdog") => self.handle_watchdog(&req),
            _ => status::NOT_SUPPORTED,
        };
        let _ = self.conn.reply_status(&req, code, None);
    }

    /// `service_handle_set()`. `add` merges into the existing instance set;
    /// `set` replaces it, which is the vlist update/flush pair.
    fn handle_set(&mut self, req: &Request, add: bool) -> i32 {
        let mut name: Option<String> = None;
        let mut autostart: Option<bool> = None;
        let mut fresh: BTreeMap<String, Instance> = BTreeMap::new();
        let mut trigger: Option<Vec<u8>> = None;
        let mut validate: Option<Vec<service::Validator>> = None;
        let mut data: BTreeMap<String, String> = BTreeMap::new();
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
                    for e in f.children() {
                        let iname = e.name.to_string();
                        fresh.insert(iname.clone(), instance::parse(&iname, e));
                    }
                }
                "data" => {
                    saw_data = true;
                    for c in f.children() {
                        if let Some(v) = c.as_str() {
                            data.insert(c.name.to_string(), v.to_string());
                        }
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
            self.triggers.del(&name);
            let f = owrt_ubus::blob::Field {
                name: "",
                ty: owrt_ubus::blob::MsgType::Array as u32,
                data: &raw,
            };
            self.triggers.add(f, &name);
        }
        // Re-borrowed: the trigger update above needed `self`, not just `s`.
        let s = self.services.get_mut(&name).expect("service exists");
        if let Some(v) = validate {
            s.validate = v;
        }
        let data_changed = saw_data && s.data != data;
        if saw_data {
            s.data = data;
        }
        s.deleted = false;
        let autostart = s.autostart;

        if !saw_instances {
            if data_changed {
                self.data_trigger(&name);
            }
            if init {
                self.run_init_script(&name);
            }
            return status::OK;
        }

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
                }
                service::InstanceChange::Stop => {
                    // `add` leaves untouched names alone; only `set` flushes.
                    if !add {
                        self.instance_stop(&name, &iname, true);
                        self.collect_stopped(&name, &iname);
                    }
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
                }
            }
        }

        if data_changed {
            self.data_trigger(&name);
        }
        self.refresh_watches(&name);
        // service_update() ends with
        //   if (init || tb[SERVICE_SET_INSTANCES]) rc(s->name, "running");
        // This is the `instances` half; the `init` half is at the early
        // return above, so between them the two paths cover the same
        // condition as the single C call.
        self.run_init_script(&name);
        status::OK
    }

    /// `instance_update()`. Not running (or already stopping) means take the
    /// new config and start; running means restart only on a real config
    /// change, and a data-only change fires the data triggers instead.
    fn instance_update(&mut self, svc: &str, name: &str, new: Instance) {
        let Some(inst) = self.services.get_mut(svc).and_then(|s| s.instances.get_mut(name)) else {
            return;
        };
        let running = inst.state == Run::Running;
        let stopping = inst.state == Run::Halting;
        let changed = inst.config_changed(&new);
        let data_changed = inst.data != new.data;

        if !running || stopping {
            inst.take_config(new);
            self.instance_start(svc, name);
            return;
        }
        inst.take_config(new);
        if changed {
            self.instance_restart(svc, name);
        } else if data_changed {
            self.data_trigger(svc);
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

    /// Subscribe to every watched path that exists and is not already
    /// subscribed. Called after a config change and again whenever ubusd
    /// announces a new object.
    fn resubscribe(&mut self) {
        let wanted: Vec<String> = {
            let mut v: Vec<String> = self.watches.values().flatten().cloned().collect();
            v.sort();
            v.dedup();
            v
        };
        // Drop subscriptions nothing wants any more.
        let stale: Vec<String> = self
            .subscribed
            .keys()
            .filter(|p| !wanted.contains(p))
            .cloned()
            .collect();
        for p in stale {
            if let Some(id) = self.subscribed.remove(&p) {
                let _ = self.conn.unsubscribe(self.watch_obj, id, 1000);
            }
        }
        for path in wanted {
            if self.subscribed.contains_key(&path) {
                continue;
            }
            // A path that does not exist yet is not an error: the
            // ubus.object.add event brings us back here when it appears.
            let Ok(id) = self.conn.lookup_id(&path, 1000) else {
                continue;
            };
            match self.conn.subscribe(self.watch_obj, id, 1000) {
                Ok(()) => {
                    self.subscribed.insert(path, id);
                }
                Err(e) => eprintln!("procd-rs: failed to subscribe {path}: {e}"),
            }
        }
    }

    /// `rc(name, "running")`: queue `<init.d>/<name> running` if that script
    /// exists. A service with no init script queues nothing, which is the
    /// normal case for anything registered straight over the bus.
    fn run_init_script(&mut self, name: &str) {
        let now = self.now_ms();
        let dir = self.init_d.clone();
        self.rc.queue(&dir, name, "running", now);
    }

    /// `service_data_trigger()`: one `service.data.update` per data key.
    fn data_trigger(&mut self, svc: &str) {
        let keys: Vec<String> = self
            .services
            .get(svc)
            .map(|s| s.data.keys().cloned().collect())
            .unwrap_or_default();
        for k in keys {
            let mut b = BlobBuf::new();
            b.msg_string("name", &k);
            let _ = self
                .conn
                .notify(self.objects.service, "service.data.update", b.payload());
        }
    }

    /// `service_handle_list()`.
    fn handle_list(&mut self, req: &Request) -> i32 {
        let mut verbose = false;
        let mut only: Option<String> = None;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "verbose" => verbose = f.as_bool().unwrap_or(false),
                "name" => only = f.as_str().map(str::to_string),
                _ => {}
            }
        }
        let mut b = BlobBuf::new();
        for (n, s) in self.services.iter() {
            if only.as_ref().is_some_and(|want| want != n) {
                continue;
            }
            s.dump(&mut b, verbose);
        }
        let _ = self.conn.reply_data(req, b.payload());
        status::OK
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
        let Some(name) = name else {
            return status::INVALID_ARGUMENT;
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
            }
            None => {
                let names: Vec<String> =
                    self.services[&name].instances.keys().cloned().collect();
                if let Some(s) = self.services.get_mut(&name) {
                    s.deleted = true;
                    s.data.clear();
                }
                for i in names {
                    self.instance_stop(&name, &i, true);
                    self.collect_stopped(&name, &i);
                }
                if self.services.get(&name).is_some_and(|s| s.can_be_freed()) {
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
        // The C arms or cancels the per-instance timer here. This build has
        // no per-instance watchdog timer yet (P3.2), so the values are
        // stored and reported but nothing fires. Recorded as a gap.
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
                let mut opts: BTreeMap<&str, &str> = BTreeMap::new();
                for v in &all[start..i] {
                    if v.kind == ty {
                        for (o, r) in &v.rules {
                            opts.insert(o.as_str(), r.as_str());
                        }
                    }
                }
                for (o, r) in opts {
                    b.msg_string(o, r);
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

        if self.triggers.pending.iter().any(|c| c.pid.is_some()) {
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
        match std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
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
            .map(|(n, i)| (n.clone(), i.state == Run::Running))
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
            let svc_hits: Vec<(&String, &String)> =
                s.data.iter().filter(|(k, _)| want(k)).collect();
            let mut cs = None;
            if !svc_hits.is_empty() {
                cs = Some(b.msg_open_table(sname));
                let ci = b.msg_open_table("*");
                for (k, v) in svc_hits {
                    b.msg_string(k, v);
                }
                b.msg_close(ci);
            }
            for (iname, inst) in s.instances.iter() {
                if instance.as_ref().is_some_and(|n| n != iname) {
                    continue;
                }
                let hits: Vec<(&String, &String)> =
                    inst.data.iter().filter(|(k, _)| want(k)).collect();
                if hits.is_empty() {
                    continue;
                }
                if cs.is_none() {
                    cs = Some(b.msg_open_table(sname));
                }
                let ci = b.msg_open_table(iname);
                for (k, v) in hits {
                    b.msg_string(k, v);
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
        let mut data: BTreeMap<String, String> = BTreeMap::new();
        let mut saw_data = false;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "instance" => instance = f.as_str().map(str::to_string),
                "data" => {
                    saw_data = true;
                    for c in f.children() {
                        if let Some(v) = c.as_str() {
                            data.insert(c.name.to_string(), v.to_string());
                        }
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
                self.data_trigger(&name);
                if let Some(s) = self.services.get_mut(&name) {
                    s.data = data;
                }
                self.data_trigger(&name);
            }
        }
        status::OK
    }

    /// `service_handle_signal()`. Signals the named instance, or every
    /// instance of the service when none is named.
    fn handle_signal(&mut self, req: &Request) -> i32 {
        let mut name: Option<String> = None;
        let mut inst: Option<String> = None;
        let mut sig = SIGKILL;
        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "instance" => inst = f.as_str().map(str::to_string),
                "signal" => sig = f.as_u32().unwrap_or(SIGKILL as u32) as i32,
                _ => {}
            }
        }
        let Some(name) = name else {
            return status::INVALID_ARGUMENT;
        };
        let Some(s) = self.services.get(&name) else {
            return status::NOT_FOUND;
        };
        for (iname, i) in s.instances.iter() {
            if inst.as_ref().is_some_and(|want| want != iname) {
                continue;
            }
            if i.state == Run::Running {
                proc::signal(i.pid, sig);
            }
        }
        status::OK
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("procd-rs: {e}");
        std::process::exit(1);
    }
}

/// The C's `-I <path>`, defaulting to `/etc/init.d`.
fn init_d_path() -> String {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "-I" {
            if let Some(p) = args.next() {
                return p;
            }
        }
    }
    "/etc/init.d".to_string()
}

fn run() -> io::Result<()> {
    owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);

    let conn = Connection::connect(None)?;
    let mut p = Procd {
        conn,
        objects: Objects::default(),
        services: BTreeMap::new(),
        base: Instant::now(),
        validator_seq: 0,
        rc: rcs::RunQueue::default(),
        init_d: init_d_path(),
        watch_obj: 0,
        watches: BTreeMap::new(),
        subscribed: BTreeMap::new(),
        triggers: trigger::Triggers::default(),
    };

    p.objects.service = p.conn.add_object("service", ubus::SERVICE_METHODS, 1000)?;
    p.objects.container = p.conn.add_object("container", ubus::CONTAINER_METHODS, 1000)?;
    p.objects.system = p.conn.add_object("system", ubus::SYSTEM_METHODS, 1000)?;

    // watch_ubus(): an anonymous subscriber object, then a subscription to
    // ubusd's event object so `ubus.object.add` tells us when a watched path
    // finally appears. netifd registers network.interface after procd is
    // already running, so without this the watch would never attach.
    p.watch_obj = p.conn.add_anonymous_object(1000)?;
    if let Err(e) = p
        .conn
        .register_event_handler(p.watch_obj, Some("ubus.object.add"), 1000)
    {
        eprintln!("procd-rs: failed to add ubus event handler: {e}");
    }

    loop {
        // Drain anything already buffered before blocking: a poll on the
        // socket does not see bytes already read out of it. The netifd loop
        // needed exactly this fix.
        while p.conn.has_pending() {
            match p.conn.read_incoming() {
                Ok(msg) => p.dispatch(msg),
                Err(_) => break,
            }
        }
        // Drain output BEFORE reaping: a child that just exited may have
        // left its last lines in the pipe, and closing it on reap would
        // lose them.
        p.pump_logs();
        p.reap();
        p.fire_timeouts();
        p.pump_triggers();
        let now = p.now_ms();
        p.rc.pump(now);

        match p.conn.next_incoming(200) {
            Ok(Some(msg)) => p.dispatch(msg),
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
