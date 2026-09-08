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
mod proc;
mod service;
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
        if !inst.valid || inst.state == Run::Running {
            return;
        }
        inst.halt = false;
        inst.restart = false;
        match proc::start(inst) {
            Ok(pid) => {
                inst.pid = pid;
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
                // An orphan we never started. PID 1 must reap these; as an
                // ordinary daemon we simply will not see many of them.
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
        let mut data: BTreeMap<String, String> = BTreeMap::new();
        let mut saw_instances = false;
        let mut saw_data = false;

        for f in owrt_ubus::blob::fields(&req.data) {
            match f.name {
                "name" => name = f.as_str().map(str::to_string),
                "autostart" => autostart = f.as_bool(),
                "triggers" => trigger = Some(f.data.to_vec()),
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
        if trigger.is_some() {
            s.trigger = trigger;
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
                }
            }
        }

        if data_changed {
            self.data_trigger(&name);
        }
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

fn run() -> io::Result<()> {
    owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);

    let conn = Connection::connect(None)?;
    let mut p = Procd {
        conn,
        objects: Objects::default(),
        services: BTreeMap::new(),
        base: Instant::now(),
    };

    p.objects.service = p.conn.add_object("service", ubus::SERVICE_METHODS, 1000)?;
    p.objects.container = p.conn.add_object("container", ubus::CONTAINER_METHODS, 1000)?;
    p.objects.system = p.conn.add_object("system", ubus::SYSTEM_METHODS, 1000)?;

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
        p.reap();
        p.fire_timeouts();

        match p.conn.next_incoming(200) {
            Ok(Some(msg)) => p.dispatch(msg),
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
