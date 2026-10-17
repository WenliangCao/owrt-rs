//! `hotplug-dispatch.c`: one `hotplug.<subsystem>` ubus object per
//! /etc/hotplug.d directory (plus `button`, which is never removed), each
//! with a single `call {env: Array}` method that sources every script in
//! that directory, one child at a time, 50 ms apart, as
//! `/bin/sh -c ". /lib/functions.sh\n. <script>\n"` with the caller's
//! variables merged into procd's own environment.
//!
//! Env rules from the C: `LD_*` and `PATH=` entries are dropped, names must
//! be [A-Za-z_][A-Za-z0-9_]*, entries shorter than 3 bytes or without `=`
//! are skipped, procd's OWN environment wins over a caller duplicate, and
//! `ASYNC=0` makes the whole call NOT_SUPPORTED. An empty script directory
//! is a successful no-op. inotify on /etc/hotplug.d keeps the object set in
//! step with directory creation/removal at runtime.

use std::collections::{BTreeMap, VecDeque};
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};

use owrt_ubus::blob::MsgType;

pub const BASEDIR: &str = "/etc/hotplug.d";
const PREFIX: &str = "hotplug.";
/// The gap between two scripts of one call (`uloop_timeout_set(.., 50)`).
const STEP_MS: i64 = 50;

pub const HOTPLUG_METHODS: &[(&str, &[(&str, MsgType)])] =
    &[("call", &[("env", MsgType::Array)])];

const IN_CREATE: u32 = 0x100;
const IN_DELETE: u32 = 0x200;
const IN_MOVED_FROM: u32 = 0x40;
const IN_MOVED_TO: u32 = 0x80;
const IN_ISDIR: u32 = 0x4000_0000;

/// One `call` in flight: the remaining scripts and the child running now.
struct Job {
    scripts: Vec<String>,
    next: usize,
    envp: Vec<(String, String)>,
    child: Option<i32>,
    /// Next script may start at this time (the 50 ms gap).
    at: i64,
}

#[derive(Default)]
pub struct Dispatch {
    /// subsystem -> registered object id.
    pub objects: BTreeMap<String, u32>,
    inotify: Option<OwnedFd>,
    jobs: Vec<Job>,
    /// Latest desired state per subsystem, in fair retry order.
    pending: VecDeque<(String, bool, i64)>,
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

/// The subsystem directories the object set starts from.
fn scan_subsystems() -> Vec<String> {
    let mut out = vec!["button".to_string()];
    if let Ok(dir) = std::fs::read_dir(BASEDIR) {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

impl Dispatch {
    pub fn new() -> Dispatch {
        use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
        let inotify = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)
            .ok()
            .and_then(|fd| {
                let events = WatchFlags::CREATE | WatchFlags::DELETE
                    | WatchFlags::MOVED_TO | WatchFlags::MOVED_FROM;
                inotify::add_watch(&fd, BASEDIR, events).ok().map(|_| fd)
            });
        Dispatch { objects: BTreeMap::new(), inotify, jobs: Vec::new(), pending: VecDeque::new() }
    }

    /// The /etc/hotplug.d inotify fd, for the main loop's poll set.
    pub fn inotify_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.inotify.as_ref().map(|f| f.as_raw_fd())
    }

    /// Queue the initial object set (`init_subsystems`). The caller gives
    /// each path one attempt before rcS, maintaining supervision in between.
    pub fn register_all(&mut self) -> usize {
        for name in scan_subsystems() {
            self.queue_change(&name, true);
        }
        self.pending.len()
    }

    fn queue_change(&mut self, name: &str, present: bool) {
        // C's button object survives removal of its directory.
        if !present && name == "button" { return; }
        if let Some((_, desired, _)) = self.pending.iter_mut().find(|(n, _, _)| n == name) {
            *desired = present;
        } else if self.objects.contains_key(name) != present {
            self.pending.push_back((name.to_owned(), present, 0));
        }
    }

    /// Retry one object operation, never a whole directory batch. Keep the
    /// desired state on failure; duplicate inotify does not reset backoff.
    pub fn pump_registration(&mut self, conn: &mut owrt_ubus::conn::Connection, now: i64) -> bool {
        use owrt_ubus::{conn::error_status, msg::status};
        let Some(index) = self.pending.iter().position(|(_, _, at)| *at <= now) else { return false };
        let (name, present, _) = self.pending.remove(index).unwrap();
        let result = if present {
            if self.objects.contains_key(&name) { return true; }
            conn.add_object(&format!("{PREFIX}{name}"), HOTPLUG_METHODS, 1000)
                .map(|id| { self.objects.insert(name.clone(), id); })
        } else {
            let Some(&id) = self.objects.get(&name) else { return true };
            let result = conn.remove_object(id, 1000);
            if result.is_ok() || result.as_ref().is_err_and(|e| error_status(e) == Some(status::NOT_FOUND)) {
                self.objects.remove(&name);
                Ok(())
            } else { result }
        };
        if let Err(error) = result {
            log!(crate::sys::LOG_ERR, "failed to update hotplug.{name}: {error}");
            // ADD_OBJECT may have succeeded even if its acknowledgement was
            // lost. Reconnect to release those connection-owned objects;
            // a blind retry could collide forever with our unknown old id.
            if error_status(&error) == Some(status::TIMEOUT) {
                let _ = conn.shutdown();
            }
            self.pending.push_back((name, present, now + 2000));
        }
        true
    }

    pub fn next_registration_ms(&self, now: i64) -> Option<i32> {
        self.pending.iter().map(|(_, _, at)| *at).min()
            .map(|at| (at - now).clamp(0, i64::from(i32::MAX)) as i32)
    }

    /// After a reconnect every id is stale; replay current directories.
    pub fn reregister(&mut self) {
        self.objects.clear();
        self.pending.clear();
        self.register_all();
    }

    /// Which subsystem an incoming invoke's objid belongs to.
    pub fn subsystem_of(&self, objid: u32) -> Option<&str> {
        self.objects
            .iter()
            .find(|(_, id)| **id == objid)
            .map(|(n, _)| n.as_str())
    }

    /// `hotplug_call`. Returns a ubus status.
    pub fn call(&mut self, subsys: &str, req_data: &[u8], now: i64) -> i32 {
        use owrt_ubus::msg::status;
        let mut env_attr = None;
        for f in owrt_ubus::blob::fields(req_data) {
            if f.name == "env" && f.ty == MsgType::Array as u32 {
                env_attr = Some(f);
            }
        }
        let Some(env_attr) = env_attr else {
            return status::INVALID_ARGUMENT;
        };
        // procd's own environment first: an existing name wins duplicates.
        let mut envp: Vec<(String, String)> = std::env::vars().collect();
        let mut async_call = true;
        for c in env_attr.children() {
            let Some(e) = c.as_str() else { continue };
            if e.starts_with("LD_") || e.starts_with("PATH=") || e.len() < 3 {
                continue;
            }
            let Some((k, v)) = e.split_once('=') else { continue };
            if !valid_env_name(k) {
                continue;
            }
            if e == "ASYNC=0" {
                async_call = false;
            }
            if !envp.iter().any(|(n, _)| n == k) {
                envp.push((k.to_string(), v.to_string()));
            }
        }
        if !async_call {
            // "synchronous calls are unsupported for now"
            return status::NOT_SUPPORTED;
        }
        let dir = format!("{BASEDIR}/{subsys}");
        // glob("<dir>/*") does not exclude directories: the C hands a
        // subdirectory to `sh -c ". <dir>"` too (which fails harmlessly into
        // /dev/null). Filtering them out changed the script count and the
        // 50 ms cadence, so they stay in.
        let mut scripts: Vec<String> = std::fs::read_dir(&dir)
            .map(|d| {
                d.flatten()
                    .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                    .map(|e| e.path().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        scripts.sort();
        if scripts.is_empty() {
            // glob() failing is still UBUS_STATUS_OK in the C.
            return status::OK;
        }
        self.jobs.push(Job { scripts, next: 0, envp, child: None, at: now + STEP_MS });
        status::OK
    }

    /// Route a reaped pid. The next script waits STEP_MS.
    pub fn reaped(&mut self, pid: i32, now: i64) -> bool {
        for j in self.jobs.iter_mut() {
            if j.child == Some(pid) {
                j.child = None;
                j.at = now + STEP_MS;
                return true;
            }
        }
        false
    }

    /// No script call in flight or waiting for its 50 ms gap. inotify events
    /// still wake the loop through its descriptor.
    pub fn is_idle(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Start due scripts and process inotify (`hotplug_exec` +
    /// `inotify_read_handler`).
    pub fn pump(&mut self, conn: &mut owrt_ubus::conn::Connection, now: i64, read_inotify: bool) {
        for j in self.jobs.iter_mut() {
            if j.child.is_some() || now < j.at {
                continue;
            }
            if j.next >= j.scripts.len() {
                continue; // collected below
            }
            let script = &j.scripts[j.next];
            j.next += 1;
            let body = format!(". /lib/functions.sh\n. {script}\n");
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(body);
            c.env_clear();
            for (k, v) in &j.envp {
                c.env(k, v);
            }
            c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            crate::proc::inherit_ignored_sigpipe(&mut c);
            match c.spawn() {
                Ok(child) => {
                    j.child = Some(child.id() as i32);
                    std::mem::forget(child);
                }
                Err(e) => log!(crate::sys::LOG_ERR, "Failed to execute script: {e}"),
            }
        }
        self.jobs.retain(|j| j.child.is_some() || j.next < j.scripts.len());

        if read_inotify { self.read_changes(); }
        self.pump_registration(conn, now);
    }

    fn read_changes(&mut self) {
        // inotify: directory create/remove tracks the object set.
        let Some(fd) = self.inotify.as_ref() else { return };
        let mut buf = [0u8; 4096];
        // One buffer per maintenance pass retains the existing fairness bound.
        {
            let Ok(n) = rustix::io::read(fd, &mut buf) else { return };
            if n == 0 { return; }
            let mut off = 0usize;
            // struct inotify_event: wd i32, mask u32, cookie u32, len u32, name[].
            while off + 16 <= n as usize {
                let mask = u32::from_ne_bytes(buf[off + 4..off + 8].try_into().unwrap());
                let len = u32::from_ne_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
                let name_bytes = &buf[off + 16..(off + 16 + len).min(n as usize)];
                off += 16 + len;
                if mask & IN_ISDIR == 0 {
                    continue;
                }
                let end = name_bytes.iter().position(|b| *b == 0).unwrap_or(name_bytes.len());
                let Ok(name) = std::str::from_utf8(&name_bytes[..end]) else { continue };
                let name = name.to_string();
                if name.is_empty() || name.starts_with('.') {
                    continue;
                }
                if mask & (IN_CREATE | IN_MOVED_TO) != 0 {
                    self.queue_change(&name, true);
                } else if mask & (IN_DELETE | IN_MOVED_FROM) != 0 {
                    self.queue_change(&name, false);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_names_follow_the_c_validator() {
        assert!(valid_env_name("FOO"));
        assert!(valid_env_name("_x9"));
        assert!(!valid_env_name("9FOO"), "no leading digit");
        assert!(!valid_env_name("FO-O"));
        assert!(!valid_env_name(""));
    }

    #[cfg(target_os = "linux")]
    mod recovery {
        use super::*;
        use std::io::{Read, Write};
        use std::os::unix::{net::{UnixListener, UnixStream}, process::ExitStatusExt};
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};
        use owrt_ubus::{blob::BlobBuf, conn::Connection, msg::{attr, ty, Header}};

        fn peer(mut stream: UnixStream, calls: Arc<Mutex<Vec<String>>>, delay: u64, mut fail: bool) {
            stream.write_all(&[0, ty::HELLO, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4]).unwrap();
            let mut id = 2000;
            loop {
                let mut head = [0; 12];
                if stream.read_exact(&mut head).is_err() { return; }
                let header = Header::decode(head[..8].try_into().unwrap()).unwrap();
                let len = (u32::from_be_bytes(head[8..].try_into().unwrap()) & 0xffffff) as usize;
                let mut body = vec![0; len - 4];
                stream.read_exact(&mut body).unwrap();
                let attrs: Vec<_> = owrt_ubus::blob::iter(&body).collect();
                let label = if header.ty == ty::ADD_OBJECT {
                    attrs.iter().find(|a| a.id == attr::OBJPATH).unwrap().as_str().unwrap().to_owned()
                } else {
                    assert_eq!(header.ty, ty::REMOVE_OBJECT);
                    "remove".to_owned()
                };
                calls.lock().unwrap().push(label);
                std::thread::sleep(Duration::from_millis(delay));
                let mut status = BlobBuf::new();
                if fail {
                    fail = false;
                    status.put_u32(attr::STATUS, owrt_ubus::msg::status::UNKNOWN_ERROR as u32);
                } else {
                    let mut data = BlobBuf::new();
                    id += 1;
                    data.put_u32(attr::OBJID, id);
                    stream.write_all(&Header { ty: ty::DATA, seq: header.seq, peer: header.peer }.encode()).unwrap();
                    stream.write_all(data.as_bytes()).unwrap();
                    status.put_u32(attr::STATUS, 0);
                }
                stream.write_all(&Header { ty: ty::STATUS, seq: header.seq, peer: header.peer }.encode()).unwrap();
                stream.write_all(status.as_bytes()).unwrap();
            }
        }

        fn connection(label: &str, delay: u64, fail: bool) -> (Connection, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
            let path = format!("/tmp/procd-dispatch-{label}-{}.sock", std::process::id());
            let listener = UnixListener::bind(&path).unwrap();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let peer_calls = Arc::clone(&calls);
            let worker = std::thread::spawn(move || peer(listener.accept().unwrap().0, peer_calls, delay, fail));
            let conn = Connection::connect(Some(&path)).unwrap();
            std::fs::remove_file(path).unwrap();
            (conn, calls, worker)
        }

        #[test]
        fn slow_directory_batch_yields_to_owned_child_deadline_and_registers_every_object() {
            // Watch a private temporary directory, never host /etc/hotplug.d.
            let path = format!("/tmp/procd-dispatch-dirs-{}", std::process::id());
            std::fs::create_dir(&path).unwrap();
            use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
            let fd = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC).unwrap();
            inotify::add_watch(&fd, &path, WatchFlags::CREATE | WatchFlags::DELETE).unwrap();
            let mut d = Dispatch {
                inotify: Some(fd),
                ..Default::default()
            };
            for n in 0..6 { std::fs::create_dir(format!("{path}/test{n}")).unwrap(); }
            let (conn, calls, worker) = connection("slow", 350, false);
            let mut p = crate::watch_tests::supervisor(conn);
            let mut child = Command::new("/bin/sleep").arg("10").spawn().unwrap();
            let mut instance = crate::Instance::new("directory-child");
            instance.pid = child.id() as i32;
            instance.halt = true;
            instance.state = crate::Run::Halting;
            instance.deadline = Some(p.now_ms() + 50);
            let mut service = crate::Service::new("directory-service");
            service.instances.insert(instance.name.clone(), instance);
            p.services.insert(service.name.clone(), service);
            let start = Instant::now();
            let mut stopped_at = None;
            while start.elapsed() < Duration::from_secs(6) {
                let now = p.now_ms();
                d.pump(&mut p.conn, now, true);
                p.fire_timeouts();
                if stopped_at.is_none() {
                    if let Some(status) = child.try_wait().unwrap() {
                        assert_eq!(status.signal(), Some(crate::SIGKILL));
                        stopped_at = Some(start.elapsed());
                    }
                }
                if stopped_at.is_some() && d.objects.len() == 6 { break; }
                std::thread::sleep(Duration::from_millis(10));
            }
            if stopped_at.is_none() { let _ = child.kill(); }
            child.wait().unwrap();
            let stopped_at = stopped_at.expect("owned child must be killed");
            eprintln!("directory batch: child stopped at {stopped_at:?}, all objects at {:?}", start.elapsed());
            assert_eq!(d.objects.len(), 6);
            assert_eq!(calls.lock().unwrap().len(), 6);
            drop(p);
            worker.join().unwrap();
            drop(d);
            std::fs::remove_dir_all(path).unwrap();
            assert!(stopped_at < Duration::from_millis(1400), "directory batch starved child: {stopped_at:?}");
        }

        #[test]
        fn failed_registration_retries_and_directory_changes_coalesce_without_dropping_button() {
            let (mut conn, calls, worker) = connection("retry", 0, true);
            let mut d = Dispatch::default();
            d.queue_change("button", true);
            d.queue_change("changing", true);
            d.queue_change("changing", false);
            assert!(d.pump_registration(&mut conn, 0)); // explicit error
            assert!(d.pump_registration(&mut conn, 0)); // cancelled creation, no call
            assert!(!d.pump_registration(&mut conn, 1000));
            // The same deadline calculation drives the main loop before
            // draining pending requests, at poll, and after readable wakes.
            let (scheduler_conn, _, scheduler_peer) = connection("scheduler", 0, false);
            let mut p = crate::watch_tests::supervisor(scheduler_conn);
            p.dispatch = d;
            assert_eq!(p.maintenance_delay_ms(1000, 5000), 1000);
            assert_eq!(p.maintenance_delay_ms(2000, 5000), 0,
                "a due retry must run maintenance even when the bus remains readable");
            d = std::mem::take(&mut p.dispatch);
            drop(p);
            scheduler_peer.join().unwrap();
            for _ in 0..100 { d.queue_change("button", true); }
            assert_eq!(d.pending.len(), 1);
            assert!(d.pump_registration(&mut conn, 2000));
            d.queue_change("button", false);
            assert!(d.pending.is_empty());
            d.queue_change("changing", true);
            d.pump_registration(&mut conn, 2000);
            d.queue_change("changing", false);
            d.pump_registration(&mut conn, 2000);
            assert_eq!(d.objects.keys().cloned().collect::<Vec<_>>(), ["button"]);
            assert_eq!(*calls.lock().unwrap(), ["hotplug.button", "hotplug.button", "hotplug.changing", "remove"]);
            drop(conn);
            worker.join().unwrap();
        }
    }

}
