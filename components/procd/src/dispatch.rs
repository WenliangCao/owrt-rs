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

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};

use owrt_ubus::blob::MsgType;

pub const BASEDIR: &str = "/etc/hotplug.d";
const PREFIX: &str = "hotplug.";
/// The gap between two scripts of one call (`uloop_timeout_set(.., 50)`).
const STEP_MS: i64 = 50;

pub const HOTPLUG_METHODS: &[(&str, &[(&str, MsgType)])] =
    &[("call", &[("env", MsgType::Array)])];

extern "C" {
    fn inotify_init1(flags: i32) -> i32;
    fn inotify_add_watch(fd: i32, path: *const u8, mask: u32) -> i32;
    fn read(fd: i32, buf: *mut u8, n: usize) -> isize;
}

const IN_NONBLOCK: i32 = 0o4000;
const IN_CLOEXEC: i32 = 0o2000000;
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
        // SAFETY: inotify_init1 with flag ints only.
        let fd = unsafe { inotify_init1(IN_NONBLOCK | IN_CLOEXEC) };
        let inotify = if fd >= 0 {
            let ok = CString::new(BASEDIR).is_ok_and(|c| {
                // SAFETY: NUL-terminated path on a live inotify fd.
                unsafe {
                    inotify_add_watch(
                        fd,
                        c.as_ptr().cast(),
                        IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM,
                    ) >= 0
                }
            });
            if ok {
                // SAFETY: fd is open and owned once.
                Some(unsafe { OwnedFd::from_raw_fd(fd) })
            } else {
                // SAFETY: fd was just opened.
                unsafe { crate::sys::close_fd(fd) };
                None
            }
        } else {
            None
        };
        Dispatch { objects: BTreeMap::new(), inotify, jobs: Vec::new() }
    }

    /// Register the initial object set (`init_subsystems`).
    pub fn register_all(&mut self, conn: &mut owrt_ubus::conn::Connection) {
        for name in scan_subsystems() {
            self.add(conn, &name);
        }
    }

    fn add(&mut self, conn: &mut owrt_ubus::conn::Connection, name: &str) {
        if self.objects.contains_key(name) {
            return;
        }
        match conn.add_object(&format!("{PREFIX}{name}"), HOTPLUG_METHODS, 1000) {
            Ok(id) => {
                self.objects.insert(name.to_string(), id);
            }
            Err(e) => eprintln!("procd-rs: failed to add hotplug.{name}: {e}"),
        }
    }

    fn remove(&mut self, conn: &mut owrt_ubus::conn::Connection, name: &str) {
        // `remove_subsystem`: button stays whatever happens on disk.
        if name == "button" {
            return;
        }
        if let Some(id) = self.objects.remove(name) {
            let _ = conn.remove_object(id, 1000);
        }
    }

    /// After a reconnect every id is stale; re-register from scratch.
    pub fn reregister(&mut self, conn: &mut owrt_ubus::conn::Connection) {
        self.objects.clear();
        self.register_all(conn);
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
        let mut scripts: Vec<String> = std::fs::read_dir(&dir)
            .map(|d| {
                d.flatten()
                    .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                    .filter(|e| e.file_type().map(|t| !t.is_dir()).unwrap_or(false))
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

    /// Start due scripts and process inotify (`hotplug_exec` +
    /// `inotify_read_handler`).
    pub fn pump(&mut self, conn: &mut owrt_ubus::conn::Connection, now: i64) {
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
            match c.spawn() {
                Ok(child) => {
                    j.child = Some(child.id() as i32);
                    std::mem::forget(child);
                }
                Err(e) => eprintln!("procd-rs: failed to execute script: {e}"),
            }
        }
        self.jobs.retain(|j| j.child.is_some() || j.next < j.scripts.len());

        // inotify: directory create/remove tracks the object set.
        use std::os::fd::AsRawFd;
        let Some(raw) = self.inotify.as_ref().map(|f| f.as_raw_fd()) else { return };
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: non-blocking read into a live buffer; the fd stays
            // owned by self.inotify for the whole loop.
            let n = unsafe { read(raw, buf.as_mut_ptr(), buf.len()) };
            if n <= 0 {
                break;
            }
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
                    self.add(conn, &name);
                } else if mask & (IN_DELETE | IN_MOVED_FROM) != 0 {
                    self.remove(conn, &name);
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
}
