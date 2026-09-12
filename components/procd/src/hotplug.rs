//! `plug/hotplug.c` + `plug/coldplug.c`: the kernel uevent listener, the
//! /etc/hotplug.json rule run, and the serialized command queue.
//!
//! Shapes that matter, read out of the C rather than assumed:
//!
//! - the netlink socket binds NETLINK_KOBJECT_UEVENT with groups -1 and a
//!   512 KiB forced receive buffer; every datagram is split on NULs and
//!   only `KEY=value` segments become variables (the "action@devpath"
//!   header has no `=` and drops out by itself).
//! - `DEVNAME`/`DEVICENAME` fall back to the basename of `DEVPATH` when the
//!   event does not carry them (`rule_handle_var`), so `has DEVNAME` is TRUE
//!   whenever DEVPATH exists. The fallback is answered by the rule engine's
//!   lookup and never enters the variable table: an `exec` child's
//!   environment and the `hotplug.<subsys>` notification carry only what
//!   the kernel sent.
//! - `makedev` and `rm` are ATOMIC (run in-process, in order); everything
//!   else is a queue of forked children, one at a time.
//! - a `button` child's exit code (>>8) is a timeout in seconds: the same
//!   argv is re-queued that much later with ACTION=timeout and SEEN=<secs>.
//!   A new event for the same button cancels the pending timeout first.
//! - `load-firmware` writes 1 to /sys/<DEVPATH>/loading, streams the file
//!   into /sys/<DEVPATH>/data, then writes 0 -- and does all of it even
//!   when the file is missing (the kernel needs the 0 to fail the request).
//! - coldplug detaches /dev, mounts a fresh 512K tmpfs (skipped inside a
//!   container), forks /sbin/udevtrigger, and EARLY advances only after the
//!   trigger has exited AND the rules have been quiet for 500 ms.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};

use crate::jsonscript;
use crate::sys;
use owrt_ubus::blob::{BlobBuf, Field, MsgType};

/// `HOTPLUG_WAIT`.
const QUIET_MS: i64 = 500;

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockaddrNl, len: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, opt: i32, val: *const i32, len: u32) -> i32;
    fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn mknod(path: *const u8, mode: u32, dev: u64) -> i32;
    fn mount(src: *const u8, target: *const u8, fstype: *const u8, flags: u64, data: *const u8) -> i32;
    fn umount2(target: *const u8, flags: i32) -> i32;
    fn umask(mask: u32) -> u32;
}

#[repr(C)]
struct SockaddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

const AF_NETLINK: i32 = 16;
const SOCK_DGRAM: i32 = 2;
const SOCK_CLOEXEC: i32 = 0x80000;
const NETLINK_KOBJECT_UEVENT: i32 = 15;
const SOL_SOCKET: i32 = 1;
const SO_RCVBUFFORCE: i32 = 33;
const MSG_DONTWAIT: i32 = 0x40;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const MNT_DETACH: i32 = 2;
const MS_NOSUID: u64 = 2;
const MS_NOEXEC: u64 = 8;
const MS_NOATIME: u64 = 0x400;

/// One queued (non-atomic) command.
struct Queued {
    kind: CmdKind,
    vars: BTreeMap<String, String>,
    argv: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum CmdKind {
    Exec,
    Button,
    Firmware,
    StartConsole,
}

/// A `button` child that exited with a timeout: fire again later.
struct ButtonTimeout {
    name: String,
    seen: i32,
    at: i64,
    argv: Vec<String>,
}

enum Coldplug {
    Idle,
    /// udevtrigger is running.
    Trigger(i32),
    /// Trigger done; waiting for QUIET_MS without rule activity.
    Quiet,
    Done,
}

pub struct Hotplug {
    fd: OwnedFd,
    /// The rules, as a blobmsg ARRAY payload converted from the JSON file.
    rules: Vec<u8>,
    queue: VecDeque<Queued>,
    /// The currently forked queue child, with its button context.
    child: Option<(i32, Queued)>,
    buttons: Vec<ButtonTimeout>,
    coldplug: Coldplug,
    /// `last_event`: rearmed on every handled command while coldplug waits.
    quiet_at: i64,
}

use owrt_ubus::convert::json_to_fields as json_to_blob;


/// `rule_handle_file` + caching: the file is read once.
fn load_rules(path: &str) -> Option<Vec<u8>> {
    rules_blob(&std::fs::read(path).ok()?)
}

/// The JSON rule text as the blobmsg array json_script runs.
pub fn rules_blob(text: &[u8]) -> Option<Vec<u8>> {
    let j = owrt_ubus::json::parse(std::str::from_utf8(text).ok()?).ok()?;
    let mut b = BlobBuf::new();
    json_to_blob(&mut b, "", &j);
    // The payload's first (only) field is the whole rule array; keep its
    // DATA so it can be re-wrapped as a Field on each run.
    let f = owrt_ubus::blob::fields(b.payload()).next()?;
    if f.ty != MsgType::Array as u32 {
        return None;
    }
    Some(f.data.to_vec())
}

/// The uevent datagram -> variable table: exactly the `KEY=value` segments
/// the kernel sent. The DEVNAME/DEVICENAME fallback lives in the rule
/// engine (`jsonscript::run_hotplug_rule`), as `rule_handle_var` does.
pub fn parse_uevent(buf: &[u8]) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for seg in buf.split(|b| *b == 0) {
        let Ok(s) = std::str::from_utf8(seg) else { continue };
        if let Some((k, v)) = s.split_once('=') {
            vars.insert(k.to_string(), v.to_string());
        }
    }
    vars
}

impl Hotplug {
    /// The uevent socket, for the main loop's poll set.
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.fd.as_raw_fd()
    }

    /// `hotplug(rules)`: open and bind the uevent socket.
    pub fn new(rule_file: &str) -> Option<Hotplug> {
        let rules = load_rules(rule_file)?;
        // SAFETY: plain socket syscalls; the fd is owned immediately.
        let fd = unsafe { socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT) };
        if fd < 0 {
            log!(sys::LOG_ERR, "Failed to open hotplug socket");
            return None;
        }
        let addr = SockaddrNl { nl_family: AF_NETLINK as u16, nl_pad: 0, nl_pid: 0, nl_groups: u32::MAX };
        // SAFETY: addr is a live local of the correct layout.
        if unsafe { bind(fd, &addr, std::mem::size_of::<SockaddrNl>() as u32) } != 0 {
            log!(sys::LOG_ERR, "Failed to bind hotplug socket");
            // SAFETY: fd was just opened.
            unsafe { sys::close_fd(fd) };
            return None;
        }
        let bufsize: i32 = 512 * 1024;
        // SAFETY: setsockopt with an int payload.
        if unsafe { setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, 4) } != 0 {
            log!(sys::LOG_ERR, "Failed to resize receive buffer");
        }
        Some(Hotplug {
            // SAFETY: fd is open and owned once.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            rules,
            queue: VecDeque::new(),
            child: None,
            buttons: Vec::new(),
            coldplug: Coldplug::Idle,
            quiet_at: 0,
        })
    }

    /// `procd_coldplug()`.
    pub fn coldplug(&mut self, in_container: bool) {
        // SAFETY: umask read-modify with plain ints.
        let old = unsafe { umask(0) };
        if !in_container {
            // SAFETY: constant NUL-terminated paths throughout.
            unsafe {
                umount2(c"/dev/pts".as_ptr().cast(), MNT_DETACH);
                umount2(c"/dev/".as_ptr().cast(), MNT_DETACH);
                mount(
                    c"tmpfs".as_ptr().cast(),
                    c"/dev".as_ptr().cast(),
                    c"tmpfs".as_ptr().cast(),
                    MS_NOATIME | MS_NOEXEC | MS_NOSUID,
                    c"mode=0755,size=512K".as_ptr().cast(),
                );
                mknod(c"/dev/null".as_ptr().cast(), S_IFCHR | 0o666, libc_makedev(1, 3));
            }
            // mkdir("/dev/pts", 0755) runs under umask(0): the mode must be
            // explicit or it comes out 0777.
            let _ = std::fs::create_dir("/dev/pts");
            let _ = std::fs::set_permissions(
                "/dev/pts",
                std::os::unix::fs::PermissionsExt::from_mode(0o755),
            );
            // SAFETY: as above.
            unsafe {
                mount(
                    c"devpts".as_ptr().cast(),
                    c"/dev/pts".as_ptr().cast(),
                    c"devpts".as_ptr().cast(),
                    MS_NOATIME | MS_NOEXEC | MS_NOSUID,
                    std::ptr::null(),
                );
            }
        }
        let _ = std::os::unix::fs::symlink("/tmp/shm", "/dev/shm");
        // SAFETY: restoring the saved mask.
        unsafe { umask(old) };

        let mut trigger = Command::new("udevtrigger");
        trigger.stdin(Stdio::null());
        crate::proc::inherit_ignored_sigpipe(&mut trigger);
        match trigger.spawn() {
            Ok(c) => {
                let pid = c.id() as i32;
                std::mem::forget(c);
                self.coldplug = Coldplug::Trigger(pid);
            }
            Err(e) => {
                log!(sys::LOG_ERR, "Failed to start coldplug: {e}");
                // The C leaves the state machine stuck here; a boot that can
                // never leave EARLY is strictly worse than one without
                // coldplug, so the quiet timer still runs.
                self.coldplug = Coldplug::Quiet;
                self.quiet_at = 0;
            }
        }
    }

    /// True once EARLY may advance (`coldplug_complete`).
    pub fn coldplug_done(&mut self, now: i64) -> bool {
        match self.coldplug {
            Coldplug::Quiet => {
                if self.quiet_at == 0 {
                    self.quiet_at = now + QUIET_MS;
                }
                if now >= self.quiet_at {
                    self.coldplug = Coldplug::Done;
                    return true;
                }
                false
            }
            Coldplug::Done => true,
            _ => false,
        }
    }

    /// Route a reaped pid here. Returns true when it was ours.
    pub fn reaped(&mut self, pid: i32, wstatus: i32) -> bool {
        if let Coldplug::Trigger(p) = self.coldplug {
            if p == pid {
                self.coldplug = Coldplug::Quiet;
                self.quiet_at = 0;
                return true;
            }
        }
        let Some((cpid, _)) = &self.child else { return false };
        if *cpid != pid {
            return false;
        }
        let (_, cmd) = self.child.take().expect("just matched");
        // handle_button_complete: exit>>8 seconds until an ACTION=timeout
        // replay of the same argv.
        if cmd.kind == CmdKind::Button {
            let secs = (wstatus >> 8) & 0xff;
            if secs != 0 {
                if let Some(name) = cmd.vars.get("BUTTON") {
                    self.buttons.push(ButtonTimeout {
                        name: name.clone(),
                        seen: secs,
                        at: 0, // armed on the next pump, which knows `now`
                        argv: cmd.argv.clone(),
                    });
                }
            }
        }
        true
    }

    fn start_next(&mut self) {
        if self.child.is_some() {
            return;
        }
        let Some(cmd) = self.queue.pop_front() else { return };
        match cmd.kind {
            // pump() intercepts StartConsole before this point; it never
            // reaches the fork path.
            CmdKind::StartConsole => {}
            CmdKind::Firmware => {
                let pid = spawn_firmware(&cmd);
                if let Some(pid) = pid {
                    self.child = Some((pid, cmd));
                }
            }
            CmdKind::Exec | CmdKind::Button => {
                let pid = spawn_exec(&cmd);
                if let Some(pid) = pid {
                    self.child = Some((pid, cmd));
                }
            }
        }
    }

    /// Drain the socket, run rules, fire button timeouts, start queue work.
    /// Returns whether a `start-console` command asked for the inittab
    /// console handlers, and the events received (for `hotplug_ubus_event`'s
    /// per-subsystem notification).
    pub fn pump(&mut self, now: i64) -> (bool, Vec<BTreeMap<String, String>>) {
        let mut console_request = false;
        let mut events = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            use std::os::fd::AsRawFd;
            // SAFETY: read into a live buffer, non-blocking.
            let n = unsafe { recv(self.fd.as_raw_fd(), buf.as_mut_ptr(), buf.len() - 1, MSG_DONTWAIT) };
            if n < 1 {
                break;
            }
            let vars = parse_uevent(&buf[..n as usize]);
            self.run_rules(&vars, now);
            events.push(vars);
        }
        // Button timers: arm the fresh ones, fire the due ones.
        for b in self.buttons.iter_mut() {
            if b.at == 0 {
                b.at = now + b.seen as i64 * 1000;
            }
        }
        let due: Vec<usize> = self
            .buttons
            .iter()
            .enumerate()
            .filter(|(_, b)| b.at != 0 && now >= b.at)
            .map(|(i, _)| i)
            .collect();
        for i in due.into_iter().rev() {
            let b = self.buttons.remove(i);
            let mut vars = BTreeMap::new();
            vars.insert("BUTTON".to_string(), b.name);
            vars.insert("ACTION".to_string(), "timeout".to_string());
            vars.insert("SEEN".to_string(), b.seen.to_string());
            self.queue.push_back(Queued { kind: CmdKind::Exec, vars, argv: b.argv });
            self.touch_quiet(now);
        }
        // start-console entries are answered in the caller's context.
        while self.child.is_none() {
            if matches!(self.queue.front().map(|c| c.kind), Some(CmdKind::StartConsole)) {
                self.queue.pop_front();
                console_request = true;
                continue;
            }
            let before = self.queue.len();
            self.start_next();
            if self.queue.len() == before {
                break;
            }
        }
        (console_request, events)
    }

    fn touch_quiet(&mut self, now: i64) {
        if matches!(self.coldplug, Coldplug::Quiet) {
            self.quiet_at = now + QUIET_MS;
        }
    }

    /// `json_script_run` over one event's variables.
    fn run_rules(&mut self, vars: &BTreeMap<String, String>, now: i64) {
        let rules = std::mem::take(&mut self.rules);
        {
            let block = Field { name: "", ty: MsgType::Array as u32, data: &rules };
            let out = jsonscript::run_hotplug_rule(block, vars);
            for e in out.errors {
                // rule_handle_error()
                log!(sys::LOG_ERR, "ERROR: {e}");
            }
            for (name, argv) in out.commands {
                self.dispatch(&name, argv, vars, now);
            }
        }
        self.rules = rules;
    }

    fn dispatch(&mut self, name: &str, argv: Vec<String>, vars: &BTreeMap<String, String>, now: i64) {
        match name {
            // Atomic: in-process, in order.
            "makedev" => handle_makedev(&argv, vars),
            "rm" => {
                if let Some(p) = argv.first() {
                    let _ = std::fs::remove_file(p);
                }
            }
            "exec" => self.queue.push_back(Queued { kind: CmdKind::Exec, vars: vars.clone(), argv }),
            "button" => {
                // handle_button_start: a new event for this button cancels
                // its pending timeout.
                if let Some(name) = vars.get("BUTTON") {
                    self.buttons.retain(|b| &b.name != name);
                }
                self.queue.push_back(Queued { kind: CmdKind::Button, vars: vars.clone(), argv });
            }
            "load-firmware" => {
                self.queue.push_back(Queued { kind: CmdKind::Firmware, vars: vars.clone(), argv })
            }
            "start-console" => {
                self.queue.push_back(Queued { kind: CmdKind::StartConsole, vars: vars.clone(), argv })
            }
            _ => return,
        }
        self.touch_quiet(now);
    }
}

fn libc_makedev(major: u32, minor: u32) -> u64 {
    // glibc/musl makedev(): the historical split layout.
    ((major as u64 & 0xfffff000) << 32)
        | ((major as u64 & 0xfff) << 8)
        | ((minor as u64 & 0xffffff00) << 12)
        | (minor as u64 & 0xff)
}

/// `handle_makedev`: /dev node under umask 0, block vs char by SUBSYSTEM,
/// optional group as the third argument.
fn handle_makedev(argv: &[String], vars: &BTreeMap<String, String>) {
    let (Some(path), Some(mode)) = (argv.first(), argv.get(1)) else { return };
    let (Some(minor), Some(major), Some(subsystem)) =
        (vars.get("MINOR"), vars.get("MAJOR"), vars.get("SUBSYSTEM"))
    else {
        return;
    };
    // SAFETY: umask read-modify.
    let old = unsafe { umask(0) };
    if let Some(dir) = std::path::Path::new(path).parent() {
        // mkdir_p(d, 0755): create_dir_all under umask(0) would leave 0777
        // directories behind (R81 F22).
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(dir);
    }
    let ifmt = if subsystem == "block" { S_IFBLK } else { S_IFCHR };
    let mode_bits = u32::from_str_radix(mode, 8).unwrap_or(0);
    let dev = libc_makedev(sys::atoi_u32(major), sys::atoi_u32(minor));
    if let Ok(c) = CString::new(path.as_str()) {
        // SAFETY: NUL-terminated path.
        unsafe { mknod(c.as_ptr().cast(), ifmt | mode_bits, dev) };
    }
    if let Some(group) = argv.get(2) {
        match crate::sys::lookup_group(group) {
            Some(gid) => {
                if !sys::chown_path(path, 0, gid) {
                    log!(sys::LOG_ERR, "cannot set group {group} for {path} (chown)");
                }
            }
            None => log!(sys::LOG_ERR, "cannot set group {group} for {path} (getgrnam)"),
        }
    }
    // SAFETY: restore.
    unsafe { umask(old) };
}

/// `handle_exec` in a forked child: env = the event variables, argv capped
/// at 7, stdio to /dev/null.
fn spawn_exec(cmd: &Queued) -> Option<i32> {
    let argv: Vec<&String> = cmd.argv.iter().take(7).collect();
    let first = argv.first()?;
    let mut c = Command::new(first);
    c.args(&argv[1..]);
    for (k, v) in &cmd.vars {
        c.env(k, v);
    }
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    crate::proc::inherit_ignored_sigpipe(&mut c);
    match c.spawn() {
        Ok(child) => {
            let pid = child.id() as i32;
            std::mem::forget(child);
            Some(pid)
        }
        Err(_) => None,
    }
}

/// `handle_firmware` in a forked child.
fn spawn_firmware(cmd: &Queued) -> Option<i32> {
    let dir = cmd.argv.first()?.clone();
    let vars = cmd.vars.clone();
    // SAFETY: the supervisor is single-threaded; the child owns its copied
    // state and exits after the firmware transfer, without returning to it.
    match unsafe { crate::proc::fork_raw() } {
        0 => {
            firmware_child(&dir, &vars);
            std::process::exit(1);
        }
        pid if pid > 0 => Some(pid),
        _ => None,
    }
}

fn firmware_child(dir: &str, vars: &BTreeMap<String, String>) {
    let (Some(file), Some(dev)) = (vars.get("FIRMWARE"), vars.get("DEVPATH")) else {
        log!(sys::LOG_ERR, "Request for unknown firmware");
        return;
    };
    let path = format!("{dir}/{file}");
    let data = std::fs::read(&path).unwrap_or_else(|e| {
        log!(sys::LOG_ERR, "Could not find firmware {path}: {e}");
        Vec::new()
    });
    let loading = format!("/sys/{dev}/loading");
    if std::fs::write(&loading, "1").is_err() {
        log!(sys::LOG_ERR, "Failed to write to {loading}");
        return;
    }
    let syspath = format!("/sys/{dev}/data");
    if !data.is_empty() {
        if let Err(e) = std::fs::write(&syspath, &data) {
            log!(
                sys::LOG_ERR,
                "failed to write firmware file {path} to {syspath}: {e}"
            );
        }
    }
    let _ = std::fs::write(&loading, "0");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uevent_datagram_becomes_exactly_the_kernels_variables() {
        let buf = b"add@/devices/platform/serial8250/tty/ttyS1\0ACTION=add\0DEVPATH=/devices/platform/serial8250/tty/ttyS1\0SUBSYSTEM=tty\0MAJOR=4\0MINOR=65\0";
        let v = parse_uevent(buf);
        assert_eq!(v.get("ACTION").map(String::as_str), Some("add"));
        assert_eq!(v.get("MAJOR").map(String::as_str), Some("4"));
        // R81 F22: the synthesized names must not leak into an exec's env or
        // a hotplug.<subsys> notification -- the rule engine answers them.
        assert!(!v.contains_key("DEVNAME"));
        assert!(!v.contains_key("DEVICENAME"));
        let rules = br#"[[ "if", [ "has", "DEVICENAME" ], [ "exec", "/bin/echo", "%DEVNAME%", "%DEVICENAME%" ] ]]"#;
        let blob = rules_blob(rules).unwrap();
        let block = Field { name: "", ty: MsgType::Array as u32, data: &blob };
        let out = jsonscript::run_hotplug_rule(block, &v);
        assert_eq!(out.commands, vec![("exec".to_string(), vec!["/bin/echo".into(), "ttyS1".into(), "ttyS1".into()])]);
    }

    #[test]
    fn an_explicit_devname_wins_over_the_fallback() {
        let buf = b"ACTION=add\0DEVPATH=/devices/x/y\0DEVNAME=bus/usb/001/002\0";
        let v = parse_uevent(buf);
        assert_eq!(v.get("DEVNAME").map(String::as_str), Some("bus/usb/001/002"));
        let rules = br#"[[ "exec", "%DEVNAME%", "%DEVICENAME%" ]]"#;
        let blob = rules_blob(rules).unwrap();
        let block = Field { name: "", ty: MsgType::Array as u32, data: &blob };
        let out = jsonscript::run_hotplug_rule(block, &v);
        assert_eq!(out.commands, vec![("exec".to_string(), vec!["bus/usb/001/002".into(), "y".into()])]);
    }

    #[test]
    fn the_device_rules_parse_and_route_a_tty_add() {
        // A trimmed hotplug.json shaped like the device's: tty adds get a
        // dialout makedev.
        let rules = r#"[
            [ "case", "ACTION", { "add": [
                [ "if", [ "regex", "DEVNAME", "^tty" ],
                    [ "makedev", "/dev/%DEVNAME%", "0660", "dialout" ] ]
            ] } ]
        ]"#;
        let dir = std::env::temp_dir().join(format!("hp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("rules.json");
        std::fs::write(&p, rules).unwrap();
        let blob = load_rules(p.to_str().unwrap()).expect("rules load");
        let mut vars = BTreeMap::new();
        vars.insert("ACTION".to_string(), "add".to_string());
        vars.insert("DEVPATH".to_string(), "/devices/platform/serial8250/tty/ttyS1".to_string());
        let block = Field { name: "", ty: MsgType::Array as u32, data: &blob };
        let out = jsonscript::run_hotplug_rule(block, &vars);
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert_eq!(
            out.commands,
            vec![(
                "makedev".to_string(),
                vec!["/dev/ttyS1".to_string(), "0660".to_string(), "dialout".to_string()]
            )]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn makedev_arithmetic_matches_the_libc_macro() {
        assert_eq!(libc_makedev(1, 3), 0x103);
        assert_eq!(libc_makedev(4, 65), 0x441);
        assert_eq!(libc_makedev(259, 0), (0x103u64) << 8);
    }
}
