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
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};

use crate::jsonscript;
use crate::sys;
use owrt_ubus::blob::{BlobBuf, Field, MsgType};

/// `HOTPLUG_WAIT`.
const QUIET_MS: i64 = 500;

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
    rule_file: String,
    included_rules: BTreeMap<String, Vec<u8>>,
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
pub(crate) fn load_rules(path: &str) -> Option<Vec<u8>> {
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
        let Ok(s) = std::str::from_utf8(seg) else {
            continue;
        };
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
        use rustix::net::netlink::{self, SocketAddrNetlink};
        use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
        let fd = match net::socket_with(
            AddressFamily::NETLINK,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            Some(netlink::KOBJECT_UEVENT),
        ) {
            Ok(fd) => fd,
            Err(_) => {
                log!(sys::LOG_ERR, "Failed to open hotplug socket");
                return None;
            }
        };
        if net::bind(&fd, &SocketAddrNetlink::new(0, u32::MAX)).is_err() {
            log!(sys::LOG_ERR, "Failed to bind hotplug socket");
            return None;
        }
        if net::sockopt::set_socket_recv_buffer_size_force(&fd, 512 * 1024).is_err() {
            log!(sys::LOG_ERR, "Failed to resize receive buffer");
        }
        Some(Hotplug {
            fd,
            rules,
            rule_file: rule_file.to_string(),
            included_rules: BTreeMap::new(),
            queue: VecDeque::new(),
            child: None,
            buttons: Vec::new(),
            coldplug: Coldplug::Idle,
            quiet_at: 0,
        })
    }

    /// `procd_coldplug()`.
    pub fn coldplug(&mut self, in_container: bool) {
        let old = rustix::process::umask(rustix::fs::Mode::empty());
        if !in_container {
            use rustix::mount::{MountFlags, UnmountFlags};
            let _ = rustix::mount::unmount("/dev/pts", UnmountFlags::DETACH);
            let _ = rustix::mount::unmount("/dev/", UnmountFlags::DETACH);
            let _ = rustix::mount::mount(
                "tmpfs",
                "/dev",
                "tmpfs",
                MountFlags::NOATIME | MountFlags::NOEXEC | MountFlags::NOSUID,
                Some(c"mode=0755,size=512K"),
            );
            let _ = rustix::fs::mknodat(
                rustix::fs::CWD,
                "/dev/null",
                rustix::fs::FileType::CharacterDevice,
                rustix::fs::Mode::from_raw_mode(0o666),
                rustix::fs::makedev(1, 3),
            );
            // mkdir("/dev/pts", 0755) runs under umask(0): the mode must be
            // explicit or it comes out 0777.
            let _ = std::fs::create_dir("/dev/pts");
            let _ = std::fs::set_permissions(
                "/dev/pts",
                std::os::unix::fs::PermissionsExt::from_mode(0o755),
            );
            let _ = rustix::mount::mount(
                "devpts",
                "/dev/pts",
                "devpts",
                MountFlags::NOATIME | MountFlags::NOEXEC | MountFlags::NOSUID,
                None,
            );
        }
        let _ = std::os::unix::fs::symlink("/tmp/shm", "/dev/shm");
        rustix::process::umask(old);

        let mut trigger = Command::new("udevtrigger");
        trigger.stdin(Stdio::null());
        crate::proc::inherit_ignored_sigpipe(&mut trigger);
        match trigger.spawn() {
            Ok(c) => {
                let pid = c.id() as i32;
                drop(c);
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
        let Some((cpid, _)) = &self.child else {
            return false;
        };
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

    /// # Safety
    /// Any queued firmware command must satisfy spawn_firmware's fork contract.
    #[expect(
        unsafe_code,
        reason = "propagate the firmware worker contract to the event owner"
    )]
    unsafe fn start_next(&mut self) {
        if self.child.is_some() {
            return;
        }
        let Some(cmd) = self.queue.pop_front() else {
            return;
        };
        // queue_next() calls handle_button_start when this command takes
        // the slot. The previous child may have armed a timeout after this
        // event was queued, so cancelling at enqueue time is too early.
        if cmd.kind == CmdKind::Button {
            if let Some(name) = cmd.vars.get("BUTTON") {
                self.buttons.retain(|b| &b.name != name);
            }
        }
        match cmd.kind {
            // pump() intercepts StartConsole before this point; it never
            // reaches the fork path.
            CmdKind::StartConsole => {}
            CmdKind::Firmware => {
                #[expect(
                    unsafe_code,
                    reason = "the pump caller owns the firmware fork prerequisite"
                )]
                // SAFETY: start_next inherits this queued firmware prerequisite from pump.
                let pid = unsafe { spawn_firmware(&cmd) };
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

    /// Nothing here needs a timer tick: no queued command, no running child,
    /// no armed button timeout and coldplug not waiting on its quiet period.
    /// New uevents still arrive through the socket in the loop's poll set.
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty()
            && self.child.is_none()
            && self.buttons.is_empty()
            && matches!(self.coldplug, Coldplug::Idle | Coldplug::Done)
    }

    /// Drain the socket, run rules, fire button timeouts, start queue work.
    /// Returns whether a `start-console` command asked for the inittab
    /// console handlers, and the events received (for `hotplug_ubus_event`'s
    /// per-subsystem notification).
    ///
    /// # Safety
    /// If rules or queued work can run a firmware command, the process must
    /// have one thread and hold no application locks across its fork. A closed
    /// fixture with no event input and only Exec/Button work needs no such fork.
    #[expect(
        unsafe_code,
        reason = "the event owner must establish firmware worker prerequisites"
    )]
    pub unsafe fn pump(&mut self, now: i64) -> (bool, Vec<BTreeMap<String, String>>) {
        let mut console_request = false;
        let mut events = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok((_, n)) =
            rustix::net::recv(&self.fd, &mut buf[..4095], rustix::net::RecvFlags::DONTWAIT)
        {
            if n < 1 {
                break;
            }
            let vars = parse_uevent(&buf[..n]);
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
            self.queue.push_back(Queued {
                kind: CmdKind::Exec,
                vars,
                argv: b.argv,
            });
            self.touch_quiet(now);
        }
        // start-console entries are answered in the caller's context.
        while self.child.is_none() {
            if matches!(
                self.queue.front().map(|c| c.kind),
                Some(CmdKind::StartConsole)
            ) {
                self.queue.pop_front();
                console_request = true;
                continue;
            }
            let before = self.queue.len();
            #[expect(
                unsafe_code,
                reason = "propagate the event owner's firmware fork contract"
            )]
            // SAFETY: pump's caller establishes the prerequisite for any firmware work.
            unsafe {
                self.start_next()
            };
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
            let block = Field {
                name: "",
                ty: MsgType::Array as u32,
                data: &rules,
            };
            let out = jsonscript::run_hotplug_rule(
                block,
                vars,
                &self.rule_file,
                &mut self.included_rules,
            );
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

    fn dispatch(
        &mut self,
        name: &str,
        argv: Vec<String>,
        vars: &BTreeMap<String, String>,
        now: i64,
    ) {
        match name {
            // Atomic: in-process, in order.
            "makedev" => handle_makedev(&argv, vars),
            "rm" => {
                if let Some(p) = argv.first() {
                    let _ = std::fs::remove_file(p);
                }
            }
            "exec" => self.queue.push_back(Queued {
                kind: CmdKind::Exec,
                vars: vars.clone(),
                argv,
            }),
            "button" => {
                self.queue.push_back(Queued {
                    kind: CmdKind::Button,
                    vars: vars.clone(),
                    argv,
                });
            }
            "load-firmware" => self.queue.push_back(Queued {
                kind: CmdKind::Firmware,
                vars: vars.clone(),
                argv,
            }),
            "start-console" => self.queue.push_back(Queued {
                kind: CmdKind::StartConsole,
                vars: vars.clone(),
                argv,
            }),
            _ => return,
        }
        self.touch_quiet(now);
    }
}

fn libc_makedev(major: u32, minor: u32) -> u64 {
    rustix::fs::makedev(major, minor)
}

/// `handle_makedev`: /dev node under umask 0, block vs char by SUBSYSTEM,
/// optional group as the third argument.
fn handle_makedev(argv: &[String], vars: &BTreeMap<String, String>) {
    let (Some(path), Some(mode)) = (argv.first(), argv.get(1)) else {
        return;
    };
    let (Some(minor), Some(major), Some(subsystem)) =
        (vars.get("MINOR"), vars.get("MAJOR"), vars.get("SUBSYSTEM"))
    else {
        return;
    };
    let old = rustix::process::umask(rustix::fs::Mode::empty());
    if let Some(dir) = std::path::Path::new(path).parent() {
        // mkdir_p(d, 0755): create_dir_all under umask(0) would leave 0777
        // directories behind (R81 F22).
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(dir);
    }
    let kind = if subsystem == "block" {
        rustix::fs::FileType::BlockDevice
    } else {
        rustix::fs::FileType::CharacterDevice
    };
    let mode_bits = u32::from_str_radix(mode, 8).unwrap_or(0);
    let dev = libc_makedev(sys::atoi_u32(major), sys::atoi_u32(minor));
    if let Ok(c) = CString::new(path.as_str()) {
        let _ = rustix::fs::mknodat(
            rustix::fs::CWD,
            &c,
            kind,
            rustix::fs::Mode::from_bits_retain(mode_bits),
            dev,
        );
    }
    if let Some(group) = argv.get(2) {
        match crate::sys::lookup_group(group) {
            Some(gid) => {
                if !sys::chown_path(path, 0, gid) {
                    log!(sys::LOG_ERR, "cannot set group {group} for {path} (chown)");
                }
            }
            None => log!(
                sys::LOG_ERR,
                "cannot set group {group} for {path} (getgrnam)"
            ),
        }
    }
    rustix::process::umask(old);
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
    c.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    crate::proc::inherit_ignored_sigpipe(&mut c);
    match c.spawn() {
        Ok(child) => {
            let pid = child.id() as i32;
            drop(child);
            Some(pid)
        }
        Err(_) => None,
    }
}

/// `handle_firmware` in a forked child.
/// # Safety
/// The process must have one thread and hold no application locks at fork.
#[expect(
    unsafe_code,
    reason = "preserve the platform firmware fork prerequisite"
)]
unsafe fn spawn_firmware(cmd: &Queued) -> Option<i32> {
    let dir = cmd.argv.first()?.clone();
    let vars = cmd.vars.clone();
    // Owned event data only; the fixed firmware child never returns into
    // the supervisor. Preserve the existing fork and exit(1) behavior.
    fn transfer((dir, vars): (String, BTreeMap<String, String>)) {
        firmware_child(&dir, &vars);
    }
    #[expect(
        unsafe_code,
        reason = "fixed firmware worker in the single-threaded supervisor"
    )]
    // SAFETY: the hotplug supervisor has one thread. The child owns the
    // cloned strings/map, runs this fixed transfer, and exits without returning
    // into the parent's event loop; no parent lock or borrowed data is captured.
    unsafe {
        owrt_platform::procd::process::spawn_firmware((dir, vars), transfer)
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
    fn queued_button_release_cancels_timeout_created_by_previous_child() {
        let dir = std::env::temp_dir().join(format!("procd-button-order-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let trace = dir.join("actions");
        let mut hp = Hotplug {
            fd: std::fs::File::open("/dev/null").unwrap().into(),
            rules: Vec::new(),
            rule_file: String::new(),
            included_rules: BTreeMap::new(),
            queue: VecDeque::new(),
            child: None,
            buttons: Vec::new(),
            coldplug: Coldplug::Idle,
            quiet_at: 0,
        };
        let argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo \"$ACTION\" >> \"$TRACE\"; [ \"$ACTION\" != pressed ]".into(),
        ];
        let mut vars = BTreeMap::from([
            ("BUTTON".into(), "reset".into()),
            ("ACTION".into(), "pressed".into()),
            ("TRACE".into(), trace.to_str().unwrap().into()),
        ]);
        hp.dispatch("button", argv.clone(), &vars, 100);

        #[expect(
            unsafe_code,
            reason = "closed button fixture cannot enqueue a firmware fork"
        )]
        // SAFETY: fd is /dev/null (recv always fails), rules are empty, and this
        // fixture enqueues only Button/Exec commands, never Firmware.
        unsafe {
            hp.pump(100);
        };
        assert!(hp.child.is_some(), "press handler must have started");

        // Release arrives before the press child has been reaped. The press
        // handler will return 1 and arm a one-second timeout on completion.
        vars.insert("ACTION".into(), "released".into());
        hp.dispatch("button", argv, &vars, 100);
        fn reap(hp: &mut Hotplug) {
            let raw = hp.child.as_ref().unwrap().0;
            let pid = rustix::process::Pid::from_raw(raw).unwrap();
            let (_, status) =
                rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
                    .unwrap()
                    .unwrap();
            assert!(hp.reaped(raw, status.as_raw()));
        }
        reap(&mut hp);
        assert_eq!(hp.buttons.len(), 1, "press completion must arm the timeout");

        #[expect(
            unsafe_code,
            reason = "closed button fixture cannot enqueue a firmware fork"
        )]
        // SAFETY: fd is /dev/null (recv always fails), rules are empty, and this
        // fixture enqueues only Button/Exec commands, never Firmware.
        unsafe {
            hp.pump(100);
        };
        reap(&mut hp);

        #[expect(
            unsafe_code,
            reason = "closed button fixture cannot enqueue a firmware fork"
        )]
        // SAFETY: fd is /dev/null (recv always fails), rules are empty, and this
        // fixture enqueues only Button/Exec commands, never Firmware.
        unsafe {
            hp.pump(1200);
        };
        let stale_timeout = hp.child.is_some();
        if stale_timeout {
            reap(&mut hp);
        }
        let actions = std::fs::read_to_string(&trace).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert!(
            !stale_timeout,
            "released button must not run a stale timeout handler"
        );
        assert_eq!(actions, "pressed\nreleased\n");
    }

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
        let block = Field {
            name: "",
            ty: MsgType::Array as u32,
            data: &blob,
        };
        let out = jsonscript::run_hotplug_rule(block, &v, "", &mut BTreeMap::new());
        assert_eq!(
            out.commands,
            vec![(
                "exec".to_string(),
                vec!["/bin/echo".into(), "ttyS1".into(), "ttyS1".into()]
            )]
        );
    }

    #[test]
    fn an_explicit_devname_wins_over_the_fallback() {
        let buf = b"ACTION=add\0DEVPATH=/devices/x/y\0DEVNAME=bus/usb/001/002\0";
        let v = parse_uevent(buf);
        assert_eq!(
            v.get("DEVNAME").map(String::as_str),
            Some("bus/usb/001/002")
        );
        let rules = br#"[[ "exec", "%DEVNAME%", "%DEVICENAME%" ]]"#;
        let blob = rules_blob(rules).unwrap();
        let block = Field {
            name: "",
            ty: MsgType::Array as u32,
            data: &blob,
        };
        let out = jsonscript::run_hotplug_rule(block, &v, "", &mut BTreeMap::new());
        assert_eq!(
            out.commands,
            vec![(
                "exec".to_string(),
                vec!["bus/usb/001/002".into(), "y".into()]
            )]
        );
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
        vars.insert(
            "DEVPATH".to_string(),
            "/devices/platform/serial8250/tty/ttyS1".to_string(),
        );
        let block = Field {
            name: "",
            ty: MsgType::Array as u32,
            data: &blob,
        };
        let out = jsonscript::run_hotplug_rule(block, &vars, "", &mut BTreeMap::new());
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert_eq!(
            out.commands,
            vec![(
                "makedev".to_string(),
                vec![
                    "/dev/ttyS1".to_string(),
                    "0660".to_string(),
                    "dialout".to_string()
                ]
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
