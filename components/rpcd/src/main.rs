//! rpcd-rs: the rpcd core objects (`session`, `uci`, `rc`; contract C7) and the
//! plugin-layer objects (`file`, `luci`; contract C5) as one ubus object server.
//! Runtime state lives under /var/run/rpcd-rs (decision 0013).

mod file;
mod glob;
mod ip;
mod iwinfo;
mod iwinfoobj;
mod luci;
mod procwait;
mod lucirpc;
mod rc;
mod rpcsys;
mod rrdns;
mod rtnl;
mod session;
mod uciobj;
mod util;

use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::Json;
use owrt_ubus::sys::{self, PollFd, POLLIN};
use owrt_ubus::{status, Connection, Incoming, MsgType, Request};
use std::cell::RefCell;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Instant;

pub struct Ctx {
    pub socket: Option<String>,
    pub exec_timeout_ms: i32,
    pub sessions: RefCell<session::Store>,
    pub apply: RefCell<uciobj::Apply>,
}

impl Ctx {
    /// `ops->session_access(sid, "file", path, perm)`, now in-process. No
    /// session id means a local root caller.
    pub fn file_access(&self, sid: Option<&str>, path: &str, perm: &str) -> bool {
        let Some(sid) = sid else { return true };
        self.sessions.borrow_mut().access(sid, "file", path, perm)
    }

    /// Plain ubus call helper for the luci methods.
    pub fn ubus_call(&self, object: &str, method: &str, args: Option<&Json>) -> Option<Json> {
        let mut conn = Connection::connect(self.socket.as_deref()).ok()?;
        let id = conn.lookup_id(object, 3000).ok()?;
        let payload = args.map(object_to_payload).unwrap_or_default();
        let reply = conn.invoke_status(id, method, &payload, 30000).ok()?;
        if reply.status != 0 {
            return None;
        }
        Some(fields_to_json(&reply.fields()))
    }
}

/// A finished deferred request coming back from a worker thread.
pub struct Done {
    pub req: Request,
    pub reply: session::Reply,
}

#[derive(Clone)]
pub struct Deferrer {
    tx: Sender<Done>,
    wake: RawFd,
}

impl Deferrer {
    pub fn finish(&self, req: Request, reply: session::Reply) {
        let _ = self.tx.send(Done { req, reply });
        wake(self.wake);
    }
}

extern "C" {
    fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    fn read(fd: i32, buf: *mut u8, n: usize) -> isize;
    fn umask(mask: u32) -> u32;
}

static SIGNAL: AtomicI32 = AtomicI32::new(0);
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
const SIGHUP: i32 = 1;
const SIGUSR1: i32 = 10;

fn wake(fd: RawFd) {
    let b = [1u8];
    // SAFETY: plain write(2) of one byte to our own pipe; async-signal-safe.
    unsafe {
        write(fd, b.as_ptr(), 1);
    }
}

extern "C" fn handle_signal(sig: i32) {
    SIGNAL.store(sig, Ordering::SeqCst);
    let fd = WAKE_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        wake(fd);
    }
}

fn drain(fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: non-blocking read into a local buffer.
        let n = unsafe { read(fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

struct Ids {
    session: u32,
    uci: u32,
    rc: u32,
    file: u32,
    luci: u32,
    sys: u32,
    rrdns: u32,
    /// luci-rpc; OWRT_RPCD_LUCI_RPC_NAME overrides the object name so the r19
    /// harness can run it next to the C plugin in one sandbox.
    lucirpc: u32,
    iwinfo: u32,
}

fn register(conn: &mut Connection, name: &str, methods: &[(&'static str, Vec<(&'static str, MsgType)>)]) -> u32 {
    let refs: Vec<(&str, &[(&str, MsgType)])> = methods.iter().map(|(n, p)| (*n, p.as_slice())).collect();
    conn.add_object(name, &refs, 5000).unwrap_or_else(|e| {
        eprintln!("Failed to register object '{name}': {e}");
        std::process::exit(1);
    })
}

fn reply(conn: &mut Connection, req: &Request, r: session::Reply) {
    for d in &r.data {
        let _ = conn.reply_data(req, d);
    }
    let _ = conn.reply_status(req, r.code, None);
}

fn dispatch(ctx: &Ctx, conn: &mut Connection, ids: &Ids, req: Request, deferrer: &Deferrer) {
    if req.objid == ids.session {
        let r = session::call(&mut ctx.sessions.borrow_mut(), &req.method, &req.data);
        reply(conn, &req, r);
    } else if req.objid == ids.uci {
        let r = uciobj::call(ctx, conn, &req.method, &req.data);
        reply(conn, &req, r);
    } else if req.objid == ids.rc {
        if let rc::Outcome::Now(req, r) = rc::call(req, deferrer) {
            reply(conn, &req, r);
        }
    } else if req.objid == ids.sys {
        if let rpcsys::Outcome::Now(req, r) = rpcsys::call(req, ctx.exec_timeout_ms, deferrer) {
            reply(conn, &req, r);
        }
    } else if req.objid == ids.rrdns {
        if let rrdns::Outcome::Now(req, r) = rrdns::call(req, deferrer) {
            reply(conn, &req, r);
        }
    } else if req.objid == ids.lucirpc {
        if let lucirpc::Outcome::Now(req, r) = lucirpc::call(ctx, req, deferrer) {
            reply(conn, &req, r);
        }
    } else if req.objid == ids.iwinfo {
        let r = iwinfoobj::call(&req.method, &req.data);
        reply(conn, &req, r);
    } else if req.objid == ids.file || req.objid == ids.luci {
        let result = if req.objid == ids.file {
            let args = fields_to_json(&req.data);
            file::call(ctx, &req.method, &args)
        } else {
            luci::call(ctx, &req.method, &req.data)
        };
        let r = match result {
            Ok(Some(data)) => session::Reply { code: status::OK, data: vec![object_to_payload(&data)] },
            Ok(None) => session::Reply { code: status::OK, data: vec![] },
            Err(code) => session::Reply { code, data: vec![] },
        };
        reply(conn, &req, r);
    } else {
        let _ = conn.reply_status(&req, status::NOT_FOUND, None);
    }
}

/// exec_self: re-run with the same arguments and RPC_HANGUP=1.
fn exec_self() {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().unwrap_or_else(|_| std::env::args_os().next().unwrap_or_default().into());
    let err = std::process::Command::new(exe).args(std::env::args_os().skip(1)).env("RPC_HANGUP", "1").exec();
    eprintln!("respawn failed: {err}");
}

fn main() {
    // getopt "s:t:" (musl: no argument permutation)
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--iwinfo-bench") {
        // profiling aid: time every `info` op for one interface and count netlink sends
        let Some(dev) = argv.get(1) else {
            eprintln!("usage: rpcd-rs --iwinfo-bench <ifname>");
            std::process::exit(2);
        };
        iwinfoobj::bench(dev);
        return;
    }
    let mut socket = None;
    let mut exec_timeout: i64 = 120_000;
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if !a.starts_with('-') || a == "-" {
            break;
        }
        if a == "--" {
            break;
        }
        let opt = a.as_bytes()[1];
        let val = if a.len() > 2 { Some(a[2..].to_owned()) } else { i += 1; argv.get(i).cloned() };
        match (opt, val) {
            (b's', Some(v)) => socket = Some(v),
            (b't', Some(v)) => {
                let t = strtol0(&v);
                exec_timeout = if t > 0 && t <= 600 { t * 1000 } else { -1 };
            }
            _ => {}
        }
        i += 1;
    }
    if !(1000..=600_000).contains(&exec_timeout) {
        eprintln!("Invalid execution timeout specified");
        std::process::exit(255);
    }
    if std::fs::metadata(session::RUN_DIR).is_err() {
        let _ = std::fs::DirBuilder::new().mode(0o700).create(session::RUN_DIR);
    }
    // SAFETY: umask(2) has no preconditions.
    unsafe {
        umask(0o077);
    }
    sys::ignore_signal(sys::SIGPIPE);
    let (pipe_r, pipe_w) = sys::pipe().unwrap_or_else(|e| {
        eprintln!("pipe: {e}");
        std::process::exit(1);
    });
    let _ = sys::set_nonblocking(pipe_r.as_raw_fd());
    WAKE_FD.store(pipe_w.as_raw_fd(), Ordering::SeqCst);
    sys::set_signal_handler(SIGHUP, handle_signal);
    sys::set_signal_handler(SIGUSR1, handle_signal);

    let mut conn = match Connection::connect(socket.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to ubus: {e}");
            std::process::exit(255);
        }
    };
    let ctx = Ctx {
        socket: socket.clone(),
        exec_timeout_ms: exec_timeout as i32,
        sessions: RefCell::new(session::Store::new()),
        apply: RefCell::new(uciobj::Apply::default()),
    };
    let ids = Ids {
        session: register(&mut conn, "session", &session::signature()),
        uci: register(&mut conn, "uci", &uciobj::signature()),
        rc: register(&mut conn, "rc", &rc::signature()),
        file: register(&mut conn, "file", &file::signature()),
        luci: register(&mut conn, "luci", &luci::signature()),
        sys: register(&mut conn, "rpc-sys", &rpcsys::signature()),
        rrdns: register(&mut conn, "network.rrdns", &rrdns::signature()),
        lucirpc: {
            let name = std::env::var("OWRT_RPCD_LUCI_RPC_NAME").unwrap_or_else(|_| "luci-rpc".to_owned());
            register(&mut conn, &name, &lucirpc::signature())
        },
        iwinfo: register(&mut conn, "iwinfo", &iwinfoobj::signature()),
    };
    if std::env::var("RPC_HANGUP").ok().as_deref() != Some("1") {
        uciobj::purge_savedirs();
    } else {
        ctx.sessions.borrow_mut().thaw();
    }

    let (tx, rx): (Sender<Done>, Receiver<Done>) = mpsc::channel();
    let deferrer = Deferrer { tx, wake: pipe_w.as_raw_fd() };
    let ubus_fd = conn.as_raw_fd();
    loop {
        // timers
        ctx.sessions.borrow_mut().expire();
        let apply_due = ctx.apply.borrow().deadline.is_some_and(|d| d <= Instant::now());
        if apply_due {
            uciobj::apply_timeout(&ctx, &mut conn);
        }
        // completed deferred requests
        while let Ok(done) = rx.try_recv() {
            reply(&mut conn, &done.req, done.reply);
        }
        // signals: freeze sessions, then respawn (SIGHUP) or exit (SIGUSR1)
        let sig = SIGNAL.swap(0, Ordering::SeqCst);
        if sig != 0 {
            ctx.sessions.borrow().freeze();
            drop(conn);
            if sig == SIGHUP {
                exec_self();
            }
            std::process::exit(0);
        }
        // next timer
        let now = Instant::now();
        let mut timeout: i32 = -1;
        let deadlines = [ctx.sessions.borrow().next_expiry(), ctx.apply.borrow().deadline];
        for d in deadlines.into_iter().flatten() {
            let ms = if d <= now { 0 } else { (d - now).as_micros().div_ceil(1000).min(i32::MAX as u128) as i32 };
            timeout = if timeout < 0 { ms } else { timeout.min(ms) };
        }
        if conn.has_pending() {
            timeout = 0;
        }
        let mut fds = [
            PollFd { fd: ubus_fd, events: POLLIN, revents: 0 },
            PollFd { fd: pipe_r.as_raw_fd(), events: POLLIN, revents: 0 },
        ];
        if sys::poll_fds(&mut fds, timeout).is_err() {
            continue;
        }
        if fds[1].revents != 0 {
            drain(pipe_r.as_raw_fd());
        }
        if fds[0].revents != 0 || conn.has_pending() {
            match conn.read_incoming() {
                Ok(Incoming::Invoke(req)) => dispatch(&ctx, &mut conn, &ids, req, &deferrer),
                Ok(_) => {}
                Err(e) => {
                    eprintln!("ubus connection lost: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// strtol(s, NULL, 0) for the -t option.
fn strtol0(s: &str) -> i64 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut base = 10i64;
    if i + 1 < b.len() && b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X') {
        base = 16;
        i += 2;
    } else if i < b.len() && b[i] == b'0' {
        base = 8;
    }
    let mut v: i64 = 0;
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => (c - b'0') as i64,
            c @ b'a'..=b'f' => (c - b'a') as i64 + 10,
            c @ b'A'..=b'F' => (c - b'A') as i64 + 10,
            _ => break,
        };
        if d >= base {
            break;
        }
        v = v.saturating_mul(base).saturating_add(d);
        i += 1;
    }
    if neg { -v } else { v }
}
