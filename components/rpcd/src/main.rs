//! rpcd-rs: the rpcd core objects (`session`, `uci`, `rc`; contract C7) and the
//! plugin-layer objects (`file`, `luci`; contract C5) as one ubus object server.
//! Runtime state lives under /var/run/rpcd-rs (decision 0013).

#![forbid(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

mod delayed;
mod file;
mod glob;
mod ip;
mod iwinfo;
mod iwinfoobj;
mod luci;
mod lucirpc;
mod procwait;
mod rc;
mod readiness;
mod reply;
mod rpcsys;
mod rrdns;
mod rtnl;
mod session;
mod uciobj;
mod util;

use owrt_platform::rpcd_signals;
use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::Json;
use owrt_ubus::sys;
use owrt_ubus::{status, Connection, Incoming, MsgType, Request};
use std::cell::RefCell;
use std::os::fd::RawFd;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

pub struct Ctx {
    pub socket: Option<String>,
    pub exec_timeout_ms: i32,
    pub sessions: RefCell<session::Store>,
    pub apply: RefCell<uciobj::Apply>,
    pub delayed: RefCell<delayed::Children>,
    pub uci_read_cache: RefCell<owrt_uci::ReadCache>,
}

impl Ctx {
    /// `ops->session_access(sid, "file", path, perm)`, now in-process. No
    /// session id means a local root caller.
    pub fn file_access(&self, sid: Option<&str>, path: &str, perm: &str) -> bool {
        self.file_access_bytes(sid, path.as_bytes(), perm)
    }

    pub fn file_access_bytes(&self, sid: Option<&str>, path: &[u8], perm: &str) -> bool {
        let Some(sid) = sid else { return true };
        self.sessions
            .borrow_mut()
            .access_bytes(sid, "file", path, perm)
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
        fields_to_json(&reply.fields()).ok()
    }
}

/// Global cap on concurrently deferred worker threads and unconsumed `Done`
/// replies across `serve()` reconnects.
pub const MAX_DEFERRED_IN_FLIGHT: usize = 32;

static DEFERRED_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

struct InFlightPermit(&'static AtomicUsize);

impl InFlightPermit {
    fn acquire(counter: &'static AtomicUsize, limit: usize) -> Option<Self> {
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if current >= limit {
                return None;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self(counter)),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// A finished deferred request coming back from a worker thread.
pub struct Done {
    pub req: Request,
    pub reply: session::Reply,
    _permit: Option<InFlightPermit>,
}

#[derive(Clone)]
pub struct Deferrer {
    tx: Sender<Done>,
    in_flight: &'static AtomicUsize,
    limit: usize,
}

impl Deferrer {
    fn channel() -> (Self, Receiver<Done>) {
        Self::channel_with(&DEFERRED_IN_FLIGHT, MAX_DEFERRED_IN_FLIGHT)
    }

    fn channel_with(in_flight: &'static AtomicUsize, limit: usize) -> (Self, Receiver<Done>) {
        let (tx, rx) = mpsc::channel();
        (
            Self {
                tx,
                in_flight,
                limit,
            },
            rx,
        )
    }

    pub fn finish(&self, req: Request, reply: session::Reply) {
        self.finish_with_permit(req, reply, None);
    }

    fn finish_with_permit(
        &self,
        req: Request,
        reply: session::Reply,
        permit: Option<InFlightPermit>,
    ) {
        if self
            .tx
            .send(Done {
                req,
                reply,
                _permit: permit,
            })
            .is_ok()
        {
            rpcd_signals::wake();
        }
    }

    /// Run `work` on a worker thread and finish `req` with its reply; None
    /// means the request is now deferred. When the global in-flight cap is
    /// saturated or the thread cannot be created, the request comes back with
    /// an UNKNOWN_ERROR reply to answer at once, as the C answers a failed
    /// fork with rpc_errno_status(); the release profile is panic=abort, so an
    /// unchecked spawn would have taken the daemon down instead (R88 rpcd F1).
    pub fn defer<F>(&self, req: Request, work: F) -> Option<(Request, session::Reply)>
    where
        F: FnOnce() -> session::Reply + Send + 'static,
    {
        self.defer_with(req, work, |task| {
            std::thread::Builder::new().spawn(task).map(|_| ())
        })
    }

    fn defer_with<F, S>(&self, req: Request, work: F, spawn: S) -> Option<(Request, session::Reply)>
    where
        F: FnOnce() -> session::Reply + Send + 'static,
        S: FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
    {
        let Some(permit) = InFlightPermit::acquire(self.in_flight, self.limit) else {
            return Some((req, session::Reply::empty(owrt_ubus::status::UNKNOWN_ERROR)));
        };
        let slot = std::sync::Arc::new(std::sync::Mutex::new(Some((req, permit))));
        let taken = std::sync::Arc::clone(&slot);
        let d = self.clone();
        let spawned = spawn(Box::new(move || {
            let entry = taken
                .lock()
                .expect("shared daemon state poisoned by a panic")
                .take();
            if let Some((req, permit)) = entry {
                let reply = work();
                d.finish_with_permit(req, reply, Some(permit));
            }
        }));
        match spawned {
            Ok(()) => None,
            Err(error) => {
                eprintln!("rpcd-rs: cannot create worker thread: {error}");
                let (req, permit) = slot
                    .lock()
                    .expect("shared daemon state poisoned by a panic")
                    .take()
                    .expect("unstarted worker keeps its request");
                drop(permit);
                Some((req, session::Reply::empty(owrt_ubus::status::UNKNOWN_ERROR)))
            }
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

fn register(
    conn: &mut Connection,
    name: &str,
    methods: &[(&'static str, Vec<(&'static str, MsgType)>)],
) -> std::io::Result<u32> {
    let refs: Vec<(&str, &[(&str, MsgType)])> =
        methods.iter().map(|(n, p)| (*n, p.as_slice())).collect();
    conn.add_object(name, &refs, 1000)
}

/// Pack a plugin-object method result into a ubus reply.
pub fn to_reply(result: Result<Option<Json>, i32>) -> session::Reply {
    match result {
        Ok(Some(data)) => session::Reply::one(status::OK, object_to_payload(&data)),
        Ok(None) => session::Reply::empty(status::OK),
        Err(code) => session::Reply::empty(code),
    }
}

fn reply(conn: &mut Connection, req: Request, r: session::Reply) {
    if let Some(data) = r.data.single() {
        let _ = conn.reply_data_status(&req, data, r.code);
        conn.recycle_request(req);
        return;
    }
    for d in r.data.iter() {
        let _ = conn.reply_data(&req, d);
    }
    let _ = conn.reply_status(&req, r.code, None);
    conn.recycle_request(req);
}

fn dispatch(ctx: &Ctx, conn: &mut Connection, ids: &Ids, req: Request, deferrer: &Deferrer) {
    if req.objid == ids.session {
        let r = session::call(&mut ctx.sessions.borrow_mut(), &req.method, &req.data);
        reply(conn, req, r);
    } else if req.objid == ids.uci {
        let r = uciobj::call(ctx, conn, &req.method, &req.data);
        reply(conn, req, r);
    } else if req.objid == ids.rc {
        if let rc::Outcome::Now(req, r) = rc::call(req, deferrer) {
            reply(conn, req, r);
        }
    } else if req.objid == ids.sys {
        if let rpcsys::Outcome::Now(req, r) = rpcsys::call(req, ctx, deferrer) {
            reply(conn, req, r);
        }
    } else if req.objid == ids.rrdns {
        if let rrdns::Outcome::Now(req, r) = rrdns::call(req, deferrer) {
            reply(conn, req, r);
        }
    } else if req.objid == ids.lucirpc {
        if let lucirpc::Outcome::Now(req, r) = lucirpc::call(ctx, req, deferrer) {
            reply(conn, req, r);
        }
    } else if req.objid == ids.iwinfo {
        let r = iwinfoobj::call(&req.method, &req.data);
        reply(conn, req, r);
    } else if req.objid == ids.file {
        if let file::Outcome::Now(req, r) = file::call(ctx, req, deferrer) {
            reply(conn, req, r);
        }
    } else if req.objid == ids.luci {
        // The C `luci` object is a ucode script that rpcd runs inside its own
        // VM: rpc_ucode_script_call defers the request but then invokes the
        // handler synchronously, and the handler's popen()/system() calls
        // block the uloop for their whole duration. Staying on the loop here
        // is what matches it.
        let r = to_reply(luci::call(ctx, &req.method, &req.data));
        reply(conn, req, r);
    } else {
        let _ = conn.reply_status(&req, status::NOT_FOUND, None);
    }
}

/// exec_self: re-run with the same arguments and RPC_HANGUP=1.
fn exec_self(children: &delayed::Children) {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::env::args_os().next().unwrap_or_default().into());
    let err = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env("RPC_HANGUP", "1")
        .env(delayed::REEXEC_ENV, children.reexec_pids())
        .exec();
    eprintln!("respawn failed: {err}");
}

/// Parse getopt "s:t:" without argument permutation, as on musl.
fn command_options(argv: &[String]) -> (Option<String>, i64) {
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
        let val = if a.len() > 2 {
            // An unknown non-ASCII option can put byte 2 inside a character.
            // Its value is ignored below; known ASCII options keep it intact.
            a.get(2..).map(str::to_owned)
        } else {
            i += 1;
            argv.get(i).cloned()
        };
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
    (socket, exec_timeout)
}

fn main() {
    use std::io::Write;
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--iwinfo-bench") {
        // profiling aid: time every `info` op for one interface and count netlink sends
        let Some(dev) = argv.get(1) else {
            let _ = writeln!(std::io::stderr(), "usage: rpcd-rs --iwinfo-bench <ifname>");
            std::process::exit(2);
        };
        iwinfoobj::bench(dev);
        return;
    }
    let (socket, exec_timeout) = command_options(&argv);
    if !(1000..=600_000).contains(&exec_timeout) {
        let _ = writeln!(std::io::stderr(), "Invalid execution timeout specified");
        std::process::exit(255);
    }
    if std::fs::metadata(session::RUN_DIR).is_err() {
        let _ = std::fs::DirBuilder::new()
            .mode(0o700)
            .create(session::RUN_DIR);
    }
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    sys::ignore_signal(sys::SIGPIPE);
    let wake_reader = rpcd_signals::install().unwrap_or_else(|e| {
        eprintln!("pipe: {e}");
        std::process::exit(1);
    });

    let mut conn = match Connection::connect(socket.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to ubus: {e}");
            std::process::exit(255);
        }
    };
    conn.set_server_io_timeout(Duration::from_secs(1));
    let ctx = Ctx {
        socket: socket.clone(),
        exec_timeout_ms: exec_timeout as i32,
        sessions: RefCell::new(session::Store::new()),
        apply: RefCell::new(uciobj::Apply::default()),
        delayed: RefCell::new(delayed::Children::inherit().unwrap_or_else(|error| {
            eprintln!("Failed to restore delayed child state: {error}");
            std::process::exit(1);
        })),
        uci_read_cache: RefCell::new(owrt_uci::ReadCache::default()),
    };
    let mut ids = register_objects(&ctx, &mut conn).unwrap_or_else(|error| {
        eprintln!("Failed to register rpcd objects: {error}");
        std::process::exit(1);
    });
    if std::env::var("RPC_HANGUP").ok().as_deref() != Some("1") {
        uciobj::purge_savedirs();
    } else {
        ctx.sessions.borrow_mut().thaw();
    }

    loop {
        if let Err(error) = serve(&ctx, &mut conn, &ids, wake_reader) {
            eprintln!("ubus connection lost: {error}");
        }
        // A deferred worker may still be running, but serve() has dropped its
        // completion receiver. It cannot send an old peer/sequence on a new bus.
        let _ = conn.shutdown();
        drop(conn);
        (conn, ids) = reconnect(&ctx, wake_reader);
    }
}

fn maintain(ctx: &Ctx) {
    ctx.delayed.borrow_mut().reap();
    ctx.sessions.borrow_mut().expire();
    let due = ctx
        .apply
        .borrow()
        .deadline
        .is_some_and(|at| at <= Instant::now());
    if due {
        uciobj::apply_timeout(ctx);
    }
}

fn check_signal(ctx: &Ctx, conn: Option<&Connection>) {
    let Some(action) = rpcd_signals::take_action() else {
        return;
    };
    ctx.sessions.borrow().freeze();
    if let Some(conn) = conn {
        let _ = conn.shutdown();
    }
    if action == rpcd_signals::Action::Hangup {
        exec_self(&ctx.delayed.borrow());
    }
    std::process::exit(0);
}

fn reconnect(ctx: &Ctx, read_fd: RawFd) -> (Connection, Ids) {
    let mut retry_at = Instant::now() + Duration::from_secs(1);
    loop {
        maintain(ctx);
        check_signal(ctx, None);
        if Instant::now() >= retry_at {
            if let Ok(mut conn) = Connection::connect(ctx.socket.as_deref()) {
                conn.set_server_io_timeout(Duration::from_secs(1));
                match register_objects(ctx, &mut conn) {
                    Ok(ids) => return (conn, ids),
                    Err(error) => {
                        eprintln!("rpcd object re-registration failed: {error}");
                        let _ = conn.shutdown();
                    }
                }
            }
            retry_at = Instant::now() + Duration::from_secs(1);
            continue;
        }
        let next = [
            Some(retry_at),
            ctx.sessions.borrow().next_expiry(),
            ctx.apply.borrow().deadline,
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap();
        let timeout = next
            .saturating_duration_since(Instant::now())
            .as_micros()
            .div_ceil(1000)
            .min(i32::MAX as u128) as i32;
        let mut fds = [sys::PollFd {
            fd: read_fd,
            events: sys::POLLIN,
            revents: 0,
        }];
        if sys::poll_fds(&mut fds, timeout).is_ok() && fds[0].revents != 0 {
            rpcd_signals::drain();
        }
    }
}

fn register_live(
    ctx: &Ctx,
    conn: &mut Connection,
    name: &str,
    methods: &[(&'static str, Vec<(&'static str, MsgType)>)],
) -> std::io::Result<u32> {
    maintain(ctx);
    check_signal(ctx, Some(conn));
    register(conn, name, methods)
}

fn register_objects(ctx: &Ctx, conn: &mut Connection) -> std::io::Result<Ids> {
    Ok(Ids {
        session: register_live(ctx, conn, "session", &session::signature())?,
        uci: register_live(ctx, conn, "uci", &uciobj::signature())?,
        rc: register_live(ctx, conn, "rc", &rc::signature())?,
        file: register_live(ctx, conn, "file", &file::signature())?,
        luci: register_live(ctx, conn, "luci", &luci::signature())?,
        sys: register_live(ctx, conn, "rpc-sys", &rpcsys::signature())?,
        rrdns: register_live(ctx, conn, "network.rrdns", &rrdns::signature())?,
        lucirpc: {
            let name =
                std::env::var("OWRT_RPCD_LUCI_RPC_NAME").unwrap_or_else(|_| "luci-rpc".to_owned());
            register_live(ctx, conn, &name, &lucirpc::signature())?
        },
        iwinfo: register_live(ctx, conn, "iwinfo", &iwinfoobj::signature())?,
    })
}

fn serve(ctx: &Ctx, conn: &mut Connection, ids: &Ids, read_fd: RawFd) -> std::io::Result<()> {
    let (deferrer, rx) = Deferrer::channel();
    let ubus_fd = conn.as_raw_fd();
    let mut readiness = readiness::Readiness::new([ubus_fd, read_fd]);
    let mut immediate_left = 0;
    loop {
        maintain(ctx);
        uciobj::retry_event(ctx, conn);
        // completed deferred requests
        while let Ok(done) = rx.try_recv() {
            reply(conn, done.req, done.reply);
        }
        check_signal(ctx, Some(conn));
        // Frames already buffered need no readiness or receive syscall. Bound
        // this path so the wake pipe is drained even under continuous input.
        // Timers, signals and completed worker replies still run above for
        // every request.
        if immediate_left > 0 && conn.has_pending() {
            immediate_left -= 1;
            match conn.read_incoming() {
                Ok(Incoming::Invoke(req)) => dispatch(ctx, conn, ids, req, &deferrer),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Err(e);
                }
            }
            continue;
        }
        // next timer
        let now = Instant::now();
        let mut timeout: i32 = -1;
        let deadlines = [
            ctx.sessions.borrow().next_expiry(),
            ctx.apply.borrow().deadline,
            ctx.apply.borrow().event_retry,
        ];
        for d in deadlines.into_iter().flatten() {
            let ms = if d <= now {
                0
            } else {
                (d - now).as_micros().div_ceil(1000).min(i32::MAX as u128) as i32
            };
            timeout = if timeout < 0 { ms } else { timeout.min(ms) };
        }
        if conn.has_pending() {
            timeout = 0;
        }
        let Ok([bus_ready, wake_ready]) = readiness.wait(timeout) else {
            continue;
        };
        if wake_ready {
            rpcd_signals::drain();
        }
        if bus_ready || conn.has_pending() {
            immediate_left = 31;
            match conn.read_incoming() {
                Ok(Incoming::Invoke(req)) => dispatch(ctx, conn, ids, req, &deferrer),
                Ok(_) => {}
                Err(e) => {
                    return Err(e);
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
    if neg {
        -v
    } else {
        v
    }
}

#[cfg(test)]
mod reconnect_tests {
    use super::*;

    #[test]
    fn command_options_preserve_known_flags_and_ignore_non_ascii_unknown_flags() {
        let parse = |args: &[&str]| {
            command_options(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(
            parse(&["-中", "-t60", "-s/tmp/路径"]),
            (Some("/tmp/路径".into()), 60_000)
        );
        assert_eq!(
            parse(&["-t", "0x10", "-s", "/tmp/bus"]),
            (Some("/tmp/bus".into()), 16_000)
        );
        assert_eq!(parse(&["--", "-t1"]), (None, 120_000));
        assert_eq!(parse(&["positional", "-t1"]), (None, 120_000));
        assert_eq!(parse(&["-t601"]), (None, -1));
    }

    #[test]
    fn file_read_denies_non_utf8_session_id_before_opening_the_path() {
        let ctx = Ctx {
            socket: None,
            exec_timeout_ms: 1000,
            sessions: RefCell::new(session::Store::new()),
            apply: Default::default(),
            delayed: Default::default(),
            uci_read_cache: Default::default(),
        };
        let mut args = owrt_ubus::BlobBuf::new();
        args.msg_string("path", "/does-not-exist");
        args.msg_string_bytes("ubus_rpc_session", b"\xff");
        let json = fields_to_json(args.payload()).unwrap();
        assert_eq!(file::read(&ctx, &json), Err(status::PERMISSION_DENIED));
        assert!(ctx.file_access_bytes(None, b"/does-not-exist", "read"));
    }

    #[test]
    fn old_worker_completion_cannot_enter_a_reconnected_generation() {
        let (old, receiver) = Deferrer::channel();
        drop(receiver);
        let (_current, receiver) = Deferrer::channel();
        let done = Done {
            req: dummy_req(42),
            reply: session::Reply::empty(0),
            _permit: None,
        };
        // A worker's captured Sender stays on the old generation even if the
        // new daemon happens to reuse the same peer/sequence/object numbers.
        assert!(old.tx.send(done).is_err());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    fn dummy_req(peer: u32) -> Request {
        Request {
            peer,
            seq: 7,
            objid: 99,
            method: "exec".into(),
            user: None,
            group: None,
            data: vec![],
            fd: None,
            no_reply: false,
        }
    }

    #[test]
    fn defer_enforces_in_flight_limit_and_releases_only_on_done_consume_or_spawn_fail() {
        static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let (deferrer, rx) = Deferrer::channel_with(&TEST_COUNTER, 2);

        // 1. Spawn failure releases permit immediately and returns UNKNOWN_ERROR.
        let failed = deferrer.defer_with(
            dummy_req(1),
            || session::Reply::empty(status::OK),
            |_task| Err(std::io::Error::other("spawn failed")),
        );
        let (req, reply) = failed.expect("spawn failure must reply immediately");
        assert_eq!(req.peer, 1);
        assert_eq!(reply.code, status::UNKNOWN_ERROR);
        assert_eq!(TEST_COUNTER.load(Ordering::Acquire), 0);

        // 2. Acquire 2 permits; worker finishes into channel, permit stays held until Done is consumed.
        let (tx1, rx1) = mpsc::channel::<()>();
        assert!(deferrer
            .defer(dummy_req(2), move || {
                let _ = rx1.recv();
                session::Reply::empty(status::OK)
            })
            .is_none());
        assert!(deferrer
            .defer(dummy_req(3), || session::Reply::empty(status::OK))
            .is_none());
        assert_eq!(TEST_COUNTER.load(Ordering::Acquire), 2);

        // Wait until worker #3 has pushed its Done into rx, proving permit is not released before consumption.
        let done3 = rx.recv().unwrap();
        assert_eq!(done3.req.peer, 3);
        assert_eq!(
            TEST_COUNTER.load(Ordering::Acquire),
            2,
            "permit must stay held while Done is still alive"
        );
        // Saturated while done3 is unconsumed and worker #2 is still running.
        let saturated = deferrer
            .defer(dummy_req(4), || session::Reply::empty(status::OK))
            .expect("saturated deferrer must reject");
        assert_eq!(saturated.1.code, status::UNKNOWN_ERROR);

        // Consuming/dropping done3 releases one permit.
        drop(done3);
        assert_eq!(TEST_COUNTER.load(Ordering::Acquire), 1);

        // Unblock worker #2 and drop rx without receiving, simulating reconnect cleanup.
        let _ = tx1.send(());
        drop(rx);
        let deadline = Instant::now() + Duration::from_secs(2);
        while TEST_COUNTER.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(TEST_COUNTER.load(Ordering::Acquire), 0);
    }

    #[test]
    fn global_deferrer_channel_caps_at_max_deferred_in_flight() {
        let (deferrer, rx) = Deferrer::channel();
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let gate_rx = std::sync::Arc::new(std::sync::Mutex::new(gate_rx));
        let mut accepted = 0;
        for i in 0..MAX_DEFERRED_IN_FLIGHT {
            let rx_shared = std::sync::Arc::clone(&gate_rx);
            if deferrer
                .defer(dummy_req(i as u32), move || {
                    let _ = rx_shared.lock().unwrap().recv();
                    session::Reply::empty(status::OK)
                })
                .is_none()
            {
                accepted += 1;
            }
        }
        assert_eq!(accepted, MAX_DEFERRED_IN_FLIGHT);
        let rejected = deferrer
            .defer(dummy_req(999), || session::Reply::empty(status::OK))
            .expect("global limit must reject at MAX_DEFERRED_IN_FLIGHT");
        assert_eq!(rejected.1.code, status::UNKNOWN_ERROR);

        drop(gate_tx);
        for _ in 0..accepted {
            let _ = rx.recv().unwrap();
        }
        assert_eq!(DEFERRED_IN_FLIGHT.load(Ordering::Acquire), 0);
    }
}
