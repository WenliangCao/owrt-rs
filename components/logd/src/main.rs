//! logd-rs: contract C2 compatible replacement for ubox logd.
//!
//! Serves ubus object `log` (methods read/write), ingests /dev/log and
//! /proc/kmsg, keeps logd's ring-buffer retention, streams records to
//! `logread` over a pipe passed with the STATUS reply, and notifies
//! subscribers. Drops privileges to user `logd` after binding sockets.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

mod ring;

use owrt_ubus::{blob, sys, BlobBuf, Connection, Incoming, MsgType, Request};
use ring::{normalize, Entry, Ring, LINE_SIZE, SOURCE_KLOG, SOURCE_SYSLOG};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::time::{SystemTime, UNIX_EPOCH};

struct Options {
    log_size: usize,
    ubus_socket: Option<String>,
    log_socket: String,
    kmsg: Option<String>,
    user: Option<String>,
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options {
        log_size: 16 * 1024,
        ubus_socket: None,
        log_socket: "/dev/log".into(),
        kmsg: Some("/proc/kmsg".into()),
        user: Some("logd".into()),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} requires a value"));
        match arg.as_str() {
            "-S" => {
                let kib: i64 = value("-S")?.parse().map_err(|_| "-S must be an integer")?;
                options.log_size = if kib < 1 { 16 } else { kib as usize } * 1024;
            }
            "--ubus-socket" => options.ubus_socket = Some(value("--ubus-socket")?),
            "--log-socket" => options.log_socket = value("--log-socket")?,
            "--kmsg" => {
                let path = value("--kmsg")?;
                options.kmsg = if path == "none" { None } else { Some(path) };
            }
            "--no-drop-privileges" => options.user = None,
            "-h" | "--help" => {
                println!("usage: logd-rs [-S KiB] [--ubus-socket PATH] [--log-socket PATH] [--kmsg PATH|none] [--no-drop-privileges]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(options)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn entry_fields(b: &mut BlobBuf, entry: &Entry) {
    b.msg_string("msg", &entry.msg)
        .msg_u32("id", entry.id)
        .msg_u32("priority", entry.priority)
        .msg_u32("source", entry.source)
        .msg_u64("time", entry.time_ms);
}

/// One frame as logd writes it to a stream client: a head blob with the fields.
fn frame(entry: &Entry) -> Vec<u8> {
    let mut b = BlobBuf::new();
    entry_fields(&mut b, entry);
    b.as_bytes().to_vec()
}

struct Client {
    fd: OwnedFd,
    pending: Vec<u8>,
    oneshot: bool,
}

impl Client {
    /// Write what we can; Ok(false) when the client must be dropped.
    fn flush(&mut self) -> bool {
        while !self.pending.is_empty() {
            // SAFETY: borrowing our own still-open descriptor to get at
            // File's write(). ManuallyDrop keeps the File from closing it --
            // self.fd remains the owner.
            let mut file =
                std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(self.fd.as_raw_fd()) });
            match file.write(&self.pending) {
                Ok(0) => return false,
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return false,
            }
        }
        !self.oneshot
    }
}

/// ubus_add_object("log", ...)
fn register_log(conn: &mut Connection) -> io::Result<u32> {
    conn.add_object(
        "log",
        &[
            (
                "read",
                &[
                    ("lines", MsgType::Int32),
                    ("stream", MsgType::Int8),
                    ("oneshot", MsgType::Int8),
                ],
            ),
            ("write", &[("event", MsgType::String)]),
        ],
        5_000,
    )
}

struct Daemon {
    ubus_socket: Option<String>,
    conn: Connection,
    objid: u32,
    ring: Ring,
    clients: Vec<Client>,
    has_subscribers: bool,
    syslog: UnixDatagram,
    kmsg: Option<File>,
    kmsg_buf: Vec<u8>,
}

impl Daemon {
    fn add(&mut self, raw: &[u8], source: u32) {
        let Some((priority, msg)) = normalize(raw, source) else {
            return;
        };
        let entry = self.ring.add(msg, priority, source, now_ms());
        if self.clients.is_empty() && !self.has_subscribers {
            return;
        }
        let bytes = frame(&entry);
        if self.has_subscribers {
            let _ = self.conn.notify(self.objid, "message", &bytes[4..]);
        }
        for client in &mut self.clients {
            client.pending.extend_from_slice(&bytes);
        }
        self.clients.retain_mut(Client::flush);
    }

    fn handle_read(&mut self, req: &Request) -> io::Result<()> {
        // logd read_policy is strict: lines is INT32, stream/oneshot BOOL
        // (INT8). blobmsg_parse drops attributes of any other type, so a
        // wrong-typed field leaves the default in place (as in logd.c).
        let mut lines: Option<i64> = None;
        let mut stream = true;
        let mut oneshot = false;
        for field in blob::fields(&req.data) {
            match field.name {
                "lines" if field.ty == MsgType::Int32 as u32 => {
                    // blobmsg_get_u32 into an int: reinterpret as signed.
                    lines = field.as_u32().map(|v| v as i32 as i64);
                }
                "stream" if field.ty == MsgType::Int8 as u32 => {
                    stream = field.as_bool().unwrap_or(true);
                }
                "oneshot" if field.ty == MsgType::Int8 as u32 => {
                    oneshot = field.as_bool().unwrap_or(false);
                }
                _ => {}
            }
        }
        // log_list(count): a present lines==0 yields no backlog, absent
        // yields all, otherwise the C min window applies.
        let backlog: Vec<&Entry> = match lines {
            Some(0) => Vec::new(),
            Some(count) => self.ring.list(count).collect(),
            None => self.ring.list(0).collect(),
        };
        if stream {
            // unix stream socket like C logd (a pipe would hand the backlog over
            // in 64 KiB pieces); one BlobBuf reused for every frame
            let pair = sys::socketpair().and_then(|(read_end, write_end)| {
                sys::set_nonblocking(write_end.as_raw_fd())?;
                Ok((read_end, write_end))
            });
            // C logd fails the request (`pipe()` failed -> handler returns -1)
            // and keeps serving; a local error must never cost us the object.
            let (read_end, write_end) = match pair {
                Ok(pair) => pair,
                Err(error) => {
                    eprintln!("logd-rs: failed to create stream socket: {error}");
                    return self
                        .conn
                        .reply_status(req, owrt_ubus::status::UNKNOWN_ERROR, None);
                }
            };
            let mut pending = Vec::with_capacity(backlog.len() * 96);
            let mut b = BlobBuf::new();
            for entry in backlog {
                b.reset();
                entry_fields(&mut b, entry);
                pending.extend_from_slice(b.as_bytes());
            }
            let mut client = Client {
                fd: write_end,
                pending,
                oneshot,
            };
            self.conn.reply_status(req, owrt_ubus::status::OK, Some(read_end.as_raw_fd()))?;
            drop(read_end);
            if client.flush() || !client.pending.is_empty() {
                self.clients.push(client);
            }
            return Ok(());
        }
        let mut b = BlobBuf::new();
        let array = b.msg_open_array("log");
        for entry in backlog {
            let table = b.msg_open_table("");
            entry_fields(&mut b, entry);
            b.msg_close(table);
        }
        b.msg_close(array);
        // A reply past UBUS_MAX_MSGLEN is refused locally by Connection::send
        // (C hands it to ubusd, which drops the client instead). Either way the
        // request fails, but it must fail as this request's status: dropping the
        // connection would cost us the `log` object until `service log restart`.
        if let Err(error) = self.conn.reply_data(req, b.payload()) {
            eprintln!("logd-rs: log read reply not sent: {error}");
            return self
                .conn
                .reply_status(req, owrt_ubus::status::INVALID_ARGUMENT, None);
        }
        self.conn.reply_status(req, owrt_ubus::status::OK, None)
    }

    fn handle_write(&mut self, req: &Request) -> io::Result<()> {
        let event = blob::fields(&req.data)
            .find(|f| f.name == "event")
            .and_then(|f| f.as_str())
            .map(str::to_owned);
        if let Some(mut event) = event {
            if event.len() + 1 > LINE_SIZE {
                let mut cut = LINE_SIZE - 1;
                while !event.is_char_boundary(cut) {
                    cut -= 1;
                }
                event.truncate(cut);
            }
            self.add(event.as_bytes(), SOURCE_SYSLOG);
        }
        self.conn.reply_status(req, owrt_ubus::status::OK, None)
    }

    fn handle_incoming(&mut self, incoming: Incoming) -> io::Result<()> {
        match incoming {
            Incoming::Invoke(req) if req.objid == self.objid => match req.method.as_str() {
                "read" => self.handle_read(&req),
                "write" => self.handle_write(&req),
                _ => self
                    .conn
                    .reply_status(&req, owrt_ubus::status::METHOD_NOT_FOUND, None),
            },
            Incoming::Invoke(req) => {
                self.conn
                    .reply_status(&req, owrt_ubus::status::NOT_FOUND, None)
            }
            Incoming::SubscribeState { objid, active } if objid == self.objid => {
                self.has_subscribers = active;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn drain_syslog(&mut self) {
        let mut buf = [0u8; LINE_SIZE];
        loop {
            match self.syslog.recv(&mut buf[..LINE_SIZE - 1]) {
                Ok(0) => break,
                Ok(n) => self.add(&buf[..n], SOURCE_SYSLOG),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }

    fn drain_kmsg(&mut self) {
        let Some(kmsg) = self.kmsg.as_mut() else {
            return;
        };
        let mut chunk = [0u8; 4096];
        if let Ok(n) = kmsg.read(&mut chunk) {
            self.kmsg_buf.extend_from_slice(&chunk[..n]);
        }
        while let Some(pos) = self.kmsg_buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.kmsg_buf.drain(..=pos).collect();
            self.add(&line[..line.len() - 1], SOURCE_KLOG);
        }
    }

    /// libubus ubus_auto_connect(): after the connection to ubusd is lost,
    /// retry every second and register the object again; the ring buffer and
    /// the stream clients survive (C logd behaves the same way).
    fn reconnect(&mut self) {
        // C `ubus_reconnect()` closes the old socket before it connects
        // (libubus-io.c:421-426), so ubusd tears the stale client down and
        // frees the `log` path. Keeping it open means every `add_object("log")`
        // is refused with INVALID_ARGUMENT while ubusd is alive -- logd would
        // retry at 1 Hz forever and nothing would serve `log` again.
        //
        // SAFETY: we borrow our own still-open descriptor to reach
        // UnixStream::shutdown; ManuallyDrop keeps the stream from closing it,
        // self.conn stays the owner and closes it when it is replaced below.
        let old =
            std::mem::ManuallyDrop::new(unsafe { UnixStream::from_raw_fd(self.conn.as_raw_fd()) });
        let _ = old.shutdown(std::net::Shutdown::Both);
        loop {
            // keep collecting syslog/kmsg while ubusd is away (uloop keeps
            // servicing those fds in C logd too)
            let mut fds = vec![sys::PollFd {
                fd: self.syslog.as_raw_fd(),
                events: sys::POLLIN,
                revents: 0,
            }];
            if let Some(kmsg) = &self.kmsg {
                fds.push(sys::PollFd {
                    fd: kmsg.as_raw_fd(),
                    events: sys::POLLIN,
                    revents: 0,
                });
            }
            if sys::poll_fds(&mut fds, 1000).is_ok() {
                if fds[0].revents & sys::POLLIN != 0 {
                    self.drain_syslog();
                }
                if fds.len() > 1 && fds[1].revents & sys::POLLIN != 0 {
                    self.drain_kmsg();
                }
            }
            if let Ok(mut conn) = Connection::connect(self.ubus_socket.as_deref()) {
                match register_log(&mut conn) {
                    Ok(id) => {
                        self.conn = conn;
                        self.objid = id;
                        self.has_subscribers = false;
                        return;
                    }
                    Err(error) => eprintln!("logd-rs: failed to add object: {error}"),
                }
            }
        }
    }

    fn run(&mut self) -> io::Result<()> {
        loop {
            if let Err(error) = self.run_connected() {
                eprintln!("logd-rs: ubus connection lost: {error}");
                self.reconnect();
            }
        }
    }

    fn run_connected(&mut self) -> io::Result<()> {
        loop {
            while self.conn.has_pending() {
                let incoming = self.conn.read_incoming()?;
                self.handle_incoming(incoming)?;
            }
            let mut fds = vec![
                sys::PollFd {
                    fd: self.conn.as_raw_fd(),
                    events: sys::POLLIN,
                    revents: 0,
                },
                sys::PollFd {
                    fd: self.syslog.as_raw_fd(),
                    events: sys::POLLIN,
                    revents: 0,
                },
            ];
            let kmsg_index = self.kmsg.as_ref().map(|kmsg| {
                fds.push(sys::PollFd {
                    fd: kmsg.as_raw_fd(),
                    events: sys::POLLIN,
                    revents: 0,
                });
                fds.len() - 1
            });
            let client_base = fds.len();
            let polled_clients = self.clients.len();
            for client in &self.clients {
                fds.push(sys::PollFd {
                    fd: client.fd.as_raw_fd(),
                    events: if client.pending.is_empty() {
                        0
                    } else {
                        sys::POLLOUT
                    },
                    revents: 0,
                });
            }
            sys::poll_fds(&mut fds, -1)?;
            if fds[0].revents & (sys::POLLIN | sys::POLLERR | sys::POLLHUP) != 0 {
                let incoming = self.conn.read_incoming()?;
                self.handle_incoming(incoming)?;
            }
            if fds[1].revents & sys::POLLIN != 0 {
                self.drain_syslog();
            }
            if let Some(index) = kmsg_index {
                if fds[index].revents & sys::POLLIN != 0 {
                    self.drain_kmsg();
                }
            }
            // Clients added while handling this iteration were not polled.
            let mut position = 0;
            self.clients.retain_mut(|client| {
                let current = position;
                position += 1;
                if current >= polled_clients {
                    return true;
                }
                let revents = fds[client_base + current].revents;
                if revents & (sys::POLLERR | sys::POLLHUP) != 0 {
                    return false;
                }
                if revents & sys::POLLOUT != 0 {
                    return client.flush();
                }
                true
            });
        }
    }
}

fn lookup_user(name: &str) -> Option<(u32, u32)> {
    // getpwnam is byte-based: a non-UTF-8 comment field elsewhere in the file must not hide the user
    let passwd = std::fs::read("/etc/passwd").ok().map(|b| String::from_utf8_lossy(&b).into_owned())?;
    passwd.lines().find_map(|line| {
        let mut parts = line.split(':');
        if parts.next()? != name {
            return None;
        }
        parts.next()?;
        let uid = parts.next()?.parse().ok()?;
        let gid = parts.next()?.parse().ok()?;
        Some((uid, gid))
    })
}

fn open_syslog(path: &str) -> io::Result<UnixDatagram> {
    let _ = std::fs::remove_file(path);
    let socket = UnixDatagram::bind(path)?;
    socket.set_nonblocking(true)?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o666))?;
    Ok(socket)
}

fn main() {
    let options = match parse_args() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("logd-rs: {error}");
            std::process::exit(64);
        }
    };
    sys::ignore_signal(sys::SIGPIPE);
    let syslog = match open_syslog(&options.log_socket) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("logd-rs: failed to open {}: {error}", options.log_socket);
            std::process::exit(1);
        }
    };
    let kmsg = options.kmsg.as_deref().and_then(|path| {
        let file = std::fs::OpenOptions::new().read(true).open(path);
        match file {
            Ok(file) => {
                let _ = sys::set_nonblocking(file.as_raw_fd());
                Some(file)
            }
            Err(error) => {
                eprintln!("logd-rs: failed to open {path}: {error}");
                None
            }
        }
    });
    let mut conn = match Connection::connect(options.ubus_socket.as_deref()) {
        Ok(conn) => conn,
        Err(error) => {
            eprintln!("logd-rs: ubus connect failed: {error}");
            std::process::exit(1);
        }
    };
    let objid = match register_log(&mut conn) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("logd-rs: failed to add object: {error}");
            std::process::exit(1);
        }
    };
    if let Some(user) = &options.user {
        match lookup_user(user) {
            Some((uid, gid)) => {
                if let Err(error) = sys::drop_privileges(uid, gid) {
                    eprintln!("logd-rs: setuid/setgid failed: {error}");
                    std::process::exit(1);
                }
            }
            None => eprintln!("logd-rs: user {user} not found, staying root"),
        }
    }
    let mut daemon = Daemon {
        ubus_socket: options.ubus_socket.clone(),
        conn,
        objid,
        ring: Ring::new(options.log_size),
        clients: Vec::new(),
        has_subscribers: false,
        syslog,
        kmsg,
        kmsg_buf: Vec::new(),
    };
    if let Err(error) = daemon.run() {
        eprintln!("logd-rs: {error}");
        std::process::exit(1);
    }
}
