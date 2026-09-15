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
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    b.msg_string_bytes("msg", &entry.msg)
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

// The original ustream write queue is unbounded. Disconnect a lagging
// stream instead of letting it exhaust the daemon.
const MAX_STREAM_PENDING: usize = 1024 * 1024;
const MAX_TOTAL_PENDING: usize = 4 * 1024 * 1024;
const MAX_STREAM_CLIENTS: usize = 64;

impl Client {
    fn poll_fd(&self) -> sys::PollFd {
        sys::PollFd {
            fd: self.fd.as_raw_fd(),
            events: if self.pending.is_empty() { 0 } else { sys::POLLOUT },
            revents: 0,
        }
    }

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

/// Consume a poll snapshot before any input handler can add/remove clients.
/// Each result belongs to the client at the same position at poll time.
fn flush_ready_clients(clients: &mut Vec<Client>, fds: &[sys::PollFd]) {
    debug_assert_eq!(clients.len(), fds.len());
    let mut ready = fds.iter();
    clients.retain_mut(|client| {
        let event = ready.next().expect("one poll result per client");
        debug_assert_eq!(client.fd.as_raw_fd(), event.fd);
        if event.revents & (sys::POLLERR | sys::POLLHUP) != 0 {
            return false;
        }
        event.revents & sys::POLLOUT == 0 || client.flush()
    });
}

fn send_to_clients(clients: &mut Vec<Client>, bytes: &[u8]) {
    let (projected, fits_each) = clients.iter().fold((0, true), |(total, fits), client| {
        let size = client.pending.len() + bytes.len();
        (total + size, fits && size <= MAX_STREAM_PENDING)
    });
    if projected <= MAX_TOTAL_PENDING && fits_each {
        clients.retain_mut(|client| {
            client.pending.extend_from_slice(bytes);
            client.flush()
        });
        return;
    }
    let mut sent = [0; MAX_STREAM_CLIENTS];
    // Pressure only: first make room with writes that were not ready at
    // poll time. Empty queues can send this frame without using a budget.
    clients.retain_mut(Client::flush);
    let mut index = 0;
    clients.retain(|client| {
        let mut offset = 0;
        if client.pending.is_empty() {
            // SAFETY: borrow this client's live fd; ManuallyDrop keeps
            // ownership in Client, as in flush().
            let mut file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(client.fd.as_raw_fd()) });
            while offset < bytes.len() {
                match file.write(&bytes[offset..]) {
                    Ok(0) => return false,
                    Ok(n) => offset += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => return false,
                }
            }
        }
        if client.pending.len() + bytes.len() - offset > MAX_STREAM_PENDING {
            return false;
        }
        sent[index] = offset;
        index += 1;
        true
    });
    let mut total: usize = clients.iter().enumerate()
        .map(|(i, client)| client.pending.len() + bytes.len() - sent[i]).sum();
    // A full global budget belongs to the lagging streams, not an earlier
    // healthy reader. This scan is only needed at the pressure boundary.
    while total > MAX_TOTAL_PENDING {
        let (index, client) = clients.iter().enumerate()
            .max_by_key(|(i, client)| client.pending.len() + bytes.len() - sent[*i])
            .expect("an over-budget set is nonempty");
        total -= client.pending.len() + bytes.len() - sent[index];
        sent.copy_within(index + 1..clients.len(), index);
        clients.remove(index);
    }
    let mut index = 0;
    clients.retain_mut(|client| {
        client.pending.extend_from_slice(&bytes[sent[index]..]);
        index += 1;
        client.flush()
    });
}

/// ubus_add_object("log", ...)
fn register_log(conn: &mut Connection) -> io::Result<u32> {
    conn.set_server_io_timeout(Duration::from_secs(1));
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
        send_to_clients(&mut self.clients, &bytes);
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
            let total: usize = self.clients.iter().map(|c| c.pending.len()).sum();
            if self.clients.len() >= MAX_STREAM_CLIENTS {
                return self.conn.reply_status(req, owrt_ubus::status::NOT_SUPPORTED, None);
            }
            // The candidate has used a Unix stream socket since before R89;
            // exact C logd uses pipe(). Both carry the same blob frames, but
            // their kernel buffering differs. Reuse one BlobBuf per backlog.
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
            let mut pending = Vec::with_capacity((backlog.len() * 96).min(MAX_STREAM_PENDING));
            let mut b = BlobBuf::new();
            for entry in backlog {
                b.reset();
                entry_fields(&mut b, entry);
                if pending.len() + b.as_bytes().len() > MAX_STREAM_PENDING
                    || total + pending.len() + b.as_bytes().len() > MAX_TOTAL_PENDING {
                    return self.conn.reply_status(req, owrt_ubus::status::NOT_SUPPORTED, None);
                }
                pending.extend_from_slice(b.as_bytes());
            }
            let mut client = Client {
                fd: write_end,
                pending,
                oneshot,
            };
            self.conn.reply_status(req, owrt_ubus::status::OK, Some(read_end.as_raw_fd()))?;
            drop(read_end);
            if client.flush() {
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
        // blobmsg_get_string / strlen operate on bytes. Truncate before
        // normalization, including when the cut splits a UTF-8 character.
        let event = blob::fields(&req.data)
            .find(|f| f.name == "event")
            .and_then(|f| f.as_bytes());
        if let Some(event) = event {
            self.add(&event[..event.len().min(LINE_SIZE - 1)], SOURCE_SYSLOG);
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
        // A continuously writing producer must not starve streams, ubus or
        // the reconnect deadline. Remaining datagrams keep POLLIN asserted.
        for _ in 0..256 {
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
        let _ = self.conn.shutdown();
        self.has_subscribers = false;
        let mut retry_at = Instant::now() + Duration::from_secs(1);
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
            let client_base = fds.len();
            fds.extend(self.clients.iter().map(Client::poll_fd));
            let timeout = retry_at.saturating_duration_since(Instant::now())
                .as_millis().min(1000) as i32;
            if sys::poll_fds(&mut fds, timeout).is_ok() {
                flush_ready_clients(&mut self.clients, &fds[client_base..]);
                if fds[0].revents & sys::POLLIN != 0 {
                    self.drain_syslog();
                }
                if self.kmsg.is_some() && fds[1].revents & sys::POLLIN != 0 {
                    self.drain_kmsg();
                }
            }
            // Stream readiness and incoming logs may wake us continuously;
            // they must not turn a one-second retry into a busy connect loop.
            if Instant::now() < retry_at {
                continue;
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
            retry_at = Instant::now() + Duration::from_secs(1);
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
            fds.extend(self.clients.iter().map(Client::poll_fd));
            sys::poll_fds(&mut fds, -1)?;
            // add()/read may compact or append clients. Apply this snapshot
            // first, while every result still names the stream we polled.
            flush_ready_clients(&mut self.clients, &fds[client_base..]);
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

#[cfg(test)]
mod stream_tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn pair(pending: Vec<u8>, oneshot: bool) -> (UnixStream, Client) {
        let (reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        (reader, Client { fd: writer.into(), pending, oneshot })
    }

    #[test]
    fn one_streams_hangup_does_not_close_the_next_stream() {
        let (closed, first) = pair(vec![1], false);
        let (mut healthy, second) = pair(b"still connected".to_vec(), false);
        let mut clients = vec![first, second];
        let mut fds: Vec<_> = clients.iter().map(Client::poll_fd).collect();
        drop(closed);
        sys::poll_fds(&mut fds, 1000).unwrap();
        assert_ne!(fds[0].revents & sys::POLLHUP, 0);
        assert_ne!(fds[1].revents & sys::POLLOUT, 0);
        flush_ready_clients(&mut clients, &fds);
        assert_eq!(clients.len(), 1);
        let mut bytes = [0; 15];
        healthy.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"still connected");
        healthy.set_nonblocking(true).unwrap();
        assert_eq!(healthy.read(&mut bytes).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn write_readiness_finishes_oneshot_without_another_log_record() {
        let (mut reader, client) = pair(b"queued history".to_vec(), true);
        let mut clients = vec![client];
        let mut fds: Vec<_> = clients.iter().map(Client::poll_fd).collect();
        sys::poll_fds(&mut fds, 1000).unwrap();
        flush_ready_clients(&mut clients, &fds);
        assert!(clients.is_empty());
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"queued history");
    }

    #[test]
    fn full_aggregate_backlog_drops_a_lagging_stream_not_the_healthy_first_reader() {
        let (mut healthy, first) = pair(Vec::new(), false);
        let mut clients = vec![first];
        let mut slow_readers = Vec::new();
        for _ in 0..8 {
            let (reader, client) = pair(vec![b'x'; MAX_TOTAL_PENDING / 8], false);
            // Fill the kernel socket buffer too: a late flush must not make
            // this supposedly stalled consumer healthy by itself.
            // SAFETY: borrow the live fd without taking its ownership.
            let mut file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(client.fd.as_raw_fd()) });
            loop {
                match file.write(&[b'x'; 65536]) {
                    Ok(n) => assert!(n > 0),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => panic!("fill socket: {e}"),
                }
            }
            slow_readers.push(reader);
            clients.push(client);
        }
        send_to_clients(&mut clients, b"live record");
        assert_eq!(clients.len(), 8);
        assert!(clients.iter().map(|c| c.pending.len()).sum::<usize>() <= MAX_TOTAL_PENDING);
        let mut bytes = [0; 11];
        healthy.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"live record");
        healthy.set_nonblocking(true).unwrap();
        assert_eq!(healthy.read(&mut bytes).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
}
