//! logd-rs: contract C2 compatible replacement for ubox logd.
//!
//! Serves ubus object `log` (methods read/write), ingests /dev/log and
//! /proc/kmsg, keeps logd's ring-buffer retention, streams records to
//! `logread` over a pipe passed with the STATUS reply, and notifies
//! subscribers. Drops privileges to user `logd` after binding sockets.
//!
//! Per record the daemon allocates nothing: the message is copied once from
//! the receive buffer into the ring arena, and its stream frame is appended
//! to a batch buffer that is written to every stream once per input round
//! (up to 256 datagrams), so a burst costs one write per stream instead of
//! one per record. The byte stream each reader sees is unchanged.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]
#![forbid(unsafe_code)]

mod frame;
mod ring;

use frame::{frame_len, push_frame, push_reply_header, push_table, table_len, REPLY_HEADER_LEN};
use owrt_ubus::{blob, sys, Connection, Incoming, MsgType, Request};
use ring::{normalize, Ring, LINE_SIZE, SOURCE_KLOG, SOURCE_SYSLOG};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
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
                let _ = writeln!(std::io::stdout(), "usage: logd-rs [-S KiB] [--ubus-socket PATH] [--log-socket PATH] [--kmsg PATH|none] [--no-drop-privileges]");
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

/// write(2) on a descriptor we keep owning elsewhere.
fn write_fd(fd: impl AsFd, bytes: &[u8]) -> io::Result<usize> {
    Ok(rustix::io::write(fd, bytes)?)
}

/// Kernel buffer of a stream pipe. The default 64 KiB pipe returns EAGAIN
/// after a few hundred frames of backlog and makes a burst cost a write
/// per pipe-full; 256 KiB matches the Unix stream socket R89..R93 used.
/// Pipe pages are allocated only while data sits in them, so this costs
/// nothing at rest. Best effort: a kernel that refuses keeps the default.
const PIPE_CAPACITY: i32 = 256 * 1024;

#[cfg(target_os = "linux")]
fn set_pipe_capacity(fd: impl AsFd, bytes: i32) -> io::Result<()> {
    rustix::pipe::fcntl_setpipe_size(fd, bytes as usize)?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn set_pipe_capacity(_fd: impl AsFd, _bytes: i32) -> io::Result<()> { Ok(()) }

struct Client {
    fd: OwnedFd,
    /// Queued frames; `pending[sent..]` is still to be written.
    pending: Vec<u8>,
    sent: usize,
    oneshot: bool,
}

// The original ustream write queue is unbounded. Disconnect a lagging
// stream instead of letting it exhaust the daemon.
const MAX_STREAM_PENDING: usize = 1024 * 1024;
const MAX_TOTAL_PENDING: usize = 4 * 1024 * 1024;
const MAX_STREAM_CLIENTS: usize = 64;

/// A complete ring must fit in one bounded history stream. The shortest
/// record uses 36 arena bytes and 96 frame bytes; longer text lowers that
/// ratio. Three times the configured arena covers every possible history.
/// Small rings retain the existing per-stream and aggregate limits.
fn stream_pending_limit(ring_capacity: usize) -> usize {
    ring_capacity.saturating_mul(3).max(MAX_STREAM_PENDING)
}
/// Storage a drained queue or batch keeps for the next burst; anything
/// larger goes back to the allocator so one slow reader does not set the
/// daemon's footprint.
const RETAINED_QUEUE: usize = 64 * 1024;
/// Storage the `read` reply buffer keeps between requests.
const RETAINED_REPLY: usize = 32 * 1024;

impl Client {
    fn queued(&self) -> usize {
        self.pending.len() - self.sent
    }

    fn poll_fd(&self) -> sys::PollFd {
        sys::PollFd {
            fd: self.fd.as_raw_fd(),
            events: if self.queued() == 0 { 0 } else { sys::POLLOUT },
            revents: 0,
        }
    }

    /// Write as much of `bytes` as the pipe takes now; Ok(n) with n < len
    /// means it is full. Err means the reader is gone.
    fn write_direct(&self, bytes: &[u8]) -> io::Result<usize> {
        let mut offset = 0;
        while offset < bytes.len() {
            match write_fd(&self.fd, &bytes[offset..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => offset += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(offset)
    }

    fn queue(&mut self, bytes: &[u8]) {
        if self.sent > 0 {
            self.pending.drain(..self.sent);
            self.sent = 0;
        }
        self.pending.extend_from_slice(bytes);
    }

    fn release(&mut self) {
        self.sent = 0;
        if self.pending.capacity() > RETAINED_QUEUE {
            self.pending = Vec::new();
        } else {
            self.pending.clear();
        }
    }

    /// Write what we can; Ok(false) when the client must be dropped.
    fn flush(&mut self) -> bool {
        match self.write_direct(&self.pending[self.sent..]) {
            Ok(n) => {
                self.sent += n;
                if self.sent < self.pending.len() {
                    return true;
                }
                self.release();
                !self.oneshot
            }
            Err(_) => false,
        }
    }

    /// Deliver `bytes`, queueing whatever the pipe does not take now.
    fn send(&mut self, bytes: &[u8]) -> bool {
        if self.queued() == 0 {
            match self.write_direct(bytes) {
                Ok(n) if n == bytes.len() => return !self.oneshot,
                Ok(n) => {
                    self.queue(&bytes[n..]);
                    return true;
                }
                Err(_) => return false,
            }
        }
        self.queue(bytes);
        self.flush()
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

/// Deliver one batch of frames to every stream.
fn send_to_clients(clients: &mut Vec<Client>, bytes: &[u8], max_stream_pending: usize) {
    let max_total_pending = MAX_TOTAL_PENDING.max(max_stream_pending);
    let (projected, fits_each) = clients.iter().fold((0, true), |(total, fits), client| {
        let size = client.queued() + bytes.len();
        (total + size, fits && size <= max_stream_pending)
    });
    if projected <= max_total_pending && fits_each {
        clients.retain_mut(|client| client.send(bytes));
        return;
    }
    let mut sent = [0; MAX_STREAM_CLIENTS];
    // Pressure only: first make room with writes that were not ready at
    // poll time. Empty queues can send this batch without using a budget.
    clients.retain_mut(Client::flush);
    let mut index = 0;
    clients.retain_mut(|client| {
        let mut offset = 0;
        if client.queued() == 0 {
            match client.write_direct(bytes) {
                Ok(n) => offset = n,
                Err(_) => return false,
            }
        }
        if client.queued() + bytes.len() - offset > max_stream_pending {
            return false;
        }
        sent[index] = offset;
        index += 1;
        true
    });
    let mut total: usize = clients.iter().enumerate()
        .map(|(i, client)| client.queued() + bytes.len() - sent[i]).sum();
    // A full global budget belongs to the lagging streams, not an earlier
    // healthy reader. This scan is only needed at the pressure boundary.
    while total > max_total_pending {
        let (index, client) = clients.iter().enumerate()
            .max_by_key(|(i, client)| client.queued() + bytes.len() - sent[*i])
            .expect("an over-budget set is nonempty");
        total -= client.queued() + bytes.len() - sent[index];
        sent.copy_within(index + 1..clients.len(), index);
        clients.remove(index);
    }
    let mut index = 0;
    clients.retain_mut(|client| {
        client.queue(&bytes[sent[index]..]);
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
    max_stream_pending: usize,
    clients: Vec<Client>,
    has_subscribers: bool,
    syslog: UnixDatagram,
    kmsg: Option<File>,
    kmsg_buf: Vec<u8>,
    /// Frames of the current input round, not yet written to the streams.
    batch: Vec<u8>,
    /// Reused `read` reply storage.
    reply: Vec<u8>,
    /// Reused poll set.
    fds: Vec<sys::PollFd>,
    /// Zero-timeout polls left before the loop blocks again (see `drain_syslog`).
    spin: u8,
}

/// Polls with a zero timeout after a round that found a burst in progress.
/// A producer writing back to back is otherwise met by a daemon that drains
/// faster than it writes and sleeps between datagrams, so every datagram
/// pays a wakeup on both sides; a few cheap polls keep the loop awake for
/// the next one and cost about a microsecond once when a burst ends.
const BURST_SPINS: u8 = 4;

impl Daemon {
    /// Store one input record; its frame joins the batch when anyone listens.
    fn add(&mut self, raw: &[u8], source: u32) {
        let Some((priority, msg)) = normalize(raw, source) else {
            return;
        };
        let record = self.ring.add(msg, priority, source, now_ms());
        if self.clients.is_empty() && !self.has_subscribers {
            return;
        }
        let start = self.batch.len();
        push_frame(&mut self.batch, &record);
        if self.has_subscribers {
            let _ = self.conn.notify(self.objid, "message", &self.batch[start + 4..]);
        }
        if self.clients.is_empty() {
            self.batch.truncate(start);
        }
    }

    /// Write the round's frames to every stream. Runs before any `read`
    /// request is served, so a new stream's backlog never overlaps them.
    fn flush_batch(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        send_to_clients(&mut self.clients, &self.batch, self.max_stream_pending);
        if self.batch.capacity() > RETAINED_QUEUE {
            self.batch = Vec::new();
        } else {
            self.batch.clear();
        }
    }

    fn handle_read(&mut self, req: &Request) -> io::Result<()> {
        debug_assert!(self.batch.is_empty(), "read served with unsent frames");
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
        let window = match lines {
            Some(0) => None,
            Some(count) => Some(count),
            None => Some(0),
        };
        if stream {
            if self.clients.len() >= MAX_STREAM_CLIENTS {
                return self.conn.reply_status(req, owrt_ubus::status::NOT_SUPPORTED, None);
            }
            let total: usize = self.clients.iter().map(Client::queued).sum();
            let backlog: usize = window
                .map_or(0, |count| self.ring.list(count).map(|r| frame_len(r.size())).sum());
            if backlog > self.max_stream_pending
                || total + backlog > MAX_TOTAL_PENDING.max(self.max_stream_pending)
            {
                return self.conn.reply_status(req, owrt_ubus::status::NOT_SUPPORTED, None);
            }
            // A pipe, as in exact C logd (R89..R93 used a Unix stream socket).
            let pair = io::pipe().and_then(|(read_end, write_end)| {
                let (read_end, write_end) = (OwnedFd::from(read_end), OwnedFd::from(write_end));
                sys::set_nonblocking(write_end.as_raw_fd())?;
                let _ = set_pipe_capacity(&write_end, PIPE_CAPACITY);
                Ok((read_end, write_end))
            });
            // C logd fails the request (`pipe()` failed -> handler returns -1)
            // and keeps serving; a local error must never cost us the object.
            let (read_end, write_end) = match pair {
                Ok(pair) => pair,
                Err(error) => {
                    eprintln!("logd-rs: failed to create stream pipe: {error}");
                    return self
                        .conn
                        .reply_status(req, owrt_ubus::status::UNKNOWN_ERROR, None);
                }
            };
            let mut pending = Vec::with_capacity(backlog);
            if let Some(count) = window {
                for record in self.ring.list(count) {
                    push_frame(&mut pending, &record);
                }
            }
            debug_assert_eq!(pending.len(), backlog);
            let mut client = Client {
                fd: write_end,
                pending,
                sent: 0,
                oneshot,
            };
            self.conn.reply_status(req, owrt_ubus::status::OK, Some(read_end.as_raw_fd()))?;
            drop(read_end);
            if client.flush() {
                self.clients.push(client);
            }
            return Ok(());
        }
        let total = REPLY_HEADER_LEN
            + window.map_or(0, |count| self.ring.list(count).map(|r| table_len(r.size())).sum::<usize>());
        self.reply.clear();
        self.reply.reserve_exact(total);
        push_reply_header(&mut self.reply, total);
        if let Some(count) = window {
            for record in self.ring.list(count) {
                push_table(&mut self.reply, &record);
            }
        }
        debug_assert_eq!(self.reply.len(), total);
        // A reply past UBUS_MAX_MSGLEN is refused locally (C hands it to
        // ubusd, which drops the client instead). Either way the request
        // fails, but it must fail as this request's status: dropping the
        // connection would cost us the `log` object until `service log restart`.
        let result = if total > owrt_ubus::msg::MAX_MSGLEN - 16 {
            eprintln!("logd-rs: log read reply of {total} bytes exceeds the ubus message limit");
            self.conn.reply_status(req, owrt_ubus::status::INVALID_ARGUMENT, None)
        } else {
            self.conn.reply_data_status(req, &self.reply, owrt_ubus::status::OK)
        };
        if self.reply.capacity() > RETAINED_REPLY {
            self.reply = Vec::new();
        }
        result
    }

    fn handle_write(&mut self, req: &Request) -> io::Result<()> {
        // blobmsg_get_string / strlen operate on bytes. Truncate before
        // normalization, including when the cut splits a UTF-8 character.
        let event = blob::fields(&req.data)
            .find(|f| f.name == "event")
            .and_then(|f| f.as_bytes());
        if let Some(event) = event {
            self.add(&event[..event.len().min(LINE_SIZE - 1)], SOURCE_SYSLOG);
            self.flush_batch();
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

    /// `spinning`: this round was entered from a zero-timeout poll.
    fn drain_syslog(&mut self, spinning: bool) {
        let mut buf = [0u8; LINE_SIZE];
        // A continuously writing producer must not starve streams, ubus or
        // the reconnect deadline. Remaining datagrams keep POLLIN asserted.
        let mut received = 0;
        while received < 256 {
            match self.syslog.recv(&mut buf[..LINE_SIZE - 1]) {
                Ok(0) => break,
                Ok(n) => {
                    self.add(&buf[..n], SOURCE_SYSLOG);
                    received += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // Two datagrams in one wakeup, or one more while spinning, means the
        // producer is still writing.
        self.spin = if received >= 2 || (spinning && received >= 1) { BURST_SPINS } else { 0 };
        self.flush_batch();
    }

    fn drain_kmsg(&mut self) {
        let Some(kmsg) = self.kmsg.as_mut() else {
            return;
        };
        let mut chunk = [0u8; 4096];
        if let Ok(n) = kmsg.read(&mut chunk) {
            self.kmsg_buf.extend_from_slice(&chunk[..n]);
        }
        let mut buf = std::mem::take(&mut self.kmsg_buf);
        let mut start = 0;
        while let Some(pos) = buf[start..].iter().position(|&b| b == b'\n') {
            self.add(&buf[start..start + pos], SOURCE_KLOG);
            start += pos + 1;
        }
        buf.drain(..start);
        self.kmsg_buf = buf;
        self.flush_batch();
    }

    /// Poll set for one loop iteration; returns the first client index.
    fn poll_set(&mut self, with_bus: bool) -> usize {
        self.fds.clear();
        if with_bus {
            self.fds.push(sys::PollFd { fd: self.conn.as_raw_fd(), events: sys::POLLIN, revents: 0 });
        }
        self.fds.push(sys::PollFd { fd: self.syslog.as_raw_fd(), events: sys::POLLIN, revents: 0 });
        if let Some(kmsg) = &self.kmsg {
            self.fds.push(sys::PollFd { fd: kmsg.as_raw_fd(), events: sys::POLLIN, revents: 0 });
        }
        let client_base = self.fds.len();
        self.fds.extend(self.clients.iter().map(Client::poll_fd));
        client_base
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
            let client_base = self.poll_set(false);
            let timeout = retry_at.saturating_duration_since(Instant::now())
                .as_millis().min(1000) as i32;
            if sys::poll_fds(&mut self.fds, timeout).is_ok() {
                flush_ready_clients(&mut self.clients, &self.fds[client_base..]);
                if self.fds[0].revents & sys::POLLIN != 0 {
                    self.drain_syslog(false);
                }
                if self.kmsg.is_some() && self.fds[1].revents & sys::POLLIN != 0 {
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
            let client_base = self.poll_set(true);
            let kmsg_index = self.kmsg.is_some().then_some(2);
            let spinning = self.spin > 0;
            if spinning {
                self.spin -= 1;
            }
            sys::poll_fds(&mut self.fds, if spinning { 0 } else { -1 })?;
            // add()/read may compact or append clients. Apply this snapshot
            // first, while every result still names the stream we polled.
            flush_ready_clients(&mut self.clients, &self.fds[client_base..]);
            if self.fds[0].revents & (sys::POLLIN | sys::POLLERR | sys::POLLHUP) != 0 {
                let incoming = self.conn.read_incoming()?;
                self.handle_incoming(incoming)?;
            }
            if self.fds[1].revents & sys::POLLIN != 0 {
                self.drain_syslog(spinning);
            }
            if let Some(index) = kmsg_index {
                if self.fds[index].revents & sys::POLLIN != 0 {
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
            let _ = writeln!(std::io::stderr(), "logd-rs: {error}");
            std::process::exit(64);
        }
    };
    sys::ignore_signal(sys::SIGPIPE);
    let syslog = match open_syslog(&options.log_socket) {
        Ok(socket) => socket,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "logd-rs: failed to open {}: {error}", options.log_socket);
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
                let _ = writeln!(std::io::stderr(), "logd-rs: failed to open {path}: {error}");
                None
            }
        }
    });
    let mut conn = match Connection::connect(options.ubus_socket.as_deref()) {
        Ok(conn) => conn,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "logd-rs: ubus connect failed: {error}");
            std::process::exit(1);
        }
    };
    let objid = match register_log(&mut conn) {
        Ok(id) => id,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "logd-rs: failed to add object: {error}");
            std::process::exit(1);
        }
    };
    if let Some(user) = &options.user {
        match lookup_user(user) {
            Some((uid, gid)) => {
                if let Err(error) = sys::drop_privileges(uid, gid) {
                    let _ = writeln!(std::io::stderr(), "logd-rs: setuid/setgid failed: {error}");
                    std::process::exit(1);
                }
            }
            None => { let _ = writeln!(std::io::stderr(), "logd-rs: user {user} not found, staying root"); },
        }
    }
    let mut daemon = Daemon {
        ubus_socket: options.ubus_socket.clone(),
        conn,
        objid,
        ring: Ring::new(options.log_size),
        max_stream_pending: stream_pending_limit(options.log_size),
        clients: Vec::new(),
        has_subscribers: false,
        syslog,
        kmsg,
        kmsg_buf: Vec::new(),
        batch: Vec::new(),
        reply: Vec::new(),
        fds: Vec::new(),
        spin: 0,
    };
    if let Err(error) = daemon.run() {
        let _ = writeln!(std::io::stderr(), "logd-rs: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    #[test]
    fn stream_budget_holds_the_most_expensive_full_ring() {
        assert_eq!(stream_pending_limit(128 * 1024), MAX_STREAM_PENDING);
        let capacity = 2048 * 1024;
        let mut ring = Ring::new(capacity);
        // Minimal messages maximize frame overhead relative to arena storage.
        for _ in 0..capacity / (ring::HEAD + 4) + 1 {
            ring.add(b"", 0, 1, 0);
        }
        let backlog: usize = ring.list(0).map(|record| frame_len(record.size())).sum();
        assert!(backlog > MAX_TOTAL_PENDING);
        assert!(backlog <= stream_pending_limit(capacity));
    }

    fn nonblocking(fd: impl AsFd) {
        let flags = rustix::fs::fcntl_getfl(&fd).unwrap();
        rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
    }

    /// A stream client over a pipe, as the daemon creates them.
    fn pair(pending: Vec<u8>, oneshot: bool) -> (File, Client) {
        let (read_end, write_end) = io::pipe().unwrap();
        let write_end = OwnedFd::from(write_end);
        nonblocking(&write_end);
        (File::from(OwnedFd::from(read_end)), Client { fd: write_end, pending, sent: 0, oneshot })
    }

    fn fill_pipe(client: &Client) {
        loop {
            match write_fd(&client.fd, &[b'x'; 65536]) {
                Ok(n) => assert!(n > 0),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("fill pipe: {e}"),
            }
        }
    }

    fn read_available(reader: &mut File) -> Vec<u8> {
        nonblocking(&*reader);
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        bytes
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn stream_pipes_get_the_larger_capacity() {
        let (_reader, client) = pair(Vec::new(), false);
        set_pipe_capacity(&client.fd, PIPE_CAPACITY).unwrap();
        let size = rustix::pipe::fcntl_getpipe_size(&client.fd).unwrap();
        assert_eq!(size, PIPE_CAPACITY as usize);
        // and such a pipe takes a whole 200 KiB burst in one write
        let big = vec![7u8; 200_000];
        assert_eq!(client.write_direct(&big).unwrap(), big.len());
    }

    #[test]
    fn one_streams_hangup_does_not_close_the_next_stream() {
        let (closed, first) = pair(vec![1], false);
        let (mut healthy, second) = pair(b"still connected".to_vec(), false);
        let mut clients = vec![first, second];
        let mut fds: Vec<_> = clients.iter().map(Client::poll_fd).collect();
        drop(closed);
        sys::poll_fds(&mut fds, 1000).unwrap();
        assert_ne!(fds[0].revents & (sys::POLLERR | sys::POLLHUP), 0);
        assert_ne!(fds[1].revents & sys::POLLOUT, 0);
        flush_ready_clients(&mut clients, &fds);
        assert_eq!(clients.len(), 1);
        let mut bytes = [0; 15];
        healthy.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"still connected");
        assert!(read_available(&mut healthy).is_empty());
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
            // Fill the kernel pipe too: a late flush must not make this
            // supposedly stalled consumer healthy by itself.
            fill_pipe(&client);
            slow_readers.push(reader);
            clients.push(client);
        }
        send_to_clients(&mut clients, b"live record", MAX_STREAM_PENDING);
        assert_eq!(clients.len(), 8);
        assert!(clients.iter().map(Client::queued).sum::<usize>() <= MAX_TOTAL_PENDING);
        let mut bytes = [0; 11];
        healthy.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"live record");
        assert!(read_available(&mut healthy).is_empty());
    }

    #[test]
    fn a_batch_reaches_every_stream_once_and_in_order() {
        // Frames of one input round go out as one write per stream; a
        // stream that was already lagging gets them appended after its
        // queue, and nothing is duplicated or reordered.
        let (mut fast, first) = pair(Vec::new(), false);
        let (mut lagging, second) = pair(b"old-backlog|".to_vec(), false);
        let mut clients = vec![first, second];
        let batch: Vec<u8> = (0..300).flat_map(|i| format!("frame-{i:03}|").into_bytes()).collect();
        send_to_clients(&mut clients, &batch, MAX_STREAM_PENDING);
        assert_eq!(clients.len(), 2);
        assert_eq!(read_available(&mut fast), batch);
        let mut expected = b"old-backlog|".to_vec();
        expected.extend_from_slice(&batch);
        assert_eq!(read_available(&mut lagging), expected);
        assert!(clients.iter().all(|c| c.queued() == 0));
        // a second round follows without repeating the first
        send_to_clients(&mut clients, b"next|", MAX_STREAM_PENDING);
        assert_eq!(read_available(&mut fast), b"next|");
        assert_eq!(read_available(&mut lagging), b"next|");
    }

    #[test]
    fn a_full_pipe_queues_the_remainder_and_drains_it_later_in_order() {
        let (mut reader, client) = pair(Vec::new(), false);
        fill_pipe(&client);
        let kernel_held = read_available(&mut reader);
        assert!(!kernel_held.is_empty());
        let mut clients = vec![client];
        // pipe is empty now; a batch larger than the pipe is split between
        // the kernel and the client queue
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        send_to_clients(&mut clients, &big, MAX_STREAM_PENDING);
        assert_eq!(clients.len(), 1);
        let queued = clients[0].queued();
        assert!(queued > 0 && queued < big.len(), "queued {queued}");
        let mut got = read_available(&mut reader);
        assert_eq!(got.len(), big.len() - queued);
        // a later frame joins the queue behind the remainder, not before it
        send_to_clients(&mut clients, b"tail", MAX_STREAM_PENDING);
        while clients[0].queued() > 0 {
            got.extend(read_available(&mut reader));
            let mut fds: Vec<_> = clients.iter().map(Client::poll_fd).collect();
            sys::poll_fds(&mut fds, 1000).unwrap();
            flush_ready_clients(&mut clients, &fds);
            assert_eq!(clients.len(), 1);
        }
        got.extend(read_available(&mut reader));
        let mut expected = big;
        expected.extend_from_slice(b"tail");
        assert_eq!(got, expected);
        assert!(clients[0].pending.capacity() <= RETAINED_QUEUE, "drained queue keeps bounded storage");
    }

    #[test]
    fn oneshot_client_closes_after_its_backlog_even_when_delivered_by_a_batch() {
        let (mut reader, client) = pair(Vec::new(), true);
        let mut clients = vec![client];
        send_to_clients(&mut clients, b"only this", MAX_STREAM_PENDING);
        assert!(clients.is_empty(), "delivered oneshot must close");
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"only this");
    }
}
