//! Blocking ubus connection usable as client and as object server.

use crate::blob::{self, BlobBuf, MsgType};
use crate::msg::{attr, status, ty, Header, Message, MAX_MSGLEN, UBUS_SOCKET};
use crate::sys;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Result of a completed request: status code, DATA payloads (each the packed
/// top-level attrs of one DATA message) and an fd delivered with the STATUS.
#[derive(Debug)]
pub struct Reply {
    pub status: i32,
    pub data: Vec<Vec<u8>>,
    pub fd: Option<OwnedFd>,
}

impl Reply {
    /// Concatenated blobmsg fields carried in the DATA attrs of all replies.
    pub fn fields(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for payload in &self.data {
            for a in blob::iter(payload) {
                if a.id == attr::DATA {
                    out.extend_from_slice(a.payload);
                }
            }
        }
        out
    }
}

/// One object returned by `lookup`.
#[derive(Debug, Default, Clone)]
pub struct LookupEntry {
    pub path: String,
    pub id: u32,
    /// Packed blobmsg fields: one table per method, each field name -> type id.
    pub signature: Vec<u8>,
}

/// An invoke received for one of our objects.
#[derive(Debug)]
pub struct Request {
    pub peer: u32,
    pub seq: u16,
    pub objid: u32,
    pub method: String,
    pub user: Option<String>,
    pub group: Option<String>,
    /// Packed blobmsg fields of the call arguments.
    pub data: Vec<u8>,
    pub fd: Option<OwnedFd>,
    pub no_reply: bool,
}

#[derive(Debug)]
pub enum Incoming {
    Invoke(Request),
    /// ubusd tells us whether our object has subscribers.
    SubscribeState {
        objid: u32,
        active: bool,
    },
    Other(Message),
}

pub struct Connection {
    stream: UnixStream,
    local_id: u32,
    seq: u16,
    pending: VecDeque<Message>,
    /// Read-ahead storage for incoming frames. One recvmsg takes everything
    /// the socket holds (up to INCOMING_BUFFER_SIZE), so a small frame costs
    /// one syscall and frames queued behind it need none. Allocated at the
    /// first read; frames that do not fit use their own storage instead.
    rx: Vec<u8>,
    rx_start: usize,
    rx_end: usize,
    /// Descriptors delivered with read-ahead bytes, keyed by the rx index one
    /// past the recvmsg that carried them. ubusd attaches a descriptor to the
    /// sendmsg that begins its frame and the kernel ends a recvmsg after the
    /// buffer carrying ancillary data, so the frame holding that last byte
    /// owns the descriptor.
    rx_fds: VecDeque<(usize, OwnedFd)>,
    /// Budget for finishing the frame being received; fixed at its first wait.
    rx_deadline: Option<Instant>,
    /// Optional storage returned by a server after it has finished a request.
    spare_request: Option<Request>,
    /// Opt-in bound for daemon reads/replies outside a timed request.
    server_io_timeout: Option<Duration>,
    /// Opt-in cooperative cancellation for short-lived clients. Daemons keep
    /// their existing signal and maintenance policy by leaving this unset.
    cancelled: Option<fn() -> bool>,
    #[cfg(test)]
    notification_pending_peak: (usize, usize, usize),
}

const INCOMING_BUFFER_SIZE: usize = 4096;

/// Where a taken frame's blob (4-byte blob header included) lives.
enum Body {
    Buffered(std::ops::Range<usize>),
    Owned(Vec<u8>),
}

/// Remove the root header without a new allocation. SDK musl memmove falls
/// back to byte copies for this four-byte misalignment; fixed-size loads keep
/// the overlapping move efficient and read each word before overwriting it.
fn remove_root_header(bytes: &mut Vec<u8>) {
    assert!(bytes.len() >= 4);
    let length = bytes.len() - 4;
    let mut index = 0;
    while length - index >= 4 {
        // Read the entire overlapping source block before writing any of it.
        let block: [u8; 4] = bytes[index + 4..index + 4 + 4].try_into().unwrap();
        bytes[index..index + 4].copy_from_slice(&block);
        index += 4;
    }
    while index < length {
        bytes[index] = bytes[index + 4];
        index += 1;
    }
    bytes.truncate(length);
}

/// Reply DATA excludes only the root blob header. Reuse large frame storage;
/// removing its four-byte prefix still moves the payload within that storage.
fn reply_payload(blob: Cow<'_, [u8]>) -> Vec<u8> {
    match blob {
        Cow::Borrowed(bytes) => bytes[4..].to_vec(),
        Cow::Owned(mut bytes) => {
            remove_root_header(&mut bytes);
            bytes
        }
    }
}

#[derive(Debug)]
struct StatusError(i32);

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ubus: {} ({})", status::name(self.0), self.0)
    }
}

impl std::error::Error for StatusError {}

fn ubus_error(code: i32) -> io::Error {
    io::Error::other(StatusError(code))
}

/// Preserve protocol failures for bridges that must return the original
/// status. Transport errors have no ubus status and return None.
pub fn error_status(error: &io::Error) -> Option<i32> {
    error.get_ref()?.downcast_ref::<StatusError>().map(|e| e.0)
}

impl Connection {
    /// A new transport must be admitted and receive its complete HELLO in
    /// one second. Failure drops only this new connection.
    pub fn connect(path: Option<&str>) -> io::Result<Self> {
        Self::connect_timeout(path, Duration::from_secs(1))
    }

    /// Build a new connection within one total admission/HELLO budget.
    /// A zero budget expires immediately; unlike request timeouts it does
    /// not mean an unbounded wait.
    pub fn connect_timeout(path: Option<&str>, timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now().checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "connect timeout too large"))?;
        Self::connect_until(path, deadline, None)
    }

    /// Connect and receive HELLO within an absolute deadline. The callback
    /// must be cheap and nonblocking; it is checked during admission and I/O
    /// waits (at most 10 ms between checks), and before subsequent requests.
    /// Cancellation returns Interrupted. Drop this connection after that
    /// error: a request may already have reached its recipient.
    pub fn connect_interruptible(
        path: Option<&str>,
        deadline: Instant,
        cancelled: fn() -> bool,
    ) -> io::Result<Self> {
        Self::connect_until(path, deadline, Some(cancelled))
    }

    fn connect_until(
        path: Option<&str>,
        deadline: Instant,
        cancelled: Option<fn() -> bool>,
    ) -> io::Result<Self> {
        let stream = crate::connect::stream(path.unwrap_or(UBUS_SOCKET), deadline, cancelled)?;
        let mut conn = Self {
            stream,
            local_id: 0,
            seq: 0,
            pending: VecDeque::new(),
            rx: Vec::new(),
            rx_start: 0,
            rx_end: 0,
            rx_fds: VecDeque::new(),
            rx_deadline: None,
            spare_request: None,
            server_io_timeout: None,
            cancelled,
            #[cfg(test)]
            notification_pending_peak: (0, 0, 0),
        };
        let hello = conn.recv_until(Some(deadline))?;
        if hello.header.ty != ty::HELLO {
            return Err(io::Error::other("ubus: expected HELLO"));
        }
        conn.local_id = hello.header.peer;
        Ok(conn)
    }

    pub fn local_id(&self) -> u32 {
        self.local_id
    }

    /// Bound completing incoming frames and sending replies/notifications.
    /// Daemons must handle a transport failure by returning to maintenance
    /// and reconnecting. Explicit request deadlines keep their own semantics.
    pub fn set_server_io_timeout(&mut self, timeout: Duration) {
        self.server_io_timeout = Some(timeout);
    }

    fn server_deadline(&self) -> Option<Instant> {
        self.server_io_timeout.map(|timeout| Instant::now() + timeout)
    }

    fn server_result<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::TimedOut) {
            let _ = self.shutdown();
        }
        result
    }

    fn server_bound(&self) -> sys::Bound {
        self.server_io_timeout.map_or(sys::Bound::Forever, sys::Bound::Within)
    }

    fn send_server_parts<const N: usize>(&self, parts: [&[u8]; N], fd: Option<RawFd>) -> io::Result<()> {
        self.server_result(sys::send_parts_until(self.as_raw_fd(), parts, fd, self.server_bound()))
    }

    /// A message can be handed out without waiting on the socket: one was
    /// read while awaiting a reply, or a complete frame is already buffered.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty() || self.rx_complete()
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// End this transport even if a forked child still holds a descriptor.
    /// The Connection remains the owner and closes its fd when dropped.
    pub fn shutdown(&self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }

    fn send(&mut self, header: Header, blob: &mut BlobBuf, fd: Option<RawFd>) -> io::Result<()> {
        let body = blob.as_bytes();
        if body.len() > MAX_MSGLEN {
            return Err(ubus_error(status::INVALID_ARGUMENT));
        }
        self.send_server_parts([&header.encode(), body], fd)
    }

    fn rx_reset(&mut self) {
        self.rx_start = 0;
        self.rx_end = 0;
        self.rx_fds.clear();
        self.rx_deadline = None;
    }

    /// Buffer at least `need` bytes of the frame at rx_start, reading whatever
    /// the socket holds. With `start`, an empty buffer on an idle socket gives
    /// Ok(false) instead of waiting. `deadline` is a caller's fixed bound; a
    /// server budget starts only when a wait becomes necessary.
    fn rx_fill(&mut self, need: usize, start: bool, deadline: Option<Instant>) -> io::Result<bool> {
        debug_assert!(need <= INCOMING_BUFFER_SIZE);
        if self.rx.is_empty() {
            self.rx = vec![0u8; INCOMING_BUFFER_SIZE];
        }
        let bound = deadline.map_or_else(|| self.server_bound(), sys::Bound::At);
        let sock = self.stream.as_raw_fd();
        while self.rx_end - self.rx_start < need {
            if self.rx_start + need > INCOMING_BUFFER_SIZE {
                self.rx.copy_within(self.rx_start..self.rx_end, 0);
                for (mark, _) in &mut self.rx_fds {
                    *mark -= self.rx_start;
                }
                self.rx_end -= self.rx_start;
                self.rx_start = 0;
            }
            let idle = self.rx_end == self.rx_start;
            if let Err(error) = sys::check_cancelled(self.cancelled)
                .and_then(|()| sys::check_deadline(deadline.or(self.rx_deadline)))
            {
                self.rx_reset();
                return Err(sys::after_progress(error, !idle));
            }
            match sys::recv_into(
                sock,
                &mut self.rx[self.rx_end..],
                true,
                bound.nonblocking() || self.cancelled.is_some() || (start && idle),
            ) {
                Ok((0, _)) => {
                    self.rx_reset();
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ubus connection closed"));
                }
                Ok((got, fd)) => {
                    self.rx_end += got;
                    if let Some(fd) = fd {
                        self.rx_fds.push_back((self.rx_end, fd));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if start && idle {
                        return Ok(false);
                    }
                    let wait = bound.deadline(&mut self.rx_deadline);
                    if let Err(e) =
                        sys::wait_until_cancelled(sock, sys::POLLIN, wait, self.cancelled)
                    {
                        // The frame cannot complete: release its bytes and any
                        // descriptor that arrived with them.
                        self.rx_reset();
                        return Err(sys::after_progress(e, !idle));
                    }
                }
                Err(e) => {
                    self.rx_reset();
                    return Err(e);
                }
            }
        }
        Ok(true)
    }

    /// Header and blob length of the frame at rx_start (12 bytes buffered).
    fn rx_frame(&self) -> io::Result<(Header, usize)> {
        let s = self.rx_start;
        let header = Header::decode(self.rx[s..s + Header::LEN].try_into().unwrap())
            .ok_or_else(|| io::Error::other("ubus: bad header"))?;
        let id_len = u32::from_be_bytes(self.rx[s + Header::LEN..s + Header::LEN + 4].try_into().unwrap());
        let raw_len = (id_len & 0x00ff_ffff) as usize;
        if !(4..=MAX_MSGLEN).contains(&raw_len) {
            return Err(io::Error::other("ubus: bad blob length"));
        }
        Ok((header, raw_len))
    }

    /// A complete frame is buffered, or a framing error awaits the next read.
    fn rx_complete(&self) -> bool {
        let buffered = self.rx_end - self.rx_start;
        if buffered < Header::LEN + 4 {
            return false;
        }
        match self.rx_frame() {
            Ok((_, len)) => Header::LEN + len <= buffered,
            Err(_) => true,
        }
    }

    /// The descriptor owned by the frame spanning rx indices `start..end`.
    fn rx_take_fd(&mut self, start: usize, end: usize) -> Option<OwnedFd> {
        while self.rx_fds.front().is_some_and(|(mark, _)| *mark <= start) {
            self.rx_fds.pop_front();
        }
        if self.rx_fds.front().is_some_and(|(mark, _)| *mark <= end) {
            return self.rx_fds.pop_front().map(|(_, fd)| fd);
        }
        None
    }

    /// Take the next frame: header, its descriptor and its blob. None only
    /// with `start` when the buffer is empty and the socket idle.
    fn take_frame(&mut self, start: bool, deadline: Option<Instant>) -> io::Result<Option<(Header, Option<OwnedFd>, Body)>> {
        if !self.rx_fill(Header::LEN + 4, start, deadline)? {
            return Ok(None);
        }
        let (header, len) = match self.rx_frame() {
            Ok(frame) => frame,
            Err(e) => {
                self.rx_reset();
                return Err(e);
            }
        };
        let total = Header::LEN + len;
        let (start, body) = if total <= INCOMING_BUFFER_SIZE {
            self.rx_fill(total, false, deadline)?;
            let s = self.rx_start;
            self.rx_start = s + total;
            (s, Body::Buffered(s + Header::LEN..s + total))
        } else {
            let s = self.rx_start;
            let mut blob = vec![0u8; len];
            let have = (self.rx_end - s - Header::LEN).min(len);
            blob[..have].copy_from_slice(&self.rx[s + Header::LEN..s + Header::LEN + have]);
            self.rx_start = s + Header::LEN + have;
            if have < len {
                let rest = deadline.or_else(|| self.server_deadline());
                sys::recv_exact_until_cancelled(
                    self.stream.as_raw_fd(),
                    &mut blob[have..],
                    false,
                    rest,
                    self.cancelled,
                )
                .map_err(sys::partial_timeout)?;
            }
            (s, Body::Owned(blob))
        };
        let fd = self.rx_take_fd(start, start + total);
        self.rx_deadline = None;
        if self.rx_start == self.rx_end {
            self.rx_reset();
        }
        Ok(Some((header, fd, body)))
    }

    fn blob_of(&self, body: Body) -> Vec<u8> {
        match body {
            Body::Buffered(range) => self.rx[range].to_vec(),
            Body::Owned(blob) => blob,
        }
    }

    #[cfg(test)]
    fn recv(&mut self) -> io::Result<Message> {
        self.recv_until(None)
    }

    fn recv_until(&mut self, deadline: Option<Instant>) -> io::Result<Message> {
        let (header, fd, body) = self.take_frame(false, deadline)?.expect("a waiting frame read yields a frame");
        Ok(Message { header, blob: self.blob_of(body), fd })
    }
    fn next_seq(&mut self) -> u16 {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        self.seq
    }

    /// Send a request and collect DATA replies until the matching STATUS.
    fn request(
        &mut self,
        cmd: u8,
        peer: u32,
        blob: &mut BlobBuf,
        fd: Option<RawFd>,
        timeout_ms: i32,
    ) -> io::Result<Reply> {
        let mut data = Vec::new();
        let mut reply = self.request_with_data(cmd, peer, blob, fd, timeout_ms,
            |blob| data.push(reply_payload(blob)))?;
        reply.data = data;
        Ok(reply)
    }

    /// Consume each DATA blob, including its root header. Small frames borrow
    /// receive storage; large frames transfer ownership. Scalar lookups need no
    /// retained metadata/signature, but still wait for final STATUS.
    fn request_with_data(
        &mut self,
        cmd: u8,
        peer: u32,
        blob: &mut BlobBuf,
        fd: Option<RawFd>,
        timeout_ms: i32,
        mut on_data: impl FnMut(Cow<'_, [u8]>),
    ) -> io::Result<Reply> {
        // One deadline covers sending and every byte of every reply. A
        // readable prefix alone must not turn a bounded call into a hang.
        let deadline = (timeout_ms > 0)
            .then(|| Instant::now() + Duration::from_millis(timeout_ms as u64));
        let result = self.request_until(cmd, peer, blob, fd, deadline, &mut on_data);
        if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::TimedOut) {
            // Only a partial frame loses its framing boundary. A clean
            // request timeout must keep object servers connected: rpcd may
            // be awaiting service.event while an apply rollback is armed.
            if result.as_ref().is_err_and(sys::is_partial_timeout) {
                let _ = self.shutdown();
            }
            return Err(ubus_error(status::TIMEOUT));
        }
        result
    }

    fn request_until(&mut self, cmd: u8, peer: u32, blob: &mut BlobBuf, fd: Option<RawFd>, deadline: Option<Instant>, on_data: &mut impl FnMut(Cow<'_, [u8]>)) -> io::Result<Reply> {
        if blob.as_bytes().len() > MAX_MSGLEN {
            return Err(ubus_error(status::INVALID_ARGUMENT));
        }
        let seq = self.next_seq();
        sys::send_parts_until_cancelled(
            self.as_raw_fd(),
            [&Header { ty: cmd, seq, peer }.encode(), blob.as_bytes()],
            fd,
            deadline.into(),
            self.cancelled,
        )?;
        let mut reply = Reply {
            status: status::UNKNOWN_ERROR,
            data: Vec::new(),
            fd: None,
        };
        loop {
            sys::check_cancelled(self.cancelled)?;
            sys::check_deadline(deadline)?;
            let (header, fd, body) = self.take_frame(false, deadline)?
                .expect("a waiting frame read yields a frame");
            if header.seq != seq || header.peer != peer
                || !matches!(header.ty, ty::DATA | ty::STATUS)
            {
                // Only this synchronous request is active. libubus discards
                // replies for completed/expired requests, including their FDs.
                // Keep invokes and subscription changes for the object owner.
                if matches!(header.ty, ty::DATA | ty::STATUS) {
                    continue;
                }
                let blob = self.blob_of(body);
                self.pending.push_back(Message { header, blob, fd });
                continue;
            }
            // Matching replies need no intermediate owned Message. DATA
            // is consumed by the caller; STATUS is consumed in place.
            match header.ty {
                ty::DATA => on_data(match body {
                    Body::Buffered(range) => Cow::Borrowed(&self.rx[range]),
                    Body::Owned(bytes) => Cow::Owned(bytes),
                }),
                ty::STATUS => {
                    let bytes = match &body {
                        Body::Buffered(range) => &self.rx[range.clone()],
                        Body::Owned(bytes) => bytes,
                    };
                    // libubus-req.c defaults a STATUS without a status attr
                    // to UBUS_STATUS_INVALID_ARGUMENT.
                    reply.status = Message::attrs_from(bytes)[attr::STATUS as usize]
                        .and_then(|a| a.as_u32()).map(|v| v as i32)
                        .unwrap_or(status::INVALID_ARGUMENT);
                    reply.fd = fd;
                    return Ok(reply);
                }
                _ => unreachable!("only matching DATA and STATUS reach this point"),
            }
        }
    }

    /// Resolve an object path to its id.
    pub fn lookup_id(&mut self, path: &str, timeout_ms: i32) -> io::Result<u32> {
        let deadline =
            (timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(timeout_ms as u64));
        let result = self.lookup_id_deadline(path, deadline);
        if result
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::TimedOut)
        {
            if result.as_ref().is_err_and(sys::is_partial_timeout) {
                let _ = self.shutdown();
            }
            return Err(ubus_error(status::TIMEOUT));
        }
        result
    }

    /// Resolve a path using the caller's absolute deadline. Unlike lookup_id,
    /// a local deadline remains io::ErrorKind::TimedOut, distinct from a
    /// remote UBUS_STATUS_TIMEOUT. An interrupted or expired call closes the
    /// transport so an abandoned partial request cannot be reused.
    pub fn lookup_id_until(&mut self, path: &str, deadline: Instant) -> io::Result<u32> {
        let result = self.lookup_id_deadline(path, Some(deadline));
        self.absolute_result(result)
    }

    fn absolute_result<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if result.as_ref().is_err_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            )
        }) {
            let _ = self.shutdown();
            self.rx_reset();
            self.pending.clear();
        }
        result
    }

    fn lookup_id_deadline(&mut self, path: &str, deadline: Option<Instant>) -> io::Result<u32> {
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, path);
        let mut found = None;
        let reply = self.request_until(ty::LOOKUP, 0, &mut b, None, deadline, &mut |blob| {
            // Keep the first usable matching DATA frame, as the collected path did.
            if found.is_some() { return; }
            let mut id = None;
            let mut matches = false;
            for a in blob::iter(&blob[4..]) {
                if a.id == attr::OBJID {
                    id = a.as_u32();
                } else if a.id == attr::OBJPATH {
                    matches = a.as_str() == Some(path);
                }
            }
            if matches { found = id; }
        })?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        found.ok_or_else(|| ubus_error(status::NOT_FOUND))
    }

    /// List objects (all when `path` is None) with id and raw signature fields.
    pub fn lookup(&mut self, path: Option<&str>, timeout_ms: i32) -> io::Result<Vec<LookupEntry>> {
        let mut b = BlobBuf::new();
        if let Some(path) = path {
            b.put_string(attr::OBJPATH, path);
        }
        let reply = self.request(ty::LOOKUP, 0, &mut b, None, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        let mut out = Vec::new();
        for payload in &reply.data {
            let mut entry = LookupEntry::default();
            for a in blob::iter(payload) {
                match a.id {
                    attr::OBJID => entry.id = a.as_u32().unwrap_or(0),
                    attr::OBJPATH => entry.path = a.as_str().unwrap_or("").to_owned(),
                    attr::SIGNATURE => entry.signature = a.payload.to_vec(),
                    _ => {}
                }
            }
            if !entry.path.is_empty() {
                out.push(entry);
            }
        }
        Ok(out)
    }

    /// Like `invoke` but returns the ubus status instead of an io::Error.
    pub fn invoke_status(
        &mut self,
        objid: u32,
        method: &str,
        args: &[u8],
        timeout_ms: i32,
    ) -> io::Result<Reply> {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, objid).put_string(attr::METHOD, method);
        b.put(attr::DATA, args);
        self.request(ty::INVOKE, objid, &mut b, None, timeout_ms)
    }

    /// Invoke within the same absolute budget used for connect and lookup.
    /// Waits for the final matching STATUS; DATA is consumed without retaining
    /// it. Local timeout/cancellation closes the transport and is never retried.
    pub fn invoke_status_until(
        &mut self,
        objid: u32,
        method: &str,
        args: &[u8],
        deadline: Instant,
    ) -> io::Result<i32> {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, objid)
            .put_string(attr::METHOD, method);
        b.put(attr::DATA, args);
        let result = self
            .request_until(ty::INVOKE, objid, &mut b, None, Some(deadline), &mut |_| {})
            .map(|reply| reply.status);
        self.absolute_result(result)
    }

    /// Invoke `method` on object `objid`; `args` are packed blobmsg fields.
    pub fn invoke(
        &mut self,
        objid: u32,
        method: &str,
        args: &[u8],
        timeout_ms: i32,
    ) -> io::Result<Reply> {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, objid)
            .put_string(attr::METHOD, method);
        b.put(attr::DATA, args);
        let reply = self.request(ty::INVOKE, objid, &mut b, None, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        Ok(reply)
    }

    /// Unregister an object by the id `add_object` returned. Needed when a
    /// config section goes away: leaving the object registered would keep
    /// answering for something that no longer exists.
    pub fn remove_object(&mut self, id: u32, timeout_ms: i32) -> io::Result<()> {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, id);
        let reply = self.request(ty::REMOVE_OBJECT, 0, &mut b, None, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        Ok(())
    }

    /// Register an object. `methods` lists (name, [(arg name, arg type)]).
    /// Returns the object id assigned by ubusd.
    pub fn add_object(
        &mut self,
        path: &str,
        methods: &[(&str, &[(&str, MsgType)])],
        timeout_ms: i32,
    ) -> io::Result<u32> {
        self.add_object_bytes(path.as_bytes(), methods, timeout_ms)
    }

    /// Register an opaque C-string object path without a UTF-8 conversion.
    /// Bytes after the first NUL are not part of the path, matching libubus.
    pub fn add_object_bytes(
        &mut self,
        path: &[u8],
        methods: &[(&str, &[(&str, MsgType)])],
        timeout_ms: i32,
    ) -> io::Result<u32> {
        self.add_object_maybe_anonymous(Some(path), methods, None, timeout_ms).map(|(id, _)| id)
    }

    /// Register an object and retain its method type for other objects on this
    /// connection. With `type_id`, reuse that live type instead of `methods`.
    /// The caller must discard the type id when reconnecting and keep an
    /// object of that type registered for as long as it is reused.
    pub fn add_object_typed(
        &mut self,
        path: &str,
        methods: &[(&str, &[(&str, MsgType)])],
        type_id: Option<u32>,
        timeout_ms: i32,
    ) -> io::Result<(u32, u32)> {
        if type_id == Some(0) {
            return Err(ubus_error(status::INVALID_ARGUMENT));
        }
        let (id, assigned_type) = self.add_object_maybe_anonymous(Some(path.as_bytes()), methods, type_id, timeout_ms)?;
        // ubusd returns OBJTYPE only when the request supplied SIGNATURE.
        // A reused type remains the connection-scoped id supplied by us.
        let assigned_type = assigned_type.or(type_id).filter(|id| *id != 0).ok_or_else(|| ubus_error(status::NO_DATA))?;
        Ok((id, assigned_type))
    }

    /// Register an object with no path. ubusd assigns an id but the object is
    /// not listed and cannot be invoked by name -- which is what a subscriber
    /// is. `ubus_register_subscriber` does exactly this before subscribing.
    pub fn add_anonymous_object(&mut self, timeout_ms: i32) -> io::Result<u32> {
        self.add_object_maybe_anonymous(None, &[], None, timeout_ms).map(|(id, _)| id)
    }

    fn add_object_maybe_anonymous(
        &mut self,
        path: Option<&[u8]>,
        methods: &[(&str, &[(&str, MsgType)])],
        type_id: Option<u32>,
        timeout_ms: i32,
    ) -> io::Result<(u32, Option<u32>)> {
        let mut b = BlobBuf::new();
        if let Some(path) = path {
            let end = path.iter().position(|byte| *byte == 0).unwrap_or(path.len());
            b.put_string_bytes(attr::OBJPATH, &path[..end]);
        }
        if let Some(id) = type_id {
            b.put_u32(attr::OBJTYPE, id);
        } else {
            let sig = b.nest_start(attr::SIGNATURE);
            for (name, policy) in methods {
                let table = b.msg_open_table(name);
                for (arg, kind) in *policy {
                    b.msg_u32(arg, *kind as u32);
                }
                b.msg_close(table);
            }
            b.nest_end(sig);
        }
        let reply = self.request(ty::ADD_OBJECT, 0, &mut b, None, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        let mut object_id = None;
        let mut assigned_type = None;
        for payload in &reply.data {
            for a in blob::iter(payload) {
                if a.id == attr::OBJID && object_id.is_none() {
                    object_id = a.as_u32();
                } else if a.id == attr::OBJTYPE && assigned_type.is_none() {
                    assigned_type = a.as_u32();
                }
            }
        }
        object_id.map(|id| (id, assigned_type)).ok_or_else(|| ubus_error(status::NO_DATA))
    }

    /// ubusd's built-in event object. Subscribing to it is how libubus
    /// implements `ubus_register_event_handler`.
    pub const SYSTEM_OBJECT_EVENT: u32 = 1;

    /// `ubus_register_event_handler`: ask ubusd to deliver events matching
    /// `pattern` (or every event when None) to our object `objid`.
    ///
    /// This is NOT a subscribe -- it is an invoke of `register` on ubusd's
    /// event object, and the events then arrive as INVOKEs on `objid` whose
    /// method is the event name. Subscribing to object 1 instead silently
    /// delivers nothing.
    pub fn register_event_handler(
        &mut self,
        objid: u32,
        pattern: Option<&str>,
        timeout_ms: i32,
    ) -> io::Result<()> {
        let mut b = BlobBuf::new();
        b.msg_u32("object", objid);
        if let Some(p) = pattern {
            b.msg_string("pattern", p);
        }
        let fields = b.payload().to_vec();
        let reply =
            self.invoke_status(Self::SYSTEM_OBJECT_EVENT, "register", &fields, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        Ok(())
    }

    /// Subscribe our object `objid` to notifications from `target`.
    /// `ubus_subscribe(ctx, sub, target)`.
    ///
    /// A notification then arrives as an ordinary INVOKE addressed to
    /// `objid`, with the notification type in the method field -- which is
    /// why a subscriber needs no methods of its own.
    pub fn subscribe(&mut self, objid: u32, target: u32, timeout_ms: i32) -> io::Result<()> {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, objid);
        b.put_u32(attr::TARGET, target);
        let reply = self.request(ty::SUBSCRIBE, 0, &mut b, None, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        Ok(())
    }

    /// Ask ubusd to stop sending `target`'s notifications to `objid`.
    pub fn unsubscribe(&mut self, objid: u32, target: u32, timeout_ms: i32) -> io::Result<()> {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, objid);
        b.put_u32(attr::TARGET, target);
        let reply = self.request(ty::UNSUBSCRIBE, 0, &mut b, None, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        Ok(())
    }

    /// Send a notification to subscribers of our object (no reply requested).
    pub fn notify(&mut self, objid: u32, kind: &str, fields: &[u8]) -> io::Result<()> {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, objid).put_string(attr::METHOD, kind);
        b.put(attr::DATA, fields).put_u8(attr::NO_REPLY, 1);
        let seq = self.next_seq();
        self.send(
            Header {
                ty: ty::NOTIFY,
                seq,
                peer: objid,
            },
            &mut b,
            None,
        )
    }

    /// Notify and stream DATA from the subscribers named by ubusd's STATUS.
    /// The callback receives packed blobmsg fields and must be nonblocking.
    /// True means every listed subscriber completed; false is a clean deadline
    /// expiry. Subscriber status codes do not change completion, as in libubus.
    /// Unrelated invokes/subscription changes remain pending for the owner.
    /// A supplied cancellation callback applies only to this call and takes
    /// precedence over the connection callback. Cancel/partial-frame failure
    /// shuts down this transport; the caller must then drop the Connection.
    pub fn notify_with_data_until(
        &mut self,
        objid: u32,
        kind: &str,
        fields: &[u8],
        deadline: Instant,
        cancelled: Option<fn() -> bool>,
        mut on_data: impl FnMut(&[u8]),
    ) -> io::Result<bool> {
        let previous_cancelled = self.cancelled;
        self.cancelled = cancelled.or(previous_cancelled);
        let result = self.notify_data_until(objid, kind, fields, deadline, &mut on_data);
        self.cancelled = previous_cancelled;
        match result {
            Err(error) if error.kind() == io::ErrorKind::TimedOut && !sys::is_partial_timeout(&error) => Ok(false),
            Err(error) => {
                let _ = self.shutdown();
                self.rx_reset();
                self.pending.clear();
                Err(error)
            }
            result => result,
        }
    }

    fn notify_data_until(
        &mut self,
        objid: u32,
        kind: &str,
        fields: &[u8],
        deadline: Instant,
        on_data: &mut impl FnMut(&[u8]),
    ) -> io::Result<bool> {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, objid).put_string(attr::METHOD, kind);
        b.put(attr::DATA, fields);
        if b.as_bytes().len() > MAX_MSGLEN {
            return Err(ubus_error(status::INVALID_ARGUMENT));
        }
        let seq = self.next_seq();
        sys::send_parts_until_cancelled(
            self.as_raw_fd(),
            [&Header { ty: ty::NOTIFY, seq, peer: objid }.encode(), b.as_bytes()],
            None,
            Some(deadline).into(),
            self.cancelled,
        )?;
        // Exact libubus UBUS_MAX_NOTIFY_PEERS, plus the broker/object slot.
        let mut peers = [0u32; 17];
        peers[0] = objid;
        let mut pending = 1u32;
        let mut pending_bytes: usize = self.pending.iter().map(|message| message.blob.len()).sum();
        while pending != 0 {
            sys::check_cancelled(self.cancelled)?;
            sys::check_deadline(Some(deadline))?;
            let (header, fd, body) = self.take_frame(false, Some(deadline))?
                .expect("a waiting frame read yields a frame");
            if matches!(header.ty, ty::DATA | ty::STATUS) {
                // libubus drops replies not belonging to an active request.
                // This also consumes late DATA/status after a previous timeout.
                if header.seq != seq {
                    continue;
                }
                let Some(index) = peers.iter().enumerate().position(|(index, peer)|
                    pending & (1 << index) != 0 && *peer == header.peer) else {
                    continue;
                };
                let bytes = match &body {
                    Body::Buffered(range) => &self.rx[range.clone()],
                    Body::Owned(bytes) => bytes,
                };
                let attrs = Message::attrs_from(bytes);
                if header.ty == ty::DATA {
                    if let Some(data) = attrs[attr::DATA as usize] {
                        on_data(data.payload);
                    }
                } else {
                    pending &= !(1 << index);
                    if index == 0 {
                        if let Some(subscribers) = attrs[attr::SUBSCRIBERS as usize] {
                            let mut index = 1;
                            for subscriber in blob::iter(subscribers.payload) {
                                // blob_check_type(BLOB_ATTR_INT32) requires 4 bytes.
                                if subscriber.payload.len() != 4 {
                                    continue;
                                }
                                peers[index] = u32::from_be_bytes(subscriber.payload.try_into().unwrap());
                                pending |= 1 << index;
                                index += 1;
                                if index == peers.len() {
                                    break;
                                }
                            }
                        }
                    }
                }
                // Notification DATA/STATUS never transfer descriptor ownership
                // to the callback. Any attached fd closes here or on continue.
                drop(fd);
            } else {
                let blob = self.blob_of(body);
                // An idle owner cannot drain this queue until notification
                // completion. Bound that temporary backlog and its retained FDs.
                if self.pending.len() >= 128 || pending_bytes + blob.len() > MAX_MSGLEN {
                    return Err(io::Error::new(io::ErrorKind::OutOfMemory, "ubus notification pending queue limit"));
                }
                pending_bytes += blob.len();
                self.pending.push_back(Message { header, blob, fd });
                #[cfg(test)]
                {
                    self.notification_pending_peak.0 = self.notification_pending_peak.0.max(self.pending.len());
                    self.notification_pending_peak.1 = self.notification_pending_peak.1.max(pending_bytes);
                    self.notification_pending_peak.2 = self.notification_pending_peak.2.max(self.pending.iter().filter(|message| message.fd.is_some()).count());
                }
            }
        }
        Ok(true)
    }

    /// Next incoming message for our objects. `timeout_ms` < 0 waits forever;
    /// returns Ok(None) on timeout.
    pub fn next_incoming(&mut self, timeout_ms: i32) -> io::Result<Option<Incoming>> {
        if !self.has_pending() && !sys::wait_readable(self.stream.as_raw_fd(), timeout_ms)? {
            return Ok(None);
        }
        self.read_incoming().map(Some)
    }

    /// Drain one message if one is already readable (used after poll()).
    pub fn read_incoming(&mut self) -> io::Result<Incoming> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Self::classify(message));
        }
        let result = self.take_frame(false, None)
            .map(|frame| self.incoming(frame.expect("a waiting frame read yields a frame")));
        self.server_result(result)
    }

    /// Read a frame without a separate readiness wait when its first byte is
    /// already available. An empty socket returns None; a started frame uses
    /// the existing blocking completion rules. Does not change socket flags.
    pub fn incoming_if_started(&mut self) -> io::Result<Option<Incoming>> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Some(Self::classify(message)));
        }
        let result = self.take_frame(true, None).map(|frame| frame.map(|frame| self.incoming(frame)));
        self.server_result(result)
    }

    /// Consume only bytes already available, retaining a partial frame for a
    /// later poll-owner turn. The ordinary blocking client APIs stay intact.
    /// At most one validated MAX_MSGLEN frame is buffered; attached descriptors
    /// remain owned by that frame and close with this connection on failure.
    pub fn incoming_if_complete(&mut self) -> io::Result<Option<Incoming>> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Some(Self::classify(message)));
        }
        let result = self.read_available_frame();
        if result.is_err() {
            self.rx_reset();
        }
        let result = result.map(|frame| frame.map(|frame| self.incoming(frame)));
        self.server_result(result)
    }

    fn read_available_frame(&mut self) -> io::Result<Option<(Header, Option<OwnedFd>, Body)>> {
        if self.rx.is_empty() {
            self.rx = vec![0; INCOMING_BUFFER_SIZE];
        }
        for _ in 0..128 {
            let have = self.rx_end - self.rx_start;
            let need = if have < Header::LEN + 4 {
                Header::LEN + 4
            } else {
                Header::LEN + self.rx_frame()?.1
            };
            if have >= need {
                // Every byte is in rx, so take_frame performs no waiting I/O.
                return self.take_frame(true, None);
            }
            if self.rx_start + need > self.rx.len() {
                self.rx.copy_within(self.rx_start..self.rx_end, 0);
                for (mark, _) in &mut self.rx_fds {
                    *mark -= self.rx_start;
                }
                self.rx_end -= self.rx_start;
                self.rx_start = 0;
                if need > self.rx.len() {
                    self.rx.resize(need, 0);
                }
            }
            match sys::recv_into(self.stream.as_raw_fd(), &mut self.rx[self.rx_end..], true, true) {
                Ok((0, _)) => {
                    self.rx_reset();
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ubus connection closed"));
                }
                Ok((count, fd)) => {
                    self.rx_end += count;
                    if let Some(fd) = fd {
                        self.rx_fds.push_back((self.rx_end, fd));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => {
                    self.rx_reset();
                    return Err(error);
                }
            }
        }
        Ok(None)
    }

    fn incoming(&mut self, (header, fd, body): (Header, Option<OwnedFd>, Body)) -> Incoming {
        if header.ty == ty::INVOKE {
            // Decode straight from the read-ahead buffer into retained storage.
            let spare = self.spare_request.take();
            let blob: &[u8] = match &body {
                Body::Buffered(range) => &self.rx[range.clone()],
                Body::Owned(blob) => blob,
            };
            return Incoming::Invoke(Self::decode_request(header, blob, fd, spare));
        }
        Self::classify(Message { header, blob: self.blob_of(body), fd })
    }
    /// Return storage only after the caller has finished using the request.
    /// At most one small request is retained; descriptors are closed now.
    pub fn recycle_request(&mut self, mut req: Request) {
        req.fd = None;
        let capacity = req.method.capacity() + req.data.capacity()
            + req.user.as_ref().map_or(0, String::capacity)
            + req.group.as_ref().map_or(0, String::capacity);
        if capacity <= INCOMING_BUFFER_SIZE {
            req.method.clear();
            req.data.clear();
            if let Some(user) = &mut req.user { user.clear(); }
            if let Some(group) = &mut req.group { group.clear(); }
            self.spare_request = Some(req);
        }
    }

    fn decode_request(header: Header, blob: &[u8], fd: Option<OwnedFd>, spare: Option<Request>) -> Request {
        let attrs = Message::attrs_from(blob);
        let objid = attrs[attr::OBJID as usize].and_then(|a| a.as_u32());
        let mut req = spare.unwrap_or_else(|| Request {
            peer: 0, seq: 0, objid: 0, method: String::new(), user: None, group: None,
            data: Vec::new(), fd: None, no_reply: false,
        });
        let method = attrs[attr::METHOD as usize]
            .and_then(|a| a.as_str())
            .unwrap_or("");
        method.clone_into(&mut req.method);
        for (id, slot) in [(attr::USER, &mut req.user), (attr::GROUP, &mut req.group)] {
            if let Some(value) = attrs[id as usize].and_then(|a| a.as_str()) {
                value.clone_into(slot.get_or_insert_with(String::new));
            } else {
                *slot = None;
            }
        }
        let data = attrs[attr::DATA as usize]
            .map(|a| a.payload)
            .unwrap_or_default();
        data.clone_into(&mut req.data);
        let no_reply = attrs[attr::NO_REPLY as usize]
            .and_then(|a| a.as_u32())
            .unwrap_or(0)
            != 0;
        req.peer = header.peer;
        req.seq = header.seq;
        req.objid = objid.unwrap_or(0);
        req.fd = fd;
        req.no_reply = no_reply;
        req
    }

    fn classify(mut message: Message) -> Incoming {
        if message.header.ty == ty::INVOKE {
            let fd = message.fd.take();
            return Incoming::Invoke(Self::decode_request(message.header, &message.blob, fd, None));
        }
        let attrs = message.attrs();
        let objid = attrs[attr::OBJID as usize].and_then(|a| a.as_u32());
        match message.header.ty {
            ty::NOTIFY | ty::UNSUBSCRIBE => match (objid, attrs[attr::ACTIVE as usize]) {
                (Some(objid), Some(active)) => Incoming::SubscribeState {
                    objid,
                    active: active.as_u32().unwrap_or(0) != 0,
                },
                _ => Incoming::Other(message),
            },
            _ => Incoming::Other(message),
        }
    }

    /// Send one DATA reply (packed blobmsg fields) for `req`.
    pub fn reply_data(&mut self, req: &Request, fields: &[u8]) -> io::Result<()> {
        // The root, OBJID and DATA headers occupy 16 bytes. For aligned
        // fields, send that fixed prefix beside the caller's storage instead
        // of allocating and copying a second complete reply.
        if fields.len() > MAX_MSGLEN - 16 {
            return Err(ubus_error(status::INVALID_ARGUMENT));
        }
        if fields.len().is_multiple_of(4) {
            let prefix = Self::data_prefix(req, fields.len());
            return self.send_server_parts([&prefix, fields], None);
        }
        // Callers can also provide unaligned raw fields. Keep the codec's
        // padding semantics for that less common case.
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, req.objid).put(attr::DATA, fields);
        self.send(
            Header {
                ty: ty::DATA,
                seq: req.seq,
                peer: req.peer,
            },
            &mut b,
            None,
        )
    }

    fn data_prefix(req: &Request, len: usize) -> [u8; 24] {
        let mut prefix = [0u8; 24];
        prefix[..8].copy_from_slice(&Header { ty: ty::DATA, seq: req.seq, peer: req.peer }.encode());
        prefix[8..12].copy_from_slice(&((16 + len) as u32).to_be_bytes());
        prefix[12..16].copy_from_slice(&((attr::OBJID << 24) | 8).to_be_bytes());
        prefix[16..20].copy_from_slice(&req.objid.to_be_bytes());
        prefix[20..24].copy_from_slice(&((attr::DATA << 24) | (4 + len) as u32).to_be_bytes());
        prefix
    }

    fn status_frame(req: &Request, code: i32) -> [u8; 28] {
        let mut frame = [0u8; 28];
        frame[..8].copy_from_slice(&Header { ty: ty::STATUS, seq: req.seq, peer: req.peer }.encode());
        frame[8..12].copy_from_slice(&20u32.to_be_bytes());
        frame[12..16].copy_from_slice(&((attr::STATUS << 24) | 8).to_be_bytes());
        frame[16..20].copy_from_slice(&(code as u32).to_be_bytes());
        frame[20..24].copy_from_slice(&((attr::OBJID << 24) | 8).to_be_bytes());
        frame[24..28].copy_from_slice(&req.objid.to_be_bytes());
        frame
    }

    /// Send a single DATA reply followed by its final STATUS, with no fd.
    /// The stream carries the same two frames; one sendmsg usually suffices.
    pub fn reply_data_status(&mut self, req: &Request, fields: &[u8], code: i32) -> io::Result<()> {
        if !req.no_reply && fields.len().is_multiple_of(4) && fields.len() <= MAX_MSGLEN - 16 {
            let prefix = Self::data_prefix(req, fields.len());
            let status = Self::status_frame(req, code);
            return self.send_server_parts([&prefix, fields, &status], None);
        }
        // Retain padding, no_reply and the existing best-effort final status
        // when a caller supplies an oversized DATA reply.
        let data = self.reply_data(req, fields);
        let status = self.reply_status(req, code, None);
        data.and(status)
    }

    /// Finish `req` with a status code and an optional fd for the caller.
    pub fn reply_status(&mut self, req: &Request, code: i32, fd: Option<RawFd>) -> io::Result<()> {
        if req.no_reply {
            return Ok(());
        }
        let frame = Self::status_frame(req, code);
        self.send_server_parts([&frame[..8], &frame[8..]], fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn pair() -> (Connection, Connection) {
        let (a, b) = UnixStream::pair().unwrap();
        let conn = |stream| Connection {
            stream,
            local_id: 0,
            seq: 0,
            pending: VecDeque::new(),
            rx: Vec::new(),
            rx_start: 0,
            rx_end: 0,
            rx_fds: VecDeque::new(),
            rx_deadline: None,
            spare_request: None,
            server_io_timeout: None,
            cancelled: None,
            notification_pending_peak: (0, 0, 0),
        };
        (conn(a), conn(b))
    }

    #[test]
    fn stale_request_replies_release_descriptors_and_preserve_live_messages() {
        let (mut client, mut server) = pair();
        let (stale_fd, mut stale_watch) = UnixStream::pair().unwrap();
        let (live_fd, mut live_watch) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            let mut body = BlobBuf::new();
            body.put_u32(attr::STATUS, status::OK as u32);
            for index in 0..256 {
                let ty = if index % 2 == 0 { ty::DATA } else { ty::STATUS };
                server.send(Header { ty, seq: request.header.seq.wrapping_sub(1), peer: 42 },
                    &mut body, Some(stale_fd.as_raw_fd())).unwrap();
            }
            drop(stale_fd);
            let mut invoke = BlobBuf::new();
            invoke.put_u32(attr::OBJID, 77).put_string(attr::METHOD, "queued");
            server.send(Header { ty: ty::INVOKE, seq: 99, peer: 3 }, &mut invoke, None).unwrap();
            server.send(Header { ty: ty::STATUS, seq: request.header.seq, peer: 42 },
                &mut body, Some(live_fd.as_raw_fd())).unwrap();
        });
        let reply = client.invoke_status(42, "probe", &[], 1000).unwrap();
        worker.join().unwrap();
        assert_eq!(reply.status, status::OK);
        assert_eq!(client.pending.len(), 1, "only the live INVOKE may remain pending");
        stale_watch.set_nonblocking(true).unwrap();
        assert_eq!(stale_watch.read(&mut [0]).unwrap(), 0, "stale reply FDs must close");
        let Incoming::Invoke(request) = client.read_incoming().unwrap() else { panic!("queued INVOKE") };
        assert_eq!((request.seq, request.method.as_str()), (99, "queued"));
        assert!(!client.has_pending());
        let mut received = UnixStream::from(reply.fd.unwrap());
        received.write_all(b"live").unwrap();
        let mut bytes = [0; 4];
        live_watch.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"live");
    }

    #[cfg(target_os = "linux")]
    fn notify_broker(server: &mut Connection, request: &Message, peers: &[u32]) {
        let mut b = BlobBuf::new();
        b.put_u32(attr::STATUS, status::OK as u32);
        let nested = b.nest_start(attr::SUBSCRIBERS);
        for peer in peers {
            b.put_u32(0, *peer);
        }
        b.nest_end(nested);
        server.send(Header { ty: ty::STATUS, seq: request.header.seq, peer: request.header.peer }, &mut b, None).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn notify_reply(server: &mut Connection, seq: u16, peer: u32, value: Option<&str>) {
        let mut b = BlobBuf::new();
        let ty = if let Some(value) = value {
            let mut fields = BlobBuf::new();
            fields.msg_string("address", value);
            b.put(attr::DATA, fields.payload());
            ty::DATA
        } else {
            b.put_u32(attr::STATUS, status::INVALID_ARGUMENT as u32);
            ty::STATUS
        };
        server.send(Header { ty, seq, peer }, &mut b, None).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notification_correlates_live_peers_sequences_and_streams_multiple_data() {
        let (mut client, mut server) = pair();
        let worker = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            assert_eq!(request.header.ty, ty::NOTIFY);
            notify_broker(&mut server, &request, &[10, 20]);
            let seq = request.header.seq;
            notify_reply(&mut server, seq.wrapping_add(1), 10, Some("wrong-seq"));
            notify_reply(&mut server, seq, 99, Some("wrong-peer"));
            notify_reply(&mut server, seq, 10, Some("first"));
            notify_reply(&mut server, seq, 10, Some("second"));
            notify_reply(&mut server, seq, 10, None);
            notify_reply(&mut server, seq, 10, Some("finished-peer"));
            let mut pending = BlobBuf::new();
            pending.put_u32(attr::OBJID, 42).put_string(attr::METHOD, "metrics");
            server.send(Header { ty: ty::INVOKE, seq: 600, peer: 77 }, &mut pending, None).unwrap();
            pending.reset();
            pending.put_u32(attr::OBJID, 42).put_u32(attr::ACTIVE, 1);
            server.send(Header { ty: ty::NOTIFY, seq: 601, peer: 42 }, &mut pending, None).unwrap();
            notify_reply(&mut server, seq, 20, Some("third"));
            notify_reply(&mut server, seq, 20, None);
        });
        let mut values = Vec::new();
        assert!(client.notify_with_data_until(42, "dns_result", &[], Instant::now() + Duration::from_secs(1), None,
            |data| values.push(blob::fields(data).next().unwrap().as_str().unwrap().to_owned())).unwrap());
        assert_eq!(values, ["first", "second", "third"]);
        let Incoming::Invoke(request) = client.read_incoming().unwrap() else { panic!("invoke was not queued") };
        assert_eq!(request.method, "metrics");
        assert!(matches!(client.read_incoming().unwrap(), Incoming::SubscribeState { objid: 42, active: true }));
        assert!(client.pending.is_empty());
        worker.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notification_timeout_keeps_transport_and_discards_late_replies() {
        let (mut client, mut server) = pair();
        let worker = std::thread::spawn(move || {
            let first = server.recv().unwrap();
            notify_broker(&mut server, &first, &[10]);
            notify_reply(&mut server, first.header.seq, 10, Some("before-timeout"));
            let second = server.recv().unwrap();
            notify_reply(&mut server, first.header.seq, 10, Some("late"));
            notify_reply(&mut server, first.header.seq, 10, None);
            notify_broker(&mut server, &second, &[10]);
            notify_reply(&mut server, second.header.seq, 10, Some("fresh"));
            notify_reply(&mut server, second.header.seq, 10, None);
        });
        let mut values = Vec::new();
        assert!(!client.notify_with_data_until(42, "event", &[], Instant::now() + Duration::from_millis(30), None,
            |data| values.push(blob::fields(data).next().unwrap().as_str().unwrap().to_owned())).unwrap());
        assert!(client.notify_with_data_until(42, "event", &[], Instant::now() + Duration::from_secs(1), None,
            |data| values.push(blob::fields(data).next().unwrap().as_str().unwrap().to_owned())).unwrap());
        assert_eq!(values, ["before-timeout", "fresh"]);
        assert!(client.pending.is_empty());
        worker.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notification_partial_timeout_and_cancel_close_descriptors() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static CANCEL: AtomicBool = AtomicBool::new(false);
        fn cancelled() -> bool { CANCEL.load(Ordering::Relaxed) }
        for cancel in [false, true] {
            CANCEL.store(false, Ordering::Relaxed);
            let (mut client, mut server) = pair();
            let (passed, mut observer) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                let request = server.recv().unwrap();
                notify_broker(&mut server, &request, &[10]);
                let mut b = BlobBuf::new();
                b.put(attr::DATA, &vec![0; 8192]);
                let mut wire = Header { ty: ty::DATA, seq: request.header.seq, peer: 10 }.encode().to_vec();
                wire.extend_from_slice(b.as_bytes());
                sys::send_with_fd(server.as_raw_fd(), &wire[..5000], &[], Some(passed.as_raw_fd())).unwrap();
                drop(passed);
                if cancel {
                    std::thread::sleep(Duration::from_millis(10));
                    CANCEL.store(true, Ordering::Relaxed);
                }
                server.stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                assert_eq!(server.stream.read(&mut [0]).unwrap(), 0);
            });
            let error = client.notify_with_data_until(42, "event", &[], Instant::now() + Duration::from_millis(50),
                Some(cancelled), |_| panic!("partial data reached callback")).unwrap_err();
            assert_eq!(error.kind(), if cancel { io::ErrorKind::Interrupted } else { io::ErrorKind::TimedOut });
            worker.join().unwrap();
            observer.set_nonblocking(true).unwrap();
            assert_eq!(observer.read(&mut [0]).unwrap(), 0, "partial notify retained passed FD");
            assert!(client.rx_fds.is_empty() && client.pending.is_empty());
        }
        CANCEL.store(false, Ordering::Relaxed);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notification_pending_queue_limit_closes_transport() {
      for payload_length in [0, 600_000] {
        let (mut client, mut server) = pair();
        let (passed, mut observer) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            notify_broker(&mut server, &request, &[10]);
            for seq in 0..129 {
                let mut b = BlobBuf::new();
                b.put_u32(attr::OBJID, 42).put_string(attr::METHOD, "metrics");
                if payload_length != 0 { b.put(attr::DATA, &vec![0; payload_length]); }
                if server.send(Header { ty: ty::INVOKE, seq, peer: 77 }, &mut b, Some(passed.as_raw_fd())).is_err() { break; }
            }
            drop(passed);
            server.stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            assert_eq!(server.stream.read(&mut [0]).unwrap(), 0);
        });
        let error = client.notify_with_data_until(42, "event", &[], Instant::now() + Duration::from_secs(1), None, |_| {}).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(client.pending.is_empty() && client.rx_fds.is_empty());
        let (messages, bytes, fds) = client.notification_pending_peak;
        assert_eq!(messages, if payload_length == 0 { 128 } else { 1 });
        assert!(bytes <= MAX_MSGLEN);
        assert_eq!(fds, messages);
        eprintln!("notification pending peak: messages={messages} bytes={bytes} descriptors={fds}; userspace retained after error=0");
        worker.join().unwrap();
        // Follow the error contract: shutdown stops the peer, but unread
        // SCM_RIGHTS in the socket receive queue are released by close.
        // Check userspace cleanup above before dropping the connection.
        drop(client);
        observer.set_nonblocking(true).unwrap();
        assert_eq!(observer.read(&mut [0]).unwrap(), 0, "pending notify backlog retained passed descriptors");
      }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notification_disconnect_releases_queued_descriptor_and_transport() {
        let (mut client, mut server) = pair();
        let (passed, mut observer) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            notify_broker(&mut server, &request, &[10]);
            let mut b = BlobBuf::new();
            b.put_u32(attr::OBJID, 42).put_string(attr::METHOD, "metrics");
            server.send(Header { ty: ty::INVOKE, seq: 600, peer: 77 }, &mut b, Some(passed.as_raw_fd())).unwrap();
        });
        let error = client.notify_with_data_until(42, "event", &[], Instant::now() + Duration::from_secs(1), None,
            |_| panic!("no DATA was sent")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        worker.join().unwrap();
        observer.set_nonblocking(true).unwrap();
        assert_eq!(observer.read(&mut [0]).unwrap(), 0);
        assert!(client.pending.is_empty() && client.rx_fds.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancellation_bounds_reply_prefixes_and_send_backpressure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static CANCEL: AtomicBool = AtomicBool::new(false);
        fn cancelled() -> bool {
            CANCEL.load(Ordering::Relaxed)
        }
        for prefix in [0, 1, 12, 5000] {
            CANCEL.store(false, Ordering::Relaxed);
            let (mut client, mut server) = pair();
            client.cancelled = Some(cancelled);
            let (passed, mut observer) = UnixStream::pair().unwrap();
            let peer = std::thread::spawn(move || {
                let req = server.recv().unwrap();
                let mut b = BlobBuf::new();
                b.put(attr::DATA, &vec![0; 8192]);
                let mut wire = Header {
                    ty: ty::DATA,
                    seq: req.header.seq,
                    peer: 42,
                }
                .encode()
                .to_vec();
                wire.extend_from_slice(b.as_bytes());
                if prefix != 0 {
                    sys::send_with_fd(
                        server.as_raw_fd(),
                        &wire[..prefix],
                        &[],
                        Some(passed.as_raw_fd()),
                    )
                    .unwrap();
                }
                drop(passed);
                std::thread::sleep(Duration::from_millis(20));
                CANCEL.store(true, Ordering::Relaxed);
                server
                    .stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                assert_eq!(
                    server.stream.read(&mut [0]).unwrap(),
                    0,
                    "cancelled request was retried or transport stayed open"
                );
            });
            let start = Instant::now();
            let error = client
                .invoke_status_until(42, "event", &[], start + Duration::from_secs(2))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(start.elapsed() < Duration::from_millis(300));
            peer.join().unwrap();
            observer.set_nonblocking(true).unwrap();
            assert_eq!(
                observer.read(&mut [0]).unwrap(),
                0,
                "cancelled partial frame retained SCM_RIGHTS"
            );
        }
        CANCEL.store(false, Ordering::Relaxed);
        let (mut client, mut server) = pair();
        client.cancelled = Some(cancelled);
        let cancel = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
            CANCEL.store(true, Ordering::Relaxed);
        });
        let start = Instant::now();
        let error = client
            .invoke_status_until(
                42,
                "event",
                &vec![0; MAX_MSGLEN - 128],
                start + Duration::from_secs(2),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(start.elapsed() < Duration::from_millis(300));
        cancel.join().unwrap();
        server.stream.set_nonblocking(true).unwrap();
        let mut bytes = Vec::new();
        server.stream.read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty() && bytes.len() < MAX_MSGLEN - 128);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn absolute_budget_spans_lookup_and_invoke_and_keeps_remote_timeout_status() {
        let (mut client, mut server) = pair();
        let peer = std::thread::spawn(move || {
            let lookup = server.recv().unwrap();
            std::thread::sleep(Duration::from_millis(35));
            let mut b = BlobBuf::new();
            b.put_u32(attr::OBJID, 42)
                .put_string(attr::OBJPATH, "service");
            server
                .send(
                    Header {
                        ty: ty::DATA,
                        seq: lookup.header.seq,
                        peer: 0,
                    },
                    &mut b,
                    None,
                )
                .unwrap();
            let mut b = BlobBuf::new();
            b.put_u32(attr::STATUS, status::OK as u32);
            server
                .send(
                    Header {
                        ty: ty::STATUS,
                        seq: lookup.header.seq,
                        peer: 0,
                    },
                    &mut b,
                    None,
                )
                .unwrap();
            let invoke = server.recv().unwrap();
            assert_eq!(invoke.header.ty, ty::INVOKE);
            // Client must close at the original deadline, not 70 ms after lookup.
            server
                .stream
                .set_read_timeout(Some(Duration::from_millis(65)))
                .unwrap();
            assert_eq!(server.stream.read(&mut [0]).unwrap(), 0);
        });
        let deadline = Instant::now() + Duration::from_millis(70);
        let id = client.lookup_id_until("service", deadline).unwrap();
        let error = client
            .invoke_status_until(id, "event", &[], deadline)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error_status(&error), None);
        peer.join().unwrap();

        let (mut client, mut server) = pair();
        let peer = std::thread::spawn(move || {
            let req = server.recv().unwrap();
            let mut b = BlobBuf::new();
            b.put_u32(attr::STATUS, status::TIMEOUT as u32);
            server
                .send(
                    Header {
                        ty: ty::STATUS,
                        seq: req.header.seq,
                        peer: 42,
                    },
                    &mut b,
                    None,
                )
                .unwrap();
        });
        assert_eq!(
            client
                .invoke_status_until(42, "event", &[], Instant::now() + Duration::from_secs(1))
                .unwrap(),
            status::TIMEOUT
        );
        peer.join().unwrap();
    }

    #[test]
    fn expired_receive_budget_rejects_even_ready_frame_bytes() {
        let (mut client, mut server) = pair();
        let mut b = BlobBuf::new();
        b.put_u32(attr::STATUS, status::OK as u32);
        server
            .send(
                Header {
                    ty: ty::STATUS,
                    seq: 1,
                    peer: 42,
                },
                &mut b,
                None,
            )
            .unwrap();
        let error = client
            .recv_until(Some(Instant::now() - Duration::from_millis(1)))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn owned_reply_payload_keeps_allocation_attributes_and_padding() {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, 17).put(attr::DATA, b"abc\xff\0")
            .put(attr::DATA, b"second");
        let samples = [b.as_bytes().to_vec(), vec![0, 0, 0, 4], vec![0, 0, 0, 7, 1, 2, 3]];
        let lengths = (0..=256).chain([4080, 4084, 8192, 32768]);
        for blob in samples.into_iter().chain(lengths.map(|len| {
            (0..len + 4).map(|i| (i % 251) as u8).collect()
        })) {
            let expected = blob[4..].to_vec();
            assert_eq!(reply_payload(Cow::Borrowed(&blob)), expected);
            let pointer = blob.as_ptr();
            let capacity = blob.capacity();
            let payload = reply_payload(Cow::Owned(blob));
            assert_eq!(payload, expected, "only the root header is removed");
            assert_eq!(payload.as_ptr(), pointer, "large frame storage was replaced");
            assert_eq!(payload.capacity(), capacity);
        }
    }

    #[test]
    fn lookup_reduction_preserves_first_match_and_waits_for_final_status() {
        for final_status in [status::OK, status::NOT_FOUND] {
            let (mut client, mut server) = pair();
            let peer = std::thread::spawn(move || {
                for path in ["fixture", "next"] {
                    let request = server.recv().unwrap();
                    assert_eq!(request.header.ty, ty::LOOKUP);
                    for (name, id) in [("wrong", 11), (path, 23), (path, 99)] {
                        let mut data = BlobBuf::new();
                        data.put_string(attr::OBJPATH, "overridden").put_string(attr::OBJPATH, name)
                            .put_u32(attr::OBJID, 1).put_u32(attr::OBJID, id)
                            .put(attr::SIGNATURE, &[0xa5; 8192]);
                        server.send(Header { ty: ty::DATA, seq: request.header.seq, peer: 0 }, &mut data, None).unwrap();
                    }
                    let mut status = BlobBuf::new();
                    status.put_u32(attr::STATUS, if path == "fixture" { final_status as u32 } else { 0 });
                    server.send(Header { ty: ty::STATUS, seq: request.header.seq, peer: 0 }, &mut status, None).unwrap();
                }
            });
            let result = client.lookup_id("fixture", 1000);
            if final_status == status::OK { assert_eq!(result.unwrap(), 23); }
            else { assert_eq!(error_status(&result.unwrap_err()), Some(final_status)); }
            assert_eq!(client.lookup_id("next", 1000).unwrap(), 23);
            assert!(client.pending.is_empty());
            peer.join().unwrap();
        }
    }

    #[test]
    fn synchronous_reply_owns_data_and_preserves_unmatched_frames() {
        // The wire has an eight-byte ubus header, four-byte root blob header
        // and four-byte DATA attr header: these straddle the rx boundary.
        for size in [16, INCOMING_BUFFER_SIZE - 16, INCOMING_BUFFER_SIZE - 12, INCOMING_BUFFER_SIZE * 2] {
            let (mut client, mut server) = pair();
            let peer = std::thread::spawn(move || {
                let req = server.recv().unwrap();
                let mut b = BlobBuf::new();
                b.put(attr::DATA, &vec![0xa5; size]);
                server.send(Header { ty: ty::INVOKE, seq: req.header.seq + 1, peer: 42 }, &mut b, None).unwrap();
                server.send(Header { ty: ty::DATA, seq: req.header.seq, peer: 42 }, &mut b, None).unwrap();
                b = BlobBuf::new();
                b.put_u32(attr::STATUS, 3).put_u32(attr::STATUS, 0);
                server.send(Header { ty: ty::STATUS, seq: req.header.seq, peer: 42 }, &mut b, None).unwrap();
            });
            let reply = client.request(ty::INVOKE, 42, &mut BlobBuf::new(), None, 1000).unwrap();
            assert_eq!(reply.status, status::OK, "last STATUS attr wins");
            assert_eq!(reply.data.len(), 1);
            assert_eq!(blob::iter(&reply.data[0]).next().unwrap().payload, vec![0xa5; size]);
            let queued = client.pending.pop_front().unwrap();
            assert_eq!(queued.header.seq, 2);
            assert_eq!(queued.blob[4..], reply.data[0]);
            assert!(client.pending.is_empty());
            peer.join().unwrap();
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn object_registration_preserves_opaque_c_string_bytes() {
        let (mut client, mut server) = pair();
        let peer = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            assert_eq!(request.header.ty, ty::ADD_OBJECT);
            let attrs = request.attrs();
            assert_eq!(attrs[attr::OBJPATH as usize].unwrap().payload, b"opaque.\xff\0");
            let mut data = BlobBuf::new();
            data.put_u32(attr::OBJID, 31);
            server.send(Header { ty: ty::DATA, seq: request.header.seq, peer: 0 }, &mut data, None).unwrap();
            let mut status = BlobBuf::new();
            status.put_u32(attr::STATUS, 0);
            server.send(Header { ty: ty::STATUS, seq: request.header.seq, peer: 0 }, &mut status, None).unwrap();
        });
        assert_eq!(client.add_object_bytes(b"opaque.\xff\0ignored", &[], 1000).unwrap(), 31);
        peer.join().unwrap();
    }

    #[test]
    fn typed_objects_reuse_server_type_without_repeating_signature() {
        let (mut client, mut server) = pair();
        let peer = std::thread::spawn(move || {
            for (index, path) in ["network.interface", "network.interface.lan"].iter().enumerate() {
                let request = server.recv().unwrap();
                assert_eq!(request.header.ty, ty::ADD_OBJECT);
                let attrs = request.attrs();
                assert_eq!(attrs[attr::OBJPATH as usize].unwrap().as_str(), Some(*path));
                if index == 0 {
                    assert!(attrs[attr::SIGNATURE as usize].is_some());
                    assert!(attrs[attr::OBJTYPE as usize].is_none());
                } else {
                    assert!(attrs[attr::SIGNATURE as usize].is_none());
                    assert_eq!(attrs[attr::OBJTYPE as usize].unwrap().as_u32(), Some(71));
                }
                let mut data = BlobBuf::new();
                data.put_u32(attr::OBJID, 31 + index as u32);
                if index == 0 {
                    data.put_u32(attr::OBJTYPE, 71);
                }
                server.send(Header { ty: ty::DATA, seq: request.header.seq, peer: 0 }, &mut data, None).unwrap();
                let mut status = BlobBuf::new();
                status.put_u32(attr::STATUS, 0);
                server.send(Header { ty: ty::STATUS, seq: request.header.seq, peer: 0 }, &mut status, None).unwrap();
            }
        });
        let first = client.add_object_typed("network.interface", &[("status", &[])], None, 1000).unwrap();
        assert_eq!(first, (31, 71));
        assert_eq!(client.add_object_typed("network.interface.lan", &[], Some(first.1), 1000).unwrap(), (32, 71));
        peer.join().unwrap();
    }

    #[test]
    fn typed_registration_requires_type_and_preserves_legacy_and_error_replies() {
        for (typed, code, expected) in [(false, status::OK, None), (true, status::OK, Some(status::NO_DATA)),
                                      (true, status::PERMISSION_DENIED, Some(status::PERMISSION_DENIED))] {
            let (mut client, mut server) = pair();
            let peer = std::thread::spawn(move || {
                let request = server.recv().unwrap();
                if code == status::OK {
                    let mut data = BlobBuf::new();
                    data.put_u32(attr::OBJID, 31);
                    server.send(Header { ty: ty::DATA, seq: request.header.seq, peer: 0 }, &mut data, None).unwrap();
                }
                let mut status = BlobBuf::new();
                status.put_u32(attr::STATUS, code as u32);
                server.send(Header { ty: ty::STATUS, seq: request.header.seq, peer: 0 }, &mut status, None).unwrap();
            });
            let result = if typed { client.add_object_typed("probe", &[], None, 1000).map(|(id, _)| id) }
                         else { client.add_object("probe", &[], 1000) };
            if let Some(expected) = expected {
                assert_eq!(error_status(&result.unwrap_err()), Some(expected));
            } else {
                assert_eq!(result.unwrap(), 31);
            }
            peer.join().unwrap();
        }
        let (mut client, _server) = pair();
        assert_eq!(error_status(&client.add_object_typed("invalid", &[], Some(0), 1000).unwrap_err()),
                   Some(status::INVALID_ARGUMENT));
        assert_eq!(client.seq, 0, "invalid type sent no request");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn poll_owner_retains_partial_frames_without_waiting_and_preserves_following_frame() {
        for split in [1, 11, 13, 4096] {
            let (mut sender, mut server) = pair();
            server.set_server_io_timeout(Duration::from_millis(1));
            let mut b = BlobBuf::new();
            b.put_string(attr::METHOD, &"x".repeat(5000));
            let mut wire = Header { ty: ty::INVOKE, seq: 1, peer: 9 }.encode().to_vec();
            wire.extend_from_slice(b.as_bytes());
            sender.stream.write_all(&wire[..split]).unwrap();
            let started = Instant::now();
            assert!(server.incoming_if_complete().unwrap().is_none());
            assert!(started.elapsed() < Duration::from_millis(20));
            std::thread::sleep(Duration::from_millis(2));
            assert!(server.incoming_if_complete().unwrap().is_none());
            sender.stream.write_all(&wire[split..]).unwrap();
            sender.stream.write_all(&wire).unwrap();
            for _ in 0..2 {
                let Some(Incoming::Invoke(req)) = server.incoming_if_complete().unwrap() else {
                    panic!("completed split {split} was not available");
                };
                assert_eq!(req.method.len(), 5000);
                assert_eq!((req.peer, req.seq), (9, 1));
            }
            assert!(server.incoming_if_complete().unwrap().is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn poll_owner_keeps_a_partial_descriptor_until_completion_or_connection_drop() {
        let (sender, mut server) = pair();
        let (passed, mut observer) = UnixStream::pair().unwrap();
        sys::send_with_fd(sender.stream.as_raw_fd(), &[0], &[], Some(passed.as_raw_fd())).unwrap();
        drop(passed);
        assert!(server.incoming_if_complete().unwrap().is_none());
        observer.set_nonblocking(true).unwrap();
        assert_eq!(observer.read(&mut [0]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        drop(server);
        assert_eq!(observer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn server_io_budget_bounds_partial_frames_and_reply_backpressure() {
        for size in [1, 12] {
            let (mut sender, mut server) = pair();
            server.set_server_io_timeout(Duration::from_millis(40));
            let mut b = BlobBuf::new();
            b.put_string(attr::METHOD, "partial");
            let mut wire = Header { ty: ty::INVOKE, seq: 1, peer: 9 }.encode().to_vec();
            wire.extend_from_slice(b.as_bytes());
            sender.stream.write_all(&wire[..size]).unwrap();
            let start = Instant::now();
            let error = server.incoming_if_started().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(start.elapsed() < Duration::from_millis(200));
            assert_eq!(sender.stream.read(&mut [0]).unwrap(), 0);
        }
        let (mut server, mut client) = pair();
        server.set_server_io_timeout(Duration::from_millis(40));
        // An empty incoming socket is still an immediate None, not a timeout.
        assert!(server.incoming_if_started().unwrap().is_none());
        let start = Instant::now();
        let error = server.reply_data_status(&request(), &vec![0; MAX_MSGLEN - 16], status::OK).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_millis(200));
        client.stream.set_nonblocking(true).unwrap();
        let mut bytes = Vec::new();
        client.stream.read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty() && bytes.len() < MAX_MSGLEN);
    }

    #[test]
    fn request_deadline_covers_partial_header_and_body() {
        for prefix in [1, 12] {
            let (mut client, mut server) = pair();
            let peer = std::thread::spawn(move || {
                let request = server.recv().unwrap();
                let mut b = BlobBuf::new();
                b.put_u32(attr::STATUS, status::OK as u32);
                let mut wire = Header { ty: ty::STATUS, seq: request.header.seq, peer: 0 }.encode().to_vec();
                wire.extend_from_slice(b.as_bytes());
                server.stream.write_all(&wire[..prefix]).unwrap();
                // Keep the transport alive much longer than the RPC deadline.
                std::thread::sleep(Duration::from_millis(300));
            });
            let start = Instant::now();
            let error = client.lookup_id("deadline-probe", 40).unwrap_err();
            let elapsed = start.elapsed();
            peer.join().unwrap();
            assert_eq!(error_status(&error), Some(status::TIMEOUT), "{error}");
            assert!(elapsed < Duration::from_millis(200), "partial prefix {prefix}: {elapsed:?}");
        }
    }

    #[test]
    fn request_deadline_bounds_backpressure_and_closes_the_transport() {
        let (mut client, mut server) = pair();
        let mut b = BlobBuf::new();
        b.put(attr::DATA, &vec![0; MAX_MSGLEN - 16]);
        let start = Instant::now();
        let error = client.request(ty::INVOKE, 42, &mut b, None, 40).unwrap_err();
        assert_eq!(error_status(&error), Some(status::TIMEOUT));
        assert!(start.elapsed() < Duration::from_millis(200));
        server.stream.set_nonblocking(true).unwrap();
        let mut received = Vec::new();
        server.stream.read_to_end(&mut received).unwrap();
        assert!(!received.is_empty() && received.len() < MAX_MSGLEN);
        assert!(client.lookup_id("cannot-reuse-partial-frame", 40).is_err());
    }

    #[test]
    fn clean_request_timeout_keeps_connection_and_late_reply_boundaries() {
        let (mut client, mut server) = pair();
        let peer = std::thread::spawn(move || {
            let first = server.recv().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let mut b = BlobBuf::new();
            b.put_u32(attr::STATUS, status::OK as u32);
            server.send(Header { ty: ty::STATUS, seq: first.header.seq, peer: 0 }, &mut b, None).unwrap();
            let second = server.recv().unwrap();
            server.send(Header { ty: ty::STATUS, seq: second.header.seq, peer: 0 }, &mut b, None).unwrap();
        });
        let error = client.request(ty::LOOKUP, 0, &mut BlobBuf::new(), None, 30).unwrap_err();
        assert_eq!(error_status(&error), Some(status::TIMEOUT));
        let next = client.request(ty::LOOKUP, 0, &mut BlobBuf::new(), None, 500).unwrap();
        assert_eq!(next.status, status::OK);
        assert!(client.pending.is_empty(), "late response belongs to an expired request");
        peer.join().unwrap();
    }

    #[test]
    fn request_deadline_keeps_fragmented_success_and_timeout_fd_cleanup() {
        for complete in [true, false] {
            let (mut client, mut server) = pair();
            let (passed, mut observer) = UnixStream::pair().unwrap();
            let peer = std::thread::spawn(move || {
                let req = server.recv().unwrap();
                let mut b = BlobBuf::new();
                b.put_u32(attr::STATUS, status::OK as u32);
                let mut wire = Header { ty: ty::STATUS, seq: req.header.seq, peer: 0 }.encode().to_vec();
                wire.extend_from_slice(b.as_bytes());
                sys::send_with_fd(server.as_raw_fd(), &wire[..1], &[], Some(passed.as_raw_fd())).unwrap();
                drop(passed);
                if complete {
                    for part in wire[1..].chunks(3) {
                        std::thread::sleep(Duration::from_millis(2));
                        server.stream.write_all(part).unwrap();
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(150));
                }
            });
            let reply = client.request(ty::LOOKUP, 0, &mut BlobBuf::new(), None, 80);
            if complete {
                let reply = reply.unwrap();
                assert_eq!(reply.status, status::OK);
                let mut fd = UnixStream::from(reply.fd.unwrap());
                fd.write_all(b"x").unwrap();
                observer.read_exact(&mut [0]).unwrap();
            } else {
                assert_eq!(error_status(&reply.unwrap_err()), Some(status::TIMEOUT));
                observer.set_nonblocking(true).unwrap();
                assert_eq!(observer.read(&mut [0]).unwrap(), 0, "timed-out prefix leaked SCM_RIGHTS");
            }
            peer.join().unwrap();
        }
    }

    #[test]
    fn started_receive_preserves_empty_socket_pending_order_and_eof() {
        let (mut sender, mut receiver) = pair();
        assert!(receiver.incoming_if_started().unwrap().is_none());
        let mut b = BlobBuf::new();
        b.put_string(attr::METHOD, "queued").put(attr::DATA, b"first");
        sender.send(Header { ty: ty::INVOKE, seq: 1, peer: 9 }, &mut b, None).unwrap();
        let queued = receiver.recv().unwrap();
        receiver.pending.push_back(queued);
        b = BlobBuf::new();
        b.put_string(attr::METHOD, "socket").put(attr::DATA, b"second");
        sender.send(Header { ty: ty::INVOKE, seq: 2, peer: 9 }, &mut b, None).unwrap();
        let Some(Incoming::Invoke(first)) = receiver.incoming_if_started().unwrap() else { panic!("queued") };
        let Some(Incoming::Invoke(second)) = receiver.incoming_if_started().unwrap() else { panic!("socket") };
        assert_eq!((first.seq, first.data.as_slice()), (1, &b"first"[..]));
        assert_eq!((second.seq, second.data.as_slice()), (2, &b"second"[..]));
        assert!(receiver.incoming_if_started().unwrap().is_none());
        drop(sender);
        assert_eq!(receiver.incoming_if_started().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn complete_pending_method_is_runnable_with_an_empty_kernel_socket() {
        let (mut sender, mut receiver) = pair();
        let mut message = BlobBuf::new();
        message.put_string(attr::METHOD, "get_metrics");
        sender.send(Header { ty: ty::INVOKE, seq: 7, peer: 9 }, &mut message, None).unwrap();
        // A doctor request consumes a nonmatching method while waiting for its
        // own response and parks it in this same queue.
        let method = receiver.recv().unwrap();
        receiver.pending.push_back(method);
        let mut fd = [sys::PollFd {
            fd: receiver.as_raw_fd(), events: sys::POLLIN, revents: 0,
        }];
        assert_eq!(sys::poll_fds(&mut fd, 0).unwrap(), 0);
        assert!(receiver.has_pending(), "owner must wake without a new socket event");
        let Some(Incoming::Invoke(method)) = receiver.incoming_if_started().unwrap()
            else { panic!("pending method") };
        assert_eq!(method.seq, 7);
        assert!(!receiver.has_pending(), "empty queues must return to fd waiting");
    }

    #[test]
    fn started_receive_finishes_fragmented_frame_and_owns_its_fd() {
        let (mut sender, mut receiver) = pair();
        let (passed, mut observer) = UnixStream::pair().unwrap();
        let mut b = BlobBuf::new();
        b.put_string(attr::METHOD, "fragment").put(attr::DATA, b"raw\xff");
        let mut wire = Header { ty: ty::INVOKE, seq: 5, peer: 8 }.encode().to_vec();
        wire.extend_from_slice(b.as_bytes());
        sys::send_with_fd(sender.as_raw_fd(), &wire[..1], &[], Some(passed.as_raw_fd())).unwrap();
        drop(passed);
        let producer = std::thread::spawn(move || {
            for part in wire[1..].chunks(3) {
                sender.stream.write_all(part).unwrap();
                std::thread::yield_now();
            }
            sender
        });
        let Some(Incoming::Invoke(req)) = receiver.incoming_if_started().unwrap() else { panic!("started") };
        assert_eq!(req.method, "fragment");
        assert_eq!(req.data, b"raw\xff");
        let mut received = UnixStream::from(req.fd.unwrap());
        received.write_all(b"x").unwrap();
        observer.read_exact(&mut [0]).unwrap();
        producer.join().unwrap();
    }

    #[test]
    fn started_receive_error_releases_descriptor() {
        for (version, len, truncated) in [(1, 4, false), (0, 3, false),
            (0, MAX_MSGLEN + 1, false), (0, 16, true)] {
            let (sender, mut receiver) = pair();
            let (passed, mut observer) = UnixStream::pair().unwrap();
            observer.set_nonblocking(true).unwrap();
            let mut header = Header { ty: ty::INVOKE, seq: 1, peer: 2 }.encode();
            header[0] = version;
            sys::send_with_fd(sender.as_raw_fd(), &header, &(len as u32).to_be_bytes(),
                Some(passed.as_raw_fd())).unwrap();
            drop(passed);
            if truncated { sender.stream.shutdown(std::net::Shutdown::Write).unwrap(); }
            assert!(receiver.incoming_if_started().is_err());
            assert_eq!(observer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn incoming_keeps_last_data_raw_bytes_metadata_and_descriptor() {
        use std::os::fd::AsFd;
        let (mut sender, mut receiver) = pair();
        let file = std::fs::File::open("/dev/null").unwrap();
        let header = Header { ty: ty::INVOKE, seq: 19, peer: 2718 };
        for data in [vec![], vec![0xff, 0, 2, 3, 4], vec![0xab; 4096]] {
            let mut b = BlobBuf::new();
            b.put(attr::DATA, b"replaced").put_string(attr::GROUP, "group")
                .put(attr::DATA, &data).put_u32(attr::OBJID, 42)
                .put_string(attr::METHOD, "run").put_string(attr::USER, "user")
                .put_u32(attr::NO_REPLY, 1);
            sender.send(header, &mut b, Some(file.as_raw_fd())).unwrap();
            let Incoming::Invoke(req) = receiver.read_incoming().unwrap() else {
                panic!("expected INVOKE");
            };
            assert_eq!((req.peer, req.seq, req.objid), (2718, 19, 42));
            assert_eq!(req.method, "run");
            assert_eq!(req.user.as_deref(), Some("user"));
            assert_eq!(req.group.as_deref(), Some("group"));
            assert!(req.no_reply);
            assert_eq!(req.data, data);
            let received = req.fd.unwrap();
            // A valid owned descriptor remains usable after the frame is gone.
            assert!(received.as_fd().try_clone_to_owned().is_ok());
        }
    }

    #[test]
    fn incoming_empty_or_small_data_does_not_pin_a_large_envelope() {
        let (mut sender, mut receiver) = pair();
        for data in [None, Some(&b""[..]), Some(&b"small"[..])] {
            let mut b = BlobBuf::new();
            b.put(attr::OBJPATH, &[b'x'; 16 * 1024]);
            if let Some(data) = data {
                b.put(attr::DATA, data);
            }
            sender.send(Header { ty: ty::INVOKE, seq: 0, peer: 0 }, &mut b, None).unwrap();
            let Incoming::Invoke(req) = receiver.read_incoming().unwrap() else {
                panic!("expected INVOKE");
            };
            assert_eq!(req.data, data.unwrap_or_default());
            assert!(req.data.capacity() < 16 * 1024);
            assert_eq!(req.method, "");
            assert_eq!(req.objid, 0);
            assert!(!req.no_reply);
            assert!(receiver.rx.capacity() <= INCOMING_BUFFER_SIZE);
        }
    }

    #[test]
    fn later_invokes_do_not_change_owned_requests_or_keep_old_credentials() {
        let (mut sender, mut receiver) = pair();
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, 42).put_string(attr::METHOD, "first")
            .put_string(attr::USER, "root").put_string(attr::GROUP, "group")
            .put_u32(attr::NO_REPLY, 1).put(attr::DATA, b"owned arguments");
        sender.send(Header { ty: ty::INVOKE, seq: 1, peer: 2 }, &mut b, None).unwrap();
        let Incoming::Invoke(first) = receiver.read_incoming().unwrap() else {
            panic!("expected first INVOKE");
        };
        // One fixed read-ahead buffer serves every small frame.
        assert_eq!(receiver.rx.capacity(), INCOMING_BUFFER_SIZE);
        for seq in 2..5 {
            let mut b = BlobBuf::new();
            sender.send(Header { ty: ty::INVOKE, seq, peer: 3 }, &mut b, None).unwrap();
            let Some(Incoming::Invoke(next)) = receiver.next_incoming(100).unwrap() else {
                panic!("expected next INVOKE");
            };
            assert_eq!((next.peer, next.seq, next.objid), (3, seq, 0));
            assert_eq!(next.method, "");
            assert!(next.user.is_none() && next.group.is_none());
            assert!(next.data.is_empty() && next.fd.is_none() && !next.no_reply);
            assert_eq!(first.method, "first");
            assert_eq!(first.user.as_deref(), Some("root"));
            assert_eq!(first.group.as_deref(), Some("group"));
            assert_eq!(first.data, b"owned arguments");
            assert!(first.no_reply);
        }
    }

    #[test]
    fn recycled_request_closes_fd_reuses_storage_and_clears_absent_fields() {
        let (mut sender, mut receiver) = pair();
        let (passed, mut observer) = UnixStream::pair().unwrap();
        observer.set_nonblocking(true).unwrap();
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, 42).put_string(attr::METHOD, "long_method")
            .put_string(attr::USER, "first_user").put_string(attr::GROUP, "first_group")
            .put_u32(attr::NO_REPLY, 1).put(attr::DATA, b"first arguments");
        sender.send(Header { ty: ty::INVOKE, seq: 1, peer: 2 }, &mut b, Some(passed.as_raw_fd())).unwrap();
        drop(passed);
        let Incoming::Invoke(first) = receiver.read_incoming().unwrap() else { panic!("INVOKE") };
        let pointers = (first.method.as_ptr(), first.user.as_ref().unwrap().as_ptr(),
            first.group.as_ref().unwrap().as_ptr(), first.data.as_ptr());
        receiver.recycle_request(first);
        assert_eq!(observer.read(&mut [0]).unwrap(), 0);

        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, 7).put_string(attr::METHOD, "next")
            .put_string(attr::USER, "user").put_string(attr::GROUP, "group").put(attr::DATA, b"next");
        sender.send(Header { ty: ty::INVOKE, seq: 3, peer: 4 }, &mut b, None).unwrap();
        let Incoming::Invoke(next) = receiver.read_incoming().unwrap() else { panic!("INVOKE") };
        assert_eq!((next.peer, next.seq, next.objid), (4, 3, 7));
        assert_eq!(next.method, "next");
        assert_eq!(next.user.as_deref(), Some("user"));
        assert_eq!(next.group.as_deref(), Some("group"));
        assert_eq!(next.data, b"next");
        assert!(!next.no_reply && next.fd.is_none());
        assert_eq!(pointers, (next.method.as_ptr(), next.user.as_ref().unwrap().as_ptr(),
            next.group.as_ref().unwrap().as_ptr(), next.data.as_ptr()));
        receiver.recycle_request(next);

        sender.send(Header { ty: ty::INVOKE, seq: 5, peer: 6 }, &mut BlobBuf::new(), None).unwrap();
        let Incoming::Invoke(empty) = receiver.read_incoming().unwrap() else { panic!("INVOKE") };
        assert_eq!((empty.peer, empty.seq, empty.objid), (6, 5, 0));
        assert!(empty.method.is_empty() && empty.data.is_empty());
        assert!(empty.user.is_none() && empty.group.is_none() && empty.fd.is_none() && !empty.no_reply);
    }

    #[test]
    fn recycling_does_not_retain_large_request_capacity() {
        let (_, mut receiver) = pair();
        for which in 0..4 {
            let mut req = request();
            let large = "x".repeat(INCOMING_BUFFER_SIZE + 1);
            match which {
                0 => req.data = large.into_bytes(),
                1 => req.method = large,
                2 => req.user = Some(large),
                _ => req.group = Some(large),
            }
            receiver.recycle_request(req);
            assert!(receiver.spare_request.is_none());
        }
        receiver.recycle_request(request());
        assert!(receiver.spare_request.is_some());
    }

    #[test]
    fn receive_buffer_is_lazy_bounded_and_preserves_frames_at_the_boundary() {
        let (mut sender, mut receiver) = pair();
        sender.reply_status(&request(), 0, None).unwrap();
        assert!(matches!(receiver.read_incoming().unwrap(), Incoming::Other(_)));
        assert_eq!(receiver.rx.capacity(), INCOMING_BUFFER_SIZE);

        let writer = std::thread::spawn(move || {
            for len in [INCOMING_BUFFER_SIZE + 4, INCOMING_BUFFER_SIZE, MAX_MSGLEN, 8] {
                let mut b = BlobBuf::new();
                b.put(attr::DATA, &vec![0xa5; len - 8]);
                assert_eq!(b.as_bytes().len(), len);
                sender.send(Header { ty: ty::INVOKE, seq: 7, peer: 9 }, &mut b, None).unwrap();
            }
        });
        let mut retained = None;
        for len in [INCOMING_BUFFER_SIZE + 4, INCOMING_BUFFER_SIZE, MAX_MSGLEN, 8] {
            let Incoming::Invoke(req) = receiver.read_incoming().unwrap() else {
                panic!("expected INVOKE");
            };
            assert_eq!((req.seq, req.peer), (7, 9));
            assert_eq!(req.data, vec![0xa5; len - 8]);
            // Frames beyond the buffer never inflate or replace it.
            let pointer = *retained.get_or_insert(receiver.rx.as_ptr());
            assert_eq!(receiver.rx.as_ptr(), pointer);
            assert_eq!(receiver.rx.capacity(), INCOMING_BUFFER_SIZE);
        }
        writer.join().unwrap();
    }

    #[test]
    fn growing_receive_storage_keeps_earlier_requests_owned() {
        let (mut sender, mut receiver) = pair();
        let mut held = Vec::new();
        for size in [32, 2048, INCOMING_BUFFER_SIZE - 8, 16] {
            let mut b = BlobBuf::new();
            b.put(attr::DATA, &vec![0xa5; size]);
            sender.send(Header { ty: ty::INVOKE, seq: 1, peer: 2 }, &mut b, None).unwrap();
            let Incoming::Invoke(req) = receiver.read_incoming().unwrap() else {
                panic!("expected INVOKE");
            };
            held.push((size, req));
            assert!(receiver.rx.capacity() <= INCOMING_BUFFER_SIZE);
            for (length, req) in &held {
                assert_eq!(req.data.len(), *length);
                assert!(req.data.iter().all(|b| *b == 0xa5));
            }
        }
    }

    #[test]
    fn queued_invokes_keep_order_ahead_of_socket_frames() {
        let (mut sender, mut receiver) = pair();
        let mut b = BlobBuf::new();
        b.put_string(attr::METHOD, "queued").put(attr::DATA, b"first");
        sender.send(Header { ty: ty::INVOKE, seq: 1, peer: 9 }, &mut b, None).unwrap();
        let queued = receiver.recv().unwrap();
        receiver.pending.push_back(queued);
        b = BlobBuf::new();
        b.put_string(attr::METHOD, "socket").put(attr::DATA, b"second");
        sender.send(Header { ty: ty::INVOKE, seq: 2, peer: 9 }, &mut b, None).unwrap();
        let Some(Incoming::Invoke(first)) = receiver.next_incoming(0).unwrap() else {
            panic!("expected queued INVOKE");
        };
        assert_eq!((first.seq, first.method.as_str(), first.data.as_slice()), (1, "queued", &b"first"[..]));
        let Incoming::Invoke(second) = receiver.read_incoming().unwrap() else {
            panic!("expected socket INVOKE");
        };
        assert_eq!((second.seq, second.method.as_str(), second.data.as_slice()), (2, "socket", &b"second"[..]));
        assert_eq!(first.data, b"first");
        assert!(receiver.next_incoming(0).unwrap().is_none());
    }

    #[test]
    fn malformed_or_truncated_frames_release_received_descriptors() {
        for (version, len, truncated) in [(1, 4, false), (0, 3, false),
            (0, MAX_MSGLEN + 1, false), (0, 16, true)] {
            let (sender, mut receiver) = pair();
            let (passed, mut observer) = UnixStream::pair().unwrap();
            observer.set_nonblocking(true).unwrap();
            let mut header = Header { ty: ty::INVOKE, seq: 1, peer: 2 }.encode();
            header[0] = version;
            sys::send_with_fd(sender.as_raw_fd(), &header, &(len as u32).to_be_bytes(),
                Some(passed.as_raw_fd())).unwrap();
            drop(passed);
            if truncated {
                sender.stream.shutdown(std::net::Shutdown::Write).unwrap();
            }
            assert!(receiver.read_incoming().is_err());
            // EOF proves the received descriptor was closed on the error path.
            // A leak returns WouldBlock instead of hanging this test.
            assert_eq!(observer.read(&mut [0]).unwrap(), 0);
            assert!(receiver.rx.capacity() <= INCOMING_BUFFER_SIZE);
        }
    }

    fn request() -> Request {
        Request { peer: 0xa1b2c3d4, seq: 0xabcd, objid: 0x10203040,
            method: "test".into(), user: None, group: None, data: vec![], fd: None, no_reply: false }
    }

    #[test]
    fn data_replies_match_codec_for_aligned_unaligned_and_maximum_fields() {
        for size in [0, 1, 3, 4, 31, 32, 65536, MAX_MSGLEN - 16] {
            let (mut server, mut client) = pair();
            server.stream.set_nonblocking(true).unwrap();
            let req = request();
            let fields: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let mut expected = BlobBuf::new();
            expected.put_u32(attr::OBJID, req.objid).put(attr::DATA, &fields);
            let bytes = expected.as_bytes().to_vec();
            let reader = std::thread::spawn(move || client.recv().unwrap());
            server.reply_data(&req, &fields).unwrap();
            let message = reader.join().unwrap();
            assert_eq!(message.header, Header { ty: ty::DATA, seq: req.seq, peer: req.peer });
            assert_eq!(message.blob, bytes, "payload size {size}");
            assert!(message.fd.is_none());
        }
    }

    #[test]
    fn oversized_reply_is_rejected_before_writing() {
        let (mut server, mut client) = pair();
        client.stream.set_nonblocking(true).unwrap();
        assert!(server.reply_data(&request(), &vec![0; MAX_MSGLEN - 15]).is_err());
        assert_eq!(client.stream.read(&mut [0]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn status_reply_preserves_signed_code_object_header_and_descriptor() {
        let (mut server, mut client) = pair();
        let req = request();
        let (read_end, write_end) = sys::pipe().unwrap();
        server.reply_status(&req, -7, Some(read_end.as_raw_fd())).unwrap();
        drop(read_end);
        let message = client.recv().unwrap();
        assert_eq!(message.header, Header { ty: ty::STATUS, seq: req.seq, peer: req.peer });
        let mut expected = BlobBuf::new();
        expected.put_u32(attr::STATUS, (-7i32) as u32).put_u32(attr::OBJID, req.objid);
        assert_eq!(message.blob, expected.as_bytes());
        std::fs::File::from(write_end).write_all(b"descriptor").unwrap();
        let mut bytes = [0; 10];
        std::fs::File::from(message.fd.unwrap()).read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"descriptor");
    }

    #[test]
    fn no_reply_suppresses_status_but_keeps_existing_data_behavior() {
        let (mut server, mut client) = pair();
        let mut req = request();
        req.no_reply = true;
        server.reply_status(&req, 0, None).unwrap();
        client.stream.set_nonblocking(true).unwrap();
        assert_eq!(client.stream.read(&mut [0]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        client.stream.set_nonblocking(false).unwrap();
        server.reply_data(&req, &[]).unwrap();
        assert_eq!(client.recv().unwrap().header.ty, ty::DATA);
    }

    #[test]
    fn combined_replies_keep_both_frames_in_order_under_partial_writes() {
        for size in [0, 1, 3, 4, 65536, MAX_MSGLEN - 16] {
            let (mut server, mut client) = pair();
            server.stream.set_nonblocking(true).unwrap();
            let req = request();
            let fields: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let reader = std::thread::spawn(move || (client.recv().unwrap(), client.recv().unwrap()));
            server.reply_data_status(&req, &fields, -7).unwrap();
            let (data, status) = reader.join().unwrap();
            let mut expected_data = BlobBuf::new();
            expected_data.put_u32(attr::OBJID, req.objid).put(attr::DATA, &fields);
            let mut expected_status = BlobBuf::new();
            expected_status.put_u32(attr::STATUS, (-7i32) as u32).put_u32(attr::OBJID, req.objid);
            assert_eq!(data.header, Header { ty: ty::DATA, seq: req.seq, peer: req.peer });
            assert_eq!(status.header, Header { ty: ty::STATUS, seq: req.seq, peer: req.peer });
            assert_eq!(data.blob, expected_data.as_bytes(), "size {size}");
            assert_eq!(status.blob, expected_status.as_bytes(), "size {size}");
            assert!(data.fd.is_none() && status.fd.is_none());
        }
    }

    #[test]
    fn combined_reply_preserves_no_reply_and_oversized_data_status_behavior() {
        let (mut server, mut client) = pair();
        let mut req = request();
        req.no_reply = true;
        server.reply_data_status(&req, &[], -7).unwrap();
        assert_eq!(client.recv().unwrap().header.ty, ty::DATA);
        client.stream.set_nonblocking(true).unwrap();
        assert_eq!(client.stream.read(&mut [0]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        client.stream.set_nonblocking(false).unwrap();
        req.no_reply = false;
        assert!(server.reply_data_status(&req, &vec![0; MAX_MSGLEN - 15], 0).is_err());
        let status = client.recv().unwrap();
        assert_eq!(status.header.ty, ty::STATUS);
        assert_eq!(status.status(), Some(0));
    }
}
