//! Blocking ubus connection usable as client and as object server.

use crate::blob::{self, BlobBuf, MsgType};
use crate::msg::{attr, status, ty, Header, Message, MAX_MSGLEN, UBUS_SOCKET};
use crate::sys;
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
    /// Grows lazily for serving small INVOKEs, up to INCOMING_BUFFER_SIZE.
    /// Large frames use temporary storage instead of inflating this buffer.
    incoming_buf: Vec<u8>,
    /// Optional storage returned by a server after it has finished a request.
    spare_request: Option<Request>,
    /// Opt-in bound for daemon reads/replies outside a timed request.
    server_io_timeout: Option<Duration>,
}

const INCOMING_BUFFER_SIZE: usize = 4096;

struct ReceivedHeader {
    header: Header,
    blob_header: [u8; 4],
    len: usize,
    fd: Option<OwnedFd>,
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
        let stream = crate::connect::stream(path.unwrap_or(UBUS_SOCKET), deadline)?;
        let mut conn = Self {
            stream,
            local_id: 0,
            seq: 0,
            pending: VecDeque::new(),
            incoming_buf: Vec::new(),
            spare_request: None,
            server_io_timeout: None,
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

    fn send_server_parts<const N: usize>(&self, parts: [&[u8]; N], fd: Option<RawFd>) -> io::Result<()> {
        self.server_result(sys::send_parts_until(self.as_raw_fd(), parts, fd, self.server_deadline()))
    }

    /// Messages already read from the socket but not yet handed out.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
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

    #[cfg(test)]
    fn recv_head(&mut self) -> io::Result<ReceivedHeader> {
        self.recv_head_until(None)
    }

    fn recv_head_until(&mut self, deadline: Option<Instant>) -> io::Result<ReceivedHeader> {
        let mut head = [0u8; Header::LEN + 4];
        let fd = sys::recv_exact_until(self.stream.as_raw_fd(), &mut head, true, deadline)?;
        Self::decode_head(head, fd)
    }

    fn decode_head(head: [u8; Header::LEN + 4], fd: Option<OwnedFd>) -> io::Result<ReceivedHeader> {
        let header = Header::decode(head[..8].try_into().unwrap())
            .ok_or_else(|| io::Error::other("ubus: bad header"))?;
        let id_len = u32::from_be_bytes(head[8..12].try_into().unwrap());
        let raw_len = (id_len & 0x00ff_ffff) as usize;
        if !(4..=MAX_MSGLEN).contains(&raw_len) {
            return Err(io::Error::other("ubus: bad blob length"));
        }
        Ok(ReceivedHeader { header, blob_header: head[8..12].try_into().unwrap(), len: raw_len, fd })
    }

    #[cfg(test)]
    fn recv_body(&mut self, head: ReceivedHeader) -> io::Result<Message> {
        self.recv_body_until(head, None)
    }

    fn recv_body_until(&mut self, head: ReceivedHeader, deadline: Option<Instant>) -> io::Result<Message> {
        let mut blob = vec![0u8; head.len];
        blob[..4].copy_from_slice(&head.blob_header);
        if head.len > 4 {
            sys::recv_exact_until(self.stream.as_raw_fd(), &mut blob[4..], false, deadline)?;
        }
        Ok(Message { header: head.header, blob, fd: head.fd })
    }

    #[cfg(test)]
    fn recv(&mut self) -> io::Result<Message> {
        let head = self.recv_head()?;
        self.recv_body(head)
    }

    fn recv_until(&mut self, deadline: Option<Instant>) -> io::Result<Message> {
        let mut bytes = [0u8; Header::LEN + 4];
        let fd = sys::recv_exact_until(self.as_raw_fd(), &mut bytes, true, deadline)?;
        let head = Self::decode_head(bytes, fd)?;
        let mut blob = vec![0u8; head.len];
        blob[..4].copy_from_slice(&head.blob_header);
        sys::recv_exact_until(self.as_raw_fd(), &mut blob[4..], false, deadline)
            .map_err(sys::partial_timeout)?;
        Ok(Message { header: head.header, blob, fd: head.fd })
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
        // One deadline covers sending and every byte of every reply. A
        // readable prefix alone must not turn a bounded call into a hang.
        let deadline = (timeout_ms > 0)
            .then(|| Instant::now() + Duration::from_millis(timeout_ms as u64));
        let result = self.request_until(cmd, peer, blob, fd, deadline);
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

    fn request_until(&mut self, cmd: u8, peer: u32, blob: &mut BlobBuf, fd: Option<RawFd>, deadline: Option<Instant>) -> io::Result<Reply> {
        if blob.as_bytes().len() > MAX_MSGLEN {
            return Err(ubus_error(status::INVALID_ARGUMENT));
        }
        let seq = self.next_seq();
        sys::send_with_fd_until(self.as_raw_fd(), &Header { ty: cmd, seq, peer }.encode(), blob.as_bytes(), fd, deadline)?;
        let mut reply = Reply {
            status: status::UNKNOWN_ERROR,
            data: Vec::new(),
            fd: None,
        };
        loop {
            let mut message = self.recv_until(deadline)?;
            if message.header.seq != seq || message.header.peer != peer {
                self.pending.push_back(message);
                continue;
            }
            match message.header.ty {
                ty::DATA => reply.data.push(message.blob[4..].to_vec()),
                ty::STATUS => {
                    // libubus-req.c defaults a STATUS without a status attr
                    // to UBUS_STATUS_INVALID_ARGUMENT.
                    reply.status = message.status().unwrap_or(status::INVALID_ARGUMENT);
                    reply.fd = message.fd.take();
                    return Ok(reply);
                }
                _ => self.pending.push_back(message),
            }
        }
    }

    /// Resolve an object path to its id.
    pub fn lookup_id(&mut self, path: &str, timeout_ms: i32) -> io::Result<u32> {
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, path);
        let reply = self.request(ty::LOOKUP, 0, &mut b, None, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        for payload in &reply.data {
            let mut id = None;
            let mut matches = false;
            for a in blob::iter(payload) {
                if a.id == attr::OBJID {
                    id = a.as_u32();
                } else if a.id == attr::OBJPATH {
                    matches = a.as_str() == Some(path);
                }
            }
            if matches {
                if let Some(id) = id {
                    return Ok(id);
                }
            }
        }
        Err(ubus_error(status::NOT_FOUND))
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
        self.add_object_maybe_anonymous(Some(path), methods, timeout_ms)
    }

    /// Register an object with no path. ubusd assigns an id but the object is
    /// not listed and cannot be invoked by name -- which is what a subscriber
    /// is. `ubus_register_subscriber` does exactly this before subscribing.
    pub fn add_anonymous_object(&mut self, timeout_ms: i32) -> io::Result<u32> {
        self.add_object_maybe_anonymous(None, &[], timeout_ms)
    }

    fn add_object_maybe_anonymous(
        &mut self,
        path: Option<&str>,
        methods: &[(&str, &[(&str, MsgType)])],
        timeout_ms: i32,
    ) -> io::Result<u32> {
        let mut b = BlobBuf::new();
        if let Some(path) = path {
            b.put_string(attr::OBJPATH, path);
        }
        let sig = b.nest_start(attr::SIGNATURE);
        for (name, policy) in methods {
            let table = b.msg_open_table(name);
            for (arg, kind) in *policy {
                b.msg_u32(arg, *kind as u32);
            }
            b.msg_close(table);
        }
        b.nest_end(sig);
        let reply = self.request(ty::ADD_OBJECT, 0, &mut b, None, timeout_ms)?;
        if reply.status != status::OK {
            return Err(ubus_error(reply.status));
        }
        for payload in &reply.data {
            for a in blob::iter(payload) {
                if a.id == attr::OBJID {
                    if let Some(id) = a.as_u32() {
                        return Ok(id);
                    }
                }
            }
        }
        Err(ubus_error(status::NO_DATA))
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
        let deadline = self.server_deadline();
        let result = self.recv_head_until(deadline)
            .and_then(|head| self.read_incoming_body(head, deadline));
        self.server_result(result)
    }

    /// Read a frame without a separate readiness wait when its first byte is
    /// already available. An empty socket returns None; a started frame uses
    /// the existing blocking completion rules. Does not change socket flags.
    pub fn incoming_if_started(&mut self) -> io::Result<Option<Incoming>> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Some(Self::classify(message)));
        }
        let mut head = [0u8; Header::LEN + 4];
        let deadline = self.server_deadline();
        let fd = match sys::recv_exact_if_started_until(self.stream.as_raw_fd(), &mut head, true, deadline) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return self.server_result(Err(e)),
        };
        let result = self.read_incoming_body(Self::decode_head(head, fd)?, deadline).map(Some);
        self.server_result(result)
    }

    fn read_incoming_body(&mut self, head: ReceivedHeader, deadline: Option<Instant>) -> io::Result<Incoming> {
        if head.header.ty == ty::INVOKE && head.len <= INCOMING_BUFFER_SIZE {
            if self.incoming_buf.len() < head.len {
                self.incoming_buf.resize(head.len.next_power_of_two(), 0);
            }
            let blob = &mut self.incoming_buf[..head.len];
            blob[..4].copy_from_slice(&head.blob_header);
            if head.len > 4 {
                sys::recv_exact_until(self.stream.as_raw_fd(), &mut blob[4..], false, deadline)?;
            }
            return Ok(Incoming::Invoke(Self::decode_request(head.header, blob, head.fd, self.spare_request.take())));
        }
        Ok(Self::classify(self.recv_body_until(head, deadline)?))
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
        let conn = |stream| Connection { stream, local_id: 0, seq: 0, pending: VecDeque::new(), incoming_buf: Vec::new(), spare_request: None, server_io_timeout: None };
        (conn(a), conn(b))
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
        assert_eq!(client.pending.len(), 1, "late response retains its own sequence");
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
            assert!(receiver.incoming_buf.capacity() <= INCOMING_BUFFER_SIZE);
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
        // A short request must not reserve the entire 4 KiB limit.
        assert!(receiver.incoming_buf.capacity() <= 256);
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
        assert_eq!(receiver.incoming_buf.capacity(), 0);

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
            if len <= INCOMING_BUFFER_SIZE {
                retained.get_or_insert(receiver.incoming_buf.as_ptr());
            }
            if let Some(pointer) = retained {
                assert_eq!(receiver.incoming_buf.as_ptr(), pointer);
                assert_eq!(receiver.incoming_buf.capacity(), INCOMING_BUFFER_SIZE);
            } else {
                assert_eq!(receiver.incoming_buf.capacity(), 0);
            }
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
            assert!(receiver.incoming_buf.capacity() <= INCOMING_BUFFER_SIZE);
            for (length, req) in &held {
                assert_eq!(req.data.len(), *length);
                assert!(req.data.iter().all(|b| *b == 0xa5));
            }
        }
    }

    #[test]
    fn queued_invokes_keep_order_and_do_not_allocate_receive_storage() {
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
        assert_eq!(receiver.incoming_buf.capacity(), 0);
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
            assert!(receiver.incoming_buf.capacity() <= INCOMING_BUFFER_SIZE);
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
