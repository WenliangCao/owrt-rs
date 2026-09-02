//! Blocking ubus connection usable as client and as object server.

use crate::blob::{self, BlobBuf, MsgType};
use crate::msg::{attr, status, ty, Header, Message, MAX_MSGLEN, UBUS_SOCKET};
use crate::sys;
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

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
}

fn ubus_error(code: i32) -> io::Error {
    io::Error::other(format!("ubus: {} ({code})", status::name(code)))
}

impl Connection {
    pub fn connect(path: Option<&str>) -> io::Result<Self> {
        let stream = UnixStream::connect(path.unwrap_or(UBUS_SOCKET))?;
        let mut conn = Self {
            stream,
            local_id: 0,
            seq: 0,
            pending: VecDeque::new(),
        };
        let hello = conn.recv()?;
        if hello.header.ty != ty::HELLO {
            return Err(io::Error::other("ubus: expected HELLO"));
        }
        conn.local_id = hello.header.peer;
        Ok(conn)
    }

    pub fn local_id(&self) -> u32 {
        self.local_id
    }

    /// Messages already read from the socket but not yet handed out.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    fn send(&mut self, header: Header, blob: &mut BlobBuf, fd: Option<RawFd>) -> io::Result<()> {
        let body = blob.as_bytes();
        if body.len() > MAX_MSGLEN {
            return Err(ubus_error(status::INVALID_ARGUMENT));
        }
        sys::send_with_fd(self.stream.as_raw_fd(), &header.encode(), body, fd)
    }

    fn recv(&mut self) -> io::Result<Message> {
        let mut head = [0u8; Header::LEN + 4];
        let fd = sys::recv_exact(self.stream.as_raw_fd(), &mut head, true)?;
        let header = Header::decode(head[..8].try_into().unwrap())
            .ok_or_else(|| io::Error::other("ubus: bad header"))?;
        let id_len = u32::from_be_bytes(head[8..12].try_into().unwrap());
        let raw_len = (id_len & 0x00ff_ffff) as usize;
        if !(4..=MAX_MSGLEN).contains(&raw_len) {
            return Err(io::Error::other("ubus: bad blob length"));
        }
        let mut blob = vec![0u8; raw_len];
        blob[..4].copy_from_slice(&head[8..12]);
        if raw_len > 4 {
            sys::recv_exact(self.stream.as_raw_fd(), &mut blob[4..], false)?;
        }
        Ok(Message { header, blob, fd })
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
        let seq = self.next_seq();
        self.send(Header { ty: cmd, seq, peer }, blob, fd)?;
        let mut reply = Reply {
            status: status::UNKNOWN_ERROR,
            data: Vec::new(),
            fd: None,
        };
        loop {
            if !sys::wait_readable(self.stream.as_raw_fd(), timeout_ms)? {
                return Err(ubus_error(status::TIMEOUT));
            }
            let mut message = self.recv()?;
            if message.header.seq != seq || message.header.peer != peer {
                self.pending.push_back(message);
                continue;
            }
            match message.header.ty {
                ty::DATA => reply.data.push(message.blob[4..].to_vec()),
                ty::STATUS => {
                    reply.status = message.status().unwrap_or(status::UNKNOWN_ERROR);
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

    /// Register an object. `methods` lists (name, [(arg name, arg type)]).
    /// Returns the object id assigned by ubusd.
    pub fn add_object(
        &mut self,
        path: &str,
        methods: &[(&str, &[(&str, MsgType)])],
        timeout_ms: i32,
    ) -> io::Result<u32> {
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, path);
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
        let message = match self.pending.pop_front() {
            Some(message) => message,
            None => {
                if !sys::wait_readable(self.stream.as_raw_fd(), timeout_ms)? {
                    return Ok(None);
                }
                self.recv()?
            }
        };
        Ok(Some(Self::classify(message)))
    }

    /// Drain one message if one is already readable (used after poll()).
    pub fn read_incoming(&mut self) -> io::Result<Incoming> {
        let message = match self.pending.pop_front() {
            Some(message) => message,
            None => self.recv()?,
        };
        Ok(Self::classify(message))
    }

    fn classify(mut message: Message) -> Incoming {
        let attrs = message.attrs();
        let objid = attrs[attr::OBJID as usize].and_then(|a| a.as_u32());
        match message.header.ty {
            ty::INVOKE => {
                let method = attrs[attr::METHOD as usize]
                    .and_then(|a| a.as_str())
                    .unwrap_or("")
                    .to_owned();
                let user = attrs[attr::USER as usize]
                    .and_then(|a| a.as_str())
                    .map(str::to_owned);
                let group = attrs[attr::GROUP as usize]
                    .and_then(|a| a.as_str())
                    .map(str::to_owned);
                let data = attrs[attr::DATA as usize]
                    .map(|a| a.payload.to_vec())
                    .unwrap_or_default();
                let no_reply = attrs[attr::NO_REPLY as usize]
                    .and_then(|a| a.as_u32())
                    .unwrap_or(0)
                    != 0;
                let fd = message.fd.take();
                Incoming::Invoke(Request {
                    peer: message.header.peer,
                    seq: message.header.seq,
                    objid: objid.unwrap_or(0),
                    method,
                    user,
                    group,
                    data,
                    fd,
                    no_reply,
                })
            }
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

    /// Finish `req` with a status code and an optional fd for the caller.
    pub fn reply_status(&mut self, req: &Request, code: i32, fd: Option<RawFd>) -> io::Result<()> {
        if req.no_reply {
            return Ok(());
        }
        let mut b = BlobBuf::new();
        b.put_u32(attr::STATUS, code as u32)
            .put_u32(attr::OBJID, req.objid);
        self.send(
            Header {
                ty: ty::STATUS,
                seq: req.seq,
                peer: req.peer,
            },
            &mut b,
            fd,
        )
    }
}
