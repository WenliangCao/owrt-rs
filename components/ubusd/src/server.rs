//! The bus itself: client table, message dispatch and the three built-in
//! system objects. Single-threaded; every handler runs to completion against
//! `&mut Server`, so there is no shared mutable state to reason about.

use crate::acl::{Acl, AclType, Cred};
use crate::client::{Client, InMsg, OutMsg, PendingCmd};
use crate::obj::{self, Registry, SYSTEM_OBJECT_ACL, SYSTEM_OBJECT_EVENT, SYSTEM_OBJECT_MAX, SYSTEM_OBJECT_MONITOR};
use owrt_ubus::blob::{self, BlobBuf, MsgType};
use owrt_ubus::msg::{attr, status, ty, Header};
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::ops::Bound::{Included, Unbounded};

/// What a handler decided: reply with this status, reply with nothing (the
/// handler already sent what was needed), or the command was parked.
enum Outcome {
    Status(i32),
    NoStatus,
    Queued,
}

struct Pattern {
    key: Vec<u8>,
    partial: bool,
    obj: u32,
}

/// A client's credentials, copied out so ACL checks do not borrow the table.
struct ClientCred {
    uid: u32,
    gid: u32,
    extra: Vec<u32>,
    user: String,
    group: String,
}

impl ClientCred {
    fn as_cred(&self) -> Cred<'_> {
        Cred { uid: self.uid, gid: self.gid, extra_gid: &self.extra }
    }
}

pub struct Server {
    pub reg: Registry,
    pub clients: HashMap<u32, Client>,
    pub acl: Acl,
    pub acl_dir: String,
    /// Event patterns, sorted by key; equal keys keep registration order.
    patterns: Vec<Pattern>,
    event_seq: u16,
    obj_event_seq: u32,
    /// Clients running `ubus monitor`, with their own sequence counters.
    monitors: Vec<(u32, u16)>,
    /// Reusable assembly buffer, the equivalent of the C daemon's static
    /// `blob_buf b`. A fresh BlobBuf starts at a 4-byte allocation and has to
    /// grow repeatedly for a multi-kilobyte object signature; keeping one
    /// around means that growth happens once.
    scratch: BlobBuf,
    /// A short prefix query is submitted together. Capacity is acquired only
    /// on first use and bounded to 16 KiB; larger queries keep the old path.
    lookup_batch: Vec<u8>,
    /// Clients written to since the loop last looked: only these can have
    /// changed whether they need output readiness. Ids may repeat.
    pub touched: Vec<u32>,
}

impl Server {
    pub fn new(acl_dir: String) -> std::io::Result<Self> {
        let mut reg = Registry::default();
        for id in [SYSTEM_OBJECT_EVENT, SYSTEM_OBJECT_ACL, SYSTEM_OBJECT_MONITOR] {
            reg.create(None, Some(id))?;
        }
        Ok(Server {
            reg,
            clients: HashMap::new(),
            acl: Acl::default(),
            acl_dir,
            patterns: Vec::new(),
            event_seq: 0,
            obj_event_seq: 0,
            monitors: Vec::new(),
            scratch: BlobBuf::new(),
            lookup_batch: Vec::new(),
            touched: Vec::new(),
        })
    }

    pub fn load_acl(&mut self) {
        let dir = self.acl_dir.clone();
        // nothing to load: C returns before vlist_update, seq++ and the event
        if !self.acl.load(&dir) {
            return;
        }
        let seq = self.acl.seq;
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, 0);
        b.put_string(attr::METHOD, "ubus.acl.sequence");
        let d = b.nest_start(attr::DATA);
        b.msg_u32("sequence", seq);
        b.nest_end(d);
        let payload = b.as_bytes().to_vec();
        self.dispatch_event(None, b"ubus.acl.sequence", payload);
    }

    // ---------------------------------------------------------------- clients

    pub fn add_client(&mut self, sock: OwnedFd) -> std::io::Result<u32> {
        let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
        let cred = crate::sys::peer_cred(fd)?;
        // The C daemon refuses a connection whose uid or gid has no entry
        // rather than inventing a name for it.
        let user = crate::sys::user_name(cred.uid)
            .ok_or_else(|| std::io::Error::other("no passwd entry for peer uid"))?;
        let group = crate::sys::group_name(cred.gid)
            .ok_or_else(|| std::io::Error::other("no group entry for peer gid"))?;

        let id = Registry::alloc_id(|id| self.clients.contains_key(&id))?;
        self.clients.insert(id, Client::new(sock, cred, user, group));
        // HELLO carries an empty blob and the client's own id as peer. It goes
        // out through Server::send so that it reaches any monitor, which is
        // what ubusd_send_hello -> ubus_msg_send does.
        let mut b = BlobBuf::new();
        let hello = OutMsg::new(ty::HELLO, 0, id, b.as_bytes().to_vec());
        self.send(id, hello);
        Ok(id)
    }

    pub fn remove_client(&mut self, id: u32) {
        self.monitors.retain(|(c, _)| *c != id);
        let objects = self.clients.get(&id).map(|c| c.objects.clone()).unwrap_or_default();
        for obj in objects {
            self.free_object(obj);
        }
        self.clients.remove(&id);
    }

    fn cred_of(&self, id: u32) -> Option<ClientCred> {
        let c = self.clients.get(&id)?;
        Some(ClientCred {
            uid: c.uid,
            gid: c.gid,
            extra: c.extra_gid.clone(),
            user: c.user.clone(),
            group: c.group.clone(),
        })
    }

    fn send(&mut self, client: u32, msg: OutMsg) {
        if msg.header.ty != ty::MONITOR {
            Self::mirror(&mut self.clients, &mut self.monitors, &mut self.touched, client, &msg.header, &msg.blob, true);
        }
        if let Some(c) = self.clients.get_mut(&client) {
            c.send(msg);
            self.touched.push(client);
        }
    }

    /// Send the assembled bytes directly. Keeping the buffer in its field
    /// avoids mem::take constructing and dropping an allocated empty buffer.
    fn send_scratch(&mut self, client: u32, header: Header, fd: Option<OwnedFd>) {
        let blob = self.scratch.as_bytes();
        if header.ty != ty::MONITOR {
            Self::mirror(&mut self.clients, &mut self.monitors, &mut self.touched, client, &header, blob, true);
        }
        if let Some(c) = self.clients.get_mut(&client) {
            c.send_borrowed(header, blob, fd);
            self.touched.push(client);
        }
    }

    // ------------------------------------------------------------- dispatch

    /// Handle one received message. Returns false when the client must go.
    pub fn receive(&mut self, client: u32, msg: InMsg) -> bool {
        Self::mirror(&mut self.clients, &mut self.monitors, &mut self.touched, client, &msg.header, &msg.blob, false);

        let seq = msg.header.seq;
        let peer = msg.header.peer;
        let outcome = self.handle(client, msg);
        match outcome {
            Outcome::Queued | Outcome::NoStatus => true,
            Outcome::Status(code) => {
                self.send_status(client, seq, peer, code);
                true
            }
        }
    }

    fn send_status(&mut self, client: u32, seq: u16, peer: u32, code: i32) {
        // the shared buffer, borrowed: a STATUS is the most frequent message
        // on the bus and the C daemon builds it in its static blob_buf too
        let b = &mut self.scratch;
        b.reset();
        b.put_u32(attr::STATUS, code as u32);
        self.send_scratch(client, Header { ty: ty::STATUS, seq, peer }, None);
    }

    fn handle(&mut self, client: u32, mut msg: InMsg) -> Outcome {
        // Only STATUS and INVOKE carry a descriptor onwards; anything else
        // drops it here, as ubus_msg_close_fd does.
        if msg.header.ty != ty::STATUS && msg.header.ty != ty::INVOKE {
            msg.fd = None;
        }
        match msg.header.ty {
            ty::PING => {
                let out = OutMsg::new(ty::DATA, msg.header.seq, msg.header.peer, msg.blob);
                self.send(client, out);
                // The handler returns 0 in the C daemon, so a STATUS follows
                // the echo; libubus waits for it to complete the request.
                Outcome::Status(status::OK)
            }
            ty::ADD_OBJECT => self.add_object(client, &msg),
            ty::REMOVE_OBJECT => self.remove_object(client, &msg),
            ty::LOOKUP => self.lookup_entry(client, msg),
            ty::INVOKE => self.invoke(client, msg),
            ty::STATUS | ty::DATA => self.response(client, msg),
            ty::SUBSCRIBE => self.add_watch(client, &msg),
            ty::UNSUBSCRIBE => self.remove_watch(client, &msg),
            ty::NOTIFY => self.notify(client, &msg),
            _ => Outcome::Status(status::INVALID_COMMAND),
        }
    }

    // -------------------------------------------------------------- objects

    fn add_object(&mut self, client: u32, msg: &InMsg) -> Outcome {
        let attrs = attrs_of(msg.payload());
        let type_id = if let Some(a) = attrs[attr::OBJTYPE as usize] {
            a.as_u32().and_then(|t| self.reg.ref_type(t))
        } else if let Some(sig) = attrs[attr::SIGNATURE as usize] {
            let mut methods = Vec::new();
            let mut ok = true;
            let mut offset = 0;
            loop {
                // blob_for_each_attr visits a 1..3-byte raw attribute; the
                // method validator then rejects it. It must not become an
                // apparently empty (valid) signature when our iterator stops.
                if short_attr(sig.payload, offset) {
                    ok = false;
                    break;
                }
                let Some((item, next)) = blob::attr_at(sig.payload, offset) else { break };
                offset = next;
                match check_method(&item) {
                    Some(name) => {
                        let blob = method_blob(&item, &name);
                        methods.push(obj::Method { name, blob });
                    }
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                self.reg.new_type(methods).ok()
            } else {
                // ubus_create_obj_type returns NULL on a bad signature and the
                // C daemon carries on, creating an object with no type: it gets
                // an id and can be removed, but never appears in a lookup.
                None
            }
        } else {
            None
        };

        let Ok(id) = self.reg.create(type_id, None) else {
            if let Some(t) = type_id {
                self.reg.unref_type(t);
            }
            return Outcome::Status(status::INVALID_ARGUMENT);
        };
        // create() took its own reference; drop the one this call held.
        if let Some(t) = type_id {
            self.reg.unref_type(t);
        }

        if let Some(p) = attrs[attr::OBJPATH as usize] {
            let path = obj::cstr_bytes(p.payload).to_vec();
            let cred = self.cred_of(client);
            let allowed = self.acl.check(cred.as_ref().map(|c| c.as_cred()).as_ref(), Some(&path), None, AclType::Publish);
            if !allowed || !self.reg.set_path(id, path) {
                self.reg.destroy(id);
                return Outcome::Status(status::INVALID_ARGUMENT);
            }
            self.send_obj_event(id, true);
        }

        if let Some(o) = self.reg.get_mut(id) {
            o.client = Some(client);
        }
        if let Some(c) = self.clients.get_mut(&client) {
            c.objects.insert(0, id);
        }

        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, id);
        if attrs[attr::SIGNATURE as usize].is_some() {
            if let Some(t) = type_id {
                b.put_u32(attr::OBJTYPE, t);
            }
        }
        let out = OutMsg::new(ty::DATA, msg.header.seq, msg.header.peer, b.as_bytes().to_vec());
        self.send(client, out);
        Outcome::Status(status::OK)
    }

    fn remove_object(&mut self, client: u32, msg: &InMsg) -> Outcome {
        let attrs = attrs_of(msg.payload());
        let Some(id) = attrs[attr::OBJID as usize].and_then(|a| a.as_u32()) else {
            return Outcome::Status(status::INVALID_ARGUMENT);
        };
        let Some(o) = self.reg.get(id) else {
            return Outcome::Status(status::NOT_FOUND);
        };
        if o.client != Some(client) {
            return Outcome::Status(status::PERMISSION_DENIED);
        }
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, id);
        // The type id is echoed only when this removal destroys it.
        if let Some(t) = o.type_id {
            if self.reg.types.get(&t).is_some_and(|t| t.refcount == 1) {
                b.put_u32(attr::OBJTYPE, t);
            }
        }
        let out = OutMsg::new(ty::DATA, msg.header.seq, msg.header.peer, b.as_bytes().to_vec());
        self.send(client, out);
        self.free_object(id);
        Outcome::Status(status::OK)
    }

    /// Tear an object down: unsubscribe both directions (telling every
    /// subscriber first), drop its event patterns and announce its removal.
    fn free_object(&mut self, id: u32) {
        let Some(o) = self.reg.get(id) else { return };
        let targets = o.targets.clone();
        let subscribers = o.subscribers.clone();
        let owner = o.client;

        for t in targets {
            if self.reg.unsubscribe(id, t) {
                self.notify_subscription(t);
            }
        }
        for s in subscribers {
            // ubus_notify_unsubscribe: UNSUBSCRIBE to the subscriber, then
            // ubus_unsubscribe(), which tells the owner NOTIFY(ACTIVE=0) once
            // the last subscriber is gone -- the object still exists here
            self.notify_unsubscribe(s, id);
            if self.reg.unsubscribe(s, id) {
                self.notify_subscription(id);
            }
        }
        self.patterns.retain(|p| p.obj != id);

        if self.reg.get(id).and_then(|o| o.path.as_ref()).is_some() {
            self.send_obj_event(id, false);
        }
        if let Some(owner) = owner {
            if let Some(c) = self.clients.get_mut(&owner) {
                c.objects.retain(|&o| o != id);
            }
        }
        self.reg.destroy(id);
    }

    // --------------------------------------------------------------- lookup

    fn lookup_entry(&mut self, client: u32, msg: InMsg) -> Outcome {
        let busy = self.clients.get(&client).is_some_and(|c| !c.tx_empty());
        if busy {
            if let Some(c) = self.clients.get_mut(&client) {
                c.cmd_queue.push_back(PendingCmd { msg, next: None });
            }
            return Outcome::Queued;
        }
        match self.lookup(client, &msg, None) {
            Ok(outcome) => outcome,
            Err(next) => {
                if let Some(c) = self.clients.get_mut(&client) {
                    c.cmd_queue.push_back(PendingCmd { msg, next });
                }
                Outcome::Queued
            }
        }
    }

    /// Resume parked LOOKUPs now that the queue drained. Mirrors
    /// `ubus_client_cmd_queue_process`.
    pub fn process_cmd_queue(&mut self, client: u32) {
        loop {
            // A completed reply may itself have started buffering. Leave the
            // next LOOKUP parked until that output drains as well.
            if self.clients.get(&client).is_some_and(|c| !c.tx_empty()) {
                return;
            }
            let Some(cmd) = self.clients.get_mut(&client).and_then(|c| c.cmd_queue.pop_front())
            else {
                return;
            };
            match self.lookup(client, &cmd.msg, cmd.next) {
                Ok(outcome) => {
                    if let Outcome::Status(code) = outcome {
                        self.send_status(client, cmd.msg.header.seq, cmd.msg.header.peer, code);
                    }
                }
                Err(next) => {
                    if let Some(c) = self.clients.get_mut(&client) {
                        c.cmd_queue.push_front(PendingCmd { msg: cmd.msg, next });
                    }
                    return;
                }
            }
        }
    }

    /// `Ok(outcome)` when the lookup finished; `Err(next)` when the transmit
    /// queue filled and it must resume at path `next` (even if its object
    /// has been deleted in the meantime).
    fn lookup(&mut self, client: u32, msg: &InMsg, resume: Option<Vec<u8>>) -> Result<Outcome, Option<Vec<u8>>> {
        let attrs = attrs_of(msg.payload());
        let Some(p) = attrs[attr::OBJPATH as usize] else {
            return self.lookup_range(client, msg, b"", resume, true);
        };

        let path = obj::cstr_bytes(p.payload);
        if path.is_empty() {
            return Ok(Outcome::Status(status::INVALID_ARGUMENT));
        }
        if path[path.len() - 1] != b'*' {
            let Some(id) = self.reg.by_path(path) else {
                return Ok(Outcome::Status(status::NOT_FOUND));
            };
            if self.monitors.is_empty() {
                if self.build_obj(client, id) {
                    let header = Header { ty: ty::DATA, seq: msg.header.seq, peer: msg.header.peer };
                    if let Some(c) = self.clients.get_mut(&client) {
                        c.send_lookup_reply(header, self.scratch.as_bytes());
                        self.touched.push(client);
                    }
                    return Ok(Outcome::NoStatus);
                }
                return Ok(Outcome::Status(status::OK));
            }
            self.send_obj(client, id, msg);
            return Ok(Outcome::Status(status::OK));
        }

        self.lookup_range(client, msg, &path[..path.len() - 1], resume, false)
    }

    /// Borrow the ordered index throughout this dispatch. Only a parked
    /// command owns a path; no array proportional to the result is allocated.
    fn lookup_range(&mut self, client: u32, msg: &InMsg, prefix: &[u8], resume: Option<Vec<u8>>, all: bool)
        -> Result<Outcome, Option<Vec<u8>>>
    {
        let resumed = resume.is_some();
        let lower = resume.as_deref().unwrap_or(prefix);
        let paths = self.reg.paths.range::<[u8], _>((Included(lower), Unbounded))
            .take_while(|(path, _)| path.starts_with(prefix));
        if paths.clone().next().is_none() {
            // An initially unmatched prefix differs from an empty bus or a
            // continuation whose remaining objects have all been removed.
            return Ok(Outcome::Status(if all || resumed { status::OK } else { status::NOT_FOUND }));
        }
        let header = Header { ty: ty::DATA, seq: msg.header.seq, peer: msg.header.peer };
        // Retain the existing 16 KiB eligibility bound and one-write policy.
        // Stop the sizing walk immediately when the bound is exceeded.
        let bytes = if self.monitors.is_empty() && !(all && resumed) {
            paths.clone().try_fold(Header::LEN + 12, |mut bytes, (_, &id)| {
                if let Some(o) = self.reg.get(id) {
                    if let (Some(path), Some(t)) = (o.path.as_deref(), o.type_id.and_then(|id| self.reg.types.get(&id))) {
                        bytes += Header::LEN + 4 + crate::client::pad4(4 + path.len() + 1) + 8 + 8 + 4;
                        bytes += t.methods.iter().map(|m| crate::client::pad4(m.blob.len())).sum::<usize>();
                    }
                }
                (bytes <= 16 * 1024).then_some(bytes)
            })
        } else {
            None
        };
        if let Some(bytes) = bytes {
            self.lookup_batch.clear();
            self.lookup_batch.reserve_exact(bytes);
            let cred = self.clients.get(&client).map(|c| Cred { uid: c.uid, gid: c.gid, extra_gid: &c.extra_gid });
            for (_, &id) in paths {
                if Self::encode_obj(&self.reg, &self.acl, cred.as_ref(), id, &mut self.scratch) {
                    self.lookup_batch.extend_from_slice(&header.encode());
                    self.lookup_batch.extend_from_slice(self.scratch.as_bytes());
                }
            }
            self.scratch.reset();
            self.scratch.put_u32(attr::STATUS, status::OK as u32);
            self.lookup_batch.extend_from_slice(&Header { ty: ty::STATUS, ..header }.encode());
            self.lookup_batch.extend_from_slice(self.scratch.as_bytes());
            debug_assert!(self.lookup_batch.len() <= bytes);
            if let Some(c) = self.clients.get_mut(&client) {
                c.send_lookup_batch(&self.lookup_batch);
                self.touched.push(client);
            }
            self.lookup_batch.clear();
            return Ok(Outcome::NoStatus);
        }
        for (path, &id) in paths {
            if self.clients.get(&client).is_some_and(|c| !c.tx_empty()) {
                return Err(Some(path.to_vec()));
            }
            let cred = self.clients.get(&client).map(|c| Cred { uid: c.uid, gid: c.gid, extra_gid: &c.extra_gid });
            if Self::encode_obj(&self.reg, &self.acl, cred.as_ref(), id, &mut self.scratch) {
                let blob = self.scratch.as_bytes();
                Self::mirror(&mut self.clients, &mut self.monitors, &mut self.touched, client, &header, blob, true);
                if let Some(c) = self.clients.get_mut(&client) {
                    c.send_borrowed(header, blob, None);
                    self.touched.push(client);
                }
            }
        }
        Ok(Outcome::Status(status::OK))
    }

    /// One object's description. Objects with no type are invisible, and a
    /// client that may call none of a type's methods does not see the object.
    fn send_obj(&mut self, client: u32, id: u32, msg: &InMsg) {
        if self.build_obj(client, id) {
            let header = Header { ty: ty::DATA, seq: msg.header.seq, peer: msg.header.peer };
            self.send_scratch(client, header, None);
        }
    }

    fn build_obj(&mut self, client: u32, id: u32) -> bool {
        let cred = self.clients.get(&client).map(|c| Cred { uid: c.uid, gid: c.gid, extra_gid: &c.extra_gid });
        Self::encode_obj(&self.reg, &self.acl, cred.as_ref(), id, &mut self.scratch)
    }

    fn encode_obj(reg: &Registry, acl: &Acl, cred: Option<&Cred<'_>>, id: u32, b: &mut BlobBuf) -> bool {
        let Some(o) = reg.get(id) else { return false };
        let Some(type_id) = o.type_id else { return false };
        let Some(path) = o.path.as_deref() else { return false };
        let Some(t) = reg.types.get(&type_id) else { return false };

        b.reset();
        b.put_string_bytes(attr::OBJPATH, path);
        b.put_u32(attr::OBJID, id);
        b.put_u32(attr::OBJTYPE, type_id);
        let s = b.nest_start(attr::SIGNATURE);
        let mut all = 0usize;
        let mut visible = 0usize;
        for m in &t.methods {
            all += 1;
            if acl.check(cred, Some(path), Some(&m.name), AclType::Access) {
                b.put_raw_fields(&m.blob);
                visible += 1;
            }
        }
        b.nest_end(s);
        visible > 0 || all == 0
    }

    // --------------------------------------------------------------- invoke

    fn invoke(&mut self, client: u32, msg: InMsg) -> Outcome {
        let attrs = attrs_of(msg.payload());
        let (Some(method), Some(id)) = (
            attrs[attr::METHOD as usize].map(|a| obj::cstr_bytes(a.payload)),
            attrs[attr::OBJID as usize].and_then(|a| a.as_u32()),
        ) else {
            return Outcome::Status(status::INVALID_ARGUMENT);
        };
        let Some(o) = self.reg.get(id) else {
            return Outcome::Status(status::NOT_FOUND);
        };
        let owner = o.client;
        // `obj->path.key` is NULL for the system objects and for anonymous
        // objects; ubusd_acl_check then allows the call outright (F02)
        let path = o.path.as_deref();

        // Borrow the caller's credentials rather than copying them: this is
        // the hot path, and the table and the ACL are disjoint fields.
        let caller = self.clients.get(&client);
        let cred = caller.map(|c| Cred { uid: c.uid, gid: c.gid, extra_gid: &c.extra_gid });
        if !self.acl.check(cred.as_ref(), path, Some(method), AclType::Access) {
            return Outcome::Status(status::PERMISSION_DENIED);
        }

        let data = attrs[attr::DATA as usize].map(|a| a.payload);
        let Some(owner) = owner else {
            let data = data.map(<[u8]>::to_vec);
            let method = method.to_vec();
            return self.system_object(client, id, &method, msg, data);
        };

        let who = caller.map(|c| (c.user.as_str(), c.group.as_str()));
        build_forward_blob(&mut self.scratch, id, method, who, data, None);
        self.send_scratch(owner, Header { ty: ty::INVOKE, seq: msg.header.seq, peer: client }, msg.fd);
        Outcome::NoStatus
    }

    /// A reply (STATUS or DATA) travelling from an object's owner back to the
    /// original caller. Every failure here is silent, as in the C daemon.
    fn response(&mut self, client: u32, msg: InMsg) -> Outcome {
        let attrs = attrs_of(msg.payload());
        let Some(id) = attrs[attr::OBJID as usize].and_then(|a| a.as_u32()) else {
            return Outcome::NoStatus;
        };
        if msg.header.ty == ty::STATUS && attrs[attr::STATUS as usize].is_none() {
            return Outcome::NoStatus;
        }
        if msg.header.ty == ty::DATA && attrs[attr::DATA as usize].is_none() {
            return Outcome::NoStatus;
        }
        if self.reg.get(id).and_then(|o| o.client) != Some(client) {
            return Outcome::NoStatus;
        }
        let dest = msg.header.peer;
        if !self.clients.contains_key(&dest) {
            return Outcome::NoStatus;
        }
        let mut out = OutMsg::new(msg.header.ty, msg.header.seq, id, msg.blob);
        out.fd = msg.fd;
        self.send(dest, out);
        Outcome::NoStatus
    }

    // ---------------------------------------------------------- subscriptions

    fn add_watch(&mut self, client: u32, msg: &InMsg) -> Outcome {
        let attrs = attrs_of(msg.payload());
        let (Some(id), Some(target)) = (
            attrs[attr::OBJID as usize].and_then(|a| a.as_u32()),
            attrs[attr::TARGET as usize].and_then(|a| target_u32(a.payload)),
        ) else {
            return Outcome::Status(status::INVALID_ARGUMENT);
        };
        let Some(o) = self.reg.get(id) else {
            return Outcome::Status(status::NOT_FOUND);
        };
        if o.client != Some(client) {
            return Outcome::Status(status::INVALID_ARGUMENT);
        }
        let Some(t) = self.reg.get(target) else {
            return Outcome::Status(status::NOT_FOUND);
        };
        let Some(t_owner) = t.client else {
            return Outcome::Status(status::NOT_FOUND);
        };
        if t_owner == client {
            return Outcome::Status(status::INVALID_ARGUMENT);
        }
        let t_path = t.path.clone();

        // A denied subscribe reports NOT_FOUND, not PERMISSION_DENIED: an
        // unauthorized client must not learn the object exists.
        match t_path {
            None => {
                let (Some(a), Some(b)) = (self.cred_of(client), self.cred_of(t_owner)) else {
                    return Outcome::Status(status::NOT_FOUND);
                };
                if a.user != b.user && a.group != b.group {
                    return Outcome::Status(status::NOT_FOUND);
                }
            }
            Some(path) => {
                let cred = self.cred_of(client);
                if !self.acl.check(cred.as_ref().map(|c| c.as_cred()).as_ref(), Some(&path), None, AclType::Subscribe) {
                    return Outcome::Status(status::NOT_FOUND);
                }
            }
        }

        if self.reg.subscribe(id, target) {
            self.notify_subscription(target);
        }
        Outcome::Status(status::OK)
    }

    fn remove_watch(&mut self, client: u32, msg: &InMsg) -> Outcome {
        let attrs = attrs_of(msg.payload());
        let (Some(id), Some(target)) = (
            attrs[attr::OBJID as usize].and_then(|a| a.as_u32()),
            attrs[attr::TARGET as usize].and_then(|a| target_u32(a.payload)),
        ) else {
            return Outcome::Status(status::INVALID_ARGUMENT);
        };
        let Some(o) = self.reg.get(id) else {
            return Outcome::Status(status::NOT_FOUND);
        };
        if o.client != Some(client) {
            return Outcome::Status(status::INVALID_ARGUMENT);
        }
        if !o.targets.contains(&target) {
            return Outcome::Status(status::NOT_FOUND);
        }
        if self.reg.unsubscribe(id, target) {
            self.notify_subscription(target);
        }
        Outcome::Status(status::OK)
    }

    fn notify(&mut self, client: u32, msg: &InMsg) -> Outcome {
        let attrs = attrs_of(msg.payload());
        let (Some(method), Some(id)) = (
            attrs[attr::METHOD as usize].map(|a| obj::cstr_bytes(a.payload).to_vec()),
            attrs[attr::OBJID as usize].and_then(|a| a.as_u32()),
        ) else {
            return Outcome::Status(status::INVALID_ARGUMENT);
        };
        let no_reply = attrs[attr::NO_REPLY as usize]
            .and_then(|a| a.payload.first().copied())
            .is_some_and(|v| v != 0);

        let Some(o) = self.reg.get(id) else {
            return Outcome::Status(status::NOT_FOUND);
        };
        if o.client != Some(client) {
            return Outcome::Status(status::PERMISSION_DENIED);
        }
        let subscribers = o.subscribers.clone();

        if !no_reply {
            let mut b = BlobBuf::new();
            b.put_u32(attr::OBJID, id);
            let c = b.nest_start(attr::SUBSCRIBERS);
            for s in &subscribers {
                b.put_u32(0, *s);
            }
            b.nest_end(c);
            b.put_u32(attr::STATUS, 0);
            let out = OutMsg::new(ty::STATUS, msg.header.seq, msg.header.peer, b.as_bytes().to_vec());
            self.send(client, out);
        }

        let data = attrs[attr::DATA as usize].map(|a| a.payload);
        let cred = self.cred_of(client);
        let who = cred.as_ref().map(|c| (c.user.as_str(), c.group.as_str()));
        for s in subscribers {
            let Some(owner) = self.reg.get(s).and_then(|o| o.client) else { continue };
            let blob = forward_blob(s, &method, who, data, Some(no_reply));
            let out = OutMsg::new(ty::INVOKE, msg.header.seq, client, blob);
            self.send(owner, out);
        }
        Outcome::NoStatus
    }

    fn notify_subscription(&mut self, target: u32) {
        let Some(o) = self.reg.get_mut(target) else { return };
        let active = !o.subscribers.is_empty();
        o.invoke_seq = o.invoke_seq.wrapping_add(1);
        let seq = o.invoke_seq;
        let Some(owner) = o.client else { return };
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, target);
        b.put_u8(attr::ACTIVE, u8::from(active));
        self.send(owner, OutMsg::new(ty::NOTIFY, seq, 0, b.as_bytes().to_vec()));
    }

    fn notify_unsubscribe(&mut self, subscriber: u32, target: u32) {
        let Some(o) = self.reg.get_mut(subscriber) else { return };
        o.invoke_seq = o.invoke_seq.wrapping_add(1);
        let seq = o.invoke_seq;
        let Some(owner) = o.client else { return };
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, subscriber);
        b.put_u32(attr::TARGET, target);
        self.send(owner, OutMsg::new(ty::UNSUBSCRIBE, seq, 0, b.as_bytes().to_vec()));
    }

    // ------------------------------------------------------- system objects

    fn system_object(
        &mut self,
        client: u32,
        id: u32,
        method: &[u8],
        msg: InMsg,
        data: Option<Vec<u8>>,
    ) -> Outcome {
        match id {
            SYSTEM_OBJECT_EVENT => match method {
                b"register" => Outcome::Status(self.event_register(client, data.as_deref())),
                b"send" => Outcome::Status(self.event_send(client, data.as_deref())),
                _ => Outcome::Status(status::INVALID_COMMAND),
            },
            SYSTEM_OBJECT_ACL => match method {
                b"query" => self.acl_query(client, &msg),
                _ => Outcome::Status(status::INVALID_COMMAND),
            },
            SYSTEM_OBJECT_MONITOR => {
                let Some(c) = self.clients.get(&client) else {
                    return Outcome::Status(status::PERMISSION_DENIED);
                };
                if c.uid != 0 || c.gid != 0 {
                    return Outcome::Status(status::PERMISSION_DENIED);
                }
                match method {
                    b"add" => {
                        self.monitors.retain(|(c, _)| *c != client);
                        self.monitors.push((client, 0));
                        Outcome::Status(status::OK)
                    }
                    b"remove" => {
                        self.monitors.retain(|(c, _)| *c != client);
                        Outcome::Status(status::OK)
                    }
                    _ => Outcome::Status(status::METHOD_NOT_FOUND),
                }
            }
            _ => Outcome::Status(status::INVALID_COMMAND),
        }
    }

    fn event_register(&mut self, client: u32, data: Option<&[u8]>) -> i32 {
        let Some(data) = data else { return status::INVALID_ARGUMENT };
        let mut pattern = None;
        let mut object = None;
        for f in blob::fields(data) {
            match f.name {
                "pattern" if pattern.is_none() => pattern = f.as_bytes().map(<[u8]>::to_vec),
                "object" if object.is_none() && f.ty == MsgType::Int32 as u32 => object = f.as_u32(),
                _ => {}
            }
        }
        let (Some(mut pattern), Some(object)) = (pattern, object) else {
            return status::INVALID_ARGUMENT;
        };
        // Registering against a system object id is never allowed.
        if object < SYSTEM_OBJECT_MAX {
            return status::PERMISSION_DENIED;
        }
        let Some(o) = self.reg.get(object) else { return status::NOT_FOUND };
        if o.client != Some(client) {
            return status::PERMISSION_DENIED;
        }
        if pattern.is_empty() {
            return status::PERMISSION_DENIED;
        }
        let partial = pattern.last() == Some(&b'*');
        if partial {
            pattern.pop();
        }
        let cred = self.cred_of(client);
        if !self.acl.check(cred.as_ref().map(|c| c.as_cred()).as_ref(), Some(&pattern), None, AclType::Listen) {
            return status::PERMISSION_DENIED;
        }
        // Keep the vector sorted, inserting after any equal keys so equal
        // patterns fire in registration order.
        let at = self.patterns.partition_point(|p| p.key <= pattern);
        self.patterns.insert(at, Pattern { key: pattern, partial, obj: object });
        status::OK
    }

    fn event_send(&mut self, client: u32, data: Option<&[u8]>) -> i32 {
        let Some(data) = data else { return status::INVALID_ARGUMENT };
        let mut id = None;
        let mut payload = None;
        for f in blob::fields(data) {
            match f.name {
                // `data` must be a table; its contents become the event payload.
                "id" if id.is_none() => id = f.as_bytes().map(<[u8]>::to_vec),
                "data" if payload.is_none() && f.ty == MsgType::Table as u32 => payload = Some(f.data.to_vec()),
                _ => {}
            }
        }
        let (Some(id), Some(payload)) = (id, payload) else {
            return status::INVALID_ARGUMENT;
        };
        // The `ubus.` namespace is reserved for events ubusd itself emits.
        if id.starts_with(b"ubus.") {
            return status::PERMISSION_DENIED;
        }
        let cred = self.cred_of(client);
        if !self.acl.check(cred.as_ref().map(|c| c.as_cred()).as_ref(), Some(&id), None, AclType::Send) {
            return status::PERMISSION_DENIED;
        }
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, 0);
        b.put(attr::METHOD, &with_nul(&id));
        b.put(attr::DATA, &payload);
        let blob = b.as_bytes().to_vec();
        self.dispatch_event(Some(client), &id, blob);
        status::OK
    }

    fn send_obj_event(&mut self, id: u32, add: bool) {
        let name: &[u8] = if add { b"ubus.object.add" } else { b"ubus.object.remove" };
        let Some(o) = self.reg.get(id) else { return };
        let Some(path) = o.path.clone() else { return };
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, 0);
        b.put(attr::METHOD, &with_nul(name));
        let d = b.nest_start(attr::DATA);
        b.msg_u32("id", id);
        b.msg_field(MsgType::String as u32, "path", &with_nul(&path));
        b.nest_end(d);
        let blob = b.as_bytes().to_vec();
        self.dispatch_event(None, name, blob);
    }

    /// Walk the pattern list and deliver `blob` to every matching listener.
    /// `from` is the sending client, whose own objects never see the event.
    fn dispatch_event(&mut self, from: Option<u32>, id: &[u8], blob: Vec<u8>) {
        self.obj_event_seq = self.obj_event_seq.wrapping_add(1);
        if self.obj_event_seq == 0 {
            // Zero means unseen. Reusing any old epoch without clearing the
            // stamps can suppress a listener's first event after wraparound.
            for object in self.reg.objects.values_mut() {
                object.event_seen = 0;
            }
            self.obj_event_seq = 1;
        }
        let round = self.obj_event_seq;

        let mut match_len = 0usize;
        let mut targets: Vec<u32> = Vec::new();
        for p in &self.patterns {
            let (full, cur) = obj::strmatch_len(id, &p.key);
            if cur < match_len {
                break;
            }
            match_len = cur;
            if !full && (!p.partial || match_len != p.key.len()) {
                continue;
            }
            targets.push(p.obj);
        }

        for obj_id in targets {
            let Some(o) = self.reg.get_mut(obj_id) else { continue };
            if o.client == from && from.is_some() {
                continue;
            }
            if o.event_seen == round {
                continue;
            }
            o.event_seen = round;
            let Some(owner) = o.client else { continue };
            // Each receiver sees its own object id patched into the message
            // and its own sequence number: `(*ub)->hdr.seq = ++event_seq`
            // runs once per delivered copy, not once per event.
            let mut per = blob.clone();
            patch_first_u32(&mut per, obj_id);
            self.event_seq = self.event_seq.wrapping_add(1);
            self.send(owner, OutMsg::new(ty::INVOKE, self.event_seq, 0, per));
        }
    }

    fn acl_query(&mut self, client: u32, msg: &InMsg) -> Outcome {
        let objects = self.clients.get(&client).map(|c| c.objects.clone()).unwrap_or_default();
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, SYSTEM_OBJECT_ACL);
        let d = b.nest_start(attr::DATA);
        b.msg_u32("seq", self.acl.seq);
        let a = b.msg_open_array("acl");
        for id in objects {
            let Some(path) = self.reg.get(id).and_then(|o| o.path.clone()) else { continue };
            for (entry, priv_acl) in self.acl.private_for(&path) {
                let t = b.msg_open_table("");
                b.msg_field(MsgType::String as u32, "obj", &with_nul(&path));
                if let Some(u) = entry.user() {
                    b.msg_string("user", u);
                }
                if let Some(g) = entry.group() {
                    b.msg_string("group", g);
                }
                // the C daemon stores the file's blobmsg form and echoes it,
                // so the `acl` table has blobmsg_add_json_element's types
                owrt_ubus::convert::json_to_fields(&mut b, "acl", priv_acl);
                b.msg_close(t);
            }
        }
        b.msg_close(a);
        b.nest_end(d);
        let out = OutMsg::new(ty::DATA, msg.header.seq, msg.header.peer, b.as_bytes().to_vec());
        self.send(client, out);
        Outcome::Status(status::OK)
    }

    // -------------------------------------------------------------- monitor

    fn mirror(clients: &mut HashMap<u32, Client>, monitors: &mut [(u32, u16)], touched: &mut Vec<u32>, client: u32, header: &Header, blob: &[u8], send: bool) {
        if monitors.is_empty() {
            return;
        }
        // attribute order as ubusd_monitor_message puts them: CLIENT, PEER,
        // SEQ, TYPE, SEND, DATA
        let mut b = BlobBuf::new();
        b.put_u32(0, client); // UBUS_MONITOR_CLIENT
        b.put_u32(1, header.peer); // UBUS_MONITOR_PEER
        b.put_u32(3, header.seq as u32); // UBUS_MONITOR_SEQ
        b.put_u32(4, header.ty as u32); // UBUS_MONITOR_TYPE
        b.put_u8(2, u8::from(send)); // UBUS_MONITOR_SEND
        b.put(5, if blob.len() > 4 { &blob[4..] } else { &[] }); // UBUS_MONITOR_DATA
        let payload = b.as_bytes().to_vec();

        let mons: Vec<u32> = monitors.iter().map(|(c, _)| *c).collect();
        for m in mons {
            let seq = {
                let Some(entry) = monitors.iter_mut().find(|(c, _)| *c == m) else { continue };
                entry.1 = entry.1.wrapping_add(1);
                entry.1
            };
            if let Some(c) = clients.get_mut(&m) {
                c.send(OutMsg::new(ty::MONITOR, seq, 0, payload.clone()));
                touched.push(m);
            }
        }
    }
}

/// The type each ubus attribute must have, from `ubus_policy` in
/// ubusd_proto.c. Anything not listed is unconstrained.
fn policy_type(id: u32) -> Option<u32> {
    Some(match id {
        attr::SIGNATURE => 1,                                  // NESTED
        attr::OBJTYPE | attr::OBJID | attr::STATUS => 6,       // INT32
        attr::OBJPATH | attr::METHOD | attr::USER | attr::GROUP => 3, // STRING
        _ => return None,
    })
}

/// `blob_check_type` for the types the ubus policy uses.
fn check_policy(ty: u32, payload: &[u8]) -> bool {
    match ty {
        3 => !payload.is_empty() && payload[payload.len() - 1] == 0, // STRING
        6 => payload.len() == 4,                                     // INT32
        _ => true, // NESTED and the unconstrained ones have minlen 0
    }
}

/// Top-level attributes of a message payload, indexed by attribute id --
/// `ubus_parse_msg`, i.e. `blob_parse_untrusted` under `ubus_policy`.
///
/// Attributes that fail the policy are *dropped*, not rejected: the handler
/// then sees the attribute as absent and usually answers INVALID_ARGUMENT.
/// Skipping this filter would let, for example, an OBJPATH that is not
/// NUL-terminated reach a handler that the C daemon never lets it reach.
fn short_attr(payload: &[u8], offset: usize) -> bool {
    payload.get(offset..offset + 4).is_some_and(|raw| {
        matches!(u32::from_be_bytes(raw.try_into().unwrap()) & 0x00ff_ffff, 1..=3)
    })
}

/// C reads four bytes even outside a short TARGET's declared payload. Reject
/// that malformed input rather than reading padding or the next attribute.
fn target_u32(payload: &[u8]) -> Option<u32> {
    payload.get(..4).map(|raw| u32::from_be_bytes(raw.try_into().unwrap()))
}

fn attrs_of(payload: &[u8]) -> [Option<blob::Attr<'_>>; attr::MAX] {
    let mut out: [Option<blob::Attr<'_>>; attr::MAX] = Default::default();
    let mut offset = 0usize;
    // blob::attr_at already stops where blob_for_each_attr_len does: when the
    // PADDED length of an attribute no longer fits
    loop {
        // blob_parse_attr drops invalid raw lengths, but the enclosing
        // iterator still advances by their four-byte padded size.
        if short_attr(payload, offset) {
            offset += 4;
            continue;
        }
        let Some((item, next)) = blob::attr_at(payload, offset) else { break };
        offset = next;
        if (item.id as usize) >= attr::MAX {
            continue;
        }
        if let Some(ty) = policy_type(item.id) {
            if !check_policy(ty, item.payload) {
                continue;
            }
        }
        // a later attribute of the same id replaces an earlier one
        out[item.id as usize] = Some(item);
    }
    out
}

fn with_nul(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    v.push(0);
    v
}

/// The payload ubusd builds when relaying a call to the object's owner
/// (`ubusd_forward_invoke`); `who` is the caller's user and group names.
fn forward_blob(
    objid: u32,
    method: &[u8],
    who: Option<(&str, &str)>,
    data: Option<&[u8]>,
    no_reply: Option<bool>,
) -> Vec<u8> {
    let mut b = BlobBuf::new();
    build_forward_blob(&mut b, objid, method, who, data, no_reply);
    b.as_bytes().to_vec()
}

fn build_forward_blob(
    b: &mut BlobBuf,
    objid: u32,
    method: &[u8],
    who: Option<(&str, &str)>,
    data: Option<&[u8]>,
    no_reply: Option<bool>,
) {
    b.reset();
    if no_reply == Some(true) {
        b.put_u8(attr::NO_REPLY, 1);
    }
    b.put_u32(attr::OBJID, objid);
    b.put_string_bytes(attr::METHOD, method);
    if let Some((user, group)) = who {
        b.put_string(attr::USER, user);
        b.put_string(attr::GROUP, group);
    }
    if let Some(d) = data {
        b.put(attr::DATA, d);
    }
}

/// Overwrite the first attribute's u32 payload -- the OBJID placeholder in an
/// event message, which is rewritten per receiver.
fn patch_first_u32(blob: &mut [u8], value: u32) {
    if blob.len() >= 12 {
        blob[8..12].copy_from_slice(&value.to_be_bytes());
    }
}

/// The wire bytes of an attribute: its 4-byte header plus payload, unpadded --
/// what `blobmsg_add_blob` copies.
// C blobmsg_add_blob() rebuilds the method's outer header using strlen,
// zeroes name padding, and copies only its data unchanged. Canonicalize once
// at registration rather than preserving an embedded-NUL suffix on lookup.
fn method_blob(a: &blob::Attr, name: &[u8]) -> Vec<u8> {
    let declared = u16::from_be_bytes(a.payload[..2].try_into().unwrap()) as usize;
    let data = &a.payload[crate::client::pad4(2 + declared + 1)..];
    let header = 4 + crate::client::pad4(2 + name.len() + 1);
    let raw = header + data.len();
    let mut v = Vec::with_capacity(raw);
    v.extend_from_slice(&((a.id << 24) | blob::EXTENDED | raw as u32).to_be_bytes());
    v.extend_from_slice(&(name.len() as u16).to_be_bytes());
    v.extend_from_slice(name);
    v.resize(header, 0);
    v.extend_from_slice(data);
    v
}

/// `blobmsg_check_attr(attr, true)` from libubox, rule for rule: the attribute
/// must be extended, carry a non-empty NUL-terminated name that fits inside the
/// padded blobmsg header, and hold a payload consistent with its blobmsg type.
/// Returns the name.
fn check_method(a: &blob::Attr) -> Option<Vec<u8>> {
    if !a.extended {
        return None;
    }
    // blobmsg_check_name: at least a blobmsg_hdr (a 2-byte name length)
    if a.payload.len() < 2 {
        return None;
    }
    let name_len = u16::from_be_bytes(a.payload[..2].try_into().ok()?) as usize;
    // a name is required here, so a zero length is a failure
    if name_len == 0 {
        return None;
    }
    // blobmsg_hdrlen(namelen): the header plus the name plus its NUL, padded
    let hdrlen = (2 + name_len + 1 + 3) & !3;
    if a.payload.len() < hdrlen || a.payload[2 + name_len] != 0 {
        return None;
    }
    // blobmsg types run 0..=8; anything above is rejected outright
    let ty = a.id;
    if ty > 8 {
        return None;
    }
    // blob_check_type against blob_type[]: array and table map to 0, which
    // libubox treats as "no further check"
    let data_len = a.payload.len() - hdrlen;
    let ok = match ty {
        1 | 2 => true,                                     // ARRAY, TABLE
        0 => true,                                         // UNSPEC -> BINARY, minlen 0
        3 => data_len >= 1 && a.payload[a.payload.len() - 1] == 0, // STRING
        4 => data_len == 8,                                // INT64
        5 => data_len == 4,                                // INT32
        6 => data_len == 2,                                // INT16
        7 => data_len == 1,                                // INT8 / BOOL
        8 => data_len >= 8,                                // DOUBLE
        _ => false,
    };
    if !ok {
        return None;
    }
    // libubox validates the declared terminator, but embedded NULs are
    // legal. ubusd ACLs compare blobmsg_name() as a C string.
    Some(obj::cstr_bytes(&a.payload[2..2 + name_len]).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr_bytes(id: u32, payload: &[u8]) -> Vec<u8> {
        let raw = 4 + payload.len();
        let mut v = (((id << 24) & 0x7f00_0000) | raw as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    #[test]
    fn string_attrs_must_be_nul_terminated() {
        let good = attr_bytes(attr::OBJPATH, b"session\0");
        assert!(attrs_of(&good)[attr::OBJPATH as usize].is_some());
        // the terminator mutated away: libubox drops the attribute, so the
        // handler sees no path at all and dumps every object instead
        let bad = attr_bytes(attr::OBJPATH, b"session\xe4");
        assert!(attrs_of(&bad)[attr::OBJPATH as usize].is_none());
        let empty = attr_bytes(attr::OBJPATH, b"");
        assert!(attrs_of(&empty)[attr::OBJPATH as usize].is_none());
    }

    #[test]
    fn int32_attrs_must_be_exactly_four_bytes() {
        assert!(attrs_of(&attr_bytes(attr::OBJID, &[0, 0, 0, 1]))[attr::OBJID as usize].is_some());
        assert!(attrs_of(&attr_bytes(attr::OBJID, &[0, 1]))[attr::OBJID as usize].is_none());
        assert!(attrs_of(&attr_bytes(attr::OBJID, &[0, 0, 0, 0, 1]))[attr::OBJID as usize].is_none());
    }

    #[test]
    fn unconstrained_attrs_pass_any_payload() {
        assert!(attrs_of(&attr_bytes(attr::DATA, &[1, 2, 3]))[attr::DATA as usize].is_some());
        assert!(attrs_of(&attr_bytes(attr::NO_REPLY, &[]))[attr::NO_REPLY as usize].is_some());
    }

    #[test]
    fn a_later_attribute_replaces_an_earlier_one() {
        let mut buf = attr_bytes(attr::OBJID, &[0, 0, 0, 1]);
        buf.extend_from_slice(&attr_bytes(attr::OBJID, &[0, 0, 0, 2]));
        let got = attrs_of(&buf)[attr::OBJID as usize].unwrap();
        assert_eq!(got.as_u32(), Some(2));
    }

    #[test]
    fn method_signature_check_matches_blobmsg_check_attr() {
        // extended, name "ping", table type: accepted
        let mut payload = 4u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"ping\0");
        payload.resize(8, 0); // pad4(2 + 4 + 1)
        let a = blob::Attr { id: 2, extended: true, payload: &payload };
        assert_eq!(check_method(&a).as_deref(), Some(&b"ping"[..]));
        for (wire_name, expected) in [(&b"ping\0suffix"[..], &b"ping"[..]),
                                      (b"\0suffix", b""), (b"p\xffng", b"p\xffng")] {
            let mut payload = (wire_name.len() as u16).to_be_bytes().to_vec();
            payload.extend_from_slice(wire_name);
            payload.push(0);
            payload.resize(crate::client::pad4(payload.len()), 0);
            let attr = blob::Attr { id: 2, extended: true, payload: &payload };
            assert_eq!(check_method(&attr).as_deref(), Some(expected));
        }
        // a zero-length name is refused when a name is required
        let mut zero = 0u16.to_be_bytes().to_vec();
        zero.resize(8, 0);
        let a = blob::Attr { id: 2, extended: true, payload: &zero };
        assert!(check_method(&a).is_none());
        // not extended: no name at all
        let a = blob::Attr { id: 2, extended: false, payload: &payload };
        assert!(check_method(&a).is_none());
        // a blobmsg type beyond the last one
        let a = blob::Attr { id: 9, extended: true, payload: &payload };
        assert!(check_method(&a).is_none());
    }
    #[cfg(target_os = "linux")]
    fn check_event_round_wrap(last_seen: u32) {
        let mut s = Server::new(String::new()).unwrap();
        let (owner, mut peer) = lookup_client();
        s.clients.insert(2000, owner);
        s.reg.create(None, Some(4000)).unwrap();
        let o = s.reg.get_mut(4000).unwrap();
        o.client = Some(2000);
        o.event_seen = last_seen;
        for _ in 0..2 {
            s.patterns.push(Pattern { key: b"event".to_vec(), partial: false, obj: 4000 });
        }
        s.obj_event_seq = u32::MAX;
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, 0);
        b.put_string(attr::METHOD, "event");
        b.put(attr::DATA, &[]);
        s.dispatch_event(None, b"event", b.as_bytes().to_vec());
        let frames = lookup_frames(&drain_lookup(&mut s, 2000, &mut peer));
        assert_eq!(frames.len(), 1, "last_seen={last_seen}: wrap must deliver once, not omit or duplicate");
        assert_eq!((frames[0].0.ty, frames[0].0.seq, frames[0].0.peer), (ty::INVOKE, 1, 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn event_round_wrap_unseen_listener() { check_event_round_wrap(0); }

    #[cfg(target_os = "linux")]
    #[test]
    fn event_round_wrap_old_epoch_listener() { check_event_round_wrap(1); }

    #[cfg(target_os = "linux")]
    #[test]
    fn event_round_wrap_recent_listener() { check_event_round_wrap(u32::MAX); }

    #[cfg(target_os = "linux")]
    fn lookup_client() -> (Client, std::os::unix::net::UnixStream) {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        unsafe extern "C" {
            fn setsockopt(fd: i32, level: i32, name: i32, value: *const i32, len: u32) -> i32;
        }
        let (sock, peer) = UnixStream::pair().unwrap();
        sock.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let size: i32 = 4096;
        // SAFETY: size is a live i32 with the declared byte length. These are
        // Linux SOL_SOCKET/SO_SNDBUF, and sock is an owned connected socket.
        assert_eq!(unsafe { setsockopt(sock.as_raw_fd(), 1, 7, &size, 4) }, 0);
        (Client::new(sock.into(), crate::sys::Ucred::default(), String::new(), String::new()), peer)
    }

    #[cfg(target_os = "linux")]
    fn drain_lookup(server: &mut Server, client: u32, peer: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
        use std::io::Read;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut bytes = Vec::new();
        loop {
            assert!(std::time::Instant::now() < deadline, "lookup did not finish");
            let mut buffer = [0u8; 4096];
            loop {
                match peer.read(&mut buffer) {
                    Ok(0) => panic!("unexpected EOF"),
                    Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("read: {e}"),
                }
            }
            let c = server.clients.get_mut(&client).unwrap();
            if c.tx_empty() && c.cmd_queue.is_empty() {
                return bytes;
            }
            assert!(c.flush());
            if c.tx_empty() {
                server.process_cmd_queue(client);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn lookup_frames(mut bytes: &[u8]) -> Vec<(Header, Vec<u8>)> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            assert!(bytes.len() >= Header::LEN + 4);
            let header = Header::decode(bytes[..Header::LEN].try_into().unwrap()).unwrap();
            let len = crate::client::blob_raw_len(&bytes[Header::LEN..]);
            assert!(len >= 4 && bytes.len() >= Header::LEN + len);
            frames.push((header, bytes[Header::LEN..Header::LEN + len].to_vec()));
            bytes = &bytes[Header::LEN + len..];
        }
        frames
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn batched_lookup_keeps_full_frames_and_fifo_under_backpressure() {
        const CALLER: u32 = 2000;
        const TYPE: u32 = 3000;
        for (count, signature_len) in [(128, 0), (1, 6000)] {
            let mut server = Server::new(String::new()).unwrap();
            let (caller, mut peer) = lookup_client();
            server.clients.insert(CALLER, caller);
            let mut methods = Vec::new();
            if signature_len != 0 {
                let mut signature = BlobBuf::new();
                let table = signature.msg_open_table("method");
                signature.msg_string("large", &"x".repeat(signature_len));
                signature.msg_close(table);
                methods.push(obj::Method { name: b"method".to_vec(), blob: signature.payload().to_vec() });
            }
            server.reg.types.insert(TYPE, obj::ObjType { refcount: 0, methods });
            let mut expected = Vec::new();
            for i in 0..count {
                let id = 4000 + i;
                server.reg.create(Some(TYPE), Some(id)).unwrap();
                assert!(server.reg.set_path(id, format!("lookup.{i:04}").into_bytes()));
                assert!(server.build_obj(CALLER, id));
                expected.push(server.scratch.as_bytes().to_vec());
            }
            for seq in [10, 11] {
                let mut blob = BlobBuf::new();
                assert!(server.receive(CALLER, InMsg {
                    header: Header { ty: ty::LOOKUP, seq, peer: 1234 },
                    blob: blob.as_bytes().to_vec(), fd: None,
                }));
            }
            assert!(!server.clients[&CALLER].tx_empty(), "fixture must force queued output");
            // Queued frames must own their bytes after both assembly buffers
            // have been reused, including a single frame larger than a block.
            server.scratch.reset();
            server.scratch.put_string(attr::OBJPATH, "overwritten");
            server.lookup_batch.clear();
            server.lookup_batch.extend_from_slice(b"overwritten");
            let frames = lookup_frames(&drain_lookup(&mut server, CALLER, &mut peer));
            assert_eq!(frames.len(), 2 * (count as usize + 1));
            for (sequence, group) in frames.chunks(count as usize + 1).enumerate() {
                for ((header, blob), expected) in group[..count as usize].iter().zip(&expected) {
                    assert_eq!(header.ty, ty::DATA);
                    assert_eq!(header.seq, 10 + sequence as u16);
                    assert_eq!(header.peer, 1234);
                    assert_eq!(blob, expected);
                }
                let (header, blob) = group.last().unwrap();
                assert_eq!(header.ty, ty::STATUS);
                assert_eq!(header.seq, 10 + sequence as u16);
                assert_eq!(attrs_of(&blob[4..])[attr::STATUS as usize].unwrap().as_u32(), Some(0));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prefix_lookup_resumes_by_path_after_delete_or_recreate_and_keeps_queued_bytes() {
        const CALLER: u32 = 2000;
        const TYPE: u32 = 3000;
        const FIRST: u32 = 4000;
        for (change, pattern) in [("delete", "*"), ("recreate", "lookup.*"), ("delete_tail", "lookup.*")] {
            let mut server = Server::new(String::new()).unwrap();
            let (caller, mut peer) = lookup_client();
            server.clients.insert(CALLER, caller);
            let mut signature = BlobBuf::new();
            let table = signature.msg_open_table("method");
            signature.msg_string("large", &"x".repeat(32768));
            signature.msg_close(table);
            server.reg.types.insert(TYPE, obj::ObjType { refcount: 0, methods: vec![obj::Method {
                name: b"method".to_vec(), blob: signature.payload().to_vec(),
            }] });
            let mut expected = Vec::new();
            for i in 0..12 {
                let id = FIRST + i;
                server.reg.create(Some(TYPE), Some(id)).unwrap();
                assert!(server.reg.set_path(id, format!("lookup.{i:02}").into_bytes()));
                assert!(server.build_obj(CALLER, id));
                expected.push(server.scratch.as_bytes().to_vec());
            }
            let mut blob = BlobBuf::new();
            blob.put_string(attr::OBJPATH, pattern);
            let request = InMsg { header: Header { ty: ty::LOOKUP, seq: 0xabcd, peer: 0x12345678 },
                blob: blob.as_bytes().to_vec(), fd: None };
            assert!(server.receive(CALLER, request));
            let next = server.clients[&CALLER].cmd_queue.front().unwrap().next.clone().unwrap();
            assert_eq!(next, b"lookup.01", "first frame must force backpressure");
            let removed = server.reg.by_path(&next).unwrap();
            server.reg.destroy(removed).unwrap();
            if change == "recreate" {
                server.reg.create(Some(TYPE), Some(9000)).unwrap();
                assert!(server.reg.set_path(9000, next));
                assert!(server.build_obj(CALLER, 9000));
                expected[1] = server.scratch.as_bytes().to_vec();
            } else if change == "delete_tail" {
                for id in FIRST + 2..FIRST + 12 {
                    server.reg.destroy(id).unwrap();
                }
                expected.truncate(1);
            } else {
                expected.remove(1);
            }
            // A newly inserted path before the saved lower bound must not
            // restart the completed prefix or appear in this continuation.
            server.reg.create(Some(TYPE), Some(9001)).unwrap();
            assert!(server.reg.set_path(9001, b"lookup.00a".to_vec()));
            if pattern != "*" {
                server.reg.create(Some(TYPE), Some(9002)).unwrap();
                assert!(server.reg.set_path(9002, b"outside".to_vec()));
            }
            // The first DATA is partially sent and queued. Deleting its
            // registry entry and overwriting scratch must not alter its tail.
            server.reg.destroy(FIRST).unwrap();
            server.scratch.reset();
            server.scratch.put_string(attr::OBJPATH, "overwritten");
            let frames = lookup_frames(&drain_lookup(&mut server, CALLER, &mut peer));
            assert_eq!(frames.len(), expected.len() + 1);
            for ((header, blob), expected) in frames[..frames.len() - 1].iter().zip(expected) {
                assert_eq!(header.ty, ty::DATA);
                assert_eq!(header.seq, 0xabcd);
                assert_eq!(header.peer, 0x12345678);
                assert_eq!(blob, &expected);
            }
            let (header, blob) = frames.last().unwrap();
            assert_eq!(header.ty, ty::STATUS);
            assert_eq!(header.seq, 0xabcd);
            assert_eq!(header.peer, 0x12345678);
            assert_eq!(attrs_of(&blob[4..])[attr::STATUS as usize].unwrap().as_u32(), Some(0));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prefix_lookup_preserves_acl_typeless_filter_raw_order_and_monitor_frames() {
        const CALLER: u32 = 2000;
        const MONITOR: u32 = 2001;
        for (root, monitored) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut server = Server::new(String::new()).unwrap();
            let (mut caller, mut peer) = lookup_client();
            caller.uid = if root { 0 } else { 12345 };
            server.clients.insert(CALLER, caller);
            let (monitor, mut monitor_peer) = lookup_client();
            server.clients.insert(MONITOR, monitor);
            if monitored {
                server.monitors.push((MONITOR, 0));
            }
            server.reg.types.insert(3000, obj::ObjType { refcount: 0, methods: Vec::new() });
            let mut signature = BlobBuf::new();
            let table = signature.msg_open_table("hidden");
            signature.msg_close(table);
            server.reg.types.insert(3001, obj::ObjType { refcount: 0, methods: vec![obj::Method {
                name: b"hidden".to_vec(), blob: signature.payload().to_vec(),
            }] });
            // Deliberately insert in reverse byte order, including non-UTF8.
            for (id, path, kind) in [(4000, &b"z\xff"[..], Some(3000)),
                                      (4001, &b"c"[..], Some(3001)),
                                      (4002, &b"b"[..], None),
                                      (4003, &b"a"[..], Some(3000))] {
                server.reg.create(kind, Some(id)).unwrap();
                assert!(server.reg.set_path(id, path.to_vec()));
            }
            let mut blob = BlobBuf::new();
            blob.put_string(attr::OBJPATH, "*");
            let request = InMsg { header: Header { ty: ty::LOOKUP, seq: 55, peer: 66 },
                blob: blob.as_bytes().to_vec(), fd: None };
            let input = request.blob[4..].to_vec();
            assert!(server.receive(CALLER, request));
            let frames = lookup_frames(&drain_lookup(&mut server, CALLER, &mut peer));
            let paths: Vec<_> = frames.iter().filter(|(h, _)| h.ty == ty::DATA).map(|(_, b)| {
                obj::cstr_bytes(attrs_of(&b[4..])[attr::OBJPATH as usize].unwrap().payload).to_vec()
            }).collect();
            let expected = if root { vec![b"a".to_vec(), b"c".to_vec(), b"z\xff".to_vec()] }
                else { vec![b"a".to_vec(), b"z\xff".to_vec()] };
            assert_eq!(paths, expected);
            assert_eq!(frames.last().unwrap().0.ty, ty::STATUS);
            let mirrored = lookup_frames(&drain_lookup(&mut server, MONITOR, &mut monitor_peer));
            if !monitored {
                assert!(mirrored.is_empty());
                continue;
            }
            assert_eq!(mirrored.len(), frames.len() + 1);
            for (index, (header, payload)) in mirrored.iter().enumerate() {
                assert_eq!(header.ty, ty::MONITOR);
                assert_eq!(header.seq, index as u16 + 1);
                let mut fields: [Option<blob::Attr<'_>>; 6] = Default::default();
                for field in blob::iter(&payload[4..]) {
                    let id = field.id as usize;
                    assert!(id < fields.len());
                    fields[id] = Some(field);
                }
                assert_eq!(fields[0].unwrap().as_u32(), Some(CALLER));
                assert_eq!(fields[1].unwrap().as_u32(), Some(66));
                assert_eq!(fields[3].unwrap().as_u32(), Some(55));
                let (kind, data) = if index == 0 { (ty::LOOKUP, input.as_slice()) }
                    else { (frames[index - 1].0.ty, &frames[index - 1].1[4..]) };
                assert_eq!(fields[4].unwrap().as_u32(), Some(kind as u32));
                assert_eq!(fields[2].unwrap().payload, &[u8::from(index != 0)]);
                assert_eq!(fields[5].unwrap().payload, data);
            }
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn prefix_lookup_pipelines_preserve_lookup_fifo_and_other_reply_sequences() {
        const CALLER: u32 = 2000;
        let mut server = Server::new(String::new()).unwrap();
        let (caller, mut peer) = lookup_client();
        server.clients.insert(CALLER, caller);
        let mut signature = BlobBuf::new();
        let table = signature.msg_open_table("method");
        signature.msg_string("large", &"x".repeat(32768));
        signature.msg_close(table);
        server.reg.types.insert(3000, obj::ObjType { refcount: 0, methods: vec![obj::Method {
            name: b"method".to_vec(), blob: signature.payload().to_vec(),
        }] });
        let mut expected = Vec::new();
        for i in 0..40 {
            let id = 4000 + i;
            server.reg.create(Some(3000), Some(id)).unwrap();
            assert!(server.reg.set_path(id, format!("lookup.{i:02}").into_bytes()));
            assert!(server.build_obj(CALLER, id));
            expected.push(server.scratch.as_bytes().to_vec());
        }
        for (seq, pattern) in [(10, "*"), (11, "lookup.39"), (12, "missing.*")] {
            let mut blob = BlobBuf::new();
            blob.put_string(attr::OBJPATH, pattern);
            assert!(server.receive(CALLER, InMsg { header: Header { ty: ty::LOOKUP, seq, peer: 55 },
                blob: blob.as_bytes().to_vec(), fd: None }));
        }
        assert_eq!(server.clients[&CALLER].cmd_queue.len(), 3);
        let mut ping = BlobBuf::new();
        ping.put_string(attr::OBJPATH, "ping");
        let ping_bytes = ping.as_bytes().to_vec();
        assert!(server.receive(CALLER, InMsg { header: Header { ty: ty::PING, seq: 13, peer: 56 },
            blob: ping_bytes.clone(), fd: None }));
        let frames = lookup_frames(&drain_lookup(&mut server, CALLER, &mut peer));
        assert_eq!(frames.len(), 46);
        assert_eq!((frames[0].0.ty, frames[0].0.seq, &frames[0].1), (ty::DATA, 10, &expected[0]));
        assert_eq!((frames[1].0.ty, frames[1].0.seq, frames[1].0.peer, &frames[1].1), (ty::DATA, 13, 56, &ping_bytes));
        assert_eq!((frames[2].0.ty, frames[2].0.seq), (ty::STATUS, 13));
        for (i, expected) in expected.iter().enumerate().skip(1) {
            assert_eq!((frames[i + 2].0.ty, frames[i + 2].0.seq, frames[i + 2].0.peer, &frames[i + 2].1), (ty::DATA, 10, 55, expected));
        }
        assert_eq!((frames[42].0.ty, frames[42].0.seq), (ty::STATUS, 10));
        assert_eq!((frames[43].0.ty, frames[43].0.seq, &frames[43].1), (ty::DATA, 11, &expected[39]));
        assert_eq!((frames[44].0.ty, frames[44].0.seq), (ty::STATUS, 11));
        assert_eq!((frames[45].0.ty, frames[45].0.seq), (ty::STATUS, 12));
        for index in [2, 42, 44, 45] {
            assert_eq!(attrs_of(&frames[index].1[4..])[attr::STATUS as usize].unwrap().as_u32(),
                Some(if index == 45 { status::NOT_FOUND as u32 } else { 0 }));
        }
    }

}
