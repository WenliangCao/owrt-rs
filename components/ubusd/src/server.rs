//! The bus itself: client table, message dispatch and the three built-in
//! system objects. Single-threaded; every handler runs to completion against
//! `&mut Server`, so there is no shared mutable state to reason about.

use crate::acl::{Acl, AclType, Cred};
use crate::client::{Client, InMsg, OutMsg, PendingCmd};
use crate::obj::{self, Registry, SYSTEM_OBJECT_ACL, SYSTEM_OBJECT_EVENT, SYSTEM_OBJECT_MAX, SYSTEM_OBJECT_MONITOR};
use owrt_ubus::blob::{self, BlobBuf, MsgType};
use owrt_ubus::msg::{attr, status, ty, Header};
use std::borrow::Cow;
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

/// Bound the temporary contiguous event write. Larger event payloads stay on
/// the existing borrowed one-frame path instead of multiplying their bytes.
const MAX_EVENT_BATCH: usize = 16 * 1024;

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
    pub clients: HashMap<u32, Box<Client>>,
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
    /// Reusable wire storage for the frames after the first event in a
    /// same-owner run. The first frame remains on the zero-copy path so a
    /// single-listener event does not pay a new copy.
    event_batch: Vec<u8>,
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
            event_batch: Vec::new(),
        })
    }

    pub fn load_acl(&mut self) {
        let dir = self.acl_dir.clone();
        // nothing to load: C returns before vlist_update, seq++ and the event
        if !self.acl.load(&dir) {
            return;
        }
        let seq = self.acl.seq;
        self.dispatch_event(None, b"ubus.acl.sequence", |b| {
            b.put_u32(attr::OBJID, 0);
            b.put_string(attr::METHOD, "ubus.acl.sequence");
            let d = b.nest_start(attr::DATA);
            b.msg_u32("sequence", seq);
            b.nest_end(d);
        });
    }

    // ---------------------------------------------------------------- clients

    pub fn add_client(&mut self, sock: OwnedFd) -> std::io::Result<u32> {
        let cred = crate::sys::peer_cred(&sock)?;
        // The C daemon refuses a connection whose uid or gid has no entry
        // rather than inventing a name for it.
        let user = crate::sys::user_name(cred.uid)
            .ok_or_else(|| std::io::Error::other("no passwd entry for peer uid"))?;
        let group = crate::sys::group_name(cred.gid)
            .ok_or_else(|| std::io::Error::other("no group entry for peer gid"))?;

        let id = Registry::alloc_id(|id| self.clients.contains_key(&id))?;
        self.clients.insert(id, Box::new(Client::new(sock, cred, user, group)));
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

    /// Reuse received bytes for PING and response forwarding. A borrowed
    /// payload is copied only if it must wait; owned large frames can move.
    fn send_received(&mut self, client: u32, header: Header, blob: Cow<'_, [u8]>, fd: Option<OwnedFd>) {
        if header.ty != ty::MONITOR {
            Self::mirror(&mut self.clients, &mut self.monitors, &mut self.touched, client, &header, &blob, true);
        }
        if let Some(c) = self.clients.get_mut(&client) {
            match blob {
                Cow::Borrowed(blob) => { c.send_borrowed(header, blob, fd); }
                Cow::Owned(blob) => { c.send(OutMsg { header, blob, fd }); }
            }
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

    /// ADD/REMOVE DATA contains only OBJID and an optional OBJTYPE. Keep
    /// its fixed 12/20-byte wire form on the stack instead of growing scratch.
    /// A successful ADD has no action left between DATA and STATUS, so it can
    /// send both together without a monitor. REMOVE still sends DATA before
    /// freeing the object and emitting notifications, then returns STATUS.
    fn send_object_reply(&mut self, client: u32, request: &InMsg, id: u32, type_id: Option<u32>) -> Outcome {
        let mut blob = [0u8; 20];
        let len = if type_id.is_some() { 20 } else { 12 };
        blob[..4].copy_from_slice(&(len as u32).to_be_bytes());
        blob[4..8].copy_from_slice(&((attr::OBJID << 24) | 8).to_be_bytes());
        blob[8..12].copy_from_slice(&id.to_be_bytes());
        if let Some(type_id) = type_id {
            blob[12..16].copy_from_slice(&((attr::OBJTYPE << 24) | 8).to_be_bytes());
            blob[16..20].copy_from_slice(&type_id.to_be_bytes());
        }
        let header = Header { ty: ty::DATA, seq: request.header.seq, peer: request.header.peer };
        if request.header.ty == ty::ADD_OBJECT && self.monitors.is_empty() {
            if let Some(c) = self.clients.get_mut(&client) {
                c.send_data_status_reply(header, &blob[..len]);
                self.touched.push(client);
            }
            return Outcome::NoStatus;
        }
        Self::mirror(&mut self.clients, &mut self.monitors, &mut self.touched, client, &header, &blob[..len], true);
        if let Some(c) = self.clients.get_mut(&client) {
            c.send_borrowed(header, &blob[..len], None);
            self.touched.push(client);
        }
        Outcome::Status(status::OK)
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
                self.send_received(client, Header { ty: ty::DATA, ..msg.header }, msg.blob, None);
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
                        let blob = method_blob(&item, name);
                        methods.push(obj::Method::new(blob));
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
            let path = obj::cstr_bytes(p.payload);
            let cred = self.clients.get(&client).map(|c| Cred { uid: c.uid, gid: c.gid, extra_gid: &c.extra_gid });
            let allowed = self.acl.check(cred.as_ref(), Some(&path), None, AclType::Publish);
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

        let reply_type = if attrs[attr::SIGNATURE as usize].is_some() { type_id } else { None };
        self.send_object_reply(client, msg, id, reply_type)
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
        // Echo the type id only if removal destroys its last reference.
        let reply_type = o.type_id.filter(|t| self.reg.types.get(t).is_some_and(|t| t.refcount == 1));
        self.send_object_reply(client, msg, id, reply_type);
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
                c.cmd_queue.push_back(PendingCmd { msg: msg.into_owned(), next: None });
            }
            return Outcome::Queued;
        }
        match self.lookup(client, &msg, None) {
            Ok(outcome) => outcome,
            Err(next) => {
                if let Some(c) = self.clients.get_mut(&client) {
                    c.cmd_queue.push_back(PendingCmd { msg: msg.into_owned(), next });
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
                        c.send_data_status_reply(header, self.scratch.as_bytes());
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
            if acl.check(cred, Some(path), Some(m.name()), AclType::Access) {
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
            return self.system_object(client, id, method, &msg, data);
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
        self.send_received(dest, Header { peer: id, ..msg.header }, msg.blob, msg.fd);
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
        msg: &InMsg,
        data: Option<&[u8]>,
    ) -> Outcome {
        match id {
            SYSTEM_OBJECT_EVENT => match method {
                b"register" => Outcome::Status(self.event_register(client, data)),
                b"send" => Outcome::Status(self.event_send(client, data)),
                _ => Outcome::Status(status::INVALID_COMMAND),
            },
            SYSTEM_OBJECT_ACL => match method {
                b"query" => self.acl_query(client, msg),
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
                // Borrow request fields; the relay frame is built only after
                // dispatch_event finds an eligible receiver.
                "id" if id.is_none() => id = f.as_bytes(),
                "data" if payload.is_none() && f.ty == MsgType::Table as u32 => payload = Some(f.data),
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
        let caller = self.clients.get(&client);
        let cred = caller.map(|c| Cred { uid: c.uid, gid: c.gid, extra_gid: &c.extra_gid });
        if !self.acl.check(cred.as_ref(), Some(&id), None, AclType::Send) {
            return status::PERMISSION_DENIED;
        }
        self.dispatch_event(Some(client), id, |b| {
            b.put_u32(attr::OBJID, 0);
            b.put_string_bytes(attr::METHOD, id);
            b.put(attr::DATA, payload);
        });
        status::OK
    }

    fn send_obj_event(&mut self, id: u32, add: bool) {
        let name: &[u8] = if add { b"ubus.object.add" } else { b"ubus.object.remove" };
        let Some(o) = self.reg.get(id) else { return };
        let Some(path) = o.path.clone() else { return };
        self.dispatch_event(None, name, |b| {
            b.put_u32(attr::OBJID, 0);
            b.put_string_bytes(attr::METHOD, name);
            let d = b.nest_start(attr::DATA);
            b.msg_u32("id", id);
            b.msg_string_bytes("path", &path);
            b.nest_end(d);
        });
    }

    /// Walk the pattern list and deliver to every matching listener. Like
    /// C's event_fill_cb, encode once, only after an eligible receiver exists.
    /// `from` is the sending client, whose own objects never see the event.
    fn dispatch_event(&mut self, from: Option<u32>, id: &[u8], build: impl FnOnce(&mut BlobBuf)) {
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
        let mut build = Some(build);
        // A monitor observes each event at its original send boundary. Keep
        // that path byte-for-byte unchanged; batching is only a destination
        // optimization for the common unmonitored case.
        let batch_events = self.monitors.is_empty();
        self.event_batch.clear();
        let mut batch_owner = None;
        let mut batch_count = 0usize;
        // Sending only changes client queues/monitors. Patterns and object
        // ownership cannot change until this single-threaded handler returns,
        // so neither a target snapshot nor a payload copy per receiver is
        // needed. send_borrowed owns any bytes that have to wait in a queue.
        for p in &self.patterns {
            let (full, cur) = obj::strmatch_len(id, &p.key);
            if cur < match_len {
                break;
            }
            match_len = cur;
            if !full && (!p.partial || match_len != p.key.len()) {
                continue;
            }
            let Some(o) = self.reg.get_mut(p.obj) else { continue };
            if o.client == from && from.is_some() {
                continue;
            }
            if o.event_seen == round {
                continue;
            }
            o.event_seen = round;
            let Some(owner) = o.client else { continue };
            if let Some(build) = build.take() {
                // Reuse the existing assembly buffer only when needed. Like
                // its lookup/invoke users, retain capacity after large frames.
                self.scratch.reset();
                build(&mut self.scratch);
            }
            let blob = self.scratch.as_mut_bytes();
            patch_first_u32(blob, p.obj);
            self.event_seq = self.event_seq.wrapping_add(1);
            let header = Header { ty: ty::INVOKE, seq: self.event_seq, peer: 0 };
            Self::mirror(&mut self.clients, &mut self.monitors, &mut self.touched, owner, &header, blob, true);
            if !batch_events {
                Self::send_event_frame_to(&mut self.clients, &mut self.touched, owner, header, blob);
                continue;
            }

            // A stale registry entry has no destination. Do not retain a
            // previous owner's batch across it; the old path also emits
            // nothing for this case.
            if !self.clients.contains_key(&owner) {
                Self::flush_event_batch_to(&mut self.clients, &mut self.touched, &mut self.event_batch, batch_owner.take());
                batch_count = 0;
                continue;
            }

            if batch_owner != Some(owner) {
                Self::flush_event_batch_to(&mut self.clients, &mut self.touched, &mut self.event_batch, batch_owner);
                batch_owner = Some(owner);
                batch_count = 0;
            }

            let frame_len = Header::LEN + blob.len();
            if batch_count == 0 {
                // Preserve the single-frame zero-copy path. Only a later
                // frame in this same owner run is copied into the batch.
                Self::send_event_frame_to(&mut self.clients, &mut self.touched, owner, header, blob);
                batch_count = 1;
            } else if frame_len <= MAX_EVENT_BATCH
                && self.event_batch.len().saturating_add(frame_len) <= MAX_EVENT_BATCH
            {
                self.event_batch.extend_from_slice(&header.encode());
                self.event_batch.extend_from_slice(blob);
                batch_count += 1;
            } else {
                // Keep large frames and oversized runs on the old path. A
                // later small frame starts a fresh run after this direct one.
                Self::flush_event_batch_to(&mut self.clients, &mut self.touched, &mut self.event_batch, Some(owner));
                Self::send_event_frame_to(&mut self.clients, &mut self.touched, owner, header, blob);
                batch_count = 1;
            }
        }
        Self::flush_event_batch_to(&mut self.clients, &mut self.touched, &mut self.event_batch, batch_owner);
    }

    /// Send one event using the existing borrowed path and readiness rules.
    fn send_event_frame_to(clients: &mut HashMap<u32, Box<Client>>, touched: &mut Vec<u32>, owner: u32, header: Header, blob: &[u8]) {
        if let Some(client) = clients.get_mut(&owner) {
            client.send_borrowed(header, blob, None);
            // A complete direct write leaves no readiness state to change.
            // Keep the conservative retry cases used by the old inline path.
            if !client.tx_empty() || client.out_registered || (!client.eof != client.in_registered) {
                touched.push(owner);
            }
        }
    }

    /// Submit the pending same-owner frames as one stream write. The client
    /// helper restores individual queue entries if the write is partial.
    fn flush_event_batch_to(clients: &mut HashMap<u32, Box<Client>>, touched: &mut Vec<u32>, event_batch: &mut Vec<u8>, owner: Option<u32>) {
        let Some(owner) = owner else {
            event_batch.clear();
            return;
        };
        if !event_batch.is_empty() {
            let frames = event_batch.as_slice();
            if let Some(client) = clients.get_mut(&owner) {
                client.send_borrowed_batch(frames);
                if !client.tx_empty() || client.out_registered || (!client.eof != client.in_registered) {
                    touched.push(owner);
                }
            }
        }
        event_batch.clear();
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

    fn mirror(clients: &mut HashMap<u32, Box<Client>>, monitors: &mut [(u32, u16)], touched: &mut Vec<u32>, client: u32, header: &Header, blob: &[u8], send: bool) {
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
fn check_method<'a>(a: &blob::Attr<'a>) -> Option<&'a [u8]> {
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
    Some(obj::cstr_bytes(&a.payload[2..2 + name_len]))
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
    #[test]
    fn registration_replies_remain_owned_while_queued_and_monitored() {
        for monitored in [false, true] {
            let mut s = Server::new(String::new()).unwrap();
            let (caller, mut peer) = lookup_client();
            let (monitor, mut monitor_peer) = lookup_client();
            s.clients.insert(2000, Box::new(caller));
            s.clients.insert(2001, Box::new(monitor));
            if monitored { s.monitors.push((2001, 0)); }
            let mut expected = Vec::new();
            for i in 0..64u16 {
                let path = format!("queue.{i:03}");
                let mut b = BlobBuf::new();
                b.put_string(attr::OBJPATH, &path);
                let signature = b.nest_start(attr::SIGNATURE);
                let method = b.msg_open_table("method");
                b.msg_u32("policy", 5);
                b.msg_close(method);
                b.nest_end(signature);
                let header = Header { ty: ty::ADD_OBJECT, seq: i * 2, peer: 123 };
                assert!(s.receive(2000, InMsg { header, blob: b.as_bytes().to_vec().into(), fd: None }));
                let id = s.reg.by_path(path.as_bytes()).unwrap();
                let type_id = s.reg.get(id).unwrap().type_id.unwrap();
                let mut data = BlobBuf::new();
                data.put_u32(attr::OBJID, id);
                data.put_u32(attr::OBJTYPE, type_id);
                let data = data.as_bytes().to_vec();
                let mut status_blob = BlobBuf::new();
                status_blob.put_u32(attr::STATUS, status::OK as u32);
                let status_blob = status_blob.as_bytes().to_vec();
                expected.push((Header { ty: ty::DATA, ..header }, data.clone()));
                expected.push((Header { ty: ty::STATUS, ..header }, status_blob.clone()));
                let mut b = BlobBuf::new();
                b.put_u32(attr::OBJID, id);
                let header = Header { ty: ty::REMOVE_OBJECT, seq: i * 2 + 1, peer: 456 };
                assert!(s.receive(2000, InMsg { header, blob: b.as_bytes().to_vec().into(), fd: None }));
                expected.push((Header { ty: ty::DATA, ..header }, data));
                expected.push((Header { ty: ty::STATUS, ..header }, status_blob));
                assert!(s.reg.get(id).is_none());
                assert!(s.reg.types.is_empty());
            }
            assert!(!s.clients[&2000].tx_empty(), "fixture must queue replies before reading");
            assert!(s.reg.paths.is_empty() && s.clients[&2000].objects.is_empty());
            let actual = lookup_frames(&drain_lookup(&mut s, 2000, &mut peer));
            assert_eq!(actual.len(), expected.len());
            for ((h, b), (wanted_h, wanted_b)) in actual.iter().zip(&expected) {
                assert_eq!(h.encode(), wanted_h.encode());
                assert_eq!(b, wanted_b);
            }
            let mirrors = lookup_frames(&drain_lookup(&mut s, 2001, &mut monitor_peer));
            if monitored {
                assert_eq!(mirrors.len(), 64 * 6);
                let mut outgoing = expected.iter();
                for (i, (h, b)) in mirrors.iter().enumerate() {
                    assert_eq!((h.ty, h.seq, h.peer), (ty::MONITOR, i as u16 + 1, 0));
                    // Monitor attributes have their own types: SEND is u8,
                    // whereas the same index is a string in the bus policy.
                    let mut attrs = [None; 6];
                    let mut offset = 0;
                    while let Some((a, next)) = blob::attr_at(&b[4..], offset) {
                        attrs[a.id as usize] = Some(a);
                        offset = next;
                    }
                    assert_eq!(attrs[0].unwrap().as_u32(), Some(2000));
                    if attrs[2].unwrap().payload == [1] {
                        let (header, blob) = outgoing.next().unwrap();
                        assert_eq!(attrs[1].unwrap().as_u32(), Some(header.peer));
                        assert_eq!(attrs[3].unwrap().as_u32(), Some(header.seq as u32));
                        assert_eq!(attrs[4].unwrap().as_u32(), Some(header.ty as u32));
                        assert_eq!(attrs[5].unwrap().payload, &blob[4..]);
                    }
                }
                assert!(outgoing.next().is_none());
            } else {
                assert!(mirrors.is_empty());
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn add_reply_preserves_event_order_shapes_errors_and_fd_close() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        // No type, a newly declared type, a reused type, and an invalid
        // signature cover both DATA sizes and successful typeless creation.
        for kind in 0..4 {
            let mut s = Server::new(String::new()).unwrap();
            let (caller, mut peer) = lookup_client();
            s.clients.insert(2000, Box::new(caller));
            s.reg.create(None, Some(4000)).unwrap();
            s.reg.get_mut(4000).unwrap().client = Some(2000);
            s.patterns.push(Pattern { key: b"ubus.object.".to_vec(), partial: true, obj: 4000 });

            let mut request = BlobBuf::new();
            request.put_string(attr::OBJPATH, "reply.test");
            match kind {
                1 => { request.put(attr::SIGNATURE, &[]); }
                2 => {
                    let type_id = s.reg.new_type(Vec::new()).unwrap();
                    request.put_u32(attr::OBJTYPE, type_id);
                }
                3 => { request.put(attr::SIGNATURE, &[0, 0, 0, 1]); }
                _ => {}
            }
            let header = Header { ty: ty::ADD_OBJECT, seq: 0xfffe, peer: 0x12345678 };
            let (sent, mut witness) = UnixStream::pair().unwrap();
            witness.set_nonblocking(true).unwrap();
            assert!(s.receive(2000, InMsg { header, blob: request.as_bytes().to_vec().into(), fd: Some(sent.into()) }));
            assert_eq!(witness.read(&mut [0u8; 1]).unwrap(), 0, "ADD must close its input FD");

            let id = s.reg.by_path(b"reply.test").unwrap();
            let mut event = BlobBuf::new();
            event.put_u32(attr::OBJID, 4000);
            event.put_string(attr::METHOD, "ubus.object.add");
            let data = event.nest_start(attr::DATA);
            event.msg_u32("id", id);
            event.msg_string("path", "reply.test");
            event.nest_end(data);
            let mut reply = BlobBuf::new();
            reply.put_u32(attr::OBJID, id);
            if kind == 1 {
                reply.put_u32(attr::OBJTYPE, s.reg.get(id).unwrap().type_id.unwrap());
            }
            assert_eq!(reply.as_bytes().len(), if kind == 1 { 20 } else { 12 });
            let mut ok = BlobBuf::new();
            ok.put_u32(attr::STATUS, status::OK as u32);
            let actual = lookup_frames(&drain_lookup(&mut s, 2000, &mut peer));
            let expected = [
                (Header { ty: ty::INVOKE, seq: 1, peer: 0 }, event.as_bytes()),
                (Header { ty: ty::DATA, ..header }, reply.as_bytes()),
                (Header { ty: ty::STATUS, ..header }, ok.as_bytes()),
            ];
            assert_eq!(actual.len(), expected.len());
            for ((h, blob), (want_h, want_blob)) in actual.iter().zip(expected) {
                assert_eq!(h.encode(), want_h.encode());
                assert_eq!(blob, want_blob);
            }

            let before = (s.reg.objects.len(), s.reg.types.len(), s.obj_event_seq);
            assert!(s.receive(2000, InMsg { header, blob: request.as_bytes().to_vec().into(), fd: None }));
            let actual = lookup_frames(&drain_lookup(&mut s, 2000, &mut peer));
            assert_eq!(actual.len(), 1, "duplicate path must have no DATA or object event");
            assert_eq!(actual[0].0.encode(), Header { ty: ty::STATUS, ..header }.encode());
            let mut error = BlobBuf::new();
            error.put_u32(attr::STATUS, status::INVALID_ARGUMENT as u32);
            assert_eq!(actual[0].1, error.as_bytes());
            assert_eq!((s.reg.objects.len(), s.reg.types.len(), s.obj_event_seq), before);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn event_send_preserves_group_root_and_missing_client_acl() {
        const SENDER: u32 = 2000;
        let mut data = BlobBuf::new();
        data.msg_string("id", "group.event");
        let payload = data.msg_open_table("data");
        data.msg_u32("value", 0x12345678);
        data.msg_close(payload);
        for (name, credentials, expected) in [
            ("supplementary group", Some((100, 7, &[42][..])), status::OK),
            ("no matching group", Some((100, 7, &[][..])), status::PERMISSION_DENIED),
            ("primary group", Some((100, 42, &[][..])), status::OK),
            ("root", Some((0, 7, &[][..])), status::OK),
            ("missing client", None, status::OK),
        ] {
            let mut s = Server::new(String::new()).unwrap();
            s.acl = Acl::send_group_fixture("group.event", 42);
            let (mut caller, _peer) = lookup_client();
            if let Some((uid, gid, extra_gid)) = credentials {
                caller.uid = uid;
                caller.gid = gid;
                caller.extra_gid = extra_gid.to_vec();
                s.clients.insert(SENDER, Box::new(caller));
            }
            let round = s.obj_event_seq;
            assert_eq!(s.event_send(SENDER, Some(data.payload())), expected, "{name}");
            assert_eq!(s.obj_event_seq, round + u32::from(expected == status::OK), "{name}: dispatch authorization");
        }
    }

    #[test]
    fn events_without_eligible_receivers_do_not_encode_but_advance_round() {
        for case in 0..5 {
            let mut s = Server::new(String::new()).unwrap();
            let object = 4000;
            if case != 4 {
                s.reg.create(None, Some(object)).unwrap();
                s.reg.get_mut(object).unwrap().client = if case == 3 { None } else { Some(2000) };
            }
            if case != 0 {
                s.patterns.push(Pattern { key: if case == 1 { b"other".to_vec() } else { b"event".to_vec() },
                    partial: false, obj: object });
            }
            let round = s.obj_event_seq;
            s.scratch.put_string(attr::METHOD, "untouched");
            let before = s.scratch.as_bytes().to_vec();
            s.dispatch_event(Some(2000), b"event", |_| panic!("no receiver in case {case}"));
            assert_eq!(s.scratch.as_bytes(), before);
            assert_eq!(s.obj_event_seq, round + 1);
            assert_eq!(s.event_seq, 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deferred_event_preserves_dedup_sequences_monitor_and_queued_payload() {
        let mut s = Server::new(String::new()).unwrap();
        let (owner, mut peer) = lookup_client();
        let (monitor, mut monitor_peer) = lookup_client();
        s.clients.insert(2000, Box::new(owner));
        s.clients.insert(2001, Box::new(monitor));
        s.monitors.push((2001, 0));
        for id in [4000, 4001] {
            s.reg.create(None, Some(id)).unwrap();
            s.reg.get_mut(id).unwrap().client = Some(2000);
            for _ in 0..2 {
                s.patterns.push(Pattern { key: b"event".to_vec(), partial: false, obj: id });
            }
        }
        let mut expected = BlobBuf::new();
        expected.put_u32(attr::OBJID, 0);
        expected.put_string(attr::METHOD, "event");
        expected.put(attr::DATA, &vec![0x5a; 32768]);
        let expected = expected.as_bytes().to_vec();
        s.event_seq = u16::MAX;
        let builds = std::cell::Cell::new(0);
        s.dispatch_event(None, b"event", |b| {
            builds.set(builds.get() + 1);
            b.put_raw_fields(&expected[4..]);
        });
        assert_eq!(builds.get(), 1);
        assert!(!s.clients[&2000].tx_empty(), "large payload must force queue ownership");
        let frames = lookup_frames(&drain_lookup(&mut s, 2000, &mut peer));
        assert_eq!(frames.len(), 2, "two objects on one connection, no duplicate deliveries");
        for (i, (header, actual)) in frames.iter().enumerate() {
            assert_eq!((header.ty, header.seq, header.peer), (ty::INVOKE, i as u16, 0));
            let mut wanted = expected.clone();
            patch_first_u32(&mut wanted, 4000 + i as u32);
            assert_eq!(*actual, wanted);
        }
        let mirrors = lookup_frames(&drain_lookup(&mut s, 2001, &mut monitor_peer));
        assert_eq!(mirrors.len(), 2);
        assert!(mirrors.iter().all(|(h, _)| h.ty == ty::MONITOR));
        s.free_object(4001);
        s.dispatch_event(None, b"event", |b| { b.put_raw_fields(&expected[4..]); });
        let frames = lookup_frames(&drain_lookup(&mut s, 2000, &mut peer));
        assert_eq!(frames.len(), 1, "deleted listener patterns must not survive");
        assert_eq!(frames[0].0.seq, 2);
        assert_eq!(attrs_of(&frames[0].1[4..])[attr::OBJID as usize].unwrap().as_u32(), Some(4000));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_invoke_queued_event_and_monitor_own_borrowed_input() {
        const OWNER: u32 = 2000;
        const MONITOR: u32 = 2001;
        const SENDER: u32 = 2002;
        const OBJECTS: [u32; 2] = [4000, 4001];
        let mut s = Server::new(String::new()).unwrap();
        let (owner, mut peer) = lookup_client();
        let (monitor, mut monitor_peer) = lookup_client();
        let (sender, _sender_peer) = lookup_client();
        s.clients.insert(OWNER, Box::new(owner));
        s.clients.insert(MONITOR, Box::new(monitor));
        s.clients.insert(SENDER, Box::new(sender));
        s.monitors.push((MONITOR, 0));
        for object in OBJECTS {
            s.reg.create(None, Some(object)).unwrap();
            s.reg.get_mut(object).unwrap().client = Some(OWNER);
            s.patterns.push(Pattern { key: b"event".to_vec(), partial: false, obj: object });
        }

        // Fill both sockets first: every subsequent event and mirror must
        // own queued bytes before another receiver/request mutates scratch.
        let mut filler = BlobBuf::new();
        filler.put(attr::DATA, &vec![0x5a; 32768]);
        for id in [OWNER, MONITOR] {
            s.clients.get_mut(&id).unwrap().send(OutMsg::new(ty::DATA, 0, 0, filler.as_bytes().to_vec()));
            assert!(!s.clients[&id].tx_empty(), "fixture must queue before invoke");
        }

        let mut expected_events = Vec::new();
        let mut expected_mirrors = Vec::new();
        for (round, size) in [32769, 3].into_iter().enumerate() {
            // An odd-sized nested string checks padding as well as removal
            // of the large frame's tail when the small frame reuses scratch.
            let mut payload = BlobBuf::new();
            payload.msg_u32("value", 0x12345678);
            let array = payload.msg_open_array("items");
            let table = payload.msg_open_table("");
            payload.msg_string("text", &"x".repeat(size));
            payload.msg_bool("end", true);
            payload.msg_close(table);
            payload.msg_close(array);
            let mut request = BlobBuf::new();
            request.put_u32(attr::OBJID, SYSTEM_OBJECT_EVENT);
            request.put_string(attr::METHOD, "send");
            let data = request.nest_start(attr::DATA);
            request.msg_string("id", "event");
            request.msg_field(MsgType::Table as u32, "data", payload.payload());
            request.nest_end(data);
            let request = request.as_bytes().to_vec();
            let header = Header { ty: ty::INVOKE, seq: 123 + round as u16 * 2, peer: 456 };
            if Header::LEN + request.len() <= crate::client::RX_SIZE {
                let mut rx = [0u8; crate::client::RX_SIZE];
                rx[..request.len()].copy_from_slice(&request);
                assert!(s.receive(SENDER, InMsg { header, blob: Cow::Borrowed(&rx[..request.len()]), fd: None }));
                rx.fill(0xa5);
            } else {
                // Match read_message's owned input for a frame above RX_SIZE;
                // it is dropped before the queued output is drained.
                assert!(s.receive(SENDER, InMsg { header, blob: Cow::Owned(request.clone()), fd: None }));
            }
            expected_mirrors.push((SENDER, false, header, request));
            for (offset, object) in OBJECTS.into_iter().enumerate() {
                let mut event = BlobBuf::new();
                event.put_u32(attr::OBJID, object);
                event.put_string(attr::METHOD, "event");
                event.put(attr::DATA, payload.payload());
                let event = event.as_bytes().to_vec();
                let event_header = Header { ty: ty::INVOKE, seq: (round * 2 + offset + 1) as u16, peer: 0 };
                expected_events.push((event_header, event.clone()));
                expected_mirrors.push((OWNER, true, event_header, event));
            }
            let mut reply = BlobBuf::new();
            reply.put_u32(attr::STATUS, status::OK as u32);
            expected_mirrors.push((SENDER, true, Header { ty: ty::STATUS, ..header }, reply.as_bytes().to_vec()));

            if round == 0 {
                // A different request uses the same scratch before either
                // queued receiver drains and before the smaller event starts.
                let mut query = BlobBuf::new();
                query.put_string(attr::OBJPATH, "r124.missing");
                let query = query.as_bytes().to_vec();
                let header = Header { ty: ty::LOOKUP, seq: 124, peer: 456 };
                assert!(s.receive(SENDER, InMsg { header, blob: Cow::Borrowed(&query), fd: None }));
                let mut reply = BlobBuf::new();
                reply.put_u32(attr::STATUS, status::NOT_FOUND as u32);
                let reply = reply.as_bytes().to_vec();
                assert_eq!(s.scratch.as_bytes(), reply);
                expected_mirrors.push((SENDER, false, header, query));
                expected_mirrors.push((SENDER, true, Header { ty: ty::STATUS, ..header }, reply));
            }
        }

        let frames = lookup_frames(&drain_lookup(&mut s, OWNER, &mut peer));
        assert_eq!(frames.len(), 1 + expected_events.len());
        assert_eq!(&frames[1..], expected_events.as_slice(), "OBJID, sequence, full payload and no old tail");
        let mirrors = lookup_frames(&drain_lookup(&mut s, MONITOR, &mut monitor_peer));
        assert_eq!(mirrors.len(), 1 + expected_mirrors.len());
        for (i, ((h, bytes), (client, send, header, original))) in mirrors[1..].iter().zip(&expected_mirrors).enumerate() {
            assert_eq!((h.ty, h.seq, h.peer), (ty::MONITOR, i as u16 + 1, 0));
            let mut wanted = BlobBuf::new();
            wanted.put_u32(0, *client);
            wanted.put_u32(1, header.peer);
            wanted.put_u32(3, header.seq as u32);
            wanted.put_u32(4, header.ty as u32);
            wanted.put_u8(2, u8::from(*send));
            wanted.put(5, &original[4..]);
            assert_eq!(bytes, wanted.as_bytes(), "complete monitor frame {i}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_event_write_does_not_mark_interest_dirty() {
        let mut s = Server::new(String::new()).unwrap();
        let (owner, mut peer) = lookup_client();
        s.clients.insert(2000, Box::new(owner));
        s.reg.create(None, Some(4000)).unwrap();
        s.reg.get_mut(4000).unwrap().client = Some(2000);
        s.patterns.push(Pattern { key: b"event".to_vec(), partial: false, obj: 4000 });
        s.dispatch_event(None, b"event", |b| {
            b.put_u32(attr::OBJID, 0);
            b.put_string(attr::METHOD, "event");
        });
        assert!(s.touched.is_empty());
        let mut buf = [0u8; 128];
        let n = std::io::Read::read(&mut peer, &mut buf).unwrap();
        assert!(n > 0);
    }

    #[cfg(target_os = "linux")]
    fn check_event_round_wrap(last_seen: u32) {
        let mut s = Server::new(String::new()).unwrap();
        let (owner, mut peer) = lookup_client();
        s.clients.insert(2000, Box::new(owner));
        s.reg.create(None, Some(4000)).unwrap();
        let o = s.reg.get_mut(4000).unwrap();
        o.client = Some(2000);
        o.event_seen = last_seen;
        for _ in 0..2 {
            s.patterns.push(Pattern { key: b"event".to_vec(), partial: false, obj: 4000 });
        }
        s.obj_event_seq = u32::MAX;
        s.dispatch_event(None, b"event", |b| {
            b.put_u32(attr::OBJID, 0);
            b.put_string(attr::METHOD, "event");
            b.put(attr::DATA, &[]);
        });
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
        use std::os::unix::net::UnixStream;
        let (sock, peer) = UnixStream::pair().unwrap();
        sock.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        rustix::net::sockopt::set_socket_send_buffer_size(&sock, 4096).unwrap();
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
    fn event_server_with_owner(objects: &[u32]) -> (Server, std::os::unix::net::UnixStream) {
        let mut server = Server::new(String::new()).unwrap();
        let (owner, peer) = lookup_client();
        server.clients.insert(2000, Box::new(owner));
        for &object in objects {
            server.reg.create(None, Some(object)).unwrap();
            server.reg.get_mut(object).unwrap().client = Some(2000);
            server.patterns.push(Pattern { key: b"event".to_vec(), partial: false, obj: object });
        }
        (server, peer)
    }

    #[cfg(target_os = "linux")]
    fn simple_event(server: &mut Server) {
        server.dispatch_event(None, b"event", |b| {
            b.put_u32(attr::OBJID, 0);
            b.put_string(attr::METHOD, "event");
            b.msg_u32("value", 0x1234_5678);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_owner_event_batch_preserves_each_frame() {
        let objects = [4000, 4001, 4002];
        let (mut server, mut peer) = event_server_with_owner(&objects);
        simple_event(&mut server);
        let frames = lookup_frames(&drain_lookup(&mut server, 2000, &mut peer));
        assert_eq!(frames.len(), objects.len());
        assert!(server.event_batch.is_empty());
        for (i, ((header, blob), object)) in frames.iter().zip(objects).enumerate() {
            assert_eq!((header.ty, header.seq, header.peer), (ty::INVOKE, i as u16 + 1, 0));
            assert_eq!(attrs_of(&blob[4..])[attr::OBJID as usize].unwrap().as_u32(), Some(object));
            assert_eq!(attrs_of(&blob[4..])[attr::METHOD as usize].unwrap().payload, b"event\0");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interleaved_owners_keep_per_client_and_global_event_order() {
        let mut server = Server::new(String::new()).unwrap();
        let (a, mut a_peer) = lookup_client();
        let (b, mut b_peer) = lookup_client();
        server.clients.insert(2000, Box::new(a));
        server.clients.insert(2001, Box::new(b));
        for (object, owner) in [(4000, 2000), (4001, 2001), (4002, 2000)] {
            server.reg.create(None, Some(object)).unwrap();
            server.reg.get_mut(object).unwrap().client = Some(owner);
            server.patterns.push(Pattern { key: b"event".to_vec(), partial: false, obj: object });
        }
        simple_event(&mut server);
        let a_frames = lookup_frames(&drain_lookup(&mut server, 2000, &mut a_peer));
        let b_frames = lookup_frames(&drain_lookup(&mut server, 2001, &mut b_peer));
        assert_eq!(a_frames.iter().map(|(h, _)| h.seq).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(b_frames.iter().map(|(h, _)| h.seq).collect::<Vec<_>>(), [2]);
        assert_eq!(attrs_of(&a_frames[0].1[4..])[attr::OBJID as usize].unwrap().as_u32(), Some(4000));
        assert_eq!(attrs_of(&a_frames[1].1[4..])[attr::OBJID as usize].unwrap().as_u32(), Some(4002));
        assert_eq!(attrs_of(&b_frames[0].1[4..])[attr::OBJID as usize].unwrap().as_u32(), Some(4001));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monitored_event_fanout_keeps_one_mirror_per_frame() {
        let (mut server, mut owner_peer) = event_server_with_owner(&[4000, 4001, 4002]);
        let (monitor, mut monitor_peer) = lookup_client();
        server.clients.insert(2001, Box::new(monitor));
        server.monitors.push((2001, 0));
        simple_event(&mut server);
        let events = lookup_frames(&drain_lookup(&mut server, 2000, &mut owner_peer));
        let mirrors = lookup_frames(&drain_lookup(&mut server, 2001, &mut monitor_peer));
        assert_eq!(events.len(), 3);
        assert_eq!(mirrors.len(), 3);
        for (i, ((event_header, event_blob), (mirror_header, mirror_blob))) in events.iter().zip(&mirrors).enumerate() {
            assert_eq!((event_header.ty, event_header.seq), (ty::INVOKE, i as u16 + 1));
            assert_eq!((mirror_header.ty, mirror_header.seq), (ty::MONITOR, i as u16 + 1));
            // Monitor fields use a separate monitor ABI; attr::METHOD/TYPE
            // ids intentionally overlap and must not be passed through the
            // request policy parser.
            let mut wanted = BlobBuf::new();
            wanted.put_u32(0, 2000);
            wanted.put_u32(1, 0);
            wanted.put_u32(3, event_header.seq as u32);
            wanted.put_u32(4, ty::INVOKE as u32);
            wanted.put_u8(2, 1);
            wanted.put(5, &event_blob[4..]);
            assert_eq!(*mirror_blob, wanted.as_bytes());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn queued_same_owner_batch_survives_scratch_reuse() {
        let (mut server, mut peer) = event_server_with_owner(&[4000, 4001, 4002]);
        let mut filler = BlobBuf::new();
        filler.put(attr::DATA, &[0x5a; 32 * 1024]);
        server.clients.get_mut(&2000).unwrap().send(OutMsg::new(ty::DATA, 0, 0, filler.as_bytes().to_vec()));
        simple_event(&mut server);
        let frames = lookup_frames(&drain_lookup(&mut server, 2000, &mut peer));
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].0.ty, ty::DATA);
        for (i, (header, blob)) in frames.iter().skip(1).enumerate() {
            assert_eq!((header.ty, header.seq), (ty::INVOKE, i as u16 + 1));
            assert_eq!(attrs_of(&blob[4..])[attr::OBJID as usize].unwrap().as_u32(), Some(4000 + i as u32));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn batched_lookup_keeps_full_frames_and_fifo_under_backpressure() {
        const CALLER: u32 = 2000;
        const TYPE: u32 = 3000;
        for (count, signature_len) in [(128, 0), (1, 6000)] {
            let mut server = Server::new(String::new()).unwrap();
            let (caller, mut peer) = lookup_client();
            server.clients.insert(CALLER, Box::new(caller));
            let mut methods = Vec::new();
            if signature_len != 0 {
                let mut signature = BlobBuf::new();
                let table = signature.msg_open_table("method");
                signature.msg_string("large", &"x".repeat(signature_len));
                signature.msg_close(table);
                methods.push(obj::Method::new(signature.payload().to_vec()));
            }
            server.reg.types.insert(TYPE, obj::ObjType { refcount: 0, methods });
            let mut expected = Vec::new();
            for i in 0..count {
                let id = 4000 + i;
                server.reg.create(Some(TYPE), Some(id)).unwrap();
                assert!(server.reg.set_path(id, &format!("lookup.{i:04}").into_bytes()));
                assert!(server.build_obj(CALLER, id));
                expected.push(server.scratch.as_bytes().to_vec());
            }
            for seq in [10, 11] {
                let mut blob = BlobBuf::new();
                assert!(server.receive(CALLER, InMsg {
                    header: Header { ty: ty::LOOKUP, seq, peer: 1234 },
                    blob: blob.as_bytes().to_vec().into(), fd: None,
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
            server.clients.insert(CALLER, Box::new(caller));
            let mut signature = BlobBuf::new();
            let table = signature.msg_open_table("method");
            signature.msg_string("large", &"x".repeat(32768));
            signature.msg_close(table);
            server.reg.types.insert(TYPE, obj::ObjType { refcount: 0, methods: vec![obj::Method::new(signature.payload().to_vec())] });
            let mut expected = Vec::new();
            for i in 0..12 {
                let id = FIRST + i;
                server.reg.create(Some(TYPE), Some(id)).unwrap();
                assert!(server.reg.set_path(id, &format!("lookup.{i:02}").into_bytes()));
                assert!(server.build_obj(CALLER, id));
                expected.push(server.scratch.as_bytes().to_vec());
            }
            let mut blob = BlobBuf::new();
            blob.put_string(attr::OBJPATH, pattern);
            let request = InMsg { header: Header { ty: ty::LOOKUP, seq: 0xabcd, peer: 0x12345678 },
                blob: blob.as_bytes().to_vec().into(), fd: None };
            assert!(server.receive(CALLER, request));
            let next = server.clients[&CALLER].cmd_queue.front().unwrap().next.clone().unwrap();
            assert_eq!(next, b"lookup.01", "first frame must force backpressure");
            let removed = server.reg.by_path(&next).unwrap();
            server.reg.destroy(removed).unwrap();
            if change == "recreate" {
                server.reg.create(Some(TYPE), Some(9000)).unwrap();
                assert!(server.reg.set_path(9000, &next));
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
            assert!(server.reg.set_path(9001, b"lookup.00a"));
            if pattern != "*" {
                server.reg.create(Some(TYPE), Some(9002)).unwrap();
                assert!(server.reg.set_path(9002, b"outside"));
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
            server.clients.insert(CALLER, Box::new(caller));
            let (monitor, mut monitor_peer) = lookup_client();
            server.clients.insert(MONITOR, Box::new(monitor));
            if monitored {
                server.monitors.push((MONITOR, 0));
            }
            server.reg.types.insert(3000, obj::ObjType { refcount: 0, methods: Vec::new() });
            let mut signature = BlobBuf::new();
            let table = signature.msg_open_table("hidden");
            signature.msg_close(table);
            server.reg.types.insert(3001, obj::ObjType { refcount: 0, methods: vec![obj::Method::new(signature.payload().to_vec())] });
            // Deliberately insert in reverse byte order, including non-UTF8.
            for (id, path, kind) in [(4000, &b"z\xff"[..], Some(3000)),
                                      (4001, &b"c"[..], Some(3001)),
                                      (4002, &b"b"[..], None),
                                      (4003, &b"a"[..], Some(3000))] {
                server.reg.create(kind, Some(id)).unwrap();
                assert!(server.reg.set_path(id, path));
            }
            let mut blob = BlobBuf::new();
            blob.put_string(attr::OBJPATH, "*");
            let mut received = blob.as_bytes().to_vec();
            let request = InMsg { header: Header { ty: ty::LOOKUP, seq: 55, peer: 66 },
                blob: Cow::Borrowed(&received), fd: None };
            let input = request.blob[4..].to_vec();
            assert!(server.receive(CALLER, request));
            received.fill(0xa5);
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
        server.clients.insert(CALLER, Box::new(caller));
        let mut signature = BlobBuf::new();
        let table = signature.msg_open_table("method");
        signature.msg_string("large", &"x".repeat(32768));
        signature.msg_close(table);
        server.reg.types.insert(3000, obj::ObjType { refcount: 0, methods: vec![obj::Method::new(signature.payload().to_vec())] });
        let mut expected = Vec::new();
        for i in 0..40 {
            let id = 4000 + i;
            server.reg.create(Some(3000), Some(id)).unwrap();
            assert!(server.reg.set_path(id, &format!("lookup.{i:02}").into_bytes()));
            assert!(server.build_obj(CALLER, id));
            expected.push(server.scratch.as_bytes().to_vec());
        }
        for (seq, pattern) in [(10, "*"), (11, "lookup.39"), (12, "missing.*")] {
            let mut blob = BlobBuf::new();
            blob.put_string(attr::OBJPATH, pattern);
            assert!(server.receive(CALLER, InMsg { header: Header { ty: ty::LOOKUP, seq, peer: 55 },
                blob: Cow::Borrowed(blob.as_bytes()), fd: None }));
            // Simulate the next input overwriting the shared receive bytes
            // while this LOOKUP is still parked behind earlier output.
            blob.reset();
        }
        assert_eq!(server.clients[&CALLER].cmd_queue.len(), 3);
        let mut ping = BlobBuf::new();
        ping.put_string(attr::OBJPATH, "ping");
        let ping_bytes = ping.as_bytes().to_vec();
        let mut borrowed_ping = ping_bytes.clone();
        assert!(server.receive(CALLER, InMsg { header: Header { ty: ty::PING, seq: 13, peer: 56 },
            blob: Cow::Borrowed(&borrowed_ping), fd: None }));
        borrowed_ping.fill(0xa5);
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
