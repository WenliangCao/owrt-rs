//! UDP forwarding state traced to patched dnsmasq 2.93 forward.c.
//!
//! Network I/O, EDNS mutation, domain matching, reply policy/cache insertion and
//! socket allocation remain in the caller. A socket token denotes a caller-owned
//! socket reference; release notifications must be consumed to drop that reference.

use super::wire::{
    decode_name, decode_name_with_aliasing, validate_name_may_alias, Header, Name, WireError,
    HEADER_LEN,
};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

pub const QUERY_TIMEOUT: i64 = 10;
pub const ABSOLUTE_TIMEOUT: i64 = 4 * QUERY_TIMEOUT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub rrtype: u16,
    pub class: u16,
}

impl Question {
    pub fn parse(packet: &[u8]) -> Result<Self, WireError> {
        let header = Header::parse(packet)?;
        Self::parse_with_header(packet, header)
    }

    /// Reuse the caller's header while decoding the owned name once.
    pub fn parse_with_header(packet: &[u8], header: Header) -> Result<Self, WireError> {
        if header.questions != 1 {
            return Err(WireError::InvalidName);
        }
        let (name, end) = decode_name(packet, HEADER_LEN, 4)?;
        Ok(Self {
            name,
            rrtype: u16::from_be_bytes([packet[end], packet[end + 1]]),
            class: u16::from_be_bytes([packet[end + 2], packet[end + 3]]),
        })
    }

    pub(super) fn parse_with_header_reusing(
        packet: &[u8],
        header: Header,
        scratch: &mut Vec<u8>,
    ) -> Result<Self, WireError> {
        if header.questions != 1 {
            return Err(WireError::InvalidName);
        }
        let (name, end) = super::wire::decode_name_reusing(packet, HEADER_LEN, 4, scratch)?;
        Ok(Self {
            name,
            rrtype: u16::from_be_bytes([packet[end], packet[end + 1]]),
            class: u16::from_be_bytes([packet[end + 2], packet[end + 3]]),
        })
    }
}

/// The ordinary-query subset of FREC flags. DO also implies AD_QUESTION when
/// deriving these from a packet (receive_query, RFC 6840 section 5.7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Flags {
    pub checking_disabled: bool,
    pub ad_requested: bool,
    pub dnssec_ok: bool,
    pub had_opt: bool,
    pub no_cache: bool,
}

impl Flags {
    pub fn from_header(header: Header, had_opt: bool, dnssec_ok: bool, cacheable: bool) -> Self {
        Self {
            checking_disabled: header.flags & 0x10 != 0,
            ad_requested: dnssec_ok || header.flags & 0x20 != 0,
            dnssec_ok,
            had_opt,
            no_cache: !cacheable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerId(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketToken(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryId(u64);

/// Shared reproduces the C lookup mask. A caller may explicitly separate
/// requests whose effective EDNS options are tied to a client. No policy about
/// that separation is silently inferred from no_cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    Shared,
    /// Effective option bytes: source-dependent identities must not leak
    /// through C's question-only matching, but identical identities can merge.
    Edns(Vec<u8>),
    Client(SocketAddr),
}

#[derive(Debug, Clone)]
pub struct Client {
    pub source: SocketAddr,
    pub destination: IpAddr,
    pub interface: u32,
    /// Optional containing-process socket identity. A library caller may
    /// still request a response without supplying a socket token.
    pub listener: Option<SocketToken>,
    /// False for an explicit background refresh. Coalesced ordinary clients
    /// retain their own delivery decision independently.
    pub reply_requested: bool,
    pub udp_limit: u16,
    pub log_id: u64,
}

impl Client {
    pub fn query_context(&self) -> crate::query_logging::QueryContext {
        crate::query_logging::QueryContext {
            display_id: self.log_id as i32,
            // forward.c::return_reply retains the refresh display ID but
            // clears log_source_addr when this recipient has fd=-1.
            client: self.reply_requested.then_some(self.source),
        }
    }
}

#[derive(Debug)]
pub struct Recipient {
    pub client: Client,
    pub original_id: u16,
    pub question_name: Name,
}

impl Recipient {
    /// Apply the client/upstream case difference, preserving any accepted
    /// upstream case changes when 0x20 authentication is disabled. Compression
    /// references remain valid; name validation precedes all mutation.
    pub fn restore_question(&self, packet: &mut [u8], upstream: &Name) -> Result<(), WireError> {
        restore_name_case(packet, &self.question_name, upstream)?;
        packet[..2].copy_from_slice(&self.original_id.to_be_bytes());
        Ok(())
    }
}

/// Randomness comes from the operating system in production. Deterministic
/// implementations belong only in tests; failure must propagate to the caller.
pub trait Random {
    fn next_u32(&mut self) -> io::Result<u32>;
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub forward_max: usize,
    pub case_randomization: bool,
    pub fast_retry_ms: u32,
    pub fast_retry_timeout_s: i64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            forward_max: 150,
            case_randomization: false,
            fast_retry_ms: 0,
            fast_retry_timeout_s: 10,
        }
    }
}

#[derive(Debug)]
pub enum SubmitError {
    Wire(WireError),
    NotQuery,
    GroupFull,
    DuplicateFull,
    IdSpaceFull,
    Random(io::Error),
}
impl From<WireError> for SubmitError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionKind {
    New,
    Coalesced,
    ClientRetry,
    LateDuplicate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Submission {
    pub id: QueryId,
    pub kind: SubmissionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    name: Vec<u8>,
    rrtype: u16,
    class: u16,
    flags: Flags,
    scope: Scope,
}

#[derive(Debug)]
pub struct Pending {
    pub id: QueryId,
    pub group: GroupId,
    pub question: Question,
    pub flags: Flags,
    pub created: i64,
    pub upstream_id: u16,
    /// The query after upstream ID/case changes, before caller's EDNS changes.
    pub packet: Vec<u8>,
    pub recipients: Vec<Recipient>,
    pub sent_to: Option<ServerId>,
    pub forward_all: u32,
    pub last_sent_ms: u32,
    pub retry_delay_ms: u32,
    key: Key,
    sockets: Vec<SocketToken>,
    slot: usize,
}

impl Pending {
    pub fn query_context(&self) -> crate::query_logging::QueryContext {
        self.recipients
            .first()
            .map_or_else(Default::default, |recipient| {
                recipient.client.query_context()
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseReason {
    Completed,
    Expired,
    Cancelled,
    ServerGone,
}
#[derive(Debug)]
pub struct Released {
    pub id: QueryId,
    pub sockets: Vec<SocketToken>,
    pub reason: ReleaseReason,
}

/// Actual forwarding actions and get_new_frec reclamation, matching C's u32
/// counters. Cancellation, server removal and duplicate-pool rejection do not
/// increment unanswered merely because they release a record.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ForwardCounters {
    pub queries_forwarded: u32,
    pub unanswered: u32,
    /// Actual failed fast-retry sends take C's local fallback with udpfd=-1.
    /// This cumulative producer counts that answer even without wire delivery.
    pub background_local_answered: u32,
}

/// Queries are indexed by normalized question and by unique upstream ID, rather
/// than repeatedly decoding every saved packet on each duplicate/reply lookup.
pub struct ForwardTable {
    options: Options,
    pending: HashMap<QueryId, Pending>,
    keys: HashMap<Key, QueryId>,
    ids: HashMap<u16, QueryId>,
    next_id: u64,
    extra_clients: usize,
    released: Vec<Released>,
    slots: Vec<Option<QueryId>>,
    counters: ForwardCounters,
}

impl ForwardTable {
    pub fn new(options: Options) -> Self {
        Self {
            options,
            pending: HashMap::new(),
            keys: HashMap::new(),
            ids: HashMap::new(),
            next_id: 0,
            extra_clients: 0,
            released: Vec::new(),
            slots: Vec::new(),
            counters: ForwardCounters::default(),
        }
    }

    pub fn get(&self, id: QueryId) -> Option<&Pending> {
        self.pending.get(&id)
    }
    pub fn len(&self) -> usize {
        self.pending.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    pub fn take_released(&mut self) -> Vec<Released> {
        std::mem::take(&mut self.released)
    }

    pub fn counters(&self) -> ForwardCounters {
        self.counters
    }

    /// One forward_query send action succeeded, possibly to several servers.
    /// Call only after at least one actual datagram send completed.
    pub fn note_forwarded_action(&mut self) {
        self.counters.queries_forwarded = self.counters.queries_forwarded.wrapping_add(1);
    }

    pub(crate) fn note_background_local_answer(&mut self) {
        self.counters.background_local_answered =
            self.counters.background_local_answered.wrapping_add(1);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit(
        &mut self,
        packet: &[u8],
        client: Client,
        group: GroupId,
        flags: Flags,
        scope: Scope,
        now: i64,
        random: &mut impl Random,
    ) -> Result<Submission, SubmitError> {
        let header = Header::parse(packet)?;
        if header.opcode() != 0
            || header.flags & 0x8000 != 0
            || header.answers != 0
            || header.authorities != 0
        {
            return Err(SubmitError::NotQuery);
        }
        let question = Question::parse(packet)?;
        let key = Key {
            name: question.name.canonical_wire(),
            rrtype: question.rrtype,
            class: question.class,
            flags,
            scope: canonical_scope(scope),
        };
        if let Some(&id) = self.keys.get(&key) {
            let forward = self.pending.get_mut(&id).unwrap();
            if age(now, forward.created) < ABSOLUTE_TIMEOUT {
                if let Some(recipient) = forward.recipients.iter_mut().find(|r| {
                    r.original_id == header.id && same_endpoint(r.client.source, client.source)
                }) {
                    // The C retry updates log identity only; case, size, route and
                    // listening FD remain those of the first request from this source.
                    recipient.client.log_id = client.log_id;
                    return Ok(Submission {
                        id,
                        kind: SubmissionKind::ClientRetry,
                    });
                }
                if self.extra_clients >= self.options.forward_max {
                    if age(now, forward.created) >= QUERY_TIMEOUT {
                        self.remove(id, ReleaseReason::Expired);
                    }
                    return Err(SubmitError::DuplicateFull);
                }
                forward.recipients.insert(
                    1,
                    Recipient {
                        client,
                        original_id: header.id,
                        question_name: question.name,
                    },
                );
                self.extra_clients += 1;
                return Ok(Submission {
                    id,
                    kind: if age(now, forward.created) < 2 {
                        SubmissionKind::Coalesced
                    } else {
                        SubmissionKind::LateDuplicate
                    },
                });
            }
        }
        // Match get_new_frec's absolute collection before its per-group count.
        let expired: Vec<_> = self
            .pending
            .values()
            .filter(|p| age(now, p.created) >= ABSOLUTE_TIMEOUT)
            .map(|p| p.id)
            .collect();
        for id in expired {
            self.reclaim_unanswered(id);
        }
        if self
            .pending
            .values()
            .filter(|p| p.group == group && age(now, p.created) < QUERY_TIMEOUT)
            .count()
            >= self.options.forward_max
        {
            return Err(SubmitError::GroupFull);
        }
        // C reuses its oldest >= TIMEOUT frec only if it has no free record.
        // This table drops freed records, so preserve its allocation high-water
        // behavior separately from active count using the slot high-water mark.
        let slot = self.allocate_slot(now);
        if self.ids.len() == 65536 {
            return Err(SubmitError::IdSpaceFull);
        }
        let upstream_id = loop {
            let candidate = random.next_u32().map_err(SubmitError::Random)? as u16;
            if !self.ids.contains_key(&candidate) {
                break candidate;
            }
        };
        let bitmap = if self.options.case_randomization {
            random.next_u32().map_err(SubmitError::Random)?
        } else {
            0
        };
        let mut packet = packet.to_vec();
        packet[..2].copy_from_slice(&upstream_id.to_be_bytes());
        flip_question_case(&mut packet, &[bitmap])?;
        let upstream_question = Question::parse(&packet)?;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("forward generation exhausted");
        let id = QueryId(self.next_id);
        let forward = Pending {
            id,
            group,
            question: upstream_question,
            flags,
            created: now,
            upstream_id,
            packet,
            recipients: vec![Recipient {
                client,
                original_id: header.id,
                question_name: question.name,
            }],
            sent_to: None,
            forward_all: 0,
            last_sent_ms: 0,
            retry_delay_ms: self.options.fast_retry_ms,
            key: key.clone(),
            sockets: Vec::new(),
            slot,
        };
        self.keys.insert(key, id);
        self.ids.insert(upstream_id, id);
        self.pending.insert(id, forward);
        self.slots[slot] = Some(id);
        Ok(Submission {
            id,
            kind: SubmissionKind::New,
        })
    }

    fn allocate_slot(&mut self, now: i64) -> usize {
        if let Some(slot) = self.slots.iter().position(Option::is_none) {
            return slot;
        }
        if let Some(oldest) = self.pending.values().min_by_key(|p| (p.created, p.slot)) {
            if age(now, oldest.created) >= QUERY_TIMEOUT {
                let slot = oldest.slot;
                let id = oldest.id;
                self.reclaim_unanswered(id);
                return slot;
            }
        }
        self.slots.push(None);
        self.slots.len() - 1
    }

    pub fn note_sent(
        &mut self,
        id: QueryId,
        server: ServerId,
        socket: SocketToken,
        now_ms: u32,
    ) -> bool {
        let Some(forward) = self.pending.get_mut(&id) else {
            return false;
        };
        forward.sent_to = Some(server);
        if !forward.sockets.contains(&socket) {
            forward.sockets.push(socket);
        }
        forward.last_sent_ms = now_ms;
        if forward.forward_all != 0 {
            forward.forward_all = forward.forward_all.saturating_add(1);
        }
        true
    }

    pub fn set_forward_all(&mut self, id: QueryId, count: u32) -> bool {
        let Some(forward) = self.pending.get_mut(&id) else {
            return false;
        };
        forward.forward_all = count;
        true
    }

    pub fn plan(
        &mut self,
        id: QueryId,
        group: &mut ServerGroup,
        reason: SendReason,
        now: i64,
    ) -> Option<SendPlan> {
        let forward = self.pending.get_mut(&id)?;
        if forward.group != group.id {
            return None;
        }
        Some(group.plan(forward, reason, now))
    }

    /// Match the response name/type/class/ID, socket ownership and upstream
    /// endpoint within the selected server group. Group-bound sockets can be
    /// supplied by the caller even when not randomly allocated for this query.
    pub fn accept_reply(
        &self,
        packet: &[u8],
        source: SocketAddr,
        socket: SocketToken,
        group: &ServerGroup,
        now: i64,
    ) -> Option<(QueryId, ServerId)> {
        let header = Header::parse(packet).ok()?;
        if header.flags & 0x8000 == 0 {
            return None;
        }
        let id = *self.ids.get(&header.id)?;
        let forward = self.pending.get(&id)?;
        if forward.sent_to.is_none()
            || forward.group != group.id
            || age(now, forward.created) >= ABSOLUTE_TIMEOUT
        {
            return None;
        }
        let question = Question::parse(packet).ok()?;
        if question.rrtype != forward.question.rrtype || question.class != forward.question.class {
            return None;
        }
        if self.options.case_randomization {
            if question.name != forward.question.name {
                return None;
            }
        } else if !question.name.eq_ignore_ascii_case(&forward.question.name) {
            return None;
        }
        if !forward.sockets.contains(&socket)
            && !group.servers.iter().any(|s| s.bound_socket == Some(socket))
        {
            return None;
        }
        let server = group
            .servers
            .iter()
            .find(|s| same_endpoint(s.address, source))?;
        Some((id, server.id))
    }

    /// Invoke only after accept_reply and caller-owned ignore-address checks.
    pub fn on_reply(&mut self, id: QueryId, server: ServerId, rcode: u8) -> Option<ReplyAction> {
        let forward = self.pending.get_mut(&id)?;
        if matches!(rcode, 2 | 5) && forward.forward_all == 0 {
            return Some(ReplyAction::Retry);
        }
        if forward.forward_all != 0 {
            forward.forward_all -= 1;
            if forward.forward_all > 1 && rcode == 5 {
                return Some(ReplyAction::Wait);
            }
        }
        forward.sent_to = Some(server);
        // Actual completion happens after reply processing; close random sockets
        // now, as C does before process_reply and per-client fanout.
        self.released.push(Released {
            id,
            sockets: std::mem::take(&mut forward.sockets),
            reason: ReleaseReason::Completed,
        });
        Some(ReplyAction::Deliver)
    }

    pub fn finish(&mut self, id: QueryId) -> Option<Pending> {
        self.remove(id, ReleaseReason::Completed)
    }
    pub fn cancel(&mut self, id: QueryId) -> Option<Pending> {
        self.remove(id, ReleaseReason::Cancelled)
    }

    pub fn server_gone(&mut self, server: ServerId) {
        let ids: Vec<_> = self
            .pending
            .values()
            .filter(|p| p.sent_to == Some(server))
            .map(|p| p.id)
            .collect();
        for id in ids {
            self.remove(id, ReleaseReason::ServerGone);
        }
    }

    /// C frecs retain a server pointer, whose current domain tier is looked
    /// up after server-array rebuilding. Reflect that without resetting IDs,
    /// deadlines, retries, recipients or the table's counters.
    pub fn rebind_groups(&mut self, groups: &HashMap<ServerId, GroupId>) {
        for pending in self.pending.values_mut() {
            if let Some(group) = pending.sent_to.and_then(|server| groups.get(&server)) {
                pending.group = *group;
            }
        }
    }

    /// Due records are not mutated: after each actual send call retry_finished.
    /// Unsigned wrapping subtraction follows dnsmasq's u32 millisecond clock.
    pub fn fast_retries(&self, now: i64, now_ms: u32) -> RetrySchedule {
        let mut result = RetrySchedule {
            due: Vec::new(),
            next_ms: None,
        };
        if self.options.fast_retry_ms == 0 {
            return result;
        }
        // C walks allocated frecs newest-slot first, including when older
        // slots are reused. Walking the existing slot list preserves that
        // order without sorting an independently collected due list.
        for id in self.slots.iter().rev().flatten() {
            let forward = &self.pending[id];
            if forward.sent_to.is_none()
                || age(now, forward.created) >= self.options.fast_retry_timeout_s
            {
                continue;
            }
            let elapsed = now_ms.wrapping_sub(forward.last_sent_ms) as i32;
            let remaining = i64::from(forward.retry_delay_ms) - i64::from(elapsed);
            if remaining <= 0 {
                result.due.push(forward.id);
            } else {
                result.next_ms = Some(
                    result
                        .next_ms
                        .unwrap_or(u32::MAX)
                        .min(remaining.min(u32::MAX as i64) as u32),
                );
            }
        }
        result
    }

    pub fn retry_finished(&mut self, id: QueryId) {
        if let Some(forward) = self.pending.get_mut(&id) {
            // Avoid C signed multiplication overflow for extreme user settings.
            forward.retry_delay_ms = forward
                .retry_delay_ms
                .saturating_mul(2)
                .min(i32::MAX as u32);
        }
    }

    fn reclaim_unanswered(&mut self, id: QueryId) {
        if self
            .remove(id, ReleaseReason::Expired)
            .is_some_and(|pending| pending.sent_to.is_some())
        {
            self.counters.unanswered = self.counters.unanswered.wrapping_add(1);
        }
    }

    fn remove(&mut self, id: QueryId, reason: ReleaseReason) -> Option<Pending> {
        let mut forward = self.pending.remove(&id)?;
        self.slots[forward.slot] = None;
        self.ids.remove(&forward.upstream_id);
        if self.keys.get(&forward.key) == Some(&id) {
            self.keys.remove(&forward.key);
        }
        self.extra_clients -= forward.recipients.len() - 1;
        self.released.push(Released {
            id,
            sockets: std::mem::take(&mut forward.sockets),
            reason,
        });
        Some(forward)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyAction {
    Retry,
    Wait,
    Deliver,
}
#[derive(Debug)]
pub struct RetrySchedule {
    pub due: Vec<QueryId>,
    pub next_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Server {
    pub id: ServerId,
    pub address: SocketAddr,
    pub bound_socket: Option<SocketToken>,
}

#[derive(Debug)]
pub struct ServerGroup {
    pub id: GroupId,
    pub servers: Vec<Server>,
    pub strict_order: bool,
    pub all_servers: bool,
    last_server: Option<ServerId>,
    forward_count: u32,
    forward_time: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendReason {
    New,
    ClientRetry,
    LateDuplicate,
    UpstreamError,
    FastRetry,
}
#[derive(Debug)]
pub struct SendPlan {
    pub candidates: Vec<ServerId>,
    pub send_all: bool,
    pub exhausted: bool,
}

impl ServerGroup {
    pub fn preferred_server(&self) -> Option<ServerId> {
        self.last_server
    }

    pub fn new(id: GroupId, servers: Vec<Server>, strict_order: bool, all_servers: bool) -> Self {
        Self {
            id,
            servers,
            strict_order,
            all_servers,
            last_server: None,
            forward_count: 0,
            forward_time: 0,
        }
    }

    /// Send candidates in order until one succeeds, or all when send_all is set.
    /// Call note_sent only after a successful send. If no candidate succeeds,
    /// cancel the transaction and let the caller create the C-equivalent error.
    pub fn plan(&mut self, forward: &mut Pending, reason: SendReason, now: i64) -> SendPlan {
        let mut start = 0;
        if self.servers.is_empty() {
            return SendPlan {
                candidates: Vec::new(),
                send_all: false,
                exhausted: true,
            };
        }
        if reason == SendReason::New {
            forward.forward_all = u32::from(self.all_servers);
            if !self.strict_order {
                let old_count = self.forward_count;
                self.forward_count = self.forward_count.wrapping_add(1);
                if old_count > 50 || age(now, self.forward_time) > 20 || self.last_server.is_none()
                {
                    self.forward_time = now;
                    self.forward_count = 0;
                    forward.forward_all = 1;
                } else {
                    start = self.position(self.last_server).unwrap_or(0);
                }
            }
        } else if !self.strict_order
            && matches!(reason, SendReason::ClientRetry | SendReason::UpstreamError)
        {
            forward.forward_all = 1;
        } else {
            start = self.position(forward.sent_to).unwrap_or(0);
            if self.strict_order && reason != SendReason::FastRetry {
                start += 1;
                if start == self.servers.len() {
                    if reason == SendReason::UpstreamError {
                        return SendPlan {
                            candidates: Vec::new(),
                            send_all: forward.forward_all != 0,
                            exhausted: true,
                        };
                    }
                    start -= 1;
                }
            }
        }
        if forward.forward_all != 0 {
            start = 0;
        }
        SendPlan {
            candidates: self.servers[start..].iter().map(|s| s.id).collect(),
            send_all: forward.forward_all != 0,
            exhausted: false,
        }
    }

    pub fn note_reply(&mut self, server: ServerId, rcode: u8) {
        if rcode != 5 {
            self.last_server = Some(server);
        } else if self.last_server == Some(server) {
            self.last_server = None;
        }
    }

    fn position(&self, id: Option<ServerId>) -> Option<usize> {
        self.servers.iter().position(|s| Some(s.id) == id)
    }
}

fn age(now: i64, then: i64) -> i64 {
    now.saturating_sub(then)
}

pub fn same_endpoint(a: SocketAddr, b: SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(a), SocketAddr::V4(b)) => a == b,
        (SocketAddr::V6(a), SocketAddr::V6(b)) => {
            a.ip() == b.ip() && a.port() == b.port() && a.scope_id() == b.scope_id()
        }
        _ => false,
    }
}

fn canonical_scope(scope: Scope) -> Scope {
    match scope {
        Scope::Client(SocketAddr::V6(mut address)) => {
            address.set_flowinfo(0);
            Scope::Client(SocketAddr::V6(address))
        }
        other => other,
    }
}

/// Flip the first bitmap.len()*32 ASCII letters, LSB first; other bytes and
/// label lengths do not consume bits. Decode first to make failure atomic.
pub fn flip_question_case(packet: &mut [u8], bitmap: &[u32]) -> Result<(), WireError> {
    let may_alias = validate_name_may_alias(packet, HEADER_LEN)?;
    let mut letter = 0;
    visit_label_bytes(packet, may_alias, |byte| {
        if byte.is_ascii_alphabetic() {
            if bitmap
                .get(letter / 32)
                .is_some_and(|word| word & (1 << (letter % 32)) != 0)
            {
                *byte ^= 0x20;
            }
            letter += 1;
        }
    })
}

fn restore_name_case(packet: &mut [u8], original: &Name, upstream: &Name) -> Result<(), WireError> {
    let (current, _, may_alias) = decode_name_with_aliasing(packet, HEADER_LEN, 0)?;
    if !current.eq_ignore_ascii_case(original) || !upstream.eq_ignore_ascii_case(original) {
        return Err(WireError::InvalidName);
    }
    let original = original.as_wire();
    let upstream = upstream.as_wire();
    let mut offset = 1;
    let mut left = original[0] as usize;
    visit_label_bytes(packet, may_alias, |byte| {
        if left == 0 {
            left = original[offset] as usize;
            offset += 1;
        }
        *byte ^= original[offset] ^ upstream[offset];
        offset += 1;
        left -= 1;
    })
}

/// Forward-only name traversal cannot revisit modified bytes. A backward
/// pointer may alias its own encoding, so stage those changes before writing.
fn visit_label_bytes(
    packet: &mut [u8],
    may_alias: bool,
    mut action: impl FnMut(&mut u8),
) -> Result<(), WireError> {
    if may_alias {
        return visit_aliased_label_bytes(packet, action);
    }
    let mut at = HEADER_LEN;
    loop {
        let length = packet[at];
        at += 1;
        match length {
            0 => return Ok(()),
            1..=63 => {
                for byte in &mut packet[at..at + length as usize] {
                    action(byte);
                }
                at += length as usize;
            }
            192..=255 => at = (((length & 63) as usize) << 8) | packet[at] as usize,
            _ => unreachable!("decode_name validated label type"),
        }
    }
}

#[inline(never)]
fn visit_aliased_label_bytes(
    packet: &mut [u8],
    mut action: impl FnMut(&mut u8),
) -> Result<(), WireError> {
    // Validation bounds expanded labels to 255 bytes and pointer hops to 255.
    // Question traversal starts at byte 12; every later target is 14 bits, so
    // every visited byte also fits u16. Keep the bounded scratch on the stack
    // in this separate frame, including for valid backward-compressed names.
    let mut changes = [(0u16, 0u8); super::wire::MAX_NAME_LEN];
    let mut change_count = 0;
    let mut pointer_offsets = [0u16; 255];
    let mut pointer_count = 0;
    let mut at = HEADER_LEN;
    loop {
        let length = packet[at];
        at += 1;
        match length {
            0 => break,
            1..=63 => {
                for (index, &original) in
                    packet.iter().enumerate().skip(at).take(usize::from(length))
                {
                    let offset = u16::try_from(index).expect("validated name position fits u16");
                    if let Some((_, byte)) = changes[..change_count]
                        .iter_mut()
                        .find(|(old, _)| *old == offset)
                    {
                        action(byte);
                    } else {
                        let mut byte = original;
                        action(&mut byte);
                        if byte != original {
                            changes[change_count] = (offset, byte);
                            change_count += 1;
                        }
                    }
                }
                at += usize::from(length);
            }
            192..=255 => {
                // Case changes cannot alter length bytes or a pointer's high
                // byte. Its low byte may also be an ASCII label elsewhere.
                pointer_offsets[pointer_count] =
                    u16::try_from(at).expect("validated compression pointer position fits u16");
                pointer_count += 1;
                at = (usize::from(length & 63) << 8) | usize::from(packet[at]);
            }
            _ => unreachable!("name validation checked every encoded label"),
        }
    }
    if changes[..change_count].iter().any(|(index, byte)| {
        *byte != packet[usize::from(*index)] && pointer_offsets[..pointer_count].contains(index)
    }) {
        return Err(WireError::InvalidName);
    }
    for &(index, byte) in &changes[..change_count] {
        packet[usize::from(index)] = byte;
    }
    Ok(())
}

#[cfg(test)]
#[path = "forward_tests.rs"]
mod tests;
