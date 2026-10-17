//! Nonblocking UDP transport for the forwarding dispatcher.
//!
//! Standalone calls can use fixed monotonic deadlines. The daemon uses C's
//! forwarding-table lifetime: wall-clock reply validity and lazy reclamation
//! on new admission. Fixed source sockets belong to the daemon; random pool
//! sockets hold one reference per transaction and close after their final
//! owner releases them. Temporary overflow sockets remain unshared. Receive
//! errors alone retain the transaction. Packets are **unchecked
//! by process_reply policy**: callers must apply address/rebind/cache/EDNS and
//! OpenWrt policies before replying to clients. Integrated TCP fallback is not
//! wired here; [`tcp_exchange`] is a standalone one-query helper below.

#[path = "source_sockets.rs"]
pub mod source_sockets;
use super::forward::{
    Client, Flags, GroupId, QueryId, Random, Recipient, ReleaseReason, ReplyAction, Scope,
    SendPlan, ServerGroup, ServerId, SocketToken, Submission, ABSOLUTE_TIMEOUT,
};
use super::forward_service::{DispatchError, ForwardDispatcher};
use super::wire::{Header, Name, WireError};
use dnsmasq_platform::poll::{PollFd, POLLERR, POLLHUP, POLLIN};
use source_sockets::{SocketSettings, SourceSocketDiagnostic, SourceSpec};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RECEIVE_BUDGET: usize = 16;
const POLLNVAL: i16 = 0x20;
const EMPTY_ERROR_RETRY: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// Bounded standalone/test transport; independent of wall-clock changes.
    Fixed(Duration),
    /// C lookup_frec/get_new_frec own reply validity and slot reclamation.
    ForwardTable,
}

impl Lifetime {
    fn wait_budget(self) -> Duration {
        match self {
            Self::Fixed(timeout) => timeout,
            Self::ForwardTable => Duration::from_secs(ABSOLUTE_TIMEOUT as u64),
        }
    }

    fn fixed(self) -> bool {
        matches!(self, Self::Fixed(_))
    }
}

#[derive(Debug)]
pub enum ResolveError {
    Dispatch(DispatchError),
    Wire(WireError),
    Io(io::Error),
    Timeout,
    NoServer,
    /// A synchronous call must not consume another caller's asynchronous work.
    Busy,
    /// This transport owns random-port sockets; server-bound sockets need the
    /// daemon's socket allocator and are explicitly outside this adapter.
    BoundSocketUnsupported,
    Released(ReleaseReason),
}

impl From<DispatchError> for ResolveError {
    fn from(value: DispatchError) -> Self {
        Self::Dispatch(value)
    }
}
impl From<WireError> for ResolveError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}
impl From<io::Error> for ResolveError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Errors from the standalone upstream DNS-over-TCP exchange helper.
///
/// This helper deliberately owns one short-lived connection and one query;
/// it is not yet connected to the UDP transaction state machine or TCP
/// fallback policy.
#[derive(Debug)]
pub enum TcpExchangeError {
    Io(io::Error),
    Wire(WireError),
    InvalidQuery,
    PeerMismatch {
        expected: SocketAddr,
        actual: SocketAddr,
    },
    EmptyResponse,
    ResponseTooLarge {
        length: usize,
        maximum: usize,
    },
    ResponseMismatch,
}

impl From<io::Error> for TcpExchangeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<WireError> for TcpExchangeError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

/// Execute one DNS-over-TCP query against `server`.
///
/// The wire length prefix and payload are written completely, the response is
/// bounded before its body is read, and the response ID, QR bit and question
/// are authenticated against the submitted query. `timeout` applies to
/// connect, read and write operations. A caller that needs C's persistent
/// `server->tcpfd`/retry behaviour must add that state machine around this
/// helper; this function intentionally opens and closes one connection.
pub fn tcp_exchange(
    server: SocketAddr,
    query: &[u8],
    timeout: Duration,
    max_response: usize,
) -> Result<Vec<u8>, TcpExchangeError> {
    if query.len() > u16::MAX as usize {
        return Err(TcpExchangeError::InvalidQuery);
    }
    let query_header = Header::parse(query)?;
    if query_header.flags & 0x8000 != 0
        || query_header.opcode() != 0
        || query_header.answers != 0
        || query_header.authorities != 0
        || query_header.additionals != 0
    {
        return Err(TcpExchangeError::InvalidQuery);
    }
    let question = super::forward::Question::parse(query)?;
    let mut stream = std::net::TcpStream::connect_timeout(&server, timeout)?;
    let actual = stream.peer_addr()?;
    if actual != server {
        return Err(TcpExchangeError::PeerMismatch {
            expected: server,
            actual,
        });
    }
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let length = (query.len() as u16).to_be_bytes();
    stream.write_all(&length)?;
    stream.write_all(query)?;

    let mut response_length = [0; 2];
    stream.read_exact(&mut response_length)?;
    let length = usize::from(u16::from_be_bytes(response_length));
    if length == 0 {
        return Err(TcpExchangeError::EmptyResponse);
    }
    let maximum = max_response.min(u16::MAX as usize);
    if length > maximum {
        return Err(TcpExchangeError::ResponseTooLarge { length, maximum });
    }
    let mut response = vec![0; length];
    stream.read_exact(&mut response)?;
    let response_header = Header::parse(&response)?;
    let response_question = super::forward::Question::parse(&response)?;
    if response_header.id != query_header.id
        || response_header.flags & 0x8000 == 0
        || !response_question.name.eq_ignore_ascii_case(&question.name)
        || response_question.rrtype != question.rrtype
        || response_question.class != question.class
    {
        return Err(TcpExchangeError::ResponseMismatch);
    }
    Ok(response)
}

/// The ID, question, socket and upstream endpoint matched a pending query.
/// No claim is made about answer RDATA, rebind policy, subnet options, cache
/// insertion or the client-visible packet. In particular, this packet retains
/// the upstream ID/case/OPT until the caller performs reply processing.
#[derive(Debug)]
pub struct UncheckedReply {
    pub packet: Vec<u8>,
    /// Move the already-owned upstream question here for relative case restoration.
    pub upstream_name: Name,
    /// Whether the authenticated UDP response carried DNS header TC.
    ///
    /// The exact OpenWrt `nodhcpv6` build has no `HAVE_DNSSEC`, so C returns
    /// this response downstream with TC set.  Keeping the classification at
    /// the transport boundary lets a future DNSSEC-enabled caller request
    /// TCP without treating a valid truncated response as an upstream error.
    pub truncated: bool,
    pub server: ServerId,
    pub flags: Flags,
    /// Cache metadata support for the first query in this forwarding group.
    /// This is deliberately separate from C's duplicate-matching flags.
    pub cache_eligible: bool,
    pub recipients: Vec<Recipient>,
}

/// Classify the DNS header's truncation bit after source/ID/question
/// authentication.  This helper deliberately does not alter forwarding
/// state: ordinary `nodhcpv6` callers deliver a truncated UDP response, while
/// a DNSSEC-enabled caller may use the result to start a separate TCP query.
pub fn udp_reply_is_truncated(packet: &[u8]) -> Result<bool, WireError> {
    Ok(Header::parse(packet)?.flags & 0x0200 != 0)
}

#[derive(Debug)]
pub struct UpstreamEvent {
    pub id: QueryId,
    pub result: Result<UncheckedReply, ResolveError>,
}

/// OS randomness is opened once per transport; failures propagate before a
/// query can be sent with a predictable ID.
pub struct OsRandom(File);
impl OsRandom {
    pub fn new() -> io::Result<Self> {
        File::open("/dev/urandom").map(Self)
    }
}
impl Random for OsRandom {
    fn next_u32(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.0.read_exact(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }
}

/// C server counters retained for the SIGUSR1 operational dump. They follow
/// live server IDs, so replacing a resolver does not inherit retired totals.
#[derive(Clone, Copy, Default)]
pub(crate) struct ServerCounters {
    pub queries: u32,
    pub retries: u32,
    pub failed: u32,
    pub nxdomain: u32,
    pub latency: u32,
    moving_latency: u32,
}

struct Transaction {
    deadline: Instant,
    sockets: HashMap<ServerId, SocketToken>,
    tokens: Vec<SocketToken>,
}

#[derive(Clone, Copy)]
struct SavedUdpQuery {
    server: ServerId,
    socket: SocketToken,
    destination: SocketAddr,
}
struct OwnedSocket {
    owners: HashSet<QueryId>,
    probe_refs: usize,
    source: SourceSpec,
    persistent: bool,
    pooled: bool,
    pool_slot: Option<usize>,
    origin: Option<ServerId>,
    pinned: bool,
    socket: UdpSocket,
    // First empty POLLERR records `now` without delay. A repeated readiness
    // with neither SO_ERROR nor a datagram schedules one bounded retry.
    empty_error_retry: Option<Instant>,
}

impl OwnedSocket {
    fn pollable_at(&self, now: Instant) -> bool {
        self.empty_error_retry.is_none_or(|retry| retry <= now)
    }
}

/// An event-driven UDP transport with a single-query convenience wrapper.
/// It neither delivers client responses nor performs automatic TCP fallback.
/// Query/socket counts are observable for resource tests; the dispatcher is
/// read-only to callers so transactions cannot bypass socket ownership.
pub struct UpstreamResolver<R = OsRandom> {
    query_logging: crate::config::logging::QueryLogging,
    query_events: Vec<(
        crate::query_logging::QueryContext,
        crate::query_logging::QueryEvent,
    )>,
    #[cfg(target_os = "linux")]
    dump: crate::dump::DumpHandle,
    dispatcher: ForwardDispatcher,
    random: R,
    transactions: HashMap<QueryId, Transaction>,
    sockets: HashMap<SocketToken, OwnedSocket>,
    events: VecDeque<UpstreamEvent>,
    lifetime: Lifetime,
    clock_origin: Instant,
    next_socket: u64,
    receive_buffer: Vec<u8>,
    poll_tokens: Vec<SocketToken>,
    poll_fds: Vec<PollFd>,
    socket_settings: SocketSettings,
    source_bindings: HashMap<ServerId, SourceSpec>,
    server_counters: HashMap<ServerId, ServerCounters>,
    reply_servers: HashMap<ServerId, SocketAddr>,
    server_sockets: HashMap<ServerId, SocketToken>,
    pool_finger: usize,
    source_diagnostics: VecDeque<SourceSocketDiagnostic>,
    loop_sends: VecDeque<LoopSend>,
    // C's srv_save/fd_save refer to the last successful send only. This
    // metadata is not a socket owner, and a token never aliases a reused fd.
    saved_udp: Option<SavedUdpQuery>,
    saved_udp_packet: Vec<u8>,
}

struct LoopSend {
    token: SocketToken,
    address: SocketAddr,
    packet: [u8; 31],
    deadline: Instant,
}

impl UpstreamResolver<OsRandom> {
    pub fn new(dispatcher: ForwardDispatcher, timeout: Duration) -> io::Result<Self> {
        Self::with_random(dispatcher, OsRandom::new()?, timeout)
    }
}

impl<R: Random> UpstreamResolver<R> {
    pub fn with_random(
        dispatcher: ForwardDispatcher,
        random: R,
        timeout: Duration,
    ) -> io::Result<Self> {
        Self::with_lifetime(dispatcher, random, Lifetime::Fixed(timeout))
    }

    pub fn with_lifetime(
        mut dispatcher: ForwardDispatcher,
        random: R,
        lifetime: Lifetime,
    ) -> io::Result<Self> {
        if lifetime.wait_budget().is_zero() || !dispatcher.table().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport requires a nonzero timeout and an empty dispatcher",
            ));
        }
        if dispatcher
            .take_released()
            .iter()
            .any(|released| !released.sockets.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport cannot adopt caller-owned sockets",
            ));
        }
        let receive_capacity = dispatcher.udp_receive_capacity();
        Ok(Self {
            query_logging: Default::default(),
            query_events: Vec::new(),
            #[cfg(target_os = "linux")]
            dump: Default::default(),
            dispatcher,
            random,
            transactions: HashMap::new(),
            sockets: HashMap::new(),
            events: VecDeque::new(),
            lifetime: match lifetime {
                Lifetime::Fixed(timeout) => {
                    Lifetime::Fixed(timeout.min(Duration::from_secs(ABSOLUTE_TIMEOUT as u64)))
                }
                Lifetime::ForwardTable => Lifetime::ForwardTable,
            },
            clock_origin: Instant::now(),
            next_socket: 0,
            receive_buffer: vec![0; receive_capacity],
            poll_tokens: Vec::new(),
            poll_fds: Vec::new(),
            socket_settings: SocketSettings::default(),
            source_bindings: HashMap::new(),
            server_counters: HashMap::new(),
            reply_servers: HashMap::new(),
            server_sockets: HashMap::new(),
            pool_finger: 0,
            source_diagnostics: VecDeque::new(),
            loop_sends: VecDeque::new(),
            saved_udp: None,
            saved_udp_packet: Vec::new(),
        })
    }

    pub fn dispatcher(&self) -> &ForwardDispatcher {
        &self.dispatcher
    }

    pub(crate) fn random_mut(&mut self) -> &mut R {
        &mut self.random
    }

    /// loop.c borrows the normal source allocator without a forward record,
    /// query metric, dump packet, or reply transaction. Hold each reference
    /// across the whole probe batch, then release it after its actual send.
    pub(crate) fn loop_probe_batch(
        &mut self,
        probes: Vec<super::loop_detect::LoopProbe>,
        startup: bool,
    ) {
        if !probes.is_empty() {
            // loop.c:57 generates a probe in daemon->packet, invalidating
            // the previous ordinary UDP query before attempting its send.
            self.invalidate_udp_resend();
        }
        let mut batch_tokens = Vec::new();
        for probe in probes {
            let super::loop_detect::LoopProbe {
                server,
                address,
                endpoint,
                packet,
            } = probe;
            let mut source = SourceSpec::endpoint(&endpoint, self.socket_settings.query_port);
            if let Some(previous) = self.source_bindings.get(&server) {
                source.ifindex = previous.ifindex;
            }
            // Initial check_servers sends probes before attaching the sfd to
            // each server. A fixed-port socket already allocated at startup
            // makes that initial random_sock bind fail with EADDRINUSE.
            if startup && source.address.port() != 0 && self.server_sockets.contains_key(&server) {
                continue;
            }
            let compatible: Vec<_> = batch_tokens
                .iter()
                .copied()
                .filter(|token| {
                    self.sockets
                        .get(token)
                        .is_some_and(|owned| self.random_source_matches(owned, &source))
                })
                .collect();
            let token = if let Some(token) = self.server_sockets.get(&server).filter(|_| !startup) {
                Ok(*token)
            } else if !compatible.is_empty()
                && compatible.len() as u32 >= self.socket_settings.port_limit
            {
                let token = *compatible.last().unwrap();
                batch_tokens.retain(|old| *old != token);
                batch_tokens.insert(0, token);
                Ok(token)
            } else {
                let pooled = self.sockets.values().filter(|owned| owned.pooled).count();
                let range = u32::from(self.socket_settings.max_port)
                    .saturating_sub(u32::from(self.socket_settings.min_port))
                    + 1;
                let full_range = self.socket_settings.max_port != 0
                    && range < 30
                    && self
                        .sockets
                        .values()
                        .filter(|owned| {
                            owned.pooled
                                && owned.source.address.is_ipv4() == source.address.is_ipv4()
                        })
                        .count()
                        >= range as usize;
                let allocated = (pooled < self.socket_settings.pool_slots && !full_range)
                    .then(|| self.open_socket(source.clone(), false, true).ok())
                    .flatten();
                if let Some(token) = allocated {
                    Ok(token)
                } else {
                    let slots = self.socket_settings.pool_slots;
                    let reusable = self
                        .sockets
                        .iter()
                        .filter(|(token, owned)| {
                            self.random_source_matches(owned, &source)
                                && owned.owners.len() + owned.probe_refs < 0xfffe
                                && !batch_tokens.contains(token)
                        })
                        .min_by_key(|(_, owned)| {
                            (owned.pool_slot.unwrap() + slots - self.pool_finger % slots) % slots
                        })
                        .map(|(token, _)| *token);
                    if let Some(token) = reusable {
                        self.pool_finger = self.sockets[&token].pool_slot.unwrap() + 1;
                        Ok(token)
                    } else {
                        self.open_socket(source, false, false)
                    }
                }
            };
            if let Ok(token) = token {
                if !batch_tokens.contains(&token) {
                    batch_tokens.insert(0, token);
                }
                let owned = self.sockets.get_mut(&token).unwrap();
                if owned.pooled && owned.origin.is_none() {
                    owned.origin = Some(server);
                }
                owned.probe_refs += 1;
                self.loop_sends.push_back(LoopSend {
                    token,
                    address,
                    packet,
                    deadline: Instant::now() + Duration::from_secs(1),
                });
            }
        }
        self.step_loop_probes();
    }

    fn step_loop_probes(&mut self) {
        for _ in 0..self.loop_sends.len().min(128) {
            let probe = self.loop_sends.pop_front().unwrap();
            let Some(socket) = self.sockets.get_mut(&probe.token) else {
                continue;
            };
            let result = socket.socket.send_to(&probe.packet, probe.address);
            if Instant::now() < probe.deadline
                && result.as_ref().is_err_and(|error| {
                    matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    )
                })
            {
                self.loop_sends.push_back(probe);
            } else {
                socket.probe_refs -= 1;
            }
        }
        self.sockets.retain(|token, owned| {
            !owned.owners.is_empty()
                || owned.probe_refs != 0
                || owned.persistent
                    && (owned.pinned || self.server_sockets.values().any(|used| used == token))
        });
    }

    pub(crate) fn retained_servers(&self) -> impl Iterator<Item = (ServerId, SocketAddr)> + '_ {
        self.reply_servers.iter().map(|(&id, &address)| (id, address))
    }

    pub(crate) fn server_counters(&self, id: ServerId) -> ServerCounters {
        self.server_counters.get(&id).copied().unwrap_or_default()
    }

    pub(crate) fn note_reply_rcode(&mut self, server: ServerId, rcode: u16) {
        if rcode == 3 {
            let counters = self.server_counters.entry(server).or_default();
            counters.nxdomain = counters.nxdomain.wrapping_add(1);
        }
    }

    fn note_retry(&mut self, id: QueryId, failed: bool) {
        if let Some(server) = self.dispatcher.table().get(id).and_then(|query| query.sent_to) {
            let counters = self.server_counters.entry(server).or_default();
            let value = if failed { &mut counters.failed } else { &mut counters.retries };
            *value = value.wrapping_add(1);
        }
    }

    pub fn set_query_logging(&mut self, config: crate::config::logging::QueryLogging) {
        self.query_logging = config;
    }

    pub fn take_query_events(
        &mut self,
    ) -> Vec<(
        crate::query_logging::QueryContext,
        crate::query_logging::QueryEvent,
    )> {
        std::mem::take(&mut self.query_events)
    }
    #[cfg(target_os = "linux")]
    pub fn set_dump(&mut self, dump: crate::dump::DumpHandle) {
        self.dump = dump;
    }
    pub fn pending_count(&self) -> usize {
        self.transactions.len()
    }
    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    /// A real caller has overwritten C's shared DNS packet. Retain only the
    /// capacity of this one bounded buffer, never a query or socket owner.
    pub fn invalidate_udp_resend(&mut self) {
        self.saved_udp = None;
        self.saved_udp_packet.clear();
    }

    /// EVENT_NEWROUTE resends only the exact last successful UDP wire on its
    /// original live socket. It does not create a query, record an ordinary
    /// forward/log/dump, change retry state, or retain that socket's lifetime.
    pub fn resend_udp_query(&mut self) {
        self.resend_udp_query_with_io(UdpSocket::send_to, wait_udp_retry);
    }

    fn resend_udp_query_with_io(
        &mut self,
        mut send: impl FnMut(&UdpSocket, &[u8], SocketAddr) -> io::Result<usize>,
        wait: impl FnMut() -> io::Result<()>,
    ) {
        let Some(saved) = self.saved_udp else { return; };
        let Some(owned) = self.sockets.get(&saved.socket) else {
            self.invalidate_udp_resend();
            return;
        };
        // forward.c::server_send ignores terminal send errors. Reuse the
        // existing exact retry_send contract (including its bounded EAGAIN
        // nanosleep boundary); do not add an independent owner send queue.
        let _ = send_udp_with_retry(
            || send(&owned.socket, &self.saved_udp_packet, saved.destination), wait,
        );
    }

    /// Borrow readiness interests without waiting or advancing any query.
    /// None means there are no sockets, timers or queued completions to drive.
    /// Otherwise the supplied deadline remains an upper bound on the wait.
    pub fn append_poll_fds(&self, fds: &mut Vec<PollFd>, deadline: Instant) -> Option<Instant> {
        if self.no_timer_or_socket_work() && self.events.is_empty() {
            return None;
        }
        let now = Instant::now();
        let mut deadline = self.next_wakeup(deadline);
        if !self.events.is_empty() {
            deadline = deadline.min(now);
        }
        for owned in self.sockets.values() {
            if owned.pollable_at(now) {
                fds.push(PollFd {
                    fd: owned.socket.as_raw_fd(),
                    events: POLLIN
                        | if owned.probe_refs != 0 {
                            dnsmasq_platform::poll::POLLOUT
                        } else {
                            0
                        },
                    revents: 0,
                });
            } else if let Some(retry) = owned.empty_error_retry {
                deadline = deadline.min(retry);
            }
        }
        Some(deadline)
    }

    pub fn counters(&self) -> super::forward::ForwardCounters {
        self.dispatcher.table().counters()
    }

    /// Start/merge a UDP query. A duplicate keeps the first query's deadline.
    /// An immediate send failure leaves no transaction or socket behind.
    pub fn start_udp(
        &mut self,
        packet: &[u8],
        client: Client,
        group: GroupId,
        scope: Scope,
    ) -> Result<Submission, ResolveError> {
        self.start_udp_with_metadata(packet, client, group, scope, None)
    }

    /// The containing owner has already decorated this packet while retaining
    /// receive_query's original client envelope and source-dependent cache bit.
    pub fn start_udp_with_metadata(
        &mut self,
        packet: &[u8],
        client: Client,
        group: GroupId,
        scope: Scope,
        metadata: Option<super::forward_service::QueryMetadata>,
    ) -> Result<Submission, ResolveError> {
        self.run_timers();
        // Timers may restore an older stash and save its successful retry.
        // receive_query subsequently restores this new client's packet even
        // if submission rejects it or answers without a successful send.
        self.invalidate_udp_resend();
        let submitted = if let Some(metadata) = metadata {
            self.dispatcher.submit_with_metadata(
                packet,
                client,
                group,
                scope,
                unix_seconds(),
                &mut self.random,
                metadata,
            )
        } else {
            self.dispatcher.submit(
                packet,
                client,
                group,
                scope,
                unix_seconds(),
                &mut self.random,
            )
        };
        // submit may reclaim a different query when its C forwarding slot is
        // reused. Consume its release even if admission of this one failed.
        self.consume_releases();
        let submitted = submitted?;
        let id = submitted.id;
        self.transactions.entry(id).or_insert_with(|| Transaction {
            deadline: Instant::now() + self.lifetime.wait_budget(),
            sockets: HashMap::new(),
            tokens: Vec::new(),
        });
        if let (Some(packet), Some(plan)) = (submitted.packet, submitted.send_plan) {
            self.note_retry(id, false);
            if let Err(error) = self.send_plan(id, &packet, &plan) {
                self.cancel(id);
                return Err(error);
            }
        }
        Ok(Submission {
            id,
            kind: submitted.kind,
        })
    }

    /// Wait up to max_wait, process a bounded batch from every ready socket,
    /// then return all terminal events. EINTR, invalid packets and REFUSED
    /// wait states never restart a query's deadline.
    pub fn poll(&mut self, max_wait: Duration) -> io::Result<Vec<UpstreamEvent>> {
        self.poll_with_filter(max_wait, |_| false)
    }

    /// Poll upstream sockets while allowing the caller to reject a matched
    /// reply before it changes forwarding state.  dnsmasq's `ignore-address`
    /// path deliberately leaves the query pending so a later upstream or
    /// retry can still produce the client-visible result.
    pub fn poll_with_filter<F>(
        &mut self,
        max_wait: Duration,
        ignore: F,
    ) -> io::Result<Vec<UpstreamEvent>>
    where
        F: Fn(&[u8]) -> bool,
    {
        self.poll_with_context_filter(max_wait, |packet, _| ignore(packet))
    }

    /// Admission has matched source/id/question but not consumed the pending
    /// transaction. ECS mismatch must leave it alive for a later valid reply.
    pub fn poll_with_context_filter<F>(
        &mut self,
        max_wait: Duration,
        ignore: F,
    ) -> io::Result<Vec<UpstreamEvent>>
    where
        F: Fn(&[u8], &super::forward::Pending) -> bool,
    {
        if self.no_timer_or_socket_work() {
            self.consume_releases();
            return Ok(self.events.drain(..).collect());
        }
        let call_deadline = Instant::now()
            .checked_add(max_wait)
            .unwrap_or_else(Instant::now);
        // A pending upstream is polled on multiple owner turns. Keep the
        // interest storage, but rebuild its contents and deadlines every time.
        let mut tokens = std::mem::take(&mut self.poll_tokens);
        let mut fds = std::mem::take(&mut self.poll_fds);
        let result = loop {
            self.run_timers();
            if !self.events.is_empty() || (self.transactions.is_empty() && self.sockets.is_empty())
            {
                break Ok(self.events.drain(..).collect());
            }
            tokens.clear();
            fds.clear();
            tokens.reserve_exact(self.sockets.len());
            fds.reserve_exact(self.sockets.len());
            let now = Instant::now();
            let mut deadline = self.next_wakeup(call_deadline);
            for (&token, owned) in &self.sockets {
                if !owned.pollable_at(now) {
                    deadline = deadline.min(owned.empty_error_retry.unwrap());
                    continue;
                }
                tokens.push(token);
                fds.push(PollFd {
                    fd: owned.socket.as_raw_fd(),
                    events: POLLIN
                        | if owned.probe_refs != 0 {
                            dnsmasq_platform::poll::POLLOUT
                        } else {
                            0
                        },
                    revents: 0,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(
                    !remaining.subsec_nanos().is_multiple_of(1_000_000),
                ))
                .min(i32::MAX as u128) as i32;
            match poll_once(&mut fds, millis) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    // poll-wide failures cannot leave hidden pending work.
                    self.clear();
                    break Err(error);
                }
                Ok(_) => {}
            }
            for (&token, fd) in tokens.iter().zip(&fds) {
                if fd.revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL) != 0 {
                    self.receive_ready(token, fd.revents, &ignore);
                }
            }
            self.run_timers();
            // One ready batch per call makes work bounded under continuous
            // input and gives a containing daemon its other work back.
            break Ok(self.events.drain(..).collect());
        };
        tokens.clear();
        fds.clear();
        self.poll_tokens = tokens;
        self.poll_fds = fds;
        result
    }

    /// Expire fixed deadlines and perform only configured fast-retry sends.
    /// A receive timeout by itself never becomes an UpstreamError retry.
    pub fn tick(&mut self) -> Vec<UpstreamEvent> {
        self.run_timers();
        self.events.drain(..).collect()
    }

    /// Cancel one transaction immediately, releasing every owned socket.
    /// Explicit cancellation does not enqueue a terminal event.
    pub fn cancel(&mut self, id: QueryId) -> bool {
        let existed = self.transactions.remove(&id).is_some();
        self.dispatcher.cancel(id);
        self.consume_releases();
        // Also remove a socket allocated before its first failed send, which
        // has not yet acquired a ForwardTable socket reference.
        self.release_owner(id);
        existed
    }

    pub fn clear(&mut self) {
        self.invalidate_udp_resend();
        let ids: Vec<_> = self.transactions.keys().copied().collect();
        for id in ids {
            self.cancel(id);
        }
        self.events.clear();
        self.sockets.clear();
        self.server_sockets.clear();
        self.loop_sends.clear();
    }

    /// Apply file-source changes without reconstructing this resolver. Only
    /// frecs sent to retired C server slots are cancelled. Other random socket
    /// references remain owned until their pending exchange is released.
    pub(crate) fn set_reply_servers(&mut self, servers: Vec<super::forward::Server>) {
        self.reply_servers = servers
            .into_iter()
            .map(|server| (server.id, server.address))
            .collect();
    }

    pub fn replace_server_groups(&mut self, groups: Vec<ServerGroup>, removed: &[ServerId]) {
        if self.saved_udp.is_some_and(|saved| removed.contains(&saved.server)) {
            // server_gone invalidates only the actual retired server record,
            // not another server or a merely excluded routing rule.
            self.invalidate_udp_resend();
        }
        self.dispatcher.replace_groups(groups, removed);
        for id in removed {
            self.server_counters.remove(id);
        }
        for owned in self.sockets.values_mut() {
            if owned.origin.is_some_and(|origin| removed.contains(&origin)) {
                owned.origin = None;
            }
        }
        self.consume_releases();
        // server_gone silently frees frecs; it is not an upstream error or a
        // timeout and must not create a client reply or failure metric.
        self.events.retain(|event| {
            !matches!(
                event.result,
                Err(ResolveError::Released(ReleaseReason::ServerGone))
            )
        });
    }

    /// Convenience wrapper for one UDP query. Busy is returned before any
    /// mutation if asynchronous work or unconsumed events already exist.
    /// The result is still an UncheckedReply, never a client response.
    pub fn resolve_udp(
        &mut self,
        packet: &[u8],
        client: Client,
        group: GroupId,
        scope: Scope,
    ) -> Result<UncheckedReply, ResolveError> {
        if !self.transactions.is_empty() || !self.events.is_empty() {
            return Err(ResolveError::Busy);
        }
        let submission = self.start_udp(packet, client, group, scope)?;
        // The synchronous convenience API always has a bounded wait, even
        // when explicitly built with the daemon's asynchronous C lifetime.
        let deadline = Instant::now() + self.lifetime.wait_budget();
        loop {
            if let Some(event) = self
                .poll(deadline.saturating_duration_since(Instant::now()))?
                .into_iter()
                .next()
            {
                debug_assert_eq!(event.id, submission.id);
                return event.result;
            }
            if Instant::now() >= deadline {
                self.cancel(submission.id);
                return Err(ResolveError::Timeout);
            }
        }
    }

    fn milliseconds(&self) -> u32 {
        self.clock_origin.elapsed().as_millis() as u32
    }

    fn no_timer_or_socket_work(&self) -> bool {
        self.transactions.is_empty()
            && self.sockets.is_empty()
            && self.loop_sends.is_empty()
            && self.dispatcher.table().is_empty()
    }

    fn next_wakeup(&self, mut deadline: Instant) -> Instant {
        for probe in &self.loop_sends {
            deadline = deadline.min(probe.deadline);
        }
        if self.lifetime.fixed() {
            for transaction in self.transactions.values() {
                deadline = deadline.min(transaction.deadline);
            }
        }
        let retry = self
            .dispatcher
            .table()
            .fast_retries(unix_seconds(), self.milliseconds());
        if !retry.due.is_empty() {
            return Instant::now();
        }
        if let Some(millis) = retry.next_ms {
            deadline = deadline.min(Instant::now() + Duration::from_millis(millis.into()));
        }
        deadline
    }

    fn run_timers(&mut self) {
        if !self.loop_sends.is_empty() {
            self.step_loop_probes();
        }
        self.run_timers_at(Instant::now(), unix_seconds(), self.milliseconds());
    }

    fn run_timers_at(&mut self, now: Instant, wall_time: i64, now_ms: u32) {
        if self.lifetime.fixed() {
            let expired: Vec<_> = self
                .transactions
                .iter()
                .filter(|(_, transaction)| now >= transaction.deadline)
                .map(|(&id, _)| id)
                .collect();
            for id in expired {
                self.fail(id, ResolveError::Timeout);
            }
        }
        // Plan the due set once. One bad packet cannot prevent another pending
        // query's retry; each send either advances its delay or fails its own
        // transaction and releases its own sockets.
        let plans = match self.dispatcher.plan_retries(wall_time, now_ms) {
            Ok(plans) => plans,
            Err(error) => {
                let ids: Vec<_> = self.transactions.keys().copied().collect();
                for id in ids {
                    self.fail(id, error.into());
                }
                Vec::new()
            }
        };
        for plan in plans {
            // fast_retry restores each stash into the shared packet before
            // forward_query. Only a new successful send establishes a save.
            self.invalidate_udp_resend();
            self.note_retry(plan.id, false);
            match self.send_plan_without_client(plan.id, &plan.packet, &plan.send_plan) {
                Ok(()) => self.dispatcher.retry_finished(plan.id),
                Err(error) => {
                    if matches!(&error, ResolveError::Io(_)) {
                        // forward_query(fd=-1) counts its terminal NETERR
                        // fallback without replying to any original client.
                        // Receive errors, expiry and failed planning do not.
                        self.dispatcher.note_background_local_answer();
                    }
                    self.fail(plan.id, error);
                }
            }
        }
        self.consume_releases();
    }

    /// Configure before dropping startup privileges. Bind failures are returned
    /// by server ID so check_servers can remove only the affected servers.
    pub fn take_source_diagnostics(&mut self) -> Vec<SourceSocketDiagnostic> {
        if self.source_diagnostics.is_empty() {
            return Vec::new();
        }
        self.source_diagnostics.drain(..).collect()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn has_source_diagnostics(&self) -> bool {
        !self.source_diagnostics.is_empty()
    }

    pub fn socket_settings(&self) -> SocketSettings {
        self.socket_settings
    }

    /// Call at C's enumerate_interfaces boundary, independently of route/file
    /// publication. Wildcard address notifications and SIGHUP do not refresh
    /// this cache; bound-dynamic address changes and parent TCP accepts do.
    pub fn refresh_source_interface_indices(&mut self) {
        for source in self.source_bindings.values_mut() {
            source.refresh_interface_index();
        }
    }

    pub fn configure_source_sockets(
        &mut self,
        settings: SocketSettings,
        mut sources: HashMap<ServerId, SourceSpec>,
    ) -> Vec<(ServerId, io::Error)> {
        // add_update_server does not refresh/reset the cached interface index
        // on slot reuse. enumerate_interfaces owns that separate boundary.
        for (id, source) in &mut sources {
            if let Some(previous) = self.source_bindings.get(id) {
                source.ifindex = previous.ifindex;
            }
        }
        self.socket_settings = settings;
        self.source_bindings = sources;
        self.server_sockets.retain(|id, token| {
            self.source_bindings.contains_key(id) && self.sockets.contains_key(token)
        });
        let mut failures = Vec::new();
        if settings.query_port != 0 {
            for destination in ["0.0.0.0:53", "[::]:53"] {
                let source =
                    SourceSpec::wildcard(destination.parse().unwrap(), settings.query_port);
                if !self
                    .sockets
                    .values()
                    .any(|owned| owned.persistent && owned.source == source)
                {
                    let _ = self.open_socket(source, true, false);
                }
            }
        }
        let mut ordered: Vec<_> = self.source_bindings.clone().into_iter().collect();
        ordered.sort_unstable_by_key(|(id, _)| id.0);
        for (id, source) in ordered {
            // add_update_server preserves a reused server's existing sfd even
            // after its source tuple changes. TCP uses the updated tuple.
            if self.server_sockets.contains_key(&id) {
                continue;
            }
            if settings.persistent(&source) {
                let token = self
                    .sockets
                    .iter()
                    .find(|(_, owned)| owned.persistent && owned.source == source)
                    .map(|(token, _)| *token);
                match token
                    .map(Ok)
                    .unwrap_or_else(|| self.open_socket(source, true, false))
                {
                    Ok(token) => {
                        self.server_sockets.insert(id, token);
                    }
                    Err(error) => failures.push((id, error)),
                }
            }
        }
        self.sockets.retain(|token, owned| {
            !owned.persistent
                || owned.pinned
                || !owned.owners.is_empty()
                || owned.probe_refs != 0
                || self.server_sockets.values().any(|used| used == token)
        });
        failures
    }

    fn open_socket(
        &mut self,
        source: SourceSpec,
        persistent: bool,
        pooled: bool,
    ) -> io::Result<SocketToken> {
        let socket = match source_sockets::udp(&source, self.socket_settings, &mut self.random) {
            Ok(socket) => socket,
            Err(failure) => {
                if !persistent
                    && failure.binding
                    && (!source.address.ip().is_unspecified()
                        || failure.error.raw_os_error() != Some(98))
                {
                    let error = failure
                        .error
                        .raw_os_error()
                        .map(io::Error::from_raw_os_error)
                        .unwrap_or_else(|| {
                            io::Error::new(failure.error.kind(), failure.error.to_string())
                        });
                    self.source_diagnostics
                        .push_back(SourceSocketDiagnostic { source, error });
                }
                return Err(failure.error);
            }
        };
        self.next_socket = self
            .next_socket
            .checked_add(1)
            .ok_or_else(|| io::Error::other("upstream socket token exhausted"))?;
        let token = SocketToken(self.next_socket);
        let pool_slot = pooled.then(|| {
            (0..self.socket_settings.pool_slots)
                .find(|slot| {
                    !self
                        .sockets
                        .values()
                        .any(|owned| owned.pool_slot == Some(*slot))
                })
                .expect("pooled allocation has a free physical slot")
        });
        self.sockets.insert(
            token,
            OwnedSocket {
                owners: HashSet::new(),
                probe_refs: 0,
                pinned: persistent
                    && source.address.ip().is_unspecified()
                    && source.interface.is_empty()
                    && source.address.port() != 0
                    && source.address.port() == self.socket_settings.query_port,
                source,
                persistent,
                pooled,
                pool_slot,
                origin: None,
                socket,
                empty_error_retry: None,
            },
        );
        Ok(token)
    }

    fn socket_for(
        &mut self,
        id: QueryId,
        server: ServerId,
        address: SocketAddr,
    ) -> io::Result<SocketToken> {
        let source = self
            .source_bindings
            .get(&server)
            .cloned()
            .unwrap_or_else(|| SourceSpec::wildcard(address, self.socket_settings.query_port));
        let persistent = self.socket_settings.persistent(&source);
        let compatible: Vec<_> = self.transactions[&id]
            .tokens
            .iter()
            .copied()
            .filter(|token| {
                self.sockets
                    .get(token)
                    .is_some_and(|owned| self.random_source_matches(owned, &source))
            })
            .collect();
        let token = if let Some(token) = self.server_sockets.get(&server) {
            *token
        } else if persistent {
            match self
                .sockets
                .iter()
                .find(|(_, owned)| owned.persistent && owned.source == source)
                .map(|(token, _)| *token)
            {
                Some(token) => token,
                None => self.open_socket(source.clone(), true, false)?,
            }
        } else if !compatible.is_empty()
            && compatible.len() as u32 >= self.socket_settings.port_limit
        {
            // C promotes the last compatible reference to the list head.
            let token = *compatible.last().unwrap();
            let transaction = self.transactions.get_mut(&id).unwrap();
            transaction.tokens.retain(|old| *old != token);
            transaction.tokens.insert(0, token);
            token
        } else {
            let pooled_count = self.sockets.values().filter(|owned| owned.pooled).count();
            let range = u32::from(self.socket_settings.max_port)
                .saturating_sub(u32::from(self.socket_settings.min_port))
                + 1;
            let full_range = self.socket_settings.max_port != 0
                && range < 30
                && self
                    .sockets
                    .values()
                    .filter(|owned| {
                        owned.pooled && owned.source.address.is_ipv4() == source.address.is_ipv4()
                    })
                    .count()
                    >= range as usize;
            let can_pool = pooled_count < self.socket_settings.pool_slots && !full_range;
            let allocated = if can_pool {
                self.open_socket(source.clone(), false, true).ok()
            } else {
                None
            };
            if let Some(token) = allocated {
                token
            } else {
                let slots = self.socket_settings.pool_slots;
                let reusable = self
                    .sockets
                    .iter()
                    .filter(|(token, owned)| {
                        self.random_source_matches(owned, &source)
                            && !owned.owners.contains(&id)
                            && owned.owners.len() < 0xfffe
                            && !compatible.contains(token)
                    })
                    .min_by_key(|(_, owned)| {
                        let slot = owned.pool_slot.expect("pooled socket has a physical slot");
                        (slot + slots - self.pool_finger % slots) % slots
                    })
                    .map(|(token, _)| *token);
                match reusable {
                    Some(token) => {
                        self.pool_finger = self.sockets[&token].pool_slot.unwrap() + 1;
                        token
                    }
                    None => self.open_socket(source.clone(), false, false)?,
                }
            }
        };
        let owned = self.sockets.get_mut(&token).unwrap();
        if owned.pooled && owned.owners.is_empty() {
            owned.origin = Some(server);
        }
        owned.owners.insert(id);
        let transaction = self.transactions.get_mut(&id).unwrap();
        if !transaction.tokens.contains(&token) {
            transaction.tokens.insert(0, token);
        }
        transaction.sockets.insert(server, token);
        Ok(token)
    }

    fn random_source_matches(&self, owned: &OwnedSocket, source: &SourceSpec) -> bool {
        owned.pooled
            && owned.origin.is_some_and(|origin| {
                self.source_bindings.get(&origin).unwrap_or(&owned.source) == source
            })
    }

    fn release_owner(&mut self, id: QueryId) {
        self.sockets.retain(|token, owned| {
            owned.owners.remove(&id);
            !owned.owners.is_empty()
                || owned.probe_refs != 0
                || (owned.persistent
                    && (owned.pinned || self.server_sockets.values().any(|used| used == token)))
        });
        if self.saved_udp.is_some_and(|saved| !self.sockets.contains_key(&saved.socket)) {
            self.invalidate_udp_resend();
        }
    }

    fn fail_socket(&mut self, token: SocketToken, message: &str) {
        let ids = self
            .sockets
            .get(&token)
            .map(|owned| owned.owners.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for id in ids {
            self.fail(id, io::Error::other(message.to_owned()).into());
        }
        self.sockets.remove(&token);
        if self.saved_udp.is_some_and(|saved| saved.socket == token) {
            self.invalidate_udp_resend();
        }
    }

    fn send_plan(
        &mut self,
        id: QueryId,
        packet: &[u8],
        plan: &SendPlan,
    ) -> Result<(), ResolveError> {
        self.send_plan_with_io(id, packet, plan, UdpSocket::send_to, wait_udp_retry)
    }

    fn send_plan_without_client(
        &mut self,
        id: QueryId,
        packet: &[u8],
        plan: &SendPlan,
    ) -> Result<(), ResolveError> {
        self.send_plan_with_source(id, packet, plan, UdpSocket::send_to, wait_udp_retry, false)
    }

    fn send_plan_with_io(
        &mut self,
        id: QueryId,
        packet: &[u8],
        plan: &SendPlan,
        send: impl FnMut(&UdpSocket, &[u8], SocketAddr) -> io::Result<usize>,
        wait: impl FnMut() -> io::Result<()>,
    ) -> Result<(), ResolveError> {
        self.send_plan_with_source(id, packet, plan, send, wait, true)
    }

    fn send_plan_with_source(
        &mut self,
        id: QueryId,
        packet: &[u8],
        plan: &SendPlan,
        mut send: impl FnMut(&UdpSocket, &[u8], SocketAddr) -> io::Result<usize>,
        mut wait: impl FnMut() -> io::Result<()>,
        include_client: bool,
    ) -> Result<(), ResolveError> {
        if plan.exhausted || plan.candidates.is_empty() {
            return Err(ResolveError::NoServer);
        }
        let group_id = self
            .dispatcher
            .table()
            .get(id)
            .ok_or(ResolveError::Timeout)?
            .group;
        let mut last_error = ResolveError::NoServer;
        let mut sent = false;
        for &server in &plan.candidates {
            let Some(address) = self
                .dispatcher
                .group(group_id)
                .and_then(|group| {
                    group
                        .servers
                        .iter()
                        .find(|candidate| candidate.id == server)
                })
                .map(|server| server.address)
            else {
                continue;
            };
            let token = match self.socket_for(id, server, address) {
                Ok(token) => token,
                Err(error) => {
                    last_error = error.into();
                    continue;
                }
            };
            let result = send_udp_with_retry(
                || send(&self.sockets[&token].socket, packet, address),
                &mut wait,
            );
            match result {
                Ok(length) if length == packet.len() => {
                    let counters = self.server_counters.entry(server).or_default();
                    counters.queries = counters.queries.wrapping_add(1);
                    self.saved_udp_packet.clear();
                    self.saved_udp_packet.extend_from_slice(packet);
                    self.saved_udp = Some(SavedUdpQuery { server, socket: token, destination: address });
                    let pending = self
                        .dispatcher
                        .table()
                        .get(id)
                        .expect("sent query remains pending");
                    let mut context = pending.query_context();
                    // forward.c:472,556: a stale-cache refresh has udpfd=-1
                    // and no client prefix, while retaining its display ID.
                    if !include_client
                        || pending.recipients.first().is_some_and(|recipient| {
                            !recipient.client.reply_requested
                        })
                    {
                        context.client = None;
                    }

                    if self.query_logging.enabled {
                        let mut event = crate::query_logging::QueryEvent::address(
                            crate::query_logging::SERVER,
                            &pending.question.name.dnsmasq_bytes(),
                            address.ip(),
                            None,
                        );
                        event.kind = address.port();
                        self.query_events.push((context, event));
                    }
                    #[cfg(target_os = "linux")]
                    if self.dump.enabled(crate::dump::UP_QUERY) {
                        if let Ok(source) = self.sockets[&token].socket.local_addr() {
                            self.dump.udp_with_context(
                                crate::dump::UP_QUERY,
                                packet,
                                source,
                                address,
                                context,
                            );
                        }
                    }
                    self.dispatcher
                        .note_sent(id, server, token, self.milliseconds());
                    sent = true;
                    if !plan.send_all {
                        break;
                    }
                }
                result => {
                    last_error = match result {
                        Err(error) => error.into(),
                        Ok(_) => {
                            io::Error::new(io::ErrorKind::WriteZero, "partial UDP send").into()
                        }
                    };
                    // Leave a previously referenced socket alive: an older
                    // successful send may still have a reply in flight. An
                    // unsent socket is reclaimed on completion/cancel below.
                }
            }
        }
        if sent {
            self.dispatcher.note_forwarded_action();
            Ok(())
        } else {
            Err(last_error)
        }
    }

    fn receive_ready<F>(&mut self, token: SocketToken, revents: i16, ignore: &F)
    where
        F: Fn(&[u8], &super::forward::Pending) -> bool,
    {
        self.receive_ready_with_io(
            token,
            revents,
            ignore,
            Instant::now(),
            UdpSocket::recv_from,
            UdpSocket::take_error,
        );
    }

    // A private syscall boundary keeps controlled errno tests on real owned
    // sockets. Production calls the standard socket methods directly; no
    // socket options or connect behavior change to manufacture error delivery.
    fn receive_ready_with_io<F, Receive, TakeError>(
        &mut self,
        token: SocketToken,
        revents: i16,
        ignore: &F,
        now: Instant,
        mut receive: Receive,
        mut take_error: TakeError,
    ) where
        F: Fn(&[u8], &super::forward::Pending) -> bool,
        Receive: FnMut(&UdpSocket, &mut [u8]) -> io::Result<(usize, SocketAddr)>,
        TakeError: FnMut(&UdpSocket) -> io::Result<Option<io::Error>>,
    {
        let Some(owned) = self.sockets.get_mut(&token) else {
            return;
        };
        if revents & POLLNVAL != 0 {
            self.fail_socket(token, "invalid upstream socket");
            return;
        }
        if revents & POLLHUP != 0 && revents & POLLIN == 0 {
            self.fail_socket(token, "upstream socket hung up");
            return;
        }
        if !owned.pollable_at(now) {
            return;
        }
        let mut empty_poll_error = false;
        if revents & POLLERR != 0 {
            match take_error(&owned.socket) {
                // Reading SO_ERROR consumes the pending asynchronous error.
                // Retain the transaction so a later retry/reply can complete.
                Ok(Some(_)) => {
                    owned.empty_error_retry = None;
                    if revents & POLLIN == 0 {
                        return;
                    }
                }
                Ok(None) => empty_poll_error = true,
                Err(error) => {
                    self.fail_socket(token, &error.to_string());
                    return;
                }
            }
        } else {
            owned.empty_error_retry = None;
        }
        for _ in 0..RECEIVE_BUDGET {
            let Some(owned) = self.sockets.get_mut(&token) else {
                break;
            };
            let result = receive(&owned.socket, &mut self.receive_buffer);
            let (length, source) = match result {
                Ok(result) => {
                    // Each real datagram replaces C's packet, even when it
                    // later fails ID/source/question/policy admission.
                    self.saved_udp = None;
                    self.saved_udp_packet.clear();
                    empty_poll_error = false;
                    owned.empty_error_retry = None;
                    result
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    self.saved_udp = None;
                    self.saved_udp_packet.clear();
                    continue;
                }
                // C reply_query returns before frec lookup on recvfrom error.
                // End this batch without changing ID, recipients, retry state
                // or deadline. A later POLLNVAL identifies an unusable FD.
                Err(_) => {
                    self.saved_udp = None;
                    self.saved_udp_packet.clear();
                    empty_poll_error = false;
                    owned.empty_error_retry = None;
                    break;
                }
            };
            let Ok(header) = Header::parse(&self.receive_buffer[..length]) else {
                continue;
            };
            let id = self.sockets[&token].owners.iter().copied().find(|id| {
                self.dispatcher
                    .table()
                    .get(*id)
                    .is_some_and(|pending| pending.upstream_id == header.id)
            });
            let Some(id) = id else {
                continue;
            };
            let Some(transaction) = self.transactions.get(&id) else {
                continue;
            };
            if self.lifetime.fixed() && Instant::now() >= transaction.deadline {
                self.fail(id, ResolveError::Timeout);
                continue;
            }
            let Some(pending) = self.dispatcher.table().get(id) else {
                continue;
            };
            let Some(matched) = self
                .dispatcher
                .accept_reply(
                    &self.receive_buffer[..length],
                    source,
                    token,
                    pending.group,
                    unix_seconds(),
                )
                .or_else(|| {
                    // Authenticate current live endpoint, original ID/question and
                    // this transaction's exact socket ownership; routing exclusion
                    // alone does not retire a C server record or its sent query.
                    transaction.sockets.iter().find_map(|(&server, &owned)| {
                        let address = *self.reply_servers.get(&server)?;
                        (owned == token && address == source)
                            .then(|| {
                                self.dispatcher.accept_reply_server(
                                    &self.receive_buffer[..length],
                                    source,
                                    token,
                                    pending.group,
                                    super::forward::Server {
                                        id: server,
                                        address,
                                        bound_socket: Some(token),
                                    },
                                    unix_seconds(),
                                )
                            })
                            .flatten()
                    })
                })
            else {
                continue;
            };
            #[cfg(target_os = "linux")]
            if self.dump.enabled(crate::dump::UP_REPLY) {
                if let Ok(destination) = self.sockets[&token].socket.local_addr() {
                    self.dump.udp_with_context(
                        crate::dump::UP_REPLY,
                        &self.receive_buffer[..length],
                        source,
                        destination,
                        pending.query_context(),
                    );
                }
            }
            // Keep the transaction and its server/retry counters untouched.
            // This must happen after source/ID admission but before
            // `complete_reply`, matching forward.c::reply_query.
            if ignore(&self.receive_buffer[..length], pending) {
                continue;
            }
            let truncated = match udp_reply_is_truncated(&self.receive_buffer[..length]) {
                Ok(truncated) => truncated,
                Err(error) => {
                    self.fail(id, error.into());
                    break;
                }
            };
            match self.dispatcher.complete_reply(matched) {
                Some(ReplyAction::Wait) => {}
                Some(ReplyAction::Retry) => {
                    self.note_retry(id, true);
                    let Some(plan) = self.dispatcher.plan_after_error(id, unix_seconds()) else {
                        break;
                    };
                    // C strict-order exhaustion leaves the query pending until
                    // normal collection; it does not re-send the last error.
                    if !plan.exhausted {
                        match self.dispatcher.upstream_packet(id) {
                            Ok(Some(packet)) => {
                                if let Err(error) = self.send_plan(id, &packet, &plan) {
                                    self.fail(id, error);
                                }
                            }
                            Err(error) => self.fail(id, error.into()),
                            Ok(None) => {}
                        }
                    }
                }
                Some(ReplyAction::Deliver) => {
                    let elapsed = self.milliseconds().wrapping_sub(
                        self.dispatcher.table().get(id).unwrap().last_sent_ms);
                    let counters = self.server_counters.entry(matched.server).or_default();
                    counters.moving_latency = if counters.latency == 0 {
                        elapsed.wrapping_mul(128)
                    } else {
                        counters.moving_latency.wrapping_add(elapsed).wrapping_sub(counters.latency)
                    };
                    counters.latency = counters.moving_latency / 128;
                    let packet = self.receive_buffer[..length].to_vec();
                    let pending = self.dispatcher.finish(id).expect("matched query exists");
                    self.transactions.remove(&id);
                    self.consume_releases();
                    self.release_owner(id);
                    self.events.push_back(UpstreamEvent {
                        id,
                        result: Ok(UncheckedReply {
                            packet,
                            truncated,
                            server: matched.server,
                            flags: pending.flags,
                            cache_eligible: super::forward_service::edns_cache_query(
                                &pending.packet,
                            ),
                            upstream_name: pending.question.name,
                            recipients: pending.recipients,
                        }),
                    });
                }
                None => break,
            }
        }
        if empty_poll_error {
            if let Some(owned) = self.sockets.get_mut(&token) {
                owned.empty_error_retry = Some(if owned.empty_error_retry.is_some() {
                    now + EMPTY_ERROR_RETRY
                } else {
                    now
                });
            }
        }
    }

    fn fail(&mut self, id: QueryId, error: ResolveError) {
        if self.cancel(id) {
            self.events.push_back(UpstreamEvent {
                id,
                result: Err(error),
            });
        }
    }

    fn consume_releases(&mut self) {
        for released in self.dispatcher.take_released() {
            for token in released.sockets {
                if let Some(owned) = self.sockets.get_mut(&token) {
                    owned.owners.remove(&released.id);
                }
                if let Some(transaction) = self.transactions.get_mut(&released.id) {
                    transaction.sockets.retain(|_, old| *old != token);
                    transaction.tokens.retain(|old| *old != token);
                }
            }
            self.release_owner(released.id);
            if self.dispatcher.table().get(released.id).is_none()
                && self.transactions.remove(&released.id).is_some()
            {
                self.release_owner(released.id);
                self.events.push_back(UpstreamEvent {
                    id: released.id,
                    result: Err(ResolveError::Released(released.reason)),
                });
            }
        }
    }
}

fn send_udp_with_retry(
    mut send: impl FnMut() -> io::Result<usize>,
    mut wait: impl FnMut() -> io::Result<()>,
) -> io::Result<usize> {
    let mut retries = 0;
    loop {
        match send() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => retries = 0,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // retry_send waits even on the final failed attempt: 1,001
                // sends/sleeps total, with 1,000 additional send attempts.
                let waited = wait();
                if retries == 1000 {
                    retries = 0;
                    // C checks errno after nanosleep. An interrupted final
                    // wait resets the budget and retries the same server.
                    match waited {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                        Ok(()) => return Err(error),
                    }
                }
                retries += 1;
            }
            result => return result,
        }
    }
}

fn wait_udp_retry() -> io::Result<()> {
    use rustix::thread::NanosleepRelativeResult;
    match rustix::thread::nanosleep(&rustix::time::Timespec { tv_sec: 0, tv_nsec: 10_000 }) {
        NanosleepRelativeResult::Ok => Ok(()),
        NanosleepRelativeResult::Interrupted(_) => Err(rustix::io::Errno::INTR.into()),
        NanosleepRelativeResult::Err(error) => Err(error.into()),
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

use dnsmasq_platform::poll::poll_once;

#[cfg(test)]
#[path = "upstream_owner_wake_tests.rs"]
mod owner_wake_tests;

#[cfg(test)]
#[path = "upstream_route_resend_tests.rs"]
mod route_resend_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::forward::{Options, Server, ServerGroup};
    use crate::dns::wire::{Header, Message, Name, PacketWriter, Section};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    pub(super) struct Counter(u32);
    impl Random for Counter {
        fn next_u32(&mut self) -> io::Result<u32> {
            self.0 += 1;
            Ok(self.0)
        }
    }

    pub(super) fn query() -> Vec<u8> {
        let name = Name::from_ascii("upstream.test").unwrap();
        let mut writer = PacketWriter::new(0x1234, 0x100, 1232).unwrap();
        writer.question(&name, 1, 1).unwrap();
        writer.finish()
    }

    pub(super) fn client() -> Client {
        Client {
            source: "127.0.0.1:53000".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
            listener: None,
            reply_requested: true,
            udp_limit: 512,
            log_id: 1,
        }
    }

    pub(super) fn response(request: &[u8], flags: u16, answer: bool) -> Vec<u8> {
        let header = Header::parse(request).unwrap();
        let name = Name::from_ascii("upstream.test").unwrap();
        let mut writer = PacketWriter::new(header.id, flags, 1232).unwrap();
        writer.question(&name, 1, 1).unwrap();
        if answer {
            writer
                .record(Section::Answer, &name, 1, 1, 20, &[192, 0, 2, 9])
                .unwrap();
        }
        writer.finish()
    }

    fn tcp_frame(packet: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(packet.len() + 2);
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(packet);
        frame
    }

    #[test]
    fn shared_source_socket_demuxes_reverse_order_and_retains_remaining_owner() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let mut resolver = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(2),
        );
        let settings = SocketSettings {
            pool_slots: 1,
            ..SocketSettings::default()
        };
        resolver.configure_source_sockets(settings, HashMap::new());
        let first = resolver
            .start_udp(
                &query(),
                client(),
                GroupId(1),
                Scope::Client("127.0.0.1:1".parse().unwrap()),
            )
            .unwrap();
        let mut buffer = [0; 2048];
        let (length, peer) = server.recv_from(&mut buffer).unwrap();
        let first_reply = response(&buffer[..length], 0x8180, true);
        let second = resolver
            .start_udp(
                &query(),
                client(),
                GroupId(1),
                Scope::Client("127.0.0.1:2".parse().unwrap()),
            )
            .unwrap();
        let (length, second_peer) = server.recv_from(&mut buffer).unwrap();
        assert_eq!(peer, second_peer);
        assert_eq!(resolver.socket_count(), 1);
        server
            .send_to(&response(&buffer[..length], 0x8180, true), peer)
            .unwrap();
        let event = wait_for_event(&mut resolver, Duration::from_millis(10));
        assert_eq!(event.id, second.id);
        assert!(event.result.is_ok());
        assert_eq!((resolver.pending_count(), resolver.socket_count()), (1, 1));
        server.send_to(&first_reply, peer).unwrap();
        assert_eq!(
            wait_for_event(&mut resolver, Duration::from_millis(10)).id,
            first.id
        );
        assert_eq!((resolver.pending_count(), resolver.socket_count()), (0, 0));
    }

    #[test]
    fn unsolicited_fixed_source_packets_are_drained_without_pending_queries() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = peer.local_addr().unwrap();
        let reserved = UdpSocket::bind("127.0.0.1:0").unwrap();
        let source_address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut resolver = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(2),
        );
        resolver.configure_source_sockets(
            SocketSettings::default(),
            HashMap::from([(
                ServerId(1),
                SourceSpec::wildcard(address, source_address.port()),
            )]),
        );
        peer.send_to(&response(&query(), 0x8180, true), source_address)
            .unwrap();
        assert!(resolver.poll(Duration::from_millis(20)).unwrap().is_empty());
        let socket = &resolver.sockets.values().next().unwrap().socket;
        let mut buffer = [0; 2048];
        assert_eq!(
            socket.recv_from(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(resolver.socket_count(), 1);
    }

    #[test]
    fn reused_server_keeps_fixed_socket_after_source_tuple_changes() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let address = peer.local_addr().unwrap();
        let reserved = UdpSocket::bind("127.0.0.1:0").unwrap();
        let old_port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut resolver = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(2),
        );
        let old_source = SourceSpec::wildcard(address, old_port);
        assert!(resolver
            .configure_source_sockets(
                SocketSettings::default(),
                HashMap::from([(ServerId(1), old_source)])
            )
            .is_empty());
        let new_source = SourceSpec {
            address: "127.0.0.9:34004".parse().unwrap(),
            interface: Vec::new(),
            ifindex: 0,
        };
        assert!(resolver
            .configure_source_sockets(
                SocketSettings::default(),
                HashMap::from([(ServerId(1), new_source.clone())])
            )
            .is_empty());
        assert_eq!(resolver.source_bindings[&ServerId(1)], new_source);
        let submission = resolver
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let mut buffer = [0; 2048];
        let (_, source) = peer.recv_from(&mut buffer).unwrap();
        assert_eq!(
            source,
            SocketAddr::new("127.0.0.1".parse().unwrap(), old_port)
        );
        resolver.configure_source_sockets(SocketSettings::default(), HashMap::new());
        assert_eq!(resolver.socket_count(), 1);
        resolver.cancel(submission.id);
        assert_eq!(resolver.socket_count(), 0);
    }

    #[test]
    fn reused_server_preserves_cached_source_index_after_failed_lookup() {
        let address = "127.0.0.2:53".parse().unwrap();
        let mut resolver = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(2),
        );
        let mut source = SourceSpec::wildcard(address, 0);
        source.ifindex = 17;
        source.interface = b"old".to_vec();
        resolver.configure_source_sockets(
            SocketSettings::default(),
            HashMap::from([(ServerId(1), source.clone())]),
        );
        source.ifindex = 0;
        source.interface = b"missing".to_vec();
        resolver.configure_source_sockets(
            SocketSettings::default(),
            HashMap::from([(ServerId(1), source.clone())]),
        );
        assert_eq!(resolver.source_bindings[&ServerId(1)].ifindex, 17);
        source.interface.clear();
        resolver.configure_source_sockets(
            SocketSettings::default(),
            HashMap::from([(ServerId(1), source)]),
        );
        assert_eq!(resolver.source_bindings[&ServerId(1)].ifindex, 17);
    }

    #[test]
    fn interface_cache_refresh_is_separate_from_route_publication() {
        let address = "127.0.0.2:53".parse().unwrap();
        let mut resolver = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(2),
        );
        let mut source = SourceSpec::wildcard(address, 0);
        source.interface = if cfg!(target_os = "linux") {
            b"lo".to_vec()
        } else {
            b"lo0".to_vec()
        };
        source.refresh_interface_index();
        let actual = source.ifindex;
        assert_ne!(actual, 0);
        source.ifindex = actual + 10;
        resolver.configure_source_sockets(
            SocketSettings::default(),
            HashMap::from([(ServerId(1), source.clone())]),
        );
        source.ifindex = actual;
        resolver.configure_source_sockets(
            SocketSettings::default(),
            HashMap::from([(ServerId(1), source)]),
        );
        assert_eq!(resolver.source_bindings[&ServerId(1)].ifindex, actual + 10);
        resolver.refresh_source_interface_indices();
        assert_eq!(resolver.source_bindings[&ServerId(1)].ifindex, actual);
        resolver
            .source_bindings
            .get_mut(&ServerId(1))
            .unwrap()
            .interface = b"missing_endpoint".to_vec();
        resolver.refresh_source_interface_indices();
        assert_eq!(resolver.source_bindings[&ServerId(1)].ifindex, actual);
    }

    #[test]
    fn retired_pool_origin_is_not_shared_while_another_server_keeps_its_owner() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let addresses = [first.local_addr().unwrap(), second.local_addr().unwrap()];
        let mut resolver = transport(
            group(&addresses, true),
            Options::default(),
            Duration::from_secs(2),
        );
        let settings = SocketSettings {
            pool_slots: 1,
            ..SocketSettings::default()
        };
        let source = SourceSpec::wildcard(addresses[0], 0);
        resolver.configure_source_sockets(
            settings,
            HashMap::from([(ServerId(1), source.clone()), (ServerId(2), source.clone())]),
        );
        let original = resolver
            .start_udp(
                &query(),
                client(),
                GroupId(1),
                Scope::Client("127.0.0.1:1".parse().unwrap()),
            )
            .unwrap();
        let mut buffer = [0; 2048];
        let (_, old_peer) = first.recv_from(&mut buffer).unwrap();
        second.recv_from(&mut buffer).unwrap();
        let mut remaining = group(&addresses[1..], false);
        remaining.servers[0].id = ServerId(2);
        resolver.configure_source_sockets(settings, HashMap::from([(ServerId(2), source)]));
        resolver.replace_server_groups(vec![remaining], &[ServerId(1)]);
        assert_eq!(resolver.pending_count(), 1);
        resolver
            .start_udp(
                &query(),
                client(),
                GroupId(1),
                Scope::Client("127.0.0.1:2".parse().unwrap()),
            )
            .unwrap();
        let (_, new_peer) = second.recv_from(&mut buffer).unwrap();
        assert_ne!(old_peer, new_peer);
        assert_eq!(resolver.socket_count(), 2);
        assert!(resolver.dispatcher.table().get(original.id).is_some());
        resolver.clear();
    }

    #[test]
    fn compatible_destinations_use_port_limit_and_fixed_source_survives_queries() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut resolver = transport(
            group(
                &[first.local_addr().unwrap(), second.local_addr().unwrap()],
                true,
            ),
            Options::default(),
            Duration::from_secs(2),
        );
        resolver
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let mut buffer = [0; 2048];
        let (_, first_peer) = first.recv_from(&mut buffer).unwrap();
        let (_, second_peer) = second.recv_from(&mut buffer).unwrap();
        assert_eq!(first_peer, second_peer);
        assert_eq!(resolver.socket_count(), 1);
        resolver.clear();
        let reserved = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut bindings = HashMap::new();
        bindings.insert(
            ServerId(1),
            SourceSpec::wildcard(first.local_addr().unwrap(), port),
        );
        bindings.insert(
            ServerId(2),
            SourceSpec::wildcard(second.local_addr().unwrap(), port),
        );
        assert!(resolver
            .configure_source_sockets(SocketSettings::default(), bindings)
            .is_empty());
        resolver
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let (_, peer) = first.recv_from(&mut buffer).unwrap();
        second.recv_from(&mut buffer).unwrap();
        assert_eq!(peer.port(), port);
        resolver.cancel(resolver.transactions.keys().copied().next().unwrap());
        assert_eq!(resolver.socket_count(), 1);
        resolver.clear();
        assert_eq!(resolver.socket_count(), 0);
    }

    #[test]
    fn tcp_exchange_authenticates_loopback_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, peer) = listener.accept().unwrap();
            assert_eq!(
                peer.ip(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            );
            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).unwrap();
            let length = usize::from(u16::from_be_bytes(prefix));
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            let mut reply = response(&request, 0x8180, true);
            reply[13] = b'U';
            let frame = tcp_frame(&reply);
            stream.write_all(&frame[..1]).unwrap();
            stream.write_all(&frame[1..]).unwrap();
        });
        let reply = tcp_exchange(address, &query(), Duration::from_secs(1), 4096).unwrap();
        assert_eq!(Header::parse(&reply).unwrap().id, 0x1234);
        assert_eq!(Header::parse(&reply).unwrap().answers, 1);
        worker.join().unwrap();
    }

    #[test]
    fn tcp_exchange_rejects_wrong_id_without_returning_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).unwrap();
            let length = usize::from(u16::from_be_bytes(prefix));
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            let mut reply = response(&request, 0x8180, true);
            reply[0] ^= 1;
            stream.write_all(&tcp_frame(&reply)).unwrap();
        });
        assert!(matches!(
            tcp_exchange(address, &query(), Duration::from_secs(1), 4096),
            Err(TcpExchangeError::ResponseMismatch)
        ));
        worker.join().unwrap();
    }

    pub(super) fn group(addresses: &[SocketAddr], all_servers: bool) -> ServerGroup {
        ServerGroup::new(
            GroupId(1),
            addresses
                .iter()
                .enumerate()
                .map(|(index, &address)| Server {
                    id: ServerId(index as u64 + 1),
                    address,
                    bound_socket: None,
                })
                .collect(),
            true,
            all_servers,
        )
    }

    pub(super) fn transport(
        group: ServerGroup,
        options: Options,
        timeout: Duration,
    ) -> UpstreamResolver<Counter> {
        let dispatcher = ForwardDispatcher::new(options, [group], 1232);
        UpstreamResolver::with_random(dispatcher, Counter(0), timeout).unwrap()
    }

    fn wait_for_event(
        transport: &mut UpstreamResolver<Counter>,
        timeout: Duration,
    ) -> UpstreamEvent {
        for _ in 0..20 {
            let events = transport.poll(timeout).unwrap();
            if let Some(event) = events.into_iter().next() {
                return event;
            }
        }
        panic!("no upstream event");
    }

    #[test]
    fn file_reload_keeps_pending_socket_and_counters_but_retires_removed_slots() {
        let old = UdpSocket::bind("127.0.0.1:0").unwrap();
        let new = UdpSocket::bind("127.0.0.1:0").unwrap();
        old.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        new.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut resolver = transport(
            group(&[old.local_addr().unwrap()], false),
            Options::default(),
            Duration::from_secs(2),
        );
        let submission = resolver
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let mut packet = [0; 2048];
        let (length, peer) = old.recv_from(&mut packet).unwrap();
        let created = resolver
            .dispatcher
            .table()
            .get(submission.id)
            .unwrap()
            .created;
        let counters = resolver.counters();
        let mut replacement = group(&[new.local_addr().unwrap()], false);
        replacement.id = GroupId(2); // C server pointer moved into another tier.
        resolver.replace_server_groups(vec![replacement], &[]);
        let pending = resolver.dispatcher.table().get(submission.id).unwrap();
        assert_eq!((pending.group, pending.created), (GroupId(2), created));
        assert_eq!(resolver.socket_count(), 1);
        assert_eq!(resolver.counters(), counters);
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        old.send_to(&packet[..length], peer).unwrap();
        assert!(resolver.poll(Duration::from_millis(5)).unwrap().is_empty());
        new.send_to(&packet[..length], peer).unwrap();
        assert!(wait_for_event(&mut resolver, Duration::from_millis(5))
            .result
            .is_ok());
        assert_eq!(resolver.pending_count(), 0);
        resolver
            .start_udp(&query(), client(), GroupId(2), Scope::Shared)
            .unwrap();
        new.recv_from(&mut packet).unwrap();
        let counters = resolver.counters();
        resolver.replace_server_groups(Vec::new(), &[ServerId(1)]);
        assert_eq!((resolver.pending_count(), resolver.socket_count()), (0, 0));
        assert_eq!(resolver.counters(), counters);
        assert!(resolver.events.is_empty());
    }

    #[test]
    fn loop_exclusion_keeps_a_sent_reply_authenticated_until_completion() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let dispatcher =
            ForwardDispatcher::new(Options::default(), [group(&[address], false)], 1232);
        let mut resolver =
            UpstreamResolver::with_lifetime(dispatcher, Counter(0), Lifetime::ForwardTable)
                .unwrap();
        resolver
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let mut packet = [0; 2048];
        let (length, peer) = server.recv_from(&mut packet).unwrap();
        resolver.set_reply_servers(vec![Server {
            id: ServerId(1),
            address,
            bound_socket: None,
        }]);
        resolver.replace_server_groups(Vec::new(), &[]);
        assert_eq!(resolver.pending_count(), 1);
        let reply = response(&packet[..length], 0x8180, true);
        server.send_to(&reply, peer).unwrap();
        assert!(wait_for_event(&mut resolver, Duration::from_millis(5))
            .result
            .is_ok());
        assert_eq!((resolver.pending_count(), resolver.socket_count()), (0, 0));
    }

    #[test]
    fn forwarding_lifetime_keeps_wall_clock_replies_until_actual_reclamation() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let dispatcher =
            ForwardDispatcher::new(Options::default(), [group(&[address], false)], 1232);
        let mut transport =
            UpstreamResolver::with_lifetime(dispatcher, Counter(0), Lifetime::ForwardTable)
                .unwrap();
        let old = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap()
            .id;
        let mut input = [0; 2048];
        let (length, _) = server.recv_from(&mut input).unwrap();
        let reply = response(&input[..length], 0x8180, true);
        let created = transport.dispatcher.table().get(old).unwrap().created;
        let transaction = &transport.transactions[&old];
        let token = *transaction.sockets.values().next().unwrap();
        let elapsed = transaction.deadline + Duration::from_secs(1);

        transport.run_timers_at(elapsed, created + 40, 41000);
        assert_eq!(transport.counters().unanswered, 0);
        assert!(transport.events.is_empty());
        assert_eq!(transport.pending_count(), 1);
        assert_eq!(transport.socket_count(), 1);
        assert!(transport
            .dispatcher
            .accept_reply(&reply, address, token, GroupId(1), created + 40)
            .is_none());
        assert!(transport
            .dispatcher
            .accept_reply(&reply, address, token, GroupId(1), created + 10)
            .is_some());

        // Run the actual new-admission boundary at a controlled wall clock.
        // Its newly allocated record has not started transport I/O yet.
        let next = transport
            .dispatcher
            .submit(
                &query(),
                client(),
                GroupId(1),
                Scope::Shared,
                created + 40,
                &mut transport.random,
            )
            .unwrap();
        transport.consume_releases();
        assert_eq!(transport.counters().unanswered, 1);
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        assert!(transport
            .dispatcher
            .accept_reply(&reply, address, token, GroupId(1), created + 10)
            .is_none());
        assert_eq!(transport.events.len(), 1);
        assert!(matches!(
            transport.events.pop_front().unwrap().result,
            Err(ResolveError::Released(ReleaseReason::Expired))
        ));
        transport.dispatcher.cancel(next.id);
        transport.consume_releases();
        assert!(transport.dispatcher.table().is_empty());
    }

    #[test]
    fn forwarded_counter_counts_actions_not_servers_or_coalesced_clients() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        for server in [&first, &second] {
            server
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
        }
        let mut transport = transport(
            group(
                &[first.local_addr().unwrap(), second.local_addr().unwrap()],
                true,
            ),
            Options::default(),
            Duration::from_secs(2),
        );
        let submitted = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let mut buffer = [0; 2048];
        for server in [&first, &second] {
            server.recv_from(&mut buffer).unwrap();
        }
        assert_eq!(transport.counters().queries_forwarded, 1);
        transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        for server in [&first, &second] {
            server.recv_from(&mut buffer).unwrap();
        }
        assert_eq!(transport.counters().queries_forwarded, 2);
        let mut extra = client();
        extra.source.set_port(53001);
        let coalesced = transport
            .start_udp(&query(), extra, GroupId(1), Scope::Shared)
            .unwrap();
        assert_eq!(coalesced.id, submitted.id);
        assert_eq!(transport.counters().queries_forwarded, 2);
        let plan = SendPlan {
            candidates: vec![ServerId(1), ServerId(2)],
            send_all: true,
            exhausted: false,
        };
        assert!(transport
            .send_plan(submitted.id, &vec![0; 65536], &plan)
            .is_err());
        assert_eq!(
            transport.counters().queries_forwarded,
            2,
            "failed sends are not forwarded actions"
        );
        transport.clear();
        assert_eq!(transport.counters().queries_forwarded, 2);
        assert_eq!(transport.counters().unanswered, 0);
        assert_eq!(transport.socket_count(), 0);
    }

    #[test]
    fn failed_fast_retry_counts_one_local_answer_without_a_bus_or_client_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let mut transport = transport(
            group(&[address], false),
            Options {
                fast_retry_ms: 50,
                ..Options::default()
            },
            Duration::from_secs(10),
        );
        for expected in 1..=2 {
            transport.dispatcher.group_mut(GroupId(1)).unwrap().servers[0].address = address;
            let submitted = transport
                .start_udp(&query(), client(), GroupId(1), Scope::Shared)
                .unwrap();
            let created = transport
                .dispatcher
                .table()
                .get(submitted.id)
                .unwrap()
                .created;
            // A zero destination port causes an actual synchronous send error;
            // do not confuse a closed peer port with a failed UDP send.
            transport.dispatcher.group_mut(GroupId(1)).unwrap().servers[0].address =
                "127.0.0.1:0".parse().unwrap();
            transport.run_timers_at(Instant::now(), created, 2000);
            assert_eq!(transport.counters().background_local_answered, expected);
            assert_eq!(transport.counters().queries_forwarded, expected);
            assert_eq!(transport.counters().unanswered, 0);
            assert_eq!(transport.pending_count(), 0);
            assert_eq!(transport.socket_count(), 0);
            let event = transport.events.pop_front().unwrap();
            assert!(matches!(event.result, Err(ResolveError::Io(_))));
            // Further ticks, explicit cleanup and failed initial sends cannot
            // count the same fallback again. No UBus service is involved.
            transport.run_timers_at(Instant::now(), created, 4000);
            transport.clear();
            assert!(transport
                .start_udp(&query(), client(), GroupId(1), Scope::Shared)
                .is_err());
            assert_eq!(transport.counters().background_local_answered, expected);
        }
    }

    #[test]
    fn udp_retry_wait_accepts_the_reference_timespec() {
        wait_udp_retry().unwrap();
    }

    #[test]
    fn transient_send_errors_retry_the_same_socket_packet_and_server() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(2),
        );
        let submitted = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let mut input = [0; 2048];
        let (length, original_peer) = server.recv_from(&mut input).unwrap();
        let original = input[..length].to_vec();
        let packet = transport
            .dispatcher
            .upstream_packet(submitted.id)
            .unwrap()
            .unwrap();
        let plan = SendPlan {
            candidates: vec![ServerId(1)],
            send_all: false,
            exhausted: false,
        };
        let mut calls = Vec::new();
        let mut waits = 0;
        transport
            .send_plan_with_io(
                submitted.id,
                &packet,
                &plan,
                |socket, packet, destination| {
                    calls.push((socket.as_raw_fd(), packet.to_vec(), destination));
                    match calls.len() {
                        1 | 3 => Err(io::ErrorKind::WouldBlock.into()),
                        2 => Err(io::ErrorKind::Interrupted.into()),
                        _ => socket.send_to(packet, destination),
                    }
                },
                || {
                    waits += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(calls.len(), 4);
        assert!(calls.iter().all(|call| call == &calls[0]));
        assert_eq!(calls[0].1, original);
        assert_eq!(waits, 2);
        assert_eq!(transport.counters().queries_forwarded, 2);
        assert_eq!(transport.counters().unanswered, 0);
        assert_eq!(transport.pending_count(), 1);
        assert_eq!(transport.socket_count(), 1);
        let (length, peer) = server.recv_from(&mut input).unwrap();
        assert_eq!(peer, original_peer);
        assert_eq!(&input[..length], original);
        server
            .send_to(&response(&input[..length], 0x8180, true), peer)
            .unwrap();
        assert!(wait_for_event(&mut transport, Duration::from_millis(100))
            .result
            .is_ok());
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
    }

    #[test]
    fn exhausted_transient_candidate_does_not_hide_a_successful_server() {
        for blocked_first in [true, false] {
            let first = UdpSocket::bind("127.0.0.1:0").unwrap();
            let second = UdpSocket::bind("127.0.0.1:0").unwrap();
            for server in [&first, &second] {
                server
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
            }
            let addresses = [first.local_addr().unwrap(), second.local_addr().unwrap()];
            let mut transport = transport(
                group(&addresses, false),
                Options::default(),
                Duration::from_secs(2),
            );
            let submitted = transport
                .start_udp(&query(), client(), GroupId(1), Scope::Shared)
                .unwrap();
            let mut input = [0; 2048];
            first.recv_from(&mut input).unwrap();
            let packet = transport
                .dispatcher
                .upstream_packet(submitted.id)
                .unwrap()
                .unwrap();
            let plan = SendPlan {
                candidates: vec![ServerId(1), ServerId(2)],
                send_all: true,
                exhausted: false,
            };
            let blocked = addresses[usize::from(!blocked_first)];
            let mut attempts = [0; 2];
            let mut waits = 0;
            transport
                .send_plan_with_io(
                    submitted.id,
                    &packet,
                    &plan,
                    |socket, packet, destination| {
                        attempts[usize::from(destination == addresses[1])] += 1;
                        if destination == blocked {
                            Err(io::ErrorKind::WouldBlock.into())
                        } else {
                            socket.send_to(packet, destination)
                        }
                    },
                    || {
                        waits += 1;
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(attempts, if blocked_first { [1001, 1] } else { [1, 1001] });
            assert_eq!(waits, 1001);
            assert_eq!(transport.counters().queries_forwarded, 2);
            assert_eq!(transport.counters().unanswered, 0);
            let successful = if blocked_first { &second } else { &first };
            let (length, peer) = successful.recv_from(&mut input).unwrap();
            successful
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
            assert!(wait_for_event(&mut transport, Duration::from_millis(100))
                .result
                .is_ok());
            assert_eq!(transport.pending_count(), 0);
            assert_eq!(transport.socket_count(), 0);
        }
    }

    #[test]
    fn terminal_and_partial_sends_do_not_increment_forwarding_counters() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut transport = transport(
            group(&[server.local_addr().unwrap()], false),
            Options::default(),
            Duration::from_secs(2),
        );
        let submitted = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let packet = transport
            .dispatcher
            .upstream_packet(submitted.id)
            .unwrap()
            .unwrap();
        let plan = SendPlan {
            candidates: vec![ServerId(1)],
            send_all: false,
            exhausted: false,
        };
        let before = transport.counters();
        for partial in [false, true] {
            let mut calls = 0;
            let error = transport
                .send_plan_with_io(
                    submitted.id,
                    &packet,
                    &plan,
                    |_, packet, _| {
                        calls += 1;
                        if partial {
                            Ok(packet.len() - 1)
                        } else {
                            Err(io::ErrorKind::PermissionDenied.into())
                        }
                    },
                    || panic!("terminal send must not wait"),
                )
                .unwrap_err();
            assert_eq!(calls, 1);
            assert!(matches!(error, ResolveError::Io(_)));
            assert_eq!(transport.counters(), before);
            // The caller owns cancellation; the syscall boundary must not
            // discard a reply already in flight from the earlier send.
            assert_eq!(transport.pending_count(), 1);
            assert_eq!(transport.socket_count(), 1);
        }
        transport.cancel(submitted.id);
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
    }

    #[test]
    fn poll_authenticates_peer_and_releases_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let spoof = UdpSocket::bind("127.0.0.1:0").unwrap();
            spoof
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
            server
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
        });
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        let submission = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let event = wait_for_event(&mut transport, Duration::from_millis(100));
        assert_eq!(event.id, submission.id);
        let reply = event.result.unwrap();
        assert_eq!(Header::parse(&reply.packet).unwrap().answers, 1);
        assert_eq!(reply.server, ServerId(1));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn ignored_reply_stays_pending_until_a_later_upstream_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            server
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
            thread::sleep(Duration::from_millis(60));
            server
                .send_to(&response(&input[..length], 0x8180, false), peer)
                .unwrap();
        });
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        let submission = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let ignored = transport
            .poll_with_filter(Duration::from_millis(20), |packet| {
                Message::parse(packet)
                    .ok()
                    .is_some_and(|message| message.records(Section::Answer).next().is_some())
            })
            .unwrap();
        assert!(ignored.is_empty());
        assert_eq!(transport.pending_count(), 1);
        let events = transport
            .poll_with_filter(Duration::from_millis(200), |_| false)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, submission.id);
        assert!(events[0].result.is_ok());
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn truncated_udp_reply_is_delivered_without_retry_or_state_leak() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            server
                .send_to(&response(&input[..length], 0x8380, false), peer)
                .unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            assert!(
                server.recv_from(&mut input).is_err(),
                "TC response was retried"
            );
        });
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        let submission = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let event = wait_for_event(&mut transport, Duration::from_millis(100));
        let reply = event.result.unwrap();
        assert_eq!(event.id, submission.id);
        assert!(reply.truncated);
        assert!(udp_reply_is_truncated(&reply.packet).unwrap());
        assert_eq!(Header::parse(&reply.packet).unwrap().flags & 0x0200, 0x0200);
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn truncated_classifier_rejects_short_header() {
        assert_eq!(udp_reply_is_truncated(&[0; 11]), Err(WireError::Truncated));
        assert!(!udp_reply_is_truncated(&[0; 12]).unwrap());
    }

    #[test]
    fn failed_first_send_falls_back_without_leaking_failed_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            server
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
        });
        // The unspecified destination has no route on supported Unix hosts;
        // unlike a closed loopback port, send_to fails synchronously.
        let bad = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut transport = transport(
            group(&[bad, address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let event = wait_for_event(&mut transport, Duration::from_millis(100));
        assert_eq!(event.result.unwrap().server, ServerId(2));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn all_servers_refused_waits_without_resending() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        let first_address = first.local_addr().unwrap();
        let second_address = second.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let first_thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = first.recv_from(&mut input).unwrap();
            tx.send(()).unwrap();
            first
                .send_to(&response(&input[..length], 0x8185, false), peer)
                .unwrap();
            first
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            assert!(
                first.recv_from(&mut input).is_err(),
                "REFUSED caused a resend"
            );
        });
        let second_thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = second.recv_from(&mut input).unwrap();
            thread::sleep(Duration::from_millis(20));
            second
                .send_to(&response(&input[..length], 0x8180, true), peer)
                .unwrap();
            second
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            assert!(
                second.recv_from(&mut input).is_err(),
                "REFUSED caused a resend"
            );
        });
        let mut transport = transport(
            group(&[first_address, second_address], true),
            Options::default(),
            Duration::from_secs(1),
        );
        transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        rx.recv_timeout(Duration::from_millis(250)).unwrap();
        let event = wait_for_event(&mut transport, Duration::from_millis(100));
        assert_eq!(event.result.unwrap().server, ServerId(2));
        first_thread.join().unwrap();
        second_thread.join().unwrap();
    }

    #[test]
    fn timeout_is_bounded_and_is_not_an_upstream_error_retry() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        drop(server);
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_millis(25),
        );
        let started = Instant::now();
        transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let event = wait_for_event(&mut transport, Duration::from_secs(1));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(matches!(event.result, Err(ResolveError::Timeout)));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
    }

    #[test]
    fn duplicate_coalesces_without_second_send_and_cancel_reclaims_refs() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, _) = server.recv_from(&mut input).unwrap();
            tx.send(length).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            assert!(
                server.recv_from(&mut input).is_err(),
                "coalesced query was resent"
            );
        });
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        let first = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        let mut second_client = client();
        second_client.source = "127.0.0.1:53001".parse().unwrap();
        let second = transport
            .start_udp(&query(), second_client, GroupId(1), Scope::Shared)
            .unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(
            second.kind,
            super::super::forward::SubmissionKind::Coalesced
        );
        rx.recv_timeout(Duration::from_millis(250)).unwrap();
        assert!(transport.cancel(first.id));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    #[test]
    fn asynchronous_query_notices_and_recipients_keep_their_saved_context() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let mut transport = transport(
            group(&[address], false),
            Options::default(),
            Duration::from_secs(1),
        );
        transport.set_query_logging(crate::config::logging::QueryLogging {
            enabled: true,
            extra: true,
            ..Default::default()
        });
        for id in [91, 92] {
            let mut request = PacketWriter::new(id, 0x0100, 1232).unwrap();
            request
                .question(
                    &Name::from_ascii(&format!("query{id}.context.test")).unwrap(),
                    1,
                    1,
                )
                .unwrap();
            let mut client = client();
            client.log_id = u64::from(id);
            client.source.set_port(53000 + id);
            transport
                .start_udp(&request.finish(), client, GroupId(1), Scope::Shared)
                .unwrap();
        }
        let notices = transport.take_query_events();
        assert_eq!(
            notices
                .iter()
                .map(|(context, _)| context.display_id)
                .collect::<Vec<_>>(),
            [91, 92]
        );
        assert_eq!(notices[0].0.client.unwrap().port(), 53091);
        assert_eq!(notices[1].0.client.unwrap().port(), 53092);
        assert!(notices
            .iter()
            .all(|(_, event)| event.flags & crate::query_logging::SERVER != 0
                && event.kind == address.port()));
        let mut received = Vec::new();
        for _ in 0..2 {
            let mut bytes = [0; 2048];
            let (length, peer) = server.recv_from(&mut bytes).unwrap();
            received.push((bytes[..length].to_vec(), peer));
        }
        for (mut request, peer) in received.into_iter().rev() {
            let mut header = Header::parse(&request).unwrap();
            header.flags = 0x8180;
            header.write(&mut request).unwrap();
            server.send_to(&request, peer).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut replies = Vec::new();
        while replies.len() < 2 && Instant::now() < deadline {
            replies.extend(transport.poll(Duration::from_millis(10)).unwrap());
        }
        assert_eq!(replies.len(), 2);
        for reply in replies {
            let reply = reply.result.unwrap();
            let recipient = &reply.recipients[0];
            let context = recipient.client.query_context();
            assert_eq!(context.display_id as u16, recipient.original_id);
            assert_eq!(
                context.client.unwrap().port(),
                53000 + recipient.original_id
            );
        }
        assert!(transport.take_query_events().is_empty());
        assert_eq!(transport.pending_count(), 0);

        let mut background = client();
        background.reply_requested = false;
        background.log_id = 93;
        let submission = transport
            .start_udp(&query(), background, GroupId(1), Scope::Shared)
            .unwrap();
        let notices = transport.take_query_events();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].0.display_id, 93);
        assert_eq!(notices[0].0.client, None);
        assert!(transport.cancel(submission.id));
    }

    #[test]
    fn fast_retry_is_explicit_and_cancel_reclaims_refs() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut input = [0; 2048];
            for _ in 0..2 {
                let (length, _) = server.recv_from(&mut input).unwrap();
                tx.send(length).unwrap();
            }
        });
        let options = Options {
            fast_retry_ms: 5,
            fast_retry_timeout_s: 10,
            ..Options::default()
        };
        let mut transport = transport(group(&[address], false), options, Duration::from_secs(1));
        let submission = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap();
        rx.recv_timeout(Duration::from_millis(250)).unwrap();
        thread::sleep(Duration::from_millis(10));
        assert!(transport.tick().is_empty());
        rx.recv_timeout(Duration::from_millis(250)).unwrap();
        assert!(transport.cancel(submission.id));
        assert_eq!(transport.pending_count(), 0);
        assert_eq!(transport.socket_count(), 0);
        thread.join().unwrap();
    }

    pub(super) fn pending_receive(
        lifetime: Lifetime,
    ) -> (UpstreamResolver<Counter>, UdpSocket, QueryId, SocketToken) {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let dispatcher = ForwardDispatcher::new(
            Options::default(),
            [group(&[server.local_addr().unwrap()], false)],
            1232,
        );
        let mut transport =
            UpstreamResolver::with_lifetime(dispatcher, Counter(0), lifetime).unwrap();
        let id = transport
            .start_udp(&query(), client(), GroupId(1), Scope::Shared)
            .unwrap()
            .id;
        let mut sibling = client();
        sibling.source.set_port(53001);
        assert_eq!(
            transport
                .start_udp(&query(), sibling, GroupId(1), Scope::Shared)
                .unwrap()
                .id,
            id
        );
        let token = *transport.transactions[&id].sockets.values().next().unwrap();
        (transport, server, id, token)
    }

    #[test]
    fn controlled_receive_errors_preserve_transaction_and_later_real_reply() {
        for lifetime in [
            Lifetime::Fixed(Duration::from_secs(1)),
            Lifetime::ForwardTable,
        ] {
            let (mut transport, server, id, token) = pending_receive(lifetime);
            let deadline = transport.transactions[&id].deadline;
            let upstream_id = transport.dispatcher.table().get(id).unwrap().upstream_id;
            let counters = transport.counters();
            for error in [
                io::ErrorKind::ConnectionRefused,
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::TimedOut,
                io::ErrorKind::Other,
            ] {
                let mut calls = 0;
                transport.receive_ready_with_io(
                    token,
                    POLLIN,
                    &|_, _| false,
                    Instant::now(),
                    |_, _| {
                        calls += 1;
                        Err(io::Error::from(error))
                    },
                    |_| panic!("POLLIN alone does not read SO_ERROR"),
                );
                assert_eq!(calls, 1);
                assert!(transport.events.is_empty());
                assert_eq!(transport.transactions[&id].deadline, deadline);
                assert_eq!(
                    transport.dispatcher.table().get(id).unwrap().upstream_id,
                    upstream_id
                );
                assert_eq!(
                    transport
                        .dispatcher
                        .table()
                        .get(id)
                        .unwrap()
                        .recipients
                        .len(),
                    2
                );
                assert_eq!(transport.counters(), counters);
                assert_eq!(
                    (transport.pending_count(), transport.socket_count()),
                    (1, 1)
                );
            }
            let mut request = [0; 2048];
            let (length, peer) = server.recv_from(&mut request).unwrap();
            server
                .send_to(&response(&request[..length], 0x8180, true), peer)
                .unwrap();
            let event = wait_for_event(&mut transport, Duration::from_millis(100));
            assert_eq!(event.id, id);
            let reply = event.result.unwrap();
            assert_eq!(Header::parse(&reply.packet).unwrap().id, upstream_id);
            assert_eq!(reply.recipients.len(), 2);
            assert_eq!(
                (transport.pending_count(), transport.socket_count()),
                (0, 0)
            );
            assert_eq!(transport.counters(), counters);
        }
    }

    #[test]
    fn controlled_poll_error_is_consumed_without_cancellation_or_deadline_extension() {
        let (mut transport, _server, id, token) =
            pending_receive(Lifetime::Fixed(Duration::from_secs(1)));
        let deadline = transport.transactions[&id].deadline;
        let mut calls = 0;
        transport.receive_ready_with_io(
            token,
            POLLERR,
            &|_, _| false,
            Instant::now(),
            |_, _| panic!("consumed standalone socket error ends the batch"),
            |_| {
                calls += 1;
                Ok(Some(io::ErrorKind::ConnectionRefused.into()))
            },
        );
        assert_eq!(calls, 1);
        assert!(transport.events.is_empty());
        assert_eq!(transport.transactions[&id].deadline, deadline);
        transport.run_timers_at(deadline, unix_seconds(), transport.milliseconds());
        assert_eq!(
            (transport.pending_count(), transport.socket_count()),
            (0, 0)
        );
        assert!(matches!(
            transport.events.pop_front().unwrap().result,
            Err(ResolveError::Timeout)
        ));
    }

    #[test]
    fn controlled_interrupted_receive_has_a_finite_batch_budget() {
        let (mut transport, _server, id, token) = pending_receive(Lifetime::ForwardTable);
        let mut calls = 0;
        transport.receive_ready_with_io(
            token,
            POLLIN,
            &|_, _| false,
            Instant::now(),
            |_, _| {
                calls += 1;
                Err(io::ErrorKind::Interrupted.into())
            },
            |_| panic!("no error readiness"),
        );
        assert_eq!(calls, RECEIVE_BUDGET);
        assert!(transport.events.is_empty());
        assert!(transport.cancel(id));
        assert_eq!(
            (transport.pending_count(), transport.socket_count()),
            (0, 0)
        );
    }

    #[test]
    fn controlled_invalid_fd_and_hangup_are_distinct_terminal_events() {
        for revents in [POLLNVAL, POLLHUP] {
            let (mut transport, _server, id, token) = pending_receive(Lifetime::ForwardTable);
            transport.receive_ready_with_io(
                token,
                revents,
                &|_, _| false,
                Instant::now(),
                |_, _| panic!("unusable descriptor must not receive"),
                |_| panic!("unusable descriptor must not read SO_ERROR"),
            );
            let event = transport.events.pop_front().unwrap();
            assert_eq!(event.id, id);
            assert!(matches!(event.result, Err(ResolveError::Io(_))));
            assert_eq!(
                (transport.pending_count(), transport.socket_count()),
                (0, 0)
            );
            assert_eq!(transport.counters().unanswered, 0);
        }
    }

    #[test]
    fn failed_socket_error_inspection_is_an_explicit_terminal_boundary() {
        let (mut transport, _server, id, token) = pending_receive(Lifetime::ForwardTable);
        transport.receive_ready_with_io(
            token,
            POLLERR,
            &|_, _| false,
            Instant::now(),
            |_, _| panic!("failed socket inspection must not receive"),
            |_| Err(io::ErrorKind::InvalidInput.into()),
        );
        let event = transport.events.pop_front().unwrap();
        assert_eq!(event.id, id);
        assert!(matches!(event.result, Err(ResolveError::Io(_))));
        assert_eq!(
            (transport.pending_count(), transport.socket_count()),
            (0, 0)
        );
    }

    #[test]
    fn repeated_empty_poll_error_does_not_continuously_retry_receive() {
        let (mut transport, server, id, token) = pending_receive(Lifetime::ForwardTable);
        let deadline = transport.transactions[&id].deadline;
        let counters = transport.counters();
        let now = Instant::now();
        let mut calls = 0;
        // Model a stale readiness source: SO_ERROR is empty and recvfrom has
        // no datagram, yet the containing loop reports POLLERR repeatedly.
        for attempt in 0..3 {
            transport.receive_ready_with_io(
                token,
                POLLERR,
                &|_, _| false,
                now,
                |_, _| {
                    calls += 1;
                    Err(io::ErrorKind::WouldBlock.into())
                },
                |_| Ok(None),
            );
            if attempt == 0 {
                assert!(transport.sockets[&token].pollable_at(now));
            }
        }
        assert_eq!(calls, 2, "third readiness must wait for a scheduled retry");
        let retry = now + Duration::from_millis(10);
        assert_eq!(transport.sockets[&token].empty_error_retry, Some(retry));
        assert!(!transport.sockets[&token].pollable_at(now));
        assert!(transport.sockets[&token].pollable_at(retry));
        assert_eq!(transport.transactions[&id].deadline, deadline);
        assert_eq!(transport.counters(), counters);
        let mut request = [0; 2048];
        let (length, peer) = server.recv_from(&mut request).unwrap();
        server
            .send_to(&response(&request[..length], 0x8180, true), peer)
            .unwrap();
        wait_until_readable(&transport.sockets[&token].socket);
        transport.receive_ready_with_io(
            token,
            POLLIN,
            &|_, _| false,
            retry,
            UdpSocket::recv_from,
            |_| panic!("normal readable retry needs no SO_ERROR"),
        );
        assert_eq!(
            transport
                .events
                .pop_front()
                .unwrap()
                .result
                .unwrap()
                .recipients
                .len(),
            2
        );
        assert_eq!(
            (transport.pending_count(), transport.socket_count()),
            (0, 0)
        );
        assert_eq!(transport.counters(), counters);
        println!(
            "owned_socket_bytes={} previous_socket_fields_bytes={}",
            std::mem::size_of::<OwnedSocket>(),
            std::mem::size_of::<(QueryId, ServerId, UdpSocket)>()
        );
    }

    #[test]
    fn controlled_poll_error_with_data_still_delivers_the_readable_reply() {
        let (mut transport, server, _id, token) = pending_receive(Lifetime::ForwardTable);
        let mut request = [0; 2048];
        let (length, peer) = server.recv_from(&mut request).unwrap();
        server
            .send_to(&response(&request[..length], 0x8180, true), peer)
            .unwrap();
        wait_until_readable(&transport.sockets[&token].socket);
        transport.receive_ready_with_io(
            token,
            POLLERR | POLLIN,
            &|_, _| false,
            Instant::now(),
            UdpSocket::recv_from,
            |_| Ok(Some(io::ErrorKind::ConnectionRefused.into())),
        );
        assert_eq!(
            transport
                .events
                .pop_front()
                .unwrap()
                .result
                .unwrap()
                .recipients
                .len(),
            2
        );
        assert_eq!(
            (transport.pending_count(), transport.socket_count()),
            (0, 0)
        );
    }

    fn wait_until_readable(socket: &UdpSocket) {
        let mut fd = [PollFd {
            fd: socket.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        }];
        assert_eq!(poll_once(&mut fd, 1000).unwrap(), 1);
        assert_ne!(fd[0].revents & POLLIN, 0);
    }
}
