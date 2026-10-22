//! Forwarded TCP caller policy from forward.c::tcp_request/process_reply.
//!
//! One service belongs to one downstream connection. The caller first attempts
//! its local answer path. Supported configuration adds no client-dependent EDNS
//! options, so the forwarded query remains byte-for-byte unchanged. Dynamic
//! cache insertion and ubus doctor notifications belong to the daemon owner.
//! Static aliases run once on each eligible upstream reply.

use super::daemon::{address_policy, validate_runtime_config, DaemonError};
use super::process::{apply_static_aliases, process_admitted_reply, AddressPolicy, ProcessError};
use super::reply::{
    apply_known_local_nxdomain, filter_rrs, prepare_udp_reply, resize_reply, ReplyPolicy,
};
use super::routing::{RouteReason, RoutingTable};
use super::service::LocalDnsService;
pub use super::tcp_upstream::TcpWait;
use super::tcp_upstream::{TcpError, TcpOptions, TcpProgress, TcpUpstream};
#[cfg(test)]
use super::wire::Message;
use super::wire::{find_pseudoheader, skip_questions, Header, Name, Question, WireError};
use crate::config::dns::DnsConfig;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

const TCP_LIMIT: usize = 65536;

#[derive(Debug)]
pub enum TcpServiceError {
    Config(DaemonError),
    Transport(TcpError),
    Wire(WireError),
    Process(ProcessError),
    InvalidQuery,
    LocalRouteNotAnswered,
}

impl std::fmt::Display for TcpServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP DNS service: {self:?}")
    }
}
impl std::error::Error for TcpServiceError {}
impl From<WireError> for TcpServiceError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

/// Incremental result for the downstream connection owner. `Complete` carries
/// the same upstream/cache-eligibility bit as handle_with_local_upstream.
#[derive(Debug)]
pub enum TcpServiceProgress {
    Pending(TcpWait),
    Complete(Vec<u8>, bool),
}

/// Short-lived completion hook. The caller owns its cache view and collects
/// a transaction; no parent lock is retained across upstream socket I/O.
pub type TcpCacheSink<'a> = dyn FnMut(&mut Vec<u8>, &AddressPolicy, u16, super::cache::Extraction) -> Result<(), WireError>
    + 'a;

enum PreparedQuery {
    Answer(Vec<u8>),
    Forward(super::forward::GroupId),
}

struct FinishedReply {
    packet: Vec<u8>,
    bogus: Option<(Name, u32)>,
    from_upstream: bool,
}

pub struct TcpDnsService {
    query_logging: bool,
    query_events: Vec<crate::query_logging::QueryEvent>,
    routing: RoutingTable,
    upstream: TcpUpstream,
    policy: AddressPolicy,
    query_policy: super::query_policy::QueryPolicy,
    proxy_dnssec: bool,
    edns_packet_max: u16,
    filter_rr: Vec<u16>,
    pending_query: Option<Vec<u8>>,
    pending_bogus: Option<(Name, u32)>,
    edns: crate::config::edns::EdnsConfig,
    client_source: Option<IpAddr>,
}

impl TcpDnsService {
    /// Re-evaluate immediately before each nonblocking forwarder step. The
    /// caller supplies its connection snapshot, or the current cache in debug
    /// mode, so this does not freeze name existence across an upstream wait.
    pub fn cached_query_name(
        &self,
        query: Option<&[u8]>,
        cache: Option<&super::cache::Cache>,
        now: i64,
    ) -> bool {
        query
            .or(self.pending_query.as_deref())
            .and_then(|query| Question::parse(query, 12).ok())
            .is_some_and(|question| {
                cache.is_some_and(|cache| cache.contains_forward_name(&question.name, now))
            })
    }

    pub fn set_query_logging(&mut self, enabled: bool) {
        self.query_logging = enabled;
    }
    pub fn take_query_events(&mut self) -> Vec<crate::query_logging::QueryEvent> {
        std::mem::take(&mut self.query_events)
    }
    fn query_error_notice(&mut self, ede: i32) {
        if self.query_logging {
            self.query_events
                .push(crate::query_logging::QueryEvent::error(
                    crate::query_logging::CONFIG,
                    b"error",
                    5,
                    Some(ede),
                ));
        }
    }
    fn query_reply_notices(&mut self, query: &[u8], packet: &[u8]) {
        if !self.query_logging {
            return;
        }
        use crate::query_logging::{self as qlog, QueryData, QueryEvent};
        if let Some(server) = self.upstream.take_reply_server() {
            if let Ok(question) = super::forward::Question::parse(query) {
                let mut event = QueryEvent::address(
                    qlog::SERVER,
                    &question.name.dnsmasq_bytes(),
                    server.ip(),
                    None,
                );
                event.kind = server.port();
                self.query_events.push(event);
            }
        }
        if let Ok(header) = Header::parse(packet) {
            if !matches!(header.rcode(), 0 | 3) {
                self.query_events.push(QueryEvent::error(
                    qlog::REPLY,
                    b"error",
                    u16::from(header.rcode()),
                    None,
                ));
            } else if header.flags & 0x0200 != 0 {
                self.query_events.push(QueryEvent {
                    flags: qlog::REPLY,
                    name: None,
                    data: QueryData::None,
                    argument: Some(b"truncated".to_vec()),
                    kind: 0,
                });
            }
        }
    }
    pub fn set_preferred_servers(
        &mut self,
        servers: impl IntoIterator<Item = (super::forward::GroupId, super::forward::ServerId)>,
    ) {
        self.upstream.set_preferred_servers(servers);
    }

    /// Set once when the accepted connection and its local/routing snapshots
    /// are created. MAC lookup remains in the owner's nonblocking path.
    pub fn take_connection_failures(&mut self) -> Vec<SocketAddr> {
        self.upstream.take_connection_failures()
    }

    pub fn set_client_source(&mut self, source: IpAddr) {
        self.client_source = Some(source);
    }

    pub fn cache_eligible_with_policy(query: &[u8], cacheable: bool) -> bool {
        cacheable && super::forward_service::edns_cache_query(query)
    }

    pub fn cache_eligible(query: &[u8]) -> bool {
        super::forward_service::ordinary_cache_query(query)
    }

    pub fn new(
        config: &DnsConfig,
        default_resolvers: &[SocketAddr],
        edns_packet_max: u16,
    ) -> Result<Self, TcpServiceError> {
        config
            .validate_ready()
            .map_err(|error| TcpServiceError::Config(error.into()))?;
        validate_runtime_config(config).map_err(TcpServiceError::Config)?;
        let routing = RoutingTable::from_runtime_config(config, default_resolvers)
            .map_err(|error| TcpServiceError::Config(error.into()))?;
        Self::with_routing(config, routing, edns_packet_max)
    }

    /// New connections receive the parent's active routing snapshot rather
    /// than reparsing an obsolete startup resolver list.
    pub fn with_routing(
        config: &DnsConfig,
        routing: RoutingTable,
        edns_packet_max: u16,
    ) -> Result<Self, TcpServiceError> {
        let mut upstream = TcpUpstream::new(routing.dispatcher_groups(), TcpOptions::default())
            .map_err(TcpServiceError::Transport)?;
        upstream.set_source_bindings(&routing.source_bindings(0));
        let mut policy = address_policy(config).map_err(TcpServiceError::Config)?;
        // ignore-address is a UDP reply_query predicate, absent from C's TCP
        // process_reply path. Keep that distinction if shared policy grows.
        policy.ignore_addresses.clear();
        Ok(Self {
            query_logging: false,
            query_events: Vec::new(),
            routing,
            upstream,
            policy,
            query_policy: super::query_policy::QueryPolicy::from_config(config),
            proxy_dnssec: config.proxy_dnssec,
            edns_packet_max,
            filter_rr: config.filter_rr.clone(),
            pending_query: None,
            pending_bogus: None,
            edns: config.edns.clone(),
            client_source: None,
        })
    }

    /// A matching bogus RR commits even for CD or --no-negcache. The owner
    /// consumes this before ordinary response insertion, which has lost the
    /// matching owner and TTL after NXDOMAIN rewriting.
    pub fn take_bogus_cache_entry(&mut self) -> Option<(Name, u32)> {
        self.pending_bogus.take()
    }

    pub fn handle(
        &mut self,
        query: &[u8],
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TcpServiceError> {
        self.handle_inner(query, None, deadline, stopped)
            .map(|(packet, _)| packet)
    }

    /// Use the downstream connection's local-name snapshot for the C
    /// NXDOMAIN-to-NODATA rule after its local answer path has missed.
    pub fn handle_with_local(
        &mut self,
        query: &[u8],
        local: &LocalDnsService,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TcpServiceError> {
        self.handle_inner(query, Some(local), deadline, stopped)
            .map(|(packet, _)| packet)
    }

    /// Return whether the response came from the upstream TCP exchange. The
    /// parent daemon uses this bit to commit the response into its shared
    /// cache; local answers remain connection-local.
    pub fn handle_with_local_upstream(
        &mut self,
        query: &[u8],
        local: &LocalDnsService,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(Vec<u8>, bool), TcpServiceError> {
        self.handle_inner(query, Some(local), deadline, stopped)
    }

    /// Start a query without waiting on any upstream socket. The caller must
    /// finish or clear it before starting the next frame on this connection.
    pub fn start_with_local_upstream(
        &mut self,
        query: &[u8],
        local: &LocalDnsService,
        deadline: Instant,
    ) -> Result<TcpServiceProgress, TcpServiceError> {
        self.start_with_cache_sink(query, local, deadline, None, false, None, false, None)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The accepted connection supplies its deadline, cache sink and forwarding cursor explicitly."
    )]
    pub fn start_with_local_upstream_cache(
        &mut self,
        query: &[u8],
        local: &LocalDnsService,
        deadline: Instant,
        no_cache: bool,
        now: i64,
        cache: &mut TcpCacheSink<'_>,
        cached_name: bool,
        forward_name: Option<&super::daemon::ForwardName>,
    ) -> Result<TcpServiceProgress, TcpServiceError> {
        self.start_with_cache_sink(
            query,
            local,
            deadline,
            Some(cache),
            no_cache,
            Some(now),
            cached_name,
            forward_name,
        )
    }

    pub fn step_with_local_upstream(
        &mut self,
        local: &LocalDnsService,
    ) -> Result<TcpServiceProgress, TcpServiceError> {
        self.step_with_cache_sink(local, None, false, None, false)
    }

    pub fn step_with_local_upstream_cache(
        &mut self,
        local: &LocalDnsService,
        no_cache: bool,
        now: i64,
        cache: &mut TcpCacheSink<'_>,
        cached_name: bool,
    ) -> Result<TcpServiceProgress, TcpServiceError> {
        self.step_with_cache_sink(local, Some(cache), no_cache, Some(now), cached_name)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Preserve explicit connection deadline, cache sink, clock and forwarding cursor ownership."
    )]
    fn start_with_cache_sink(
        &mut self,
        query: &[u8],
        local: &LocalDnsService,
        deadline: Instant,
        cache: Option<&mut TcpCacheSink<'_>>,
        no_cache: bool,
        now: Option<i64>,
        cached_name: bool,
        forward_name: Option<&super::daemon::ForwardName>,
    ) -> Result<TcpServiceProgress, TcpServiceError> {
        if self.pending_query.is_some() {
            return Err(TcpServiceError::Transport(TcpError::Busy));
        }
        self.pending_bogus = None;
        let group = match self.prepare(query, Some(local), forward_name, cached_name)? {
            PreparedQuery::Answer(packet) => {
                return Ok(TcpServiceProgress::Complete(packet, false))
            }
            PreparedQuery::Forward(group) => group,
        };
        let progress = self.upstream.start(group, query, deadline);
        self.finish_progress(
            query.to_vec(),
            local,
            progress,
            cache,
            no_cache,
            now,
            cached_name,
        )
    }

    /// Resume after fd readiness or its absolute timer. This is also safe to
    /// call on each owner-loop turn: all transport syscalls are nonblocking.
    fn step_with_cache_sink(
        &mut self,
        local: &LocalDnsService,
        cache: Option<&mut TcpCacheSink<'_>>,
        no_cache: bool,
        now: Option<i64>,
        cached_name: bool,
    ) -> Result<TcpServiceProgress, TcpServiceError> {
        let query = self
            .pending_query
            .take()
            .ok_or(TcpServiceError::Transport(TcpError::NotStarted))?;
        let progress = self.upstream.step();
        self.finish_progress(query, local, progress, cache, no_cache, now, cached_name)
    }

    /// Cancel the current exchange and release all per-session upstream fds.
    pub fn clear(&mut self) {
        self.pending_query = None;
        self.pending_bogus = None;
        self.upstream.clear();
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Completion combines the retained query with caller-owned cache and local snapshot state."
    )]
    fn finish_progress(
        &mut self,
        query: Vec<u8>,
        local: &LocalDnsService,
        progress: Result<TcpProgress, TcpError>,
        cache: Option<&mut TcpCacheSink<'_>>,
        no_cache: bool,
        now: Option<i64>,
        cached_name: bool,
    ) -> Result<TcpServiceProgress, TcpServiceError> {
        match progress {
            Ok(TcpProgress::Pending(wait)) => {
                self.pending_query = Some(query);
                Ok(TcpServiceProgress::Pending(wait))
            }
            Ok(TcpProgress::Complete(reply)) => {
                self.query_reply_notices(&query, &reply);
                finish_reply_with_edns(
                    &query,
                    &reply,
                    &self.policy,
                    self.proxy_dnssec,
                    self.edns_packet_max,
                    &self.filter_rr,
                    Some(local),
                    Some(&self.routing),
                    self.client_source.map(|source| (&self.edns, source)),
                    cache,
                    no_cache,
                    now,
                    cached_name,
                )
                .map(|reply| {
                    self.pending_bogus = reply.bogus;
                    TcpServiceProgress::Complete(reply.packet, reply.from_upstream)
                })
            }
            Err(TcpError::NoReply) => {
                self.query_error_notice(23);
                Ok(TcpServiceProgress::Complete(
                    refusal(&query, self.edns_packet_max, 23, TCP_LIMIT, true)?,
                    false,
                ))
            }
            Err(error) => Err(TcpServiceError::Transport(error)),
        }
    }

    fn prepare(
        &mut self,
        query: &[u8],
        local: Option<&LocalDnsService>,
        forward_name: Option<&super::daemon::ForwardName>,
        cached_name: bool,
    ) -> Result<PreparedQuery, TcpServiceError> {
        let header = Header::parse(query)?;
        if header.flags & 0x8000 != 0 {
            return Err(TcpServiceError::InvalidQuery);
        }
        if let Some(reply) = query_error(query)? {
            if self.query_logging {
                if header.opcode() != 0 {
                    self.query_events
                        .push(crate::query_logging::QueryEvent::error(
                            crate::query_logging::REPLY,
                            b"opcode",
                            4,
                            None,
                        ));
                } else {
                    self.query_events
                        .push(crate::query_logging::QueryEvent::error(
                            crate::query_logging::CONFIG,
                            b"error",
                            5,
                            Some(24),
                        ));
                }
            }
            return Ok(PreparedQuery::Answer(reply));
        }
        let policy_reply = self.query_policy.reply_with_cache(
            query,
            &self.routing,
            local,
            self.edns_packet_max,
            true,
            forward_name.map(|cursor| &cursor.name),
            forward_name.map_or(cached_name, |cursor| cursor.cached),
            self.query_logging.then_some(&mut self.query_events),
        );
        if let Some(packet) = policy_reply? {
            return Ok(PreparedQuery::Answer(packet));
        }
        let question = Question::parse(query, 12)?;
        let route = self.routing.select(
            forward_name.map_or(&question.name, |cursor| &cursor.name),
            question.qtype,
            question.class,
            false,
        );
        let Some(group) = route.upstream_group() else {
            return match route.reason {
                RouteReason::NoMatchingRule => {
                    self.query_error_notice(14);
                    Ok(PreparedQuery::Answer(refusal(
                        query,
                        self.edns_packet_max,
                        14,
                        TCP_LIMIT,
                        true,
                    )?))
                }
                _ => Err(TcpServiceError::LocalRouteNotAnswered),
            };
        };
        Ok(PreparedQuery::Forward(group))
    }

    fn handle_inner(
        &mut self,
        query: &[u8],
        local: Option<&LocalDnsService>,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(Vec<u8>, bool), TcpServiceError> {
        self.pending_bogus = None;
        let group = match self.prepare(query, local, None, false)? {
            PreparedQuery::Answer(packet) => return Ok((packet, false)),
            PreparedQuery::Forward(group) => group,
        };
        match self.upstream.exchange(group, query, deadline, stopped) {
            Ok(reply) => finish_reply_with_edns(
                query,
                &reply,
                &self.policy,
                self.proxy_dnssec,
                self.edns_packet_max,
                &self.filter_rr,
                local,
                Some(&self.routing),
                self.client_source.map(|source| (&self.edns, source)),
                None,
                false,
                None,
                false,
            )
            .map(|reply| {
                self.pending_bogus = reply.bogus;
                (reply.packet, reply.from_upstream)
            }),
            Err(TcpError::NoReply) => Ok((
                refusal(query, self.edns_packet_max, 23, TCP_LIMIT, true)?,
                false,
            )),
            Err(error) => Err(TcpServiceError::Transport(error)),
        }
    }
}

/// Shared make_local_answer(flags=0) boundary. UDP supplies its own output
/// limit; the advertised OPT size remains the configured daemon maximum.
pub(super) fn refusal(
    query: &[u8],
    edns_packet_max: u16,
    ede: u16,
    out_limit: usize,
    copy_do: bool,
) -> Result<Vec<u8>, WireError> {
    let scan = find_pseudoheader(query, true)?;
    let had_opt = scan.opt.is_some();
    let do_bit = copy_do && scan.opt.is_some_and(|opt| opt.dnssec_ok());
    let mut packet = error_reply(query, 5)?;
    if had_opt {
        add_ede(&mut packet, edns_packet_max, do_bit, ede, out_limit)?;
    }
    Ok(packet)
}

fn error_reply(query: &[u8], rcode: u16) -> Result<Vec<u8>, WireError> {
    let mut header = Header::parse(query)?;
    // setup_reply: clear AA/TC/AD, retain CD/RD/Z, set QR/RA and the error.
    header.flags = (header.flags & !0x062f) | 0x8080 | rcode;
    header.answers = 0;
    header.authorities = 0;
    header.additionals = 0;
    let mut packet = query[..skip_questions(query)?].to_vec();
    header.write(&mut packet)?;
    Ok(packet)
}

fn query_error(query: &[u8]) -> Result<Option<Vec<u8>>, WireError> {
    let header = Header::parse(query)?;
    if header.opcode() != 0 {
        return error_reply(query, 4).map(Some);
    }
    if header.questions != 1
        || header.answers != 0
        || header.authorities != 0
        || Question::parse(query, 12).is_err()
    {
        // extract_request failure precedes OPT discovery in tcp_request. For
        // this request the EDE_INVALID_DATA code is logged, not put on wire.
        return error_reply(query, 5).map(Some);
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn finish_reply(
    query: &[u8],
    reply: &[u8],
    policy: &AddressPolicy,
    proxy_dnssec: bool,
    edns_packet_max: u16,
    filter_rr: &[u16],
    local: Option<&LocalDnsService>,
    routing: Option<&RoutingTable>,
) -> Result<FinishedReply, TcpServiceError> {
    finish_reply_with_edns(
        query,
        reply,
        policy,
        proxy_dnssec,
        edns_packet_max,
        filter_rr,
        local,
        routing,
        None,
        None,
        false,
        None,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_reply_with_edns(
    query: &[u8],
    reply: &[u8],
    policy: &AddressPolicy,
    proxy_dnssec: bool,
    edns_packet_max: u16,
    filter_rr: &[u16],
    local: Option<&LocalDnsService>,
    routing: Option<&RoutingTable>,
    edns: Option<(&crate::config::edns::EdnsConfig, IpAddr)>,
    mut cache: Option<&mut TcpCacheSink<'_>>,
    no_cache: bool,
    now: Option<i64>,
    cached_name: bool,
) -> Result<FinishedReply, TcpServiceError> {
    if edns.is_some_and(|(config, source)| {
        !super::edns_policy::check_reply_source(reply, config, source)
    }) {
        // forward.c tcp_request sets m=0 after process_reply mismatch, clears
        // have_pseudoheader, and takes make_local_answer's plain REFUSED.
        return Ok(FinishedReply {
            packet: error_reply(query, 5)?,
            bogus: None,
            from_upstream: false,
        });
    }
    let upstream_cd = Header::parse(reply)?.flags & 0x10 != 0;
    let has_cache_sink = cache.is_some();
    let query_header = Header::parse(query)?;
    let scan = find_pseudoheader(query, true)?;
    let do_bit = scan.opt.as_ref().is_some_and(|opt| opt.dnssec_ok());
    // A complete TCP frame may contain a clipped RR. C runs bogus/extract
    // policy before resize_packet, just as for a received UDP datagram.
    let envelope = prepare_udp_reply(
        reply,
        ReplyPolicy {
            client_had_opt: scan.opt.is_some(),
            checking_disabled: query_header.flags & 0x10 != 0,
            proxy_dnssec,
            edns_packet_max,
        },
    )?;
    let mut packet = envelope.packet;
    let mut bogus = None;
    // process_reply captures the full RCODE before possibly stripping OPT.
    // Do not reinterpret an extended error as NOERROR after that strip.
    if matches!(envelope.rcode, 0 | 3) {
        apply_known_local_nxdomain(&mut packet, envelope.rcode, |name| {
            super::reply::known_name(
                name,
                local,
                routing,
                cached_name,
                now.unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |time| time.as_secs() as i64)
                }),
            )
        })?;
        apply_static_aliases(&mut packet, &policy.static_aliases, envelope.rcode)
            .map_err(TcpServiceError::Process)?;
        let extraction = super::cache::Extraction::from_source(
            super::forward_service::edns_cache_query(query),
            no_cache,
            query_header.flags & 0x10 != 0,
            upstream_cd,
        );
        let cache_failed = cache
            .as_mut()
            .is_some_and(|sink| sink(&mut packet, policy, envelope.rcode, extraction).is_err());
        if cache_failed {
            super::process::reject_malformed_reply(&mut packet)?;
        }
        // Read the match before process_admitted_reply removes all answer
        // records. Only its bogus decision is allowed to publish this event.
        let bogus_candidate =
            super::process::bogus_cache_entry(&packet, Header::parse(&packet)?.answers, policy);
        let report = process_admitted_reply(&mut packet, policy, envelope.rcode)
            .map_err(TcpServiceError::Process)?;
        if report.bogus_nxdomain {
            bogus = bogus_candidate;
        }
        let ede = if report.blocked_rebind || report.bogus_nxdomain {
            Some(15)
        } else if report.malformed_address || cache_failed {
            Some(0)
        } else {
            None
        };
        if let Some(ede) = ede {
            if find_pseudoheader(&packet, false)?.opt.is_some() {
                add_ede(&mut packet, edns_packet_max, do_bit, ede, TCP_LIMIT)?;
            }
        }
        // C's process_reply only applies configured filtering to a complete
        // NOERROR answer. NXDOMAIN authority data and TC prefixes bypass the
        // rrfilter branch entirely.
        if envelope.rcode == 0 && Header::parse(&packet)?.flags & 0x0200 == 0 {
            let filtered = filter_rrs(&mut packet, filter_rr)?.matched != 0;
            if filtered && find_pseudoheader(&packet, false)?.opt.is_some() {
                add_ede(&mut packet, edns_packet_max, do_bit, 17, TCP_LIMIT)?;
            }
        }
    }
    resize_reply(&mut packet);
    if has_cache_sink {
        bogus = None;
    }
    Ok(FinishedReply {
        packet,
        bogus,
        from_upstream: true,
    })
}

/// EDE insertion/replacement follows edns0.c::add_pseudoheader, including its
/// strict option-loop bound and relocation of a non-final OPT. Other EDNS
/// decoration is deliberately not inferred from the UDP dispatcher.
pub(super) fn add_ede(
    packet: &mut Vec<u8>,
    max: u16,
    set_do: bool,
    ede: u16,
    limit: usize,
) -> Result<(), WireError> {
    super::edns_policy::add_pseudoheader(
        packet,
        max,
        limit,
        Some(15),
        &ede.to_be_bytes(),
        set_do,
        super::edns_policy::Replace::Replace,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;
    use crate::dns::wire::{Name, PacketWriter, Section};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn completion_sink_precedes_filter_and_preserves_original_cd_admission() {
        use super::super::cache::Extraction;
        let owner = Name::from_ascii("sink.test").unwrap();
        for (no_cache, request_cd, upstream_cd, expected) in [
            (true, false, false, Extraction::ExtractOnly),
            (false, true, false, Extraction::ExtractOnly),
            (false, false, true, Extraction::ExtractOnly),
            (false, false, false, Extraction::Commit),
        ] {
            let mut request =
                PacketWriter::new(1, 0x100 | if request_cd { 0x10 } else { 0 }, 1232).unwrap();
            request.question(&owner, 16, 1).unwrap();
            let request = request.finish();
            let mut response =
                PacketWriter::new(1, 0x8180 | if upstream_cd { 0x10 } else { 0 }, 1232).unwrap();
            response.question(&owner, 16, 1).unwrap();
            response
                .record_at(Section::Answer, 12, 16, 1, 600, &[1, b'x'])
                .unwrap();
            let response = response.finish();
            let mut observed = None;
            let mut sink = |packet: &mut Vec<u8>, _: &AddressPolicy, rcode, mode| {
                assert_eq!(Header::parse(packet).unwrap().answers, 1);
                assert_eq!(rcode, 0);
                assert_eq!(Header::parse(packet).unwrap().flags & 0x10 != 0, request_cd);
                observed = Some(mode);
                Ok(())
            };
            let result = finish_reply_with_edns(
                &request,
                &response,
                &Default::default(),
                false,
                1232,
                &[16],
                None,
                None,
                None,
                Some(&mut sink),
                no_cache,
                Some(100),
                false,
            )
            .unwrap();
            assert_eq!(observed, Some(expected));
            assert_eq!(Header::parse(&result.packet).unwrap().answers, 0);
        }
    }

    fn query(opt: bool) -> Vec<u8> {
        let mut writer = PacketWriter::new(0x2930, 0x110, 1232).unwrap();
        writer
            .question(&Name::from_ascii("caller.test").unwrap(), 1, 1)
            .unwrap();
        if opt {
            writer
                .record(Section::Additional, &Name::root(), 41, 4096, 0x8000, &[])
                .unwrap();
        }
        writer.finish()
    }

    #[test]
    fn no_route_is_refused_with_not_ready_only_for_edns_clients() {
        let mut config = DnsConfig::default();
        config
            .apply(&lex_line(b"no-resolv").unwrap().unwrap())
            .unwrap();
        let mut service = TcpDnsService::new(&config, &[], 1232).unwrap();
        for with_opt in [false, true] {
            let packet = service
                .handle(
                    &query(with_opt),
                    Instant::now() + Duration::from_secs(2),
                    &|| false,
                )
                .unwrap();
            // Exact C tcp_caller_diff corpus freezes these flags/error fields.
            assert_eq!(Header::parse(&packet).unwrap().flags, 0x8195);
            let opt = find_pseudoheader(&packet, true).unwrap().opt;
            assert_eq!(opt.is_some(), with_opt);
            if let Some(opt) = opt {
                assert_eq!(opt.record.class, 1232);
                assert!(opt.dnssec_ok());
                assert_eq!(
                    opt.options().next().unwrap().unwrap(),
                    (15, [0, 14].as_slice())
                );
            }
        }
    }

    #[test]
    fn forwards_original_tcp_query_and_keeps_c_reply_id_policy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let request = query(false);
        let expected_request = request.clone();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).unwrap();
            let mut packet = vec![0; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut packet).unwrap();
            assert_eq!(packet, expected_request); // No UDP-added empty OPT.
            let mut header = Header::parse(&packet).unwrap();
            header.id = 0xabcd;
            header.flags = 0x8020;
            header.write(&mut packet).unwrap();
            stream
                .write_all(&(packet.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&packet).unwrap();
        });
        let mut config = DnsConfig::default();
        config
            .apply(&lex_line(b"no-resolv").unwrap().unwrap())
            .unwrap();
        config
            .apply(
                &lex_line(format!("server=127.0.0.1#{}", endpoint.port()).as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut service = TcpDnsService::new(&config, &[], 1232).unwrap();
        let packet = service
            .handle(&request, Instant::now() + Duration::from_secs(2), &|| false)
            .unwrap();
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.id, 0xabcd);
        assert_eq!(header.flags, 0x8090); // CD restored, AD cleared, RA set.
        assert_eq!(header.additionals, 0);
        drop(service);
        worker.join().unwrap();
    }

    #[test]
    fn bogus_cache_event_keeps_matching_owner_and_ttl_before_rewriting() {
        let query_name = Name::from_ascii("caller.test").unwrap();
        let target = Name::from_ascii("target.test").unwrap();
        for checking_disabled in [false, true] {
            let mut request = query(true);
            request[3] = if checking_disabled { 0x10 } else { 0 };
            let mut writer = PacketWriter::new(0x2930, 0x8180, 1232).unwrap();
            writer.question(&query_name, 1, 1).unwrap();
            writer
                .record(Section::Answer, &query_name, 5, 1, 37, target.as_wire())
                .unwrap();
            writer
                .record(Section::Answer, &target, 1, 1, 120, &[8, 8, 4, 4])
                .unwrap();
            writer
                .record(Section::Additional, &Name::root(), 41, 1232, 0x8000, &[])
                .unwrap();
            let mut reply = writer.finish();
            let policy = AddressPolicy {
                bogus_addresses: vec![super::super::process::AddressPrefix::new(
                    "8.8.4.4".parse().unwrap(),
                    32,
                )
                .unwrap()],
                ..AddressPolicy::default()
            };
            let finished =
                finish_reply(&request, &reply, &policy, false, 1232, &[], None, None).unwrap();
            assert_eq!(finished.bogus, Some((target.clone(), 120)));
            let header = Header::parse(&finished.packet).unwrap();
            assert_eq!((header.rcode(), header.answers), (3, 0));
            assert_eq!(header.flags & 0x10 != 0, checking_disabled);

            // TC and an original NXDOMAIN bypass check_for_bogus_wildcard.
            for flags in [0x8380u16, 0x8183] {
                reply[2..4].copy_from_slice(&flags.to_be_bytes());
                let finished =
                    finish_reply(&request, &reply, &policy, false, 1232, &[], None, None).unwrap();
                assert_eq!(finished.bogus, None);
            }
        }
    }

    #[test]
    fn clipped_tcp_rr_runs_bogus_before_malformed_address_policy() {
        let name = Name::from_ascii("caller.test").unwrap();
        let policy = AddressPolicy {
            bogus_addresses: vec![super::super::process::AddressPrefix::new(
                "8.8.4.4".parse().unwrap(),
                32,
            )
            .unwrap()],
            ..AddressPolicy::default()
        };
        for (address, rcode) in [([8, 8, 4, 4], 3), ([8, 8, 4, 5], 2)] {
            for later_match in [false, true] {
                let mut writer = PacketWriter::new(0x2930, 0x8180, 1232).unwrap();
                writer.question(&name, 1, 1).unwrap();
                writer
                    .record(Section::Answer, &name, 1, 1, 120, &address)
                    .unwrap();
                if later_match {
                    writer
                        .record(Section::Answer, &name, 1, 1, 15, &[8, 8, 4, 4])
                        .unwrap();
                }
                let mut reply = writer.finish();
                let fixed = Message::parse(&reply)
                    .unwrap()
                    .records(Section::Answer)
                    .next()
                    .unwrap()
                    .fixed;
                reply[fixed + 8..fixed + 10].copy_from_slice(&u16::MAX.to_be_bytes());
                let finished =
                    finish_reply(&query(false), &reply, &policy, false, 1232, &[], None, None)
                        .unwrap();
                let header = Header::parse(&finished.packet).unwrap();
                assert_eq!((header.rcode(), header.answers), (rcode, 0));
                assert_eq!(finished.bogus, (rcode == 3).then(|| (name.clone(), 120)));
            }
        }
    }

    #[test]
    fn io_exhaustion_returns_network_error_ede() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        drop(listener);
        let config = DnsConfig::default();
        let mut service = TcpDnsService::new(&config, &[endpoint], 1232).unwrap();
        let packet = service
            .handle(
                &query(true),
                Instant::now() + Duration::from_secs(2),
                &|| false,
            )
            .unwrap();
        assert_eq!(Header::parse(&packet).unwrap().rcode(), 5);
        let scan = find_pseudoheader(&packet, false).unwrap();
        assert_eq!(
            scan.opt.unwrap().options().next().unwrap().unwrap(),
            (15, [0, 23].as_slice())
        );
    }
}
