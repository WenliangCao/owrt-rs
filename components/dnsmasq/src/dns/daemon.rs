//! DNS daemon integration for the UDP client/upstream path.
//!
//! This is deliberately a small, socket-independent boundary.  The containing
//! process owns the listening UDP socket: [`DnsDaemon::handle_udp`] accepts one
//! client datagram and either returns a local answer or starts an upstream
//! transaction, while [`DnsDaemon::poll`] turns completed upstream events into
//! client responses. TCP listeners, resolver-file polling, and the remaining
//! `forward.c::process_reply` cache policy are separate work; direct positive
//! A/AAAA cache insertion and lookup are wired below.

use super::cache::{Cache, CacheCounters, Policy as CachePolicy, StalePolicy};
#[cfg(test)]
use super::cache::{Kind, Record};
use super::cache_engine::{CacheContext, CacheError, CachedAnswer};
use super::forward::{Client, Options as ForwardOptions, QueryId, Random, Scope};
use super::forward_service::ForwardDispatcher;
use super::process::{
    apply_doctor, apply_static_aliases, ignore_reply, process_admitted_reply, AddressPolicy,
    AddressPrefix, ProcessAction, ProcessError,
};
use super::reply::{
    apply_known_local_nxdomain, limit_udp_reply, prepare_udp_reply, resize_reply, ReplyPolicy,
};
use super::routing::{RouteReason, RoutingError, RoutingTable};
use super::service::{LocalDnsService, ServiceError};
use super::upstream::{
    Lifetime, OsRandom, ResolveError, UncheckedReply, UpstreamEvent, UpstreamResolver,
};
use super::wire::{find_pseudoheader, Name, WireError};
#[cfg(test)]
use super::wire::{Header, Message, PacketWriter, Question as WireQuestion, Section};
use crate::config::dns::DnsConfig;
use crate::config::{Error as ConfigError, FastRetry};
use crate::hosts::Hosts;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Transport-independent identity of a DNS client datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequest {
    pub source: SocketAddr,
    pub destination: IpAddr,
    pub interface: u32,
}

/// A response ready for the containing process to send on its client socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResponse {
    pub destination: SocketAddr,
    pub listener: Option<super::forward::SocketToken>,
    pub packet: Vec<u8>,
}

/// A synchronous record callback with this daemon's current counters, before
/// replacing RDATA or committing the current reply's cache transaction. The
/// caller captures other engines' metrics before acquiring the DNS owner lock.
pub type ReplyDoctor<'a> = dyn FnMut(&[u8], u32, IpAddr, CacheCounters, super::forward::ForwardCounters) -> Option<IpAddr>
    + 'a;

/// Cumulative failure counts for this daemon instance. Cache/hosts reloads do
/// not reset them. Counts are bounded state, not an undrained failure queue.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PollFailures {
    pub timeouts: u64,
    pub upstream_errors: u64,
    pub invalid_replies: u64,
    pub recipient_errors: u64,
    pub poll_errors: u64,
}

/// Result of admitting one client query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    /// A local answer is ready to send immediately.
    Local(Vec<u8>),
    /// A positive answer synthesized from the daemon's forward cache.
    Cached(Vec<u8>),
    /// An expired-but-retained answer. The caller must attempt this reply
    /// before calling `refresh_udp_on_listener` with the original request.
    Stale(Vec<u8>),
    /// The query was admitted to the upstream transaction table.
    Forwarded(QueryId),
    /// The query exceeds the admitted size or reaches an unimplemented local
    /// routing boundary. A missing upstream route is answered with REFUSED.
    Dropped,
}

/// Runtime knobs needed by the DNS integration.  Unsupported options must be
/// rejected by the caller before constructing a daemon; these fields only
/// describe behaviour implemented by the existing forwarding modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonOptions {
    pub forward_max: usize,
    pub fast_retry: Option<FastRetry>,
    pub edns_packet_max: u16,
    pub proxy_dnssec: bool,
    pub local_ttl: u32,
    pub max_udp: usize,
    pub upstream_lifetime: Lifetime,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            forward_max: 150,
            fast_retry: None,
            edns_packet_max: 1232,
            proxy_dnssec: false,
            local_ttl: 0,
            max_udp: 1232 + 255 + 10,
            upstream_lifetime: Lifetime::ForwardTable,
        }
    }
}

#[derive(Debug)]
pub enum DaemonError {
    Config(ConfigError),
    MissingDefaultResolvers,
    Routing(RoutingError),
    Wire(WireError),
    Local(ServiceError),
    Process(ProcessError),
    Upstream(ResolveError),
    Io(io::Error),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(f, "DNS configuration: {error}"),
            Self::MissingDefaultResolvers => f.write_str("no default resolvers available"),
            Self::Routing(error) => write!(f, "DNS routing: {error:?}"),
            Self::Wire(error) => write!(f, "DNS wire: {error}"),
            Self::Local(error) => write!(f, "local DNS service: {error:?}"),
            Self::Process(error) => write!(f, "upstream reply policy: {error:?}"),
            Self::Upstream(error) => write!(f, "upstream DNS: {error:?}"),
            Self::Io(error) => write!(f, "DNS I/O: {error}"),
        }
    }
}
impl std::error::Error for DaemonError {}
impl From<ConfigError> for DaemonError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}
impl From<RoutingError> for DaemonError {
    fn from(value: RoutingError) -> Self {
        Self::Routing(value)
    }
}
impl From<WireError> for DaemonError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}
impl From<CacheError> for DaemonError {
    fn from(value: CacheError) -> Self {
        match value {
            CacheError::Wire(error) => Self::Wire(error),
            CacheError::Local(error) => Self::Local(ServiceError::from(error)),
        }
    }
}
impl From<ServiceError> for DaemonError {
    fn from(value: ServiceError) -> Self {
        Self::Local(value)
    }
}
impl From<ProcessError> for DaemonError {
    fn from(value: ProcessError) -> Self {
        Self::Process(value)
    }
}
impl From<ResolveError> for DaemonError {
    fn from(value: ResolveError) -> Self {
        Self::Upstream(value)
    }
}
impl From<io::Error> for DaemonError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// The integrated local-routing/upstream UDP daemon boundary.
pub struct DnsDaemon<R = OsRandom> {
    local: LocalDnsService,
    routing: RoutingTable,
    upstream: UpstreamResolver<R>,
    cache: Option<Cache>,
    cache_counters: CacheCounters,
    negative_ttl: u32,
    negative_cache: bool,
    policy: AddressPolicy,
    proxy_dnssec: bool,
    max_udp: usize,
    edns_packet_max: u16,
    poll_failures: PollFailures,
}

impl DnsDaemon<OsRandom> {
    pub fn new(
        config: DnsConfig,
        hosts: Hosts,
        default_resolvers: &[SocketAddr],
        options: DaemonOptions,
    ) -> Result<Self, DaemonError> {
        Self::with_random(config, hosts, default_resolvers, options, OsRandom::new()?)
    }
}

impl<R: Random> DnsDaemon<R> {
    /// Build the daemon only after validating all platform-dependent routing
    /// inputs. `default_resolvers` is the already parsed resolver-file state;
    /// this constructor intentionally does not read files or resolve names.
    /// `hosts` includes the configured prefix and subsequently read files.
    pub fn with_random(
        mut config: DnsConfig,
        hosts: Hosts,
        default_resolvers: &[SocketAddr],
        options: DaemonOptions,
        random: R,
    ) -> Result<Self, DaemonError> {
        config.finalize()?;
        config.validate_ready().map_err(DaemonError::Config)?;
        validate_runtime_config(&config)?;
        if options.forward_max == 0 {
            return Err(DaemonError::Config(ConfigError(
                "dns-forward-max must be positive",
            )));
        }
        if !config.no_resolv && default_resolvers.is_empty() {
            return Err(DaemonError::MissingDefaultResolvers);
        }

        let routing = RoutingTable::from_runtime_config(&config, default_resolvers)?;
        let groups = routing.dispatcher_groups();
        let fast_retry = options.fast_retry.map(|retry| ForwardOptions {
            forward_max: options.forward_max,
            case_randomization: config.do_0x20_encode && !config.no_0x20_encode,
            fast_retry_ms: retry.interval_ms,
            fast_retry_timeout_s: i64::from(retry.timeout_seconds),
        });
        let forward_options = fast_retry.unwrap_or(ForwardOptions {
            forward_max: options.forward_max,
            case_randomization: config.do_0x20_encode && !config.no_0x20_encode,
            ..ForwardOptions::default()
        });
        let dispatcher = ForwardDispatcher::new(forward_options, groups, options.edns_packet_max);
        let upstream =
            UpstreamResolver::with_lifetime(dispatcher, random, options.upstream_lifetime)?;
        let policy = address_policy(&config)?;
        let local = LocalDnsService::new_with_limits(
            config,
            hosts,
            options.local_ttl,
            options.max_udp.max(512),
            options.edns_packet_max,
        );
        Ok(Self {
            local,
            routing,
            upstream,
            cache: None,
            cache_counters: CacheCounters::default(),
            negative_ttl: 0,
            negative_cache: false,
            policy,
            proxy_dnssec: options.proxy_dnssec,
            max_udp: options.max_udp.max(512),
            edns_packet_max: options.edns_packet_max,
            poll_failures: PollFailures::default(),
        })
    }

    pub fn pending_count(&self) -> usize {
        self.upstream.pending_count()
    }

    pub fn poll_failures(&self) -> PollFailures {
        self.poll_failures
    }

    /// Cumulative real cache events since initialization or the last reload.
    /// Reading is non-destructive and independent of ubus enablement.
    pub fn cache_counters(&self) -> CacheCounters {
        self.cache_counters
    }

    /// PRIVATE correctness snapshot only. Full cloning has not passed the
    /// product resource gate, and stale TCP close/refresh is not implemented.
    pub fn snapshot_tcp_cache(
        &self,
        accepted_at: i64,
    ) -> Result<super::tcp_cache::TcpCache, DaemonError> {
        if self
            .cache
            .as_ref()
            .is_some_and(|cache| cache.policy().stale != StalePolicy::Disabled)
        {
            return Err(ConfigError(
                "private TCP cache prototype excludes stale cache policy".into(),
            )
            .into());
        }
        Ok(super::tcp_cache::TcpCache {
            cache: self.cache.clone(),
            counters: self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
            accepted_at,
        })
    }

    pub fn import_tcp_cache(
        &mut self,
        transaction: super::cache::CacheTransaction,
        now: i64,
        local: &LocalDnsService,
    ) -> bool {
        let Some(cache) = &mut self.cache else {
            return false;
        };
        CacheContext {
            cache,
            counters: &mut self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
        }
        .import_transaction(transaction, now, local)
    }

    pub fn forward_counters(&self) -> super::forward::ForwardCounters {
        self.upstream.counters()
    }

    /// Replace the reloaded hosts snapshot and discard dynamic DNS answers.
    /// Resolver routing and in-flight upstream requests retain their owners.
    pub fn reload_hosts(&mut self, hosts: Hosts) {
        self.local.hosts = hosts;
        if let Some(cache) = &mut self.cache {
            cache.clear_counted(&mut self.cache_counters);
        }
    }

    /// Publish a completed DHCP source against this parent's forwarded cache.
    /// The caller installs the result before allowing the DHCP ACK to be sent.
    pub fn publish_lease_names(
        &mut self,
        records: &[crate::dhcp::persistence::DnsLeaseRecord<'_>],
        hosts: &mut Hosts,
        cnames: &[crate::config::records::Cname],
        policy: super::lease_names::LeasePolicy,
    ) -> super::lease_names::LeaseNames {
        match self.cache.as_mut() {
            Some(cache) => {
                super::lease_names::LeaseNames::build(records, hosts, cnames, policy, cache)
            }
            None => super::lease_names::LeaseNames::build(records, hosts, cnames, policy, &mut ()),
        }
    }

    pub fn rebuild_lease_names(
        &mut self,
        previous: &super::lease_names::LeaseNames,
        hosts: &mut Hosts,
        cnames: &[crate::config::records::Cname],
    ) -> super::lease_names::LeaseNames {
        match self.cache.as_mut() {
            Some(cache) => previous.rebuild(hosts, cnames, cache),
            None => previous.rebuild(hosts, cnames, &mut ()),
        }
    }

    /// Enable the positive forward cache after daemon construction.  Keeping
    /// this explicit lets the caller pass scalar options (cache-size and TTL
    /// bounds) without duplicating them in `DnsConfig`.
    pub fn enable_cache(
        &mut self,
        capacity: usize,
        min_ttl: u32,
        max_ttl: u32,
        stale: StalePolicy,
    ) {
        self.cache = Some(Cache::new(
            capacity,
            CachePolicy {
                min_ttl,
                max_ttl,
                max_reply_ttl: 0,
                stale,
            },
        ));
        self.cache_counters = CacheCounters::default();
    }

    /// Enable the no-SOA NXDOMAIN cache fallback. SOA/NODATA synthesis is
    /// intentionally separate; a zero TTL keeps this path disabled.
    pub fn enable_negative_cache(&mut self, negative_ttl: u32, enabled: bool) {
        self.negative_ttl = negative_ttl;
        self.negative_cache = enabled;
    }

    /// Admit a single client UDP payload. Local answers are returned directly;
    /// forwarded queries are completed by [`Self::poll`].
    pub fn handle_udp(
        &mut self,
        query: &[u8],
        client: ClientRequest,
    ) -> Result<QueryResult, DaemonError> {
        if query.len() > self.max_udp {
            return Ok(QueryResult::Dropped);
        }
        match super::udp_query::inspect(query, self.edns_packet_max) {
            super::udp_query::Admission::Drop => return Ok(QueryResult::Dropped),
            super::udp_query::Admission::Reply(reply) => return Ok(QueryResult::Local(reply)),
            super::udp_query::Admission::Continue => {}
        }
        if let Some(answer) = self.local.handle_udp(query)? {
            return Ok(QueryResult::Local(answer));
        }
        self.forward_udp(query, client)
    }

    /// Continue only after the caller's shared local generation returned
    /// no answer. This avoids a second lookup/rotation in a private snapshot.
    pub fn forward_udp(
        &mut self,
        query: &[u8],
        client: ClientRequest,
    ) -> Result<QueryResult, DaemonError> {
        self.forward_udp_on_listener(query, client, None)
    }

    /// Preserve the receiving socket when multiple listeners share one
    /// forwarding table. Coalesced recipients retain their own listener.
    pub fn forward_udp_on_listener(
        &mut self,
        query: &[u8],
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
    ) -> Result<QueryResult, DaemonError> {
        self.forward_udp_inner(query, client, listener, None)
    }

    /// Cached aliases can terminate at a current local name. Keep that
    /// lookup/expiry/rotation in the same parent generation as direct answers.
    pub fn forward_udp_on_listener_with_local(
        &mut self,
        query: &[u8],
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
        local: &mut LocalDnsService,
    ) -> Result<QueryResult, DaemonError> {
        self.forward_udp_inner(query, client, listener, Some(local))
    }

    fn forward_udp_inner(
        &mut self,
        query: &[u8],
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
        local: Option<&mut LocalDnsService>,
    ) -> Result<QueryResult, DaemonError> {
        if query.len() > self.max_udp {
            return Ok(QueryResult::Dropped);
        }
        let question = super::forward::Question::parse(query).map_err(DaemonError::Wire)?;
        let answer = self.cached_answer_at_with_local(query, &question, unix_seconds(), local)?;
        if let Some(packet) = answer.packet {
            return Ok(if answer.stale {
                QueryResult::Stale(packet)
            } else {
                QueryResult::Cached(packet)
            });
        }
        self.submit_upstream(query, &question, client, listener, true)
    }

    /// Submit the original query after attempting a stale client reply, as
    /// receive_query does before forward_query(fd=-1). Normal coalescing and
    /// cache insertion still apply; this recipient receives no second reply.
    pub fn refresh_udp_on_listener(
        &mut self,
        query: &[u8],
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
    ) -> Result<QueryResult, DaemonError> {
        let question = super::forward::Question::parse(query)?;
        self.submit_upstream(query, &question, client, listener, false)
    }

    fn submit_upstream(
        &mut self,
        query: &[u8],
        question: &super::forward::Question,
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
        reply_requested: bool,
    ) -> Result<QueryResult, DaemonError> {
        let route = self
            .routing
            .select(&question.name, question.rrtype, question.class, false);
        let Some(group) = route.upstream_group() else {
            if route.reason == RouteReason::NoMatchingRule {
                let limit = find_pseudoheader(query, true)?
                    .opt
                    .map_or(512, |opt| usize::from(opt.udp_size(self.edns_packet_max)));
                // forward.c::forward_query: EDE_NOT_READY for no server.
                // UDP's add_pseudoheader clears DO, unlike the TCP caller.
                return Ok(QueryResult::Local(super::tcp_service::refusal(
                    query,
                    self.edns_packet_max,
                    14,
                    limit,
                    false,
                )?));
            }
            return Ok(QueryResult::Dropped);
        };
        let client = Client {
            source: client.source,
            destination: client.destination,
            interface: client.interface,
            listener,
            reply_requested,
            udp_limit: 512,
            log_id: u64::from(question.rrtype),
        };
        let submission = match self.upstream.start_udp(query, client, group, Scope::Shared) {
            Ok(submission) => submission,
            Err(ResolveError::Dispatch(super::forward_service::DispatchError::Submit(
                super::forward::SubmitError::GroupFull | super::forward::SubmitError::DuplicateFull,
            ))) => {
                return Ok(super::udp_query::table_full(query, self.edns_packet_max)
                    .map_or(QueryResult::Dropped, QueryResult::Local))
            }
            Err(ResolveError::Io(_)) => {
                // forward_query cancels this transaction when every socket /
                // send attempt fails, then makes a local REFUSED with NETERR.
                // start_udp has already released it. Background refreshes
                // return Local too: the parent counts this fallback without
                // sending a second response to the stale-answer recipient.
                let limit = find_pseudoheader(query, true)?
                    .opt
                    .map_or(512, |opt| usize::from(opt.udp_size(self.edns_packet_max)));
                return Ok(QueryResult::Local(super::tcp_service::refusal(
                    query,
                    self.edns_packet_max,
                    23,
                    limit,
                    false,
                )?));
            }
            Err(error) => return Err(error.into()),
        };
        Ok(QueryResult::Forwarded(submission.id))
    }

    /// Poll upstream sockets and produce client-visible UDP replies.  The
    /// reply envelope is applied, but this intentionally does not claim the
    /// full C `process_reply` contract (cache/SOA/ubus/TCP fallback remain
    /// outside this adapter).
    pub fn poll(&mut self, wait: Duration) -> Result<Vec<ClientResponse>, DaemonError> {
        self.poll_inner(wait, None, None)
    }

    /// Complete replies using the parent's current local-name generation.
    /// A reload or synchronous lease publication can change it while an
    /// upstream query is pending; callers must not substitute an old clone.
    pub fn poll_with_local(
        &mut self,
        wait: Duration,
        local: &LocalDnsService,
    ) -> Result<Vec<ClientResponse>, DaemonError> {
        self.poll_inner(wait, Some(local), None)
    }

    pub fn poll_with_local_doctor(
        &mut self,
        wait: Duration,
        local: &LocalDnsService,
        doctor: &mut ReplyDoctor<'_>,
    ) -> Result<Vec<ClientResponse>, DaemonError> {
        self.poll_inner(wait, Some(local), Some(doctor))
    }

    fn poll_inner(
        &mut self,
        wait: Duration,
        external_local: Option<&LocalDnsService>,
        doctor: Option<&mut ReplyDoctor<'_>>,
    ) -> Result<Vec<ClientResponse>, DaemonError> {
        let policy = self.policy.clone();
        let events = self.upstream.poll_with_filter(wait, move |packet| {
            ignore_reply(packet, &policy).unwrap_or(false)
        });
        let events = match events {
            Ok(events) => events,
            Err(error) => {
                self.poll_failures.poll_errors = self.poll_failures.poll_errors.saturating_add(1);
                return Err(error.into());
            }
        };
        Ok(self.finish_upstream_events_with_doctor(events, unix_seconds(), external_local, doctor))
    }

    #[cfg(test)]
    fn finish_upstream_events(
        &mut self,
        events: Vec<UpstreamEvent>,
        now: i64,
        external_local: Option<&LocalDnsService>,
    ) -> Vec<ClientResponse> {
        self.finish_upstream_events_with_doctor(events, now, external_local, None)
    }

    fn finish_upstream_events_with_doctor(
        &mut self,
        events: Vec<UpstreamEvent>,
        now: i64,
        external_local: Option<&LocalDnsService>,
        mut doctor: Option<&mut ReplyDoctor<'_>>,
    ) -> Vec<ClientResponse> {
        let mut responses = Vec::new();
        for event in events {
            let mut reply = match event.result {
                Ok(reply) => reply,
                Err(
                    ResolveError::Timeout
                    | ResolveError::Released(super::forward::ReleaseReason::Expired),
                ) => {
                    self.poll_failures.timeouts = self.poll_failures.timeouts.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    self.poll_failures.upstream_errors =
                        self.poll_failures.upstream_errors.saturating_add(1);
                    continue;
                }
            };
            let rcode =
                match self.process_completed_reply(&mut reply, now, external_local, &mut doctor) {
                    Ok(rcode) => rcode,
                    Err(_) => {
                        self.poll_failures.invalid_replies =
                            self.poll_failures.invalid_replies.saturating_add(1);
                        continue;
                    }
                };
            for recipient in &reply.recipients {
                if !recipient.client.reply_requested {
                    continue;
                }
                match self.recipient_packet(&reply, recipient, rcode) {
                    Ok(Some(packet)) => responses.push(ClientResponse {
                        destination: recipient.client.source,
                        listener: recipient.client.listener,
                        packet,
                    }),
                    Ok(None) => {}
                    Err(_) => {
                        self.poll_failures.recipient_errors =
                            self.poll_failures.recipient_errors.saturating_add(1)
                    }
                }
            }
        }
        responses
    }

    fn process_completed_reply(
        &mut self,
        reply: &mut UncheckedReply,
        now: i64,
        external_local: Option<&LocalDnsService>,
        doctor: &mut Option<&mut ReplyDoctor<'_>>,
    ) -> Result<u16, DaemonError> {
        let envelope = prepare_udp_reply(
            &reply.packet,
            ReplyPolicy {
                client_had_opt: reply.flags.had_opt,
                checking_disabled: reply.flags.checking_disabled,
                proxy_dnssec: self.proxy_dnssec,
                edns_packet_max: self.edns_packet_max,
            },
        )?;
        let rcode = envelope.rcode;
        reply.packet = envelope.packet;
        // These common stages happen once, before both cache insertion and
        // recipient copies. Repeating known-local after the doctor would
        // restore AA and repeating alias rules could rewrite an address twice.
        apply_known_local_nxdomain(&mut reply.packet, rcode, |name| {
            let local = external_local.unwrap_or(&self.local);
            super::local::known_forwarded_domain_with_leases(
                &local.config,
                &local.hosts,
                name,
                &local.leases,
                now,
            ) || self.routing.has_configured_address(name)
        })?;
        if let Some(doctor) = doctor.as_mut() {
            let cache = self.cache_counters;
            let forward = self.upstream.counters();
            let mut notify = |name: &[u8], ttl, address| doctor(name, ttl, address, cache, forward);
            apply_doctor(
                &mut reply.packet,
                &self.policy.static_aliases,
                rcode,
                Some(&mut notify),
            )?;
        } else {
            apply_static_aliases(&mut reply.packet, &self.policy.static_aliases, rcode)?;
        }
        // Cache extraction has ordered side effects: a later malformed RR or
        // rebind rejection prevents commit but retains earlier old-RR removal.
        // Run it after doctor, before recipient-specific packet rewriting.
        if matches!(rcode, 0 | 3)
            && !reply.flags.no_cache
            && reply.cache_eligible
            && !reply.flags.ad_requested
            && !reply.flags.checking_disabled
        {
            if let Some(cache) = self.cache.as_mut() {
                CacheContext {
                    cache,
                    counters: &mut self.cache_counters,
                    negative_cache: self.negative_cache,
                    negative_ttl: self.negative_ttl,
                }
                .insert_reply_with_policy(
                    &reply.packet,
                    now,
                    external_local.unwrap_or(&self.local),
                    &self.policy,
                    rcode,
                );
            }
        }
        Ok(rcode)
    }

    fn recipient_packet(
        &self,
        reply: &UncheckedReply,
        recipient: &super::forward::Recipient,
        rcode: u16,
    ) -> Result<Option<Vec<u8>>, DaemonError> {
        let mut packet = reply.packet.clone();
        recipient.restore_question(&mut packet)?;
        let envelope = prepare_udp_reply(
            &packet,
            ReplyPolicy {
                client_had_opt: reply.flags.had_opt,
                checking_disabled: reply.flags.checking_disabled,
                proxy_dnssec: self.proxy_dnssec,
                edns_packet_max: self.edns_packet_max,
            },
        )?;
        let mut packet = envelope.packet;
        if matches!(rcode, 0 | 3) {
            let report = process_admitted_reply(&mut packet, &self.policy, rcode)?;
            if report.action == ProcessAction::Ignore {
                return Ok(None);
            }
            let ede = if report.blocked_rebind || report.bogus_nxdomain {
                Some(15)
            } else if report.malformed_address {
                Some(0)
            } else {
                None
            };
            if let Some(ede) = ede {
                if find_pseudoheader(&packet, false)?.opt.is_some() {
                    super::tcp_service::add_ede(
                        &mut packet,
                        self.edns_packet_max,
                        reply.flags.dnssec_ok,
                        ede,
                        usize::from(self.edns_packet_max),
                    )?;
                }
            }
        }
        resize_reply(&mut packet);
        Ok(Some(limit_udp_reply(&packet, recipient.client.udp_limit)?))
    }

    #[cfg(test)]
    fn cached_answer(
        &mut self,
        query: &[u8],
        question: &super::forward::Question,
    ) -> Result<Option<Vec<u8>>, DaemonError> {
        self.cached_answer_at(query, question, unix_seconds())
    }

    #[cfg(test)]
    fn cached_answer_at(
        &mut self,
        query: &[u8],
        question: &super::forward::Question,
        now: i64,
    ) -> Result<Option<Vec<u8>>, DaemonError> {
        self.cached_answer_at_with_local(query, question, now, None)
            .map(|answer| answer.packet)
    }

    fn cached_answer_at_with_local(
        &mut self,
        query: &[u8],
        question: &super::forward::Question,
        now: i64,
        external_local: Option<&mut LocalDnsService>,
    ) -> Result<CachedAnswer, DaemonError> {
        let Some(cache) = self.cache.as_mut() else {
            return Ok(CachedAnswer {
                packet: None,
                stale: false,
            });
        };
        CacheContext {
            cache,
            counters: &mut self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
        }
        .answer_udp(
            query,
            question,
            now,
            external_local.unwrap_or(&mut self.local),
            self.max_udp,
            self.edns_packet_max,
        )
        .map_err(Into::into)
    }

    #[cfg(test)]
    fn cache_reply_at(&mut self, packet: &[u8], now: i64) {
        let Ok(header) = Header::parse(packet) else {
            return;
        };
        let Some(cache) = self.cache.as_mut() else {
            return;
        };
        CacheContext {
            cache,
            counters: &mut self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
        }
        .insert_reply_with_policy(
            packet,
            now,
            &self.local,
            &Default::default(),
            header.rcode().into(),
        );
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

pub(super) fn address_policy(config: &DnsConfig) -> Result<AddressPolicy, DaemonError> {
    let mut rebind_domains = Vec::with_capacity(config.rebind_domains.len());
    for domain in &config.rebind_domains {
        let text = std::str::from_utf8(domain).map_err(|_| ConfigError("bad rebind domain"))?;
        rebind_domains.push(Name::from_ascii(text)?.canonical_wire());
    }
    Ok(AddressPolicy {
        stop_rebind: config.stop_rebind,
        rebind_localhost_ok: config.rebind_localhost_ok,
        rebind_domains,
        static_aliases: config
            .aliases
            .iter()
            .map(|rule| super::doctor::Alias {
                from: rule.from,
                end: rule.end,
                to: rule.to,
                mask: rule.mask,
            })
            .collect(),
        bogus_addresses: config
            .bogus_addresses
            .iter()
            .map(|rule| AddressPrefix {
                address: rule.address,
                prefix: rule.prefix,
            })
            .collect(),
        ignore_addresses: config
            .ignore_addresses
            .iter()
            .map(|rule| AddressPrefix {
                address: rule.address,
                prefix: rule.prefix,
            })
            .collect(),
    })
}

pub(super) fn validate_runtime_config(config: &DnsConfig) -> Result<(), DaemonError> {
    if config.servers_file.is_some() {
        return Err(DaemonError::Config(ConfigError(
            "servers-file loading is not implemented by the DNS daemon",
        )));
    }
    if !config.interfaces.is_empty()
        || !config.excluded_interfaces.is_empty()
        || config.bind_interfaces
        || config.bind_dynamic
        || config.local_service_net
        || config.local_service_host
    {
        return Err(DaemonError::Config(ConfigError(
            "interface binding is owned by the containing listener",
        )));
    }
    if config.domain_needed || config.bogus_priv || config.no_poll || config.localise_queries {
        return Err(DaemonError::Config(ConfigError(
            "configured DNS policy is not implemented by the daemon",
        )));
    }
    if config.records.needs_hostname() {
        return Err(DaemonError::Config(ConfigError(
            "hostname-dependent local records need explicit hostname finalization",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "daemon_cache_tests.rs"]
mod cache_tests;

#[cfg(test)]
#[path = "daemon_stale_tests.rs"]
mod stale_tests;

#[cfg(test)]
#[path = "daemon_policy_tests.rs"]
mod policy_tests;

#[cfg(test)]
#[path = "daemon_poll_tests.rs"]
mod poll_tests;

#[cfg(test)]
#[path = "daemon_lease_cache_tests.rs"]
mod lease_cache_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{lex_line, validate_directive};
    use crate::dns::forward::Random;
    use crate::dns::wire::{Header, Name, PacketWriter, Section};
    use std::io;
    use std::net::UdpSocket;
    use std::thread;

    struct Counter(u32);
    impl Random for Counter {
        fn next_u32(&mut self) -> io::Result<u32> {
            self.0 += 1;
            Ok(self.0)
        }
    }

    fn apply(config: &mut DnsConfig, line: &[u8]) {
        let directive = lex_line(line).unwrap().unwrap();
        validate_directive(&directive).unwrap();
        config.apply(&directive).unwrap();
    }

    fn query(name: &str, id: u16) -> Vec<u8> {
        query_type(name, 1, id)
    }

    fn query_type(name: &str, qtype: u16, id: u16) -> Vec<u8> {
        query_type_flags(name, qtype, id, 0x100)
    }

    fn query_type_flags(name: &str, qtype: u16, id: u16, flags: u16) -> Vec<u8> {
        let name = Name::from_ascii(name).unwrap();
        let mut writer = PacketWriter::new(id, flags, 1232).unwrap();
        writer.question(&name, qtype, 1).unwrap();
        writer.finish()
    }

    fn soa_data() -> Vec<u8> {
        let mname = Name::from_ascii("ns.example.test").unwrap();
        let rname = Name::from_ascii("hostmaster.example.test").unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(mname.as_wire());
        data.extend_from_slice(rname.as_wire());
        data.extend_from_slice(&1u32.to_be_bytes()); // serial
        data.extend_from_slice(&2u32.to_be_bytes()); // refresh
        data.extend_from_slice(&3u32.to_be_bytes()); // retry
        data.extend_from_slice(&4u32.to_be_bytes()); // expire
        data.extend_from_slice(&10u32.to_be_bytes()); // MINIMUM
        data
    }

    fn options() -> DaemonOptions {
        DaemonOptions {
            upstream_lifetime: Lifetime::Fixed(Duration::from_secs(1)),
            ..DaemonOptions::default()
        }
    }

    #[test]
    fn local_and_unowned_queries_use_distinct_boundaries() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"no-resolv");
        apply(&mut config, b"host-record=router.test,192.0.2.1");
        let mut daemon = DnsDaemon::with_random(
            config.clone(),
            super::super::local::configured_hosts(&config, options().local_ttl),
            &[],
            options(),
            Counter(0),
        )
        .unwrap();
        assert!(matches!(
            daemon
                .handle_udp(
                    &query("router.test", 7),
                    ClientRequest {
                        source: "127.0.0.1:53000".parse().unwrap(),
                        destination: "127.0.0.1".parse().unwrap(),
                        interface: 0,
                    },
                )
                .unwrap(),
            QueryResult::Local(_)
        ));
        let QueryResult::Local(reply) = daemon
            .handle_udp(
                &query("unknown.test", 8),
                ClientRequest {
                    source: "127.0.0.1:53000".parse().unwrap(),
                    destination: "127.0.0.1".parse().unwrap(),
                    interface: 0,
                },
            )
            .unwrap()
        else {
            panic!("missing upstream must receive REFUSED")
        };
        let header = Header::parse(&reply).unwrap();
        assert_eq!(header.id, 8);
        assert_eq!(header.flags, 0x8185);
        assert_eq!(
            (
                header.questions,
                header.answers,
                header.authorities,
                header.additionals
            ),
            (1, 0, 0, 0)
        );
        assert_eq!(daemon.pending_count(), 0);
    }

    #[test]
    fn unowned_udp_query_preserves_cd_but_clears_ad_and_do() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"no-resolv");
        let mut daemon = DnsDaemon::with_random(
            config,
            Hosts::new(),
            &[],
            DaemonOptions {
                edns_packet_max: 512,
                ..options()
            },
            Counter(0),
        )
        .unwrap();
        let mut request = query("missing.test", 0x406b);
        request[2..4].copy_from_slice(&0x0130u16.to_be_bytes());
        request[10..12].copy_from_slice(&1u16.to_be_bytes());
        request.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]);
        let QueryResult::Local(reply) = daemon
            .handle_udp(
                &request,
                ClientRequest {
                    source: "127.0.0.1:53000".parse().unwrap(),
                    destination: "127.0.0.1".parse().unwrap(),
                    interface: 0,
                },
            )
            .unwrap()
        else {
            panic!("missing upstream must receive REFUSED")
        };
        // Exact C receive_query/forward_query baseline: advertise configured
        // 512, retain CD/RD, clear AD/DO, append EDE NOT_READY (14).
        assert_eq!(Header::parse(&reply).unwrap().flags, 0x8195);
        let opt = find_pseudoheader(&reply, true).unwrap().opt.unwrap();
        assert_eq!(opt.record.class, 512);
        assert_eq!(opt.record.ttl, 0);
        assert_eq!(opt.record.rdata, &[0, 15, 0, 2, 0, 14]);
        assert_eq!(daemon.pending_count(), 0);
    }

    #[test]
    fn loopback_upstream_round_trip_restores_client_id() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let request = &input[..length];
            let header = Header::parse(request).unwrap();
            let name = Name::from_ascii("upstream.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8180, 1232).unwrap();
            writer.question(&name, 1, 1).unwrap();
            writer
                .record(Section::Answer, &name, 1, 1, 30, &[192, 0, 2, 7])
                .unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
        });
        let mut config = DnsConfig::default();
        config.no_resolv = false;
        let mut daemon =
            DnsDaemon::with_random(config, Hosts::new(), &[address], options(), Counter(0))
                .unwrap();
        let result = daemon
            .handle_udp(
                &query("upstream.test", 0x4321),
                ClientRequest {
                    source: "127.0.0.1:53001".parse().unwrap(),
                    destination: "127.0.0.1".parse().unwrap(),
                    interface: 0,
                },
            )
            .unwrap();
        assert!(matches!(result, QueryResult::Forwarded(_)));
        let responses = daemon.poll(Duration::from_secs(1)).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(Header::parse(&responses[0].packet).unwrap().id, 0x4321);
        worker.join().unwrap();
    }

    #[test]
    fn positive_cache_hit_restores_new_client_id_without_second_upstream_send() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let request = &input[..length];
            let header = Header::parse(request).unwrap();
            let name = Name::from_ascii("upstream.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8180, 1232).unwrap();
            writer.question(&name, 1, 1).unwrap();
            writer
                .record(Section::Answer, &name, 1, 1, 30, &[192, 0, 2, 7])
                .unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let mut extra = [0; 2048];
            usize::from(server.recv_from(&mut extra).is_ok())
        });

        let config = DnsConfig::default();
        let mut daemon =
            DnsDaemon::with_random(config, Hosts::new(), &[address], options(), Counter(0))
                .unwrap();
        daemon.enable_cache(8, 0, 60, StalePolicy::Disabled);
        let client = |id| ClientRequest {
            source: format!("127.0.0.1:{}", 53000 + id).parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        };
        assert!(matches!(
            daemon.handle_udp(&query("upstream.test", 0x1111), client(1)),
            Ok(QueryResult::Forwarded(_))
        ));
        assert_eq!(daemon.poll(Duration::from_secs(1)).unwrap().len(), 1);
        let cached = daemon
            .handle_udp(&query("upstream.test", 0x2222), client(2))
            .unwrap();
        let QueryResult::Cached(packet) = cached else {
            panic!("second query did not use the positive cache");
        };
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.id, 0x2222);
        assert_eq!(header.answers, 1);
        assert_eq!(worker.join().unwrap(), 0);
    }

    #[test]
    fn negative_cache_hit_returns_nxdomain_without_second_upstream_send() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let header = Header::parse(&input[..length]).unwrap();
            let name = Name::from_ascii("missing.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8183, 1232).unwrap();
            writer.question(&name, 1, 1).unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let mut extra = [0; 2048];
            usize::from(server.recv_from(&mut extra).is_ok())
        });

        let mut daemon = DnsDaemon::with_random(
            DnsConfig::default(),
            Hosts::new(),
            &[address],
            options(),
            Counter(0),
        )
        .unwrap();
        daemon.enable_cache(8, 0, 60, StalePolicy::Disabled);
        daemon.enable_negative_cache(30, true);
        let client = |port| ClientRequest {
            source: format!("127.0.0.1:{port}").parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        };
        assert!(matches!(
            daemon.handle_udp(&query("missing.test", 0x1111), client(53101)),
            Ok(QueryResult::Forwarded(_))
        ));
        let first = daemon.poll(Duration::from_secs(1)).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(Header::parse(&first[0].packet).unwrap().rcode(), 3);
        let cached = daemon
            .handle_udp(&query("missing.test", 0x2222), client(53102))
            .unwrap();
        let QueryResult::Cached(packet) = cached else {
            panic!("second NXDOMAIN query did not use the negative cache");
        };
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.id, 0x2222);
        assert_eq!(header.rcode(), 3);
        assert_eq!(header.answers, 0);
        assert_eq!(worker.join().unwrap(), 0);
    }

    #[test]
    fn nodata_cache_hit_returns_noerror_without_second_upstream_send() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let header = Header::parse(&input[..length]).unwrap();
            let name = Name::from_ascii("empty.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8180, 1232).unwrap();
            writer.question(&name, 1, 1).unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let mut extra = [0; 2048];
            usize::from(server.recv_from(&mut extra).is_ok())
        });

        let mut daemon = DnsDaemon::with_random(
            DnsConfig::default(),
            Hosts::new(),
            &[address],
            options(),
            Counter(0),
        )
        .unwrap();
        daemon.enable_cache(8, 0, 60, StalePolicy::Disabled);
        daemon.enable_negative_cache(30, true);
        let client = |port| ClientRequest {
            source: format!("127.0.0.1:{port}").parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        };
        assert!(matches!(
            daemon.handle_udp(&query("empty.test", 0x1111), client(53301)),
            Ok(QueryResult::Forwarded(_))
        ));
        let first = daemon.poll(Duration::from_secs(1)).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(Header::parse(&first[0].packet).unwrap().rcode(), 0);
        assert_eq!(Header::parse(&first[0].packet).unwrap().answers, 0);
        let cached = daemon
            .handle_udp(&query("empty.test", 0x2222), client(53302))
            .unwrap();
        let QueryResult::Cached(packet) = cached else {
            panic!("second NODATA query did not use the negative cache");
        };
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.id, 0x2222);
        assert_eq!(header.rcode(), 0);
        assert_eq!(header.answers, 0);
        assert_eq!(worker.join().unwrap(), 0);
    }

    #[test]
    fn cname_cache_hit_replays_alias_and_terminal_address() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let header = Header::parse(&input[..length]).unwrap();
            let alias = Name::from_ascii("alias.test").unwrap();
            let target = Name::from_ascii("target.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8180, 1232).unwrap();
            writer.question(&alias, 1, 1).unwrap();
            writer
                .record(Section::Answer, &alias, 5, 1, 20, target.as_wire())
                .unwrap();
            writer
                .record(Section::Answer, &target, 1, 1, 30, &[192, 0, 2, 9])
                .unwrap();
            writer
                .record(Section::Answer, &target, 1, 1, 30, &[192, 0, 2, 10])
                .unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let mut extra = [0; 2048];
            usize::from(server.recv_from(&mut extra).is_ok())
        });

        let mut daemon = DnsDaemon::with_random(
            DnsConfig::default(),
            Hosts::new(),
            &[address],
            options(),
            Counter(0),
        )
        .unwrap();
        daemon.enable_cache(8, 0, 60, StalePolicy::Disabled);
        let client = |port| ClientRequest {
            source: format!("127.0.0.1:{port}").parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        };
        assert!(matches!(
            daemon.handle_udp(&query("alias.test", 0x1111), client(53201)),
            Ok(QueryResult::Forwarded(_))
        ));
        let first = daemon.poll(Duration::from_secs(1)).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(Message::parse(&first[0].packet).unwrap().header.answers, 3);
        let cached = daemon
            .handle_udp(&query("alias.test", 0x2222), client(53202))
            .unwrap();
        let QueryResult::Cached(packet) = cached else {
            panic!("second CNAME query did not use the cache");
        };
        let message = Message::parse(&packet).unwrap();
        assert_eq!(message.header.id, 0x2222);
        assert_eq!(message.header.answers, 3);
        let mut records = message.records(Section::Answer);
        assert_eq!(records.next().unwrap().rrtype, 5);
        assert_eq!(records.next().unwrap().rrtype, 1);
        assert_eq!(records.next().unwrap().rrtype, 1);
        assert_eq!(worker.join().unwrap(), 0);
    }

    #[test]
    fn cname_cache_does_not_answer_other_address_family() {
        let mut config = DnsConfig::default();
        config.no_resolv = true;
        let mut daemon = DnsDaemon::with_random(
            config.clone(),
            super::super::local::configured_hosts(&config, options().local_ttl),
            &[],
            options(),
            Counter(0),
        )
        .unwrap();
        let mut cache = Cache::new(4, CachePolicy::default());
        let alias = Name::from_ascii("alias.test").unwrap();
        let target = Name::from_ascii("target.test").unwrap();
        let now = unix_seconds();
        cache.start_insert();
        let cname = cache
            .insert(
                Record {
                    name: alias.clone(),
                    kind: Kind::Cname,
                    negative: false,
                    data: target.canonical_wire(),
                },
                now,
                60,
            )
            .unwrap();
        let address = cache
            .insert(
                Record {
                    name: target,
                    kind: Kind::Ipv4,
                    negative: false,
                    data: vec![192, 0, 2, 1],
                },
                now,
                60,
            )
            .unwrap();
        assert!(cache.set_cname_target(cname, address));
        assert!(cache.commit());
        daemon.cache = Some(cache);
        let packet = query_type("alias.test", 28, 0x1234);
        let question = super::super::forward::Question::parse(&packet).unwrap();
        assert!(daemon.cached_answer(&packet, &question).unwrap().is_none());
        let packet = query_type_flags("alias.test", 1, 0x5678, 0x110);
        let question = super::super::forward::Question::parse(&packet).unwrap();
        let answer = daemon.cached_answer(&packet, &question).unwrap().unwrap();
        assert_ne!(Header::parse(&answer).unwrap().flags & 0x10, 0);
    }

    #[test]
    fn soa_nodata_cache_hit_replays_authority_and_minimum_ttl() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let header = Header::parse(&input[..length]).unwrap();
            let name = Name::from_ascii("empty.example.test").unwrap();
            let zone = Name::from_ascii("example.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8180, 1232).unwrap();
            writer.question(&name, 1, 1).unwrap();
            writer
                .record(Section::Authority, &zone, 6, 1, 40, &soa_data())
                .unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let mut extra = [0; 2048];
            usize::from(server.recv_from(&mut extra).is_ok())
        });

        let mut daemon = DnsDaemon::with_random(
            DnsConfig::default(),
            Hosts::new(),
            &[address],
            options(),
            Counter(0),
        )
        .unwrap();
        daemon.enable_cache(8, 0, 60, StalePolicy::Disabled);
        daemon.enable_negative_cache(30, true);
        let client = |port| ClientRequest {
            source: format!("127.0.0.1:{port}").parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        };
        assert!(matches!(
            daemon.handle_udp(&query("empty.example.test", 0x1111), client(53401)),
            Ok(QueryResult::Forwarded(_))
        ));
        let first = daemon.poll(Duration::from_secs(1)).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(
            Message::parse(&first[0].packet).unwrap().header.authorities,
            1
        );
        let cached = daemon
            .handle_udp(&query("empty.example.test", 0x2222), client(53402))
            .unwrap();
        let QueryResult::Cached(packet) = cached else {
            panic!("SOA NODATA did not use the negative cache");
        };
        let message = Message::parse(&packet).unwrap();
        assert_eq!(message.header.id, 0x2222);
        assert_eq!(message.header.rcode(), 0);
        assert_eq!(message.header.answers, 0);
        assert_eq!(message.header.authorities, 1);
        let authority = message.records(Section::Authority).next().unwrap();
        assert_eq!(authority.rrtype, 6);
        assert!(authority.ttl <= 40);
        assert!(authority.ttl >= 1);
        assert_eq!(worker.join().unwrap(), 0);
    }

    #[test]
    fn cname_nxdomain_cache_hit_replays_chain_and_soa_authority() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let header = Header::parse(&input[..length]).unwrap();
            let alias = Name::from_ascii("alias.example.test").unwrap();
            let target = Name::from_ascii("missing.example.test").unwrap();
            let zone = Name::from_ascii("example.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8183, 1232).unwrap();
            writer.question(&alias, 1, 1).unwrap();
            writer
                .record(Section::Answer, &alias, 5, 1, 20, target.as_wire())
                .unwrap();
            writer
                .record(Section::Authority, &zone, 6, 1, 40, &soa_data())
                .unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let mut extra = [0; 2048];
            usize::from(server.recv_from(&mut extra).is_ok())
        });

        let mut daemon = DnsDaemon::with_random(
            DnsConfig::default(),
            Hosts::new(),
            &[address],
            options(),
            Counter(0),
        )
        .unwrap();
        daemon.enable_cache(8, 0, 60, StalePolicy::Disabled);
        daemon.enable_negative_cache(30, true);
        let client = |port| ClientRequest {
            source: format!("127.0.0.1:{port}").parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        };
        assert!(matches!(
            daemon.handle_udp(&query("alias.example.test", 0x1111), client(53501)),
            Ok(QueryResult::Forwarded(_))
        ));
        assert_eq!(daemon.poll(Duration::from_secs(1)).unwrap().len(), 1);
        let cached = daemon
            .handle_udp(&query("alias.example.test", 0x2222), client(53502))
            .unwrap();
        let QueryResult::Cached(packet) = cached else {
            panic!("CNAME NXDOMAIN did not use the negative cache");
        };
        let message = Message::parse(&packet).unwrap();
        assert_eq!(message.header.id, 0x2222);
        assert_eq!(message.header.rcode(), 3);
        assert_eq!(message.header.answers, 1);
        assert_eq!(message.header.authorities, 1);
        assert_eq!(message.records(Section::Answer).next().unwrap().rrtype, 5);
        assert_eq!(
            message.records(Section::Authority).next().unwrap().rrtype,
            6
        );
        assert_eq!(worker.join().unwrap(), 0);
    }

    #[test]
    fn unresolved_endpoint_is_rejected_at_startup() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"no-resolv");
        apply(&mut config, b"server=resolver.example");
        let result = DnsDaemon::with_random(config, Hosts::new(), &[], options(), Counter(0));
        assert!(matches!(result, Err(DaemonError::Config(_))));
    }

    #[test]
    fn explicit_default_server_works_with_no_resolv() {
        let mut config = DnsConfig::default();
        config.no_resolv = true;
        apply(&mut config, b"server=127.0.0.1#5300");
        let daemon = DnsDaemon::with_random(config, Hosts::new(), &[], options(), Counter(0));
        assert!(daemon.is_ok());
    }
}
