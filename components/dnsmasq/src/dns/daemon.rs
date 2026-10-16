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
use super::cache_engine::{CacheContext, CacheError, CachedAnswer, OrdinaryCacheMode};
use super::files::{ServerSources, Source, SourceRule};
use super::forward::{Client, Options as ForwardOptions, QueryId, Random};
use super::forward_service::ForwardDispatcher;
use super::process::{
    apply_doctor, apply_static_aliases, ignore_reply, process_admitted_reply, AddressPolicy,
    AddressPrefix, ProcessAction, ProcessError,
};
use super::reply::{
    apply_known_local_nxdomain, filter_rrs, limit_udp_reply, prepare_udp_reply, resize_reply,
    ReplyPolicy,
};
use super::routing::{RouteReason, RoutingError, RoutingTable};
use super::service::{LocalDnsService, ServiceError};
use super::upstream::{
    Lifetime, OsRandom, ResolveError, UncheckedReply, UpstreamEvent, UpstreamResolver,
};
use super::wire::{find_pseudoheader, Header, Name, WireError};
#[cfg(test)]
use super::wire::{Message, PacketWriter, Question as WireQuestion, Section};
use crate::config::dns::{DnsConfig, RuleTarget};
use crate::config::{Error as ConfigError, FastRetry};
use crate::hosts::Hosts;
use crate::query_logging::{self as qlog, QueryContext, QueryEvent};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "daemon_dump.rs"]
mod dump;

fn source_error_text(error: &io::Error) -> String {
    #[cfg(target_os = "linux")]
    {
        super::filewatch::os_message(error)
    }
    #[cfg(not(target_os = "linux"))]
    {
        error.to_string()
    }
}

/// Transport-independent identity of a DNS client datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequest {
    pub source: SocketAddr,
    pub destination: IpAddr,
    pub interface: u32,
}

/// Shared local/cache lookup, with C's name cursor retained on a miss. UDP
/// reparses the original question before forwarding; TCP uses this cursor.
#[derive(Default)]
pub struct LocalLookup {
    pub answer: Option<QueryResult>,
    pub forward_name: Option<ForwardName>,
}

/// Read-only cache existence accompanies the cursor for domain-needed policy.
/// It must come from the same current/connection cache view as the traversal.
#[derive(Debug, PartialEq, Eq)]
pub struct ForwardName {
    pub name: Name,
    pub cached: bool,
}

impl LocalLookup {
    fn answered(answer: QueryResult) -> Self {
        Self { answer: Some(answer), forward_name: None }
    }
}

/// A response ready for the containing process to send on its client socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResponse {
    pub destination: SocketAddr,
    /// Original query destination and ingress, retained per recipient even
    /// when several clients share one upstream transaction or wildcard socket.
    pub source: IpAddr,
    pub interface: u32,
    pub listener: Option<super::forward::SocketToken>,
    pub packet: Vec<u8>,
    pub query_context: QueryContext,
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
    SourceBind(super::upstream::source_sockets::SourceBindError),
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
            Self::SourceBind(error) => error.fmt(f),
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
    query_logging: crate::config::logging::QueryLogging,
    query_context: QueryContext,
    query_events: Vec<(QueryContext, QueryEvent)>,
    forward_max: usize,
    last_query_full: i64,
    local: LocalDnsService,
    routing: RoutingTable,
    startup_routing: Option<RoutingTable>,
    server_sources: ServerSources,
    source_warnings: Vec<String>,
    #[cfg(target_os = "linux")]
    server_notices: Vec<crate::logging::LogEvent>,
    upstream: UpstreamResolver<R>,
    cache: Option<Cache>,
    // One bounded decode scratch, not a per-name cache. A successful name
    // is at most255 bytes; Vec's amortized capacity may exceed256 (for
    // example380 for uneven labels), while ordinary names retain32 bytes.
    udp_name_buffer: Vec<u8>,
    cache_counters: CacheCounters,
    negative_ttl: u64,
    negative_cache: bool,
    policy: AddressPolicy,
    query_policy: super::query_policy::QueryPolicy,
    proxy_dnssec: bool,
    max_udp: usize,
    edns_packet_max: u16,
    filter_rr: Vec<u16>,
    poll_failures: PollFailures,
    loop_state: super::loop_detect::LoopState,
    startup_loop_probes: Vec<super::loop_detect::LoopProbe>,
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
        mut random: R,
    ) -> Result<Self, DaemonError> {
        config.finalize()?;
        config.validate_ready().map_err(DaemonError::Config)?;
        validate_runtime_config(&config)?;
        let mut server_sources = ServerSources::new(&config.rules);
        if !config.no_resolv {
            server_sources.replace(
                Source::Resolv,
                default_resolvers
                    .iter()
                    .copied()
                    .map(|address| SourceRule::resolver(address, 0))
                    .collect(),
            );
        }
        let mut loop_state = super::loop_detect::LoopState::default();
        let startup_loop_probes = if config.loop_detect {
            loop_state.probes(&server_sources, &mut random)?
        } else {
            Vec::new()
        };
        // Source FD preallocation precedes check_servers, even for a zero
        // destination which will never be eligible for actual forwarding.
        let startup_routing = if server_sources
            .rules()
            .iter()
            .any(|row| row.server.is_some() && !server_usable(&row.value, &[]))
        {
            Some(RoutingTable::from_sources(&config, &server_sources, None)?)
        } else {
            None
        };
        // IPv4 zero is always discarded by C's check_servers. Local listener
        // address filtering follows once the containing owner supplies them.
        server_sources.retain_servers(|row| server_usable(row, &[]));
        let routing = RoutingTable::from_sources(&config, &server_sources, None)?;
        config = server_sources.effective_config(&config);
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
        let query_policy = super::query_policy::QueryPolicy::from_config(&config);
        let filter_rr = config.filter_rr.clone();
        let local = LocalDnsService::new_with_limits(
            config,
            hosts,
            options.local_ttl,
            options.max_udp.max(512),
            options.edns_packet_max,
        );
        Ok(Self {
            query_logging: Default::default(),
            query_context: Default::default(),
            query_events: Vec::new(),
            forward_max: options.forward_max,
            last_query_full: 0,
            local,
            routing,
            startup_routing,
            server_sources,
            source_warnings: Vec::new(),
            #[cfg(target_os = "linux")]
            server_notices: Vec::new(),
            upstream,
            cache: None,
            udp_name_buffer: Vec::new(),
            cache_counters: CacheCounters::default(),
            negative_ttl: 0,
            negative_cache: false,
            policy,
            query_policy,
            proxy_dnssec: options.proxy_dnssec,
            max_udp: options.max_udp.max(512),
            edns_packet_max: options.edns_packet_max,
            filter_rr,
            poll_failures: PollFailures::default(),
            loop_state,
            startup_loop_probes,
        })
    }

    pub fn set_query_logging(&mut self, config: crate::config::logging::QueryLogging) {
        self.query_logging = config;
        self.local.query_logging = config.enabled;
        self.upstream.set_query_logging(config);
    }

    pub fn set_query_context(&mut self, context: QueryContext) {
        self.collect_local_query_events();
        self.query_context = context;
    }

    fn collect_local_query_events(&mut self) {
        self.query_events.extend(
            self.local
                .take_query_events()
                .into_iter()
                .map(|event| (self.query_context, event)),
        );
    }

    pub fn take_local_query_events(&mut self) -> Vec<QueryEvent> {
        self.local.take_query_events()
    }

    pub fn take_query_events(&mut self) -> Vec<(QueryContext, QueryEvent)> {
        self.collect_local_query_events();
        self.query_events.extend(self.upstream.take_query_events());
        std::mem::take(&mut self.query_events)
    }

    fn query_notice(&mut self, context: QueryContext, event: QueryEvent) {
        if self.query_logging.enabled {
            self.query_events.push((context, event));
        }
    }

    fn policy_reply(
        &mut self,
        query: &[u8],
        external: Option<&LocalDnsService>,
    ) -> Result<Option<Vec<u8>>, WireError> {
        let local = external.unwrap_or(&self.local);
        let mut events = Vec::new();
        let question = super::forward::Question::parse(query)?;
        let cached_name = self.cache.as_ref().is_some_and(|cache| {
            cache.contains_forward_name(&question.name, unix_seconds())
        });
        let reply = self.query_policy.reply_with_cache(
            query, &self.routing, Some(local), self.edns_packet_max, false,
            None, cached_name, self.query_logging.enabled.then_some(&mut events),
        );
        self.query_events
            .extend(events.into_iter().map(|event| (self.query_context, event)));
        reply
    }

    pub fn pending_count(&self) -> usize {
        self.upstream.pending_count()
    }

    /// Actual parent callers that overwrite C's shared packet clear the last
    /// UDP resend. Ordinary TCP child snapshots must not call this method.
    pub fn invalidate_udp_resend(&mut self) {
        self.upstream.invalidate_udp_resend();
    }

    /// Invoke before the route event's resolver publication, matching
    /// EVENT_NEWROUTE: resend_query followed by poll_resolv.
    pub fn resend_udp_query(&mut self) {
        self.upstream.resend_udp_query();
    }

    /// Capture a finite snapshot only at actual C check_servers call sites.
    #[cfg(target_os = "linux")]
    pub fn queue_server_notices(&mut self) {
        self.server_notices
            .extend(crate::logging::startup::server_messages(
                self.server_sources.rules(),
                |id| self.loop_state.disabled.contains(&id),
            ));
    }

    #[cfg(target_os = "linux")]
    pub fn take_server_notices(&mut self) -> Vec<crate::logging::LogEvent> {
        std::mem::take(&mut self.server_notices)
    }

    /// EVENT_INIT/RELOAD checks after its file calls even when a source open
    /// failed. Loop probes clear prior loop flags at this actual caller only.
    #[cfg(target_os = "linux")]
    pub fn recheck_server_notices(&mut self) -> Result<(), DaemonError> {
        if self.local.config.loop_detect {
            self.send_loop_probes()?;
            self.rebuild_server_routes(&[])?;
        }
        self.queue_server_notices();
        Ok(())
    }

    pub fn take_source_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.source_warnings)
    }

    pub fn take_source_diagnostics(
        &mut self,
    ) -> Vec<super::upstream::source_sockets::SourceSocketDiagnostic> {
        self.upstream.take_source_diagnostics()
    }

    #[cfg(target_os = "linux")]
    /// Source warnings, socket diagnostics and server notices share the owner.
    pub fn has_pending_notices(&self) -> bool {
        !self.source_warnings.is_empty()
            || !self.server_notices.is_empty()
            || self.upstream.has_source_diagnostics()
    }

    pub fn local_config(&self) -> &DnsConfig {
        &self.local.config
    }

    pub fn tcp_snapshot(
        &self,
    ) -> Result<super::tcp_service::TcpDnsService, super::tcp_service::TcpServiceError> {
        let mut service = super::tcp_service::TcpDnsService::with_routing(
            &self.local.config,
            self.routing.snapshot(),
            self.edns_packet_max,
        )?;
        service.set_preferred_servers(self.routing.groups().filter_map(|group| {
            self.upstream
                .dispatcher()
                .group(group.id)
                .and_then(|state| state.preferred_server())
                .map(|server| (group.id, server))
        }));
        Ok(service)
    }

    /// Publish one successfully opened file source while retaining live
    /// forwarding state. The owner next clones local_config into ParentDns.local;
    /// existing TCP sessions keep their earlier immutable routing snapshots.
    /// Unsupported endpoint forms remain explicit errors until their family
    /// supplies resolved endpoint state, rather than silently dropping rows.
    pub fn replace_server_source(
        &mut self,
        source: Source,
        rows: Vec<SourceRule>,
        local_addresses: &[SocketAddr],
    ) -> Result<(), DaemonError> {
        for row in &rows {
            if row.address.is_none() {
                if let RuleTarget::Upstream(endpoint) = &row.rule.target {
                    super::routing::validate_endpoint(endpoint)?;
                }
            }
        }
        if !self.local.config.bind_interfaces {
            self.refresh_source_interface_indices();
        }
        let checks_servers = source == super::files::Source::ServersFile
            || (source == super::files::Source::Resolv
                && !self.local.config.no_poll
                && !rows.is_empty());
        let mut removed = self.server_sources.replace(source, rows);
        self.loop_state.reset_source(source, &self.server_sources);
        if checks_servers {
            self.send_loop_probes()?;
        }
        removed.extend(
            self.server_sources
                .retain_servers(|row| server_usable(row, local_addresses)),
        );
        self.rebuild_server_routes(&removed)?;
        #[cfg(target_os = "linux")]
        if checks_servers {
            self.queue_server_notices();
        }
        Ok(())
    }

    /// Initial listener/interface addresses are known after daemon creation.
    /// No source file needs to be present for check_servers to reject a loop.
    pub fn check_server_addresses(
        &mut self,
        local_addresses: &[SocketAddr],
    ) -> Result<(), DaemonError> {
        self.send_loop_probes()?;
        let removed = self
            .server_sources
            .retain_servers(|row| server_usable(row, local_addresses));
        self.rebuild_server_routes(&removed)
    }

    pub fn refresh_source_interface_indices(&mut self) {
        self.upstream.refresh_source_interface_indices();
    }

    pub fn configure_source_sockets(
        &mut self,
        settings: super::upstream::source_sockets::SocketSettings,
        startup: bool,
    ) -> Result<(), DaemonError> {
        let startup_routing = self.startup_routing.take().filter(|_| startup);
        let bindings = startup_routing
            .as_ref()
            .unwrap_or(&self.routing)
            .source_bindings(settings.query_port);
        let failures = self
            .upstream
            .configure_source_sockets(settings, bindings.clone());
        if startup && self.local.config.bind_interfaces {
            if let Some((id, error)) = failures.into_iter().next() {
                return Err(DaemonError::SourceBind(
                    super::upstream::source_sockets::SourceBindError {
                        source: bindings[&id].clone(),
                        error,
                    },
                ));
            }
        } else {
            let ids: Vec<_> = failures
                .into_iter()
                // check_servers silently discards zero destinations before
                // reporting failed per-server bindings in wildcard modes.
                .filter(|(id, _)| {
                    self.server_sources
                        .rules()
                        .iter()
                        .any(|row| row.server == Some(*id))
                })
                .map(|(id, error)| {
                    self.source_warnings.push(format!(
                        "ignoring nameserver {} - cannot make/bind socket: {}",
                        self.routing.server_label(id),
                        source_error_text(&error)
                    ));
                    id
                })
                .collect();
            if !ids.is_empty() {
                self.server_sources.remove_server_ids(&ids);
                self.rebuild_server_routes(&ids)?;
            }
        }
        Ok(())
    }

    fn rebuild_server_routes(
        &mut self,
        removed: &[super::forward::ServerId],
    ) -> Result<(), DaemonError> {
        let excluded: Vec<_> = self.loop_state.disabled.iter().copied().collect();
        let mut routing = RoutingTable::from_sources_except(
            &self.local.config,
            &self.server_sources,
            Some(&self.routing),
            &excluded,
        )?;
        let settings = self.upstream.socket_settings();
        let bindings = if self.local.config.loop_detect {
            RoutingTable::from_sources(
                &self.local.config,
                &self.server_sources,
                Some(&self.routing),
            )?
            .source_bindings(settings.query_port)
        } else {
            routing.source_bindings(settings.query_port)
        };
        let failures = self.upstream.configure_source_sockets(settings, bindings);
        let mut removed = removed.to_vec();
        for (id, error) in failures {
            self.source_warnings.push(format!(
                "ignoring nameserver {} - cannot make/bind socket: {}",
                routing.server_label(id),
                source_error_text(&error)
            ));
            removed.push(id);
        }
        self.server_sources.remove_server_ids(&removed);
        if !removed.is_empty() {
            routing = RoutingTable::from_sources_except(
                &self.local.config,
                &self.server_sources,
                Some(&routing),
                &excluded,
            )?;
            self.upstream
                .configure_source_sockets(settings, routing.source_bindings(settings.query_port));
        }
        if self.local.config.loop_detect {
            let live = RoutingTable::from_sources(
                &self.local.config,
                &self.server_sources,
                Some(&self.routing),
            )?;
            self.upstream.set_reply_servers(
                live.dispatcher_groups()
                    .into_iter()
                    .flat_map(|group| group.servers)
                    .collect(),
            );
        }
        self.upstream
            .replace_server_groups(routing.dispatcher_groups(), &removed);
        self.routing = routing;
        self.local.config = self.server_sources.effective_config(&self.local.config).into();
        if !excluded.is_empty() {
            std::sync::Arc::make_mut(&mut self.local.config).rules = self
                .server_sources
                .rules()
                .iter()
                .filter(|row| !row.server.is_some_and(|id| excluded.contains(&id)))
                .map(|row| row.value.rule.clone())
                .collect();
        }
        Ok(())
    }

    fn send_loop_probes(&mut self) -> Result<(), DaemonError> {
        if !self.local.config.loop_detect {
            return Ok(());
        }
        let startup = !self.startup_loop_probes.is_empty();
        let probes = if startup {
            std::mem::take(&mut self.startup_loop_probes)
        } else {
            self.loop_state
                .probes(&self.server_sources, self.upstream.random_mut())?
        };
        self.upstream.loop_probe_batch(probes, startup);
        Ok(())
    }

    /// receive_query detects returned probes before local/cache/forward work.
    pub fn detect_loop(&mut self, packet: &[u8]) -> Result<bool, DaemonError> {
        if !self.local.config.loop_detect {
            return Ok(false);
        }
        let Some(_) = self.loop_state.detect(packet, &self.server_sources) else {
            return Ok(false);
        };
        self.rebuild_server_routes(&[])?;
        #[cfg(target_os = "linux")]
        self.queue_server_notices();
        Ok(true)
    }

    pub fn poll_failures(&self) -> PollFailures {
        self.poll_failures
    }

    pub fn append_poll_fds(
        &self,
        fds: &mut Vec<owrt_ubus::sys::PollFd>,
        deadline: std::time::Instant,
    ) -> Option<std::time::Instant> {
        self.upstream.append_poll_fds(fds, deadline)
    }

    /// Cumulative real cache events since initialization or the last reload.
    /// Reading is non-destructive and independent of ubus enablement.
    pub fn cache_counters(&self) -> CacheCounters {
        self.cache_counters
    }

    /// Initial name-hash sizing for a new static hosts generation.
    pub fn cache_capacity(&self) -> usize {
        self.cache.as_ref().map_or(0, Cache::capacity)
    }

    pub fn forward_counters(&self) -> super::forward::ForwardCounters {
        self.upstream.counters()
    }

    /// Publish a completed hosts generation without changing forwarded cache.
    pub fn publish_hosts_source(&mut self, hosts: Hosts) {
        self.local.hosts = hosts;
    }

    /// Restore the other owner view after a failed hosts replacement. The
    /// caller first drops its incomplete generation to release that memory.
    pub fn try_clone_hosts_source(&self) -> Result<Hosts, std::collections::TryReserveError> {
        self.local.hosts.try_clone()
    }

    /// HUP invalidates forwarded answers even if loading replacement hosts
    /// later fails. Keep the published hosts until a complete view is ready.
    pub fn begin_hosts_reload(&mut self) {
        // cache_reload uses daemon->packet as its temporary reverse hash.
        self.invalidate_udp_resend();
        if let Some(cache) = &mut self.cache {
            cache.clear_counted(&mut self.cache_counters);
        }
    }

    pub fn reload_hosts(&mut self, hosts: Hosts) {
        self.begin_hosts_reload();
        self.publish_hosts_source(hosts);
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
    pub fn publish_interface_records(
        &mut self,
        records: std::sync::Arc<super::interface_records::InterfaceRecords>,
    ) {
        self.local.interfaces = records;
    }
    pub fn publish_domain_interfaces(
        &mut self,
        domains: std::sync::Arc<crate::config::domains::DomainInterfaces>,
    ) {
        self.local.publish_domain_interfaces(domains);
    }

    #[cfg(target_os = "linux")]
    pub fn set_dump(&mut self, dump: crate::dump::DumpHandle) {
        self.upstream.set_dump(dump);
    }

    pub fn enable_cache(
        &mut self,
        capacity: usize,
        min_ttl: u64,
        max_ttl: u64,
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

    pub fn set_max_reply_ttl(&mut self, maximum: u64) {
        if let Some(cache) = &mut self.cache {
            cache.set_max_reply_ttl(maximum);
        }
    }

    /// Enable the no-SOA NXDOMAIN cache fallback. SOA/NODATA synthesis is
    /// intentionally separate; a zero TTL keeps this path disabled.
    pub fn enable_negative_cache(&mut self, negative_ttl: u64, enabled: bool) {
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
        self.invalidate_udp_resend();
        if query.len() > self.max_udp {
            return Ok(QueryResult::Dropped);
        }
        match super::udp_query::inspect(query, self.edns_packet_max) {
            super::udp_query::Admission::Drop => return Ok(QueryResult::Dropped),
            super::udp_query::Admission::Reply(reply) => return Ok(QueryResult::Local(reply)),
            super::udp_query::Admission::Continue => {}
        }
        let header = Header::parse(query)?;
        let question = super::forward::Question::parse_with_header(query, header)?;
        if let Some(answer) = Self::answer_local_or_cached(
            self.cache.as_mut(),
            query,
            header,
            &question,
            &mut self.local,
            unix_seconds(),
            true,
            false,
        )?.answer {
            return Ok(answer);
        }
        if let Some(packet) = self.policy_reply(query, None)? {
            return Ok(QueryResult::Local(packet));
        }
        self.submit_upstream(query, &question, client, None, true)
    }

    /// The single poll owner supplies its local generation. MX/SRV Additional
    /// addresses consult the same cache as ordinary lookups, without I/O.
    pub fn local_udp_answer(
        &mut self,
        query: &[u8],
        local: &mut LocalDnsService,
        now: i64,
    ) -> Result<Option<Vec<u8>>, DaemonError> {
        self.invalidate_udp_resend();
        Ok(local.handle_udp_with_cache(query, now, self.cache.as_mut())?)
    }

    pub fn local_tcp_answer(
        &mut self,
        query: &[u8],
        local: &mut LocalDnsService,
        now: i64,
    ) -> Result<Option<Vec<u8>>, DaemonError> {
        Ok(local.handle_tcp_with_cache(query, now, self.cache.as_mut())?)
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

    /// The UDP owner has established admission/context. None permits the
    /// unchanged general path; Some commits both lookup and the original
    /// prepared-query resend boundary, including any final writer error.
    pub fn try_plain_cached_udp(
        &mut self, query: &[u8], local: &mut LocalDnsService,
    ) -> Option<Result<Vec<u8>, DaemonError>> {
        let result = CacheContext::try_plain_udp(self.cache.as_mut()?, query, local, unix_seconds(),
            &mut self.udp_name_buffer).map(|result| result.map_err(Into::into));
        if result.is_some() {
            // Deferred interface admission may resume after an upstream
            // retry saved a new packet. The receive-time clear is not enough.
            self.invalidate_udp_resend();
        }
        result
    }

    /// The owner decorates after preserving the original client metadata and
    /// completing MAC I/O. Local/cache envelopes still use the original UDP
    /// query, while forward.c stashes and retries the decorated packet.
    pub fn answer_udp_prepared_with_local(
        &mut self,
        original: &[u8],
        decorated: &[u8],
        metadata: super::forward_service::QueryMetadata,
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
        local: &mut LocalDnsService,
    ) -> Result<QueryResult, DaemonError> {
        self.invalidate_udp_resend();
        let header = Header::parse(original)?;
        let mut scratch = std::mem::take(&mut self.udp_name_buffer);
        let question = match super::forward::Question::parse_with_header_reusing(original, header, &mut scratch) {
            Ok(question) => question,
            Err(error) => {
                self.udp_name_buffer = scratch;
                return Err(error.into());
            }
        };
        // Forwarding retains its own owned question; no result can borrow
        // this synchronous decode. Recover the buffer on every result path.
        let result = (|| {
            if let Some(answer) = Self::answer_local_or_cached(
                self.cache.as_mut(),
                original,
                header,
                &question,
                local,
                unix_seconds(),
                !metadata.flags.no_cache,
                false,
            )?.answer {
                return Ok(answer);
            }
            if let Some(packet) = self.policy_reply(original, Some(local))? {
                return Ok(QueryResult::Local(packet));
            }
            self.submit_upstream_with_metadata(
                decorated,
                original,
                &question,
                client,
                listener,
                true,
                Some(metadata),
            )
        })();
        self.udp_name_buffer = question.name.into_wire_buffer();
        result
    }

    pub fn refresh_udp_prepared_on_listener(
        &mut self,
        original: &[u8],
        decorated: &[u8],
        metadata: super::forward_service::QueryMetadata,
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
    ) -> Result<QueryResult, DaemonError> {
        let question = super::forward::Question::parse(original)?;
        self.submit_upstream_with_metadata(
            decorated,
            original,
            &question,
            client,
            listener,
            false,
            Some(metadata),
        )
    }

    fn forward_udp_inner(
        &mut self,
        query: &[u8],
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
        mut local: Option<&mut LocalDnsService>,
    ) -> Result<QueryResult, DaemonError> {
        self.invalidate_udp_resend();
        if query.len() > self.max_udp {
            return Ok(QueryResult::Dropped);
        }
        let question = super::forward::Question::parse(query).map_err(DaemonError::Wire)?;
        let answer = self.cached_answer_at_with_local(
            query,
            &question,
            unix_seconds(),
            local.as_deref_mut(),
        )?;
        if let Some(packet) = answer.packet {
            return Ok(if answer.stale {
                QueryResult::Stale(packet)
            } else {
                QueryResult::Cached(packet)
            });
        }
        if let Some(packet) = self.policy_reply(query, local.as_deref())? {
            return Ok(QueryResult::Local(packet));
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
        self.submit_upstream_with_metadata(
            query,
            query,
            question,
            client,
            listener,
            reply_requested,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_upstream_with_metadata(
        &mut self,
        query: &[u8],
        original: &[u8],
        question: &super::forward::Question,
        client: ClientRequest,
        listener: Option<super::forward::SocketToken>,
        reply_requested: bool,
        metadata: Option<super::forward_service::QueryMetadata>,
    ) -> Result<QueryResult, DaemonError> {
        let route = self
            .routing
            .select(&question.name, question.rrtype, question.class, false);
        let Some(group) = route.upstream_group() else {
            if route.reason == RouteReason::NoMatchingRule {
                let limit = find_pseudoheader(original, true)?
                    .opt
                    .map_or(512, |opt| usize::from(opt.udp_size(self.edns_packet_max)));
                self.query_notice(
                    self.query_context,
                    QueryEvent::error(qlog::CONFIG, b"error", 5, Some(14)),
                );
                // forward.c::forward_query: EDE_NOT_READY for no server.
                // UDP's add_pseudoheader clears DO, unlike the TCP caller.
                return Ok(QueryResult::Local(super::tcp_service::refusal(
                    original,
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
            log_id: self.query_context.display_id as u64,
        };
        let submission = match self.upstream.start_udp_with_metadata(
            query,
            client,
            group,
            super::forward_service::edns_scope(query),
            metadata,
        ) {
            Ok(submission) => submission,
            Err(ResolveError::Dispatch(super::forward_service::DispatchError::Submit(
                error @ (super::forward::SubmitError::GroupFull
                | super::forward::SubmitError::DuplicateFull),
            ))) => {
                let now = unix_seconds();
                if now.saturating_sub(self.last_query_full) > 5 {
                    self.last_query_full = now;
                    let domain = match &route.reason {
                        RouteReason::Upstream { pattern, .. }
                            if matches!(error, super::forward::SubmitError::GroupFull) =>
                        {
                            &pattern.suffix[..]
                        }
                        _ => b"",
                    };
                    self.source_warnings.push(if domain.is_empty() {
                        format!(
                            "Maximum number of concurrent DNS queries reached (max: {})",
                            self.forward_max
                        )
                    } else {
                        format!(
                            "Maximum number of concurrent DNS queries to {} reached (max: {})",
                            String::from_utf8_lossy(domain),
                            self.forward_max
                        )
                    });
                }
                self.query_notice(
                    self.query_context,
                    QueryEvent::error(qlog::CONFIG, b"error", 5, None),
                );
                return Ok(super::udp_query::table_full(original, self.edns_packet_max)
                    .map_or(QueryResult::Dropped, QueryResult::Local));
            }
            Err(ResolveError::Io(_)) => {
                self.query_notice(
                    self.query_context,
                    QueryEvent::error(qlog::CONFIG, b"error", 5, Some(23)),
                );
                // forward_query cancels this transaction when every socket /
                // send attempt fails, then makes a local REFUSED with NETERR.
                // start_udp has already released it. Background refreshes
                // return Local too: the parent counts this fallback without
                // sending a second response to the stale-answer recipient.
                let limit = find_pseudoheader(original, true)?
                    .opt
                    .map_or(512, |opt| usize::from(opt.udp_size(self.edns_packet_max)));
                return Ok(QueryResult::Local(super::tcp_service::refusal(
                    original,
                    self.edns_packet_max,
                    23,
                    limit,
                    false,
                )?));
            }
            Err(error) => return Err(error.into()),
        };
        self.query_events.extend(self.upstream.take_query_events());
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
        let policy = &self.policy;
        let events = self.upstream.poll_with_filter(wait, move |packet| {
            ignore_reply(packet, policy).unwrap_or(false)
        });
        let events = match events {
            Ok(events) => events,
            Err(error) => {
                self.poll_failures.poll_errors = self.poll_failures.poll_errors.saturating_add(1);
                return Err(error.into());
            }
        };
        let now = if events.is_empty() { 0 } else { unix_seconds() };
        Ok(self.finish_upstream_events_with_doctor(events, now, external_local, doctor))
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
        doctor: Option<&mut ReplyDoctor<'_>>,
    ) -> Vec<ClientResponse> {
        self.query_events.extend(self.upstream.take_query_events());
        if events.is_empty() {
            return Vec::new();
        }
        self.finish_nonempty_upstream_events(events, now, external_local, doctor)
    }

    // Cached answers still drain upstream notices, but have no reply work.
    // Keep the completed-reply frame out of that ordinary empty poll path.
    #[inline(never)]
    fn finish_nonempty_upstream_events(
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
                    Ok(Some(rcode)) => rcode,
                    Ok(None) => continue,
                    Err(_) => {
                        self.poll_failures.invalid_replies =
                            self.poll_failures.invalid_replies.saturating_add(1);
                        continue;
                    }
                };
            let mut projected_truncated = false;
            let mut counted_reply = false;
            for (index, recipient) in reply.recipients.iter().enumerate() {
                if !recipient.client.reply_requested && counted_reply {
                    continue;
                }
                match self.recipient_packet(&reply, recipient, rcode) {
                    Ok(Some((packet, clipped))) => {
                        // C counts the post-policy RCODE once before copying
                        // recipients, including a replyless stale refresh.
                        if !counted_reply {
                            if let Ok(header) = Header::parse(&packet) {
                                self.upstream.note_reply_rcode(reply.server, header.flags & 15);
                            }
                            counted_reply = true;
                        }
                        if !recipient.client.reply_requested {
                            continue;
                        }
                        projected_truncated |= clipped;
                        // return_reply logs an extra recipient after its full
                        // answer send; an upstream TC packet still fits here.
                        if self.query_logging.extra
                            && index != 0
                            && (reply.truncated
                                || Header::parse(&packet)
                                    .is_ok_and(|header| header.flags & 0x0200 == 0))
                        {
                            self.query_notice(
                                recipient.client.query_context(),
                                QueryEvent::label(qlog::REPLY, b"query", Some(b"duplicate"), 0),
                            );
                        }
                        responses.push(ClientResponse {
                            destination: recipient.client.source,
                            source: recipient.client.destination,
                            interface: recipient.client.interface,
                            listener: recipient.client.listener,
                            packet,
                            query_context: recipient.client.query_context(),
                        });
                    }
                    Ok(None) => {}
                    Err(_) => {
                        self.poll_failures.recipient_errors =
                            self.poll_failures.recipient_errors.saturating_add(1)
                    }
                }
            }
            // return_reply logs one projection after full-sized recipients,
            // using the primary source's saved display/client context.
            if projected_truncated {
                if let Some(primary) = reply.recipients.first() {
                    let mut context = primary.client.query_context();
                    context.client = Some(primary.client.source);
                    self.query_notice(
                        context,
                        QueryEvent {
                            flags: qlog::REPLY,
                            name: None,
                            data: qlog::QueryData::None,
                            argument: Some(b"truncated".to_vec()),
                            kind: 0,
                        },
                    );
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
    ) -> Result<Option<u16>, DaemonError> {
        // C authenticates the reply and releases the source sockets before
        // process_reply checks ECS. A mismatch cancels this transaction, so a
        // later valid reply cannot revive it or populate the cache.
        if reply.recipients.first().is_some_and(|recipient| {
            !super::edns_policy::check_reply_source(
                &reply.packet,
                &self.local.config.edns,
                recipient.client.source.ip(),
            )
        }) {
            self.source_warnings
                .push("discarding DNS reply: subnet option mismatch".to_owned());
            return Ok(None);
        }
        // C suppresses ordinary commit for original request CD or raw reply
        // CD, before return_reply restores the outgoing bit to the request.
        let upstream_checking_disabled = Header::parse(&reply.packet)?.flags & 0x10 != 0;
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
        let context = reply
            .recipients
            .first()
            .map_or_else(Default::default, |recipient| {
                recipient.client.query_context()
            });
        if !matches!(rcode, 0 | 3) {
            self.query_notice(
                context,
                QueryEvent::error(qlog::REPLY, b"error", rcode, None),
            );
        } else if Header::parse(&reply.packet)?.flags & 0x0200 != 0 {
            self.query_notice(
                context,
                QueryEvent {
                    flags: qlog::REPLY,
                    name: None,
                    data: qlog::QueryData::None,
                    argument: Some(b"truncated".to_vec()),
                    kind: 0,
                },
            );
        }
        reply.packet = envelope.packet;
        // These common stages happen once, before both cache insertion and
        // recipient copies. Repeating known-local after the doctor would
        // restore AA and repeating alias rules could rewrite an address twice.
        apply_known_local_nxdomain(&mut reply.packet, rcode, |name| {
            super::reply::known_name(
                name,
                Some(external_local.unwrap_or(&self.local)),
                Some(&self.routing),
                self.cache.as_ref().is_some_and(|cache| cache.contains_forward_name(name, now)),
                now,
            )
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
        // CD/no_cache suppress ordinary commit, while ordered extraction still
        // removes old records and may evict entries. Unsupported metadata is
        // separate; bogus policy owns its own transaction before these gates.
        let ordinary = if !reply.cache_eligible {
            OrdinaryCacheMode::Unsupported
        } else if reply.flags.no_cache
            || reply.flags.checking_disabled
            || upstream_checking_disabled
        {
            OrdinaryCacheMode::ExtractOnly
        } else {
            OrdinaryCacheMode::Commit
        };
        if matches!(rcode, 0 | 3) {
            if let Some(cache) = self.cache.as_mut() {
                let mut query_events = Vec::new();
                let mut cache_context = CacheContext {
                    cache,
                    counters: &mut self.cache_counters,
                    negative_cache: self.negative_cache,
                    negative_ttl: self.negative_ttl,
                    filter_rr: &self.filter_rr,
                };
                let extracted = cache_context
                    .insert_reply_with_events(
                        &reply.packet,
                        now,
                        external_local.unwrap_or(&self.local),
                        &self.policy,
                        rcode,
                        ordinary,
                        false,
                        &mut query_events,
                    )
                    .map(|_| ());
                self.query_events
                    .extend(query_events.into_iter().map(|event| (context, event)));
                if extracted.is_err() {
                    // The extractor has already applied any complete prefix.
                    // Reject the wire reply without rolling that state back.
                    super::process::reject_malformed_reply(&mut reply.packet)?;
                    if find_pseudoheader(&reply.packet, false)?.opt.is_some() {
                        super::tcp_service::add_ede(
                            &mut reply.packet,
                            self.edns_packet_max,
                            reply.flags.dnssec_ok,
                            0,
                            usize::from(self.edns_packet_max),
                        )?;
                    }
                    return Ok(Some(2));
                }
            }
        }
        if let Some(cache) = &self.cache {
            super::cache::clip_live_reply_ttls(
                &mut reply.packet,
                cache.policy().max_reply_ttl,
                rcode,
            )?;
        }
        Ok(Some(rcode))
    }

    fn recipient_packet(
        &self,
        reply: &UncheckedReply,
        recipient: &super::forward::Recipient,
        rcode: u16,
    ) -> Result<Option<(Vec<u8>, bool)>, DaemonError> {
        let mut packet = reply.packet.clone();
        recipient.restore_question(&mut packet, &reply.upstream_name)?;
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
            // forward.c skips the configured rrfilter for non-NOERROR
            // replies and for upstream TC packets. Filtering either case
            // would mutate a negative authority or a clipped prefix that C
            // deliberately returns untouched.
            if rcode == 0 && Header::parse(&packet)?.flags & 0x0200 == 0 {
                let filtered = filter_rrs(&mut packet, &self.filter_rr)?.matched != 0;
                if filtered && find_pseudoheader(&packet, false)?.opt.is_some() {
                    super::tcp_service::add_ede(
                        &mut packet,
                        self.edns_packet_max,
                        reply.flags.dnssec_ok,
                        17,
                        usize::from(self.edns_packet_max),
                    )?;
                }
            }
        }
        resize_reply(&mut packet);
        let clipped = packet.len() > usize::from(recipient.client.udp_limit);
        Ok(Some((
            limit_udp_reply(&packet, recipient.client.udp_limit)?,
            clipped,
        )))
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
        self.cached_answer_at_with_local_limit(query, question, now, external_local, self.max_udp)
    }

    fn cached_answer_at_with_local_limit(
        &mut self,
        query: &[u8],
        question: &super::forward::Question,
        now: i64,
        external_local: Option<&mut LocalDnsService>,
        max_udp: usize,
    ) -> Result<CachedAnswer, DaemonError> {
        self.cached_answer_at_with_edns_limit(query, question, now, external_local, max_udp, false)
    }

    #[allow(clippy::too_many_arguments)]
    fn cached_answer_at_with_edns_limit(
        &mut self,
        query: &[u8],
        question: &super::forward::Question,
        now: i64,
        external_local: Option<&mut LocalDnsService>,
        max_udp: usize,
        allow_options: bool,
    ) -> Result<CachedAnswer, DaemonError> {
        let Some(cache) = self.cache.as_mut() else {
            return Ok(CachedAnswer {
                forward_name: None,
                filtered: false,
                packet: None,
                stale: false,
            });
        };
        CacheContext {
            cache,
            counters: &mut self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
            filter_rr: &self.filter_rr,
        }
        .answer_udp_with_edns(
            query,
            question,
            now,
            external_local.unwrap_or(&mut self.local),
            max_udp,
            self.edns_packet_max,
            allow_options,
        )
        .map_err(Into::into)
    }

    /// TCP emits this before removing a bogus RR from its client response.
    /// Like C's helper, this insertion is independent of ordinary cache gates.
    pub fn cache_bogus_reply(&mut self, name: Name, ttl: u32, now: i64) {
        let Some(cache) = self.cache.as_mut() else {
            return;
        };
        CacheContext {
            cache,
            counters: &mut self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
            filter_rr: &self.filter_rr,
        }
        .insert_bogus(name, ttl, now, &self.local);
    }

    pub fn cache_tcp_reply(&mut self, packet: &[u8], now: i64) {
        let Ok(header) = Header::parse(packet) else {
            return;
        };
        let Some(cache) = self.cache.as_mut() else {
            return;
        };
        let _ = CacheContext {
            cache,
            counters: &mut self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
            filter_rr: &self.filter_rr,
        }
        .insert_reply_with_policy(
            packet,
            now,
            &self.local,
            &Default::default(),
            header.rcode().into(),
            OrdinaryCacheMode::Commit,
        );
    }

    /// Owner preview for a dynamic CNAME that will reach interface-name's
    /// enumeration point in answer_request. The caller has already applied
    /// source-dependent EDNS cacheability; this performs no cache lookup side
    /// effects and does not start collection or read network state itself.
    pub fn interface_query_needs_enumeration(&self, query: &[u8], now: i64) -> bool {
        if self.local.config.interface_records.rules.is_empty() {
            return false;
        }
        if super::local::interface_forward_name(&self.local.config, query).is_some() {
            return true;
        }
        let Ok(header) = Header::parse(query) else {
            return false;
        };
        if header.flags & 0x8100 != 0x0100
            || header.questions != 1
            || header.answers != 0
            || header.authorities != 0
            || header.opcode() != 0
        {
            return false;
        }
        let Ok(question) = super::forward::Question::parse(query) else {
            return false;
        };
        if question.class != 1 || !matches!(question.rrtype, 1 | 28 | 255) {
            return false;
        }
        if find_pseudoheader(query, true)
            .ok()
            .and_then(|scan| scan.opt)
            .is_some_and(|opt| opt.dnssec_ok())
        {
            return false;
        }
        let Some(target) = self
            .cache
            .as_ref()
            .and_then(|cache| cache.cname_terminal_name(&question.name, now))
        else {
            return false;
        };
        let mut terminal =
            super::wire::PacketWriter::new(header.id, header.flags, 65535).expect("fixed envelope");
        if terminal
            .question(&target, question.rrtype, question.class)
            .is_err()
        {
            return false;
        }
        super::local::interface_forward_name(&self.local.config, &terminal.finish()).is_some()
    }

    /// Read-only access for reply-time known-name checks in debug TCP mode.
    pub fn current_cache(&self) -> Option<&Cache> {
        self.cache.as_ref()
    }

    /// Retire only the memory-owned cache at the executable's final successful
    /// shutdown boundary. The process must exit after this call: the kernel
    /// reclaims these pages without a second allocator walk/unmap pass.
    ///
    /// Cache owns records, indices and reference-counted byte storage only;
    /// sockets, lease persistence, log writers and helper children are outside
    /// it and must still run their normal shutdown and Drop paths. Library
    /// users which continue running must use ordinary Drop instead.
    pub fn retire_cache_for_process_exit(&mut self) {
        std::mem::forget(self.cache.take());
    }

    pub fn tcp_cache_view(&self) -> Option<Cache> {
        self.cache.as_ref().map(Cache::snapshot)
    }

    pub fn tcp_cache_parameters(&self) -> (bool, u64) {
        (self.negative_cache, self.negative_ttl)
    }

    pub fn tcp_view_answer(
        cache: &mut Cache,
        query: &[u8],
        local: &mut LocalDnsService,
        now: i64,
        negative_cache: bool,
        negative_ttl: u64,
    ) -> Result<super::cache_engine::CachedAnswer, DaemonError> {
        let Ok(question) = super::forward::Question::parse(query) else {
            // Invalid questions cannot hit the cache. Let tcp_request's
            // existing query-error path send REFUSED instead of closing the
            // downstream connection on a cache lookup error.
            return Ok(super::cache_engine::CachedAnswer {
                forward_name: None,
                packet: None,
                stale: false,
                filtered: false,
            });
        };
        Self::tcp_view_answer_parsed(cache, query, Header::parse(query)?, &question,
            local, now, negative_cache, negative_ttl)
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp_view_answer_parsed(
        cache: &mut Cache,
        query: &[u8],
        header: Header,
        question: &super::forward::Question,
        local: &mut LocalDnsService,
        now: i64,
        negative_cache: bool,
        negative_ttl: u64,
    ) -> Result<super::cache_engine::CachedAnswer, DaemonError> {
        let filter = local.config.filter_rr.clone();
        let maximum = local.edns_packet_max;
        CacheContext {
            cache,
            counters: &mut CacheCounters::default(),
            negative_cache,
            negative_ttl,
            filter_rr: &filter,
        }
        .answer_tcp(query, header, question, now, local, maximum)
        .map_err(Into::into)
    }

    pub fn tcp_current_answer(
        &mut self,
        query: &[u8],
        local: &mut LocalDnsService,
        now: i64,
    ) -> Result<super::cache_engine::CachedAnswer, DaemonError> {
        let Some(cache) = self.cache.as_mut() else {
            return Ok(super::cache_engine::CachedAnswer {
                forward_name: None,
                packet: None,
                stale: false,
                filtered: false,
            });
        };
        Self::tcp_view_answer(
            cache,
            query,
            local,
            now,
            self.negative_cache,
            self.negative_ttl,
        )
    }

    pub fn tcp_view_local_answer(
        cache: Option<&mut Cache>,
        query: &[u8],
        local: &mut LocalDnsService,
        now: i64,
    ) -> Result<Option<Vec<u8>>, DaemonError> {
        local
            .handle_tcp_with_cache(query, now, cache)
            .map_err(Into::into)
    }

    /// Both packet owners use C's local/CNAME/cache order. A connection may
    /// supply its accepted cache view; UDP supplies the current generation.
    /// A miss retains C's transport-specific forwarding name without a second
    /// cache lookup, rotation, or expiry pass.
    #[allow(clippy::too_many_arguments)]
    pub fn answer_local_or_cached(
        mut cache: Option<&mut Cache>,
        query: &[u8],
        header: Header,
        question: &super::forward::Question,
        local: &mut LocalDnsService,
        now: i64,
        cacheable: bool,
        tcp: bool,
    ) -> Result<LocalLookup, DaemonError> {
        let mut name_lookup = None;
        let local_answer = local.lookup_local_parsed(
            query, header, question, now, cache.as_deref_mut(), tcp, &mut name_lookup,
        );
        // A malformed TCP question must reach tcp_request's REFUSED path;
        // UDP admission instead drops it. Valid questions share this lookup.
        let local_answer = if tcp { local_answer.ok().flatten() } else { local_answer? };
        if local_answer.as_ref().is_some_and(|answer| !answer.forward_rule) {
            return Ok(LocalLookup::answered(QueryResult::Local(local.finish_local_answer(local_answer.unwrap()))));
        }
        let mut forward_name = None;
        if cacheable {
            if let Some(cache) = cache.as_deref_mut() {
                let filtered_type = local.config.filter_rr.contains(&question.rrtype);
                let maximum = local.edns_packet_max;
                let limit = if tcp { 65536 } else { local.max_udp };
                let answer = CacheContext::answer_from_cache(
                    cache, query, header, question, now, local,
                    limit, maximum, tcp, filtered_type, name_lookup.as_ref(),
                )?;
                if let Some(packet) = answer.packet {
                    return Ok(LocalLookup::answered(if answer.stale {
                        QueryResult::Stale(packet)
                    } else {
                        QueryResult::Cached(packet)
                    }));
                }
                // receive_query restores the question before forward_query;
                // tcp_request keeps answer_request's terminal name instead.
                if tcp {
                    forward_name = answer.forward_name;
                }
            }
        }
        let local_answer = if let Some(name) = forward_name.as_ref() {
            local.lookup_forward_rule(query, header, question, name, now, cache.as_deref_mut(), tcp)?
        } else {
            local_answer
        };
        let forward_name = forward_name.map(|name| ForwardName {
            cached: cache.as_deref().is_some_and(|cache| cache.contains_forward_name(&name, now)),
            name,
        });
        Ok(LocalLookup {
            answer: local_answer.map(|answer| QueryResult::Local(local.finish_local_answer(answer))),
            forward_name,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn current_answer_local_or_cached(
        &mut self,
        query: &[u8],
        header: Header,
        question: &super::forward::Question,
        local: &mut LocalDnsService,
        now: i64,
        cacheable: bool,
        tcp: bool,
    ) -> Result<LocalLookup, DaemonError> {
        Self::answer_local_or_cached(
            self.cache.as_mut(), query, header, question, local, now, cacheable, tcp,
        )
    }

    pub fn tcp_view_extract(
        cache: &mut Cache,
        counters: &mut CacheCounters,
        packet: &mut Vec<u8>,
        local: &LocalDnsService,
        policy: &AddressPolicy,
        now: i64,
        rcode: u16,
        mode: super::cache::Extraction,
        negative_cache: bool,
        negative_ttl: u64,
        events: &mut Vec<QueryEvent>,
    ) -> Result<Option<super::cache::CacheTransaction>, WireError> {
        let maximum = cache.policy().max_reply_ttl;
        let result = CacheContext {
            cache,
            counters,
            negative_cache,
            negative_ttl,
            filter_rr: &local.config.filter_rr,
        }
        .insert_reply_with_events(packet, now, local, policy, rcode, mode, true, events);
        // Even a later extraction error may have written an earlier TTL prefix.
        let clipped = super::cache::clip_live_reply_ttls(packet, maximum, rcode);
        result.and_then(|transaction| clipped.map(|_| transaction))
    }

    pub fn tcp_current_extract(
        &mut self,
        packet: &mut Vec<u8>,
        policy: &AddressPolicy,
        now: i64,
        rcode: u16,
        mode: super::cache::Extraction,
        events: &mut Vec<QueryEvent>,
    ) -> Result<(), WireError> {
        let Some(cache) = self.cache.as_mut() else {
            return Ok(());
        };
        let maximum = cache.policy().max_reply_ttl;
        let result = CacheContext {
            cache,
            counters: &mut self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
            filter_rr: &self.filter_rr,
        }
        .insert_reply_with_events(packet, now, &self.local, policy, rcode, mode, false, events)
        .map(|_| ());
        let clipped = super::cache::clip_live_reply_ttls(packet, maximum, rcode);
        result.and(clipped)
    }

    pub fn import_tcp_cache_transfer(
        &mut self,
        transaction: super::cache::CacheTransaction,
        now: i64,
        local: &LocalDnsService,
    ) -> bool {
        let Some(cache) = self.cache.as_mut() else {
            return false;
        };
        CacheContext {
            cache,
            counters: &mut self.cache_counters,
            negative_cache: self.negative_cache,
            negative_ttl: self.negative_ttl,
            filter_rr: &self.filter_rr,
        }
        // DHCP/hosts publication belongs to the event owner's current local
        // generation, independently of this daemon's resolver state.
        .import_transfer(transaction, now, local)
    }

    pub fn cached_tcp_answer(
        &mut self,
        query: &[u8],
        local: &mut LocalDnsService,
        now: i64,
    ) -> Result<Option<Vec<u8>>, DaemonError> {
        let question = super::forward::Question::parse(query).map_err(DaemonError::Wire)?;
        self.cached_answer_at_with_local_limit(query, &question, now, Some(local), 65536)
            .map(|answer| answer.packet)
    }

    /// TCP uses its decorated frame for local OPT semantics; the owner has
    /// already evaluated source dependence from its connection MAC snapshot.
    pub fn cached_tcp_answer_with_edns(
        &mut self,
        query: &[u8],
        local: &mut LocalDnsService,
        now: i64,
        cacheable: bool,
    ) -> Result<Option<Vec<u8>>, DaemonError> {
        if !cacheable {
            return Ok(None);
        }
        let question = super::forward::Question::parse(query)?;
        self.cached_answer_at_with_edns_limit(query, &question, now, Some(local), 65536, true)
            .map(|answer| answer.packet)
    }

    #[cfg(test)]
    fn cache_reply_at(&mut self, packet: &[u8], now: i64) {
        self.cache_tcp_reply(packet, now);
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

fn server_usable(row: &SourceRule, local_addresses: &[SocketAddr]) -> bool {
    let address = row.address.or_else(|| match &row.rule.target {
        RuleTarget::Upstream(endpoint) => super::routing::validate_endpoint(endpoint).ok(),
        _ => None,
    });
    address.is_none_or(|address| {
        !matches!(address.ip(), IpAddr::V4(address) if address.is_unspecified())
            && !local_addresses
                .iter()
                .any(|local| super::forward::same_endpoint(*local, address))
    })
}

pub(super) fn address_policy(config: &DnsConfig) -> Result<AddressPolicy, DaemonError> {
    let mut rebind_domains = Vec::with_capacity(config.rebind_domains.len());
    for domain in &config.rebind_domains {
        let text = std::str::from_utf8(domain).map_err(|_| ConfigError("bad rebind domain"))?;
        // C permits empty internal labels in this textual exception list.
        // They cannot match a valid wire name, but must not abort startup.
        if let Ok(name) = Name::from_ascii(text) {
            rebind_domains.push(name.canonical_wire());
        }
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
    // Interface selection and local-source admission are consumed by the
    // containing UDP/TCP listeners before this transport-independent engine.
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
#[path = "daemon_route_resend_tests.rs"]
mod route_resend_tests;

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
    fn active_resolver_default_precedes_only_the_empty_wildcard_literal() {
        for (pattern, forwards) in [("*.", true), ("#", false)] {
            let mut config = DnsConfig::default();
            apply(
                &mut config,
                format!("address=/{pattern}/192.0.2.77").as_bytes(),
            );
            let mut daemon = DnsDaemon::with_random(
                config,
                Hosts::new(),
                &["127.0.0.2:53".parse().unwrap()],
                options(),
                Counter(0),
            )
            .unwrap();
            for query in [query("example.test", 3), query("single", 4)] {
                assert_eq!(daemon.local.handle_udp(&query).unwrap().is_none(), forwards);
                assert_eq!(
                    daemon.local.handle_tcp_payload(&query).unwrap().is_none(),
                    forwards
                );
            }
        }
    }

    #[test]
    fn source_publication_keeps_cache_and_tcp_routes_until_explicit_reload() {
        let config = DnsConfig::default();
        let mut daemon =
            DnsDaemon::with_random(config, Hosts::new(), &[], options(), Counter(0)).unwrap();
        daemon.enable_cache(8, 0, 0, StalePolicy::Disabled);
        let name = Name::from_ascii("cached.test").unwrap();
        let mut writer = PacketWriter::new(9, 0x8180, 512).unwrap();
        writer.question(&name, 1, 1).unwrap();
        writer
            .record(Section::Answer, &name, 1, 1, 120, &[192, 0, 2, 8])
            .unwrap();
        daemon.cache_reply_at(&writer.finish(), 100);
        let rows = vec![SourceRule::resolver("[fe80::1%7]:53".parse().unwrap(), 1)];
        daemon
            .replace_server_source(Source::Resolv, rows, &[])
            .unwrap();
        let old_tcp = daemon.routing.snapshot();
        let config = daemon.local_config();
        assert_eq!(config.rules.len(), 1);
        daemon
            .replace_server_source(
                Source::Resolv,
                vec![SourceRule::resolver("192.0.2.9:53".parse().unwrap(), 1)],
                &[],
            )
            .unwrap();
        let route = old_tcp.select(&name, 1, 1, false);
        assert_eq!(
            old_tcp.group(route.group.unwrap()).unwrap().servers[0].address,
            "[fe80::1%7]:53".parse().unwrap()
        );
        let query = query("cached.test", 8);
        let question = super::super::forward::Question::parse(&query).unwrap();
        assert!(daemon
            .cached_answer_at(&query, &question, 101)
            .unwrap()
            .is_some());
        let local_rule = super::super::files::server_line(b"server=/local.test/")
            .unwrap()
            .into_iter()
            .map(|rule| SourceRule::configured(rule, 1))
            .collect();
        daemon
            .replace_server_source(Source::ServersFile, local_rule, &[])
            .unwrap();
        assert!(daemon
            .local
            .handle_udp(&query_type("local.test", 1, 7))
            .unwrap()
            .is_some());
        daemon
            .check_server_addresses(&["192.0.2.9:53".parse().unwrap()])
            .unwrap();
        assert_eq!(daemon.routing.groups().count(), 0);
        assert!(daemon
            .cached_answer_at(&query, &question, 101)
            .unwrap()
            .is_some());
        daemon.reload_hosts(Hosts::new());
        assert!(daemon
            .cached_answer_at(&query, &question, 101)
            .unwrap()
            .is_none());
    }

    #[test]
    fn tcp_bogus_event_publishes_matching_owner_despite_no_negcache() {
        let mut config = DnsConfig::default();
        config.no_resolv = true;
        let mut daemon =
            DnsDaemon::with_random(config, Hosts::new(), &[], options(), Counter(0)).unwrap();
        daemon.enable_cache(4, 0, 0, StalePolicy::Disabled);
        daemon.enable_negative_cache(999, false);
        daemon.cache_bogus_reply(Name::from_ascii("target.test").unwrap(), 120, 1000);
        let request = query("target.test", 12);
        let question = super::super::forward::Question::parse(&request).unwrap();
        let answer = daemon
            .cached_answer_at(&request, &question, 1119)
            .unwrap()
            .unwrap();
        assert_eq!(Header::parse(&answer).unwrap().rcode(), 3);
        assert_eq!(daemon.cache_counters().inserted, 1);
        assert!(daemon
            .cached_answer_at(&request, &question, 1120)
            .unwrap()
            .is_none());
        let original = query("caller.test", 13);
        let question = super::super::forward::Question::parse(&original).unwrap();
        assert!(daemon
            .cached_answer_at(&original, &question, 1001)
            .unwrap()
            .is_none());
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
    fn configured_a_filter_elides_forwarded_answer_after_cache_extraction() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let request = &input[..length];
            let header = Header::parse(request).unwrap();
            let name = Name::from_ascii("filtered.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8180, 1232).unwrap();
            writer.question(&name, 1, 1).unwrap();
            writer
                .record(Section::Answer, &name, 1, 1, 30, &[192, 0, 2, 9])
                .unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
        });
        let mut config = DnsConfig::default();
        apply(&mut config, b"filter-A");
        let mut daemon =
            DnsDaemon::with_random(config, Hosts::new(), &[address], options(), Counter(0))
                .unwrap();
        daemon.enable_cache(8, 0, 60, StalePolicy::Disabled);
        assert!(matches!(
            daemon.handle_udp(
                &query("filtered.test", 0x1234),
                ClientRequest {
                    source: "127.0.0.1:53000".parse().unwrap(),
                    destination: "127.0.0.1".parse().unwrap(),
                    interface: 0,
                },
            ),
            Ok(QueryResult::Forwarded(_))
        ));
        let responses = daemon.poll(Duration::from_secs(1)).unwrap();
        assert_eq!(responses.len(), 1);
        let packet = Message::parse(&responses[0].packet).unwrap();
        assert_eq!(packet.header.answers, 0);
        worker.join().unwrap();
    }

    #[test]
    fn filtered_cache_miss_uses_existing_other_type_as_nodata() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut input = [0; 2048];
            let (length, peer) = server.recv_from(&mut input).unwrap();
            let header = Header::parse(&input[..length]).unwrap();
            let name = Name::from_ascii("shortcut.test").unwrap();
            let mut writer = PacketWriter::new(header.id, 0x8180, 1232).unwrap();
            writer.question(&name, 1, 1).unwrap();
            writer
                .record(Section::Answer, &name, 1, 1, 30, &[192, 0, 2, 10])
                .unwrap();
            server.send_to(&writer.finish(), peer).unwrap();
        });
        let mut config = DnsConfig::default();
        apply(&mut config, b"filter-AAAA");
        let mut daemon =
            DnsDaemon::with_random(config, Hosts::new(), &[address], options(), Counter(0))
                .unwrap();
        daemon.enable_cache(8, 0, 60, StalePolicy::Disabled);
        let client = ClientRequest {
            source: "127.0.0.1:53001".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        };
        assert!(matches!(
            daemon.handle_udp(&query("shortcut.test", 0x2001), client.clone()),
            Ok(QueryResult::Forwarded(_))
        ));
        assert_eq!(daemon.poll(Duration::from_secs(1)).unwrap().len(), 1);
        let result = daemon
            .handle_udp(&query_type("shortcut.test", 28, 0x2002), client)
            .unwrap();
        let QueryResult::Cached(packet) = result else {
            panic!("filtered cache shortcut forwarded unexpectedly")
        };
        assert_eq!(Message::parse(&packet).unwrap().header.answers, 0);
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
