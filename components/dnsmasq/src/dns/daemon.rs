//! DNS daemon integration for the UDP client/upstream path.
//!
//! This is deliberately a small, socket-independent boundary.  The containing
//! process owns the listening UDP socket: [`DnsDaemon::handle_udp`] accepts one
//! client datagram and either returns a local answer or starts an upstream
//! transaction, while [`DnsDaemon::poll`] turns completed upstream events into
//! client responses.  TCP listeners, resolver-file polling, cache insertion,
//! and the remaining `forward.c::process_reply` policy are separate work.

use super::forward::{Client, Options as ForwardOptions, QueryId, Random, Scope};
use super::forward_service::ForwardDispatcher;
use super::process::{process_reply, AddressPolicy, ProcessAction, ProcessError};
use super::reply::{limit_udp_reply, prepare_reply, ReplyPolicy};
use super::routing::{RoutingError, RoutingTable};
use super::service::{LocalDnsService, ServiceError};
use super::upstream::{OsRandom, ResolveError, UpstreamResolver};
use super::wire::{Name, WireError};
use crate::config::dns::{DnsConfig, DomainPattern, RuleTarget, ServerRule};
use crate::config::{Error as ConfigError, FastRetry};
use crate::hosts::Hosts;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

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
    pub packet: Vec<u8>,
}

/// Result of admitting one client query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    /// A local answer is ready to send immediately.
    Local(Vec<u8>),
    /// The query was admitted to the upstream transaction table.
    Forwarded(QueryId),
    /// The query was syntactically valid but has no local answer or upstream
    /// route.  This is an explicit drop, never an implicit NXDOMAIN.
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
    pub upstream_timeout: Duration,
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
            upstream_timeout: Duration::from_secs(10),
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
    policy: AddressPolicy,
    proxy_dnssec: bool,
    max_udp: usize,
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

        // dnsmasq implicitly uses the active resolver file for an ordinary
        // query.  Represent that default as a normal routing rule so every
        // query goes through the same RoutingTable/ForwardDispatcher path.
        let mut routing_config = config.clone();
        if !config.no_resolv
            && !default_resolvers.is_empty()
            && !routing_config.rules.iter().any(|rule| {
                matches!(rule.target, RuleTarget::DefaultResolvers)
                    && rule.domain.suffix.is_empty()
                    && !rule.domain.dotless
            })
        {
            routing_config.rules.push(ServerRule {
                domain: DomainPattern {
                    suffix: Vec::new(),
                    wildcard: false,
                    wildcard_dot: false,
                    dotless: false,
                },
                target: RuleTarget::DefaultResolvers,
            });
        }
        let routing = RoutingTable::from_config(&routing_config, default_resolvers)?;
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
        let upstream = UpstreamResolver::with_random(dispatcher, random, options.upstream_timeout)?;
        let policy = address_policy(&config)?;
        let local =
            LocalDnsService::new(config, hosts, options.local_ttl, options.max_udp.max(512));
        Ok(Self {
            local,
            routing,
            upstream,
            policy,
            proxy_dnssec: options.proxy_dnssec,
            max_udp: options.max_udp.max(512),
        })
    }

    pub fn pending_count(&self) -> usize {
        self.upstream.pending_count()
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
        if let Some(answer) = self.local.handle_udp(query)? {
            return Ok(QueryResult::Local(answer));
        }
        let question = super::forward::Question::parse(query).map_err(DaemonError::Wire)?;
        let route = self
            .routing
            .select(&question.name, question.rrtype, question.class, false);
        let Some(group) = route.upstream_group() else {
            return Ok(QueryResult::Dropped);
        };
        let client = Client {
            source: client.source,
            destination: client.destination,
            interface: client.interface,
            listener: None,
            udp_limit: 512,
            log_id: u64::from(question.rrtype),
        };
        let submission = self
            .upstream
            .start_udp(query, client, group, Scope::Shared)?;
        Ok(QueryResult::Forwarded(submission.id))
    }

    /// Poll upstream sockets and produce client-visible UDP replies.  The
    /// reply envelope is applied, but this intentionally does not claim the
    /// full C `process_reply` contract (cache/SOA/ubus/TCP fallback remain
    /// outside this adapter).
    pub fn poll(&mut self, wait: Duration) -> Result<Vec<ClientResponse>, DaemonError> {
        let events = self.upstream.poll(wait)?;
        let mut responses = Vec::new();
        for event in events {
            let reply = event.result?;
            for recipient in reply.recipients {
                let mut packet = reply.packet.clone();
                recipient.restore_question(&mut packet)?;
                let report = process_reply(&mut packet, &self.policy)?;
                if report.action == ProcessAction::Ignore {
                    continue;
                }
                let envelope = prepare_reply(
                    &packet,
                    ReplyPolicy {
                        client_had_opt: reply.flags.had_opt,
                        checking_disabled: reply.flags.checking_disabled,
                        proxy_dnssec: self.proxy_dnssec,
                        edns_packet_max: recipient.client.udp_limit,
                    },
                )?;
                let packet = limit_udp_reply(&envelope.packet, recipient.client.udp_limit)?;
                responses.push(ClientResponse {
                    destination: recipient.client.source,
                    packet,
                });
            }
        }
        Ok(responses)
    }
}

fn address_policy(config: &DnsConfig) -> Result<AddressPolicy, DaemonError> {
    let mut rebind_domains = Vec::with_capacity(config.rebind_domains.len());
    for domain in &config.rebind_domains {
        let text = std::str::from_utf8(domain).map_err(|_| ConfigError("bad rebind domain"))?;
        rebind_domains.push(Name::from_ascii(text)?.canonical_wire());
    }
    Ok(AddressPolicy {
        stop_rebind: config.stop_rebind,
        rebind_localhost_ok: config.rebind_localhost_ok,
        rebind_domains,
        ..AddressPolicy::default()
    })
}

fn validate_runtime_config(config: &DnsConfig) -> Result<(), DaemonError> {
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
    if config.domain_needed
        || config.bogus_priv
        || config.no_poll
        || config.no_negative_cache
        || config.localise_queries
    {
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
        let name = Name::from_ascii(name).unwrap();
        let mut writer = PacketWriter::new(id, 0x100, 1232).unwrap();
        writer.question(&name, 1, 1).unwrap();
        writer.finish()
    }

    fn options() -> DaemonOptions {
        DaemonOptions {
            upstream_timeout: Duration::from_secs(1),
            ..DaemonOptions::default()
        }
    }

    #[test]
    fn local_and_unowned_queries_use_distinct_boundaries() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"no-resolv");
        apply(&mut config, b"host-record=router.test,192.0.2.1");
        let mut daemon =
            DnsDaemon::with_random(config, Hosts::new(), &[], options(), Counter(0)).unwrap();
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
        assert_eq!(
            daemon
                .handle_udp(
                    &query("unknown.test", 8),
                    ClientRequest {
                        source: "127.0.0.1:53000".parse().unwrap(),
                        destination: "127.0.0.1".parse().unwrap(),
                        interface: 0,
                    },
                )
                .unwrap(),
            QueryResult::Dropped
        );
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
