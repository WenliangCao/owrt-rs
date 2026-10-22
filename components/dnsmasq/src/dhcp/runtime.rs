//! DHCPv4 runtime boundary after datagram admission.
//!
//! The C path owns four distinct steps (`dhcp.c:130-530`): bounded admission,
//! dispatch/context selection, reply construction and destination/send cleanup.
//! This module models those steps without hiding unsupported relay/PXE/
//! leasequery routes behind a local send. State selection is caller-configured:
//! tests may provide a callback, while [`StateProvider`] supplies the local
//! DHCP/BOOTP state adapter without opening a socket here.

use super::message_counters::MessageCounters;
use super::reply::{
    broken_string_option, build_reply_with_boot, needs_renewal_fuzz, ReplyError, ReplyOption,
};
use super::service::{Dispatch, DispatchKind, Route};
use super::state::{self, Environment, HostPolicy, Name, Outcome, Reply, Request};
use super::{
    allocation::{AddressRange, ProbeResult},
    lease::{LeaseCounters, LeaseStore},
};
use crate::config::dhcp::{BootConfig, DhcpOption, OptionValue};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const BROADCAST_FLAG: u16 = 0x8000;

/// A socket-independent sender. Linux's audited `DatagramSocket` implements
/// this trait below; unit tests use a recorder/failure stub instead.
pub trait DatagramSender {
    fn interface_name(&mut self, _interface: u32) -> io::Result<Option<[u8; 16]>> {
        Ok(None)
    }
    fn prepare_destination(&mut self, _destination: &Destination) -> io::Result<()> {
        Ok(())
    }
    fn send(&mut self, bytes: &[u8], destination: &Destination) -> io::Result<()>;
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl DatagramSender for crate::net::DatagramSocket {
    fn interface_name(&mut self, interface: u32) -> io::Result<Option<[u8; 16]>> {
        crate::net::interface_name(self, interface).map(Some)
    }
    fn prepare_destination(&mut self, destination: &Destination) -> io::Result<()> {
        if let Some(arp) = &destination.arp {
            let SocketAddr::V4(address) = destination.address else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DHCP ARP needs IPv4",
                ));
            };
            if *address.ip() != arp.address {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DHCP ARP destination mismatch",
                ));
            }
            return if let Some(name) = &arp.interface_name {
                crate::net::inject_arp_with_name(
                    self,
                    address,
                    arp.hardware_type,
                    &arp.hardware_address,
                    name,
                )
            } else {
                crate::net::inject_arp(
                    self,
                    destination.interface,
                    address,
                    arp.hardware_type,
                    &arp.hardware_address,
                )
            };
        }
        Ok(())
    }

    fn send(&mut self, bytes: &[u8], destination: &Destination) -> io::Result<()> {
        match destination.kind {
            DestinationKind::Broadcast => {
                self.set_broadcast(true)?;
                self.send_on_interface_once(bytes, destination.address, destination.interface)
            }
            DestinationKind::Client | DestinationKind::Peer => {
                if destination.interface == 0 {
                    self.send_once(bytes, destination.address, None)
                } else {
                    self.send_on_interface_once(bytes, destination.address, destination.interface)
                }
            }
        }
    }
}

/// Caller-owned state transition. The callback must commit the same lease/name
/// side effects as the state layer before returning its `Outcome`; runtime send
/// failure never rolls those effects back.
pub trait OutcomeProvider {
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError>;

    /// Record actual serialized output before destination/ARP/send failure.
    fn record_reply(
        &mut self,
        _request: super::packet::Packet<'_>,
        _reply: Reply,
        _output: &[u8],
        _omitted_options: &[u8],
        _option_warnings: &[super::logging::OptionWarning],
    ) {
    }

    /// Encode an optional direct PXE reply into the supplied output buffer.
    ///
    /// On `Some`, the provider must have written a complete BOOTP header and
    /// return its actual encoded length, no greater than the output buffer.
    /// Violating this implementation contract is a programming bug and may panic.
    fn direct_pxe_reply(
        &mut self,
        _request: super::packet::Packet<'_>,
        _output: &mut [u8],
    ) -> Result<Option<super::reply::ReplyEncoding>, RuntimeError> {
        Ok(None)
    }

    /// Encode an optional leasequery reply into the supplied output buffer.
    ///
    /// On `Some`, the provider must have written a complete BOOTP header and
    /// return its actual encoded length, no greater than the output buffer.
    /// Violating this implementation contract is a programming bug and may panic.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn lease_query_reply(
        &mut self,
        _dispatch: &Dispatch<'_>,
        _interface_name: Option<&[u8]>,
        _source: Ipv4Addr,
        _output: &mut [u8],
    ) -> Result<Option<usize>, RuntimeError> {
        Ok(None)
    }

    /// Interface name captured before state/probing, matching dhcp.c's event
    /// and routing snapshot. Ordinary pure providers need no interface string.
    fn resolve_on_interface(
        &mut self,
        dispatch: &Dispatch<'_>,
        _interface: Option<&[u8]>,
    ) -> Result<Outcome, RuntimeError> {
        self.resolve(dispatch)
    }

    /// Network defaults from the context actually selected by this outcome.
    /// Explicit selected options take precedence over these defaults.
    fn network_options(&self, _outcome: &Outcome) -> Option<NetworkOptions> {
        None
    }

    fn boot_config(&self) -> Option<&BootConfig> {
        None
    }

    fn configured_options(&self) -> &[DhcpOption] {
        &[]
    }
    fn selected_options(&self, _: &Outcome) -> crate::config::dhcp::FilteredOptions<'_> {
        crate::config::dhcp::option_filter(
            self.configured_options(),
            &[],
            &[],
            &[],
            self.pxe_encoding().option_mode,
        )
    }
    fn pxe_encoding(&self) -> PxeEncoding<'_> {
        PxeEncoding::default()
    }
    fn client_update(&self) -> bool {
        false
    }

    /// Request tags selected by the daemon's do_options policy. This changes
    /// the reply flag before the existing destination/ARP decision.
    fn force_broadcast(&self, _outcome: &Outcome) -> bool {
        false
    }

    /// Some(0) is a failed hosts-name lookup and deliberately replaces the
    /// context default. None means no explicit override.
    fn boot_next_server(&mut self) -> io::Result<Option<Ipv4Addr>> {
        if self
            .boot_config()
            .is_some_and(|boot| boot.next_server_name.is_some())
        {
            return Err(io::Error::other("DHCP boot hosts lookup is not attached"));
        }
        Ok(self
            .boot_config()
            .map(|boot| boot.next_server)
            .filter(|address| !address.is_unspecified()))
    }

    fn allow_override(&self) -> bool {
        true
    }

    /// Selected hostname/domain after the same state transaction which will
    /// be sent. OFFER suppression and lease-name ownership belong to callers.
    fn reply_names(
        &self,
        _packet: super::packet::Packet<'_>,
        _outcome: &Outcome,
    ) -> Option<ReplyNames<'_>> {
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReplyNames<'a> {
    pub hostname: Option<&'a [u8]>,
    pub domain: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkOptions {
    /// BOOTP siaddr default from the selected context (do_options:2668).
    pub next_server: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    /// The caller only supplies this when DNS is enabled on standard port 53.
    pub dns_server: Option<Ipv4Addr>,
}

/// Per-packet PXE additions to the existing option encoder. The default
/// preserves standalone legacy callers; a production provider uses ordinary
/// even with no PXE client to retain C's pxe_arch != 1 encapsulation behavior.
#[derive(Clone, Copy, Debug)]
pub struct PxeEncoding<'a> {
    pub option_mode: u8,
    pub encap_mode: u8,
    pub client: Option<&'a super::pxe::Client>,
    pub vendor_prefixes: &'a [Vec<u8>],
    pub generated_vendor: &'a [(u8, Vec<u8>)],
    pub direct: bool,
    pub include_vendor: bool,
}

impl Default for PxeEncoding<'_> {
    fn default() -> Self {
        Self {
            option_mode: 0,
            encap_mode: 0,
            client: None,
            vendor_prefixes: &[],
            generated_vendor: &[],
            direct: false,
            include_vendor: true,
        }
    }
}

impl<'a> PxeEncoding<'a> {
    pub fn ordinary(
        client: Option<&'a super::pxe::Client>,
        vendor_prefixes: &'a [Vec<u8>],
        generated_vendor: &'a [(u8, Vec<u8>)],
    ) -> Self {
        let architecture = client.and_then(|client| client.architecture);
        Self {
            option_mode: u8::from(architecture.is_some()),
            encap_mode: u8::from(architecture != Some(1)),
            client,
            vendor_prefixes,
            generated_vendor,
            direct: false,
            include_vendor: true,
        }
    }

    pub fn direct(
        client: &'a super::pxe::Client,
        vendor_prefixes: &'a [Vec<u8>],
        generated_vendor: &'a [(u8, Vec<u8>)],
        include_vendor: bool,
    ) -> Self {
        Self {
            option_mode: 2,
            encap_mode: 2,
            client: Some(client),
            vendor_prefixes,
            generated_vendor,
            direct: true,
            include_vendor,
        }
    }

    fn active_client(&self) -> Option<&'a super::pxe::Client> {
        self.client
            .filter(|client| self.direct || client.architecture.is_some())
    }
}

impl<F> OutcomeProvider for F
where
    F: for<'a> FnMut(&Dispatch<'a>) -> Result<Outcome, RuntimeError>,
{
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        self(dispatch)
    }
}

type RapidName<'a> =
    dyn FnMut(Ipv4Addr, usize) -> Result<Option<(Vec<u8>, bool)>, RuntimeError> + 'a;

/// A small state adapter for the local DHCP/BOOTP path.  It owns no socket or
/// event loop; callers configure contexts/tags and pass it to
/// [`process`] or `crate::dhcp::service::SocketListener`.  This
/// keeps the C ordering explicit: lease allocation, expiry and hostname/DNS
/// dirtying happen before runtime builds or sends the reply.
pub struct StateProvider<'a, F> {
    pub store: &'a mut LeaseStore,
    pub ranges: &'a mut [AddressRange],
    pub tags: &'a [&'a [u8]],
    pub host: Option<&'a mut HostPolicy>,
    pub reserved: &'a [Ipv4Addr],
    pub configured_name: Option<&'a [u8]>,
    /// Suppress an unauthenticated client name on ACK without clearing a
    /// name already owned by the lease. Configured/static names still win.
    pub ignore_client_name: bool,
    pub generated_name: Option<&'a [u8]>,
    /// Rapid commit resolves hostname policy only after DISCOVER selects yiaddr.
    pub(crate) rapid_name: Option<&'a mut RapidName<'a>>,
    /// Scoped BOOTP permission indexed by the context finally chosen by state.
    pub bootp_contexts: &'a [bool],
    pub domains: Option<&'a crate::config::dhcp::NameDomains>,
    pub environment: Environment<'a>,
    pub quiet_dhcp: bool,
    /// Optional owner supplied by the daemon; pure state callers can omit it.
    pub message_counters: Option<&'a mut MessageCounters>,
    pub(crate) event_sink: Option<&'a mut state::LogSink<'a>>,
    /// Each probe borrows the current lease counters after packet/BOOTP prune.
    /// The owner can report live counters while its provider is borrowed.
    pub probe: F,
    pub before_offer: Option<&'a mut state::OfferWait<'a>>,
}

impl<'a, F> StateProvider<'a, F> {
    pub fn new(
        store: &'a mut LeaseStore,
        ranges: &'a mut [AddressRange],
        tags: &'a [&'a [u8]],
        host: Option<&'a mut HostPolicy>,
        reserved: &'a [Ipv4Addr],
        environment: Environment<'a>,
        probe: F,
    ) -> Self {
        Self {
            store,
            ranges,
            tags,
            host,
            reserved,
            configured_name: None,
            ignore_client_name: false,
            generated_name: None,
            rapid_name: None,
            bootp_contexts: &[],
            domains: None,
            environment,
            quiet_dhcp: false,
            message_counters: None,
            event_sink: None,
            probe,
            before_offer: None,
        }
    }
}

impl<'a, F> OutcomeProvider for StateProvider<'a, F>
where
    F: FnMut(Ipv4Addr, u32, LeaseCounters) -> ProbeResult,
{
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        let mut environment = self.environment;
        environment.interface = dispatch.ingress.interface_index;
        environment.unicast_destination = dispatch.ingress.unicast_destination;
        // dhcp.c prunes before dhcp_reply(), including packets whose state
        // branch ultimately returns no response. Retain those leases in the
        // owned outcome so the caller can queue deletion/name notifications.
        let mut expired = self.store.prune(None, environment.now);
        let packet = dispatch.packet;
        // rfc2131.c:390-410,1052-1055: no initial context, or a proxy-only
        // head context, returns before ordinary message-counter write sites.
        // An INFORM may lose its narrowed context later, but still requires
        // this initial serving context. Packet-triggered pruning is retained.
        if self
            .ranges
            .first()
            .is_none_or(|range| range.kind == super::allocation::RangeKind::Proxy)
        {
            return Ok(Outcome {
                reply: Reply::Ignore,
                lost_names: LeaseStore::names_lost(&expired),
                newly_allocated: false,
                removed: expired,
            });
        }
        let hostname = (!self.ignore_client_name)
            .then(|| packet.client_hostname())
            .flatten();
        let name = self
            .configured_name
            .or(self.generated_name)
            .or(hostname.as_deref())
            .map(|hostname| Name {
                hostname,
                domains: self.domains,
                // rfc2131.c sets hostname_auth only for configured/hosts names,
                // independently of the server's dhcp-authoritative lease policy.
                authoritative: self.configured_name.is_some(),
            });
        let request = |name| Request {
            packet,
            tags: self.tags,
            host: self.host.as_deref(),
            reserved: self.reserved,
            name,
            environment,
        };
        let mut discarded_counters = MessageCounters::default();
        let counters = self
            .message_counters
            .as_deref_mut()
            .unwrap_or(&mut discarded_counters);
        let mut events = self.event_sink.as_deref_mut();
        let outcome = match packet.message_type() {
            0 => state::bootp_counted_logged(
                self.store,
                self.ranges,
                request(name),
                &mut self.probe,
                counters,
                self.bootp_contexts,
                events,
            ),
            1 => {
                let offer = state::select_discover_counted(
                    self.store,
                    self.ranges,
                    &request(name),
                    &mut self.probe,
                    self.quiet_dhcp,
                    counters,
                    events.as_deref_mut(),
                    self.before_offer.as_deref_mut(),
                )
                .map_err(|error| RuntimeError::State(format!("{error:?}")))?;
                let rapid_name = if environment.rapid_commit && packet.option(80, 0).is_some() {
                    if let (
                        Some(resolve),
                        Reply::Offer {
                            address, context, ..
                        },
                    ) = (self.rapid_name.as_deref_mut(), offer.reply)
                    {
                        Some(resolve(address, context)?)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let name = rapid_name.as_ref().map_or(name, |resolved| {
                    resolved.as_ref().map(|(hostname, authoritative)| Name {
                        hostname,
                        authoritative: *authoritative,
                        domains: self.domains,
                    })
                });
                state::finish_discover_counted(
                    self.store,
                    self.ranges,
                    request(name),
                    offer,
                    counters,
                    events,
                )
            }
            3 => state::request_counted(self.store, self.ranges, request(name), counters, events),
            4 => Ok(Outcome {
                reply: Reply::Ignore,
                removed: state::decline_counted_logged(
                    self.store,
                    self.ranges,
                    packet,
                    self.host.as_deref_mut(),
                    environment,
                    counters,
                    events,
                ),
                lost_names: Vec::new(),
                newly_allocated: false,
            }),
            7 => Ok(Outcome {
                reply: Reply::Ignore,
                removed: state::release_counted(
                    self.store,
                    self.ranges,
                    packet,
                    self.tags,
                    environment,
                    counters,
                    events,
                ),
                lost_names: Vec::new(),
                newly_allocated: false,
            }),
            8 => state::inform_counted(self.store, self.ranges, request(name), counters, events),
            // The runtime filters PXE, relay, leasequery and unknown routes
            // before this callback. A known but client-only message type is a
            // no-reply state transition in rfc2131.c.
            _ => Ok(Outcome {
                reply: Reply::Ignore,
                removed: Vec::new(),
                lost_names: Vec::new(),
                newly_allocated: false,
            }),
        };
        let mut outcome = outcome.map_err(|error| RuntimeError::State(format!("{error:?}")))?;
        let mut lost_names = LeaseStore::names_lost(&expired);
        lost_names.extend(LeaseStore::names_lost(&outcome.removed));
        lost_names.append(&mut outcome.lost_names);
        if !expired.is_empty() {
            expired.append(&mut outcome.removed);
            outcome.removed = expired;
        }
        outcome.lost_names = lost_names;
        Ok(outcome)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationKind {
    Broadcast,
    Client,
    Peer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub address: SocketAddr,
    pub interface: u32,
    pub kind: DestinationKind,
    pub arp: Option<ArpRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpRequest {
    pub address: Ipv4Addr,
    pub hardware_type: u8,
    pub hardware_address: Vec<u8>,
    /// Snapshot from before state/prune/ICMP work, retaining C rename behavior.
    pub interface_name: Option<[u8; 16]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeEvent {
    Admitted {
        kind: DispatchKind,
        route: Route,
        interface: u32,
    },
    StateCommitted {
        removed: usize,
        lost_names: usize,
    },
    NoReply,
    Built {
        length: usize,
        omitted: usize,
        overload: u8,
    },
    DestinationSelected(Destination),
    ArpInjected,
    ArpInjectionFailed {
        kind: io::ErrorKind,
        raw_os_error: Option<i32>,
    },
    Sent {
        length: usize,
    },
    Cleanup {
        outcome_dropped: bool,
    },
}

#[derive(Debug)]
pub enum RuntimeError {
    Unsupported { kind: DispatchKind, route: Route },
    State(String),
    Interface(io::Error),
    Reply(ReplyError),
    Random(io::Error),
    BootLookup(io::Error),
    Send(io::Error),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { kind, route } => {
                write!(
                    formatter,
                    "unsupported DHCP dispatch {kind:?} on route {route:?}"
                )
            }
            Self::State(message) => write!(formatter, "DHCP state transition failed: {message}"),
            Self::Interface(error) => write!(formatter, "DHCP interface lookup failed: {error}"),
            Self::Reply(error) => write!(formatter, "DHCP reply construction failed: {error}"),
            Self::Random(error) => write!(formatter, "DHCP entropy read failed: {error}"),
            Self::BootLookup(error) => write!(formatter, "DHCP boot lookup failed: {error}"),
            Self::Send(error) => write!(formatter, "DHCP reply send failed: {error}"),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Interface(error)
            | Self::Random(error)
            | Self::BootLookup(error)
            | Self::Send(error) => Some(error),
            Self::Reply(error) => Some(error),
            Self::Unsupported { .. } | Self::State(_) => None,
        }
    }
}

#[derive(Debug)]
pub struct RuntimeFailure {
    pub error: RuntimeError,
    pub events: Vec<RuntimeEvent>,
    pub outcome: Option<Outcome>,
    /// True once the provider returned an outcome. The runtime deliberately
    /// cannot undo state/lease side effects after this point.
    pub committed: bool,
}

impl std::fmt::Display for RuntimeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.error)
    }
}

impl std::error::Error for RuntimeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
pub struct RuntimeReport {
    pub events: Vec<RuntimeEvent>,
    pub outcome: Option<Outcome>,
}

/// Execute one admitted dispatch. Relay/PXE/LEASEQUERY and unknown message
/// routes fail explicitly before invoking the state callback. `buffer` is
/// caller-owned and bounded by `Packet::response_capacity` in `build_outcome`.
pub fn process<P, S>(
    dispatch: Dispatch<'_>,
    peer: SocketAddr,
    provider: &mut P,
    sender: &mut S,
    options: &[ReplyOption<'_>],
    buffer: &mut [u8],
) -> Result<RuntimeReport, Box<RuntimeFailure>>
where
    P: OutcomeProvider,
    S: DatagramSender,
{
    // Convenience entry point. SocketListener keeps the entropy descriptor
    // open and uses process_with_random to avoid opening it on each renewal.
    process_with_random(dispatch, peer, provider, sender, options, buffer, || {
        let mut bytes = [0; 2];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(u16::from_ne_bytes(bytes))
    })
}

/// Process with a caller-owned entropy source. A successful renewing or
/// rebinding REQUEST gets the same `rand16` input as rfc2131.c:1486. Injecting
/// a fixed value makes differential tests independent of OS randomness.
pub fn process_with_random<P, S>(
    dispatch: Dispatch<'_>,
    peer: SocketAddr,
    provider: &mut P,
    sender: &mut S,
    options: &[ReplyOption<'_>],
    buffer: &mut [u8],
    random: impl FnMut() -> io::Result<u16>,
) -> Result<RuntimeReport, Box<RuntimeFailure>>
where
    P: OutcomeProvider,
    S: DatagramSender,
{
    process_with_random_and_ports(
        dispatch,
        peer,
        provider,
        sender,
        options,
        buffer,
        crate::config::dhcp_relay::DhcpPorts::default(),
        random,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn process_with_random_and_ports<P, S>(
    dispatch: Dispatch<'_>,
    peer: SocketAddr,
    provider: &mut P,
    sender: &mut S,
    options: &[ReplyOption<'_>],
    buffer: &mut [u8],
    ports: crate::config::dhcp_relay::DhcpPorts,
    mut random: impl FnMut() -> io::Result<u16>,
) -> Result<RuntimeReport, Box<RuntimeFailure>>
where
    P: OutcomeProvider,
    S: DatagramSender,
{
    // dhcp.c clears its all-ones extension before context/state processing.
    // Keep the route separately so reply delivery restores the received wire
    // value and uses the original source port.
    let normalized = matches!(dispatch.route, Route::RelaySource { .. }).then(|| {
        let mut bytes = dispatch.packet.bytes().to_vec();
        bytes[24..28].fill(0);
        bytes
    });
    let dispatch = Dispatch {
        packet: normalized.as_ref().map_or(dispatch.packet, |bytes| {
            super::packet::Packet::parse(bytes).expect("clearing giaddr preserves packet validity")
        }),
        ..dispatch
    };

    let mut events = vec![RuntimeEvent::Admitted {
        kind: dispatch.kind,
        route: dispatch.route,
        interface: dispatch.ingress.interface_index,
    }];
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if dispatch.kind == DispatchKind::LeaseQuery {
        let source = match dispatch.route {
            Route::Relay { giaddr } => giaddr,
            Route::RelaySource { .. } => match peer.ip() {
                IpAddr::V4(address) => address,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            },
            Route::Local => Ipv4Addr::UNSPECIFIED,
        };
        let interface_name = sender
            .interface_name(dispatch.ingress.interface_index)
            .map_err(|error| {
                failure(RuntimeError::Interface(error), events.clone(), None, false)
            })?;
        let interface_bytes = interface_name.as_ref().map(|name| {
            &name[..name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len())]
        });
        let length = match provider.lease_query_reply(&dispatch, interface_bytes, source, buffer) {
            Ok(length) => length,
            Err(error) => return Err(failure(error, events, None, false)),
        };
        if let Some(length) = length {
            restore_relay_source(&dispatch, buffer);
            // dhcp.c restores the all-ones giaddr sentinel and sends to the
            // original source address AND port for this relay extension.
            let destination = Destination {
                address: if dispatch.ingress.listener == super::service::Listener::Pxe {
                    pxe_peer(buffer, peer)
                } else if matches!(dispatch.route, Route::RelaySource { .. }) {
                    peer
                } else {
                    SocketAddr::from((source, ports.server))
                },
                interface: if dispatch.ingress.listener == super::service::Listener::Pxe {
                    0
                } else {
                    dispatch.ingress.interface_index
                },
                kind: DestinationKind::Peer,
                arp: None,
            };
            events.push(RuntimeEvent::Built {
                length,
                omitted: 0,
                overload: 0,
            });
            events.push(RuntimeEvent::DestinationSelected(destination.clone()));
            if let Err(error) = send_with_retry(|| sender.send(&buffer[..length], &destination)) {
                return Err(failure(RuntimeError::Send(error), events, None, false));
            }
            events.push(RuntimeEvent::Sent { length });
            events.push(RuntimeEvent::Cleanup {
                outcome_dropped: true,
            });
            return Ok(RuntimeReport {
                events,
                outcome: None,
            });
        }
        events.push(RuntimeEvent::NoReply);
        return Ok(RuntimeReport {
            events,
            outcome: None,
        });
    }
    if !matches!(
        dispatch.kind,
        DispatchKind::Dhcp | DispatchKind::Bootp | DispatchKind::Pxe
    ) {
        return Err(failure(
            RuntimeError::Unsupported {
                kind: dispatch.kind,
                route: dispatch.route,
            },
            events,
            None,
            false,
        ));
    }

    let interface_name = match sender.interface_name(dispatch.ingress.interface_index) {
        Ok(name) => name,
        Err(error) => return Err(failure(RuntimeError::Interface(error), events, None, false)),
    };
    let interface_bytes = interface_name.as_ref().map(|name| {
        &name[..name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len())]
    });
    let outcome = match provider.resolve_on_interface(&dispatch, interface_bytes) {
        Ok(outcome) => outcome,
        Err(error) => return Err(failure(error, events, None, false)),
    };
    events.push(RuntimeEvent::StateCommitted {
        removed: outcome.removed.len(),
        lost_names: outcome.lost_names.len(),
    });
    let direct = match provider.direct_pxe_reply(dispatch.packet, buffer) {
        Ok(reply) => reply,
        Err(error) => return Err(failure(error, events, Some(outcome), true)),
    };
    if let Some(encoding) = direct {
        restore_relay_source(&dispatch, buffer);
        events.push(RuntimeEvent::Built {
            length: encoding.len,
            omitted: encoding.omitted,
            overload: encoding.overload,
        });
        // Direct PXE replies already encode all routing-relevant header
        // fields. They neither use INFORM peer trust nor NAK policy flags.
        let mut destination =
            destination_with_ports(&dispatch, peer, &Reply::Ignore, buffer, encoding.len, ports)
                .map_err(|error| failure(error, events.clone(), None, true))?;
        if let Some(arp) = &mut destination.arp {
            arp.interface_name = interface_name;
        }
        events.push(RuntimeEvent::DestinationSelected(destination.clone()));
        if destination.arp.is_some() {
            match sender.prepare_destination(&destination) {
                Ok(()) => events.push(RuntimeEvent::ArpInjected),
                Err(error) => events.push(RuntimeEvent::ArpInjectionFailed {
                    kind: error.kind(),
                    raw_os_error: error.raw_os_error(),
                }),
            }
        }
        // The socket owner accepts transient failures into its bounded queue.
        // Never enter the legacy retry/sleep loop for a direct PXE response.
        if let Err(error) = sender.send(&buffer[..encoding.len], &destination) {
            return Err(failure(
                RuntimeError::Send(error),
                events,
                Some(outcome),
                true,
            ));
        }
        events.push(RuntimeEvent::Sent {
            length: encoding.len,
        });
        events.push(RuntimeEvent::Cleanup {
            outcome_dropped: true,
        });
        return Ok(RuntimeReport {
            events,
            outcome: Some(outcome),
        });
    }
    if outcome.reply == Reply::Ignore {
        events.push(RuntimeEvent::NoReply);
        events.push(RuntimeEvent::Cleanup {
            outcome_dropped: true,
        });
        return Ok(RuntimeReport {
            events,
            outcome: Some(outcome),
        });
    }

    let fuzz = if needs_renewal_fuzz(dispatch.packet, outcome.reply) {
        match random() {
            Ok(value) => value,
            Err(error) => {
                events.push(RuntimeEvent::Cleanup {
                    outcome_dropped: true,
                });
                return Err(failure(
                    RuntimeError::Random(error),
                    events,
                    Some(outcome),
                    true,
                ));
            }
        }
    } else {
        0
    };
    let network = (!matches!(outcome.reply, Reply::Nak { .. }))
        .then(|| provider.network_options(&outcome))
        .flatten();
    let values = network.map(|network| {
        [
            Some(network.netmask.octets()),
            network
                .broadcast
                .filter(|ip| !ip.is_unspecified())
                .map(|ip| ip.octets()),
            network
                .router
                .filter(|ip| !ip.is_unspecified())
                .map(|ip| ip.octets()),
            network.dns_server.map(|ip| ip.octets()),
        ]
    });
    let names = provider.reply_names(dispatch.packet, &outcome);
    let name_values =
        names.map(|names| encode_name_options(dispatch.packet, names, provider.client_update()));
    let mut configured_codes = [false; 256];
    let mut fixed_boot_fields = [None, None];
    let selection = provider.selected_options(&outcome);
    let mut option_next_server = None;
    let mut option_warnings = Vec::new();
    let configured = encode_filtered_options_with_pxe_notices(
        dispatch.packet,
        outcome.reply,
        network.map(|network| network.next_server),
        provider.configured_options(),
        &selection,
        &mut configured_codes,
        provider.boot_config().is_some(),
        &mut fixed_boot_fields,
        &mut option_next_server,
        &provider.pxe_encoding(),
        &mut option_warnings,
    );
    let boot_next_server = if matches!(outcome.reply, Reply::Nak { .. }) {
        None
    } else {
        match provider.boot_next_server() {
            Ok(address) => address,
            Err(error) => {
                events.push(RuntimeEvent::Cleanup {
                    outcome_dropped: true,
                });
                return Err(failure(
                    RuntimeError::BootLookup(error),
                    events,
                    Some(outcome),
                    true,
                ));
            }
        }
    };
    let mut combined = Vec::with_capacity(options.len() + configured.len() + 7);
    if let Some(values) = &values {
        for (code, value) in [1, 28, 3, 6].into_iter().zip(values) {
            if let Some(value) = value {
                if !options.iter().any(|option| option.code == code)
                    && !configured_codes[usize::from(code)]
                    && (matches!(code, 1 | 28)
                        || matches!(outcome.reply, Reply::Bootp { .. })
                        || dispatch.packet.requests(code))
                {
                    combined.push(ReplyOption { code, value });
                }
            }
        }
    }
    if let Some(names) = &name_values {
        for (code, value) in [15, 12, 81].into_iter().zip(names) {
            if let Some(value) = value {
                if !options.iter().any(|option| option.code == code)
                    && (code == 81 || !configured_codes[usize::from(code)])
                {
                    combined.push(ReplyOption { code, value });
                }
            }
        }
    }
    for (code, value) in &configured {
        if !options.iter().any(|option| option.code == *code) {
            combined.push(ReplyOption { code: *code, value });
        }
    }
    combined.extend_from_slice(options);
    let options = combined.as_slice();
    // Only unrequested, unforced 66/67 with no dhcp-boot reach fixed fields.
    // Reuse the bounded field serializer; these values cannot be selected as
    // early boot TLVs because the same request did not ask for their codes.
    let fallback_boot = BootConfig {
        server_name: fixed_boot_fields[0].take(),
        filename: fixed_boot_fields[1].take(),
        next_server: Ipv4Addr::UNSPECIFIED,
        next_server_name: None,
    };
    let boot = provider.boot_config().or_else(|| {
        (fallback_boot.server_name.is_some() || fallback_boot.filename.is_some())
            .then_some(&fallback_boot)
    });
    let encoding = match build_reply_with_boot(
        dispatch.packet,
        outcome.reply,
        options,
        dispatch.packet.option(55, 0).is_some() && provider.allow_override(),
        fuzz,
        boot,
        buffer,
    ) {
        Ok(encoding) => encoding,
        Err(error) => {
            events.push(RuntimeEvent::Cleanup {
                outcome_dropped: true,
            });
            return Err(failure(
                RuntimeError::Reply(error),
                events,
                Some(outcome),
                true,
            ));
        }
    };
    events.push(RuntimeEvent::Built {
        length: encoding.len,
        omitted: encoding.omitted,
        overload: encoding.overload,
    });
    if let Some(next_server) = boot_next_server
        .or(option_next_server)
        .or_else(|| network.map(|network| network.next_server))
    {
        buffer[20..24].copy_from_slice(&next_server.octets());
    }
    // NAK does not call C's do_options. OFFER/ACK/INFORM/BOOTP use its raw
    // netid force-broadcast decision; destination still prioritizes ciaddr.
    if !matches!(outcome.reply, Reply::Nak { .. }) && provider.force_broadcast(&outcome) {
        buffer[10] |= 0x80;
    }
    provider.record_reply(
        dispatch.packet,
        outcome.reply,
        &buffer[..encoding.len],
        &encoding.omitted_options,
        &option_warnings,
    );
    restore_relay_source(&dispatch, buffer);
    let mut destination = match destination_with_ports(
        &dispatch,
        peer,
        &outcome.reply,
        buffer,
        encoding.len,
        ports,
    ) {
        Ok(destination) => destination,
        Err(error) => {
            events.push(RuntimeEvent::Cleanup {
                outcome_dropped: true,
            });
            return Err(failure(error, events, Some(outcome), true));
        }
    };
    if let Some(arp) = &mut destination.arp {
        arp.interface_name = interface_name;
    }
    events.push(RuntimeEvent::DestinationSelected(destination.clone()));
    if destination.arp.is_some() {
        match sender.prepare_destination(&destination) {
            Ok(()) => events.push(RuntimeEvent::ArpInjected),
            Err(error) => events.push(RuntimeEvent::ArpInjectionFailed {
                kind: error.kind(),
                raw_os_error: error.raw_os_error(),
            }),
        }
    }
    if let Err(error) = send_with_retry(|| sender.send(&buffer[..encoding.len], &destination)) {
        events.push(RuntimeEvent::Cleanup {
            outcome_dropped: true,
        });
        return Err(failure(
            RuntimeError::Send(error),
            events,
            Some(outcome),
            true,
        ));
    }
    events.push(RuntimeEvent::Sent {
        length: encoding.len,
    });
    events.push(RuntimeEvent::Cleanup {
        outcome_dropped: true,
    });
    Ok(RuntimeReport {
        events,
        outcome: Some(outcome),
    })
}

/// rfc2131.c:700-765,2814-2874. FQDN is sent when the client supplies option
/// 81, independently of its PRL. Without a configured domain, C's encoded
/// form ends after the hostname label (no final root byte).
/// Select ordinary untagged options in C's reverse configuration order.
/// `present` intentionally records options before PRL and empty-value tests:
/// those options still suppress network/name defaults when omitted from wire.
#[cfg(test)]
fn encode_configured_options(
    packet: super::packet::Packet<'_>,
    reply: Reply,
    local: Option<Ipv4Addr>,
    configured: &[DhcpOption],
    present: &mut [bool; 256],
    has_boot: bool,
    fixed_boot_fields: &mut [Option<Vec<u8>>; 2],
) -> Vec<(u8, Vec<u8>)> {
    let selection = crate::config::dhcp::option_filter(configured, &[], &[], &[], 0);
    encode_filtered_options(
        packet,
        reply,
        local,
        configured,
        &selection,
        present,
        has_boot,
        fixed_boot_fields,
        &mut None,
    )
}

// The arguments mirror the C do_options call boundary: packet/reply context,
// selected configuration, and two output slots. Keeping them explicit makes
// the precedence and mutation points auditable against that call chain.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn encode_filtered_options(
    packet: super::packet::Packet<'_>,
    reply: Reply,
    local: Option<Ipv4Addr>,
    configured: &[DhcpOption],
    selection: &crate::config::dhcp::FilteredOptions<'_>,
    present: &mut [bool; 256],
    has_boot: bool,
    fixed_boot_fields: &mut [Option<Vec<u8>>; 2],
    next_server: &mut Option<Ipv4Addr>,
) -> Vec<(u8, Vec<u8>)> {
    encode_filtered_options_with_pxe(
        packet,
        reply,
        local,
        configured,
        selection,
        present,
        has_boot,
        fixed_boot_fields,
        next_server,
        &PxeEncoding {
            include_vendor: true,
            ..PxeEncoding::default()
        },
    )
}

/// Shared option encoding; modes affect selection/PRL/encapsulation without
/// adding another allocator or serializer.
#[allow(clippy::too_many_arguments)]
pub fn encode_filtered_options_with_pxe(
    packet: super::packet::Packet<'_>,
    reply: Reply,
    local: Option<Ipv4Addr>,
    configured: &[DhcpOption],
    selection: &crate::config::dhcp::FilteredOptions<'_>,
    present: &mut [bool; 256],
    has_boot: bool,
    fixed_boot_fields: &mut [Option<Vec<u8>>; 2],
    next_server: &mut Option<Ipv4Addr>,
    pxe: &PxeEncoding<'_>,
) -> Vec<(u8, Vec<u8>)> {
    encode_filtered_options_with_pxe_notices(
        packet,
        reply,
        local,
        configured,
        selection,
        present,
        has_boot,
        fixed_boot_fields,
        next_server,
        pxe,
        &mut Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encode_filtered_options_with_pxe_notices(
    packet: super::packet::Packet<'_>,
    reply: Reply,
    local: Option<Ipv4Addr>,
    configured: &[DhcpOption],
    selection: &crate::config::dhcp::FilteredOptions<'_>,
    present: &mut [bool; 256],
    has_boot: bool,
    fixed_boot_fields: &mut [Option<Vec<u8>>; 2],
    next_server: &mut Option<Ipv4Addr>,
    pxe: &PxeEncoding<'_>,
    notices: &mut Vec<super::logging::OptionWarning>,
) -> Vec<(u8, Vec<u8>)> {
    use crate::config::dhcp::Encapsulation;
    let mut values = Vec::new();
    if matches!(reply, Reply::Nak { .. } | Reply::Ignore) {
        return values;
    }
    let bootp = matches!(reply, Reply::Bootp { .. });
    let leasequery = packet.message_type() == 10;
    let null_term = !bootp && !leasequery && broken_string_option(packet);
    notices.extend(
        selection
            .duplicate_codes
            .iter()
            .copied()
            .map(super::logging::OptionWarning::Duplicate),
    );
    for &index in &selection.selected {
        let option = &configured[index];
        present[usize::from(option.code)] = true;
        if pxe.direct {
            values.push((option.code, option.value.bytes(local, null_term)));
            continue;
        }
        if pxe.active_client().is_some() && option.code == 60 {
            continue;
        }
        if option.code == 255 {
            if !has_boot {
                let bytes = option.value.bytes(None, false);
                if bytes.len() == 4 {
                    *next_server = Some(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()));
                }
            }
            continue;
        }
        if matches!(option.code, 66 | 67)
            && !leasequery
            && !has_boot
            && !option.force
            && (bootp || packet.option(55, 0).is_none() || !packet.requests(option.code))
        {
            let value = option.value.bytes(None, false);
            fixed_boot_fields[usize::from(option.code - 66)] = Some(value);
            continue;
        }
        if matches!(option.code, 58 | 59) {
            if matches!(reply, Reply::Offer { .. } | Reply::Ack { .. }) {
                let bytes = option.value.bytes(None, false);
                if let Some(bytes) = bytes.get(..4) {
                    values.push((option.code, bytes.to_vec()));
                }
            }
            continue;
        }
        if matches!(option.code, 0 | 52 | 57 | 81) {
            continue;
        }
        if (leasequery || !option.force) && !bootp && !packet.requests(option.code) {
            continue;
        }
        let mut value = option
            .value
            .bytes(local, null_term || matches!(option.code, 66 | 67));
        if matches!(option.code, 1 | 3 | 6 | 12 | 15 | 28)
            && option.value.bytes(None, false).is_empty()
        {
            continue;
        }
        // Empty (absent value) is distinct from a quoted empty string.
        if matches!(option.value, OptionValue::Empty) {
            value.clear();
        }
        values.push((option.code, value));
    }
    let requested = |code| pxe.direct || bootp || packet.requests(code);
    let mut completed = Vec::new();
    for option in configured {
        if !matches!(
            option.encapsulation,
            Encapsulation::Option(_) | Encapsulation::Enterprise(_)
        ) || completed.contains(&option.encapsulation)
        {
            continue;
        }
        completed.push(option.encapsulation.clone());
        let outer = match option.encapsulation {
            Encapsulation::Option(code) => code,
            _ => 125,
        };
        let selected: Vec<_> = configured
            .iter()
            .filter(|other| {
                other.encapsulation == option.encapsulation
                    && other.tags.matches_with(&selection.tags, true)
                    && other.pxe_ok(pxe.encap_mode)
                    && (other.force || requested(outer))
            })
            .collect();
        if selected.is_empty() {
            continue;
        }
        if let Encapsulation::Enterprise(number) = option.encapsulation {
            let mut data = Vec::new();
            for child in selected {
                let value = child.value.bytes(None, false);
                data.extend_from_slice(&[child.code, value.len() as u8]);
                data.extend_from_slice(&value);
            }
            if data.len() > 250 {
                notices.push(super::logging::OptionWarning::EnterpriseTooLarge(number));
            } else {
                let mut payload = number.to_be_bytes().to_vec();
                payload.push(data.len() as u8);
                payload.extend(data);
                values.push((125, payload));
            }
        } else {
            append_encapsulated(&mut values, outer, &selected, null_term);
        }
    }
    let vendor_sent = (!pxe.direct)
        .then(|| {
            values
                .iter()
                .find(|(code, _)| *code == 60)
                .map(|(_, value)| value.as_slice())
        })
        .flatten();
    let mut vendor_values = vendor_options(
        packet,
        configured,
        &selection.tags,
        pxe,
        vendor_sent,
        null_term,
        local.is_some() || pxe.direct,
    );
    if pxe.direct {
        // The proxy branch emits PXE misc/menu before ordinary mode2 options
        // and arbitrary encapsulation. Ordinary do_options uses the reverse.
        vendor_values.extend(values);
        vendor_values
    } else {
        values.extend(vendor_values);
        values
    }
}

/// Proxy-only ordinary/encapsulated options using the same shared encoder.
pub fn encode_pxe_options(
    packet: super::packet::Packet<'_>,
    local: Ipv4Addr,
    configured: &[DhcpOption],
    selection: &crate::config::dhcp::FilteredOptions<'_>,
    pxe: &PxeEncoding<'_>,
) -> Vec<(u8, Vec<u8>)> {
    encode_pxe_options_notices(packet, local, configured, selection, pxe, &mut Vec::new())
}

pub fn encode_pxe_options_notices(
    packet: super::packet::Packet<'_>,
    local: Ipv4Addr,
    configured: &[DhcpOption],
    selection: &crate::config::dhcp::FilteredOptions<'_>,
    pxe: &PxeEncoding<'_>,
    notices: &mut Vec<super::logging::OptionWarning>,
) -> Vec<(u8, Vec<u8>)> {
    encode_filtered_options_with_pxe_notices(
        packet,
        Reply::Inform {
            lease_time: None,
            context: None,
            server: local,
        },
        Some(local),
        configured,
        selection,
        &mut [false; 256],
        false,
        &mut [None, None],
        &mut None,
        pxe,
        notices,
    )
}

/// Boot-item replies emit only PXE misc and vendor suboptions (generated71
/// first); normal option-pxe/encap options belong to the proxy path above.
pub fn encode_pxe_vendor_options(
    packet: super::packet::Packet<'_>,
    configured: &[DhcpOption],
    tags: &[&[u8]],
    pxe: &PxeEncoding<'_>,
) -> Vec<(u8, Vec<u8>)> {
    vendor_options(packet, configured, tags, pxe, None, false, true)
}

fn vendor_options(
    packet: super::packet::Packet<'_>,
    configured: &[DhcpOption],
    tags: &[&[u8]],
    pxe: &PxeEncoding<'_>,
    configured_vendor: Option<&[u8]>,
    null_term: bool,
    have_context: bool,
) -> Vec<(u8, Vec<u8>)> {
    use crate::config::dhcp::Encapsulation;
    let mut values = Vec::new();
    if packet.message_type() == 10 {
        return values;
    }
    let active = pxe.active_client();
    if let Some(client) = active.filter(|_| have_context) {
        values.push((60, client.vendor.clone()));
        if let Some(uuid) = client.uuid {
            values.push((97, uuid.to_vec()));
        }
    }
    if !pxe.include_vendor {
        return values;
    }
    let Some(vendor) = configured_vendor.or_else(|| packet.option(60, 1)) else {
        return values;
    };
    let contains = |needle: &[u8]| {
        needle.is_empty() || vendor.windows(needle.len()).any(|part| part == needle)
    };
    let selected: Vec<_> = configured
        .iter()
        .filter(|option| {
            option.tags.matches_with(tags, true)
                && match &option.encapsulation {
                    Encapsulation::Vendor(needle) => contains(needle),
                    Encapsulation::PxeVendor => {
                        pxe.vendor_prefixes.iter().any(|prefix| contains(prefix))
                    }
                    _ => false,
                }
        })
        .collect();
    let generated = if active.is_some() && have_context {
        pxe.generated_vendor
    } else {
        &[]
    };
    if (!generated.is_empty() || !selected.is_empty())
        && (pxe.direct
            || selected.iter().any(|option| option.force)
            || packet.requests(43)
            || packet.requests(60))
    {
        let suboptions = generated
            .iter()
            .cloned()
            .chain(selected.iter().map(|option| {
                (
                    option.code,
                    option
                        .value
                        .bytes(None, if pxe.direct { false } else { null_term }),
                )
            }));
        append_encoded_encapsulated(&mut values, 43, suboptions);
        if active.is_none() && configured_vendor.is_none() {
            if let Some(echo) = packet.option(60, 1) {
                values.push((60, echo.to_vec()));
            }
        }
    }
    values
}

fn append_encapsulated(
    values: &mut Vec<(u8, Vec<u8>)>,
    outer: u8,
    options: &[&DhcpOption],
    null_term: bool,
) {
    append_encoded_encapsulated(
        values,
        outer,
        options
            .iter()
            .map(|option| (option.code, option.value.bytes(None, null_term))),
    );
}

fn append_encoded_encapsulated(
    values: &mut Vec<(u8, Vec<u8>)>,
    outer: u8,
    options: impl IntoIterator<Item = (u8, Vec<u8>)>,
) {
    let mut block = Vec::new();
    for (code, value) in options {
        if value.len() + 2 > 255 {
            continue;
        }
        if block.len() + value.len() + 2 > 255 {
            values.push((outer, std::mem::take(&mut block)));
        }
        block.extend_from_slice(&[code, value.len() as u8]);
        block.extend_from_slice(&value);
    }
    if !block.is_empty() {
        // Never emit the C boundary bug: a 256-byte option encoded with a
        // zero length. A full final block is sent without an extra END byte.
        if block.len() < 255 {
            block.push(255);
        }
        values.push((outer, block));
    }
}

fn encode_name_options(
    packet: super::packet::Packet<'_>,
    names: ReplyNames<'_>,
    client_update: bool,
) -> [Option<Vec<u8>>; 3] {
    let fqdn = (packet.message_type() != 0)
        .then(|| packet.option(81, 3))
        .flatten();
    let null_term = if let Some(fqdn) = fqdn {
        fqdn[0] & 4 == 0 && fqdn.len() > 3 && fqdn.last() == Some(&0)
    } else {
        packet.message_type() != 0
            && packet
                .option(12, 1)
                .is_some_and(|name| name.last() == Some(&0))
    };
    let string = |value: &[u8]| {
        let mut bytes = value.to_vec();
        if null_term && bytes.len() != 255 {
            bytes.push(0);
        }
        bytes
    };
    let domain = names
        .domain
        .filter(|_| packet.message_type() == 0 || packet.requests(15))
        .map(string);
    let hostname = names
        .hostname
        .filter(|_| packet.message_type() == 0 || packet.requests(12))
        .map(string);
    let fqdn = fqdn.zip(names.hostname).map(|(input, name)| {
        let mut flags = input[0];
        if client_update {
            if flags & 1 != 0 {
                flags = (flags | 2) & !1;
            }
            flags |= 8;
        } else {
            if flags & 1 == 0 {
                flags |= 3;
            }
            flags &= !8;
        }
        let mut output = vec![flags & 15, 255, 255];
        if flags & 4 != 0 {
            for label in name.split(|byte| *byte == b'.') {
                output.push(label.len() as u8);
                output.extend_from_slice(label);
            }
            if let Some(domain) = names.domain {
                for label in domain.split(|byte| *byte == b'.') {
                    output.push(label.len() as u8);
                    output.extend_from_slice(label);
                }
                output.push(0);
            }
        } else {
            output.extend_from_slice(name);
            if let Some(domain) = names.domain {
                output.push(b'.');
                output.extend_from_slice(domain);
            }
            if null_term {
                output.push(0);
            }
        }
        output
    });
    [domain, hostname, fqdn]
}

/// util.c:718-749: retries are per completed send loop; EINTR resets the
/// EAGAIN count, and each of at most 1001 EAGAIN failures waits 10 microseconds.
fn send_with_retry(mut send: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    let mut retries = 0;
    loop {
        match send() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_micros(10));
                if retries >= 1000 {
                    return Err(error);
                }
                retries += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => retries = 0,
            Err(error) => return Err(error),
        }
    }
}

fn failure(
    error: RuntimeError,
    events: Vec<RuntimeEvent>,
    outcome: Option<Outcome>,
    committed: bool,
) -> Box<RuntimeFailure> {
    Box::new(RuntimeFailure {
        error,
        events,
        outcome,
        committed,
    })
}

/// Select the local-client destination using the same observable fields as
/// `dhcp.c`'s IPv4 send branch. Relay metadata is rejected by `process` before
/// this function; caller can still inspect it in the `Admitted` event.
pub fn destination(
    dispatch: &Dispatch<'_>,
    peer: SocketAddr,
    reply: &Reply,
    packet: &[u8],
    length: usize,
) -> Result<Destination, RuntimeError> {
    destination_with_ports(
        dispatch,
        peer,
        reply,
        packet,
        length,
        crate::config::dhcp_relay::DhcpPorts::default(),
    )
}

fn pxe_peer(packet: &[u8], peer: SocketAddr) -> SocketAddr {
    let ciaddr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    if ciaddr.is_unspecified() {
        peer
    } else {
        SocketAddr::from((ciaddr, peer.port()))
    }
}

fn restore_relay_source(dispatch: &Dispatch<'_>, packet: &mut [u8]) {
    if dispatch.ingress.listener != super::service::Listener::Pxe {
        if let Route::RelaySource { original_giaddr } = dispatch.route {
            packet[24..28].copy_from_slice(&original_giaddr.octets());
        }
    }
}

pub fn destination_with_ports(
    dispatch: &Dispatch<'_>,
    peer: SocketAddr,
    reply: &Reply,
    packet: &[u8],
    length: usize,
    ports: crate::config::dhcp_relay::DhcpPorts,
) -> Result<Destination, RuntimeError> {
    if !matches!(
        dispatch.kind,
        DispatchKind::Dhcp | DispatchKind::Bootp | DispatchKind::Pxe
    ) {
        return Err(RuntimeError::Unsupported {
            kind: dispatch.kind,
            route: dispatch.route,
        });
    }
    if length < 20 || packet.len() < length {
        return Err(RuntimeError::Reply(ReplyError::BufferTooSmall {
            required: length.max(20),
            available: packet.len(),
        }));
    }
    if dispatch.ingress.listener == super::service::Listener::Pxe {
        return Ok(Destination {
            address: pxe_peer(packet, peer),
            interface: 0,
            kind: DestinationKind::Peer,
            arp: None,
        });
    }
    let relayed = match dispatch.route {
        Route::Relay { giaddr } => Some(SocketAddr::from((giaddr, ports.server))),
        Route::RelaySource { .. } => Some(peer),
        Route::Local => None,
    };
    if let Some(address) = relayed {
        return Ok(Destination {
            address,
            // C leaves msg_control NULL for a relay: use the route table.
            interface: 0,
            kind: DestinationKind::Peer,
            arp: None,
        });
    }
    let flags = u16::from_be_bytes([packet[10], packet[11]]);
    // Read the completed wire header: build_outcome applies effective_ciaddr
    // (DISCOVER/option-50 sanitisation) before routing.
    let ciaddr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let yiaddr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let htype = packet[1];
    let hlen = packet[2];
    if !ciaddr.is_unspecified() {
        // dhcp.c trusts an INFORM source even when it differs from ciaddr,
        // but a zero IPv4 source or source port still falls back to ciaddr.
        let trust_peer = matches!(peer.ip(), IpAddr::V4(address) if !address.is_unspecified())
            && peer.port() != 0
            && (matches!(reply, Reply::Inform { .. }) || peer.ip() == IpAddr::V4(ciaddr));
        return Ok(Destination {
            address: if trust_peer {
                peer
            } else {
                SocketAddr::from((ciaddr, ports.client))
            },
            interface: dispatch.ingress.interface_index,
            kind: if trust_peer {
                DestinationKind::Peer
            } else {
                DestinationKind::Client
            },
            arp: None,
        });
    }
    let broadcast = matches!(
        reply,
        Reply::Nak {
            broadcast: true,
            ..
        }
    ) || flags & BROADCAST_FLAG != 0
        || hlen == 0
        || hlen > 14
        || htype == 0;
    let (address, kind) = if broadcast {
        (Ipv4Addr::BROADCAST, DestinationKind::Broadcast)
    } else {
        (yiaddr, DestinationKind::Client)
    };
    if kind == DestinationKind::Client {
        // The C packet is always a complete BOOTP header, but this public
        // boundary also accepts caller-provided wire slices.  Do not index
        // chaddr past a short buffer while preparing ARP metadata.
        let required = 28 + usize::from(hlen);
        if length < required {
            return Err(RuntimeError::Reply(ReplyError::BufferTooSmall {
                required,
                available: packet.len(),
            }));
        }
    }
    Ok(Destination {
        address: SocketAddr::from((address, ports.client)),
        interface: dispatch.ingress.interface_index,
        kind,
        arp: (kind == DestinationKind::Client).then(|| ArpRequest {
            address: yiaddr,
            hardware_type: htype,
            hardware_address: packet[28..28 + usize::from(hlen)].to_vec(),
            interface_name: None,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::allocation::RangeKind;
    use crate::dhcp::packet::COOKIE;
    use crate::dhcp::service::{dispatch, Ingress, Listener};
    use std::cell::Cell;

    #[test]
    fn failure_error_chain_preserves_io_errno_and_bootp_cause() {
        use std::error::Error;

        let failed = failure(
            RuntimeError::Send(io::Error::from_raw_os_error(5)),
            Vec::new(),
            None,
            true,
        );
        let cause = failed.source().unwrap().source().unwrap();
        assert_eq!(
            cause.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(5)
        );
        assert!(failed.committed);

        let failed = failure(
            RuntimeError::Reply(ReplyError::Bootp(
                super::super::packet::VendorError::PadHasValue,
            )),
            Vec::new(),
            None,
            true,
        );
        let cause = failed.source().unwrap().source().unwrap().source().unwrap();
        assert_eq!(
            cause.downcast_ref::<super::super::packet::VendorError>(),
            Some(&super::super::packet::VendorError::PadHasValue)
        );
    }

    struct Sender {
        sent: Vec<(Vec<u8>, SocketAddr)>,
        fail: bool,
    }

    impl DatagramSender for Sender {
        fn send(&mut self, bytes: &[u8], destination: &Destination) -> io::Result<()> {
            if self.fail {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "test send"));
            }
            self.sent.push((bytes.to_vec(), destination.address));
            Ok(())
        }
    }

    fn packet(options: &[u8], flags: u16, ciaddr: Ipv4Addr, giaddr: Ipv4Addr) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[10..12].copy_from_slice(&flags.to_be_bytes());
        bytes[12..16].copy_from_slice(&ciaddr.octets());
        bytes[24..28].copy_from_slice(&giaddr.octets());
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes.extend_from_slice(options);
        bytes
    }

    #[test]
    fn proxy_options_put_vendor_before_mode2_values_and_ignore_prl() {
        use crate::config::{dhcp::Encapsulation, EncodedArg};
        let bytes = packet(
            b"\x35\x01\x01\x3c\x09PXEClient\x37\0\xff",
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let packet = super::super::packet::Packet::parse(&bytes).unwrap();
        let mut configured = vec![
            DhcpOption::parse_mode(&EncodedArg::command_line(b"60,replaced"), false, true).unwrap(),
            DhcpOption::parse_mode(&EncodedArg::command_line(b"225,pxe"), false, true).unwrap(),
            DhcpOption::parse_mode(&EncodedArg::command_line(b"224,ordinary"), false, false)
                .unwrap(),
            DhcpOption::parse_mode(
                &EncodedArg::command_line(b"encap:172,17,nested"),
                false,
                true,
            )
            .unwrap(),
        ];
        configured.push(DhcpOption {
            code: 10,
            value: OptionValue::Raw(vec![0, b'G', b'o']),
            encapsulation: Encapsulation::PxeVendor,
            ..DhcpOption::default()
        });
        let selected = crate::config::dhcp::option_filter(&configured, &[], &[], &[], 2);
        let client = super::super::pxe::Client {
            vendor: b"PXEClient".to_vec(),
            architecture: Some(0),
            uuid: None,
        };
        let prefixes = [b"PXEClient".to_vec()];
        let generated = [(6, vec![3])];
        let pxe = PxeEncoding::direct(&client, &prefixes, &generated, true);
        let result = encode_pxe_options(packet, Ipv4Addr::LOCALHOST, &configured, &selected, &pxe);
        assert_eq!(
            result.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
            [60, 43, 60, 225, 172]
        );
        assert_eq!(result[1].1, [6, 1, 3, 10, 3, 0, b'G', b'o', 255]);
        assert_eq!(result[2].1, b"replaced");
    }

    #[test]
    fn ordinary_encapsulation_keeps_the_image_pc98_exception() {
        use crate::config::EncodedArg;
        let configured = [DhcpOption::parse_mode(
            &EncodedArg::command_line(b"encap:172,17,value"),
            false,
            true,
        )
        .unwrap()];
        let selected = crate::config::dhcp::option_filter(&configured, &[], &[], &[], 0);
        let bytes = packet(
            &[53, 1, 1, 55, 1, 172, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let packet = super::super::packet::Packet::parse(&bytes).unwrap();
        let encode = |pxe| {
            encode_filtered_options_with_pxe(
                packet,
                Reply::Inform {
                    lease_time: None,
                    context: None,
                    server: Ipv4Addr::LOCALHOST,
                },
                Some(Ipv4Addr::LOCALHOST),
                &configured,
                &selected,
                &mut [false; 256],
                false,
                &mut [None, None],
                &mut None,
                &pxe,
            )
        };
        let normal = encode(PxeEncoding::ordinary(None, &[], &[]));
        assert_eq!(
            normal.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
            [172]
        );
        let client = super::super::pxe::Client {
            vendor: b"PXEClient".to_vec(),
            architecture: Some(1),
            uuid: None,
        };
        let pc98 = encode(PxeEncoding::ordinary(Some(&client), &[], &[]));
        assert_eq!(pc98.iter().map(|(code, _)| *code).collect::<Vec<_>>(), [60]);
    }

    #[test]
    fn pxe_misc_does_not_depend_on_vendor_prl_and_redirect_suppresses_vendor_bank() {
        use crate::config::dhcp::Encapsulation;
        let configured = [DhcpOption {
            code: 10,
            value: OptionValue::Raw(vec![0, b'G', b'o']),
            encapsulation: Encapsulation::PxeVendor,
            ..DhcpOption::default()
        }];
        let client = super::super::pxe::Client {
            vendor: b"PXEClient".to_vec(),
            architecture: Some(7),
            uuid: Some([9; 17]),
        };
        let prefixes = [b"PXEClient".to_vec()];
        let generated = [(6, vec![3])];
        let bytes = packet(
            b"\x35\x01\x01\x3c\x09PXEClient\x37\0\xff",
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let packet = super::super::packet::Packet::parse(&bytes).unwrap();
        let ordinary = encode_pxe_vendor_options(
            packet,
            &configured,
            &[],
            &PxeEncoding::ordinary(Some(&client), &prefixes, &generated),
        );
        assert_eq!(
            ordinary.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
            [60, 97]
        );
        let redirected = encode_pxe_vendor_options(
            packet,
            &configured,
            &[],
            &PxeEncoding::direct(&client, &prefixes, &generated, false),
        );
        assert_eq!(
            redirected.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
            [60, 97]
        );
    }

    #[test]
    fn pxe_inform_without_context_keeps_configured_vendor_but_no_misc() {
        use crate::config::dhcp::Encapsulation;
        let configured = [DhcpOption {
            code: 10,
            value: OptionValue::Raw(vec![1, b'G', b'o']),
            encapsulation: Encapsulation::PxeVendor,
            ..DhcpOption::default()
        }];
        let bytes = packet(
            b"\x35\x01\x08\x3c\x09PXEClient\x37\x02\x2b\x3c\xff",
            0,
            Ipv4Addr::new(198, 51, 100, 20),
            Ipv4Addr::UNSPECIFIED,
        );
        let packet = super::super::packet::Packet::parse(&bytes).unwrap();
        let client = super::super::pxe::Client {
            vendor: b"PXEClient".to_vec(),
            architecture: Some(0),
            uuid: Some([9; 17]),
        };
        let prefixes = [b"PXEClient".to_vec()];
        let generated = [(6, vec![3])];
        let encoding = PxeEncoding::ordinary(Some(&client), &prefixes, &generated);
        let selected = crate::config::dhcp::option_filter(&configured, &[], &[], &[], 1);
        let values = encode_filtered_options_with_pxe(
            packet,
            Reply::Inform {
                lease_time: None,
                context: None,
                server: Ipv4Addr::LOCALHOST,
            },
            None,
            &configured,
            &selected,
            &mut [false; 256],
            false,
            &mut [None, None],
            &mut None,
            &encoding,
        );
        assert_eq!(values, [(43, vec![10, 3, 1, b'G', b'o', 255])]);
    }

    fn dispatch_for(bytes: &[u8]) -> Dispatch<'_> {
        dispatch(
            bytes,
            Ingress {
                listener: Listener::Dhcp,
                interface_index: 7,
                unicast_destination: false,
            },
            &[],
        )
        .unwrap()
    }

    fn offer() -> Outcome {
        Outcome {
            reply: Reply::Offer {
                address: Ipv4Addr::new(192, 0, 2, 42),
                lease_time: 60,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            removed: Vec::new(),
            lost_names: Vec::new(),
            newly_allocated: false,
        }
    }

    #[test]
    fn configured_presence_precedes_prl_and_bootp_uses_all_options() {
        let configured = [
            DhcpOption {
                code: 3,
                force: false,
                value: OptionValue::Empty,
                ..Default::default()
            },
            DhcpOption {
                code: 3,
                force: true,
                value: OptionValue::Addresses(vec![Ipv4Addr::LOCALHOST]),
                ..Default::default()
            },
            DhcpOption {
                code: 6,
                force: false,
                value: OptionValue::Addresses(vec![Ipv4Addr::UNSPECIFIED]),
                ..Default::default()
            },
            DhcpOption {
                code: 15,
                force: true,
                value: OptionValue::String(b"wire.test".to_vec()),
                ..Default::default()
            },
            DhcpOption {
                code: 58,
                force: false,
                value: OptionValue::Time(180),
                ..Default::default()
            },
        ];
        let request = packet(
            &[53, 1, 1, 55, 0, 255],
            BROADCAST_FLAG,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let request = super::super::packet::Packet::parse(&request).unwrap();
        let mut present = [false; 256];
        let values = encode_configured_options(
            request,
            offer().reply,
            Some(Ipv4Addr::LOCALHOST),
            &configured,
            &mut present,
            false,
            &mut [None, None],
        );
        assert!(present[3] && present[6] && present[15] && present[58]);
        assert_eq!(
            values,
            vec![
                (15, b"wire.test".to_vec()),
                (58, 180u32.to_be_bytes().to_vec())
            ]
        );
        let bootp = packet(
            &[55, 0, 255],
            BROADCAST_FLAG,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let bootp = super::super::packet::Packet::parse(&bootp).unwrap();
        present.fill(false);
        let values = encode_configured_options(
            bootp,
            Reply::Bootp {
                address: Ipv4Addr::LOCALHOST,
                context: 0,
            },
            Some(Ipv4Addr::LOCALHOST),
            &configured,
            &mut present,
            false,
            &mut [None, None],
        );
        assert_eq!(
            values,
            vec![(6, vec![127, 0, 0, 1]), (15, b"wire.test".to_vec())]
        );
    }

    #[test]
    fn boot_lookup_failure_retains_committed_outcome_without_sending() {
        struct Provider;
        impl OutcomeProvider for Provider {
            fn resolve(&mut self, _: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
                Ok(offer())
            }
            fn boot_next_server(&mut self) -> io::Result<Option<Ipv4Addr>> {
                Err(io::Error::other("DNS state lock poisoned"))
            }
        }
        let bytes = packet(
            &[53, 1, 1, 255],
            BROADCAST_FLAG,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let mut sender = Sender {
            sent: Vec::new(),
            fail: false,
        };
        let mut output = [0; 548];
        let error = process(
            dispatch_for(&bytes),
            "0.0.0.0:68".parse().unwrap(),
            &mut Provider,
            &mut sender,
            &[],
            &mut output,
        )
        .unwrap_err();
        assert!(matches!(error.error, RuntimeError::BootLookup(_)));
        assert!(error.committed);
        assert_eq!(error.outcome.unwrap().reply, offer().reply);
        assert!(sender.sent.is_empty());
        assert!(matches!(
            error.events.last(),
            Some(RuntimeEvent::Cleanup {
                outcome_dropped: true
            })
        ));
    }

    #[test]
    fn selected_boot_fields_are_sent_by_the_runtime_without_prl_codes() {
        struct Provider {
            boot: BootConfig,
        }
        impl OutcomeProvider for Provider {
            fn resolve(&mut self, _: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
                Ok(offer())
            }
            fn boot_config(&self) -> Option<&BootConfig> {
                Some(&self.boot)
            }
            fn boot_next_server(&mut self) -> io::Result<Option<Ipv4Addr>> {
                Ok(Some(self.boot.next_server))
            }
        }
        let bytes = packet(
            &[53, 1, 1, 55, 1, 1, 255],
            BROADCAST_FLAG,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let mut sender = Sender {
            sent: Vec::new(),
            fail: false,
        };
        let mut output = [0; 548];
        process(
            dispatch_for(&bytes),
            "0.0.0.0:68".parse().unwrap(),
            &mut Provider {
                boot: BootConfig {
                    filename: Some(b"known.img".to_vec()),
                    server_name: Some(b"boot.test".to_vec()),
                    next_server: Ipv4Addr::new(192, 0, 2, 9),
                    next_server_name: None,
                },
            },
            &mut sender,
            &[],
            &mut output,
        )
        .unwrap();
        let sent = &sender.sent[0].0;
        assert_eq!(&sent[20..24], [192, 0, 2, 9]);
        assert_eq!(&sent[44..54], b"boot.test\0");
        assert_eq!(&sent[108..118], b"known.img\0");
    }

    #[test]
    fn bootp_network_defaults_ignore_client_parameter_request_list() {
        struct Provider;
        impl OutcomeProvider for Provider {
            fn resolve(&mut self, _: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
                Ok(Outcome {
                    reply: Reply::Bootp {
                        address: Ipv4Addr::new(127, 0, 0, 10),
                        context: 0,
                    },
                    removed: Vec::new(),
                    lost_names: Vec::new(),
                    newly_allocated: false,
                })
            }
            fn network_options(&self, _: &Outcome) -> Option<NetworkOptions> {
                Some(NetworkOptions {
                    next_server: Ipv4Addr::LOCALHOST,
                    netmask: Ipv4Addr::new(255, 0, 0, 0),
                    broadcast: Some(Ipv4Addr::new(127, 255, 255, 255)),
                    router: Some(Ipv4Addr::LOCALHOST),
                    dns_server: Some(Ipv4Addr::LOCALHOST),
                })
            }
        }
        let request = packet(
            &[55, 0, 255],
            BROADCAST_FLAG,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let mut sender = Sender {
            sent: Vec::new(),
            fail: false,
        };
        process_with_random(
            dispatch_for(&request),
            SocketAddr::from(([127, 0, 0, 1], 68)),
            &mut Provider,
            &mut sender,
            &[],
            &mut [0; 548],
            || Ok(0),
        )
        .unwrap();
        let reply = &sender.sent[0].0;
        assert_eq!(reply.len(), 300);
        // Actual C BOOTP calls do_options with req_options=NULL even when
        // the request's vendor area contains an empty DHCP option 55.
        assert_eq!(wire_option(reply, 3), Some(&[127, 0, 0, 1][..]));
        assert_eq!(wire_option(reply, 6), Some(&[127, 0, 0, 1][..]));
        assert!(wire_option(reply, 53).is_none());
    }

    fn wire_option(bytes: &[u8], wanted: u8) -> Option<&[u8]> {
        let mut rest = &bytes[240..];
        while let Some((&code, tail)) = rest.split_first() {
            if code == 255 {
                return None;
            }
            if code == 0 {
                rest = tail;
                continue;
            }
            let (&length, tail) = tail.split_first()?;
            let (value, tail) = tail.split_at_checked(usize::from(length))?;
            if code == wanted {
                return Some(value);
            }
            rest = tail;
        }
        None
    }

    #[test]
    fn failed_arp_still_sends_once_after_transient_retries() {
        struct RetrySender<'a> {
            preparations: usize,
            attempts: usize,
            captured: &'a Cell<bool>,
        }
        impl DatagramSender for RetrySender<'_> {
            fn interface_name(&mut self, _: u32) -> io::Result<Option<[u8; 16]>> {
                self.captured.set(true);
                let mut name = [0; 16];
                name[..6].copy_from_slice(b"before");
                Ok(Some(name))
            }
            fn prepare_destination(&mut self, destination: &Destination) -> io::Result<()> {
                self.preparations += 1;
                assert_eq!(
                    &destination.arp.as_ref().unwrap().interface_name.unwrap()[..6],
                    b"before"
                );
                Err(io::Error::from_raw_os_error(1))
            }
            fn send(&mut self, _: &[u8], _: &Destination) -> io::Result<()> {
                self.attempts += 1;
                match self.attempts {
                    1 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                    2 => Err(io::Error::from(io::ErrorKind::Interrupted)),
                    _ => Ok(()),
                }
            }
        }
        let bytes = packet(
            &[53, 1, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let captured = Cell::new(false);
        let mut sender = RetrySender {
            preparations: 0,
            attempts: 0,
            captured: &captured,
        };
        let mut provider = |_: &Dispatch<'_>| {
            assert!(captured.get());
            Ok(offer())
        };
        let report = process(
            dispatch_for(&bytes),
            SocketAddr::from(([0, 0, 0, 0], 68)),
            &mut provider,
            &mut sender,
            &[],
            &mut [0; 548],
        )
        .unwrap();
        assert_eq!((sender.preparations, sender.attempts), (1, 3));
        let failed = report
            .events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    RuntimeEvent::ArpInjectionFailed {
                        raw_os_error: Some(1),
                        ..
                    }
                )
            })
            .unwrap();
        let sent = report
            .events
            .iter()
            .position(|event| matches!(event, RuntimeEvent::Sent { .. }))
            .unwrap();
        assert!(failed < sent);
        assert!(report.outcome.is_some());
    }

    #[test]
    fn missing_interface_stops_before_state_and_prune() {
        struct MissingInterface;
        impl DatagramSender for MissingInterface {
            fn interface_name(&mut self, _: u32) -> io::Result<Option<[u8; 16]>> {
                Err(io::Error::from_raw_os_error(6))
            }
            fn send(&mut self, _: &[u8], _: &Destination) -> io::Result<()> {
                panic!("no send")
            }
        }
        let bytes = packet(
            &[53, 1, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let mut provider =
            |_: &Dispatch<'_>| -> Result<Outcome, RuntimeError> { panic!("no state/prune") };
        let error = process(
            dispatch_for(&bytes),
            SocketAddr::from(([0, 0, 0, 0], 68)),
            &mut provider,
            &mut MissingInterface,
            &[],
            &mut [0; 548],
        )
        .unwrap_err();
        assert!(!error.committed);
        assert!(error.outcome.is_none());
        assert!(matches!(error.error, RuntimeError::Interface(_)));
    }

    #[test]
    fn only_renewal_ack_draws_random_and_entropy_failure_keeps_commit() {
        let ciaddr = Ipv4Addr::new(192, 0, 2, 9);
        for options in [
            &[53, 1, 3, 255][..],
            &[53, 1, 3, 50, 4, 192, 0, 2, 9, 255][..],
            &[53, 1, 1, 80, 0, 255][..],
        ] {
            let bytes = packet(options, BROADCAST_FLAG, ciaddr, Ipv4Addr::UNSPECIFIED);
            let dispatch = dispatch_for(&bytes);
            let mut provider = |_: &Dispatch<'_>| {
                Ok(Outcome {
                    reply: Reply::Ack {
                        address: ciaddr,
                        lease_time: 600,
                        context: 0,
                        server: Ipv4Addr::new(192, 0, 2, 1),
                        rapid_commit: false,
                    },
                    removed: Vec::new(),
                    lost_names: Vec::new(),
                    newly_allocated: false,
                })
            };
            let mut sender = Sender {
                sent: Vec::new(),
                fail: false,
            };
            let mut output = vec![0; 548];
            let draws = Cell::new(0);
            process_with_random(
                dispatch,
                SocketAddr::from((ciaddr, 1068)),
                &mut provider,
                &mut sender,
                &[],
                &mut output,
                || {
                    draws.set(draws.get() + 1);
                    Ok(65535)
                },
            )
            .unwrap();
            let renewal = options == [53, 1, 3, 255];
            assert_eq!(draws.get(), u8::from(renewal));
            assert_eq!(
                wire_option(&output, 58),
                Some(
                    (if renewal { 269u32 } else { 300 })
                        .to_be_bytes()
                        .as_slice()
                )
            );
            let result = process_with_random(
                dispatch,
                SocketAddr::from((ciaddr, 1068)),
                &mut provider,
                &mut sender,
                &[],
                &mut output,
                || Err(io::Error::other("entropy unavailable")),
            );
            if renewal {
                let failure = result.unwrap_err();
                assert!(failure.committed);
                assert!(failure.outcome.is_some());
                assert!(matches!(failure.error, RuntimeError::Random(_)));
                assert_eq!(sender.sent.len(), 1);
            } else {
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn network_defaults_follow_selected_context_prl_and_explicit_options() {
        struct Provider;
        impl OutcomeProvider for Provider {
            fn resolve(&mut self, _: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
                Ok(offer())
            }
            fn network_options(&self, _: &Outcome) -> Option<NetworkOptions> {
                Some(NetworkOptions {
                    next_server: Ipv4Addr::new(192, 0, 2, 1),
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                    broadcast: Some(Ipv4Addr::new(192, 0, 2, 255)),
                    router: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    dns_server: Some(Ipv4Addr::new(192, 0, 2, 2)),
                })
            }
        }
        for (request_options, dns_requested) in [
            (&[53, 1, 1, 255][..], true),
            (&[53, 1, 1, 55, 0, 255][..], false),
            (&[53, 1, 1, 55, 1, 6, 255][..], true),
        ] {
            let bytes = packet(
                request_options,
                BROADCAST_FLAG,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
            );
            let mut sender = Sender {
                sent: Vec::new(),
                fail: false,
            };
            let mut output = vec![0; 548];
            let explicit = [ReplyOption {
                code: 3,
                value: &[192, 0, 2, 10],
            }];
            process_with_random(
                dispatch_for(&bytes),
                SocketAddr::from(([192, 0, 2, 9], 68)),
                &mut Provider,
                &mut sender,
                &explicit,
                &mut output,
                || panic!("OFFER must not draw random"),
            )
            .unwrap();
            assert_eq!(wire_option(&output, 1), Some([255, 255, 255, 0].as_slice()));
            assert_eq!(wire_option(&output, 28), Some([192, 0, 2, 255].as_slice()));
            assert_eq!(wire_option(&output, 3), Some([192, 0, 2, 10].as_slice()));
            assert_eq!(wire_option(&output, 6).is_some(), dns_requested);
            assert_eq!(&output[20..24], &[192, 0, 2, 1]);
        }
    }

    #[test]
    fn configured_broadcast_changes_wire_flag_and_skips_arp_unicast() {
        struct Provider;
        impl OutcomeProvider for Provider {
            fn resolve(&mut self, _: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
                Ok(offer())
            }

            fn force_broadcast(&self, _: &Outcome) -> bool {
                true
            }
        }
        let bytes = packet(
            &[53, 1, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let mut sender = Sender {
            sent: Vec::new(),
            fail: false,
        };
        let mut output = vec![0; 548];
        let report = process_with_random(
            dispatch_for(&bytes),
            SocketAddr::from(([0, 0, 0, 0], 68)),
            &mut Provider,
            &mut sender,
            &[],
            &mut output,
            || panic!("OFFER must not draw random"),
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([output[10], output[11]]), BROADCAST_FLAG);
        let destination = report.events.iter().find_map(|event| match event {
            RuntimeEvent::DestinationSelected(destination) => Some(destination),
            _ => None,
        });
        let destination = destination.unwrap();
        assert_eq!(destination.kind, DestinationKind::Broadcast);
        assert_eq!(destination.address.ip(), IpAddr::V4(Ipv4Addr::BROADCAST));
        assert!(destination.arp.is_none());
    }

    #[test]
    fn local_offer_broadcasts_and_records_cleanup() {
        let bytes = packet(
            &[53, 1, 1, 255],
            BROADCAST_FLAG,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        let mut sender = Sender {
            sent: Vec::new(),
            fail: false,
        };
        let mut provider = |_dispatch: &Dispatch<'_>| Ok(offer());
        let mut buffer = vec![0; 548];
        let report = process(
            dispatch,
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &mut provider,
            &mut sender,
            &[],
            &mut buffer,
        )
        .unwrap();
        assert!(report.outcome.is_some());
        assert_eq!(sender.sent[0].0.len(), 300);
        assert_eq!(
            sender.sent[0].1,
            SocketAddr::from((Ipv4Addr::BROADCAST, 68))
        );
        assert!(report.events.iter().any(|event| matches!(
            event,
            RuntimeEvent::DestinationSelected(Destination {
                kind: DestinationKind::Broadcast,
                interface: 7,
                ..
            })
        )));
        assert!(matches!(
            report.events.last(),
            Some(RuntimeEvent::Cleanup { .. })
        ));
    }

    #[test]
    fn renewal_unicasts_to_ciaddr_and_failure_keeps_commit() {
        let bytes = packet(
            &[53, 1, 3, 255],
            0,
            Ipv4Addr::new(192, 0, 2, 9),
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        let committed = Cell::new(false);
        let mut provider = |_dispatch: &Dispatch<'_>| {
            committed.set(true);
            Ok(offer())
        };
        let mut sender = Sender {
            sent: Vec::new(),
            fail: true,
        };
        let mut buffer = vec![0; 548];
        let failure = process(
            dispatch,
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &mut provider,
            &mut sender,
            &[],
            &mut buffer,
        )
        .unwrap_err();
        assert!(committed.get());
        assert!(failure.committed);
        assert!(failure.outcome.is_some());
        assert!(matches!(failure.error, RuntimeError::Send(_)));
        assert!(failure.events.iter().any(
            |event| matches!(event, RuntimeEvent::DestinationSelected(Destination {
                kind: DestinationKind::Client,
                address,
                ..
            }) if *address == SocketAddr::from(([192, 0, 2, 9], 68)))
        ));
        assert!(matches!(
            failure.events.last(),
            Some(RuntimeEvent::Cleanup { .. })
        ));
    }

    #[test]
    fn unconfigured_yiaddr_requires_arp_route_metadata() {
        let bytes = packet(
            &[53, 1, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        let mut wire = vec![0; 300];
        wire[1] = 1;
        wire[2] = 6;
        wire[16..20].copy_from_slice(&[192, 0, 2, 42]);
        let selected = destination(
            &dispatch,
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &Reply::Offer {
                address: Ipv4Addr::new(192, 0, 2, 42),
                lease_time: 60,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &wire,
            wire.len(),
        )
        .unwrap();
        assert_eq!(selected.kind, DestinationKind::Client);
        assert_eq!(selected.interface, 7);
        assert_eq!(selected.arp.unwrap().hardware_address, vec![0; 6]);
    }

    #[test]
    fn short_unicast_wire_is_rejected_before_arp_slice() {
        let bytes = packet(
            &[53, 1, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        let mut wire = vec![0; 20];
        wire[1] = 1;
        wire[2] = 6;
        wire[16..20].copy_from_slice(&[192, 0, 2, 42]);
        let error = destination(
            &dispatch,
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &Reply::Offer {
                address: Ipv4Addr::new(192, 0, 2, 42),
                lease_time: 60,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &wire,
            wire.len(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Reply(ReplyError::BufferTooSmall {
                required: 34,
                available: 20,
            })
        ));
    }

    #[test]
    fn inform_trusts_only_nonzero_ipv4_peer_and_port() {
        let ciaddr = Ipv4Addr::new(192, 0, 2, 9);
        let bytes = packet(&[53, 1, 8, 255], 0, ciaddr, Ipv4Addr::UNSPECIFIED);
        let dispatch = dispatch_for(&bytes);
        let reply = Reply::Inform {
            lease_time: None,
            context: None,
            server: Ipv4Addr::new(192, 0, 2, 1),
        };
        // dhcp.c:415-428: INFORM overrides the address comparison, never
        // the checks for an unspecified source address or zero source port.
        for peer in [
            SocketAddr::from(([192, 0, 2, 10], 0)),
            SocketAddr::from(([0, 0, 0, 0], 1068)),
            SocketAddr::from(([0, 0, 0, 0], 0)),
            "[::1]:1068".parse().unwrap(),
        ] {
            let selected = destination(&dispatch, peer, &reply, &bytes, bytes.len()).unwrap();
            assert_eq!(selected.address, SocketAddr::from((ciaddr, 68)));
            assert_eq!(selected.kind, DestinationKind::Client);
            assert!(selected.arp.is_none());
        }
        let peer = SocketAddr::from(([192, 0, 2, 10], 1068));
        let selected = destination(&dispatch, peer, &reply, &bytes, bytes.len()).unwrap();
        assert_eq!(selected.address, peer);
        assert_eq!(selected.kind, DestinationKind::Peer);
    }

    #[test]
    fn zero_yiaddr_does_not_change_linux_arp_route_to_broadcast() {
        let bytes = packet(
            &[53, 1, 3, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        let selected = destination(
            &dispatch,
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &offer().reply,
            &bytes,
            bytes.len(),
        )
        .unwrap();
        // dhcp.c's Linux branch chooses broadcast from flags/hardware only.
        // The state layer, rather than this route selector, owns yiaddr.
        assert_eq!(
            selected.address,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 68))
        );
        assert_eq!(selected.kind, DestinationKind::Client);
        assert_eq!(selected.arp.unwrap().address, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn relay_routes_commit_and_restore_source_extension() {
        let peer = SocketAddr::from(([192, 0, 2, 10], 1068));
        for relay in [Ipv4Addr::new(192, 0, 2, 254), Ipv4Addr::BROADCAST] {
            let bytes = packet(&[53, 1, 1, 255], 0, Ipv4Addr::UNSPECIFIED, relay);
            let dispatch = dispatch_for(&bytes);
            let called = Cell::new(false);
            let mut provider = |dispatch: &Dispatch<'_>| {
                called.set(true);
                assert_eq!(
                    dispatch.packet.giaddr(),
                    if relay == Ipv4Addr::BROADCAST {
                        Ipv4Addr::UNSPECIFIED
                    } else {
                        relay
                    }
                );
                Ok(offer())
            };
            let mut sender = Sender {
                sent: Vec::new(),
                fail: false,
            };
            let mut buffer = vec![0; 548];
            let report = process_with_random_and_ports(
                dispatch,
                peer,
                &mut provider,
                &mut sender,
                &[],
                &mut buffer,
                crate::config::dhcp_relay::DhcpPorts {
                    server: 2067,
                    client: 2068,
                },
                || Ok(0),
            )
            .unwrap();
            assert!(called.get());
            assert_eq!(sender.sent.len(), 1);
            let (packet, sent_address) = &sender.sent[0];
            let destination = report
                .events
                .iter()
                .find_map(|event| match event {
                    RuntimeEvent::DestinationSelected(destination) => Some(destination),
                    _ => None,
                })
                .unwrap();
            assert_eq!(*sent_address, destination.address);
            assert_eq!(&packet[24..28], &relay.octets());
            assert_eq!(
                destination.address,
                if relay == Ipv4Addr::BROADCAST {
                    peer
                } else {
                    SocketAddr::from((relay, 2067))
                }
            );
            assert_eq!(destination.interface, 0);
            assert!(destination.arp.is_none());
        }
    }

    #[test]
    fn pxe_peer_port_precedes_relay_route_and_keeps_cleared_source_sentinel() {
        let peer = SocketAddr::from(([192, 0, 2, 10], 1040));
        let bytes = packet(
            &[53, 1, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        );
        let mut dispatch = dispatch_for(&bytes);
        dispatch.ingress.listener = super::super::service::Listener::Pxe;
        dispatch.kind = DispatchKind::Pxe;
        let mut provider = |request: &Dispatch<'_>| {
            assert!(request.packet.giaddr().is_unspecified());
            Ok(offer())
        };
        let mut sender = Sender {
            sent: Vec::new(),
            fail: false,
        };
        let mut output = [0; 548];
        process_with_random_and_ports(
            dispatch,
            peer,
            &mut provider,
            &mut sender,
            &[],
            &mut output,
            crate::config::dhcp_relay::DhcpPorts {
                server: 2067,
                client: 2068,
            },
            || Ok(0),
        )
        .unwrap();
        assert_eq!(sender.sent[0].1, peer);
        assert_eq!(&sender.sent[0].0[24..28], &[0; 4]);
        output[12..16].copy_from_slice(&[192, 0, 2, 20]);
        assert_eq!(
            pxe_peer(&output, peer),
            SocketAddr::from(([192, 0, 2, 20], 1040))
        );
    }

    #[test]
    fn state_provider_commits_request_lease_and_hostname_before_send() {
        let requested = Ipv4Addr::new(192, 0, 2, 10);
        let server = Ipv4Addr::new(192, 0, 2, 1);
        let bytes = packet(
            &[
                53, 1, 3, 50, 4, 192, 0, 2, 10, 54, 4, 192, 0, 2, 1, 12, 4, b't', b'e', b's', b't',
                255,
            ],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        let mut store = LeaseStore::new(4);
        let mut ranges = vec![AddressRange {
            start: requested,
            end: Ipv4Addr::new(192, 0, 2, 20),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 0, 2, 254),
            local: server,
            lease_time: 600,
            kind: RangeKind::Dynamic,
            filter: Vec::new(),
            epoch: 0,
        }];
        let environment = Environment {
            now: 100,
            interface: 0,
            authoritative: true,
            unicast_destination: true,
            ignored: false,
            ignore_client_id: false,
            fqdn_only: false,
            rapid_commit: false,
            bootp_dynamic: true,
            consecutive_addresses: false,
            override_server: None,
            fallback_server: server,
            server_aliases: &[],
        };
        let tags: &[&[u8]] = &[];
        let reserved: &[Ipv4Addr] = &[];
        let mut counters = MessageCounters::default();
        let notifications = Cell::new(0);
        let request_notices = Cell::new(0);
        let tag_notices = Cell::new(0);
        let mut on_event = |event: state::LogEvent<'_>| {
            if let state::LogEvent::Tags { context } = event {
                assert_eq!(context, Some(0));
                tag_notices.set(tag_notices.get() + 1);
            } else if let state::LogEvent::Packet { .. } = event {
                assert_eq!(
                    event,
                    state::LogEvent::Packet {
                        kind: b"DHCPREQUEST",
                        address: Some(requested),
                        extra: None,
                        error: None
                    }
                );
                request_notices.set(request_notices.get() + 1);
            } else {
                assert_eq!(
                    event,
                    state::LogEvent::Ack {
                        address: requested,
                        name: Some(b"test")
                    }
                );
                notifications.set(notifications.get() + 1);
            }
        };
        let mut provider = StateProvider::new(
            &mut store,
            &mut ranges,
            tags,
            None,
            reserved,
            environment,
            |_, _, _| ProbeResult::Available { offer_hash: 1 },
        );
        provider.message_counters = Some(&mut counters);
        provider.event_sink = Some(&mut on_event);
        let outcome = provider.resolve(&dispatch).unwrap();
        assert!(matches!(
            outcome.reply,
            Reply::Ack {
                address,
                lease_time: 600,
                server: reply_server,
                ..
            } if address == requested && reply_server == server
        ));
        assert_eq!(
            provider.store.get(requested).unwrap().hostname.as_deref(),
            Some(&b"test"[..])
        );
        // rfc2131.c:90,799-816 keeps hostname_auth=0 for client option 12;
        // OPT_AUTHORITATIVE only affects address/lease decisions.
        assert!(!provider.store.get(requested).unwrap().authoritative_name);
        assert!(provider.store.changes().dns);
        assert_eq!(provider.message_counters.as_deref().unwrap().request, 1);
        assert_eq!(provider.message_counters.as_deref().unwrap().ack, 1);

        // A configured name may displace a client name, but a subsequent
        // client REQUEST must not steal it back (lease.c:1127-1133).
        let configured = Ipv4Addr::new(192, 0, 2, 20);
        provider
            .store
            .allocate(
                configured,
                crate::dhcp::lease::ClientIdentity {
                    hardware_type: 1,
                    hardware_address: vec![2; 6],
                    client_id: None,
                },
            )
            .unwrap();
        provider
            .store
            .set_hostname(configured, Some(b"test"), true, None, false)
            .unwrap();
        provider.store.set_expires(configured, 600, 100).unwrap();
        let outcome = provider.resolve(&dispatch).unwrap();
        assert!(matches!(outcome.reply, Reply::Ack { .. }));
        assert!(outcome.lost_names.is_empty());
        assert!(provider.store.get(requested).unwrap().hostname.is_none());
        assert_eq!(
            provider.store.get(configured).unwrap().hostname.as_deref(),
            Some(&b"test"[..])
        );
        // C updates both counters while constructing its ACK, before the
        // containing DHCP caller attempts socket delivery. A send error must
        // neither undo those events nor count another packet-level event.
        struct SourceOrderSender<'a> {
            tag_notices: &'a Cell<usize>,
            request_notices: &'a Cell<usize>,
            notifications: &'a Cell<usize>,
            sent: bool,
        }
        impl DatagramSender for SourceOrderSender<'_> {
            fn send(&mut self, _: &[u8], _: &Destination) -> io::Result<()> {
                assert_eq!(
                    self.notifications.get(),
                    3,
                    "source callback must precede send"
                );
                assert_eq!(
                    self.request_notices.get(),
                    3,
                    "request notices must precede send"
                );
                assert_eq!(
                    self.tag_notices.get(),
                    3,
                    "selected tag notices must precede send"
                );
                self.sent = true;
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
        let mut sender = SourceOrderSender {
            tag_notices: &tag_notices,
            request_notices: &request_notices,
            notifications: &notifications,
            sent: false,
        };
        let failure = process_with_random(
            dispatch_for(&bytes),
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &mut provider,
            &mut sender,
            &[],
            &mut [0; 548],
            || Ok(0),
        )
        .unwrap_err();
        assert!(matches!(failure.error, RuntimeError::Send(_)));
        assert!(failure.committed);
        assert_eq!(provider.message_counters.as_deref().unwrap().request, 3);
        assert_eq!(provider.message_counters.as_deref().unwrap().ack, 3);
        assert!(sender.sent);
        assert_eq!(
            notifications.get(),
            3,
            "send failure must not repeat or undo notification"
        );
    }

    #[test]
    fn script_backpressure_cannot_be_bypassed_by_address_change_or_packet_expiry() {
        let old = Ipv4Addr::new(192, 0, 2, 10);
        let requested = Ipv4Addr::new(192, 0, 2, 11);
        let server = Ipv4Addr::new(192, 0, 2, 1);
        let bytes = packet(
            &[53, 1, 3, 50, 4, 192, 0, 2, 11, 54, 4, 192, 0, 2, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        for expired in [false, true] {
            let mut store = LeaseStore::new(1);
            store
                .allocate(old, state::identity(dispatch.packet, false))
                .unwrap();
            store
                .set_expires(old, if expired { 1 } else { 600 }, 1)
                .unwrap();
            store.set_script_backlog(Some(63));
            let mut ranges = [AddressRange {
                start: old,
                end: requested,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                router: server,
                local: server,
                lease_time: 600,
                kind: RangeKind::Dynamic,
                filter: Vec::new(),
                epoch: 0,
            }];
            let environment = Environment {
                now: 100,
                interface: 0,
                authoritative: true,
                unicast_destination: false,
                ignored: false,
                ignore_client_id: false,
                fqdn_only: false,
                rapid_commit: false,
                bootp_dynamic: false,
                consecutive_addresses: false,
                override_server: None,
                fallback_server: server,
                server_aliases: &[],
            };
            let mut provider = StateProvider::new(
                &mut store,
                &mut ranges,
                &[],
                None,
                &[],
                environment,
                |_, _, _| ProbeResult::Available { offer_hash: 1 },
            );
            let outcome = provider.resolve(&dispatch).unwrap();
            assert!(matches!(
                outcome.reply,
                Reply::Nak {
                    reason: state::Refusal::NoLeasesLeft,
                    ..
                }
            ));
            assert_eq!(outcome.removed.len(), 1);
            assert_eq!(outcome.removed[0].address, old);
            assert!(provider.store.is_empty());
        }
    }

    #[test]
    fn state_provider_prunes_expired_even_for_no_reply_message() {
        let expired = Ipv4Addr::new(192, 0, 2, 10);
        let bytes = packet(
            &[53, 1, 2, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        let mut store = LeaseStore::new(1);
        store
            .allocate(
                expired,
                crate::dhcp::lease::ClientIdentity {
                    hardware_type: 1,
                    hardware_address: vec![1; 6],
                    client_id: None,
                },
            )
            .unwrap();
        store
            .set_hostname(expired, Some(b"old"), false, None, false)
            .unwrap();
        store.set_expires(expired, 10, 1).unwrap();
        let mut ranges = [];
        let environment = Environment {
            now: 11,
            interface: 0,
            authoritative: false,
            unicast_destination: false,
            ignored: false,
            ignore_client_id: false,
            fqdn_only: false,
            rapid_commit: false,
            bootp_dynamic: false,
            consecutive_addresses: false,
            override_server: None,
            fallback_server: Ipv4Addr::UNSPECIFIED,
            server_aliases: &[],
        };
        let mut provider = StateProvider::new(
            &mut store,
            &mut ranges,
            &[],
            None,
            &[],
            environment,
            |_, _, _| ProbeResult::InUse,
        );
        let outcome = provider.resolve(&dispatch).unwrap();
        assert_eq!(outcome.reply, Reply::Ignore);
        assert_eq!(outcome.removed.len(), 1);
        assert_eq!(outcome.removed[0].address, expired);
        assert_eq!(outcome.lost_names[0].name, b"old");
        assert!(provider.store.is_empty());
    }

    #[test]
    fn probe_snapshot_includes_expiry_and_bootp_wrong_network_prunes() {
        let offered = Ipv4Addr::new(192, 0, 2, 10);
        let server = Ipv4Addr::new(192, 0, 2, 1);
        let hardware = vec![2, 0, 0, 0, 0, 1];
        for (bootp, scoped, permitted) in [
            (false, false, true),
            (true, false, true),
            (true, true, true),
            (true, true, false),
        ] {
            let options = if bootp {
                vec![255]
            } else {
                vec![53, 1, 1, 50, 4, 192, 0, 2, 10, 255]
            };
            let mut bytes = packet(&options, 0, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);
            bytes[28..34].copy_from_slice(&hardware);
            let dispatch = dispatch_for(&bytes);
            let previous = if bootp {
                Ipv4Addr::new(198, 51, 100, 10)
            } else {
                offered
            };
            let mut store = LeaseStore::new(2);
            store
                .allocate(
                    previous,
                    crate::dhcp::lease::ClientIdentity {
                        hardware_type: 1,
                        hardware_address: hardware.clone(),
                        client_id: None,
                    },
                )
                .unwrap();
            if !bootp {
                store.set_expires(previous, 10, 90).unwrap();
            }
            let mut ranges = vec![AddressRange {
                start: offered,
                end: offered,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                router: Ipv4Addr::new(192, 0, 2, 254),
                local: server,
                lease_time: 600,
                kind: RangeKind::Dynamic,
                filter: Vec::new(),
                epoch: 0,
            }];
            if scoped {
                let mut excluded = ranges[0].clone();
                excluded.filter = vec![b"missing".to_vec()];
                ranges.insert(0, excluded);
            }
            let environment = Environment {
                now: 100,
                interface: 0,
                authoritative: false,
                unicast_destination: false,
                ignored: false,
                ignore_client_id: false,
                fqdn_only: false,
                rapid_commit: false,
                bootp_dynamic: !scoped,
                consecutive_addresses: false,
                override_server: None,
                fallback_server: server,
                server_aliases: &[],
            };
            let snapshots = Cell::new(0);
            let mut provider = StateProvider::new(
                &mut store,
                &mut ranges,
                &[],
                None,
                &[],
                environment,
                |address, hash, counters| {
                    assert_eq!(address, offered);
                    assert_eq!(
                        counters,
                        LeaseCounters {
                            allocated4: 1,
                            pruned4: 1,
                            pruned6: 0
                        }
                    );
                    snapshots.set(snapshots.get() + 1);
                    ProbeResult::Available { offer_hash: hash }
                },
            );
            let permissions = [!permitted, permitted];
            if scoped {
                provider.bootp_contexts = &permissions;
            }
            let outcome = provider.resolve(&dispatch).unwrap();
            assert_eq!(snapshots.get(), 1);
            assert_eq!(outcome.removed.len(), 1);
            assert_eq!(outcome.removed[0].address, previous);
            if !permitted {
                assert_eq!(outcome.reply, Reply::Ignore);
                assert!(provider.store.is_empty());
                continue;
            }
            if scoped {
                assert!(matches!(outcome.reply, Reply::Bootp { context: 1, .. }));
            }
            assert!(if bootp {
                matches!(outcome.reply, Reply::Bootp { address, .. } if address == offered)
            } else {
                matches!(outcome.reply, Reply::Offer { address, .. } if address == offered)
            });
        }
    }

    #[test]
    fn no_reply_and_small_buffer_do_not_send() {
        let bytes = packet(
            &[53, 1, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        );
        let dispatch = dispatch_for(&bytes);
        let mut sender = Sender {
            sent: Vec::new(),
            fail: false,
        };
        let mut provider = |_dispatch: &Dispatch<'_>| {
            Ok(Outcome {
                reply: Reply::Ignore,
                removed: Vec::new(),
                lost_names: Vec::new(),
                newly_allocated: false,
            })
        };
        let mut buffer = vec![0; 548];
        let report = process(
            dispatch,
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &mut provider,
            &mut sender,
            &[],
            &mut buffer,
        )
        .unwrap();
        assert!(report.outcome.is_some());
        assert!(report
            .events
            .iter()
            .any(|event| matches!(event, RuntimeEvent::NoReply)));
        assert!(sender.sent.is_empty());

        let dispatch = dispatch_for(&bytes);
        let mut provider = |_dispatch: &Dispatch<'_>| Ok(offer());
        let mut short = vec![0; 299];
        let failure = process(
            dispatch,
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &mut provider,
            &mut sender,
            &[],
            &mut short,
        )
        .unwrap_err();
        assert!(failure.committed);
        assert!(matches!(
            failure.error,
            RuntimeError::Reply(ReplyError::BufferTooSmall { .. })
        ));
    }
}
