//! Lease transactions after the caller has resolved interface contexts, tags,
//! host configuration and hostname policy. Reference: rfc2131.c:1237-1753.
//! This layer does not pretend that pre-dispatch matching or wire reply option
//! generation has been implemented; both remain required service boundaries.

use super::allocation::{
    allocate_address, available, narrow, AddressRange, ProbeResult, RangeKind,
};
use super::lease::{ClientIdentity, Lease, LeaseCounters, LeaseError, LeaseStore, NameLost};
use super::message_counters::MessageCounters;
use super::packet::Packet;
use super::request::{
    classify_request, extended_hardware_id, lease_duration, NakReason, RequestDecision, RequestMode,
};
use std::net::Ipv4Addr;

pub const DECLINE_BACKOFF: i64 = 600;

#[derive(Clone, Debug, Default)]
pub struct HostPolicy {
    pub address: Option<Ipv4Addr>,
    pub lease_time: Option<u32>,
    pub declined_at: Option<i64>,
    pub hardware_addresses: Vec<ClientIdentity>,
    pub ignore_client_id: bool,
}

impl HostPolicy {
    /// config_has_mac's exact-address branch, used to hand a static address
    /// between explicitly configured MACs; wildcard matches cannot authorize it.
    fn has_hardware(&self, identity: &ClientIdentity) -> bool {
        self.hardware_addresses.iter().any(|configured| {
            (configured.hardware_type == 0 || configured.hardware_type == identity.hardware_type)
                && configured.hardware_address == identity.hardware_address
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Name<'a> {
    pub hostname: &'a [u8],
    pub domains: Option<&'a crate::config::dhcp::NameDomains>,
    pub authoritative: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Environment<'a> {
    pub now: i64,
    pub interface: u32,
    pub authoritative: bool,
    pub unicast_destination: bool,
    pub ignored: bool,
    pub ignore_client_id: bool,
    pub fqdn_only: bool,
    pub rapid_commit: bool,
    /// BOOTP dynamic permission after the caller's tag evaluation.
    pub bootp_dynamic: bool,
    pub consecutive_addresses: bool,
    pub override_server: Option<Ipv4Addr>,
    pub fallback_server: Ipv4Addr,
    /// Additional accepted local IPv4 interface aliases, checked by C after
    /// the receiving context chain fails to contain the selected server ID.
    pub server_aliases: &'a [Ipv4Addr],
}

pub struct Request<'a> {
    pub packet: Packet<'a>,
    pub tags: &'a [&'a [u8]],
    pub host: Option<&'a HostPolicy>,
    /// All configured static addresses, including the selected host's address.
    pub reserved: &'a [Ipv4Addr],
    pub name: Option<Name<'a>>,
    pub environment: Environment<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    WrongServer,
    WrongAddress,
    LeaseNotFound,
    WrongNetwork,
    AddressNotAvailable,
    StaticLeaseAvailable,
    AddressReserved,
    AddressInUse,
    NoUniqueId,
    NoLeasesLeft,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Self::WrongServer => "wrong server-ID",
            Self::WrongAddress => "wrong address",
            Self::LeaseNotFound => "lease not found",
            Self::WrongNetwork => "wrong network",
            Self::AddressNotAvailable => "address not available",
            Self::StaticLeaseAvailable => "static lease available",
            Self::AddressReserved => "address reserved",
            Self::AddressInUse => "address in use",
            Self::NoUniqueId => "no unique-id",
            Self::NoLeasesLeft => "no leases left",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    Ignore,
    Offer {
        address: Ipv4Addr,
        lease_time: u32,
        context: usize,
        server: Ipv4Addr,
    },
    Bootp {
        address: Ipv4Addr,
        context: usize,
    },
    Inform {
        lease_time: Option<u32>,
        context: Option<usize>,
        server: Ipv4Addr,
    },
    Ack {
        address: Ipv4Addr,
        lease_time: u32,
        context: usize,
        server: Ipv4Addr,
        rapid_commit: bool,
    },
    Nak {
        reason: Refusal,
        broadcast: bool,
        server: Ipv4Addr,
    },
}

#[derive(Debug)]
pub struct Outcome {
    pub reply: Reply,
    pub removed: Vec<Lease>,
    pub lost_names: Vec<NameLost>,
    /// This transaction allocated a lease record, rather than reusing one.
    pub newly_allocated: bool,
}

/// Values at rfc2131.c's ACK/RELEASE log_packet write sites. This is emitted
/// during the state transaction, before the caller persists/publishes/sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogEvent<'a> {
    Warning {
        message: &'a [u8],
    },
    Tags {
        context: Option<usize>,
    },
    Packet {
        kind: &'static [u8],
        address: Option<Ipv4Addr>,
        extra: Option<&'a [u8]>,
        error: Option<&'a [u8]>,
    },
    Ack {
        address: Ipv4Addr,
        name: Option<&'a [u8]>,
    },
    Release {
        address: Ipv4Addr,
        unknown_lease: bool,
    },
}

pub(crate) type LogSink<'a> = dyn for<'event> FnMut(LogEvent<'event>) + 'a;

fn log_packet(
    events: &mut Option<&mut LogSink<'_>>,
    kind: &'static [u8],
    address: Option<Ipv4Addr>,
    extra: Option<&[u8]>,
    error: Option<&[u8]>,
) {
    if let Some(events) = events.as_deref_mut() {
        events(LogEvent::Packet {
            kind,
            address,
            extra,
            error,
        });
    }
}

impl Outcome {
    fn ignored() -> Self {
        Self {
            reply: Reply::Ignore,
            removed: Vec::new(),
            lost_names: Vec::new(),
            newly_allocated: false,
        }
    }
}

pub(crate) fn identity(packet: Packet<'_>, ignore_client_id: bool) -> ClientIdentity {
    ClientIdentity {
        hardware_type: u32::from(packet.hardware_type()),
        hardware_address: packet.hardware_address().to_vec(),
        client_id: (!ignore_client_id)
            .then(|| packet.client_id().map(<[u8]>::to_vec))
            .flatten(),
    }
}

fn server_id(
    context: Option<&AddressRange>,
    environment: Environment<'_>,
    override_id: Option<Ipv4Addr>,
) -> Ipv4Addr {
    override_id
        .filter(|id| !id.is_unspecified())
        .or_else(|| {
            context
                .map(|context| context.local)
                .filter(|id| !id.is_unspecified())
        })
        .unwrap_or(environment.fallback_server)
}

/// REQUEST only. The caller prunes expired leases before dispatch, as dhcp.c
/// does. Lease/database side effects commit before packet transmission.
pub fn request(
    store: &mut LeaseStore,
    ranges: &[AddressRange],
    request: Request<'_>,
) -> Result<Outcome, LeaseError> {
    request_counted(
        store,
        ranges,
        request,
        &mut MessageCounters::default(),
        None,
    )
}

pub(crate) fn request_counted(
    store: &mut LeaseStore,
    ranges: &[AddressRange],
    request: Request<'_>,
    counters: &mut MessageCounters,
    events: Option<&mut LogSink<'_>>,
) -> Result<Outcome, LeaseError> {
    transaction(store, ranges, request, None, counters, events)
}

fn transaction(
    store: &mut LeaseStore,
    ranges: &[AddressRange],
    request: Request<'_>,
    offered: Option<Ipv4Addr>,
    counters: &mut MessageCounters,
    mut events: Option<&mut LogSink<'_>>,
) -> Result<Outcome, LeaseError> {
    let mut output = Outcome::ignored();
    let env = request.environment;
    if env.ignored || (offered.is_none() && request.packet.message_type() != 3) {
        return Ok(output);
    }
    let mut client = identity(request.packet, env.ignore_client_id);
    let mut existing_id = store.find_client(&client).map(Lease::id);
    let mut existing = existing_id.map(|id| id.address());
    if client.client_id.is_none() {
        client.client_id =
            existing_id.and_then(|id| store.get_by_id(id)?.identity.client_id.clone());
    }
    let selection = if let Some(address) = offered {
        RequestDecision::CheckAddress {
            mode: RequestMode::InitReboot,
            address,
            prune_old_lease: existing.is_some_and(|old| old != address),
            error: None,
            force_broadcast: false,
        }
    } else {
        classify_request(
            request.packet,
            existing,
            env.authoritative,
            env.unicast_destination,
            env.override_server,
            |server| {
                ranges.iter().any(|range| range.local == server)
                    || env.server_aliases.contains(&server)
            },
        )
    };
    let RequestDecision::CheckAddress {
        mode,
        address,
        prune_old_lease,
        error,
        force_broadcast,
    } = selection
    else {
        return Ok(output);
    };
    if prune_old_lease {
        output.removed = store.prune_lease(existing_id, env.now);
        existing = None;
        existing_id = None;
    }
    // rfc2131.c:1490, after REQUEST-mode early returns. Rapid commit jumps
    // over this statement after DISCOVER and never counts REQUEST or OFFER.
    if offered.is_none() {
        counters.request = counters.request.wrapping_add(1);
        log_packet(&mut events, b"DHCPREQUEST", Some(address), None, None);
    }
    // C's server-ID search consumes the front of the context chain.
    let first = if mode == RequestMode::Selecting && env.override_server.is_none() {
        request
            .packet
            .server_identifier()
            .and_then(|server| ranges.iter().position(|range| range.local == server))
            .unwrap_or(ranges.len())
    } else {
        0
    };
    // The alias exception sets override only after the server-ID scan has
    // exhausted the context chain. Keep that empty chain (and its NAK), but
    // echo the accepted alias instead of the fallback interface address.
    let override_server = env.override_server.or_else(|| {
        (mode == RequestMode::Selecting && first == ranges.len())
            .then(|| request.packet.server_identifier())
            .flatten()
            .filter(|server| env.server_aliases.contains(server))
    });
    let selected_ranges = &ranges[first..];
    let mut context = None;
    let mut error = error.map(|error| match error {
        NakReason::WrongServer => Refusal::WrongServer,
        NakReason::WrongAddress => Refusal::WrongAddress,
        NakReason::LeaseNotFound => Refusal::LeaseNotFound,
    });
    let mut broadcast = force_broadcast;
    if error.is_none() {
        context = narrow(selected_ranges, address, request.tags).map(|index| first + index);
        if let Some(index) = context {
            let static_address = request.host.and_then(|host| host.address);
            let static_is_router = static_address.is_some_and(|address| {
                selected_ranges
                    .first()
                    .is_some_and(|range| range.router == address)
            });
            if available(&ranges[index..index + 1], address, request.tags).is_none()
                && static_address != Some(address)
            {
                error = Some(Refusal::AddressNotAvailable);
            } else if !static_is_router
                && mode != RequestMode::Selecting
                && request.host.is_some_and(|host| {
                    host.declined_at
                        .is_none_or(|time| env.now.saturating_sub(time) > DECLINE_BACKOFF)
                })
                && static_address.is_some_and(|static_address| {
                    static_address != address
                        && store
                            .get(static_address)
                            .is_none_or(|lease| Some(lease.id()) == existing_id)
                })
            {
                error = Some(Refusal::StaticLeaseAvailable);
            } else if request.reserved.contains(&address) && static_address != Some(address) {
                error = Some(Refusal::AddressReserved);
            } else if existing.is_none() {
                if let Some(occupant) = store.get(address) {
                    if request
                        .host
                        .is_some_and(|host| host.has_hardware(&occupant.identity))
                    {
                        existing_id = Some(occupant.id());
                    } else {
                        error = Some(Refusal::AddressInUse);
                    }
                }
            }
        } else {
            error = Some(Refusal::WrongNetwork);
            broadcast = true;
        }
    }
    if error.is_none()
        && extended_hardware_id(
            request.packet.hardware_type(),
            &client.hardware_address,
            client.client_id.as_deref(),
        )
        .is_empty()
    {
        error = Some(Refusal::NoUniqueId);
    }
    if error.is_none() && existing_id.is_none() {
        let mut allocation_identity = client.clone();
        if request.host.is_some_and(|host| host.ignore_client_id) {
            allocation_identity.client_id = None;
        }
        match store.allocate(address, allocation_identity) {
            Ok(()) => output.newly_allocated = true,
            Err(LeaseError::Full) => error = Some(Refusal::NoLeasesLeft),
            Err(error) => return Err(error),
        }
    }
    if let Some(reason) = error {
        // Failed rapid commit sends no NAK (rfc2131.c:1567-1576).
        if offered.is_some() {
            counters.no_answer = counters.no_answer.wrapping_add(1); // :1565
            log_packet(
                &mut events,
                b"NOANSWER",
                Some(address),
                None,
                Some(reason.message().as_bytes()),
            );
            return Ok(output);
        }
        counters.nak = counters.nak.wrapping_add(1); // :1565
        log_packet(
            &mut events,
            b"DHCPNAK",
            Some(address),
            None,
            Some(reason.message().as_bytes()),
        );

        // A failed narrow_context assigns NULL in rfc2131.c. Its NAK uses
        // the ingress fallback, not the former chain head. Earlier mode
        // errors skip narrowing and still retain that head.
        let chosen = if reason == Refusal::WrongNetwork {
            None
        } else {
            context
                .map(|index| &ranges[index])
                .or_else(|| selected_ranges.first())
        };
        let client_address = request.packet.effective_ciaddr();
        broadcast |= !env.unicast_destination
            || !request.packet.giaddr().is_unspecified()
            || client_address.is_unspecified()
            || chosen.is_some_and(|range| {
                (u32::from(range.local) & u32::from(range.netmask))
                    == (u32::from(client_address) & u32::from(range.netmask))
            });
        output.reply = Reply::Nak {
            reason,
            broadcast,
            server: server_id(chosen, env, override_server),
        };
        return Ok(output);
    }
    let index = context.ok_or(LeaseError::NotFound)?;
    if let Some(events) = events.as_deref_mut() {
        events(LogEvent::Tags {
            context: Some(index),
        });
    }
    let duration = lease_duration(
        ranges[index].lease_time,
        request.host.and_then(|host| host.lease_time),
        request.packet.requested_lease_time(),
    );
    if request.host.is_some_and(|host| host.ignore_client_id) {
        client.client_id = None;
    }
    let id = existing_id
        .or_else(|| store.get(address).map(Lease::id))
        .ok_or(LeaseError::NotFound)?;
    store.set_identity_by_id(id, &client)?;
    if let Some(name) = request.name {
        output.lost_names = store.set_hostname_by_id(
            id,
            Some(name.hostname),
            name.authoritative,
            name.domains
                .and_then(|domains| domains.for_address(address)),
            env.fqdn_only,
        )?;
    }
    store.set_expires_by_id(id, duration, env.now)?;
    store.set_interface_by_id(id, env.interface)?;
    let override_id = store.server_override_by_id(id, override_server)?;
    counters.ack = counters.ack.wrapping_add(1); // :1738, before wire/send
    if let Some(events) = events {
        events(LogEvent::Ack {
            address,
            name: request.name.map(|name| name.hostname),
        });
    }
    output.reply = Reply::Ack {
        address,
        lease_time: duration,
        context: index,
        server: server_id(Some(&ranges[index]), env, override_id),
        rapid_commit: offered.is_some(),
    };
    Ok(output)
}

/// DISCOVER chooses an address without committing a lease. Static reservations,
/// existing leases, requested free addresses, and hashed allocation are tried
/// in exactly that order (rfc2131.c:1287-1389).
pub fn discover(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    request: Request<'_>,
    mut probe: impl FnMut(Ipv4Addr, u32) -> ProbeResult,
) -> Result<Outcome, LeaseError> {
    discover_counted(
        store,
        ranges,
        request,
        |address, hash, _| probe(address, hash),
        false,
        &mut MessageCounters::default(),
        None,
        None,
    )
}

/// Called after successful DISCOVER address narrowing, before rapid lease commit.
pub type OfferWait<'a> = dyn FnMut(usize, LeaseCounters) -> bool + 'a;

#[expect(clippy::too_many_arguments, reason = "retain the explicit DHCP transaction and callback boundary")]
pub(crate) fn discover_counted(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    request: Request<'_>,
    probe: impl FnMut(Ipv4Addr, u32, LeaseCounters) -> ProbeResult,
    quiet: bool,
    counters: &mut MessageCounters,
    mut events: Option<&mut LogSink<'_>>,
    before_offer: Option<&mut OfferWait<'_>>,
) -> Result<Outcome, LeaseError> {
    let outcome = select_discover_counted(
        store,
        ranges,
        &request,
        probe,
        quiet,
        counters,
        events.as_deref_mut(),
        before_offer,
    )?;
    finish_discover_counted(store, ranges, request, outcome, counters, events)
}

/// Select an address before ACK name policy: rapid commit needs the actual
/// context and yiaddr, which cannot be inferred from DISCOVER option 50.
#[expect(clippy::too_many_arguments, reason = "retain the explicit DHCP selection and callback boundary")]
pub(crate) fn select_discover_counted(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    request: &Request<'_>,
    mut probe: impl FnMut(Ipv4Addr, u32, LeaseCounters) -> ProbeResult,
    quiet: bool,
    counters: &mut MessageCounters,
    mut events: Option<&mut LogSink<'_>>,
    before_offer: Option<&mut OfferWait<'_>>,
) -> Result<Outcome, LeaseError> {
    let env = request.environment;
    if request.packet.message_type() != 1 {
        return Ok(Outcome::ignored());
    }
    if env.ignored {
        // :1289-1293: quiet-dhcp suppresses this one counter as well as log.
        if !quiet {
            counters.discover = counters.discover.wrapping_add(1);
            log_packet(&mut events, b"DHCPDISCOVER", None, None, Some(b"ignored"));
        }
        return Ok(Outcome::ignored());
    }
    let mut client = identity(request.packet, env.ignore_client_id);
    let existing_id = store.find_client(&client).map(Lease::id);
    let existing = existing_id.map(|id| id.address());
    if client.client_id.is_none() {
        client.client_id =
            existing_id.and_then(|id| store.get_by_id(id)?.identity.client_id.clone());
    }
    let static_address = request.host.and_then(|host| {
        let address = host.address?;
        let message = if let Some(occupant) = store.get(address).filter(|occupant| {
            Some(occupant.id()) != existing_id && !host.has_hardware(&occupant.identity)
        }) {
            let hardware = super::logging::hardware(
                occupant.identity.hardware_type as u8,
                &occupant.identity.hardware_address,
                occupant.identity.client_id.as_deref(),
            );
            Some(format!("not using configured address {address} because it is leased to {}",
                String::from_utf8_lossy(&hardware)))
        } else if ranges.first().is_some_and(|range| range.router == address) {
            Some(format!("not using configured address {address} because it is in use by the server or relay"))
        } else if host.declined_at.is_some_and(|time| env.now.saturating_sub(time) < DECLINE_BACKOFF) {
            Some(format!("not using configured address {address} because it was previously declined"))
        } else {
            None
        };
        if let Some(message) = message {
            if let Some(events) = events.as_deref_mut() {
                events(LogEvent::Warning { message: message.as_bytes() });
            }
            None
        } else {
            Some(address)
        }
    });
    let retained = existing.filter(|address| {
        available(ranges, *address, request.tags).is_some() && !request.reserved.contains(address)
    });
    let wanted = if static_address.is_none() && retained.is_none() {
        let eligible = request.packet.requested_address().filter(|address| {
            available(ranges, *address, request.tags).is_some()
                && store.get(*address).is_none()
                && !request.reserved.contains(address)
        });
        if let Some(address) = eligible {
            match probe(address, 0, store.counters()) {
                ProbeResult::Available { .. } => Some(address),
                ProbeResult::InUse => None,
                ProbeResult::Failed => {
                    return Ok(discover_failed(
                        counters,
                        &mut events,
                        request.packet.requested_address(),
                        b"no address available",
                    ))
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    let address = if let Some(address) = static_address.or(retained).or(wanted) {
        address
    } else {
        let hardware = extended_hardware_id(
            request.packet.hardware_type(),
            &client.hardware_address,
            client.client_id.as_deref(),
        );
        if hardware.is_empty() {
            return Ok(discover_failed(
                counters,
                &mut events,
                request.packet.requested_address(),
                b"no unique-id",
            ));
        }
        let Some((_, address)) = allocate_address(
            ranges,
            store,
            hardware,
            request.tags,
            env.consecutive_addresses,
            |address| request.reserved.contains(&address),
            |address, hash| probe(address, hash, store.counters()),
        ) else {
            return Ok(discover_failed(
                counters,
                &mut events,
                request.packet.requested_address(),
                b"no address available",
            ));
        };
        address
    };
    counters.discover = counters.discover.wrapping_add(1); // :1349
    log_packet(
        &mut events,
        b"DHCPDISCOVER",
        request.packet.requested_address(),
        None,
        None,
    );
    let Some(context) = narrow(ranges, address, request.tags) else {
        return Ok(Outcome::ignored());
    };
    if let Some(wait) = before_offer {
        if !wait(context, store.counters()) {
            return Ok(Outcome::ignored());
        }
    }
    let lease_time = lease_duration(
        ranges[context].lease_time,
        request.host.and_then(|host| host.lease_time),
        request.packet.requested_lease_time(),
    );
    Ok(Outcome {
        reply: Reply::Offer {
            address,
            lease_time,
            context,
            server: server_id(Some(&ranges[context]), env, env.override_server),
        },
        removed: Vec::new(),
        lost_names: Vec::new(),
        newly_allocated: false,
    })
}

/// Complete DISCOVER after the owner has resolved any ACK name policy.
pub(crate) fn finish_discover_counted(
    store: &mut LeaseStore,
    ranges: &[AddressRange],
    request: Request<'_>,
    outcome: Outcome,
    counters: &mut MessageCounters,
    mut events: Option<&mut LogSink<'_>>,
) -> Result<Outcome, LeaseError> {
    let Reply::Offer { address, context, .. } = outcome.reply else {
        return Ok(outcome);
    };
    if request.environment.rapid_commit && request.packet.option(80, 0).is_some() {
        return transaction(store, ranges, request, Some(address), counters, events);
    }
    if let Some(events) = events.as_deref_mut() {
        events(LogEvent::Tags {
            context: Some(context),
        });
    }
    counters.offer = counters.offer.wrapping_add(1); // :1377
    log_packet(&mut events, b"DHCPOFFER", Some(address), None, None);
    Ok(outcome)
}

fn discover_failed(
    counters: &mut MessageCounters,
    events: &mut Option<&mut LogSink<'_>>,
    address: Option<Ipv4Addr>,
    error: &'static [u8],
) -> Outcome {
    // Address selection/identity errors still reach C's DISCOVER write site.
    counters.discover = counters.discover.wrapping_add(1);
    log_packet(events, b"DHCPDISCOVER", address, None, Some(error));
    Outcome::ignored()
}

/// BOOTP's address/lease transaction (rfc2131.c:565-697). Its wire reply has
/// only a 64-byte vendor area and no DHCP message type; the serializer must
/// preserve that distinct format. BOOTP defaults to an infinite lease.
pub fn bootp(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    request: Request<'_>,
    mut probe: impl FnMut(Ipv4Addr, u32) -> ProbeResult,
) -> Result<Outcome, LeaseError> {
    bootp_counted(
        store,
        ranges,
        request,
        |address, hash, _| probe(address, hash),
        &mut MessageCounters::default(),
        &[],
    )
}

pub(crate) fn bootp_counted(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    request: Request<'_>,
    probe: impl FnMut(Ipv4Addr, u32, LeaseCounters) -> ProbeResult,
    counters: &mut MessageCounters,
    permitted_contexts: &[bool],
) -> Result<Outcome, LeaseError> {
    bootp_counted_logged(
        store,
        ranges,
        request,
        probe,
        counters,
        permitted_contexts,
        None,
    )
}

pub(crate) fn bootp_counted_logged(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    request: Request<'_>,
    mut probe: impl FnMut(Ipv4Addr, u32, LeaseCounters) -> ProbeResult,
    counters: &mut MessageCounters,
    permitted_contexts: &[bool],
    mut events: Option<&mut LogSink<'_>>,
) -> Result<Outcome, LeaseError> {
    let mut output = Outcome::ignored();
    let env = request.environment;
    let packet = request.packet;
    if packet.message_type() != 0
        || packet.hardware_type() == 0
        || packet.hardware_address().is_empty()
        || ranges
            .first()
            .is_none_or(|range| range.kind == RangeKind::Proxy)
    {
        return Ok(output);
    }
    if env.ignored {
        return Ok(bootp_finished(
            output,
            counters,
            &mut events,
            None,
            Some(b"ignored"),
        ));
    }
    let client = identity(packet, true);
    let mut existing = store.find_client(&client).map(Lease::id);
    let static_address = request.host.and_then(|host| host.address);
    let address = if let Some(address) = static_address {
        existing = store.get(address).map(Lease::id);
        if store.get(address).is_some_and(|lease| {
            lease.identity.hardware_type != client.hardware_type
                || lease.identity.hardware_address != client.hardware_address
        }) {
            return Ok(bootp_finished(
                output,
                counters,
                &mut events,
                static_address,
                Some(b"address in use"),
            ));
        }
        address
    } else {
        if existing.is_some_and(|id| available(ranges, id.address(), request.tags).is_none()) {
            output.removed = store.prune_lease(existing, env.now);
            existing = None;
        }
        if let Some(id) = existing {
            id.address()
        } else {
            let Some((_, address)) = allocate_address(
                ranges,
                store,
                &client.hardware_address,
                request.tags,
                env.consecutive_addresses,
                |address| request.reserved.contains(&address),
                |address, hash| probe(address, hash, store.counters()),
            ) else {
                return Ok(bootp_finished(
                    output,
                    counters,
                    &mut events,
                    None,
                    Some(b"no address available"),
                ));
            };
            address
        }
    };
    let Some(context) = narrow(ranges, address, request.tags) else {
        return Ok(bootp_finished(
            output,
            counters,
            &mut events,
            static_address,
            Some(b"wrong network"),
        ));
    };
    if let Some(events) = events.as_deref_mut() {
        events(LogEvent::Tags {
            context: Some(context),
        });
    }
    if static_address.is_none()
        && !env.bootp_dynamic
        && !permitted_contexts.get(context).copied().unwrap_or(false)
    {
        return Ok(bootp_finished(
            output,
            counters,
            &mut events,
            None,
            Some(b"no address configured"),
        ));
    }
    if existing.is_none() {
        match store.allocate(address, client.clone()) {
            Ok(()) => output.newly_allocated = true,
            Err(LeaseError::Full) => {
                return Ok(bootp_finished(
                    output,
                    counters,
                    &mut events,
                    static_address,
                    Some(b"no leases left"),
                ))
            }
            Err(error) => return Err(error),
        }
    }
    let id = existing
        .or_else(|| store.get(address).map(Lease::id))
        .ok_or(LeaseError::NotFound)?;
    store.set_identity_by_id(id, &client)?;
    if let Some(name) = request.name {
        output.lost_names = store.set_hostname_by_id(
            id,
            Some(name.hostname),
            true,
            name.domains
                .and_then(|domains| domains.for_address(address)),
            env.fqdn_only,
        )?;
    }
    store.set_expires_by_id(
        id,
        request
            .host
            .and_then(|host| host.lease_time)
            .unwrap_or(u32::MAX),
        env.now,
    )?;
    store.set_interface_by_id(id, env.interface)?;
    output.reply = Reply::Bootp { address, context };
    Ok(bootp_finished(
        output,
        counters,
        &mut events,
        Some(address),
        None,
    ))
}

fn bootp_finished(
    outcome: Outcome,
    counters: &mut MessageCounters,
    events: &mut Option<&mut LogSink<'_>>,
    address: Option<Ipv4Addr>,
    error: Option<&[u8]>,
) -> Outcome {
    // :694: counted for both success and the post-admission failure paths.
    counters.bootp = counters.bootp.wrapping_add(1);
    log_packet(events, b"BOOTP", address, None, error);
    outcome
}

/// DECLINE never replies. A matching static address is suppressed for 600 s;
/// otherwise every eligible context's epoch changes, even for an unknown lease.
pub fn decline(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    packet: Packet<'_>,
    host: Option<&mut HostPolicy>,
    environment: Environment<'_>,
) -> Vec<Lease> {
    decline_counted(
        store,
        ranges,
        packet,
        host,
        environment,
        &mut MessageCounters::default(),
    )
}

pub(crate) fn decline_counted(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    packet: Packet<'_>,
    host: Option<&mut HostPolicy>,
    environment: Environment<'_>,
    counters: &mut MessageCounters,
) -> Vec<Lease> {
    decline_counted_logged(store, ranges, packet, host, environment, counters, None)
}

pub(crate) fn decline_counted_logged(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    packet: Packet<'_>,
    mut host: Option<&mut HostPolicy>,
    environment: Environment<'_>,
    counters: &mut MessageCounters,
    mut events: Option<&mut LogSink<'_>>,
) -> Vec<Lease> {
    if packet.message_type() != 4
        || packet.server_identifier()
            != Some(server_id(
                ranges.first(),
                environment,
                environment.override_server,
            ))
    {
        return Vec::new();
    }
    let Some(address) = packet.requested_address() else {
        return Vec::new();
    };
    counters.decline = counters.decline.wrapping_add(1); // :1248
    let message = super::logging::sanitise_option(packet.option(56, 1));
    log_packet(
        &mut events,
        b"DHCPDECLINE",
        Some(address),
        None,
        Some(&message),
    );
    let existing = store
        .find_client(&identity(packet, environment.ignore_client_id))
        .map(Lease::id);
    let removed = if existing.is_some_and(|id| id.address() == address) {
        store.prune_lease(existing, environment.now)
    } else {
        Vec::new()
    };
    if let Some(host) = host.as_mut().filter(|host| host.address == Some(address)) {
        let message = format!("disabling DHCP static address {address} for 10m");
        if let Some(events) = events {
            events(LogEvent::Warning {
                message: message.as_bytes(),
            });
        }
        host.declined_at = Some(environment.now);
    } else {
        for range in ranges {
            range.epoch = range.epoch.wrapping_add(1);
        }
    }
    removed
}

/// RELEASE validates the narrowed network and server identity before deletion;
/// finding a lease by address alone must never authorize another client's release.
pub fn release(
    store: &mut LeaseStore,
    ranges: &[AddressRange],
    packet: Packet<'_>,
    tags: &[&[u8]],
    environment: Environment<'_>,
) -> Vec<Lease> {
    release_counted(
        store,
        ranges,
        packet,
        tags,
        environment,
        &mut MessageCounters::default(),
        None,
    )
}

pub(crate) fn release_counted(
    store: &mut LeaseStore,
    ranges: &[AddressRange],
    packet: Packet<'_>,
    tags: &[&[u8]],
    environment: Environment<'_>,
    counters: &mut MessageCounters,
    events: Option<&mut LogSink<'_>>,
) -> Vec<Lease> {
    if packet.message_type() != 7 {
        return Vec::new();
    }
    let Some(index) = narrow(ranges, packet.effective_ciaddr(), tags) else {
        return Vec::new();
    };
    if packet.server_identifier()
        != Some(server_id(
            Some(&ranges[index]),
            environment,
            environment.override_server,
        ))
    {
        return Vec::new();
    }
    let existing = store
        .find_client(&identity(packet, environment.ignore_client_id))
        .map(Lease::id);
    let removed = if existing.is_some_and(|id| id.address() == packet.effective_ciaddr()) {
        store.prune_lease(existing, environment.now)
    } else {
        Vec::new()
    };
    counters.release = counters.release.wrapping_add(1); // :1282, including unknown lease
    if let Some(events) = events {
        events(LogEvent::Release {
            address: packet.effective_ciaddr(),
            unknown_lease: existing.is_none_or(|id| id.address() != packet.effective_ciaddr()),
        });
    }
    removed
}

/// INFORM returns settings without allocating or extending a lease. It may
/// succeed without a context, and reports remaining lease time only when the
/// PRL allows option 51 (including the reference's absent-PRL "all" behavior).
pub fn inform(
    store: &mut LeaseStore,
    ranges: &[AddressRange],
    request: Request<'_>,
) -> Result<Outcome, LeaseError> {
    inform_counted(
        store,
        ranges,
        request,
        &mut MessageCounters::default(),
        None,
    )
}

pub(crate) fn inform_counted(
    store: &mut LeaseStore,
    ranges: &[AddressRange],
    request: Request<'_>,
    counters: &mut MessageCounters,
    mut events: Option<&mut LogSink<'_>>,
) -> Result<Outcome, LeaseError> {
    let mut output = Outcome::ignored();
    let env = request.environment;
    let address = request.packet.effective_ciaddr();
    if request.packet.message_type() != 8 {
        return Ok(output);
    }
    counters.inform = counters.inform.wrapping_add(1); // :1757, before ignore/zero-ciaddr
    log_packet(
        &mut events,
        b"DHCPINFORM",
        Some(address),
        env.ignored.then_some(b"ignored".as_slice()),
        None,
    );
    if env.ignored || address.is_unspecified() {
        return Ok(output);
    }
    let context = narrow(ranges, address, request.tags);
    let client_existing = store
        .find_client(&identity(request.packet, env.ignore_client_id))
        .map(Lease::id);
    let existing = client_existing.or_else(|| store.get(address).map(Lease::id));
    let mut override_id = env.override_server;
    let mut lease_time = None;
    if let Some(events) = events.as_deref_mut() {
        events(LogEvent::Tags { context });
    }
    counters.ack = counters.ack.wrapping_add(1); // :1784, before lease interface update
    if let Some(events) = events {
        let name = client_existing
            .is_none()
            .then(|| existing.and_then(|existing| store.get_by_id(existing)?.hostname.as_deref()))
            .flatten()
            .or_else(|| request.name.map(|name| name.hostname));
        events(LogEvent::Ack { address, name });
    }
    if let Some(existing) = existing {
        store.set_interface_by_id(existing, env.interface)?;
        override_id = store.server_override_by_id(existing, override_id)?;
        if request.packet.requests(51) {
            lease_time = Some(
                store
                    .get_by_id(existing)
                    .ok_or(LeaseError::NotFound)?
                    .expires
                    .map_or(u32::MAX, |expires| {
                        super::lease::remaining_seconds(expires, env.now)
                    }),
            );
        }
    }
    output.reply = Reply::Inform {
        lease_time,
        context,
        server: server_id(context.map(|index| &ranges[index]), env, override_id),
    };
    Ok(output)
}

#[cfg(test)]
mod alias_tests {
    use super::*;

    #[test]
    fn failed_narrowing_naks_use_ingress_fallback_for_selecting_and_renewal() {
        let fallback = Ipv4Addr::new(10, 77, 0, 1);
        let context_server = Ipv4Addr::new(10, 78, 0, 1);
        let wanted = Ipv4Addr::new(10, 79, 0, 10);
        let ranges = [AddressRange {
            start: Ipv4Addr::new(10, 78, 0, 10),
            end: Ipv4Addr::new(10, 78, 0, 20),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: context_server,
            local: context_server,
            lease_time: 600,
            kind: RangeKind::Dynamic,
            filter: Vec::new(),
            epoch: 0,
        }];
        for selecting in [false, true] {
            let mut bytes = vec![0; 240];
            bytes[..3].copy_from_slice(&[1, 1, 6]);
            bytes[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
            bytes[236..240].copy_from_slice(&super::super::packet::COOKIE);
            bytes.extend_from_slice(&[53, 1, 3]);
            if selecting {
                bytes.extend_from_slice(&[50, 4, 10, 79, 0, 10, 54, 4, 10, 78, 0, 1]);
            } else {
                bytes[12..16].copy_from_slice(&wanted.octets());
            }
            bytes.push(255);
            let mut store = LeaseStore::new(2);
            let outcome = request(
                &mut store,
                &ranges,
                Request {
                    packet: Packet::parse(&bytes).unwrap(),
                    tags: &[],
                    host: None,
                    reserved: &[],
                    name: None,
                    environment: Environment {
                        now: 100,
                        interface: 1,
                        authoritative: true,
                        unicast_destination: false,
                        ignored: false,
                        ignore_client_id: false,
                        fqdn_only: false,
                        rapid_commit: false,
                        bootp_dynamic: false,
                        consecutive_addresses: false,
                        override_server: None,
                        fallback_server: fallback,
                        server_aliases: &[],
                    },
                },
            )
            .unwrap();
            assert_eq!(
                outcome.reply,
                Reply::Nak {
                    reason: Refusal::WrongNetwork,
                    broadcast: true,
                    server: fallback,
                }
            );
            assert!(store.is_empty());
        }
    }

    #[test]
    fn accepted_alias_echoes_sid_but_does_not_restore_consumed_contexts() {
        let server = Ipv4Addr::new(10, 77, 0, 1);
        let alias = Ipv4Addr::new(10, 77, 0, 254);
        let wanted = Ipv4Addr::new(10, 77, 0, 10);
        let mut bytes = vec![0; 240];
        bytes[..3].copy_from_slice(&[1, 1, 6]);
        bytes[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        bytes[236..240].copy_from_slice(&super::super::packet::COOKIE);
        bytes.extend_from_slice(&[53, 1, 3, 50, 4, 10, 77, 0, 10, 54, 4, 10, 77, 0, 254, 255]);
        let ranges = [AddressRange {
            start: wanted,
            end: Ipv4Addr::new(10, 77, 0, 20),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: server,
            local: server,
            lease_time: 600,
            kind: RangeKind::Dynamic,
            filter: Vec::new(),
            epoch: 0,
        }];
        for authoritative in [false, true] {
            for admitted in [false, true] {
                let aliases = admitted.then_some(alias);
                let mut store = LeaseStore::new(2);
                let outcome = request(
                    &mut store,
                    &ranges,
                    Request {
                        packet: Packet::parse(&bytes).unwrap(),
                        tags: &[],
                        host: None,
                        reserved: &[],
                        name: None,
                        environment: Environment {
                            now: 100,
                            interface: 1,
                            authoritative,
                            unicast_destination: false,
                            ignored: false,
                            ignore_client_id: false,
                            fqdn_only: false,
                            rapid_commit: false,
                            bootp_dynamic: false,
                            consecutive_addresses: false,
                            override_server: None,
                            fallback_server: server,
                            server_aliases: aliases.as_slice(),
                        },
                    },
                )
                .unwrap();
                let expected = if admitted {
                    Reply::Nak {
                        reason: Refusal::WrongNetwork,
                        broadcast: true,
                        server: alias,
                    }
                } else if authoritative {
                    Reply::Nak {
                        reason: Refusal::WrongServer,
                        broadcast: true,
                        server,
                    }
                } else {
                    Reply::Ignore
                };
                assert_eq!(outcome.reply, expected);
                assert!(store.get(wanted).is_none());
            }
        }
    }
}
