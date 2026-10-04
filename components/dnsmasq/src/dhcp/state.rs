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
}

/// Values at rfc2131.c's ACK/RELEASE log_packet write sites. This is emitted
/// during the state transaction, before the caller persists/publishes/sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogEvent<'a> {
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

impl Outcome {
    fn ignored() -> Self {
        Self {
            reply: Reply::Ignore,
            removed: Vec::new(),
            lost_names: Vec::new(),
        }
    }
}

fn identity(packet: Packet<'_>, ignore_client_id: bool) -> ClientIdentity {
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
    events: Option<&mut LogSink<'_>>,
) -> Result<Outcome, LeaseError> {
    let mut output = Outcome::ignored();
    let env = request.environment;
    if env.ignored || (offered.is_none() && request.packet.message_type() != 3) {
        return Ok(output);
    }
    let mut client = identity(request.packet, env.ignore_client_id);
    let mut existing = store.find_client(&client).map(|lease| lease.address);
    if client.client_id.is_none() {
        client.client_id =
            existing.and_then(|address| store.get(address).unwrap().identity.client_id.clone());
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
        output.removed = store.prune(existing, env.now);
        existing = None;
    }
    // rfc2131.c:1490, after REQUEST-mode early returns. Rapid commit jumps
    // over this statement after DISCOVER and never counts REQUEST or OFFER.
    if offered.is_none() {
        counters.request = counters.request.wrapping_add(1);
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
                            .is_none_or(|lease| Some(lease.address) == existing)
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
                        existing = Some(address);
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
    if error.is_none() && existing.is_none() {
        let mut allocation_identity = client.clone();
        if request.host.is_some_and(|host| host.ignore_client_id) {
            allocation_identity.client_id = None;
        }
        match store.allocate(address, allocation_identity) {
            Ok(()) => {}
            Err(LeaseError::Full) => error = Some(Refusal::NoLeasesLeft),
            Err(error) => return Err(error),
        }
    }
    if let Some(reason) = error {
        // Failed rapid commit sends no NAK (rfc2131.c:1567-1576).
        if offered.is_some() {
            counters.no_answer = counters.no_answer.wrapping_add(1); // :1565
            return Ok(output);
        }
        counters.nak = counters.nak.wrapping_add(1); // :1565
        let chosen = context
            .map(|index| &ranges[index])
            .or_else(|| selected_ranges.first());
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
            server: server_id(chosen, env, env.override_server),
        };
        return Ok(output);
    }
    let index = context.expect("address validation selected a context");
    let duration = lease_duration(
        ranges[index].lease_time,
        request.host.and_then(|host| host.lease_time),
        request.packet.requested_lease_time(),
    );
    if request.host.is_some_and(|host| host.ignore_client_id) {
        client.client_id = None;
    }
    store.set_identity(address, &client)?;
    if let Some(name) = request.name {
        output.lost_names = store.set_hostname(
            address,
            Some(name.hostname),
            name.authoritative,
            name.domains
                .and_then(|domains| domains.for_address(address)),
            env.fqdn_only,
        )?;
    }
    store.set_expires(address, duration, env.now)?;
    store.set_interface(address, env.interface)?;
    let override_id = store.server_override(address, env.override_server)?;
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
    )
}

pub(crate) fn discover_counted(
    store: &mut LeaseStore,
    ranges: &mut [AddressRange],
    request: Request<'_>,
    mut probe: impl FnMut(Ipv4Addr, u32, LeaseCounters) -> ProbeResult,
    quiet: bool,
    counters: &mut MessageCounters,
    events: Option<&mut LogSink<'_>>,
) -> Result<Outcome, LeaseError> {
    let env = request.environment;
    if request.packet.message_type() != 1 {
        return Ok(Outcome::ignored());
    }
    if env.ignored {
        // :1289-1293: quiet-dhcp suppresses this one counter as well as log.
        if !quiet {
            counters.discover = counters.discover.wrapping_add(1);
        }
        return Ok(Outcome::ignored());
    }
    let mut client = identity(request.packet, env.ignore_client_id);
    let existing = store.find_client(&client).map(|lease| lease.address);
    if client.client_id.is_none() {
        client.client_id =
            existing.and_then(|address| store.get(address).unwrap().identity.client_id.clone());
    }
    let static_address = request.host.and_then(|host| {
        host.address.filter(|address| {
            store.get(*address).is_none_or(|occupant| {
                Some(occupant.address) == existing || host.has_hardware(&occupant.identity)
            }) && ranges.first().is_none_or(|range| range.router != *address)
                && host
                    .declined_at
                    .is_none_or(|time| env.now.saturating_sub(time) >= DECLINE_BACKOFF)
        })
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
                ProbeResult::Failed => return Ok(discover_failed(counters)),
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
            return Ok(discover_failed(counters));
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
            return Ok(discover_failed(counters));
        };
        address
    };
    counters.discover = counters.discover.wrapping_add(1); // :1349
    let Some(context) = narrow(ranges, address, request.tags) else {
        return Ok(Outcome::ignored());
    };
    if env.rapid_commit && request.packet.option(80, 0).is_some() {
        return transaction(store, ranges, request, Some(address), counters, events);
    }
    counters.offer = counters.offer.wrapping_add(1); // :1377
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
    })
}

fn discover_failed(counters: &mut MessageCounters) -> Outcome {
    // Address selection/identity errors still reach C's DISCOVER write site.
    counters.discover = counters.discover.wrapping_add(1);
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
    mut probe: impl FnMut(Ipv4Addr, u32, LeaseCounters) -> ProbeResult,
    counters: &mut MessageCounters,
    permitted_contexts: &[bool],
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
        return Ok(bootp_finished(output, counters));
    }
    let client = identity(packet, true);
    let mut existing = store.find_client(&client).map(|lease| lease.address);
    let static_address = request.host.and_then(|host| host.address);
    let address = if let Some(address) = static_address {
        existing = store.get(address).map(|lease| lease.address);
        if store.get(address).is_some_and(|lease| {
            lease.identity.hardware_type != client.hardware_type
                || lease.identity.hardware_address != client.hardware_address
        }) {
            return Ok(bootp_finished(output, counters));
        }
        address
    } else {
        if existing.is_some_and(|address| available(ranges, address, request.tags).is_none()) {
            output.removed = store.prune(existing, env.now);
            existing = None;
        }
        if let Some(address) = existing {
            address
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
                return Ok(bootp_finished(output, counters));
            };
            address
        }
    };
    let Some(context) = narrow(ranges, address, request.tags) else {
        return Ok(bootp_finished(output, counters));
    };
    if static_address.is_none()
        && !env.bootp_dynamic
        && !permitted_contexts.get(context).copied().unwrap_or(false)
    {
        return Ok(bootp_finished(output, counters));
    }
    if existing.is_none() {
        match store.allocate(address, client.clone()) {
            Ok(()) => {}
            Err(LeaseError::Full) => return Ok(bootp_finished(output, counters)),
            Err(error) => return Err(error),
        }
    }
    store.set_identity(address, &client)?;
    if let Some(name) = request.name {
        output.lost_names = store.set_hostname(
            address,
            Some(name.hostname),
            true,
            name.domains
                .and_then(|domains| domains.for_address(address)),
            env.fqdn_only,
        )?;
    }
    store.set_expires(
        address,
        request
            .host
            .and_then(|host| host.lease_time)
            .unwrap_or(u32::MAX),
        env.now,
    )?;
    store.set_interface(address, env.interface)?;
    output.reply = Reply::Bootp { address, context };
    Ok(bootp_finished(output, counters))
}

fn bootp_finished(outcome: Outcome, counters: &mut MessageCounters) -> Outcome {
    // :694: counted for both success and the post-admission failure paths.
    counters.bootp = counters.bootp.wrapping_add(1);
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
    mut host: Option<&mut HostPolicy>,
    environment: Environment<'_>,
    counters: &mut MessageCounters,
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
    let existing = store
        .find_client(&identity(packet, environment.ignore_client_id))
        .map(|lease| lease.address);
    let removed = if existing == Some(address) {
        store.prune(existing, environment.now)
    } else {
        Vec::new()
    };
    if let Some(host) = host.as_mut().filter(|host| host.address == Some(address)) {
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
        .map(|lease| lease.address);
    let removed = if existing == Some(packet.effective_ciaddr()) {
        store.prune(existing, environment.now)
    } else {
        Vec::new()
    };
    counters.release = counters.release.wrapping_add(1); // :1282, including unknown lease
    if let Some(events) = events {
        events(LogEvent::Release {
            address: packet.effective_ciaddr(),
            unknown_lease: existing != Some(packet.effective_ciaddr()),
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
    events: Option<&mut LogSink<'_>>,
) -> Result<Outcome, LeaseError> {
    let mut output = Outcome::ignored();
    let env = request.environment;
    let address = request.packet.effective_ciaddr();
    if request.packet.message_type() != 8 {
        return Ok(output);
    }
    counters.inform = counters.inform.wrapping_add(1); // :1757, before ignore/zero-ciaddr
    if env.ignored || address.is_unspecified() {
        return Ok(output);
    }
    let context = narrow(ranges, address, request.tags);
    let client_existing = store
        .find_client(&identity(request.packet, env.ignore_client_id))
        .map(|lease| lease.address);
    let existing = client_existing.or_else(|| store.get(address).map(|lease| lease.address));
    let mut override_id = env.override_server;
    let mut lease_time = None;
    counters.ack = counters.ack.wrapping_add(1); // :1784, before lease interface update
    if let Some(events) = events {
        let name = client_existing
            .is_none()
            .then(|| existing.and_then(|existing| store.get(existing)?.hostname.as_deref()))
            .flatten()
            .or_else(|| request.name.map(|name| name.hostname));
        events(LogEvent::Ack { address, name });
    }
    if let Some(existing) = existing {
        store.set_interface(existing, env.interface)?;
        override_id = store.server_override(existing, override_id)?;
        if request.packet.requests(51) {
            lease_time = Some(
                store
                    .get(existing)
                    .unwrap()
                    .expires
                    .map_or(u32::MAX, |expires| expires.saturating_sub(env.now) as u32),
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
