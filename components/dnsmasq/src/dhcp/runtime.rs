//! DHCPv4 runtime boundary after datagram admission.
//!
//! The C path owns four distinct steps (`dhcp.c:130-530`): bounded admission,
//! dispatch/context selection, reply construction and destination/send cleanup.
//! This module models those steps without hiding unsupported relay/PXE/
//! leasequery routes behind a local send. State selection is caller-configured:
//! tests may provide a callback, while [`StateProvider`] supplies the local
//! DHCP/BOOTP state adapter without opening a socket here.

use super::reply::{build_reply_with_fuzz, needs_renewal_fuzz, ReplyError, ReplyOption};
use super::service::{Dispatch, DispatchKind, Route};
use super::state::{self, Environment, HostPolicy, Name, Outcome, Reply, Request};
use super::{
    allocation::{AddressRange, ProbeResult},
    lease::LeaseStore,
};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const DHCP_CLIENT_PORT: u16 = 68;
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
                // C's `send_from` keeps the receiving interface for renewals
                // and peer unicasts as well as broadcasts.  Supplying
                // `ipi_ifindex` here prevents a multi-interface route lookup
                // from selecting a different source address.
                self.send_on_interface_once(bytes, destination.address, destination.interface)
            }
        }
    }
}

/// Caller-owned state transition. The callback must commit the same lease/name
/// side effects as the state layer before returning its `Outcome`; runtime send
/// failure never rolls those effects back.
pub trait OutcomeProvider {
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError>;

    /// Network defaults from the context actually selected by this outcome.
    /// Explicit selected options take precedence over these defaults.
    fn network_options(&self, _outcome: &Outcome) -> Option<NetworkOptions> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkOptions {
    pub netmask: Ipv4Addr,
    pub broadcast: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    /// The caller only supplies this when DNS is enabled on standard port 53.
    pub dns_server: Option<Ipv4Addr>,
}

impl<F> OutcomeProvider for F
where
    F: for<'a> FnMut(&Dispatch<'a>) -> Result<Outcome, RuntimeError>,
{
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        self(dispatch)
    }
}

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
    pub environment: Environment<'a>,
    pub probe: F,
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
            environment,
            probe,
        }
    }
}

impl<'a, F> OutcomeProvider for StateProvider<'a, F>
where
    F: FnMut(Ipv4Addr, u32) -> ProbeResult,
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
        let hostname = packet.option(12, 1);
        let name = hostname.map(|hostname| Name {
            hostname: hostname.strip_suffix(&[0]).unwrap_or(hostname),
            domain: None,
            // rfc2131.c sets hostname_auth only for configured/hosts names,
            // independently of the server's dhcp-authoritative lease policy.
            authoritative: false,
        });
        let request = || Request {
            packet,
            tags: self.tags,
            host: self.host.as_deref(),
            reserved: self.reserved,
            name,
            environment,
        };
        let outcome = match packet.message_type() {
            0 => state::bootp(self.store, self.ranges, request(), &mut self.probe),
            1 => state::discover(self.store, self.ranges, request(), &mut self.probe),
            3 => state::request(self.store, self.ranges, request()),
            4 => Ok(Outcome {
                reply: Reply::Ignore,
                removed: state::decline(
                    self.store,
                    self.ranges,
                    packet,
                    self.host.as_deref_mut(),
                    environment,
                ),
                lost_names: Vec::new(),
            }),
            7 => Ok(Outcome {
                reply: Reply::Ignore,
                removed: state::release(self.store, self.ranges, packet, self.tags, environment),
                lost_names: Vec::new(),
            }),
            8 => state::inform(self.store, self.ranges, request()),
            // The runtime filters PXE, relay, leasequery and unknown routes
            // before this callback. A known but client-only message type is a
            // no-reply state transition in rfc2131.c.
            _ => Ok(Outcome {
                reply: Reply::Ignore,
                removed: Vec::new(),
                lost_names: Vec::new(),
            }),
        };
        let mut outcome = outcome.map_err(|error| RuntimeError::State(format!("{error:?}")))?;
        let mut lost_names = LeaseStore::names_lost(&expired);
        lost_names.extend(LeaseStore::names_lost(&outcome.removed));
        lost_names.append(&mut outcome.lost_names);
        expired.append(&mut outcome.removed);
        outcome.removed = expired;
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
    Send(io::Error),
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
    mut random: impl FnMut() -> io::Result<u16>,
) -> Result<RuntimeReport, Box<RuntimeFailure>>
where
    P: OutcomeProvider,
    S: DatagramSender,
{
    let mut events = vec![RuntimeEvent::Admitted {
        kind: dispatch.kind,
        route: dispatch.route,
        interface: dispatch.ingress.interface_index,
    }];
    if dispatch.kind != DispatchKind::Dhcp && dispatch.kind != DispatchKind::Bootp
        || dispatch.route != Route::Local
    {
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
    let outcome = match provider.resolve(&dispatch) {
        Ok(outcome) => outcome,
        Err(error) => return Err(failure(error, events, None, false)),
    };
    events.push(RuntimeEvent::StateCommitted {
        removed: outcome.removed.len(),
        lost_names: outcome.lost_names.len(),
    });
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
    let mut combined = Vec::new();
    let options = if let Some(values) = &values {
        combined.reserve(options.len() + 4);
        for (code, value) in [1, 28, 3, 6].into_iter().zip(values) {
            if let Some(value) = value {
                if !options.iter().any(|option| option.code == code)
                    && (matches!(code, 1 | 28) || dispatch.packet.requests(code))
                {
                    combined.push(ReplyOption { code, value });
                }
            }
        }
        combined.extend_from_slice(options);
        combined.as_slice()
    } else {
        options
    };
    let encoding = match build_reply_with_fuzz(
        dispatch.packet,
        outcome.reply,
        options,
        dispatch.packet.option(55, 0).is_some(),
        fuzz,
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
    let mut destination = match destination(&dispatch, peer, &outcome.reply, buffer, encoding.len) {
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
    if dispatch.route != Route::Local
        || (dispatch.kind != DispatchKind::Dhcp && dispatch.kind != DispatchKind::Bootp)
    {
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
                SocketAddr::from((ciaddr, DHCP_CLIENT_PORT))
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
        address: SocketAddr::from((address, DHCP_CLIENT_PORT)),
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
        }
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
        }
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
    fn relay_is_explicitly_unsupported_before_provider() {
        let mut bytes = packet(
            &[53, 1, 1, 255],
            0,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 0, 2, 254),
        );
        let dispatch = dispatch_for(&bytes);
        let called = Cell::new(false);
        let mut provider = |_dispatch: &Dispatch<'_>| {
            called.set(true);
            Ok(offer())
        };
        let mut sender = Sender {
            sent: Vec::new(),
            fail: false,
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
        assert!(!called.get());
        assert!(!failure.committed);
        assert!(matches!(
            failure.error,
            RuntimeError::Unsupported {
                route: Route::Relay { .. },
                ..
            }
        ));
        bytes[24..28].copy_from_slice(&[255, 255, 255, 255]);
        let source_dispatch = dispatch_for(&bytes);
        let failure = process(
            source_dispatch,
            SocketAddr::from(([192, 0, 2, 10], 68)),
            &mut provider,
            &mut sender,
            &[],
            &mut buffer,
        )
        .unwrap_err();
        assert!(matches!(
            failure.error,
            RuntimeError::Unsupported {
                route: Route::RelaySource { .. },
                ..
            }
        ));
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
        let mut provider = StateProvider::new(
            &mut store,
            &mut ranges,
            tags,
            None,
            reserved,
            environment,
            |_, _| ProbeResult::Available { offer_hash: 1 },
        );
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
            |_, _| ProbeResult::InUse,
        );
        let outcome = provider.resolve(&dispatch).unwrap();
        assert_eq!(outcome.reply, Reply::Ignore);
        assert_eq!(outcome.removed.len(), 1);
        assert_eq!(outcome.removed[0].address, expired);
        assert_eq!(outcome.lost_names[0].name, b"old");
        assert!(provider.store.is_empty());
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
