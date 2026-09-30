//! DHCPv4 runtime boundary after datagram admission.
//!
//! The C path owns four distinct steps (`dhcp.c:130-530`): bounded admission,
//! dispatch/context selection, reply construction and destination/send cleanup.
//! This module models those steps without hiding unsupported relay/PXE/
//! leasequery routes behind a local send. State selection is caller-configured:
//! tests may provide a callback, while [`StateProvider`] supplies the local
//! DHCP/BOOTP state adapter without opening a socket here.

use super::reply::{build_outcome, ReplyError, ReplyOption};
use super::service::{Dispatch, DispatchKind, Route};
use super::state::{self, Environment, HostPolicy, Name, Outcome, Reply, Request};
use super::{
    allocation::{AddressRange, ProbeResult},
    lease::LeaseStore,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const DHCP_CLIENT_PORT: u16 = 68;
const BROADCAST_FLAG: u16 = 0x8000;

/// A socket-independent sender. Linux's audited `DatagramSocket` implements
/// this trait below; unit tests use a recorder/failure stub instead.
pub trait DatagramSender {
    fn send(&mut self, bytes: &[u8], destination: &Destination) -> io::Result<()>;
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl DatagramSender for crate::net::DatagramSocket {
    fn send(&mut self, bytes: &[u8], destination: &Destination) -> io::Result<()> {
        if destination.arp.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "DHCP unconfigured-client route needs ARP injection",
            ));
        }
        match destination.kind {
            DestinationKind::Broadcast => {
                self.set_broadcast(true)?;
                self.send_on_interface(bytes, destination.address, destination.interface)
            }
            DestinationKind::Client | DestinationKind::Peer => {
                // C's `send_from` keeps the receiving interface for renewals
                // and peer unicasts as well as broadcasts.  Supplying
                // `ipi_ifindex` here prevents a multi-interface route lookup
                // from selecting a different source address.
                self.send_on_interface(bytes, destination.address, destination.interface)
            }
        }
    }
}

/// Caller-owned state transition. The callback must commit the same lease/name
/// side effects as the state layer before returning its `Outcome`; runtime send
/// failure never rolls those effects back.
pub trait OutcomeProvider {
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError>;
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
        let packet = dispatch.packet;
        let hostname = packet.option(12, 1);
        let name = hostname.map(|hostname| Name {
            hostname: hostname.strip_suffix(&[0]).unwrap_or(hostname),
            domain: None,
            authoritative: environment.authoritative,
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
        outcome.map_err(|error| RuntimeError::State(format!("{error:?}")))
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
    Reply(ReplyError),
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

    let encoding = match build_outcome(dispatch.packet, &outcome, options, buffer) {
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
    let destination = match destination(&dispatch, peer, &outcome.reply, buffer, encoding.len) {
        Ok(destination) => destination,
        Err(error) => {
            events.push(RuntimeEvent::Cleanup {
                outcome_dropped: true,
            });
            return Err(failure(error, events, Some(outcome), true));
        }
    };
    events.push(RuntimeEvent::DestinationSelected(destination.clone()));
    if let Err(error) = sender.send(&buffer[..encoding.len], &destination) {
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
        let trust_peer = matches!(reply, Reply::Inform { .. })
            || (peer.ip() == IpAddr::V4(ciaddr) && peer.port() != 0);
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
    } else if !yiaddr.is_unspecified() {
        (yiaddr, DestinationKind::Client)
    } else {
        (Ipv4Addr::BROADCAST, DestinationKind::Broadcast)
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
        assert!(provider.store.changes().dns);
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
