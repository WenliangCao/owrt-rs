//! Bounded DHCPv4 datagram admission and dispatch.
//!
//! This is the socket-independent boundary between `recvmsg(2)`/pktinfo and
//! the state machine.  The C implementation performs the same split in
//! `dhcp.c:130-373`: it bounds the receive buffer, rejects non-requests, then
//! chooses local, relay, BOOTP, PXE, or leasequery handling before calling
//! `dhcp_reply()`.  Interface discovery, relay forwarding, reply serialising,
//! and actual UDP sockets remain caller responsibilities.

use super::packet::{Packet, ParseError, FIXED_LEN, MAX_PACKET_LEN};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// C's DHCP and PXE listeners use separate UDP sockets (dhcp.c:130-133).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    Dhcp,
    Pxe,
}

/// Metadata that a recvmsg/pktinfo adapter must supply before dispatch.
/// `unicast_destination` is the C `IP_PKTINFO`/MSG_BCAST result used when
/// selecting the renewal destination and NAK broadcast policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ingress {
    pub listener: Listener,
    pub interface_index: u32,
    pub unicast_destination: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchKind {
    /// DHCP message type 1..9, handed to the RFC 2131 state machine.
    Dhcp,
    /// BOOTP has no option 53 and uses the 64-byte vendor area on reply.
    Bootp,
    /// RFC 4388 DHCPLEASEQUERY (message type 10).
    LeaseQuery,
    /// A PXE vendor match or the dedicated UDP 4011 listener.
    Pxe,
    /// An option-53 value for which rfc2131.c has no request branch.  The C
    /// default returns no reply, so callers must not pass this to a mutating
    /// state transition.
    Unsupported,
}

/// Route selected from `giaddr`, including dnsmasq's all-ones local-test
/// extension (dhcp.c:251-264).  The original address is retained for audit;
/// the C path clears it before context matching and restores it for sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Local,
    Relay { giaddr: Ipv4Addr },
    RelaySource { original_giaddr: Ipv4Addr },
}

#[derive(Clone, Copy, Debug)]
pub struct Dispatch<'a> {
    pub packet: Packet<'a>,
    pub ingress: Ingress,
    pub kind: DispatchKind,
    pub route: Route,
}

/// A datagram after Linux `recvmsg`/pktinfo admission. The containing runtime
/// owns the socket and may pass `dispatch` to the state machine without
/// losing the source/destination metadata needed by the send path.
#[derive(Clone, Copy, Debug)]
pub struct Received<'a> {
    pub dispatch: Dispatch<'a>,
    pub peer: SocketAddr,
    pub destination: IpAddr,
    /// Local interface address (`ipi_spec_dst`), distinct from a broadcast
    /// or multicast IP-header destination.
    pub local_address: IpAddr,
    pub interface: u32,
}

/// Input states understood by the socket-independent poll adapter.  A socket
/// wrapper maps `recvmsg`'s `EAGAIN` to `WouldBlock` and ancillary/policy
/// drops to `Ignored` without handing either to the DHCP state machine.
#[derive(Clone, Copy, Debug)]
pub enum PollInput<'a> {
    Datagram(&'a [u8]),
    Ignored,
    WouldBlock,
}

/// One non-blocking poll step. `Admitted` is the only variant that may be
/// handed to a state-machine caller; all other variants have no lease or DNS
/// side effects. The generic payload lets the pure adapter return `Dispatch`
/// while the Linux socket wrapper retains peer/pktinfo in `Received`.
#[derive(Clone, Copy, Debug)]
pub enum PollOutcome<T> {
    Admitted(T),
    Malformed(DispatchError),
    Ignored,
    WouldBlock,
    Stopped,
}

/// Classify one bounded datagram without touching a socket or lease provider.
/// This is the deterministic handoff used by platform receive loops and is
/// directly testable on every host target.
pub fn dispatch_poll<'a>(
    input: PollInput<'a>,
    ingress: Ingress,
    pxe_prefixes: &[&[u8]],
    stop: bool,
) -> PollOutcome<Dispatch<'a>> {
    if stop {
        return PollOutcome::Stopped;
    }
    match input {
        PollInput::Datagram(bytes) => match dispatch(bytes, ingress, pxe_prefixes) {
            Ok(dispatch) => PollOutcome::Admitted(dispatch),
            Err(error) => PollOutcome::Malformed(error),
        },
        PollInput::Ignored => PollOutcome::Ignored,
        PollInput::WouldBlock => PollOutcome::WouldBlock,
    }
}

/// Receive one bounded DHCP/PXE datagram through the audited pktinfo socket.
/// `Ok(None)` means the kernel discarded a truncated datagram or reported no
/// usable ancillary destination metadata. A malformed but bounded packet is
/// returned as `Some(Err(...))` so callers can account for the drop.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn receive_once<'a>(
    socket: &crate::net::DatagramSocket,
    buffer: &'a mut [u8],
    listener: Listener,
    pxe_prefixes: &[&[u8]],
) -> io::Result<Option<Result<Received<'a>, DispatchError>>> {
    let Some(datagram) = socket.receive(buffer)? else {
        return Ok(None);
    };
    // dhcp_init() binds the DHCPv4 and PXE descriptors with AF_INET
    // (dhcp.c:40-109).  Do not let a caller accidentally pass an IPv6
    // DatagramSocket here and reinterpret an arbitrary 236-byte payload as
    // BOOTP; DHCPv6 belongs to odhcpd and is not compiled in this variant.
    if !matches!(datagram.destination, IpAddr::V4(_))
        || !matches!(datagram.local_address, IpAddr::V4(_))
    {
        return Ok(None);
    }
    // dhcp.c resolves the pktinfo index with indextoname() before any
    // interface/context matching.  An index of zero is therefore an
    // admission failure, even if the payload itself is a valid BOOTP packet.
    if datagram.interface == 0 {
        return Ok(None);
    }
    let ingress = Ingress {
        listener,
        interface_index: datagram.interface,
        // dhcp.c:196 compares the IP-header destination with INADDR_BROADCAST,
        // not the local interface address supplied alongside it by pktinfo.
        unicast_destination: datagram.destination != IpAddr::V4(Ipv4Addr::BROADCAST),
    };
    let result =
        dispatch(&buffer[..datagram.len], ingress, pxe_prefixes).map(|dispatch| Received {
            dispatch,
            peer: datagram.peer,
            destination: datagram.destination,
            local_address: datagram.local_address,
            interface: datagram.interface,
        });
    Ok(Some(result))
}

/// Stop-aware wrapper for one non-blocking Linux receive step. `DatagramSocket`
/// is created with `SOCK_NONBLOCK`, so checking `stop` before the receive
/// cannot strand a shutdown waiter in a blocking syscall.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn poll_once<'a>(
    socket: &crate::net::DatagramSocket,
    buffer: &'a mut [u8],
    listener: Listener,
    pxe_prefixes: &[&[u8]],
    mut stop: impl FnMut() -> bool,
) -> io::Result<PollOutcome<Received<'a>>> {
    if stop() {
        return Ok(PollOutcome::Stopped);
    }
    match receive_once(socket, buffer, listener, pxe_prefixes) {
        Ok(Some(Ok(received))) => Ok(PollOutcome::Admitted(received)),
        Ok(Some(Err(error))) => Ok(PollOutcome::Malformed(error)),
        Ok(None) => Ok(PollOutcome::Ignored),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(PollOutcome::WouldBlock),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// A UDP datagram larger than the C receive buffer is not admitted.  This
    /// check also prevents a future reply builder from allocating unbounded
    /// memory from attacker-controlled input.
    DatagramTooLarge {
        length: usize,
        maximum: usize,
    },
    Packet(ParseError),
}

/// Decode one received DHCP datagram and hand it to the state-machine caller.
/// No reply is generated and no lease is mutated here.  `pxe_prefixes` are
/// configured `dhcp-vendorclass` prefixes; matching uses the C starts-with
/// rule (`rfc2131.c:is_pxe_client`).
pub fn dispatch<'a>(
    bytes: &'a [u8],
    ingress: Ingress,
    pxe_prefixes: &[&[u8]],
) -> Result<Dispatch<'a>, DispatchError> {
    if bytes.len() > MAX_PACKET_LEN {
        return Err(DispatchError::DatagramTooLarge {
            length: bytes.len(),
            maximum: MAX_PACKET_LEN,
        });
    }
    // Keep the explicit lower bound in this boundary: dhcp.c drops a short
    // recvmsg result before invoking rfc2131.c, even though Packet::parse also
    // reports the same error.
    if bytes.len() < FIXED_LEN {
        return Err(DispatchError::Packet(ParseError::TruncatedHeader));
    }
    let packet = Packet::parse(bytes).map_err(DispatchError::Packet)?;
    let route = match packet.giaddr() {
        address if address == Ipv4Addr::new(255, 255, 255, 255) => Route::RelaySource {
            original_giaddr: address,
        },
        address if !address.is_unspecified() => Route::Relay { giaddr: address },
        _ => Route::Local,
    };
    let kind = if ingress.listener == Listener::Pxe || packet.pxe_vendor(pxe_prefixes).is_some() {
        DispatchKind::Pxe
    } else {
        match packet.message_type() {
            0 => DispatchKind::Bootp,
            1..=9 => DispatchKind::Dhcp,
            10 => DispatchKind::LeaseQuery,
            _ => DispatchKind::Unsupported,
        }
    };
    Ok(Dispatch {
        packet,
        ingress,
        kind,
        route,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::packet::COOKIE;

    fn packet(options: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes.extend_from_slice(options);
        bytes
    }

    fn ingress() -> Ingress {
        Ingress {
            listener: Listener::Dhcp,
            interface_index: 3,
            unicast_destination: false,
        }
    }

    #[test]
    fn dispatch_poll_separates_stop_idle_drop_and_malformed_states() {
        let valid = packet(&[]);
        assert!(matches!(
            dispatch_poll(PollInput::Datagram(&valid), ingress(), &[], true),
            PollOutcome::Stopped
        ));
        assert!(matches!(
            dispatch_poll(PollInput::Ignored, ingress(), &[], false),
            PollOutcome::Ignored
        ));
        assert!(matches!(
            dispatch_poll(PollInput::WouldBlock, ingress(), &[], false),
            PollOutcome::WouldBlock
        ));
        assert!(matches!(
            dispatch_poll(
                PollInput::Datagram(&[0; FIXED_LEN - 1]),
                ingress(),
                &[],
                false
            ),
            PollOutcome::Malformed(DispatchError::Packet(ParseError::TruncatedHeader))
        ));
        assert!(matches!(
            dispatch_poll(PollInput::Datagram(&valid), ingress(), &[], false),
            PollOutcome::Admitted(_)
        ));
    }

    #[test]
    fn short_and_oversized_datagrams_are_rejected_before_state() {
        assert!(matches!(
            dispatch(&[0; FIXED_LEN - 1], ingress(), &[]),
            Err(DispatchError::Packet(ParseError::TruncatedHeader))
        ));
        let bytes = vec![0; MAX_PACKET_LEN + 1];
        match dispatch(&bytes, ingress(), &[]) {
            Err(DispatchError::DatagramTooLarge { length, maximum }) => {
                assert_eq!(length, MAX_PACKET_LEN + 1);
                assert_eq!(maximum, MAX_PACKET_LEN);
            }
            other => panic!("unexpected dispatch result: {other:?}"),
        }
    }

    #[test]
    fn dispatches_bootp_leasequery_and_regular_dhcp() {
        let bootp = packet(&[]);
        assert_eq!(
            dispatch(&bootp, ingress(), &[]).unwrap().kind,
            DispatchKind::Bootp
        );
        let query = packet(&[53, 1, 10]);
        assert_eq!(
            dispatch(&query, ingress(), &[]).unwrap().kind,
            DispatchKind::LeaseQuery
        );
        let discover = packet(&[53, 1, 1]);
        assert_eq!(
            dispatch(&discover, ingress(), &[]).unwrap().kind,
            DispatchKind::Dhcp
        );
        let unknown = packet(&[53, 1, 99]);
        assert_eq!(
            dispatch(&unknown, ingress(), &[]).unwrap().kind,
            DispatchKind::Unsupported
        );
    }

    #[test]
    fn preserves_relay_source_extension_and_normal_giaddr() {
        let mut source = packet(&[53, 1, 3]);
        source[24..28].copy_from_slice(&[255, 255, 255, 255]);
        assert_eq!(
            dispatch(&source, ingress(), &[]).unwrap().route,
            Route::RelaySource {
                original_giaddr: Ipv4Addr::new(255, 255, 255, 255)
            }
        );
        let mut relay = packet(&[53, 1, 3]);
        relay[24..28].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(
            dispatch(&relay, ingress(), &[]).unwrap().route,
            Route::Relay {
                giaddr: Ipv4Addr::new(192, 0, 2, 1)
            }
        );
    }

    #[test]
    fn pxe_listener_and_vendor_prefix_are_explicit_dispatches() {
        let vendor = packet(&[
            53, 1, 1, 60, 9, b'P', b'X', b'E', b'C', b'l', b'i', b'e', b'n', b't',
        ]);
        assert_eq!(
            dispatch(&vendor, ingress(), &[b"PXEClient"]).unwrap().kind,
            DispatchKind::Pxe
        );
        let pxe = Ingress {
            listener: Listener::Pxe,
            ..ingress()
        };
        let ordinary = packet(&[53, 1, 1]);
        assert_eq!(
            dispatch(&ordinary, pxe, &[]).unwrap().kind,
            DispatchKind::Pxe
        );
    }

    #[test]
    fn malformed_request_is_rejected_without_panicking() {
        let mut bytes = packet(&[53, 1, 1]);
        bytes[0] = 2; // BOOTREPLY: dhcp.c/rfc2131.c only accepts BOOTREQUEST.
        assert!(matches!(
            dispatch(&bytes, ingress(), &[]),
            Err(DispatchError::Packet(ParseError::NotRequest))
        ));
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires Linux isolated loopback; run with run_isolated.sh"]
    fn receive_once_admits_loopback_pktinfo_and_preserves_addresses() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let listener = crate::net::DatagramSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let target = listener.local_addr().unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bytes = packet(&[]);
        client.send_to(&bytes, target).unwrap();
        let mut buffer = vec![0; MAX_PACKET_LEN];
        let received = loop {
            match receive_once(&listener, &mut buffer, Listener::Dhcp, &[]) {
                Ok(Some(Ok(received))) => break received,
                Ok(Some(Err(error))) => panic!("unexpected DHCP parse error: {error:?}"),
                Ok(None) => panic!("pktinfo datagram was not admitted"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("receive_once failed: {error}"),
            }
        };
        assert_eq!(received.destination, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(received.local_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            received.interface,
            received.dispatch.ingress.interface_index
        );
        assert_ne!(received.interface, 0);
        assert!(received.dispatch.ingress.unicast_destination);
        assert_eq!(received.dispatch.kind, DispatchKind::Bootp);
        assert_eq!(received.peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(received.dispatch.packet.bytes(), bytes.as_slice());
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires Linux isolated loopback; run with run_isolated.sh"]
    fn receive_once_rejects_ipv6_for_dhcpv4() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let listener = match crate::net::DatagramSocket::bind("[::1]:0".parse().unwrap()) {
            Ok(listener) => listener,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::AddrNotAvailable) => return,
            Err(error) => panic!("IPv6 loopback bind failed: {error}"),
        };
        let target = listener.local_addr().unwrap();
        let client = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let bytes = packet(&[]);
        client.send_to(&bytes, target).unwrap();
        let mut buffer = vec![0; MAX_PACKET_LEN];
        loop {
            match receive_once(&listener, &mut buffer, Listener::Dhcp, &[]) {
                Ok(None) => break,
                Ok(Some(Ok(received))) => {
                    panic!("IPv6 DHCPv4 datagram admitted: {received:?}")
                }
                Ok(Some(Err(error))) => panic!("unexpected DHCP parse error: {error:?}"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("receive_once failed: {error}"),
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires Linux isolated loopback; run with run_isolated.sh"]
    fn poll_once_is_nonblocking_and_stop_aware() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let listener = crate::net::DatagramSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut buffer = vec![0; MAX_PACKET_LEN];
        assert!(matches!(
            poll_once(&listener, &mut buffer, Listener::Dhcp, &[], || true).unwrap(),
            PollOutcome::Stopped
        ));
        assert!(matches!(
            poll_once(&listener, &mut buffer, Listener::Dhcp, &[], || false).unwrap(),
            PollOutcome::WouldBlock
        ));
    }
}
