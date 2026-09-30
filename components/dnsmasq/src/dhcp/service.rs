//! Bounded DHCPv4 datagram admission and dispatch.
//!
//! This is the socket-independent boundary between `recvmsg(2)`/pktinfo and
//! the state machine.  The C implementation performs the same split in
//! `dhcp.c:130-373`: it bounds the receive buffer, rejects non-requests, then
//! chooses local, relay, BOOTP, PXE, or leasequery handling before calling
//! `dhcp_reply()`.  Interface discovery, relay forwarding, reply serialising,
//! and actual UDP sockets remain caller responsibilities.

use super::packet::{Packet, ParseError, FIXED_LEN, MAX_PACKET_LEN};
use std::net::Ipv4Addr;

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
}
