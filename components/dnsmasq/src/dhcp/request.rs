//! DHCPREQUEST's early state decisions, rfc2131.c:1392-1488. The result is
//! deliberately not an ACK: address ownership, static policy, range narrowing
//! and capacity still have to pass the later 1493-1566 checks before commit.

use super::packet::Packet;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestMode {
    Selecting,
    InitReboot,
    RenewOrRebind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NakReason {
    WrongServer,
    WrongAddress,
    LeaseNotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestDecision {
    Ignore,
    CheckAddress {
        mode: RequestMode,
        address: Ipv4Addr,
        prune_old_lease: bool,
        error: Option<NakReason>,
        force_broadcast: bool,
    },
}

/// accepted_server must include the local interface aliases accepted at
/// rfc2131.c:1413-1439; override_server corresponds to relay option 82/11.
pub fn classify_request(
    packet: Packet<'_>,
    existing_lease: Option<Ipv4Addr>,
    authoritative: bool,
    unicast_destination: bool,
    override_server: Option<Ipv4Addr>,
    accepted_server: impl FnOnce(Ipv4Addr) -> bool,
) -> RequestDecision {
    if let Some(address) = packet.requested_address() {
        if let Some(server) = packet.server_identifier() {
            let error = if let Some(expected) = override_server {
                if server != expected {
                    return RequestDecision::Ignore;
                }
                None
            } else if !accepted_server(server) {
                if !authoritative {
                    return RequestDecision::Ignore;
                }
                Some(NakReason::WrongServer)
            } else {
                None
            };
            RequestDecision::CheckAddress {
                mode: RequestMode::Selecting,
                address,
                prune_old_lease: existing_lease.is_some_and(|old| old != address),
                error,
                force_broadcast: false,
            }
        } else {
            if existing_lease.is_none() && !authoritative {
                return RequestDecision::Ignore;
            }
            RequestDecision::CheckAddress {
                mode: RequestMode::InitReboot,
                address,
                prune_old_lease: false,
                error: existing_lease
                    .filter(|&old| old != address)
                    .map(|_| NakReason::WrongAddress),
                force_broadcast: false,
            }
        }
    } else {
        let address = packet.ciaddr();
        let missing = existing_lease.is_some_and(|old| old != address)
            || (existing_lease.is_none() && !authoritative);
        if missing && !unicast_destination {
            return RequestDecision::Ignore;
        }
        RequestDecision::CheckAddress {
            mode: RequestMode::RenewOrRebind,
            address,
            prune_old_lease: false,
            error: missing.then_some(NakReason::LeaseNotFound),
            force_broadcast: missing,
        }
    }
}

/// rfc2131.c:1859-1873; a configured lease shorter than 120 seconds is retained,
/// while client-requested durations are clamped before choosing the minimum.
pub fn lease_duration(range: u32, configured: Option<u32>, requested: Option<u32>) -> u32 {
    let maximum = configured.unwrap_or(range);
    requested.map_or(maximum, |requested| maximum.min(requested.max(120)))
}

/// rfc2131.c:1832-1857, target Linux ARPHRD_EUI64=27/IEEE1394=24.
pub fn extended_hardware_id<'a>(
    hardware_type: u8,
    hardware: &'a [u8],
    client_id: Option<&'a [u8]>,
) -> &'a [u8] {
    if hardware.is_empty() {
        if let Some(client_id) = client_id.filter(|client_id| client_id.len() > 3) {
            if client_id[0] == hardware_type || (client_id[0] == 27 && hardware_type == 24) {
                return &client_id[1..];
            }
            return client_id;
        }
    }
    hardware
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::packet::COOKIE;

    fn bytes(options: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes.extend_from_slice(&[53, 1, 3]);
        bytes.extend_from_slice(options);
        bytes
    }

    #[test]
    fn foreign_selecting_is_ignored_unless_authoritative() {
        let bytes = bytes(&[50, 4, 192, 0, 2, 10, 54, 4, 192, 0, 2, 1]);
        let packet = Packet::parse(&bytes).unwrap();
        assert_eq!(
            classify_request(packet, None, false, false, None, |_| false),
            RequestDecision::Ignore
        );
        assert!(matches!(
            classify_request(packet, None, true, false, None, |_| false),
            RequestDecision::CheckAddress {
                error: Some(NakReason::WrongServer),
                ..
            }
        ));
        assert_eq!(
            classify_request(
                packet,
                None,
                true,
                false,
                Some(Ipv4Addr::new(192, 0, 2, 2)),
                |_| true
            ),
            RequestDecision::Ignore
        );
    }

    #[test]
    fn unknown_rebinding_ignored_but_unicast_renewal_naked() {
        let bytes = bytes(&[]);
        let packet = Packet::parse(&bytes).unwrap();
        assert_eq!(
            classify_request(packet, None, false, false, None, |_| true),
            RequestDecision::Ignore
        );
        assert!(matches!(
            classify_request(packet, None, false, true, None, |_| true),
            RequestDecision::CheckAddress {
                error: Some(NakReason::LeaseNotFound),
                force_broadcast: true,
                ..
            }
        ));
    }

    #[test]
    fn duration_clamps_client_request_not_configuration() {
        assert_eq!(lease_duration(43200, None, Some(0)), 120);
        assert_eq!(lease_duration(60, None, Some(0)), 60);
        assert_eq!(lease_duration(u32::MAX, None, Some(7200)), 7200);
        assert_eq!(lease_duration(7200, None, Some(u32::MAX)), 7200);
        assert_eq!(lease_duration(7200, Some(3600), None), 3600);
    }
}
