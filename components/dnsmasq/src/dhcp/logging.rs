//! DHCP packet notices from rfc2131.c::log_packet (1918-1959).
//! Callers supply values at their actual state transition, before wire/send.
use crate::ubus_service::DhcpLogging;
use std::net::Ipv4Addr;

pub struct PacketLog<'a> {
    pub kind: &'a [u8],
    pub address: Option<Ipv4Addr>,
    /// C print_mac output for the producer's actual extended hardware id.
    pub mac: Option<&'a [u8]>,
    pub interface: Option<&'a [u8]>,
    pub extra: Option<&'a [u8]>,
    /// Some(empty) is an error pointer and remains visible under quiet-dhcp.
    pub error: Option<&'a [u8]>,
    /// Already converted from the request's network-order field.
    pub xid: u32,
}

pub fn packet(settings: DhcpLogging, record: PacketLog<'_>) -> Option<Vec<u8>> {
    let settings = DhcpLogging {
        has_error: record.error.is_some(),
        ..settings
    };
    if settings.suppresses_event() {
        return None;
    }
    let mut message = Vec::new();
    if settings.log_options {
        message.extend_from_slice(format!("{} ", record.xid).as_bytes());
    }
    message.extend_from_slice(record.kind);
    message.push(b'(');
    message.extend_from_slice(record.interface.unwrap_or(b"(null)"));
    message.extend_from_slice(b") ");
    if let Some(address) = record.address {
        message.extend_from_slice(address.to_string().as_bytes());
        message.push(b' ');
    }
    if let Some(mac) = record.mac {
        message.extend_from_slice(mac);
        message.push(b' ');
    }
    if let Some(extra) = record.extra {
        message.extend_from_slice(extra);
    }
    if let Some(error) = record.error {
        message.extend_from_slice(error);
    }
    Some(message)
}

/// DHCP sanitise copies all printable bytes, unlike log_txt's prefix rule.
pub fn sanitise_option(value: Option<&[u8]>) -> Vec<u8> {
    value
        .unwrap_or_default()
        .iter()
        .copied()
        .filter(|byte| (0x20..=0x7e).contains(byte))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings(quiet: bool, detail: bool) -> DhcpLogging {
        DhcpLogging {
            quiet_dhcp: quiet,
            log_options: detail,
            has_error: false,
        }
    }
    #[test]
    fn actual_packet_values_keep_spacing_xid_and_quiet_error_gate() {
        let record = || PacketLog {
            kind: b"DHCPACK",
            address: Some("192.0.2.7".parse().unwrap()),
            mac: Some(b"02:00:00:00:00:07"),
            interface: Some(b"br-test"),
            extra: Some(b"client"),
            error: None,
            xid: 0x01020304,
        };
        assert_eq!(
            packet(settings(false, false), record()).unwrap(),
            b"DHCPACK(br-test) 192.0.2.7 02:00:00:00:00:07 client"
        );
        assert!(packet(settings(true, false), record()).is_none());
        assert_eq!(
            packet(settings(true, true), record()).unwrap(),
            b"16909060 DHCPACK(br-test) 192.0.2.7 02:00:00:00:00:07 client"
        );
        let unknown = PacketLog {
            kind: b"DHCPRELEASE",
            extra: None,
            error: Some(b"unknown lease"),
            ..record()
        };
        assert!(packet(settings(true, false), unknown)
            .unwrap()
            .ends_with(b" unknown lease"));
        let decline = PacketLog {
            kind: b"DHCPDECLINE",
            extra: None,
            error: Some(b""),
            ..record()
        };
        assert!(packet(settings(true, false), decline).is_some());
        assert_eq!(
            sanitise_option(Some(b"client\x01message\0tail")),
            b"clientmessagetail"
        );
    }
}
