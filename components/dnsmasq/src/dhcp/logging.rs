//! DHCP packet notices from rfc2131.c::log_packet (1918-1959).
//! Callers supply values at their actual state transition, before wire/send.
use crate::ubus_service::DhcpLogging;
use std::io::Write;
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
    let mut message = Vec::with_capacity(128);
    // Vec writes are infallible; format directly into the message buffer.
    if settings.log_options {
        let _ = write!(message, "{} ", record.xid);
    }
    message.extend_from_slice(record.kind);
    message.push(b'(');
    message.extend_from_slice(record.interface.unwrap_or(b"(null)"));
    message.extend_from_slice(b") ");
    if let Some(address) = record.address {
        let _ = write!(message, "{address} ");
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

/// The actual extended hardware identity selected by the packet caller.
pub fn hardware(hardware_type: u8, hardware: &[u8], client_id: Option<&[u8]>) -> Vec<u8> {
    let mac = super::request::extended_hardware_id(hardware_type, hardware, client_id);
    if mac.is_empty() {
        return b"<null>".to_vec();
    }
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
        .into_bytes()
}

/// Pre-outcome notices shared by ordinary DHCP, direct PXE and leasequery.
/// BOOTP returns before hostname parsing in C; counted FQDN labels become
/// their printable name while plain hostname spelling is retained verbatim.
pub fn request_details(packet: super::packet::Packet<'_>) -> Vec<Vec<u8>> {
    let xid = packet.transaction_id();
    let mut notices = Vec::new();
    for (code, label) in [
        (60, b"vendor class: ".as_slice()),
        (77, b"user class: ".as_slice()),
    ] {
        if let Some(value) = packet.option(code, 1) {
            let value = if code == 77 {
                user_class(value)
            } else {
                sanitise_option(Some(value))
            };
            notices.push(detail(xid, label, &value));
        }
    }
    if packet.client_hostname_full().is_some() {
        let value = if let Some(fqdn) = packet.option(81, 3) {
            if fqdn[0] & 4 == 0 {
                fqdn[3..].to_vec()
            } else {
                let mut value = Vec::new();
                let mut rest = &fqdn[3..];
                while let Some(&length) = rest.first() {
                    if length == 0 || usize::from(length) >= rest.len() {
                        break;
                    }
                    if !value.is_empty() {
                        value.push(b'.');
                    }
                    value.extend_from_slice(&rest[1..=usize::from(length)]);
                    rest = &rest[usize::from(length) + 1..];
                }
                value
            }
        } else {
            packet.option(12, 1).unwrap_or_default().to_vec()
        };
        let value = value.split(|byte| *byte == 0).next().unwrap_or_default();
        notices.push(detail(xid, b"client provides name: ", value));
    }
    notices
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum OptionLogKind {
    Address,
    Name,
    Time,
    Decimal,
    Raw,
}

/// The names come from the shared exact-image option table. Only OT_DEC
/// entries use decimal; scalar size hints alone remain hexadecimal in C.
pub fn option_name(code: u8) -> &'static [u8] {
    crate::config::dhcp::DhcpOption::log_descriptor(code).map_or(b"", |(name, _)| name)
}

pub fn option_value(code: u8, data: &[u8]) -> Vec<u8> {
    let kind = crate::config::dhcp::DhcpOption::log_descriptor(code).map(|(_, kind)| kind);
    match kind {
        Some(OptionLogKind::Address) => data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|bytes| Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .into_bytes(),
        Some(OptionLogKind::Name) => sanitise_option(Some(data)),
        Some(OptionLogKind::Time | OptionLogKind::Decimal) if !data.is_empty() => {
            let value = data
                .iter()
                .fold(0u32, |value, byte| value.wrapping_shl(8) | u32::from(*byte));
            if kind == Some(OptionLogKind::Time) {
                duration(value)
            } else {
                value.to_string().into_bytes()
            }
        }
        _ => {
            let mut value = data
                .iter()
                .take(14)
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
                .into_bytes();
            if data.len() > 14 {
                value.extend_from_slice(b"...");
            }
            value
        }
    }
}

pub fn duration(seconds: u32) -> Vec<u8> {
    if seconds == u32::MAX {
        return b"infinite".to_vec();
    }
    let mut text = String::new();
    for (value, suffix) in [
        (seconds / 86400, 'd'),
        (seconds / 3600 % 24, 'h'),
        (seconds / 60 % 60, 'm'),
        (seconds % 60, 's'),
    ] {
        if value != 0 {
            text.push_str(&format!("{value}{suffix}"));
        }
    }
    text.into_bytes()
}

pub fn user_class(value: &[u8]) -> Vec<u8> {
    let mut at = 0;
    while at < value.len() {
        at += usize::from(value[at]) + 1;
    }
    if at != value.len() {
        return sanitise_option(Some(value));
    }
    let mut normalized = value.to_vec();
    let mut at = 0;
    while at < value.len() {
        normalized[at] = 0;
        at += usize::from(value[at]) + 1;
    }
    sanitise_option(Some(&normalized))
}

pub fn detail(xid: u32, label: &[u8], value: &[u8]) -> Vec<u8> {
    let mut message = format!("{xid} ").into_bytes();
    message.extend_from_slice(label);
    message.extend_from_slice(value);
    message
}

pub fn tags(xid: u32, values: &[&[u8]]) -> Option<Vec<u8>> {
    if values.is_empty() {
        return None;
    }
    let mut value = Vec::new();
    for (index, tag) in values.iter().enumerate() {
        if values[index + 1..].contains(tag) {
            continue;
        }
        value.extend_from_slice(tag);
        if index + 1 != values.len() {
            value.extend_from_slice(b", ");
        }
    }
    value.truncate(503);
    Some(detail(xid, b"tags: ", &value))
}

pub fn requested_options(xid: u32, codes: &[u8]) -> Vec<Vec<u8>> {
    let mut events = Vec::new();
    let mut value = Vec::new();
    for (index, code) in codes.iter().enumerate() {
        value.extend_from_slice(code.to_string().as_bytes());
        let name = option_name(*code);
        if !name.is_empty() {
            value.push(b':');
            value.extend_from_slice(name);
        }
        if index + 1 != codes.len() {
            value.extend_from_slice(b", ");
        }
        if index + 1 == codes.len() || value.len() > 40 {
            events.push(detail(xid, b"requested options: ", &value));
            value.clear();
        }
    }
    events
}

/// dhcp_packet_size visits overloaded file/sname before primary options.
/// The serializer has already supplied its actual final fields and flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionWarning {
    Duplicate(u8),
    EnterpriseTooLarge(u32),
}

pub fn option_warning(warning: OptionWarning) -> Vec<u8> {
    match warning {
        OptionWarning::Duplicate(code) => {
            format!("Ignoring duplicate dhcp-option {code}").into_bytes()
        }
        OptionWarning::EnterpriseTooLarge(number) => format!(
            "cannot send RFC3925 option: too many options for enterprise number {}",
            number as i32
        )
        .into_bytes(),
    }
}

pub fn omission(code: u8) -> Vec<u8> {
    format!("cannot send DHCP/BOOTP option {code}: no space left in packet").into_bytes()
}

pub fn reply_details(packet: &[u8]) -> Vec<Vec<u8>> {
    if packet.len() < 240 {
        return Vec::new();
    }
    let xid = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    let overload =
        crate::dhcp::packet::find_option(&packet[240..], 52, 1).map_or(0, |option| option.value[0]);
    let mut events = Vec::new();
    fn options(xid: u32, region: &[u8], events: &mut Vec<Vec<u8>>) {
        let mut at = 0;
        while at < region.len() {
            let code = region[at];
            at += 1;
            if code == 255 {
                return;
            }
            if code == 0 {
                continue;
            }
            let Some(&length) = region.get(at) else {
                return;
            };
            at += 1;
            let Some(data) = region.get(at..at + usize::from(length)) else {
                return;
            };
            at += usize::from(length);
            let mut message = format!("{xid} sent size:{length:3} option:{code:3} ").into_bytes();
            message.extend_from_slice(option_name(code));
            message.extend_from_slice(b"  ");
            message.extend_from_slice(&option_value(code, data));
            events.push(message);
        }
    }
    for (bit, range, label) in [
        (1, 108..236, b"bootfile name: ".as_slice()),
        (2, 44..108, b"server name: ".as_slice()),
    ] {
        let region = &packet[range];
        if overload & bit != 0 {
            options(xid, region, &mut events);
        } else {
            let end = region
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(region.len());
            if end != 0 {
                events.push(detail(xid, label, &region[..end]));
            }
        }
    }
    let server = Ipv4Addr::new(packet[20], packet[21], packet[22], packet[23]);
    if !server.is_unspecified() {
        events.push(detail(xid, b"next server: ", server.to_string().as_bytes()));
    }
    if packet[10] & 0x80 != 0 && packet[12..16] == [0; 4] {
        events.push(detail(xid, b"broadcast response", b""));
    }
    options(xid, &packet[240..], &mut events);
    events
}
