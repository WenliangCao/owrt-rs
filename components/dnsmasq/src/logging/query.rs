//! Query events from cache.c:2312-2515. Producers supply their actual origin;
//! this formatter never infers provenance from the final DNS packet.
#[cfg(target_os = "linux")]
use crate::config::logging::QueryLogging;
#[cfg(target_os = "linux")]
use crate::logging::{address_text, LogEvent, Priority, Service};
use std::net::{IpAddr, SocketAddr};

pub const REVERSE: u32 = 1 << 2;
pub const DHCP: u32 = 1 << 4;
pub const NEGATIVE: u32 = 1 << 5;
pub const HOSTS: u32 = 1 << 6;
pub const IPV4: u32 = 1 << 7;
pub const IPV6: u32 = 1 << 8;
pub const NXDOMAIN: u32 = 1 << 10;
pub const CNAME: u32 = 1 << 11;
pub const CONFIG: u32 = 1 << 13;
pub const REPLY: u32 = 1 << 16;
pub const RRNAME: u32 = 1 << 17;
pub const SERVER: u32 = 1 << 18;
pub const QUERY: u32 = 1 << 19;
pub const AUTHORITATIVE: u32 = 1 << 20;
pub const AUTH: u32 = 1 << 21;
pub const NO_EXTRA: u32 = 1 << 27;
pub const RCODE: u32 = 1 << 29;
pub const RR: u32 = 1 << 30;
pub const STALE: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueryContext {
    /// C uses a negative display id for TCP and a positive id for UDP.
    pub display_id: i32,
    pub client: Option<SocketAddr>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct QueryIds(i32);
impl QueryIds {
    pub fn next(&mut self, tcp: bool, client: Option<SocketAddr>) -> QueryContext {
        self.0 = self.0.wrapping_add(1);
        QueryContext {
            display_id: if tcp { self.0.wrapping_neg() } else { self.0 },
            client,
        }
    }
    /// Normal TCP inherits the current sequence while its parent reserves100.
    /// Debug TCP uses the parent's next() directly and does not reserve ids.
    pub fn accept_tcp(&mut self) -> Self {
        let accepted = *self;
        self.0 = self.0.wrapping_add(100);
        accepted
    }
}

#[cfg(test)]
mod id_wrap_tests {
    use super::*;
    #[test]
    fn signed_display_and_parent_reservation_wrap_explicitly() {
        let mut ids = QueryIds(i32::MAX);
        assert_eq!(ids.next(false, None).display_id, i32::MIN);
        assert_eq!(ids.next(true, None).display_id, i32::MAX);
        let mut parent = QueryIds(i32::MAX - 49);
        let child = parent.accept_tcp();
        assert_eq!(child.0, i32::MAX - 49);
        assert_eq!(parent.0, i32::MIN + 50);
    }
}

#[derive(Clone, Debug)]
pub enum QueryData {
    /// Plain producer diagnostic, independent of query filters and prefixes.
    Warning(Vec<u8>),
    None,
    Address(IpAddr),
    Rcode {
        value: u16,
        ede: Option<i32>,
    },
    RrType(u16),
}

#[derive(Clone, Debug)]
pub struct QueryEvent {
    pub flags: u32,
    /// The producer's dnsmasq byte name, including its escape markers.
    pub name: Option<Vec<u8>>,
    pub data: QueryData,
    pub argument: Option<Vec<u8>>,
    /// Query RR type, non-query opcode, or upstream port, per producer.
    pub kind: u16,
}

impl QueryEvent {
    pub fn warning(message: Vec<u8>) -> Self {
        Self {
            flags: 0,
            name: None,
            data: QueryData::Warning(message),
            argument: None,
            kind: 0,
        }
    }
    /// receive_query/tcp_request's admitted request, before local/forward work.
    pub fn request(packet: &[u8], client: SocketAddr, auth: bool) -> Option<Self> {
        let header = crate::dns::wire::Header::parse(packet).ok()?;
        if header.flags & 0x8000 != 0 {
            return None;
        }
        if header.opcode() != 0 {
            let mut event = Self::address(QUERY | CONFIG | if auth { AUTHORITATIVE } else { 0 },
                                          b"", client.ip(), None);
            event.name = None;
            event.kind = u16::from(header.opcode());
            return Some(event);
        }
        if header.answers != 0 || header.authorities != 0 {
            return None;
        }
        let question = crate::dns::forward::Question::parse(packet).ok()?;
        let mut event = Self::address(QUERY | if auth { AUTH | AUTHORITATIVE } else { 0 },
                                      &question.name.dnsmasq_bytes(), client.ip(), None);
        event.kind = question.rrtype;
        Some(event)
    }

    pub fn label(flags: u32, name: &[u8], argument: Option<&[u8]>, kind: u16) -> Self {
        Self {
            flags,
            name: Some(name.to_vec()),
            data: QueryData::None,
            argument: argument.map(<[u8]>::to_vec),
            kind,
        }
    }

    pub fn address(flags: u32, name: &[u8], address: IpAddr, argument: Option<&[u8]>) -> Self {
        Self {
            flags: flags | if address.is_ipv4() { IPV4 } else { IPV6 },
            name: Some(name.to_vec()),
            data: QueryData::Address(address),
            argument: argument.map(<[u8]>::to_vec),
            kind: 0,
        }
    }

    pub fn error(flags: u32, name: &[u8], value: u16, ede: Option<i32>) -> Self {
        Self {
            flags: flags | RCODE,
            name: Some(name.to_vec()),
            data: QueryData::Rcode { value, ede },
            argument: None,
            kind: 0,
        }
    }
}

/// rfc1035.c::log_txt emits each counted string through its printable prefix.
/// The caller supplies the selected upstream/cache RDATA without modifying it.
pub(crate) fn txt_events(flags: u32, name: &[u8], data: &[u8], events: &mut Vec<QueryEvent>) {
    let mut position = 0;
    while position < data.len() {
        let length = usize::from(data[position]);
        let Some(text) = data.get(position + 1..position + 1 + length) else {
            return;
        };
        let printable = text
            .iter()
            .position(|byte| !(0x20..=0x7e).contains(byte))
            .unwrap_or(text.len());
        events.push(QueryEvent::label(flags, name, Some(&text[..printable]), 0));
        position += length + 1;
    }
}

/// Producer-owned finite notices. Disabled logging adds no record allocation.
pub(crate) struct QueryEvents {
    pub enabled: bool,
    pub events: Vec<QueryEvent>,
}

impl QueryEvents {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            events: Vec::new(),
        }
    }

    pub fn label(&mut self, flags: u32, name: &[u8], argument: Option<&[u8]>, kind: u16) {
        if self.enabled {
            self.events
                .push(QueryEvent::label(flags, name, argument, kind));
        }
    }

    pub fn address(&mut self, flags: u32, name: &[u8], address: IpAddr, argument: Option<&[u8]>) {
        if self.enabled {
            self.events
                .push(QueryEvent::address(flags, name, address, argument));
        }
    }

    pub fn record(&mut self, flags: u32, name: &[u8], kind: u16, data: &[u8]) {
        if !self.enabled {
            return;
        }
        let address = match kind {
            1 => <[u8; 4]>::try_from(data)
                .ok()
                .map(|value| IpAddr::V4(value.into())),
            28 => <[u8; 16]>::try_from(data)
                .ok()
                .map(|value| IpAddr::V6(value.into())),
            _ => None,
        };
        if let Some(address) = address {
            self.address(flags, name, address, None);
        } else if kind == 5 {
            self.label(flags | CNAME, name, None, 0);
        } else {
            self.label(flags | RRNAME, name, None, kind);
        }
    }
}

pub fn type_text(description: Option<&[u8]>, kind: u16) -> Vec<u8> {
    let label = crate::config::rrtypes::name(kind)
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| format!("type={kind}").into_bytes());
    match description {
        Some(description) => {
            let mut value = description.to_vec();
            value.push(b'[');
            value.extend_from_slice(&label);
            value.push(b']');
            value
        }
        None => {
            let mut value = vec![b'<'];
            value.extend_from_slice(&label);
            value.push(b'>');
            value
        }
    }
}

#[cfg(target_os = "linux")]
pub fn format(config: QueryLogging, context: QueryContext, event: &QueryEvent) -> Option<LogEvent> {
    if let QueryData::Warning(message) = &event.data {
        return Some(LogEvent::new(
            Service::Dns,
            Priority::Warning,
            message.clone(),
        ));
    }
    let flags = event.flags;
    if !config.enabled
        || config.only_failed && flags & (RCODE | NEGATIVE) == 0
        || config.authoritative_only && flags & AUTHORITATIVE == 0
    {
        return None;
    }
    let mut argument = event.argument.clone();
    if flags & (SERVER | QUERY | RR) == 0 && event.kind > 0 {
        argument = Some(type_text(argument.as_deref(), event.kind));
    }
    let mut name = event.name.as_ref().map(|name| sanitise(name));
    let mut destination = argument.clone().unwrap_or_else(|| b"(null)".to_vec());
    let mut address = Vec::new();
    let mut extra = Vec::new();
    match &event.data {
        QueryData::Warning(_) => (),
        QueryData::None => (),
        QueryData::Address(value) => {
            address = address_text(SocketAddr::new(*value, 0));
            destination = address.clone();
            if flags & SERVER != 0 && event.kind != 53 {
                extra = format!("#{}", event.kind).into_bytes();
            }
        }
        QueryData::Rcode { value, ede } => {
            destination = match *value {
                1 => b"FORMERR".to_vec(),
                2 => b"SERVFAIL".to_vec(),
                4 => b"not implemented".to_vec(),
                5 => b"REFUSED".to_vec(),
                _ => value.to_string().into_bytes(),
            };
            if let Some(ede) = ede {
                extra = format!(" (EDE: {})", ede_text(*ede)).into_bytes();
            }
        }
        QueryData::RrType(kind) => destination = type_text(None, *kind),
    }
    if flags & REVERSE != 0 {
        destination = name.clone().unwrap_or_else(|| b"(null)".to_vec());
        name = Some(address);
    }
    if flags & NEGATIVE != 0 {
        destination = if flags & NXDOMAIN != 0 {
            b"NXDOMAIN".to_vec()
        } else if flags & IPV4 != 0 {
            b"NODATA-IPv4".to_vec()
        } else if flags & IPV6 != 0 {
            b"NODATA-IPv6".to_vec()
        } else {
            b"NODATA".to_vec()
        };
    } else if flags & CNAME != 0 {
        destination = b"<CNAME>".to_vec();
    } else if flags & RRNAME != 0 {
        destination = argument.clone().unwrap_or_else(|| b"(null)".to_vec());
    }
    let mut source = if flags & CONFIG != 0 {
        b"config".to_vec()
    } else if flags & DHCP != 0 {
        b"DHCP".to_vec()
    } else if flags & HOSTS != 0 {
        event.argument.clone().unwrap_or_else(|| b"(null)".to_vec())
    } else if flags & REPLY != 0 {
        b"reply".to_vec()
    } else if flags & AUTH != 0 {
        b"auth".to_vec()
    } else if flags & QUERY != 0 {
        b"query".to_vec()
    } else if flags & SERVER != 0 {
        b"forwarded".to_vec()
    } else if flags & STALE != 0 {
        b"cached-stale".to_vec()
    } else {
        b"cached".to_vec()
    };
    let mut verb =
        if flags & SERVER != 0 && flags & (CONFIG | DHCP | HOSTS | REPLY | AUTH | QUERY) == 0 {
            b"to".as_slice()
        } else {
            b"is".as_slice()
        };
    if flags & QUERY != 0 {
        if flags & CONFIG != 0 {
            source = b"non-query opcode".to_vec();
            name = Some((event.kind & 15).to_string().into_bytes());
        } else if event.kind > 0 {
            source = type_text(Some(&source), event.kind);
        }
        verb = b"from";
    }
    let gap = name.is_some();
    let name = name
        .map(|name| if name.is_empty() { b".".to_vec() } else { name })
        .unwrap_or_default();
    let mut message = Vec::new();
    if config.extra {
        if config.protocol {
            message.extend_from_slice(if context.display_id < 0 {
                b"TCP "
            } else {
                b"UDP "
            });
        }
        message.extend_from_slice(context.display_id.unsigned_abs().to_string().as_bytes());
        message.push(b' ');
        if flags & NO_EXTRA == 0 {
            if let Some(client) = context.client {
                message.extend_from_slice(&address_text(client));
                message.push(b'/');
                message.extend_from_slice(client.port().to_string().as_bytes());
                message.push(b' ');
            }
        }
    }
    message.extend_from_slice(&source);
    message.push(b' ');
    message.extend_from_slice(&name);
    if gap {
        message.push(b' ');
    }
    message.extend_from_slice(verb);
    message.push(b' ');
    message.extend_from_slice(&destination);
    message.extend_from_slice(&extra);
    Some(LogEvent::new(Service::Dns, Priority::Info, message))
}

#[cfg(target_os = "linux")]
fn sanitise(name: &[u8]) -> Vec<u8> {
    let name = &name[..name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len())];
    if name.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
        b"<name unprintable>".to_vec()
    } else {
        name.to_ascii_lowercase()
    }
}

#[cfg(target_os = "linux")]
fn ede_text(value: i32) -> &'static str {
    match value {
        0 => "other",
        1 => "unsupported DNSKEY algorithm",
        2 => "unsupported DS digest",
        3 => "stale answer",
        4 => "forged",
        5 => "DNSSEC indeterminate",
        6 => "DNSSEC bogus",
        7 => "DNSSEC signature expired",
        8 => "DNSSEC sig not yet valid",
        9 => "DNSKEY missing",
        10 => "RRSIG missing",
        11 => "no zone key bit set",
        12 => "NSEC(3) missing",
        13 => "cached error",
        14 => "not ready",
        15 => "blocked",
        16 => "censored",
        17 => "filtered",
        18 => "prohibited",
        19 => "stale NXDOMAIN",
        20 => "not authoritative",
        21 => "not supported",
        22 => "no reachable authority",
        23 => "network error",
        24 => "invalid data",
        25 => "signature expired before valid",
        26 => "too early",
        27 => "unsupported NSEC3 iterations value",
        28 => "uanble to conform to policy",
        29 => "synthesized",
        -2 => "upstream returned SERVFAIL",
        _ => "unknown",
    }
}

#[cfg(test)]
mod txt_producer_tests {
    use super::*;

    #[test]
    fn selected_txt_strings_keep_case_empty_fields_and_input_bytes() {
        let data = b"\x05hello\x06Second\x00";
        let before = data.to_vec();
        let mut events = Vec::new();
        txt_events(REPLY, b"txt.test", data, &mut events);
        assert_eq!(
            events
                .iter()
                .map(|event| event.argument.as_deref().unwrap())
                .collect::<Vec<_>>(),
            [b"hello".as_slice(), b"Second".as_slice(), b"".as_slice()]
        );
        assert!(events
            .iter()
            .all(|event| event.flags == REPLY && event.kind == 0));
        assert_eq!(data.as_slice(), before);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn enabled() -> QueryLogging {
        QueryLogging {
            enabled: true,
            ..Default::default()
        }
    }
    #[test]
    fn ordinary_reference_payloads_keep_origin_negative_and_reverse_semantics() {
        let event = QueryEvent {
            flags: CONFIG | IPV4,
            name: Some(b"READY.LOGGING".to_vec()),
            data: QueryData::Address("192.0.2.1".parse().unwrap()),
            argument: None,
            kind: 0,
        };
        assert_eq!(
            format(enabled(), QueryContext::default(), &event)
                .unwrap()
                .message,
            b"config ready.logging is 192.0.2.1"
        );
        let reverse = QueryEvent {
            flags: CONFIG | IPV4 | REVERSE,
            ..event.clone()
        };
        assert_eq!(
            format(enabled(), QueryContext::default(), &reverse)
                .unwrap()
                .message,
            b"config 192.0.2.1 is ready.logging"
        );
        let failure = QueryEvent {
            flags: CONFIG | RCODE,
            name: Some(b"error".to_vec()),
            data: QueryData::Rcode {
                value: 5,
                ede: Some(14),
            },
            argument: None,
            kind: 0,
        };
        assert_eq!(
            format(enabled(), QueryContext::default(), &failure)
                .unwrap()
                .message,
            b"config error is REFUSED (EDE: not ready)"
        );
        let negative = QueryEvent {
            flags: CONFIG | NEGATIVE | NXDOMAIN,
            ..event
        };
        assert_eq!(
            format(enabled(), QueryContext::default(), &negative)
                .unwrap()
                .message,
            b"config ready.logging is NXDOMAIN"
        );
        let only_failed = QueryLogging {
            only_failed: true,
            ..enabled()
        };
        assert!(format(only_failed, QueryContext::default(), &reverse).is_none());
        assert!(format(only_failed, QueryContext::default(), &negative).is_some());
    }
    #[test]
    fn source_controlled_signed_extremes_use_the_c_unsigned_display_word() {
        let config = crate::config::logging::QueryLogging {
            enabled: true,
            extra: true,
            protocol: true,
            ..Default::default()
        };
        let event = QueryEvent::label(CONFIG, b"wrap.logging", Some(b"value"), 0);
        for (seed, expected) in [
            (0, "UDP 0"),
            (1, "UDP 1"),
            (-1, "TCP 1"),
            (i32::MAX, "UDP 2147483647"),
            (i32::MIN, "TCP 2147483648"),
        ] {
            let context = QueryContext {
                display_id: seed,
                client: None,
            };
            assert_eq!(
                format(config, context, &event).unwrap().message,
                format!("{expected} config wrap.logging is value").as_bytes()
            );
        }
    }
    #[test]
    fn actual_client_protocol_and_parent_tcp_reservation_are_independent() {
        let client = Some("127.0.0.1:16502".parse().unwrap());
        let mut parent = QueryIds::default();
        for _ in 0..9 {
            parent.next(false, client);
        }
        let mut accepted = parent.accept_tcp();
        let context = accepted.next(true, client);
        assert_eq!(context.display_id, -10);
        assert_eq!(parent.next(false, client).display_id, 110);
        let config = QueryLogging {
            extra: true,
            protocol: true,
            ..enabled()
        };
        let event = QueryEvent {
            flags: QUERY | IPV4,
            name: Some(b"ready.logging".to_vec()),
            data: QueryData::Address("127.0.0.1".parse().unwrap()),
            argument: None,
            kind: 1,
        };
        assert_eq!(
            format(config, context, &event).unwrap().message,
            b"TCP 10 127.0.0.1/16502 query[A] ready.logging from 127.0.0.1"
        );
        let opcode = QueryEvent {
            flags: QUERY | CONFIG | IPV4,
            kind: 4,
            ..event
        };
        assert_eq!(
            format(enabled(), context, &opcode).unwrap().message,
            b"non-query opcode 4 from 127.0.0.1"
        );
    }
}
