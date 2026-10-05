//! Query events from cache.c:2312-2515. Producers supply their actual origin;
//! this formatter never infers provenance from the final DNS packet.
use super::{address_text, LogEvent, Priority, Service};
use crate::config::logging::QueryLogging;
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

#[derive(Clone, Debug)]
pub enum QueryData {
    None,
    Address(IpAddr),
    Rcode { value: u16, ede: Option<i32> },
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

pub fn format(config: QueryLogging, context: QueryContext, event: &QueryEvent) -> Option<LogEvent> {
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
