//! RFC4388 state from rfc2131.c:1066-1235, including dnsmasq's PRL semantics.
//! Context/tag/config resolution from stored relay/vendor data is an explicit
//! caller responsibility. The caller prunes expired leases before invocation.

use super::allocation::{available, narrow, AddressRange};
use super::lease::{ClientIdentity, LeaseStore};
use super::packet::{Packet, VendorOption, COOKIE, FIXED_LEN, OPTIONS_OFFSET};
use crate::config::{validate_directive, Directive, EncodedArg, Error};
use std::net::{IpAddr, Ipv4Addr};

/// Parsed `--leasequery[=<addr>[/<prefix>]]` state from option.c:2933-2990.
/// The ACL stores both address families because the C parser accepts IPv6
/// entries even though this DHCPv4 path only matches IPv4 sources.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeaseQueryConfig {
    pub enabled: bool,
    /// New directives are inserted first, matching daemon->leasequery_addr.
    pub allowed_sources: Vec<(IpAddr, u8)>,
}

impl LeaseQueryConfig {
    /// Parse one already lexed `leasequery` directive. The caller owns the
    /// containing DHCP config and can keep this value as its single poll-owner
    /// state; this parser performs no I/O or blocking work.
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        if directive.name.as_slice() != b"leasequery" {
            return Ok(false);
        }
        validate_directive(directive)?;
        self.enabled = true;
        if let Some(argument) = directive.argument.as_ref() {
            self.allowed_sources.insert(0, parse_source(argument)?);
        }
        Ok(true)
    }

    pub fn allows(&self, source: Ipv4Addr) -> bool {
        self.enabled && allowed_source(source, &self.allowed_sources)
    }
}

fn parse_source(argument: &EncodedArg) -> Result<(IpAddr, u8), Error> {
    let decoded = argument.decoded();
    let encoded = EncodedArg::command_line(&decoded);
    let (address, prefix) = encoded.split_once(b'/');
    let address = std::str::from_utf8(&address.decoded())
        .ok()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .ok_or(Error("bad leasequery source"))?;
    let width: u8 = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix
        .map(|value| {
            value.encoded().iter().try_fold(0u32, |number, &byte| {
                byte.is_ascii_digit()
                    .then_some(number)
                    .and_then(|number| number.checked_mul(10))
                    .and_then(|number| number.checked_add(u32::from(byte - b'0')))
                    .filter(|&number| number <= i32::MAX as u32)
                    .ok_or(Error("bad leasequery prefix"))
            })
        })
        .transpose()?
        .unwrap_or(u32::from(width));
    if prefix > u32::from(width) {
        return Err(Error("bad leasequery prefix"));
    }
    Ok((address, prefix as u8))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Unassigned = 11,
    Unknown = 12,
    Active = 13,
}

pub struct Query<'a> {
    pub packet: Packet<'a>,
    pub source: Ipv4Addr,
    pub enabled: bool,
    /// Empty means no configured ACL; IPv6-only entries deny IPv4 queries.
    pub allowed_sources: &'a [(IpAddr, u8)],
    pub tags: &'a [&'a [u8]],
    pub now: i64,
    pub ignore_client_id: bool,
    pub configured_lease_time: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseQueryReply {
    pub status: Status,
    pub client_address: Ipv4Addr,
    pub hardware_type: u8,
    pub hardware_address: Vec<u8>,
    pub context: Option<usize>,
    pub client_id: Option<Vec<u8>>,
    pub lease_time: Option<u32>,
    pub renewal_time: Option<u32>,
    pub rebinding_time: Option<u32>,
    pub last_transaction: Option<u32>,
    pub agent_id: Option<Vec<u8>>,
}

/// Result of encoding a DHCPLEASE* reply. `omitted` counts options which did
/// not fit the request's bounded response regions, following `free_space()`;
/// the status and mandatory message type are never omitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyEncoding {
    pub len: usize,
    pub omitted: usize,
    /// Actual codes in serializer omission order; empty does not allocate.
    pub omitted_options: Vec<u8>,
    pub overload: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    BufferTooSmall { required: usize, available: usize },
    HardwareAddressTooLong { length: usize },
    OptionTooLong { code: u8, length: usize },
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall {
                required,
                available,
            } => write!(
                formatter,
                "DHCP leasequery reply needs {required} bytes but the output buffer has {available}"
            ),
            Self::HardwareAddressTooLong { length } => write!(
                formatter,
                "DHCP leasequery hardware address has {length} bytes, exceeding its 16-byte field"
            ),
            Self::OptionTooLong { code, length } => write!(
                formatter,
                "DHCP leasequery option {code} has {length} bytes, exceeding its wire length"
            ),
        }
    }
}

impl std::error::Error for ReplyError {}

/// Serialize the RFC4388 reply fields selected by [`query`]. The caller may
/// pass additional options selected by its context/tag owner; these are
/// appended after the RFC-mandated timers and before option 82 (agent-id),
/// matching rfc2131.c:1188-1233. No socket, thread, or event-loop work occurs.
pub fn encode_reply(
    request: Packet<'_>,
    reply: &LeaseQueryReply,
    options: &[VendorOption<'_>],
    output: &mut [u8],
) -> Result<ReplyEncoding, ReplyError> {
    encode_reply_with_policy(request, reply, options, true, output)
}

/// `allow_option_overload` affects do_options only. C writes RFC4388 identity,
/// timers and the final agent-id outside that policy boundary.
pub fn encode_reply_with_policy(
    request: Packet<'_>,
    reply: &LeaseQueryReply,
    options: &[VendorOption<'_>],
    allow_option_overload: bool,
    output: &mut [u8],
) -> Result<ReplyEncoding, ReplyError> {
    let required = request.response_capacity().max(300);
    if output.len() < required {
        return Err(ReplyError::BufferTooSmall {
            required,
            available: output.len(),
        });
    }
    if reply.hardware_address.len() > 16 {
        return Err(ReplyError::HardwareAddressTooLong {
            length: reply.hardware_address.len(),
        });
    }
    for option in options {
        if option.code == 0 || option.code == 255 || option.code == 52 {
            // These are owned by the serializer; accepting caller-supplied
            // control TLVs would permit duplicate END/overload state.
            continue;
        }
        if option.value.len() > u8::MAX as usize {
            return Err(ReplyError::OptionTooLong {
                code: option.code,
                length: option.value.len(),
            });
        }
    }

    output[..required].fill(0);
    output[..FIXED_LEN].copy_from_slice(&request.bytes()[..FIXED_LEN]);
    output[0] = 2; // BOOTREPLY, set before clear_packet in rfc2131.c.
    output[20..24].fill(0); // clear_packet: siaddr.
    output[44..236].fill(0); // clear_packet: sname and file.
    output[OPTIONS_OFFSET..required].fill(0);
    output[236..240].copy_from_slice(&COOKIE);

    let address = match reply.status {
        Status::Unassigned | Status::Active => reply.client_address,
        Status::Unknown => Ipv4Addr::UNSPECIFIED,
    };
    output[12..16].copy_from_slice(&address.octets());
    if reply.status == Status::Active {
        output[1] = reply.hardware_type;
        output[2] = reply.hardware_address.len() as u8;
        output[28..28 + reply.hardware_address.len()].copy_from_slice(&reply.hardware_address);
    }

    let mut writer = LeaseQueryWriter::new(&mut output[..required], true);
    writer.append(53, &[reply.status as u8])?;
    if reply.status == Status::Active {
        if request.requests(61) {
            if let Some(value) = reply.client_id.as_deref().filter(|value| !value.is_empty()) {
                writer.append(61, value)?;
            }
        }
        if request.requests(51) {
            if let Some(value) = reply.lease_time {
                writer.append(51, &value.to_be_bytes())?;
            }
        }
        if request.requests(58) {
            if let Some(value) = reply.renewal_time {
                writer.append(58, &value.to_be_bytes())?;
            }
        }
        if request.requests(59) {
            if let Some(value) = reply.rebinding_time {
                writer.append(59, &value.to_be_bytes())?;
            }
        }
        if request.requests(91) {
            if let Some(value) = reply.last_transaction {
                writer.append(91, &value.to_be_bytes())?;
            }
        }
        writer.allow_overload = allow_option_overload && request.option(55, 0).is_some();
        writer.primary_end = if writer.allow_overload {
            writer.packet.len().saturating_sub(3)
        } else {
            writer.packet.len()
        };
        for option in options {
            if !matches!(option.code, 0 | 52 | 255) {
                writer.append(option.code, option.value)?;
            }
        }
        writer.allow_overload = true;
        writer.primary_end = writer.packet.len();
        if request.requests(82) {
            if let Some(value) = reply.agent_id.as_deref().filter(|value| !value.is_empty()) {
                writer.append(82, value)?;
            }
        }
    }
    Ok(writer.finish())
}

struct LeaseQueryWriter<'a> {
    packet: &'a mut [u8],
    primary: usize,
    primary_end: usize,
    file: usize,
    sname: usize,
    overload_offset: Option<usize>,
    overload: u8,
    allow_overload: bool,
    omitted: usize,
    omitted_options: Vec<u8>,
}

impl<'a> LeaseQueryWriter<'a> {
    fn new(packet: &'a mut [u8], allow_overload: bool) -> Self {
        let primary_end = packet.len();
        Self {
            packet,
            primary: OPTIONS_OFFSET,
            primary_end,
            file: 108,
            sname: 44,
            overload_offset: None,
            overload: 0,
            allow_overload,
            omitted: 0,
            omitted_options: Vec::new(),
        }
    }

    fn append(&mut self, code: u8, value: &[u8]) -> Result<(), ReplyError> {
        if value.len() > u8::MAX as usize {
            return Err(ReplyError::OptionTooLong {
                code,
                length: value.len(),
            });
        }
        let needed = value.len() + 2;
        if self.fits(self.primary, self.primary_end, needed) {
            self.write(self.primary, code, value);
            self.primary += needed;
            return Ok(());
        }
        if !self.allow_overload && self.overload_offset.is_none() {
            self.omitted += 1;
            self.omitted_options.push(code);
            return Ok(());
        }
        self.ensure_overload();
        if self.overload_offset.is_none() {
            self.omitted += 1;
            self.omitted_options.push(code);
            return Ok(());
        }
        if self.overload & 1 == 0 && self.allow_overload && self.packet[108] == 0 {
            self.overload |= 1;
            if self.fits(self.file, 108 + 128, needed) {
                self.write(self.file, code, value);
                self.file += needed;
                self.set_overload();
                return Ok(());
            }
        } else if self.overload & 1 != 0 && self.fits(self.file, 108 + 128, needed) {
            self.write(self.file, code, value);
            self.file += needed;
            return Ok(());
        }
        if self.allow_overload && self.packet[44] == 0 {
            self.overload |= 2;
        }
        if self.overload & 2 != 0 && self.fits(self.sname, 44 + 64, needed) {
            self.write(self.sname, code, value);
            self.sname += needed;
            self.set_overload();
            return Ok(());
        }
        self.omitted += 1;
        self.omitted_options.push(code);
        Ok(())
    }

    fn fits(&self, position: usize, end: usize, needed: usize) -> bool {
        position
            .checked_add(needed)
            .and_then(|value| value.checked_add(1))
            .is_some_and(|value| value < end)
    }

    fn ensure_overload(&mut self) {
        if self.overload_offset.is_none() && self.primary + 3 < self.packet.len() {
            let offset = self.primary;
            self.packet[offset..offset + 3].copy_from_slice(&[52, 1, 0]);
            self.primary += 3;
            self.overload_offset = Some(offset);
        }
    }

    fn set_overload(&mut self) {
        if let Some(offset) = self.overload_offset {
            self.packet[offset + 2] = self.overload;
        }
    }

    fn write(&mut self, position: usize, code: u8, value: &[u8]) {
        self.packet[position] = code;
        self.packet[position + 1] = value.len() as u8;
        self.packet[position + 2..position + 2 + value.len()].copy_from_slice(value);
    }

    fn finish(mut self) -> ReplyEncoding {
        self.set_overload();
        if self.primary < self.packet.len() {
            self.packet[self.primary] = 255;
            self.primary += 1;
        }
        if self.overload & 1 != 0 && self.file < 108 + 128 {
            self.packet[self.file] = 255;
            self.file += 1;
        }
        if self.overload & 2 != 0 && self.sname < 44 + 64 {
            self.packet[self.sname] = 255;
            self.sname += 1;
        }
        ReplyEncoding {
            len: self.primary.max(self.file).max(self.sname).max(300),
            omitted: self.omitted,
            omitted_options: self.omitted_options,
            overload: self.overload,
        }
    }
}

pub fn allowed_source(source: Ipv4Addr, allowed: &[(IpAddr, u8)]) -> bool {
    !source.is_unspecified()
        && (allowed.is_empty()
            || allowed.iter().any(|&(network, prefix)| {
                let IpAddr::V4(network) = network else {
                    return false;
                };
                if prefix > 32 {
                    return false;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(source) & mask == u32::from(network) & mask
            }))
}

pub fn query(
    store: &LeaseStore,
    ranges: &[AddressRange],
    query: Query<'_>,
) -> Option<LeaseQueryReply> {
    if query.packet.message_type() != 10
        || !query.enabled
        || !allowed_source(query.source, query.allowed_sources)
    {
        return None;
    }
    let packet = query.packet;
    let client = ClientIdentity {
        hardware_type: u32::from(packet.hardware_type()),
        hardware_address: packet.hardware_address().to_vec(),
        client_id: (!query.ignore_client_id)
            .then(|| packet.client_id().map(<[u8]>::to_vec))
            .flatten(),
    };
    let lease = if packet.effective_ciaddr().is_unspecified() {
        store.find_client(&client)
    } else {
        store.get(packet.effective_ciaddr())
    };
    let mut reply = LeaseQueryReply {
        status: Status::Unknown,
        client_address: Ipv4Addr::UNSPECIFIED,
        hardware_type: packet.hardware_type(),
        hardware_address: packet.hardware_address().to_vec(),
        context: None,
        client_id: None,
        lease_time: None,
        renewal_time: None,
        rebinding_time: None,
        last_transaction: None,
        agent_id: None,
    };
    if lease.is_none()
        && !packet.effective_ciaddr().is_unspecified()
        && available(ranges, packet.effective_ciaddr(), query.tags).is_some()
    {
        reply.status = Status::Unassigned;
        reply.client_address = packet.effective_ciaddr();
    }
    if let Some(lease) = lease {
        if let Some(context) = narrow(ranges, lease.address, query.tags) {
            reply.status = Status::Active;
            reply.client_address = lease.address;
            reply.hardware_type = lease.identity.hardware_type as u8;
            reply
                .hardware_address
                .clone_from(&lease.identity.hardware_address);
            reply.context = Some(context);
            if packet.requests(61) {
                reply.client_id.clone_from(&lease.identity.client_id);
            }
            if packet.requests(82) {
                reply.agent_id.clone_from(&lease.agent_id);
            }
            let remaining = lease
                .expires
                .map(|expires| super::lease::remaining_seconds(expires, query.now));
            if packet.requests(51) {
                reply.lease_time = Some(remaining.unwrap_or(u32::MAX));
            }
            if let Some(remaining) = remaining {
                let duration = query
                    .configured_lease_time
                    .unwrap_or(ranges[context].lease_time);
                if packet.requests(58) && remaining > duration / 2 {
                    reply.renewal_time = Some(remaining - duration / 2);
                }
                if packet.requests(59) && remaining > duration / 8 {
                    reply.rebinding_time = Some(remaining - duration / 8);
                }
                if packet.requests(91) && remaining < duration {
                    reply.last_transaction = Some(duration - remaining);
                }
            }
        }
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::super::allocation::RangeKind;
    use super::*;
    use crate::config::lex_line;
    use crate::dhcp::packet::find_option;

    fn request(options: &[u8], ciaddr: Ipv4Addr) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&ciaddr.octets());
        bytes[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes.extend_from_slice(options);
        bytes
    }

    fn reply_option(bytes: &[u8], code: u8) -> Option<&[u8]> {
        find_option(&bytes[OPTIONS_OFFSET..], code, 1).map(|option| option.value)
    }

    #[test]
    fn leasequery_parser_matches_optional_acl_and_ipv6_storage() {
        let mut config = LeaseQueryConfig::default();
        assert!(config
            .apply(&lex_line(b"leasequery").unwrap().unwrap())
            .unwrap());
        assert!(config.enabled);
        assert!(config.allowed_sources.is_empty());
        config
            .apply(&lex_line(b"leasequery=192.0.2.0/24").unwrap().unwrap())
            .unwrap();
        config
            .apply(&lex_line(b"leasequery=2001:db8::1/64").unwrap().unwrap())
            .unwrap();
        assert_eq!(config.allowed_sources.len(), 2);
        assert_eq!(config.allowed_sources[0].1, 64);
        assert!(config.allows(Ipv4Addr::new(192, 0, 2, 55)));
        assert!(!config.allows(Ipv4Addr::new(192, 0, 3, 1)));
        assert!(!config.allows(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            config
                .apply(&lex_line(b"leasequery=").unwrap().unwrap())
                .unwrap_err(),
            Error("bad leasequery source")
        );
        assert_eq!(
            config
                .apply(&lex_line(b"leasequery=192.0.2.1/33").unwrap().unwrap())
                .unwrap_err(),
            Error("bad leasequery prefix")
        );
    }

    #[test]
    fn leasequery_reply_clears_unknown_and_preserves_unassigned_identity() {
        let query_bytes = request(
            &[53, 1, 10, 55, 5, 61, 51, 58, 59, 82, 255],
            Ipv4Addr::new(192, 0, 2, 99),
        );
        let query_packet = Packet::parse(&query_bytes).unwrap();
        let unknown = LeaseQueryReply {
            status: Status::Unknown,
            client_address: Ipv4Addr::new(192, 0, 2, 99),
            hardware_type: 1,
            hardware_address: vec![2, 0, 0, 0, 0, 1],
            context: None,
            client_id: None,
            lease_time: None,
            renewal_time: None,
            rebinding_time: None,
            last_transaction: None,
            agent_id: None,
        };
        let mut output = vec![0; 548];
        let encoding = encode_reply(query_packet, &unknown, &[], &mut output).unwrap();
        assert_eq!(output[0], 2);
        assert_eq!(&output[12..16], &[0, 0, 0, 0]);
        assert_eq!(reply_option(&output[..encoding.len], 53), Some(&[12][..]));
        assert!(reply_option(&output[..encoding.len], 51).is_none());

        let unassigned = LeaseQueryReply {
            status: Status::Unassigned,
            client_address: Ipv4Addr::new(192, 0, 2, 99),
            ..unknown
        };
        let encoding = encode_reply(query_packet, &unassigned, &[], &mut output).unwrap();
        assert_eq!(&output[12..16], &unassigned.client_address.octets());
        assert_eq!(&output[28..34], &[2, 0, 0, 0, 0, 1]);
        assert_eq!(reply_option(&output[..encoding.len], 53), Some(&[11][..]));
    }

    #[test]
    fn leasequery_active_reply_follows_prl_and_places_agent_last() {
        let mut query_bytes = request(
            &[53, 1, 10, 55, 6, 61, 51, 58, 59, 91, 82, 255],
            Ipv4Addr::UNSPECIFIED,
        );
        query_bytes[20..24].copy_from_slice(&[192, 0, 2, 254]);
        query_bytes[34..44].copy_from_slice(b"QUERY-TAIL");
        let query_packet = Packet::parse(&query_bytes).unwrap();
        let active = LeaseQueryReply {
            status: Status::Active,
            client_address: Ipv4Addr::new(192, 0, 2, 10),
            hardware_type: 1,
            hardware_address: vec![0x02, 0, 0, 0, 0, 10],
            context: Some(0),
            client_id: Some(vec![1, 2, 3]),
            lease_time: Some(90),
            renewal_time: Some(30),
            rebinding_time: Some(75),
            last_transaction: Some(30),
            agent_id: Some(vec![82, 1, 9]),
        };
        let mut output = vec![0; 548];
        let encoding = encode_reply(
            query_packet,
            &active,
            &[VendorOption {
                code: 15,
                value: b"example.test",
            }],
            &mut output,
        )
        .unwrap();
        assert_eq!(output[0], 2);
        assert_eq!(&output[20..24], &[0; 4]);
        assert_eq!(&output[34..44], b"QUERY-TAIL");
        assert_eq!(&output[12..16], &active.client_address.octets());
        assert_eq!(output[1], active.hardware_type);
        assert_eq!(&output[28..34], active.hardware_address.as_slice());
        assert_eq!(reply_option(&output[..encoding.len], 53), Some(&[13][..]));
        assert_eq!(
            reply_option(&output[..encoding.len], 61),
            Some(&[1, 2, 3][..])
        );
        assert_eq!(
            reply_option(&output[..encoding.len], 51),
            Some(&90u32.to_be_bytes()[..])
        );
        assert_eq!(
            reply_option(&output[..encoding.len], 58),
            Some(&30u32.to_be_bytes()[..])
        );
        assert_eq!(
            reply_option(&output[..encoding.len], 59),
            Some(&75u32.to_be_bytes()[..])
        );
        assert_eq!(
            reply_option(&output[..encoding.len], 91),
            Some(&30u32.to_be_bytes()[..])
        );
        assert_eq!(
            reply_option(&output[..encoding.len], 15),
            Some(b"example.test".as_slice())
        );
        assert_eq!(
            reply_option(&output[..encoding.len], 82),
            Some(&[82, 1, 9][..])
        );
    }

    #[test]
    fn ipv6_only_acl_does_not_become_allow_all_for_ipv4() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        assert!(allowed_source(source, &[]));
        assert!(!allowed_source(Ipv4Addr::UNSPECIFIED, &[]));
        assert!(!allowed_source(
            source,
            &[(IpAddr::V6("::1".parse().unwrap()), 128)]
        ));
        assert!(allowed_source(
            source,
            &[(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)]
        ));
        assert!(!allowed_source(
            source,
            &[(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)]
        ));
    }

    #[test]
    fn leasequery_remaining_timers_and_infinite_values() {
        let address = Ipv4Addr::new(192, 0, 2, 10);
        let range = AddressRange {
            start: address,
            end: address,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 0, 2, 1),
            local: Ipv4Addr::new(192, 0, 2, 1),
            lease_time: 120,
            kind: RangeKind::Dynamic,
            filter: vec![],
            epoch: 0,
        };
        let mut bytes = vec![0; 240];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[12..16].copy_from_slice(&address.octets());
        bytes[236..240].copy_from_slice(&super::super::packet::COOKIE);
        bytes.extend_from_slice(&[53, 1, 10]);
        let packet = Packet::parse(&bytes).unwrap();
        let mut store = LeaseStore::new(1);
        store
            .allocate(
                address,
                ClientIdentity {
                    hardware_type: 1,
                    hardware_address: vec![2, 0, 0, 0, 0, 1],
                    client_id: Some(vec![1, 2, 3]),
                },
            )
            .unwrap();
        store.set_expires(address, 120, 120).unwrap();
        let make_query = || Query {
            packet,
            source: Ipv4Addr::LOCALHOST,
            enabled: true,
            allowed_sources: &[],
            tags: &[],
            now: 150,
            ignore_client_id: false,
            configured_lease_time: None,
        };
        let reply = query(&store, std::slice::from_ref(&range), make_query()).unwrap();
        assert_eq!(reply.status, Status::Active);
        assert_eq!(
            (
                reply.lease_time,
                reply.renewal_time,
                reply.rebinding_time,
                reply.last_transaction
            ),
            (Some(90), Some(30), Some(75), Some(30))
        );
        store.set_expires(address, u32::MAX, 150).unwrap();
        let reply = query(&store, &[range], make_query()).unwrap();
        assert_eq!(reply.lease_time, Some(u32::MAX));
        assert_eq!(
            (
                reply.renewal_time,
                reply.rebinding_time,
                reply.last_transaction
            ),
            (None, None, None)
        );
    }
}
