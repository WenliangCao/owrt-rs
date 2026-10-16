//! Transport boundaries for the local DNS engine.
//!
//! The service owns socket I/O and TCP framing, while `local::LocalAnswerer`
//! owns answer selection.  An unowned query is returned as `None` so a future
//! upstream dispatcher can take over without changing the wire boundary.

use super::cache::Cache;
use super::lease_names::LeaseNames;
use super::local::{AnswerError, LocalAnswerer};
use super::wire::{find_pseudoheader, Header};
use crate::config::dns::DnsConfig;
use crate::hosts::Hosts;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream, UdpSocket};
use std::sync::Arc;

/// Only these OPT fields affect a local/cache reply envelope. Keep the
/// successful scan's absence distinct from a suppressed parse error.
#[derive(Clone, Copy)]
pub(super) struct AnswerEdns {
    pub udp_limit: u16,
    pub had_opt: bool,
    pub dnssec_ok: bool,
}

impl AnswerEdns {
    pub(super) fn scan(query: &[u8], maximum: u16) -> Result<Self, super::wire::WireError> {
        let scan = find_pseudoheader(query, true)?;
        Ok(match scan.opt {
            Some(opt) => Self {
                udp_limit: opt.udp_size(maximum), had_opt: true, dnssec_ok: opt.dnssec_ok(),
            },
            None => Self { udp_limit: 512, had_opt: false, dnssec_ok: false },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    Empty,
    TooLarge,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated DNS TCP frame",
            Self::Empty => "empty DNS TCP frame",
            Self::TooLarge => "DNS TCP frame exceeds its receive limit",
        })
    }
}

impl std::error::Error for FrameError {}

pub fn encode_tcp_frame(packet: &[u8]) -> Result<Vec<u8>, FrameError> {
    if packet.is_empty() {
        return Err(FrameError::Empty);
    }
    if packet.len() > u16::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    let mut frame = Vec::with_capacity(packet.len() + 2);
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}

/// An owned answer with its wire prefix kept separately. The packet is already
/// owned by the answer engine; framing must not allocate and copy it again.
#[derive(Debug)]
pub struct TcpWriteFrame {
    packet: Vec<u8>,
    length: [u8; 2],
}

impl TcpWriteFrame {
    pub fn new(packet: Vec<u8>) -> Result<Self, FrameError> {
        if packet.is_empty() {
            return Err(FrameError::Empty);
        }
        if packet.len() > u16::MAX as usize {
            return Err(FrameError::TooLarge);
        }
        let length = (packet.len() as u16).to_be_bytes();
        Ok(Self { packet, length })
    }

    pub fn wire_len(&self) -> usize {
        self.packet.len() + self.length.len()
    }

    /// Write from the same wire offset used for a contiguous length-prefixed
    /// packet, including a partial write which stops inside the two-byte prefix.
    pub fn write_from(&self, output: &mut impl Write, offset: usize) -> io::Result<usize> {
        if offset < self.length.len() {
            output.write_vectored(&[
                io::IoSlice::new(&self.length[offset..]),
                io::IoSlice::new(&self.packet),
            ])
        } else {
            output.write(&self.packet[offset - self.length.len()..])
        }
    }
}

/// Incremental DNS-over-TCP decoder. It never allocates according to an
/// incomplete frame and rejects zero-length frames before returning payload.
/// A bounded instance also rejects a length prefix before reading its body,
/// matching `forward.c::tcp_request`'s early `packet_buff_sz` check.
#[derive(Debug)]
pub struct TcpFramer {
    bytes: Vec<u8>,
    max_frame: usize,
}

impl Default for TcpFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpFramer {
    pub fn new() -> Self {
        Self::with_max_frame(u16::MAX as usize)
    }

    /// Construct a framer with a caller-owned receive limit. Values above the
    /// two-byte DNS/TCP maximum are clamped; a zero limit deliberately rejects
    /// every non-empty frame and is useful only for validation.
    pub fn with_max_frame(max_frame: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_frame: max_frame.min(u16::MAX as usize),
        }
    }

    /// Consume at most one frame, returning the number of input bytes used.
    /// A listener must handle a completed frame before parsing the next one:
    /// a later invalid length must not discard earlier requests in the read.
    pub fn push_frame(&mut self, input: &[u8]) -> Result<(usize, Option<Vec<u8>>), FrameError> {
        if self.bytes.is_empty() && input.len() >= 2 {
            let length = u16::from_be_bytes([input[0], input[1]]) as usize;
            if length == 0 {
                return Err(FrameError::Empty);
            }
            if length > self.max_frame {
                return Err(FrameError::TooLarge);
            }
            if input.len() >= length + 2 {
                // No fragment needs retaining. Copy directly to the owned
                // request rather than through the reusable assembly buffer.
                return Ok((length + 2, Some(input[2..length + 2].to_vec())));
            }
        }
        let mut offset = 0;
        if self.bytes.len() < 2 {
            let count = (2 - self.bytes.len()).min(input.len());
            self.bytes.extend_from_slice(&input[..count]);
            offset += count;
            if self.bytes.len() < 2 {
                return Ok((offset, None));
            }
        }
        let length = u16::from_be_bytes([self.bytes[0], self.bytes[1]]) as usize;
        if length == 0 {
            self.bytes.clear();
            return Err(FrameError::Empty);
        }
        if length > self.max_frame {
            self.bytes.clear();
            return Err(FrameError::TooLarge);
        }
        let count = (length + 2 - self.bytes.len()).min(input.len() - offset);
        self.bytes.extend_from_slice(&input[offset..offset + count]);
        offset += count;
        if self.bytes.len() < length + 2 {
            return Ok((offset, None));
        }
        let frame = self.bytes[2..length + 2].to_vec();
        self.bytes.clear();
        Ok((offset, Some(frame)))
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            let (consumed, frame) = self.push_frame(&input[offset..])?;
            offset += consumed;
            if let Some(frame) = frame {
                frames.push(frame);
            }
        }
        Ok(frames)
    }

    pub fn finish(&self) -> Result<(), FrameError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(FrameError::Truncated)
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Debug)]
pub enum ServiceError {
    Answer(AnswerError),
    Frame(FrameError),
    Io(io::Error),
}

impl From<AnswerError> for ServiceError {
    fn from(value: AnswerError) -> Self {
        Self::Answer(value)
    }
}
impl From<FrameError> for ServiceError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}
impl From<io::Error> for ServiceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// A socket-independent service that can be embedded by a daemon or exercised
/// in an isolated namespace.  It currently answers only locally owned names.
/// `hosts` is a complete generation seeded with `local::configured_hosts`
/// before the caller reads hosts files; constructors never replay that load.
pub struct LocalDnsService {
    pub config: Arc<DnsConfig>,
    pub hosts: Hosts,
    /// A completed publication. Existing TCP children retain their snapshot.
    pub leases: Arc<LeaseNames>,
    pub interfaces: Arc<super::interface_records::InterfaceRecords>,
    pub local_ttl: u32,
    pub max_udp: usize,
    pub edns_packet_max: u16,
    /// IPv4 destination interface address and mask for localise-queries.
    /// The listener supplies this for each UDP request or TCP connection.
    pub local_network: Option<(Ipv4Addr, Ipv4Addr)>,
    pub query_logging: bool,
    query_events: Vec<crate::query_logging::QueryEvent>,
    pub(super) cached_reply_buffer: Vec<u8>,
}

impl LocalDnsService {
    pub fn new(config: impl Into<Arc<DnsConfig>>, hosts: Hosts, local_ttl: u32, max_udp: usize) -> Self {
        Self::new_with_limits(
            config,
            hosts,
            local_ttl,
            max_udp,
            u16::try_from(max_udp.max(512)).unwrap_or(u16::MAX),
        )
    }

    pub fn new_with_limits(
        config: impl Into<Arc<DnsConfig>>,
        hosts: Hosts,
        local_ttl: u32,
        receive_limit: usize,
        edns_packet_max: u16,
    ) -> Self {
        Self {
            config: config.into(),
            hosts,
            leases: Arc::new(LeaseNames::default()),
            interfaces: Arc::new(super::interface_records::InterfaceRecords::default()),
            local_ttl,
            max_udp: receive_limit.max(512),
            edns_packet_max,
            local_network: None,
            query_logging: false,
            query_events: Vec::new(),
            cached_reply_buffer: Vec::new(),
        }
    }

    /// Interface enumeration also runs before TCP accepts. Preserve the shared
    /// configuration generation when its derived domains have not changed.
    pub fn publish_domain_interfaces(
        &mut self,
        domains: Arc<crate::config::domains::DomainInterfaces>,
    ) {
        if self.config.domain_interfaces != domains {
            Arc::make_mut(&mut self.config).domain_interfaces = domains;
        }
    }

    pub fn record_query_event(&mut self, event: crate::query_logging::QueryEvent) {
        if self.query_logging {
            self.query_events.push(event);
        }
    }

    pub fn take_query_events(&mut self) -> Vec<crate::query_logging::QueryEvent> {
        std::mem::take(&mut self.query_events)
    }

    /// The UDP owner may return a cache reply after its final send. Retain at
    /// most one small allocation; large/general replies keep their old lifetime.
    pub fn recycle_cached_reply(&mut self, mut packet: Vec<u8>) {
        if packet.capacity() <= 512 && packet.capacity() >= self.cached_reply_buffer.capacity() {
            packet.clear();
            self.cached_reply_buffer = packet;
        }
    }

    pub fn handle_udp(&mut self, query: &[u8]) -> Result<Option<Vec<u8>>, ServiceError> {
        self.handle_udp_at(query, unix_now())
    }

    pub fn handle_udp_at(
        &mut self,
        query: &[u8],
        now: i64,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        self.handle_udp_with_cache(query, now, None)
    }

    pub(crate) fn handle_udp_with_cache(
        &mut self,
        query: &[u8],
        now: i64,
        cache: Option<&mut Cache>,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        let header = Header::parse(query).map_err(|_| AnswerError::Malformed)?;
        let question = super::forward::Question::parse_with_header(query, header)
            .map_err(|_| AnswerError::Malformed)?;
        self.handle_local_parsed(query, header, &question, now, cache, false)
    }

    pub fn handle_tcp_payload(&mut self, query: &[u8]) -> Result<Option<Vec<u8>>, ServiceError> {
        self.handle_tcp_payload_at(query, unix_now())
    }

    pub fn handle_tcp_payload_at(
        &mut self,
        query: &[u8],
        now: i64,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        self.handle_tcp_with_cache(query, now, None)
    }

    pub(crate) fn handle_tcp_with_cache(
        &mut self,
        query: &[u8],
        now: i64,
        cache: Option<&mut Cache>,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        let header = Header::parse(query).map_err(|_| AnswerError::Malformed)?;
        let question = super::forward::Question::parse_with_header(query, header)
            .map_err(|_| AnswerError::Malformed)?;
        self.handle_local_parsed(query, header, &question, now, cache, true)
    }

    /// The local record lookup is identical for UDP and TCP. Transport only
    /// selects the output envelope and forward_query's distinct OPT policy.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_local_parsed(
        &mut self,
        query: &[u8],
        header: Header,
        question: &super::forward::Question,
        now: i64,
        cache: Option<&mut Cache>,
        tcp: bool,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        let answer = self.lookup_local_parsed(query, header, question, now, cache, tcp, &mut None, &mut None)?;
        Ok(answer.map(|answer| self.finish_local_answer(answer)))
    }

    pub(super) fn finish_local_answer(&mut self, answer: super::local::LocalAnswer) -> Vec<u8> {
        self.query_events.extend(answer.query_events);
        answer.packet
    }

    /// Retain forward-rule answers until answer_request's cache lookup has
    /// run. Their query log events belong only to the answer actually sent.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn lookup_local_parsed<'q>(
        &mut self,
        query: &[u8],
        header: Header,
        question: &'q super::forward::Question,
        now: i64,
        cache: Option<&mut Cache>,
        tcp: bool,
        name_lookup: &mut Option<super::cache::NameLookup<'q>>,
        edns_scan: &mut Option<AnswerEdns>,
    ) -> Result<Option<super::local::LocalAnswer>, ServiceError> {
        // C treats an invalid additional section as no pseudoheader; a
        // valid question may still receive a local answer.
        let opt = if tcp {
            None
        } else {
            // Only successful scans are shared with the following cache
            // answer of this same immutable query. Failed scans retain the
            // local caller's suppression and the cache caller's own error.
            *edns_scan = AnswerEdns::scan(query, self.edns_packet_max).ok();
            *edns_scan
        };
        let limit = if tcp {
            u16::MAX as usize
        } else {
            opt.map_or(512, |opt| usize::from(opt.udp_limit))
        };
        let mut answerer = LocalAnswerer {
            config: &self.config,
            hosts: &mut self.hosts,
            local_ttl: self.local_ttl,
            max_packet: limit,
        };
        let Some(mut answer) = answerer.answer_parsed_with_query_events(
            query,
            header,
            question,
            &mut self.leases,
            now,
            self.local_network,
            cache,
            &self.interfaces,
            self.query_logging,
            name_lookup,
        )?
        else {
            return Ok(None);
        };
        // TCP needs OPT only after a hit; UDP needs it to size the writer.
        let opt = if tcp {
            AnswerEdns::scan(query, self.edns_packet_max).ok()
        } else {
            opt
        };
        if let Some(opt) = opt.filter(|opt| opt.had_opt) {
            let opt_limit = if tcp || answer.forward_rule {
                limit
            } else {
                usize::from(self.edns_packet_max)
            };
            append_empty_opt(
                &mut answer.packet,
                self.edns_packet_max,
                opt.dnssec_ok && (tcp || !answer.forward_rule),
                opt_limit,
            )?;
        }
        Ok(Some(answer))
    }

    /// Forwarding rules select by the CNAME cursor, but make_local_answer
    /// writes the original client question and literal-address owner.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn lookup_forward_rule(
        &mut self,
        query: &[u8],
        header: Header,
        question: &super::forward::Question,
        name: &super::wire::Name,
        now: i64,
        cache: Option<&mut Cache>,
        tcp: bool,
    ) -> Result<Option<super::local::LocalAnswer>, ServiceError> {
        let opt = find_pseudoheader(query, true).ok().and_then(|scan| scan.opt);
        let limit = if tcp { u16::MAX as usize } else {
            opt.as_ref().map_or(512, |opt| usize::from(opt.udp_size(self.edns_packet_max)))
        };
        let answerer = LocalAnswerer {
            config: &self.config, hosts: &mut self.hosts,
            local_ttl: self.local_ttl, max_packet: limit,
        };
        let Some(mut answer) = answerer.answer_forward_rule(
            header, question, name, &self.leases, now, cache.as_deref(), self.query_logging,
        )? else { return Ok(None); };
        if let Some(opt) = opt {
            append_empty_opt(&mut answer.packet, self.edns_packet_max, opt.dnssec_ok() && tcp, limit)?;
        }
        Ok(Some(answer))
    }

    pub fn handle_tcp_frame(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, ServiceError> {
        let mut framer = TcpFramer::new();
        let frames = framer.push(frame)?;
        if frames.len() != 1 || framer.buffered_len() != 0 {
            return Err(FrameError::Truncated.into());
        }
        self.handle_tcp_payload(&frames[0])?
            .map(|packet| encode_tcp_frame(&packet).map_err(ServiceError::from))
            .transpose()
    }

    /// Receive and answer one UDP datagram.  `None` means the query belongs to
    /// the upstream path and is intentionally left untouched here.
    pub fn serve_udp_once(&mut self, socket: &UdpSocket) -> Result<bool, ServiceError> {
        let mut query = vec![0; 65_535];
        let (length, peer) = socket.recv_from(&mut query)?;
        // std::net::UdpSocket does not expose MSG_TRUNC.  Reading the maximum
        // IPv4/IPv6 datagram and applying the configured receive limit before
        // parsing has the same observable result: an oversized request is
        // discarded without creating a forward or local answer.
        if length > self.max_udp {
            return Ok(false);
        }
        if let Some(answer) = self.handle_udp(&query[..length])? {
            socket.send_to(&answer, peer)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Serve a blocking TCP connection until EOF.  The framing decoder keeps
    /// partial reads and permits multiple queries on one connection.
    pub fn serve_tcp_connection(&mut self, mut stream: TcpStream) -> Result<(), ServiceError> {
        let mut framer = TcpFramer::new();
        let mut input = [0u8; 4096];
        loop {
            let count = stream.read(&mut input)?;
            if count == 0 {
                return framer.finish().map_err(ServiceError::from);
            }
            for query in framer.push(&input[..count])? {
                if let Some(answer) = self.handle_tcp_payload(&query)? {
                    stream.write_all(&encode_tcp_frame(&answer)?)?;
                }
            }
        }
    }
}

pub(super) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64)
}

/// Local answers contain no client OPT. edns0.c checks room for the empty
/// 11-byte RR plus a four-byte option header even when optno/optlen are zero;
/// on failure it returns the original packet length and arcount.
pub(super) fn append_empty_opt(
    packet: &mut Vec<u8>,
    advertised: u16,
    do_bit: bool,
    limit: usize,
) -> Result<(), AnswerError> {
    if packet.len().checked_add(15).is_none_or(|len| len > limit) {
        return Ok(());
    }
    let mut header = Header::parse(packet)?;
    packet.extend_from_slice(&[0, 0, 41]);
    packet.extend_from_slice(&advertised.to_be_bytes());
    packet.extend_from_slice(&(if do_bit { 0x8000u32 } else { 0 }).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    header.additionals += 1;
    header.write(packet)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dns::DnsConfig;
    use crate::config::{lex_line, validate_directive};
    use crate::dns::wire::{Header, Name};

    fn query() -> Vec<u8> {
        let name = Name::from_ascii("router.test").unwrap();
        let mut packet = vec![0; 12];
        Header {
            id: 1,
            flags: 0x0100,
            questions: 1,
            ..Header::default()
        }
        .write(&mut packet)
        .unwrap();
        packet.extend(name.as_wire());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn tcp_config_snapshot_shares_direct_records_until_a_real_domain_change() {
        use crate::config::domains::{DomainAddress, DomainInterfaces};
        let mut config = DnsConfig::default();
        config.apply(&lex_line(b"host-record=direct.test,192.0.2.8").unwrap().unwrap()).unwrap();
        let hosts = super::super::local::configured_hosts(&config, 37);
        let mut parent = LocalDnsService::new(config, hosts, 37, 1232);
        let child = LocalDnsService::new(Arc::clone(&parent.config), parent.hosts.tcp_snapshot(), 37, 1232);
        parent.publish_domain_interfaces(Arc::new(DomainInterfaces::default()));
        assert!(Arc::ptr_eq(&parent.config, &child.config));
        assert_eq!(parent.config.host_records.as_ptr(), child.config.host_records.as_ptr());
        parent.publish_domain_interfaces(Arc::new(DomainInterfaces { addresses: vec![DomainAddress {
            label: b"eth0".to_vec(), address: "192.0.2.1".parse().unwrap(), prefix: 24,
        }] }));
        assert!(!Arc::ptr_eq(&parent.config, &child.config));
        assert!(child.config.domain_interfaces.addresses.is_empty());
        assert_eq!(parent.config.domain_interfaces.addresses.len(), 1);
    }

    #[test]
    fn one_frame_is_delivered_before_later_invalid_length() {
        // C tcp_request reads/answers the first frame before the next length.
        for suffix in [[0, 0], [0x10, 0]] {
            let input = [0, 3, 1, 2, 3, suffix[0], suffix[1]];
            let mut framer = TcpFramer::with_max_frame(512);
            assert_eq!(framer.push_frame(&input).unwrap(), (5, Some(vec![1, 2, 3])));
            assert!(framer.push_frame(&input[5..]).is_err());
        }
    }

    #[test]
    fn tcp_framer_handles_split_and_multiple_frames() {
        let first = encode_tcp_frame(b"one").unwrap();
        let second = encode_tcp_frame(b"two").unwrap();
        let mut input = first.clone();
        input.extend_from_slice(&second);
        let mut framer = TcpFramer::new();
        assert!(framer.push(&input[..2]).unwrap().is_empty());
        let mut rest = input[2..4].to_vec();
        assert!(framer.push(&rest).unwrap().is_empty());
        rest = input[4..].to_vec();
        assert_eq!(
            framer.push(&rest).unwrap(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert!(framer.finish().is_ok());
    }

    #[test]
    fn local_service_uses_tcp_frame_boundary() {
        let mut config = DnsConfig::default();
        let directive = lex_line(b"host-record=router.test,192.0.2.1")
            .unwrap()
            .unwrap();
        validate_directive(&directive).unwrap();
        config.apply(&directive).unwrap();
        let service = LocalDnsService::new(
            config.clone(),
            super::super::local::configured_hosts(&config, 60),
            60,
            512,
        );
        let mut service = service;
        let response = service
            .handle_tcp_frame(&encode_tcp_frame(&query()).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]) as usize,
            response.len() - 2
        );
    }

    #[test]
    fn localise_filters_only_ipv4_hosts_when_one_matches_destination_network() {
        let mut service = configured(
            &[
                b"localise-queries".to_vec(),
                b"no-round-robin".to_vec(),
                b"host-record=multi.test,192.0.2.3,2001:db8::3".to_vec(),
                b"host-record=multi.test,198.51.100.3".to_vec(),
                b"cname=alias.test,multi.test".to_vec(),
            ],
            1232,
        );
        service.local_network = Some((
            "192.0.2.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        ));
        for name in ["multi.test", "alias.test"] {
            let mut writer = crate::dns::wire::PacketWriter::new(1, 0x100, 512).unwrap();
            writer
                .question(&crate::dns::wire::Name::from_ascii(name).unwrap(), 255, 1)
                .unwrap();
            let query = writer.finish();
            let packet = service.handle_udp(&query).unwrap().unwrap();
            let parsed = crate::dns::wire::Message::parse(&packet).unwrap();
            let a = parsed
                .records(crate::dns::wire::Section::Answer)
                .filter(|rr| rr.rrtype == 1)
                .collect::<Vec<_>>();
            assert_eq!(a.len(), 1);
            assert_eq!(a[0].rdata, [192, 0, 2, 3]);
            assert_eq!(
                parsed
                    .records(crate::dns::wire::Section::Answer)
                    .filter(|rr| rr.rrtype == 28)
                    .count(),
                1
            );
        }
        service.local_network = Some((
            "203.0.113.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        ));
        let mut writer = crate::dns::wire::PacketWriter::new(1, 0x100, 512).unwrap();
        writer
            .question(
                &crate::dns::wire::Name::from_ascii("multi.test").unwrap(),
                1,
                1,
            )
            .unwrap();
        let packet = service
            .handle_tcp_payload(&writer.finish())
            .unwrap()
            .unwrap();
        assert_eq!(
            crate::dns::wire::Message::parse(&packet)
                .unwrap()
                .header
                .answers,
            2
        );
    }

    fn configured(lines: &[Vec<u8>], maximum: u16) -> LocalDnsService {
        let mut config = DnsConfig::default();
        for line in lines {
            config.apply(&lex_line(line).unwrap().unwrap()).unwrap();
        }
        LocalDnsService::new_with_limits(
            config.clone(),
            super::super::local::configured_hosts(&config, 37),
            37,
            1497,
            maximum,
        )
    }

    #[test]
    fn query_notices_keep_selected_record_origin_without_changing_answers() {
        use crate::dns::wire::{Name, PacketWriter};
        use crate::query_logging::{self as log, QueryData};
        let lines = [
            b"host-record=config.test,192.0.2.1".to_vec(),
            b"cname=alias.test,file.test".to_vec(),
            b"txt-record=txt.test,hello".to_vec(),
            b"filterwin2k".to_vec(),
        ];
        let mut silent = configured(&lines, 1232);
        let mut logged = configured(&lines, 1232);
        for service in [&mut silent, &mut logged] {
            // File uid1 overlaps the configured uid. Provenance belongs to
            // the selected row, not a guessed numeric source namespace.
            service
                .hosts
                .set_source_name(1, b"/m2/hosts.extra".to_vec());
            service
                .hosts
                .read(b"192.0.2.2 file.test\n", 1, 37, false, |_| None);
        }
        logged.query_logging = true;
        for (name, kind, origin) in [
            ("config.test", 1, log::CONFIG),
            ("file.test", 1, log::HOSTS),
            ("alias.test", 1, log::CONFIG | log::CNAME),
            ("2.2.0.192.in-addr.arpa", 12, log::HOSTS | log::REVERSE),
            ("txt.test", 16, log::CONFIG | log::RRNAME),
            ("windows.test", 6, log::CONFIG),
        ] {
            let mut writer = PacketWriter::new(1, 0x0100, 512).unwrap();
            writer
                .question(&Name::from_ascii(name).unwrap(), kind, 1)
                .unwrap();
            let request = writer.finish();
            assert_eq!(
                logged.handle_udp_at(&request, 100).unwrap(),
                silent.handle_udp_at(&request, 100).unwrap()
            );
            let notices = logged.take_query_events();
            assert!(!notices.is_empty(), "{name}");
            assert_eq!(notices[0].flags & origin, origin, "{name}");
            if name == "file.test" {
                assert_eq!(
                    notices[0].argument.as_deref(),
                    Some(b"/m2/hosts.extra".as_slice())
                );
                assert!(matches!(notices[0].data, QueryData::Address(_)));
            }
            if name == "alias.test" {
                assert_eq!(notices.len(), 2);
                assert_eq!(notices[1].flags & log::HOSTS, log::HOSTS);
                assert_eq!(notices[1].name.as_deref(), Some(b"file.test".as_slice()));
            }
            assert!(silent.take_query_events().is_empty());
            assert!(logged.take_query_events().is_empty());
        }
    }

    fn opt_query(kind: u16, size: u16) -> Vec<u8> {
        let mut packet = query();
        let end = packet.len();
        packet[end - 4..end - 2].copy_from_slice(&kind.to_be_bytes());
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 41]);
        packet.extend_from_slice(&size.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0x80, 0, 0, 0]);
        packet
    }

    #[test]
    fn udp_limit_discards_fitting_prefix_and_tcp_keeps_full_local_answer() {
        let lines: Vec<_> = (*b"abc")
            .into_iter()
            .map(|byte| {
                let mut line = b"txt-record=router.test,".to_vec();
                line.extend(std::iter::repeat_n(byte, 200));
                line
            })
            .collect();
        let mut service = configured(&lines, 1232);
        let mut no_opt = query();
        let end = no_opt.len();
        no_opt[end - 4..end - 2].copy_from_slice(&16u16.to_be_bytes());
        let reply = service.handle_udp(&no_opt).unwrap().unwrap();
        let header = Header::parse(&reply).unwrap();
        assert_eq!(header.flags, 0x8780);
        assert_eq!(
            (header.answers, header.additionals, reply.len()),
            (0, 0, no_opt.len())
        );
        let small = opt_query(16, 512);
        let reply = service.handle_udp(&small).unwrap().unwrap();
        let header = Header::parse(&reply).unwrap();
        assert_eq!(
            (header.answers, header.additionals, reply.len()),
            (0, 1, 40)
        );
        let opt = find_pseudoheader(&reply, true).unwrap().opt.unwrap();
        assert_eq!((opt.record.class, opt.record.ttl), (1232, 0x8000));
        for reply in [
            service.handle_udp(&opt_query(16, 4096)).unwrap().unwrap(),
            service.handle_tcp_payload(&small).unwrap().unwrap(),
        ] {
            let header = Header::parse(&reply).unwrap();
            assert_eq!(
                (header.answers, header.additionals, reply.len()),
                (3, 1, 679)
            );
            assert_eq!(header.flags & 0x0200, 0);
        }
    }

    #[test]
    fn empty_opt_reserves_four_bytes_and_does_not_leave_trailing_data() {
        for (tail, expected_length, expected_opt) in [(199, 508, 1), (200, 498, 0)] {
            let mut line = b"txt-record=router.test,".to_vec();
            line.extend([b'x'; 255]);
            line.push(b',');
            line.extend(std::iter::repeat_n(b'y', tail));
            let mut service = configured(&[line], 512);
            let reply = service.handle_udp(&opt_query(16, 512)).unwrap().unwrap();
            assert_eq!(reply.len(), expected_length);
            assert_eq!(Header::parse(&reply).unwrap().additionals, expected_opt);
            assert_eq!(
                super::super::wire::Message::parse(&reply).unwrap().end,
                reply.len()
            );
        }
    }

    #[test]
    fn local_opt_do_policy_and_truncated_opt_follow_the_c_caller() {
        for (line, do_bit) in [
            (b"host-record=router.test,192.0.2.1".as_slice(), true),
            (b"address=/router.test/192.0.2.1", false),
            (b"local=/router.test/", false),
        ] {
            let mut service = configured(&[line.to_vec()], 1232);
            let packet = opt_query(1, 512);
            let udp = service.handle_udp(&packet).unwrap().unwrap();
            let tcp = service.handle_tcp_payload(&packet).unwrap().unwrap();
            assert_eq!(
                find_pseudoheader(&udp, true)
                    .unwrap()
                    .opt
                    .unwrap()
                    .dnssec_ok(),
                do_bit
            );
            assert!(find_pseudoheader(&tcp, true)
                .unwrap()
                .opt
                .unwrap()
                .dnssec_ok());
            for length in [0, 1, 4, 9, 10] {
                let broken = &packet[..packet.len() - 11 + length];
                let reply = service.handle_udp(broken).unwrap().unwrap();
                assert_eq!(Header::parse(&reply).unwrap().additionals, 0);
            }
        }
    }

    #[test]
    fn tcp_framer_accepts_maximum_frame_followed_by_another_frame() {
        let first = vec![0xa5; u16::MAX as usize];
        let second = encode_tcp_frame(b"second").unwrap();
        let mut input = encode_tcp_frame(&first).unwrap();
        input.extend_from_slice(&second);
        let mut framer = TcpFramer::new();
        let frames = framer.push(&input).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], first);
        assert_eq!(frames[1], b"second");
        assert!(framer.finish().is_ok());
    }

    #[test]
    fn tcp_framer_rejects_zero_length_and_reports_partial_tail() {
        let mut framer = TcpFramer::new();
        assert_eq!(framer.push(&[0, 0]), Err(FrameError::Empty));
        assert_eq!(framer.push(&[0, 3, b'a']), Ok(Vec::new()));
        assert_eq!(framer.finish(), Err(FrameError::Truncated));
    }

    #[test]
    fn bounded_tcp_framer_rejects_length_before_reading_body() {
        let mut framer = TcpFramer::with_max_frame(4);
        assert_eq!(framer.push(&[0, 5, b'a']), Err(FrameError::TooLarge));
        assert_eq!(framer.buffered_len(), 0);
        assert_eq!(
            framer.push(&encode_tcp_frame(b"ok").unwrap()),
            Ok(vec![b"ok".to_vec()])
        );
    }

    #[test]
    fn tcp_write_frame_keeps_prefix_and_payload_across_partial_writes() {
        struct ShortWriter { bytes: Vec<u8>, maximum: usize }
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let count = bytes.len().min(self.maximum);
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn write_vectored(&mut self, inputs: &[io::IoSlice<'_>]) -> io::Result<usize> {
                let mut count = 0;
                for input in inputs {
                    let take = input.len().min(self.maximum - count);
                    self.bytes.extend_from_slice(&input[..take]);
                    count += take;
                }
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        for length in [1, 32, 1232, u16::MAX as usize] {
            let packet = vec![0xa5; length];
            let expected = encode_tcp_frame(&packet).unwrap();
            for maximum in [1, 2, 3, 31, length + 2] {
                let frame = TcpWriteFrame::new(packet.clone()).unwrap();
                let mut output = ShortWriter { bytes: Vec::new(), maximum };
                let mut offset = 0;
                while offset < frame.wire_len() {
                    offset += frame.write_from(&mut output, offset).unwrap();
                }
                assert_eq!(offset, expected.len());
                assert_eq!(output.bytes, expected);
            }
        }
        assert!(matches!(TcpWriteFrame::new(Vec::new()), Err(FrameError::Empty)));
        assert!(matches!(TcpWriteFrame::new(vec![0; 65536]), Err(FrameError::TooLarge)));
    }

    #[test]
    fn tcp_framer_all_fragment_boundaries_keep_one_frame_and_tail() {
        let packet = vec![0xa5; 64];
        let first = encode_tcp_frame(&packet).unwrap();
        let second = encode_tcp_frame(b"second").unwrap();
        for split in 0..=first.len() {
            let mut framer = TcpFramer::new();
            let mut input = first[split..].to_vec();
            input.extend_from_slice(&second);
            let (_, before) = framer.push_frame(&first[..split]).unwrap();
            let (used, after) = framer.push_frame(&input).unwrap();
            if split == first.len() {
                assert_eq!(before.unwrap(), packet);
                assert_eq!(after.unwrap(), b"second");
                assert_eq!(used, second.len());
            } else {
                assert!(before.is_none());
                assert_eq!(after.unwrap(), packet);
                assert_eq!(used, first.len() - split);
                assert_eq!(framer.push_frame(&input[used..]).unwrap().1.unwrap(), b"second");
            }
            assert_eq!(framer.buffered_len(), 0);
            assert!(framer.finish().is_ok());
        }
    }
}
