//! Forwarded TCP caller policy from forward.c::tcp_request/process_reply.
//!
//! One service belongs to one downstream connection. The caller first attempts
//! its local answer path. Supported configuration adds no client-dependent EDNS
//! options, so the forwarded query remains byte-for-byte unchanged. Dynamic
//! cache insertion, doctor/ubus and additional RR filtering are separate work.

use super::daemon::{address_policy, validate_runtime_config, DaemonError};
use super::process::{process_reply, AddressPolicy, ProcessError};
use super::reply::{apply_known_local_nxdomain, prepare_reply, strip_opt, ReplyPolicy};
use super::routing::{RouteReason, RoutingTable};
use super::service::LocalDnsService;
use super::tcp_upstream::{TcpError, TcpOptions, TcpUpstream};
use super::wire::{find_pseudoheader, skip_questions, Header, Message, Question, WireError};
use crate::config::dns::DnsConfig;
use std::net::SocketAddr;
use std::time::Instant;

const TCP_LIMIT: usize = 65536;

#[derive(Debug)]
pub enum TcpServiceError {
    Config(DaemonError),
    Transport(TcpError),
    Wire(WireError),
    Process(ProcessError),
    InvalidQuery,
    LocalRouteNotAnswered,
}

impl std::fmt::Display for TcpServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP DNS service: {self:?}")
    }
}
impl std::error::Error for TcpServiceError {}
impl From<WireError> for TcpServiceError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

pub struct TcpDnsService {
    routing: RoutingTable,
    upstream: TcpUpstream,
    policy: AddressPolicy,
    proxy_dnssec: bool,
    edns_packet_max: u16,
}

impl TcpDnsService {
    pub fn new(
        config: &DnsConfig,
        default_resolvers: &[SocketAddr],
        edns_packet_max: u16,
    ) -> Result<Self, TcpServiceError> {
        config
            .validate_ready()
            .map_err(|error| TcpServiceError::Config(error.into()))?;
        validate_runtime_config(config).map_err(TcpServiceError::Config)?;
        let routing = RoutingTable::from_runtime_config(config, default_resolvers)
            .map_err(|error| TcpServiceError::Config(error.into()))?;
        let upstream = TcpUpstream::new(routing.dispatcher_groups(), TcpOptions::default())
            .map_err(TcpServiceError::Transport)?;
        let mut policy = address_policy(config).map_err(TcpServiceError::Config)?;
        // ignore-address is a UDP reply_query predicate, absent from C's TCP
        // process_reply path. Keep that distinction if shared policy grows.
        policy.ignore_addresses.clear();
        Ok(Self {
            routing,
            upstream,
            policy,
            proxy_dnssec: config.proxy_dnssec,
            edns_packet_max,
        })
    }

    pub fn handle(
        &mut self,
        query: &[u8],
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TcpServiceError> {
        self.handle_inner(query, None, deadline, stopped)
    }

    /// Use the downstream connection's local-name snapshot for the C
    /// NXDOMAIN-to-NODATA rule after its local answer path has missed.
    pub fn handle_with_local(
        &mut self,
        query: &[u8],
        local: &LocalDnsService,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TcpServiceError> {
        self.handle_inner(query, Some(local), deadline, stopped)
    }

    fn handle_inner(
        &mut self,
        query: &[u8],
        local: Option<&LocalDnsService>,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TcpServiceError> {
        let header = Header::parse(query)?;
        if header.flags & 0x8000 != 0 {
            return Err(TcpServiceError::InvalidQuery);
        }
        if let Some(reply) = query_error(query)? {
            return Ok(reply);
        }
        let question = Question::parse(query, 12)?;
        let route = self
            .routing
            .select(&question.name, question.qtype, question.class, false);
        let Some(group) = route.upstream_group() else {
            return match route.reason {
                RouteReason::NoMatchingRule => {
                    Ok(refusal(query, self.edns_packet_max, 14, TCP_LIMIT, true)?)
                }
                _ => Err(TcpServiceError::LocalRouteNotAnswered),
            };
        };
        match self.upstream.exchange(group, query, deadline, stopped) {
            Ok(reply) => finish_reply(
                query,
                &reply,
                &self.policy,
                self.proxy_dnssec,
                self.edns_packet_max,
                local,
                Some(&self.routing),
            ),
            Err(TcpError::NoReply) => {
                Ok(refusal(query, self.edns_packet_max, 23, TCP_LIMIT, true)?)
            }
            Err(error) => Err(TcpServiceError::Transport(error)),
        }
    }
}

/// Shared make_local_answer(flags=0) boundary. UDP supplies its own output
/// limit; the advertised OPT size remains the configured daemon maximum.
pub(super) fn refusal(
    query: &[u8],
    edns_packet_max: u16,
    ede: u16,
    out_limit: usize,
    copy_do: bool,
) -> Result<Vec<u8>, WireError> {
    let scan = find_pseudoheader(query, true)?;
    let had_opt = scan.opt.is_some();
    let do_bit = copy_do && scan.opt.is_some_and(|opt| opt.dnssec_ok());
    let mut packet = error_reply(query, 5)?;
    if had_opt {
        add_ede(&mut packet, edns_packet_max, do_bit, ede, out_limit)?;
    }
    Ok(packet)
}

fn error_reply(query: &[u8], rcode: u16) -> Result<Vec<u8>, WireError> {
    let mut header = Header::parse(query)?;
    // setup_reply: clear AA/TC/AD, retain CD/RD/Z, set QR/RA and the error.
    header.flags = (header.flags & !0x062f) | 0x8080 | rcode;
    header.answers = 0;
    header.authorities = 0;
    header.additionals = 0;
    let mut packet = query[..skip_questions(query)?].to_vec();
    header.write(&mut packet)?;
    Ok(packet)
}

fn query_error(query: &[u8]) -> Result<Option<Vec<u8>>, WireError> {
    let header = Header::parse(query)?;
    if header.opcode() != 0 {
        return error_reply(query, 4).map(Some);
    }
    if header.questions != 1
        || header.answers != 0
        || header.authorities != 0
        || Question::parse(query, 12).is_err()
    {
        // extract_request failure precedes OPT discovery in tcp_request. For
        // this request the EDE_INVALID_DATA code is logged, not put on wire.
        return error_reply(query, 5).map(Some);
    }
    Ok(None)
}

fn finish_reply(
    query: &[u8],
    reply: &[u8],
    policy: &AddressPolicy,
    proxy_dnssec: bool,
    edns_packet_max: u16,
    local: Option<&LocalDnsService>,
    routing: Option<&RoutingTable>,
) -> Result<Vec<u8>, TcpServiceError> {
    let query_header = Header::parse(query)?;
    let scan = find_pseudoheader(query, true)?;
    let do_bit = scan.opt.as_ref().is_some_and(|opt| opt.dnssec_ok());
    let envelope = prepare_reply(
        reply,
        ReplyPolicy {
            client_had_opt: scan.opt.is_some(),
            checking_disabled: query_header.flags & 0x10 != 0,
            proxy_dnssec,
            edns_packet_max,
        },
    )?;
    let mut packet = envelope.packet;
    // process_reply captures the full RCODE before possibly stripping OPT.
    // Do not reinterpret an extended error as NOERROR after that strip.
    if matches!(envelope.rcode, 0 | 3) {
        apply_known_local_nxdomain(&mut packet, envelope.rcode, |name| {
            local.is_some_and(|local| {
                super::local::known_forwarded_domain_with_leases(
                    &local.config,
                    &local.hosts,
                    name,
                    &local.leases,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |time| time.as_secs() as i64),
                )
            }) || routing.is_some_and(|routing| routing.has_configured_address(name))
        })?;
        let report = process_reply(&mut packet, policy).map_err(TcpServiceError::Process)?;
        let ede = if report.blocked_rebind || report.bogus_nxdomain {
            Some(15)
        } else if report.malformed_address {
            Some(0)
        } else {
            None
        };
        if let Some(ede) = ede {
            if find_pseudoheader(&packet, false)?.opt.is_some() {
                add_ede(&mut packet, edns_packet_max, do_bit, ede, TCP_LIMIT)?;
            }
        }
    }
    Ok(packet)
}

/// EDE insertion/replacement follows edns0.c::add_pseudoheader, including its
/// strict option-loop bound and relocation of a non-final OPT. Other EDNS
/// decoration is deliberately not inferred from the UDP dispatcher.
pub(super) fn add_ede(
    packet: &mut Vec<u8>,
    max: u16,
    set_do: bool,
    ede: u16,
    limit: usize,
) -> Result<(), WireError> {
    let scan = find_pseudoheader(packet, true)?;
    if scan.signed {
        return Ok(());
    }
    let mut ttl = if set_do { 0x8000u32 } else { 0 };
    let mut options = Vec::new();
    let mut existing_last = None;
    if let Some(opt) = scan.opt {
        ttl |= opt.record.ttl;
        let fixed = opt.record.fixed;
        let mut bytes = opt.record.rdata.to_vec();
        let mut at = 0;
        let mut malformed = false;
        while at + 4 < bytes.len() {
            let code = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
            let length = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
            if at + 4 + length > bytes.len() {
                bytes.clear();
                malformed = true;
                break;
            }
            if code == 15 {
                bytes.drain(at..at + 4 + length);
            } else {
                at += 4 + length;
            }
        }
        if opt.is_last && !malformed {
            bytes.truncate(at);
            existing_last = Some(fixed);
        }
        options = bytes;
        packet[fixed + 2..fixed + 4].copy_from_slice(&max.to_be_bytes());
        packet[fixed + 4..fixed + 8].copy_from_slice(&ttl.to_be_bytes());
        if existing_last.is_none() {
            strip_opt(packet)?;
        }
    }
    options.extend_from_slice(&[0, 15, 0, 2]);
    options.extend_from_slice(&ede.to_be_bytes());
    if let Some(fixed) = existing_last {
        if fixed + 10 + options.len() > limit {
            return Ok(());
        }
        packet.truncate(fixed + 10);
        packet[fixed + 8..fixed + 10].copy_from_slice(&(options.len() as u16).to_be_bytes());
    } else {
        let end = Message::parse(packet)?.end;
        if end + 11 + options.len() > limit {
            return Ok(());
        }
        packet.truncate(end);
        packet.extend_from_slice(&[0, 0, 41]);
        packet.extend_from_slice(&max.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&(options.len() as u16).to_be_bytes());
        let mut header = Header::parse(packet)?;
        header.additionals = header.additionals.checked_add(1).ok_or(WireError::Full)?;
        header.write(packet)?;
    }
    packet.extend_from_slice(&options);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;
    use crate::dns::wire::{Name, PacketWriter, Section};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn query(opt: bool) -> Vec<u8> {
        let mut writer = PacketWriter::new(0x2930, 0x110, 1232).unwrap();
        writer
            .question(&Name::from_ascii("caller.test").unwrap(), 1, 1)
            .unwrap();
        if opt {
            writer
                .record(Section::Additional, &Name::root(), 41, 4096, 0x8000, &[])
                .unwrap();
        }
        writer.finish()
    }

    #[test]
    fn no_route_is_refused_with_not_ready_only_for_edns_clients() {
        let mut config = DnsConfig::default();
        config
            .apply(&lex_line(b"no-resolv").unwrap().unwrap())
            .unwrap();
        let mut service = TcpDnsService::new(&config, &[], 1232).unwrap();
        for with_opt in [false, true] {
            let packet = service
                .handle(
                    &query(with_opt),
                    Instant::now() + Duration::from_secs(2),
                    &|| false,
                )
                .unwrap();
            // Exact C tcp_caller_diff corpus freezes these flags/error fields.
            assert_eq!(Header::parse(&packet).unwrap().flags, 0x8195);
            let opt = find_pseudoheader(&packet, true).unwrap().opt;
            assert_eq!(opt.is_some(), with_opt);
            if let Some(opt) = opt {
                assert_eq!(opt.record.class, 1232);
                assert!(opt.dnssec_ok());
                assert_eq!(
                    opt.options().next().unwrap().unwrap(),
                    (15, [0, 14].as_slice())
                );
            }
        }
    }

    #[test]
    fn forwards_original_tcp_query_and_keeps_c_reply_id_policy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let request = query(false);
        let expected_request = request.clone();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).unwrap();
            let mut packet = vec![0; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut packet).unwrap();
            assert_eq!(packet, expected_request); // No UDP-added empty OPT.
            let mut header = Header::parse(&packet).unwrap();
            header.id = 0xabcd;
            header.flags = 0x8020;
            header.write(&mut packet).unwrap();
            stream
                .write_all(&(packet.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&packet).unwrap();
        });
        let mut config = DnsConfig::default();
        config
            .apply(&lex_line(b"no-resolv").unwrap().unwrap())
            .unwrap();
        config
            .apply(
                &lex_line(format!("server=127.0.0.1#{}", endpoint.port()).as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut service = TcpDnsService::new(&config, &[], 1232).unwrap();
        let packet = service
            .handle(&request, Instant::now() + Duration::from_secs(2), &|| false)
            .unwrap();
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.id, 0xabcd);
        assert_eq!(header.flags, 0x8090); // CD restored, AD cleared, RA set.
        assert_eq!(header.additionals, 0);
        drop(service);
        worker.join().unwrap();
    }

    #[test]
    fn io_exhaustion_returns_network_error_ede() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        drop(listener);
        let config = DnsConfig::default();
        let mut service = TcpDnsService::new(&config, &[endpoint], 1232).unwrap();
        let packet = service
            .handle(
                &query(true),
                Instant::now() + Duration::from_secs(2),
                &|| false,
            )
            .unwrap();
        assert_eq!(Header::parse(&packet).unwrap().rcode(), 5);
        let scan = find_pseudoheader(&packet, false).unwrap();
        assert_eq!(
            scan.opt.unwrap().options().next().unwrap().unwrap(),
            (15, [0, 23].as_slice())
        );
    }
}
