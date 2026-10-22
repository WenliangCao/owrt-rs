//! Local refusal-to-forward policies, after local records and cached answers.

use super::local::{arpa_address, known_forwarded_domain_with_leases, wire_to_dotted};
use super::routing::RoutingTable;
use super::service::{append_empty_opt, LocalDnsService};
use super::wire::{find_pseudoheader, Header, Name, PacketWriter, Question, WireError};
use crate::config::dns::DnsConfig;

#[derive(Clone, Copy)]
pub(super) struct QueryPolicy {
    domain_needed: bool,
    bogus_priv: bool,
}

impl QueryPolicy {
    pub fn from_config(config: &DnsConfig) -> Self {
        Self {
            domain_needed: config.domain_needed,
            bogus_priv: config.bogus_priv,
        }
    }

    #[cfg(test)]
    pub fn reply(
        self,
        query: &[u8],
        routing: &RoutingTable,
        local: Option<&LocalDnsService>,
        maximum: u16,
        tcp: bool,
    ) -> Result<Option<Vec<u8>>, WireError> {
        self.reply_with_cache(query, routing, local, maximum, tcp, None, false, None)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "UDP and TCP supply distinct envelope, routing cursor and current-cache existence metadata."
    )]
    pub fn reply_with_cache(
        self,
        query: &[u8],
        routing: &RoutingTable,
        local: Option<&LocalDnsService>,
        maximum: u16,
        tcp: bool,
        forward_name: Option<&Name>,
        cached_name: bool,
        events: Option<&mut Vec<crate::query_logging::QueryEvent>>,
    ) -> Result<Option<Vec<u8>>, WireError> {
        let question = Question::parse(query, 12)?;
        let routing_name = forward_name.unwrap_or(&question.name);
        let name = wire_to_dotted(routing_name);
        let private_reverse = self.bogus_priv
            && question.class == 1
            && matches!(question.qtype, 12 | 255)
            && name
                .as_deref()
                .and_then(arpa_address)
                .is_some_and(|address| !super::process::is_allowed_address(address, false))
            && !routing.has_domain_server(routing_name);
        let dotless = self.domain_needed && question.class == 1
            && matches!(question.qtype, 1 | 28 | 255)
            && name.as_ref().is_some_and(|name| !name.is_empty() && !name.contains(&b'.'))
            // tcp_request tests EDE_NOT_READY before OPT_NODOTS_LOCAL.
            && (!tcp || routing.select(routing_name, question.qtype, question.class, false).upstream_group().is_some());
        if !private_reverse && !dotless {
            return Ok(None);
        }
        let known = !private_reverse
            && (cached_name || local.is_some_and(|local| {
                known_forwarded_domain_with_leases(
                    &local.config,
                    &local.hosts,
                    routing_name,
                    &local.leases,
                    super::service::unix_now(),
                )
            }));
        if let Some(events) = events {
            use crate::query_logging::{self as log, QueryEvent};
            if private_reverse {
                if let Some(address) = name.as_deref().and_then(arpa_address) {
                    events.push(QueryEvent::address(
                        log::CONFIG | log::REVERSE | log::NEGATIVE | log::NXDOMAIN,
                        &routing_name.dnsmasq_bytes(),
                        address,
                        None,
                    ));
                }
            } else {
                let family = match question.qtype {
                    1 => log::IPV4,
                    28 => log::IPV6,
                    255 => log::IPV4 | log::IPV6,
                    _ => 0,
                };
                events.push(QueryEvent::label(
                    log::CONFIG | log::NEGATIVE | family | if known { 0 } else { log::NXDOMAIN },
                    &routing_name.dnsmasq_bytes(),
                    None,
                    0,
                ));
            }
        }
        let header = Header::parse(query)?;
        let opt = find_pseudoheader(query, true)
            .ok()
            .and_then(|scan| scan.opt);
        let limit = if tcp {
            usize::from(u16::MAX)
        } else {
            opt.as_ref()
                .map_or(512, |opt| usize::from(opt.udp_size(maximum)))
        };
        let flags = 0x8080
            | (header.flags & 0x0150)
            | if private_reverse { 0x0400 } else { 0 }
            | if known { 0 } else { 3 };
        let mut writer = PacketWriter::new(header.id, flags, limit)?;
        writer.question(&question.name, question.qtype, question.class)?;
        let mut packet = writer.finish();
        if let Some(opt) = opt {
            append_empty_opt(
                &mut packet,
                maximum,
                opt.dnssec_ok() && (tcp || private_reverse),
                if private_reverse && !tcp {
                    usize::from(maximum)
                } else {
                    limit
                },
            )
            .map_err(|_| WireError::Full)?;
        }
        Ok(Some(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;
    use crate::dns::wire::{Message, Name, Section};

    fn setup(lines: &[&[u8]]) -> (QueryPolicy, RoutingTable, LocalDnsService) {
        let mut config = DnsConfig::default();
        for line in lines {
            config.apply(&lex_line(line).unwrap().unwrap()).unwrap();
        }
        let routing =
            RoutingTable::from_runtime_config(&config, &["127.0.0.1:1053".parse().unwrap()])
                .unwrap();
        let policy = QueryPolicy::from_config(&config);
        let hosts = crate::dns::local::configured_hosts(&config, 0);
        (
            policy,
            routing,
            LocalDnsService::new(config, hosts, 0, 1232),
        )
    }

    fn query(name: &str, qtype: u16, class: u16) -> Vec<u8> {
        let mut writer = PacketWriter::new(29, 0x0110, 1232).unwrap();
        writer
            .question(&Name::from_ascii(name).unwrap(), qtype, class)
            .unwrap();
        writer
            .record(Section::Additional, &Name::root(), 41, 1232, 0x8000, &[])
            .unwrap();
        writer.finish()
    }

    #[test]
    fn dotless_known_cache_uses_selected_cursor_and_retains_client_question() {
        let (policy, routing, local) = setup(&[b"domain-needed"]);
        let cursor = Name::from_ascii("terminal").unwrap();
        for tcp in [false, true] {
            for cached_name in [false, true] {
                for alias in [false, true] {
                    let query = query(if alias { "alias.test" } else { "terminal" }, 28, 1);
                    let packet = policy.reply_with_cache(
                        &query, &routing, Some(&local), 1232, tcp,
                        alias.then_some(&cursor), cached_name, None,
                    ).unwrap().unwrap();
                    assert_eq!(Header::parse(&packet).unwrap().rcode(), if cached_name { 0 } else { 3 });
                    assert_eq!(Question::parse(&packet, 12).unwrap(), Question::parse(&query, 12).unwrap());
                }
            }
        }
    }

    #[test]
    fn dotless_address_queries_stop_after_local_or_cache_miss() {
        let (policy, routing, local) = setup(&[b"domain-needed", b"host-record=known,192.0.2.1"]);
        for qtype in [1, 28, 255] {
            for tcp in [false, true] {
                let packet = policy
                    .reply(
                        &query("missing", qtype, 1),
                        &routing,
                        Some(&local),
                        1232,
                        tcp,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(Header::parse(&packet).unwrap().flags, 0x8193);
                assert_eq!(
                    find_pseudoheader(&packet, true)
                        .unwrap()
                        .opt
                        .unwrap()
                        .dnssec_ok(),
                    tcp
                );
            }
        }
        let packet = policy
            .reply(&query("known", 28, 1), &routing, Some(&local), 1232, false)
            .unwrap()
            .unwrap();
        assert_eq!(Header::parse(&packet).unwrap().rcode(), 0);
        for (name, qtype, class) in [
            ("missing", 16, 1),
            ("missing.test", 1, 1),
            ("", 1, 1),
            ("missing", 1, 3),
        ] {
            assert!(policy
                .reply(
                    &query(name, qtype, class),
                    &routing,
                    Some(&local),
                    1232,
                    false
                )
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn private_reverse_preserves_do_and_specific_server_exception() {
        let (policy, routing, local) =
            setup(&[b"bogus-priv", b"server=/168.192.in-addr.arpa/127.0.0.2"]);
        for name in [
            "1.0.0.10.in-addr.arpa",
            "1.0.64.100.in-addr.arpa",
            "1.2.0.192.in-addr.arpa",
        ] {
            let packet = policy
                .reply(&query(name, 12, 1), &routing, Some(&local), 1232, false)
                .unwrap()
                .unwrap();
            assert_eq!(Header::parse(&packet).unwrap().flags, 0x8593);
            assert_eq!(Message::parse(&packet).unwrap().header.answers, 0);
            assert!(find_pseudoheader(&packet, true)
                .unwrap()
                .opt
                .unwrap()
                .dnssec_ok());
        }
        for name in ["1.1.168.192.in-addr.arpa", "8.8.8.8.in-addr.arpa"] {
            assert!(policy
                .reply(&query(name, 12, 1), &routing, Some(&local), 1232, false)
                .unwrap()
                .is_none());
        }
    }
}
