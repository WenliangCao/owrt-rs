use super::*;
use crate::dns::cache::{CacheCounters, EntryId, Policy, Record};
use crate::dns::cache_engine::CacheContext;
use crate::dns::lease_names::LeasePolicy;
use crate::dns::service::LocalDnsService;
use crate::dns::wire::Message;

fn negative_cache(owner: &str, zone: &str, large: bool, alias: bool) -> Cache {
    let terminal = Name::from_ascii(owner).unwrap();
    let authority = Name::from_ascii(zone).unwrap();
    let mut cache = Cache::new(8, Policy::default());
    cache.start_insert();
    let cname: Option<EntryId> = alias.then(|| {
        cache
            .insert(
                Record {
                    name: Name::from_ascii("alias.test").unwrap(),
                    kind: Kind::Cname,
                    negative: false,
                    data: terminal.as_wire().to_vec(),
                },
                100,
                600,
            )
            .unwrap()
    });
    let negative = cache
        .insert(
            Record {
                name: terminal,
                kind: Kind::NxDomain,
                negative: true,
                data: vec![],
            },
            100,
            600,
        )
        .unwrap();
    if let Some(cname) = cname {
        assert!(cache.set_cname_target(cname, negative));
    }
    assert!(cache.set_negative_authority(negative, authority.clone()));
    let mut soa = Vec::new();
    for prefix in ['n', 'r'] {
        let name = if large {
            [
                prefix.to_string().repeat(63),
                prefix.to_string().repeat(63),
                prefix.to_string().repeat(63),
                prefix.to_string().repeat(61),
            ]
            .join(".")
        } else {
            format!("{prefix}.test")
        };
        soa.extend_from_slice(Name::from_ascii(&name).unwrap().as_wire());
    }
    for value in [1u32, 60, 60, 600, 600] {
        soa.extend_from_slice(&value.to_be_bytes());
    }
    cache
        .insert(
            Record {
                name: authority,
                kind: Kind::Generic(6),
                negative: false,
                data: soa,
            },
            100,
            600,
        )
        .unwrap();
    assert!(cache.commit());
    cache
}

fn publish(hosts: &mut Hosts, cache: &mut Cache) -> Arc<LeaseNames> {
    Arc::new(LeaseNames::build(
        &[crate::dhcp::persistence::DnsLeaseRecord {
            name: b"lease.test",
            address: Ipv4Addr::new(192, 0, 2, 8),
            expires: Some(700),
        }],
        hosts,
        &[],
        LeasePolicy {
            dhcp_ttl: Some(5),
            ..Default::default()
        },
        cache,
    ))
}

fn request(host: &str, kind: u16, rd: bool, dnssec: bool) -> Vec<u8> {
    let mut writer = PacketWriter::new(7, if rd { 0x100 } else { 0 }, 1232).unwrap();
    writer
        .question(&Name::from_ascii(host).unwrap(), kind, 1)
        .unwrap();
    if dnssec {
        writer
            .record_wire(Section::Additional, &[0], 41, 512, 0x8000, &[])
            .unwrap();
    }
    writer.finish()
}

#[test]
fn dhcp_positive_retains_nxdomain_soa_independently_of_rd_and_do() {
    for large in [false, true] {
        for limit in [512, 1232] {
            for rd in [false, true] {
                for dnssec in [false, true] {
                    let mut cache = negative_cache("lease.test", "test", large, false);
                    let mut hosts = Hosts::new();
                    let mut leases = publish(&mut hosts, &mut cache);
                    assert!(cache.has_nxdomain(&Name::from_ascii("lease.test").unwrap(), 110));
                    let config = DnsConfig::default();
                    let answer = LocalAnswerer {
                        config: &config,
                        hosts: &mut hosts,
                        local_ttl: 37,
                        max_packet: limit,
                    }
                    .answer_on_network_with_cache(
                        &request("lease.test", 1, rd, dnssec),
                        &mut leases,
                        110,
                        None,
                        Some(&mut cache),
                    )
                    .unwrap()
                    .unwrap();
                    let message = Message::parse(&answer.packet).unwrap();
                    assert_eq!(message.header.rcode(), 0);
                    assert_eq!(
                        message.header.flags & 0x500,
                        0x400 | if rd { 0x100 } else { 0 }
                    );
                    if large && limit == 512 {
                        assert_ne!(message.header.flags & 0x200, 0);
                        assert_eq!((message.header.answers, message.header.authorities), (0, 0));
                    } else {
                        assert_eq!((message.header.answers, message.header.authorities), (1, 1));
                        let address = message.records(Section::Answer).next().unwrap();
                        assert_eq!(
                            (address.rrtype, address.ttl, address.rdata),
                            (1, 5, &[192, 0, 2, 8][..])
                        );
                        let soa = message.records(Section::Authority).next().unwrap();
                        assert_eq!((soa.rrtype, soa.ttl), (6, 590));
                    }
                }
            }
        }
    }
}

#[test]
fn configured_answers_keep_negative_authority_before_mail_additional() {
    let mut config = DnsConfig::default();
    for line in [
        "txt-record=lease.test,hello",
        "dns-rr=lease.test,65401,abcd",
        "mx-host=lease.test,mail.test",
        "host-record=mail.test,192.0.2.9",
    ] {
        config
            .apply(&crate::config::lex_line(line.as_bytes()).unwrap().unwrap())
            .unwrap();
    }
    let mut hosts = configured_hosts(&config, 37);
    let mut cache = negative_cache("lease.test", "test", false, false);
    for kind in [16, 65401, 15] {
        let answer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 1232,
        }
        .answer_on_network_with_cache(
            &request("lease.test", kind, true, false),
            &mut Arc::new(LeaseNames::default()),
            110,
            None,
            Some(&mut cache),
        )
        .unwrap()
        .unwrap();
        let message = Message::parse(&answer.packet).unwrap();
        assert_eq!((message.header.answers, message.header.authorities), (1, 1));
        assert_eq!(
            message.records(Section::Answer).next().unwrap().rrtype,
            kind
        );
        assert_eq!(
            message.records(Section::Authority).next().unwrap().rrtype,
            6
        );
        assert_eq!(message.header.additionals, u16::from(kind == 15));
    }
}

#[test]
fn cached_cname_to_dhcp_address_appends_the_retained_soa_once() {
    let mut cache = negative_cache("lease.test", "test", false, true);
    let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 37, 1232);
    local.leases = publish(&mut local.hosts, &mut cache);
    let mut counters = CacheCounters::default();
    let packet = request("alias.test", 1, true, false);
    let question = crate::dns::forward::Question::parse(&packet).unwrap();
    let answer = CacheContext {
        cache: &mut cache,
        counters: &mut counters,
        negative_cache: true,
        negative_ttl: 600,
        filter_rr: &[],
    }
    .answer_tcp(
        &packet,
        Header::parse(&packet).unwrap(),
        &question,
        110,
        &mut local,
        1232,
    )
    .unwrap()
    .packet
    .unwrap();
    let message = Message::parse(&answer).unwrap();
    assert_eq!((message.header.answers, message.header.authorities), (2, 1));
    assert_eq!(
        message
            .records(Section::Answer)
            .map(|record| record.rrtype)
            .collect::<Vec<_>>(),
        [5, 1]
    );
}

#[test]
fn reverse_synthesis_does_not_attach_the_previous_arpa_soa() {
    let reverse = "7.2.0.192.in-addr.arpa";
    for alias in [false, true] {
        for qtype in [12, 255] {
            for explicit in [false, true] {
                let mut config = DnsConfig::default();
                for line in [
                    "synth-domain=synthetic.test,192.0.2.7,192.0.2.9",
                    "cname=alias.test,7.2.0.192.in-addr.arpa",
                ] {
                    config
                        .apply(&crate::config::lex_line(line.as_bytes()).unwrap().unwrap())
                        .unwrap();
                }
                if explicit {
                    config
                        .apply(
                            &crate::config::lex_line(
                                b"ptr-record=7.2.0.192.in-addr.arpa,explicit.test",
                            )
                            .unwrap()
                            .unwrap(),
                        )
                        .unwrap();
                }
                let mut hosts = configured_hosts(&config, 37);
                let mut cache = negative_cache(reverse, "2.0.192.in-addr.arpa", false, false);
                let answer = LocalAnswerer {
                    config: &config,
                    hosts: &mut hosts,
                    local_ttl: 37,
                    max_packet: 1232,
                }
                .answer_on_network_with_cache(
                    &request(
                        if alias { "alias.test" } else { reverse },
                        qtype,
                        true,
                        false,
                    ),
                    &mut Arc::new(LeaseNames::default()),
                    110,
                    None,
                    Some(&mut cache),
                )
                .unwrap()
                .unwrap();
                let message = Message::parse(&answer.packet).unwrap();
                assert_eq!(
                    message.header.answers,
                    1 + u16::from(alias) + u16::from(qtype == 255 && !explicit)
                );
                assert_eq!(
                    message.header.authorities,
                    u16::from(explicit),
                    "alias={alias} qtype={qtype} explicit={explicit}"
                );
            }
        }
    }
}

#[test]
fn configured_cname_question_stops_before_the_targets_negative_soa() {
    let mut config = DnsConfig::default();
    config
        .apply(
            &crate::config::lex_line(b"cname=alias.test,lease.test")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    let mut hosts = configured_hosts(&config, 37);
    let mut cache = negative_cache("lease.test", "test", false, false);
    let mut leases = publish(&mut hosts, &mut cache);
    for qtype in [5, 1] {
        let answer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 1232,
        }
        .answer_on_network_with_cache(
            &request("alias.test", qtype, true, false),
            &mut leases,
            110,
            None,
            Some(&mut cache),
        )
        .unwrap()
        .unwrap();
        let message = Message::parse(&answer.packet).unwrap();
        assert_eq!(message.header.answers, if qtype == 5 { 1 } else { 2 });
        assert_eq!(message.header.authorities, u16::from(qtype != 5));
    }
}

#[test]
fn raw_cname_rdata_does_not_change_the_negative_authority_cursor() {
    let target = Name::from_ascii("lease.test").unwrap();
    for (data, negative) in [
        (&[0xc0, 0x0c][..], None),
        (target.as_wire(), Some("lease.test")),
        (target.as_wire(), Some("raw.test")),
    ] {
        let hex = data
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut config = DnsConfig::default();
        config
            .apply(
                &crate::config::lex_line(format!("dns-rr=raw.test,5,{hex}").as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut hosts = configured_hosts(&config, 37);
        let mut cache = negative.map_or_else(
            || Cache::new(8, Policy::default()),
            |owner| negative_cache(owner, "test", false, false),
        );
        let answer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 1232,
        }
        .answer_on_network_with_cache(
            &request("raw.test", 255, true, false),
            &mut Arc::new(LeaseNames::default()),
            110,
            None,
            Some(&mut cache),
        )
        .unwrap()
        .unwrap();
        let message = Message::parse(&answer.packet).unwrap();
        assert_eq!(message.header.answers, 1);
        assert_eq!(message.records(Section::Answer).next().unwrap().rdata, data);
        assert_eq!(
            message.header.authorities,
            u16::from(negative == Some("raw.test"))
        );
    }
}

#[test]
fn unrepresentable_configured_cname_target_does_not_fail_the_optional_footer() {
    for (target, negative, zone) in [
        ("a..b", "lease.test", "test"),
        ("lease.test..", "lease.test", "test"),
        ("..", "", ""),
    ] {
        let mut config = DnsConfig::default();
        config
            .apply(
                &crate::config::lex_line(format!("cname=alias.test,{target}").as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut hosts = configured_hosts(&config, 37);
        let mut cache = negative_cache(negative, zone, false, false);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 1232,
        };
        let mut leases = Arc::new(LeaseNames::default());
        let query = request("alias.test", 1, true, false);
        let uncached = answerer
            .answer_on_network_with_cache(&query, &mut leases, 110, None, None)
            .unwrap()
            .unwrap()
            .packet;
        let cached = answerer
            .answer_on_network_with_cache(&query, &mut leases, 110, None, Some(&mut cache))
            .unwrap()
            .unwrap()
            .packet;
        assert_eq!(cached, uncached, "target={target}");
    }
}
