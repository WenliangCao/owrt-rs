use super::*;
use crate::dns::cache::{CacheCounters, EntryId, Policy, Record};
use crate::dns::cache_engine::CacheContext;
use crate::dns::lease_names::LeasePolicy;
use crate::dns::service::LocalDnsService;
use crate::dns::wire::Message;

fn negative_cache(large: bool, alias: bool) -> Cache {
    let terminal = Name::from_ascii("lease.test").unwrap();
    let authority = Name::from_ascii("test").unwrap();
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
                    let mut cache = negative_cache(large, false);
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
    let mut cache = negative_cache(false, false);
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
    let mut cache = negative_cache(false, true);
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
