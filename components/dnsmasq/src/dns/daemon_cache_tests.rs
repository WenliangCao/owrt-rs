//! Frozen-clock cache caller regressions. Expected protocol fields come from
//! exact dnsmasq 2.93 `extract_addresses` / `answer_request`, not this writer.

use super::*;

fn daemon() -> DnsDaemon {
    let mut config = DnsConfig::default();
    config.no_resolv = true;
    let mut daemon = DnsDaemon::new(config, Hosts::new(), &[], DaemonOptions::default()).unwrap();
    daemon.enable_cache(150, 0, 0, StalePolicy::Disabled);
    daemon.enable_negative_cache(30, true);
    daemon
}

fn packet(name: &str, qtype: u16, flags: u16) -> PacketWriter {
    let mut writer = PacketWriter::new(0x1234, flags, 65535).unwrap();
    writer
        .question(&Name::from_ascii(name).unwrap(), qtype, 1)
        .unwrap();
    writer
}

fn chain_reply(qtype: u16, negative: bool) -> Vec<u8> {
    let mut writer = packet("alias.test", qtype, if negative { 0x8183 } else { 0x8180 });
    for (owner, target, ttl) in [
        ("alias.test", "middle.test", 60),
        ("middle.test", "target.test", 50),
    ] {
        writer
            .record(
                Section::Answer,
                &Name::from_ascii(owner).unwrap(),
                5,
                1,
                ttl,
                Name::from_ascii(target).unwrap().as_wire(),
            )
            .unwrap();
    }
    if !negative {
        writer
            .record(
                Section::Answer,
                &Name::from_ascii("target.test").unwrap(),
                1,
                1,
                40,
                &[192, 0, 2, 1],
            )
            .unwrap();
    }
    writer.finish()
}

fn cached(daemon: &mut DnsDaemon, name: &str, qtype: u16, now: i64) -> Option<Vec<u8>> {
    let query = packet(name, qtype, 0x100).finish();
    let question = super::super::forward::Question::parse(&query).unwrap();
    daemon.cached_answer_at(&query, &question, now).unwrap()
}

fn cached_details(
    daemon: &mut DnsDaemon,
    name: &str,
    qtype: u16,
    now: i64,
) -> Option<CachedAnswer> {
    let query = packet(name, qtype, 0x100).finish();
    let question = super::super::forward::Question::parse(&query).unwrap();
    let answer = daemon
        .cached_answer_at_with_local(&query, &question, now, None)
        .unwrap();
    answer.packet.is_some().then_some(answer)
}

fn shared_answer(daemon: &mut DnsDaemon, query: &[u8], now: i64, tcp: bool) -> Option<Vec<u8>> {
    let header = Header::parse(query).unwrap();
    let question = super::super::forward::Question::parse_with_header(query, header).unwrap();
    DnsDaemon::<OsRandom>::answer_local_or_cached(
        daemon.cache.as_mut(),
        query,
        header,
        &question,
        &mut daemon.local,
        now,
        true,
        tcp,
    )
    .unwrap()
    .answer
    .map(|answer| match answer {
        QueryResult::Local(packet) | QueryResult::Cached(packet) | QueryResult::Stale(packet) => {
            packet
        }
        _ => panic!("answer lookup cannot forward a query"),
    })
}

#[test]
fn cached_local_shortcut_keeps_same_name_hosts_raw_and_rule_precedence() {
    use super::super::cache::{Kind, Record};
    use std::sync::Arc;
    for rrtype in [1, 28] {
        for tcp in [false, true] {
            for mode in [
                "none",
                "host",
                "raw",
                "literal",
                "local-only",
                "configured-cname",
            ] {
                let mut daemon = daemon();
                let address = if rrtype == 1 {
                    "192.0.2.9"
                } else {
                    "2001:db8::9"
                };
                let directives = match mode {
                    "host" => vec![format!("host-record=coexist.test,{address}")],
                    "raw" => vec![format!(
                        "dns-rr=coexist.test,{rrtype},{}",
                        if rrtype == 1 {
                            "c0000209"
                        } else {
                            "20010db8000000000000000000000009"
                        }
                    )],
                    "literal" => vec![format!("address=/coexist.test/{address}")],
                    "local-only" => vec!["local=/coexist.test/".to_owned()],
                    "configured-cname" => vec![
                        "cname=coexist.test,target.test".to_owned(),
                        format!("host-record=target.test,{address}"),
                    ],
                    _ => Vec::new(),
                };
                for line in directives {
                    Arc::make_mut(&mut daemon.local.config)
                        .apply(&crate::config::lex_line(line.as_bytes()).unwrap().unwrap())
                        .unwrap();
                }
                daemon.local.hosts =
                    super::super::local::configured_hosts(&daemon.local.config, 60);
                daemon.local.query_logging = true;
                let data = if rrtype == 1 {
                    vec![192, 0, 2, 7]
                } else {
                    "2001:db8::7"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec()
                };
                let kind = if rrtype == 1 { Kind::Ipv4 } else { Kind::Ipv6 };
                let cache = daemon.cache.as_mut().unwrap();
                cache.start_insert();
                cache
                    .insert(
                        Record {
                            name: Name::from_ascii("coexist.test").unwrap(),
                            kind,
                            negative: false,
                            data: data.clone(),
                        },
                        100,
                        300,
                    )
                    .unwrap();
                assert!(cache.commit());
                let query = packet("coexist.test", rrtype, 0x100).finish();
                let header = Header::parse(&query).unwrap();
                let question =
                    super::super::forward::Question::parse_with_header(&query, header).unwrap();
                let (_, hint) = cache.inspect_name(&question.name, 100);
                assert!(cache
                    .single_fresh_address_id_with_hint(&question.name, kind, 100, hint.as_ref())
                    .is_some());
                let answer = DnsDaemon::<OsRandom>::answer_local_or_cached(
                    daemon.cache.as_mut(),
                    &query,
                    header,
                    &question,
                    &mut daemon.local,
                    100,
                    true,
                    tcp,
                )
                .unwrap()
                .answer
                .unwrap();
                let local = matches!(mode, "host" | "raw" | "configured-cname");
                assert_eq!(
                    matches!(&answer, QueryResult::Local(_)),
                    local,
                    "{mode}/{rrtype}/{tcp}"
                );
                let response = match answer {
                    QueryResult::Local(p) | QueryResult::Cached(p) => p,
                    _ => panic!("unexpected answer"),
                };
                let message = Message::parse(&response).unwrap();
                let address_record = message
                    .records(Section::Answer)
                    .find(|rr| rr.rrtype == rrtype)
                    .unwrap();
                let expected = if local {
                    if rrtype == 1 {
                        vec![192, 0, 2, 9]
                    } else {
                        "2001:db8::9"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets()
                            .to_vec()
                    }
                } else {
                    data
                };
                assert_eq!(address_record.rdata, expected);
                assert!(
                    !daemon.local.take_query_events().is_empty(),
                    "logging remains in the selected original answer owner"
                );
            }
        }
    }
}

#[test]
fn cached_local_shortcut_expires_live_lease_before_cache_and_clock_rollback() {
    use super::super::cache::{Kind, Record};
    use super::super::lease_names::{LeaseNames, LeasePolicy};
    use crate::dhcp::persistence::DnsLeaseRecord;
    use std::sync::Arc;
    for tcp in [false, true] {
        let mut daemon = daemon();
        daemon.local.leases = Arc::new(LeaseNames::build(
            &[DnsLeaseRecord {
                name: b"coexist.test",
                address: "192.0.2.9".parse().unwrap(),
                expires: Some(150),
            }],
            &mut daemon.local.hosts,
            &[],
            LeasePolicy::default(),
            &mut (),
        ));
        let cache = daemon.cache.as_mut().unwrap();
        cache.start_insert();
        cache
            .insert(
                Record {
                    name: Name::from_ascii("coexist.test").unwrap(),
                    kind: Kind::Ipv4,
                    negative: false,
                    data: vec![192, 0, 2, 7],
                },
                100,
                300,
            )
            .unwrap();
        assert!(cache.commit());
        let query = packet("coexist.test", 1, 0x100).finish();
        for (now, last) in [(100, 9), (160, 7), (100, 7)] {
            let response = shared_answer(&mut daemon, &query, now, tcp).unwrap();
            let message = Message::parse(&response).unwrap();
            assert_eq!(
                message
                    .records(Section::Answer)
                    .find(|rr| rr.rrtype == 1)
                    .unwrap()
                    .rdata,
                [192, 0, 2, last]
            );
        }
        assert!(daemon
            .local
            .leases
            .lookup(b"coexist.test", 100)
            .next()
            .is_none());
    }
}

#[test]
fn shared_lookup_checks_cached_terminal_before_local_forward_rules() {
    for directive in ["local=/test/", "address=/test/203.0.113.9"] {
        let mut daemon = daemon();
        std::sync::Arc::make_mut(&mut daemon.local.config)
            .apply(
                &crate::config::lex_line(directive.as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        daemon.cache_reply_at(&chain_reply(1, false), 100);
        let target = Name::from_ascii("target.test").unwrap();
        assert!(daemon
            .cache
            .as_ref()
            .unwrap()
            .contains_forward_name(&target, 100));
        for tcp in [false, true] {
            for qtype in if directive.starts_with("local=") {
                &[1, 28][..]
            } else {
                &[1][..]
            } {
                let qtype = *qtype;
                let response = shared_answer(
                    &mut daemon,
                    &packet("target.test", qtype, 0x100).finish(),
                    100,
                    tcp,
                )
                .unwrap();
                let message = Message::parse(&response).unwrap();
                assert_eq!(message.header.flags, 0x8180);
                let records = message.records(Section::Answer).collect::<Vec<_>>();
                if qtype == 1 {
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0].rdata, &[192, 0, 2, 1]);
                    assert_eq!(records[0].ttl, 40);
                } else {
                    assert!(records.is_empty());
                }
            }
        }
        // Expiration removes the existence proof; no stale NODATA survives.
        if directive.starts_with("local=") {
            for tcp in [false, true] {
                let response = shared_answer(
                    &mut daemon,
                    &packet("target.test", 28, 0x100).finish(),
                    141,
                    tcp,
                )
                .unwrap();
                assert_eq!(Header::parse(&response).unwrap().rcode(), 3);
            }
        }
    }
}

#[test]
fn shared_lookup_preserves_cname_cursor_for_tcp_forward_rules_only() {
    for (directive, expected_types) in [
        ("local=/target.test/", &[][..]),
        ("address=/target.test/2001:db8::9", &[28][..]),
    ] {
        let mut daemon = daemon();
        std::sync::Arc::make_mut(&mut daemon.local.config)
            .apply(
                &crate::config::lex_line(directive.as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        daemon.cache_reply_at(&chain_reply(1, false), 100);
        for tcp in [false, true] {
            let query = packet("alias.test", 28, 0x100).finish();
            let header = Header::parse(&query).unwrap();
            let question =
                super::super::forward::Question::parse_with_header(&query, header).unwrap();
            let lookup = DnsDaemon::<OsRandom>::answer_local_or_cached(
                daemon.cache.as_mut(),
                &query,
                header,
                &question,
                &mut daemon.local,
                100,
                true,
                tcp,
            )
            .unwrap();
            if tcp {
                assert_eq!(
                    lookup.forward_name,
                    Some(ForwardName {
                        name: Name::from_ascii("target.test").unwrap(),
                        cached: true
                    })
                );
                let Some(QueryResult::Local(response)) = lookup.answer else {
                    panic!("TCP terminal rule missed");
                };
                let message = Message::parse(&response).unwrap();
                assert_eq!(
                    message.header.flags,
                    if expected_types.is_empty() {
                        0x8180
                    } else {
                        0x8580
                    }
                );
                assert_eq!(
                    super::super::forward::Question::parse(&response)
                        .unwrap()
                        .name,
                    question.name
                );
                assert_eq!(
                    message
                        .records(Section::Answer)
                        .map(|rr| rr.rrtype)
                        .collect::<Vec<_>>(),
                    expected_types
                );
                for rr in message.records(Section::Answer) {
                    assert_eq!(rr.name().unwrap(), question.name);
                    assert_eq!(
                        rr.rdata,
                        "2001:db8::9"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets()
                    );
                }
            } else {
                assert!(lookup.answer.is_none());
                assert!(lookup.forward_name.is_none());
            }
        }
    }
}

#[test]
fn shared_lookup_keeps_udp_tcp_cname_local_cache_order_and_rd_do_gates() {
    for negative in [false, true] {
        let mut daemon = daemon();
        for directive in [
            "filterwin2k",
            "no-round-robin",
            "txt-record=alias.test,alias-local",
            "txt-record=target.test,target-local",
            "mx-host=target.test,mail.test,10",
            "srv-host=target.test,mail.test,8443,10,0",
            "dns-rr=target.test,65401,abcd",
            "host-record=mail.test,192.0.2.80",
        ] {
            std::sync::Arc::make_mut(&mut daemon.local.config)
                .apply(
                    &crate::config::lex_line(directive.as_bytes())
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
        }
        daemon.local.hosts = super::super::local::configured_hosts(&daemon.local.config, 0);
        daemon.cache_reply_at(&chain_reply(1, negative), 100);
        for qtype in [1, 5, 6, 15, 16, 33, 255, 65401] {
            for rd in [false, true] {
                for do_bit in [false, true] {
                    let mut query = packet("alias.test", qtype, if rd { 0x100 } else { 0 });
                    query
                        .record(
                            Section::Additional,
                            &Name::root(),
                            41,
                            1232,
                            if do_bit { 0x8000 } else { 0 },
                            &[],
                        )
                        .unwrap();
                    let query = query.finish();
                    let udp = shared_answer(&mut daemon, &query, 101, false);
                    let tcp = shared_answer(&mut daemon, &query, 101, true);
                    assert_eq!(
                        udp, tcp,
                        "qtype={qtype}, negative={negative}, RD={rd}, DO={do_bit}"
                    );
                    if do_bit || !rd {
                        assert!(tcp.is_none(), "unsigned cached CNAME must be forwarded");
                    } else if matches!(qtype, 15 | 16 | 33 | 65401) {
                        let answer = tcp.unwrap();
                        let message = Message::parse(&answer).unwrap();
                        let types = message
                            .records(Section::Answer)
                            .map(|rr| rr.rrtype)
                            .collect::<Vec<_>>();
                        assert_eq!(types, [5, 5, qtype]);
                        if qtype == 16 {
                            assert_eq!(
                                message.records(Section::Answer).last().unwrap().rdata,
                                b"\x0ctarget-local"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn cached_cname_raw_terminal_copies_rdata_pointers_opaquely() {
    // rfc1035.c writes dns-rr data unchanged; a pointer refers to the final
    // reply, never to the scratch packet used to evaluate the terminal.
    for data in ["c00c", "c02b"] {
        let mut daemon = daemon();
        let directive = format!("dns-rr=target.test,2,{data}");
        std::sync::Arc::make_mut(&mut daemon.local.config)
            .apply(
                &crate::config::lex_line(directive.as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        daemon.cache_reply_at(&chain_reply(1, false), 100);
        let query = packet("alias.test", 2, 0x100).finish();
        let udp = shared_answer(&mut daemon, &query, 101, false);
        let tcp = shared_answer(&mut daemon, &query, 101, true);
        assert_eq!(udp, tcp, "data={data}");
        let answer = tcp.expect("the configured NS terminates the cached alias");
        let message = Message::parse(&answer).unwrap();
        let last = message.records(Section::Answer).last().unwrap();
        assert_eq!(last.rrtype, 2);
        assert_eq!(last.rdata, [0xc0, if data == "c00c" { 0x0c } else { 0x2b }]);
    }
}

#[test]
fn cached_cname_raw_cname_terminals_keep_c_owner_layout() {
    // Raw TYPE 5 data never moves C's name cursor, so every raw owner stays a
    // pointer to the terminal and C's absolute RDATA pointer stays valid.
    // C emits raw RRs in reverse declaration order: the pointer comes last.
    let configured = |pointer: &str| {
        let mut daemon = daemon();
        for directive in [format!("dns-rr=target.test,5,{pointer}")]
            .into_iter()
            .chain(std::iter::repeat_n(
                "dns-rr=target.test,5,056f74686572047465737400".into(),
                3,
            ))
        {
            std::sync::Arc::make_mut(&mut daemon.local.config)
                .apply(
                    &crate::config::lex_line(directive.as_bytes())
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
        }
        daemon.cache_reply_at(&chain_reply(1, false), 100);
        daemon
    };
    let query = packet("alias.test", 255, 0x100).finish();
    // A same-length placeholder fixes the layout before choosing the pointer.
    let probe = shared_answer(&mut configured("c00c"), &query, 101, true)
        .expect("raw CNAMEs terminate the cached alias");
    let other = probe
        .windows(7)
        .position(|w| w == b"\x05other\x04")
        .unwrap();
    let mut daemon = configured(&format!("{:04x}", 0xc000 | other));
    let udp = shared_answer(&mut daemon, &query, 101, false);
    let tcp = shared_answer(&mut daemon, &query, 101, true);
    assert_eq!(udp, tcp);
    let answer = tcp.unwrap();
    let message = Message::parse(&answer).unwrap();
    let cnames: Vec<_> = message
        .records(Section::Answer)
        .filter(|rr| rr.rrtype == 5)
        .collect();
    assert!(cnames.len() >= 4);
    let raw = &cnames[cnames.len() - 4..];
    let owner = &answer[raw[0].start..raw[0].start + 2];
    assert_eq!(
        owner[0] & 0xc0,
        0xc0,
        "raw owners are pointers, as C writes them"
    );
    for rr in raw {
        assert_eq!(
            &answer[rr.start..rr.fixed],
            owner,
            "raw TYPE 5 must not move the cursor"
        );
        assert_eq!(
            rr.rdata_name(0).unwrap().0,
            Name::from_ascii("other.test").unwrap()
        );
    }
}

#[test]
fn cached_cname_terminal_owner_past_pointer_range_uses_full_name() {
    // A large TCP answer can place the MX target beyond 0x3fff, where a
    // compression pointer cannot reach; C still returns a complete answer.
    let mut daemon = daemon();
    let mut directives = vec![
        "host-record=example,192.0.2.20".to_string(),
        "mx-host=target.test,example,10".to_string(),
    ];
    directives.extend((0..60).map(|i| format!("txt-record=target.test,{i:03}{}", "x".repeat(252))));
    directives.push(format!("txt-record=target.test,{}", "z".repeat(220)));
    for directive in &directives {
        std::sync::Arc::make_mut(&mut daemon.local.config)
            .apply(
                &crate::config::lex_line(directive.as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
    }
    daemon.local.hosts = super::super::local::configured_hosts(&daemon.local.config, 0);
    daemon.cache_reply_at(&chain_reply(1, false), 100);
    let answer = shared_answer(
        &mut daemon,
        &packet("alias.test", 255, 0x100).finish(),
        101,
        true,
    )
    .expect("the large local terminal still answers over TCP");
    assert!(answer.len() > 0x4000);
    let message = Message::parse(&answer).unwrap();
    let additional: Vec<_> = message.records(Section::Additional).collect();
    assert_eq!(additional.len(), 1);
    assert_eq!(
        additional[0].name().unwrap(),
        Name::from_ascii("example").unwrap()
    );
}

#[test]
fn reply_known_name_uses_live_cache_or_connection_snapshot() {
    let mut daemon = daemon();
    let forward =
        super::super::tcp_service::TcpDnsService::new(&daemon.local.config, &[], 1232).unwrap();
    let query = packet("alias.test", 6, 0x100).finish();
    let cold = daemon.tcp_cache_view();
    daemon.cache_reply_at(&chain_reply(1, true), 100);
    let warm = daemon.tcp_cache_view();
    daemon.cache.as_mut().unwrap().clear();
    for (cache, now, known) in [
        (cold.as_ref(), 101, false),
        (warm.as_ref(), 101, true),
        (daemon.current_cache(), 101, false),
        (warm.as_ref(), 161, false),
    ] {
        let cached = forward.cached_query_name(Some(&query), cache, now);
        assert_eq!(cached, known);
        let mut reply = packet("alias.test", 6, 0x8183).finish();
        super::super::reply::apply_known_local_nxdomain(&mut reply, 3, |name| {
            super::super::reply::known_name(
                name,
                Some(&daemon.local),
                Some(&daemon.routing),
                cached,
                now,
            )
        })
        .unwrap();
        assert_eq!(
            Header::parse(&reply).unwrap().rcode(),
            if known { 0 } else { 3 }
        );
    }
}

#[test]
fn cached_cname_local_terminal_uses_the_current_query_network() {
    let mut daemon = daemon();
    std::sync::Arc::make_mut(&mut daemon.local.config).localise_queries = true;
    std::sync::Arc::make_mut(&mut daemon.local.config).no_round_robin = true;
    for address in ["192.0.2.1", "198.51.100.3"] {
        daemon
            .local
            .hosts
            .insert(b"target.test".to_vec(), address.parse().unwrap(), 0, 1);
    }
    daemon.cache_reply_at(&chain_reply(1, false), 100);
    for (network, expected) in [
        (Some("192.0.2.254"), vec![vec![192, 0, 2, 1]]),
        (Some("198.51.100.254"), vec![vec![198, 51, 100, 3]]),
        (None, vec![vec![192, 0, 2, 1], vec![198, 51, 100, 3]]),
    ] {
        daemon.local.local_network =
            network.map(|address| (address.parse().unwrap(), "255.255.255.0".parse().unwrap()));
        let answer = cached(&mut daemon, "alias.test", 1, 100).unwrap();
        let message = Message::parse(&answer).unwrap();
        let addresses = message
            .records(Section::Answer)
            .filter(|record| record.rrtype == 1)
            .map(|record| record.rdata.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(addresses, expected);
    }
}

#[test]
fn cached_cname_precedes_alias_local_txt_with_the_cache_expiry_policy() {
    for (stale, now, follows_cname) in [
        (StalePolicy::Disabled, 101, true),
        (StalePolicy::Disabled, 161, false),
        (StalePolicy::Seconds(30), 161, true),
        (StalePolicy::Seconds(30), 191, false),
        (StalePolicy::Forever, 191, true),
    ] {
        let mut daemon = daemon();
        daemon.enable_cache(32, 0, 0, stale);
        std::sync::Arc::make_mut(&mut daemon.local.config)
            .cache_rr
            .push(16);
        std::sync::Arc::make_mut(&mut daemon.local.config)
            .records
            .txt
            .push(crate::config::records::RawRecord {
                name: b"alias.test".to_vec(),
                rr_type: 16,
                data: b"\x0balias-local".to_vec(),
            });
        daemon.cache_reply_at(&chain_reply(1, false), 100);
        let mut txt = packet("target.test", 16, 0x8180);
        txt.record_at(Section::Answer, 12, 16, 1, 600, b"\x0ftarget-upstream")
            .unwrap();
        daemon.cache_reply_at(&txt.finish(), 100);
        let query = packet("alias.test", 16, 0x100).finish();
        for tcp in [false, true] {
            let local = if tcp {
                daemon
                    .local
                    .handle_tcp_with_cache(&query, now, daemon.cache.as_mut())
            } else {
                daemon
                    .local
                    .handle_udp_with_cache(&query, now, daemon.cache.as_mut())
            }
            .unwrap();
            assert_eq!(local.is_none(), follows_cname);
            let answer = local
                .or_else(|| cached(&mut daemon, "alias.test", 16, now))
                .unwrap();
            let message = Message::parse(&answer).unwrap();
            let records: Vec<_> = message.records(Section::Answer).collect();
            assert_eq!(records.len(), if follows_cname { 3 } else { 1 });
            assert_eq!(
                records.last().unwrap().rdata,
                if follows_cname {
                    b"\x0ftarget-upstream".as_slice()
                } else {
                    b"\x0balias-local".as_slice()
                }
            );
        }
    }
}

#[test]
fn cached_nxdomain_does_not_mask_new_dhcp_address() {
    let mut daemon = daemon();
    daemon.cache_reply_at(&packet("client.test", 28, 0x8183).finish(), 100);
    let mut hosts = std::mem::take(&mut daemon.local.hosts);
    let names = daemon.publish_lease_names(
        &[crate::dhcp::persistence::DnsLeaseRecord {
            name: b"client.test",
            address: "192.0.2.30".parse().unwrap(),
            expires: Some(3600),
        }],
        &mut hosts,
        &[],
        super::super::lease_names::LeasePolicy::default(),
    );
    daemon.local.hosts = hosts;
    daemon.local.leases = std::sync::Arc::new(names);
    assert!(daemon
        .cache
        .as_ref()
        .unwrap()
        .has_nxdomain(&Name::from_ascii("client.test").unwrap(), 101));
    let query = packet("client.test", 1, 0x100).finish();
    for tcp in [false, true] {
        let answer = shared_answer(&mut daemon, &query, 101, tcp).unwrap();
        let message = Message::parse(&answer).unwrap();
        assert_eq!(message.header.rcode(), 0);
        assert_eq!(message.header.answers, 1);
        assert_eq!(
            message.records(Section::Answer).next().unwrap().rdata,
            [192, 0, 2, 30]
        );
    }
}

#[test]
fn shared_lookup_bypasses_only_dynamic_answers_when_not_cacheable() {
    let mut daemon = daemon();
    daemon
        .local
        .hosts
        .insert(b"local.test".to_vec(), "192.0.2.3".parse().unwrap(), 0, 1);
    let mut reply = packet("remote.test", 1, 0x8180);
    reply
        .record_at(Section::Answer, 12, 1, 1, 60, &[192, 0, 2, 4])
        .unwrap();
    daemon.cache_reply_at(&reply.finish(), 100);
    for (cacheable, tcp) in [(false, false), (false, true), (true, false), (true, true)] {
        for name in ["local.test", "remote.test"] {
            let query = packet(name, 1, 0x100).finish();
            let header = Header::parse(&query).unwrap();
            let question =
                super::super::forward::Question::parse_with_header(&query, header).unwrap();
            let mut local = LocalDnsService::new(
                daemon.local.config.clone(),
                daemon.local.hosts.clone(),
                0,
                1232,
            );
            let answer = daemon
                .current_answer_local_or_cached(
                    &query, header, &question, &mut local, 101, cacheable, tcp,
                )
                .unwrap();
            assert_eq!(answer.answer.is_some(), name == "local.test" || cacheable);
            if let Some(QueryResult::Local(answer) | QueryResult::Cached(answer)) = answer.answer {
                let message = Message::parse(&answer).unwrap();
                let address = message.records(Section::Answer).next().unwrap();
                assert_eq!(
                    address.rdata,
                    if name == "local.test" {
                        [192, 0, 2, 3]
                    } else {
                        [192, 0, 2, 4]
                    }
                );
            }
        }
    }
}

#[test]
fn cached_cname_dynamic_terminal_uses_configured_txt_mx_srv_before_cached_type() {
    for (qtype, directive, expected_data) in [
        (
            16,
            "txt-record=target.test,local-target",
            b"\x0clocal-target".to_vec(),
        ),
        (
            15,
            "mx-host=target.test,mail.test,10",
            [
                10u16.to_be_bytes().as_slice(),
                Name::from_ascii("mail.test").unwrap().as_wire(),
            ]
            .concat(),
        ),
        (
            33,
            "srv-host=target.test,mail.test,8443,10,0",
            [
                &[0, 10, 0, 0, 32, 251],
                Name::from_ascii("mail.test").unwrap().as_wire(),
            ]
            .concat(),
        ),
    ] {
        let mut daemon = daemon();
        std::sync::Arc::make_mut(&mut daemon.local.config)
            .cache_rr
            .push(qtype);
        std::sync::Arc::make_mut(&mut daemon.local.config)
            .apply(
                &crate::config::lex_line(directive.as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        daemon.local.query_logging = true;
        daemon.cache_reply_at(&chain_reply(1, false), 100);
        // The target's local record must win even if the requested upstream
        // type and the MX/SRV Additional address are already cached.
        let mut upstream = packet("target.test", qtype, 0x8180);
        let data = if qtype == 16 {
            b"\x08upstream".to_vec()
        } else {
            expected_data.clone()
        };
        upstream
            .record_at(Section::Answer, 12, qtype, 1, 60, &data)
            .unwrap();
        daemon.cache_reply_at(&upstream.finish(), 100);
        let mut mail = packet("mail.test", 1, 0x8180);
        mail.record_at(Section::Answer, 12, 1, 1, 90, &[192, 0, 2, 90])
            .unwrap();
        daemon.cache_reply_at(&mail.finish(), 100);
        let answer = cached(&mut daemon, "alias.test", qtype, 101).unwrap();
        let message = Message::parse(&answer).unwrap();
        assert_eq!(message.header.flags, 0x8580);
        let records: Vec<_> = message.records(Section::Answer).collect();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records[2].name().unwrap(),
            Name::from_ascii("target.test").unwrap()
        );
        assert_eq!(records[2].rrtype, qtype);
        assert_eq!(records[2].ttl, 0);
        assert_eq!(records[2].canonical_rdata().unwrap(), expected_data);
        let extra: Vec<_> = message.records(Section::Additional).collect();
        assert_eq!(extra.len(), usize::from(qtype != 16));
        if qtype != 16 {
            assert_eq!(
                extra[0].name().unwrap(),
                Name::from_ascii("mail.test").unwrap()
            );
            assert_eq!(extra[0].rdata, [192, 0, 2, 90]);
            assert_eq!(extra[0].ttl, 89);
        }
        assert!(daemon.local.take_query_events().iter().any(|event| {
            event.flags & crate::query_logging::CONFIG != 0
                && event.name.as_deref() == Some(b"target.test")
        }));
        // The dynamic CNAME itself still requires RD and rejects DO before
        // its configured terminal can answer.
        for (flags, dnssec) in [(0, false), (0x100, true)] {
            let mut query = packet("alias.test", qtype, flags);
            if dnssec {
                query
                    .record(
                        Section::Additional,
                        &Name::from_ascii("").unwrap(),
                        41,
                        1232,
                        0x8000,
                        &[],
                    )
                    .unwrap();
            }
            let query = query.finish();
            let question = super::super::forward::Question::parse(&query).unwrap();
            assert!(daemon
                .cached_answer_at(&query, &question, 101)
                .unwrap()
                .is_none());
        }
    }
}

#[test]
fn configured_cname_terminal_keeps_negative_soa_before_mail_additional() {
    let mut daemon = daemon();
    std::sync::Arc::make_mut(&mut daemon.local.config)
        .apply(
            &crate::config::lex_line(b"mx-host=target.test,mail.test,10")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    let mut reply = packet("alias.test", 1, 0x8183);
    reply
        .record_at(
            Section::Answer,
            12,
            5,
            1,
            60,
            Name::from_ascii("target.test").unwrap().as_wire(),
        )
        .unwrap();
    let mut soa = Name::from_ascii("ns.test").unwrap().as_wire().to_vec();
    soa.extend_from_slice(Name::from_ascii("hostmaster.test").unwrap().as_wire());
    for value in [1u32, 2, 3, 4, 60] {
        soa.extend_from_slice(&value.to_be_bytes());
    }
    reply
        .record(
            Section::Authority,
            &Name::from_ascii("test").unwrap(),
            6,
            1,
            60,
            &soa,
        )
        .unwrap();
    daemon.cache_reply_at(&reply.finish(), 100);
    let mut mail = packet("mail.test", 1, 0x8180);
    mail.record_at(Section::Answer, 12, 1, 1, 90, &[192, 0, 2, 90])
        .unwrap();
    daemon.cache_reply_at(&mail.finish(), 100);
    let answer = cached(&mut daemon, "alias.test", 15, 101).unwrap();
    let message = Message::parse(&answer).unwrap();
    assert_eq!(message.header.flags, 0x8580);
    assert_eq!(
        message
            .records(Section::Answer)
            .map(|row| row.rrtype)
            .collect::<Vec<_>>(),
        [5, 15]
    );
    let authority = message.records(Section::Authority).next().unwrap();
    assert_eq!(authority.rrtype, 6);
    assert_eq!(authority.name().unwrap(), Name::from_ascii("test").unwrap());
    let additional = message.records(Section::Additional).next().unwrap();
    assert_eq!(additional.rrtype, 1);
    assert_eq!(additional.rdata, [192, 0, 2, 90]);
}

#[test]
fn malformed_replacement_keeps_prefix_removal_but_zero_ttl_stops_before_removal() {
    for ttl in [0, 53] {
        let mut daemon = daemon();
        let mut old = packet("replace.test", 1, 0x8180);
        old.record_at(Section::Answer, 12, 1, 1, 53, &[8, 8, 8, 7])
            .unwrap();
        daemon.cache_reply_at(&old.finish(), 100);
        let mut unrelated = packet("other.test", 1, 0x8180);
        unrelated
            .record_at(Section::Answer, 12, 1, 1, 53, &[9, 9, 9, 9])
            .unwrap();
        daemon.cache_reply_at(&unrelated.finish(), 100);
        assert!(cached(&mut daemon, "replace.test", 1, 100).is_some());

        let mut incoming = packet("replace.test", 1, 0x8180);
        incoming
            .record_at(Section::Answer, 12, 1, 1, ttl, &[8, 8, 8, 8])
            .unwrap();
        let mut incoming = incoming.finish();
        incoming[7] = 2;
        incoming.push(0); // Second Answer has an owner but no fixed RR fields.
        daemon.cache_reply_at(&incoming, 100);
        assert_eq!(
            cached(&mut daemon, "replace.test", 1, 100).is_some(),
            ttl == 0
        );
        assert!(cached(&mut daemon, "other.test", 1, 100).is_some());
        assert_eq!(
            daemon.cache_counters,
            CacheCounters {
                inserted: 2,
                live_freed: 0
            }
        );

        let mut recovery = packet("replace.test", 1, 0x8180);
        recovery
            .record_at(Section::Answer, 12, 1, 1, 53, &[8, 8, 4, 4])
            .unwrap();
        daemon.cache_reply_at(&recovery.finish(), 100);
        let answer = cached(&mut daemon, "replace.test", 1, 100).unwrap();
        assert_eq!(
            Message::parse(&answer)
                .unwrap()
                .records(Section::Answer)
                .next()
                .unwrap()
                .rdata,
            [8, 8, 4, 4]
        );
        assert_eq!(daemon.cache_counters.inserted, 3);
    }
}

#[test]
fn finite_cname_negative_cutoff_does_not_contribute_stale_metadata() {
    for (minimum, maximum) in [(0, 0), (4, 12)] {
        let mut daemon = daemon();
        daemon.enable_cache(32, minimum, maximum, StalePolicy::Seconds(5));
        daemon.enable_negative_cache(5, true);
        let mut reply = packet("alias.test", 1, 0x8183);
        reply
            .record_at(
                Section::Answer,
                12,
                5,
                1,
                20,
                Name::from_ascii("target.test").unwrap().as_wire(),
            )
            .unwrap();
        let mut soa = Name::from_ascii("ns.test").unwrap().as_wire().to_vec();
        soa.extend_from_slice(Name::from_ascii("hostmaster.test").unwrap().as_wire());
        for value in [1u32, 2, 3, 4, 5] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        reply
            .record(
                Section::Authority,
                &Name::from_ascii("test").unwrap(),
                6,
                1,
                20,
                &soa,
            )
            .unwrap();
        daemon.cache_reply_at(&reply.finish(), 100);
        let query = packet("alias.test", 1, 0x100).finish();
        let question = super::super::forward::Question::parse(&query).unwrap();
        let retained = daemon
            .cached_answer_at_with_local(&query, &question, 109, None)
            .unwrap();
        assert!(retained.packet.is_some() && retained.stale);
        let expired = daemon
            .cached_answer_at_with_local(&query, &question, 110, None)
            .unwrap();
        assert!(expired.packet.is_none());
        assert!(!expired.stale, "exact-C finite/min-max cname-nx-q1-at-110");
    }
}

#[test]
fn zero_ttl_at_expiry_is_not_yet_stale_and_new_address_precedes_old_nxdomain() {
    let mut daemon = daemon();
    daemon.enable_cache(32, 0, 0, StalePolicy::Seconds(30));
    daemon.enable_negative_cache(1, true);
    daemon.cache_reply_at(&packet("stale.test", 1, 0x8183).finish(), 100);
    assert!(
        !cached_details(&mut daemon, "stale.test", 1, 101)
            .unwrap()
            .stale
    );
    assert!(
        cached_details(&mut daemon, "stale.test", 1, 102)
            .unwrap()
            .stale
    );
    let mut positive = packet("stale.test", 1, 0x8180);
    positive
        .record_at(Section::Answer, 12, 1, 1, 120, &[192, 0, 2, 8])
        .unwrap();
    daemon.cache_reply_at(&positive.finish(), 104);
    let answer = cached_details(&mut daemon, "stale.test", 1, 104).unwrap();
    // The exact C service returned the new address and still refreshed: its
    // earlier CNAME/NXDOMAIN scan had already marked the old entry stale.
    assert!(answer.stale);
    let message = Message::parse(answer.packet.as_deref().unwrap()).unwrap();
    assert_eq!(message.header.rcode(), 0);
    let rr = message.records(Section::Answer).next().unwrap();
    assert_eq!(rr.ttl, 120);
    assert_eq!(rr.rdata, &[192, 0, 2, 8]);
    let cname = cached_details(&mut daemon, "stale.test", 5, 104).unwrap();
    assert!(cname.stale);
    assert_eq!(
        Header::parse(cname.packet.as_deref().unwrap())
            .unwrap()
            .rcode(),
        3
    );
}

#[test]
fn stale_metadata_follows_the_returned_cname_chain_and_finite_allowance() {
    let mut daemon = daemon();
    daemon.enable_cache(32, 0, 0, StalePolicy::Seconds(30));
    let mut reply = packet("alias.test", 1, 0x8180);
    reply
        .record_at(
            Section::Answer,
            12,
            5,
            1,
            60,
            Name::from_ascii("target.test").unwrap().as_wire(),
        )
        .unwrap();
    reply
        .record(
            Section::Answer,
            &Name::from_ascii("target.test").unwrap(),
            1,
            1,
            1,
            &[192, 0, 2, 7],
        )
        .unwrap();
    daemon.cache_reply_at(&reply.finish(), 100);
    let at_expiry = cached_details(&mut daemon, "alias.test", 1, 101).unwrap();
    assert!(!at_expiry.stale);
    assert_eq!(
        Message::parse(at_expiry.packet.as_deref().unwrap())
            .unwrap()
            .records(Section::Answer)
            .nth(1)
            .unwrap()
            .ttl,
        0
    );
    assert!(
        cached_details(&mut daemon, "alias.test", 1, 102)
            .unwrap()
            .stale
    );
    assert!(
        !cached_details(&mut daemon, "alias.test", 5, 102)
            .unwrap()
            .stale
    );
    assert!(
        cached_details(&mut daemon, "target.test", 1, 130)
            .unwrap()
            .stale
    );
    assert!(cached_details(&mut daemon, "target.test", 1, 131).is_none());
}

#[test]
fn response_counters_count_committed_records_and_follow_real_reload() {
    let mut daemon = daemon();
    let response = chain_reply(1, false);
    assert_eq!(daemon.cache_counters(), CacheCounters::default());
    daemon.cache_reply_at(&response, 100);
    assert_eq!(
        daemon.cache_counters(),
        CacheCounters {
            inserted: 3,
            live_freed: 0
        }
    );
    assert!(cached(&mut daemon, "alias.test", 1, 101).is_some());
    assert_eq!(daemon.cache_counters().inserted, 3);
    daemon.cache_reply_at(&response, 101);
    assert_eq!(
        daemon.cache_counters(),
        CacheCounters {
            inserted: 6,
            live_freed: 0
        }
    );
    daemon.reload_hosts(Hosts::new());
    assert_eq!(daemon.cache_counters(), CacheCounters::default());
    assert!(cached(&mut daemon, "alias.test", 1, 102).is_none());
}

#[test]
fn failed_hosts_reload_still_invalidates_unexpired_forwarded_answers() {
    let mut daemon = daemon();
    daemon.local.hosts.insert(
        b"retained.test".to_vec(),
        "192.0.2.41".parse().unwrap(),
        37,
        2,
    );
    daemon.cache_reply_at(&chain_reply(1, false), 100);
    assert!(cached(&mut daemon, "alias.test", 1, 101).is_some());

    // Model an allocation failure: begin reload, but never publish a replacement.
    daemon.begin_hosts_reload();
    assert!(cached(&mut daemon, "alias.test", 1, 102).is_none());
    assert_eq!(daemon.cache_counters(), CacheCounters::default());
    assert_eq!(daemon.local.hosts.addresses(b"retained.test").count(), 1);
    daemon.cache_reply_at(&chain_reply(1, false), 102);
    assert!(cached(&mut daemon, "alias.test", 1, 103).is_some());
}

#[test]
fn cname_query_stops_at_first_alias_and_keeps_exact_c_flags() {
    for negative in [false, true] {
        let mut daemon = daemon();
        daemon.cache_reply_at(&chain_reply(1, negative), 100);
        let answer = cached(&mut daemon, "alias.test", 5, 105).unwrap();
        let message = Message::parse(&answer).unwrap();
        assert_eq!(message.header.flags, 0x8580);
        assert_eq!(message.header.answers, 1);
        assert_eq!(message.header.authorities, 0);
        let rr = message.records(Section::Answer).next().unwrap();
        assert_eq!((rr.rrtype, rr.ttl), (5, 55));
        assert_eq!(
            rr.rdata_name(0).unwrap().0,
            Name::from_ascii("middle.test").unwrap()
        );
        assert!(cached(&mut daemon, "alias.test", 5, 160).is_none());
    }
}

#[test]
fn cname_positive_queries_do_not_populate_cache() {
    for negative_envelope in [false, true] {
        let mut daemon = daemon();
        daemon.cache_reply_at(&chain_reply(5, negative_envelope), 100);
        assert!(cached(&mut daemon, "alias.test", 5, 100).is_none());
        assert!(cached(&mut daemon, "target.test", 1, 100).is_none());
    }
}

#[test]
fn cname_nxdomain_query_populates_name_wide_negative_cache() {
    let mut daemon = daemon();
    daemon.cache_reply_at(&packet("missing.test", 5, 0x8183).finish(), 100);
    for qtype in [1, 5, 28] {
        let answer = cached(&mut daemon, "missing.test", qtype, 110).unwrap();
        let message = Message::parse(&answer).unwrap();
        assert_eq!(message.header.flags, 0x8183);
        assert_eq!(message.header.answers, 0);
        assert_eq!(message.header.authorities, 0);
    }
    assert!(cached(&mut daemon, "missing.test", 5, 130).is_none());
}

#[test]
fn cname_nodata_query_does_not_populate_cache() {
    let mut daemon = daemon();
    daemon.cache_reply_at(&packet("empty.test", 5, 0x8180).finish(), 100);
    assert!(cached(&mut daemon, "empty.test", 5, 100).is_none());
    assert!(cached(&mut daemon, "empty.test", 1, 100).is_none());
}

#[test]
fn cname_negative_terminal_preserves_qtype_and_expiry() {
    for nxdomain in [false, true] {
        let mut daemon = daemon();
        let mut reply = chain_reply(1, true);
        if !nxdomain {
            reply[3] &= !3;
        }
        daemon.cache_reply_at(&reply, 100);
        assert!(cached(&mut daemon, "alias.test", 1, 110).is_some());
        assert_eq!(
            cached(&mut daemon, "alias.test", 28, 110).is_some(),
            nxdomain
        );
        // The CNAME lives for 60 seconds; its terminal negative lives for 30.
        assert!(cached(&mut daemon, "alias.test", 1, 130).is_none());
        assert!(cached(&mut daemon, "target.test", 1, 130).is_none());
    }
}

#[test]
fn long_cached_chain_reuses_names_to_preserve_c_truncation_boundary() {
    let owner = format!(
        "{}.{}.{}.test",
        "a".repeat(60),
        "a".repeat(60),
        "a".repeat(60)
    );
    let target = format!(
        "{}.{}.{}.test",
        "b".repeat(60),
        "b".repeat(60),
        "b".repeat(60)
    );
    let mut daemon = daemon();
    let mut reply = packet(&owner, 1, 0x8180);
    reply
        .record(
            Section::Answer,
            &Name::from_ascii(&owner).unwrap(),
            5,
            1,
            60,
            Name::from_ascii(&target).unwrap().as_wire(),
        )
        .unwrap();
    reply
        .record(
            Section::Answer,
            &Name::from_ascii(&target).unwrap(),
            1,
            1,
            60,
            &[192, 0, 2, 1],
        )
        .unwrap();
    daemon.cache_reply_at(&reply.finish(), 100);
    for (qtype, count, length) in [(5, 1, 406), (1, 2, 422)] {
        let answer = cached(&mut daemon, &owner, qtype, 100).unwrap();
        let message = Message::parse(&answer).unwrap();
        assert_eq!(message.header.answers, count);
        assert_eq!(message.header.flags & 0x200, 0);
        assert_eq!(answer.len(), length);
    }
}

#[test]
fn address_cache_preserves_configured_rotation() {
    for no_round_robin in [false, true] {
        let mut daemon = daemon();
        std::sync::Arc::make_mut(&mut daemon.local.config).no_round_robin = no_round_robin;
        let mut reply = packet("Service.Test", 1, 0x8180);
        for last in [1, 2] {
            reply
                .record(
                    Section::Answer,
                    &Name::from_ascii("Service.Test").unwrap(),
                    1,
                    1,
                    60,
                    &[192, 0, 2, last],
                )
                .unwrap();
        }
        daemon.cache_reply_at(&reply.finish(), 100);
        for attempt in 0..4 {
            let answer = cached(&mut daemon, "Service.Test", 1, 105).unwrap();
            let message = Message::parse(&answer).unwrap();
            assert_eq!(message.header.flags, 0x8180);
            let addresses: Vec<_> = message
                .records(Section::Answer)
                .map(|rr| rr.rdata[3])
                .collect();
            assert_eq!(
                addresses,
                if !no_round_robin && attempt % 2 == 1 {
                    [2, 1]
                } else {
                    [1, 2]
                }
            );
        }
    }
}

#[test]
fn soa_cache_only_answers_matching_rrtype() {
    let mut daemon = daemon();
    let mut soa = Name::from_ascii("ns.same.test").unwrap().as_wire().to_vec();
    soa.extend_from_slice(Name::from_ascii("hostmaster.same.test").unwrap().as_wire());
    for value in [1u32, 2, 3, 4, 10] {
        soa.extend_from_slice(&value.to_be_bytes());
    }
    let mut reply = packet("missing.same.test", 1, 0x8183);
    reply
        .record(
            Section::Authority,
            &Name::from_ascii("same.test").unwrap(),
            6,
            1,
            60,
            &soa,
        )
        .unwrap();
    daemon.cache_reply_at(&reply.finish(), 100);
    {
        let answer = cached(&mut daemon, "same.test", 6, 100).unwrap();
        let message = Message::parse(&answer).unwrap();
        assert_eq!(message.header.answers, 1);
        assert_eq!(message.records(Section::Answer).next().unwrap().rrtype, 6);
    }
    for qtype in [15, 33, 255, 65401] {
        assert!(cached(&mut daemon, "same.test", qtype, 100).is_none());
    }
}

#[test]
fn name_wide_negative_supports_unknown_qtypes_and_cname_without_rd() {
    let mut daemon = daemon();
    daemon.cache_reply_at(&packet("missing.test", 1, 0x8183).finish(), 100);
    for qtype in [6, 15, 33, 255, 65401] {
        let answer = cached(&mut daemon, "missing.test", qtype, 100).unwrap();
        assert_eq!(Header::parse(&answer).unwrap().flags, 0x8183);
    }
    let query = packet("missing.test", 5, 0).finish();
    let question = super::super::forward::Question::parse(&query).unwrap();
    let answer = daemon
        .cached_answer_at(&query, &question, 100)
        .unwrap()
        .unwrap();
    assert_eq!(Header::parse(&answer).unwrap().flags, 0x8083);
}

// The differential tool sets an explicit corpus path and runs this test by
// name. It is ignored in the ordinary suite because an exact-C build is an
// external prerequisite; its dedicated execution is recorded separately.
#[test]
#[ignore = "requires DNSMASQ_CACHE_ORACLE_INPUT from cache_answer_diff.py"]
fn exact_c_oracle_driver() {
    let corpus =
        std::fs::read_to_string(std::env::var("DNSMASQ_CACHE_ORACLE_INPUT").unwrap()).unwrap();
    let mut daemon = daemon();
    for line in corpus.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words[0] == "RESET" {
            daemon.reload_hosts(Hosts::new());
            println!("CACHE_ORACLE RESET");
            continue;
        }
        if words[0] == "M" {
            let counters = daemon.cache_counters();
            println!(
                "CACHE_ORACLE M {} {}",
                counters.inserted, counters.live_freed
            );
            continue;
        }
        let now: i64 = words[1].parse().unwrap();
        let limit: usize = words[2].parse().unwrap();
        let encoded = words[3];
        let packet: Vec<u8> = (0..encoded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
            .collect();
        if words[0] == "P" {
            daemon.cache_reply_at(&packet, now);
            println!("CACHE_ORACLE P");
        } else {
            assert_eq!(words[0], "Q");
            daemon.max_udp = limit;
            let question = super::super::forward::Question::parse(&packet).unwrap();
            let answer = daemon.cached_answer_at(&packet, &question, now).unwrap();
            let result = answer.map_or_else(
                || "NONE".into(),
                |packet| {
                    packet
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                },
            );
            println!("CACHE_ORACLE {result}");
        }
    }
}

#[test]
fn prepared_udp_name_buffer_survives_decode_errors_and_keeps_answers_owned() {
    let mut daemon = daemon();
    let now = unix_seconds();
    for name in ["one.test", "two.test"] {
        let mut reply = packet(name, 1, 0x8180);
        reply
            .record(
                Section::Answer,
                &Name::from_ascii(name).unwrap(),
                1,
                1,
                120,
                &[192, 0, 2, 7],
            )
            .unwrap();
        daemon.cache_reply_at(&reply.finish(), now);
    }
    let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 120, 1232);
    let client = ClientRequest {
        source: "127.0.0.1:53001".parse().unwrap(),
        destination: "127.0.0.1".parse().unwrap(),
        interface: 0,
    };
    let first = packet("one.test", 1, 0x100).finish();
    let metadata = super::super::forward_service::query_metadata(&first, 1232).unwrap();
    let mut answers = Vec::new();
    let mut allocation = None;
    for name in ["one.test", "two.test", "one.test"] {
        let query = packet(name, 1, 0x100).finish();
        let answer = daemon
            .answer_udp_prepared_with_local(
                &query,
                &query,
                metadata,
                client.clone(),
                None,
                &mut local,
            )
            .unwrap();
        let QueryResult::Cached(answer) = answer else {
            panic!("expected cache hit");
        };
        answers.push((name, answer));
        let pointer = daemon.udp_name_buffer.as_ptr();
        if let Some(previous) = allocation {
            assert_eq!(pointer, previous);
        }
        allocation = Some(pointer);
        assert_eq!(daemon.udp_name_buffer.capacity(), 32);
        // An invalid pointer loop follows a complete header/question footer.
        // Failed decoding must return its scratch instead of losing it.
        let mut malformed = first[..12].to_vec();
        malformed.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert!(matches!(
            daemon.answer_udp_prepared_with_local(
                &malformed,
                &malformed,
                metadata,
                client.clone(),
                None,
                &mut local
            ),
            Err(DaemonError::Wire(_))
        ));
        assert_eq!(daemon.udp_name_buffer.as_ptr(), pointer);
        for tail in [
            &[3, b'a', b'b', b'c', 4, b'z'][..],
            &[3, b'a', b'b', b'c', 0x40, 0, 1, 0, 1][..],
        ] {
            let mut partial = first[..12].to_vec();
            partial.extend_from_slice(tail);
            assert!(matches!(
                daemon.answer_udp_prepared_with_local(
                    &partial,
                    &partial,
                    metadata,
                    client.clone(),
                    None,
                    &mut local
                ),
                Err(DaemonError::Wire(_))
            ));
            assert_eq!(daemon.udp_name_buffer.as_slice(), &[3, b'a', b'b', b'c']);
            assert_eq!(daemon.udp_name_buffer.as_ptr(), pointer);
        }
    }
    // Reusing and failing the following requests cannot overwrite retained replies.
    for (name, answer) in answers {
        let message = Message::parse(&answer).unwrap();
        assert_eq!(
            super::super::forward::Question::parse(&answer)
                .unwrap()
                .name,
            Name::from_ascii(name).unwrap()
        );
        assert_eq!(
            message.records(Section::Answer).next().unwrap().rdata,
            &[192, 0, 2, 7]
        );
    }
    // A compressed question and the longest valid question use the same
    // decoder/cursor contract; capacity growth remains bounded for DNS names.
    let mut compressed = first[..12].to_vec();
    compressed.extend_from_slice(&[0xc0, 18, 0, 1, 0, 1]);
    compressed.extend_from_slice(Name::from_ascii("one.test").unwrap().as_wire());
    assert!(matches!(
        daemon.answer_udp_prepared_with_local(
            &compressed,
            &compressed,
            metadata,
            client.clone(),
            None,
            &mut local
        ),
        Ok(QueryResult::Cached(_))
    ));
    let long_name = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    let long = packet(&long_name, 1, 0x100).finish();
    let _ = daemon.answer_udp_prepared_with_local(
        &long,
        &long,
        metadata,
        client.clone(),
        None,
        &mut local,
    );
    assert_eq!(daemon.udp_name_buffer.len(), 255);
    assert_eq!(daemon.udp_name_buffer.capacity(), 256);
    let mut overlong = first[..12].to_vec();
    for _ in 0..4 {
        overlong.push(63);
        overlong.extend_from_slice(&[b'x'; 63]);
    }
    overlong.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert!(matches!(
        daemon.answer_udp_prepared_with_local(
            &overlong,
            &overlong,
            metadata,
            client.clone(),
            None,
            &mut local
        ),
        Err(DaemonError::Wire(WireError::NameTooLong))
    ));
    assert_eq!(daemon.udp_name_buffer.len(), 192);
    assert_eq!(daemon.udp_name_buffer.capacity(), 256);
    assert!(matches!(
        daemon.answer_udp_prepared_with_local(&first, &first, metadata, client, None, &mut local),
        Ok(QueryResult::Cached(_))
    ));
    assert_eq!(daemon.udp_name_buffer.capacity(), 256);
    // Irregular label sizes can make amortized growth exceed256 even when
    // the complete name is shorter. Retention is bounded, not rounded down.
    let mut irregular_daemon = self::daemon();
    let irregular_name = [
        "a".repeat(30),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63),
    ]
    .join(".");
    let irregular = packet(&irregular_name, 1, 0x100).finish();
    let _ = irregular_daemon.answer_udp_prepared_with_local(
        &irregular,
        &irregular,
        metadata,
        ClientRequest {
            source: "127.0.0.1:53001".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        },
        None,
        &mut local,
    );
    assert_eq!(irregular_daemon.udp_name_buffer.len(), 224);
    assert!(irregular_daemon.udp_name_buffer.capacity() > 256);
    assert!(irregular_daemon.udp_name_buffer.capacity() <= 512);
}

#[test]
fn prepared_udp_recycled_cache_replies_keep_wire_data_and_ownership() {
    let mut daemon = daemon();
    let now = unix_seconds();
    let long = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    let cases = [(long.as_str(), 28), ("a.test", 1), ("other.test", 28)];
    for (name, rrtype) in cases {
        let mut reply = packet(name, rrtype, 0x8180);
        let data = if rrtype == 1 {
            vec![192, 0, 2, 7]
        } else {
            vec![7; 16]
        };
        reply
            .record(
                Section::Answer,
                &Name::from_ascii(name).unwrap(),
                rrtype,
                1,
                120,
                &data,
            )
            .unwrap();
        daemon.cache_reply_at(&reply.finish(), now);
    }
    let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 120, 1232);
    let client = ClientRequest {
        source: "127.0.0.1:53001".parse().unwrap(),
        destination: "127.0.0.1".parse().unwrap(),
        interface: 0,
    };
    let mut held = None;
    for turn in 0..3 {
        for (name, rrtype) in cases {
            for edns in [true, false] {
                let mut query = packet(name, rrtype, 0x100);
                if edns {
                    query
                        .record(Section::Additional, &Name::root(), 41, 1232, 0, &[])
                        .unwrap();
                }
                let query = query.finish();
                let metadata = super::super::forward_service::query_metadata(&query, 1232).unwrap();
                let answer = daemon
                    .answer_udp_prepared_with_local(
                        &query,
                        &query,
                        metadata,
                        client.clone(),
                        None,
                        &mut local,
                    )
                    .unwrap();
                let QueryResult::Cached(answer) = answer else {
                    panic!("expected fresh cache hit");
                };
                let question = super::super::forward::Question::parse(&answer).unwrap();
                assert_eq!(question.name, Name::from_ascii(name).unwrap());
                assert_eq!(question.rrtype, rrtype);
                let message = Message::parse(&answer).unwrap();
                assert_eq!(message.header.answers, 1);
                assert_eq!(message.header.additionals, u16::from(edns));
                let record = message.records(Section::Answer).next().unwrap();
                assert_eq!(
                    record.rdata,
                    if rrtype == 1 {
                        &[192, 0, 2, 7][..]
                    } else {
                        &[7; 16][..]
                    }
                );
                if turn == 0 && held.is_none() {
                    held = Some((answer.clone(), answer));
                } else {
                    local.recycle_cached_reply(answer);
                }
            }
        }
    }
    let (saved, answer) = held.unwrap();
    assert_eq!(
        saved, answer,
        "a caller-retained reply must remain independent"
    );
    assert!(local.cached_reply_buffer.capacity() <= 512);
    let retained = local.cached_reply_buffer.capacity();
    local.recycle_cached_reply(vec![0; 4096]);
    assert_eq!(
        local.cached_reply_buffer.capacity(),
        retained,
        "a large general reply must not enlarge retained storage"
    );
}
