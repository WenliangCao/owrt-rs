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
        daemon.local.config.no_round_robin = no_round_robin;
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
