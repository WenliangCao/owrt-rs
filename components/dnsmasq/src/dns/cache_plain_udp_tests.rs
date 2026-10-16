use super::*;
use crate::config::{dns::DnsConfig, lex_line};
use crate::dhcp::persistence::DnsLeaseRecord;
use crate::dns::cache::{EntryId, Policy, StalePolicy};
use crate::dns::daemon::{DnsDaemon, QueryResult};
use crate::dns::forward::Question;
use crate::dns::lease_names::{LeaseNames, LeasePolicy};
use crate::dns::upstream::OsRandom;
use crate::hosts::Hosts;
use std::net::Ipv4Addr;
use std::sync::Arc;

fn in_place_answer(cache: &mut Cache, query: &[u8], local: &mut LocalDnsService,
                   now: i64, scratch: &mut Vec<u8>) -> Option<Result<Vec<u8>, CacheError>> {
    let mut packet = vec![0xa5; query.len().max(512)];
    packet[..query.len()].copy_from_slice(query);
    let before = packet.clone();
    let length = CacheContext::try_plain_udp_in_place(cache, &mut packet, query.len(), local, now, scratch);
    match length {
        Some(length) => { assert!(packet[length..].iter().all(|&byte| byte == 0xa5));
                          packet.truncate(length); Some(Ok(packet)) },
        None => { assert_eq!(packet, before, "fallback changed packet bytes"); None },
    }
}

fn name(value: &str) -> Name {
    Name::from_ascii(value).unwrap()
}

fn query(owner: &Name, rrtype: u16) -> Vec<u8> {
    let mut writer = PacketWriter::new(0x1234, 0x0100, 512).unwrap();
    writer.question(owner, rrtype, 1).unwrap();
    writer.finish()
}

fn address(owner: Name, rrtype: u16, last: u8) -> Record {
    Record {
        name: owner, kind: if rrtype == 1 { Kind::Ipv4 } else { Kind::Ipv6 },
        negative: false,
        data: if rrtype == 1 { vec![192, 0, 2, last] } else { vec![last; 16] },
    }
}

fn insert(cache: &mut Cache, counters: &mut CacheCounters, record: Record) -> EntryId {
    cache.start_insert();
    let id = cache.insert_counted(record, 100, 60, counters).unwrap();
    assert!(cache.commit_counted(counters));
    id
}

fn fixture(owner: &Name, rrtype: u16, policy: Policy) -> (Cache, CacheCounters, LocalDnsService) {
    // C permits at most capacity/10 long names; keep the boundary fixture insertable.
    let capacity = if owner.dnsmasq_bytes_len() >= 75 { 10 } else { 4 };
    let mut cache = Cache::new(capacity, policy);
    let mut counters = CacheCounters::default();
    insert(&mut cache, &mut counters, address(owner.clone(), rrtype, 7));
    for index in 0..3 {
        insert(&mut cache, &mut counters, address(name(&format!("other{index}.test")), 1, index));
    }
    let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
    local.recycle_cached_reply(vec![0xee; 128]);
    (cache, counters, local)
}

fn general(cache: &mut Cache, local: &mut LocalDnsService, packet: &[u8], now: i64) -> Option<QueryResult> {
    let header = Header::parse(packet).unwrap();
    let question = Question::parse_with_header(packet, header).unwrap();
    DnsDaemon::<OsRandom>::answer_local_or_cached(
        Some(cache), packet, header, &question, local, now, true, false,
    ).unwrap().answer
}

fn entries(cache: &Cache) -> String {
    format!("{:?}", cache.entries().collect::<Vec<_>>())
}

// Exercise externally visible eviction order rather than exposing the LRU's
// private links solely for tests. Time 100 keeps the original records live.
fn eviction_trace(cache: &Cache, counters: CacheCounters) -> Vec<(String, CacheCounters)> {
    let mut cache = cache.snapshot();
    let mut counters = counters;
    (0..cache.capacity()).map(|index| {
        insert(&mut cache, &mut counters, address(name(&format!("evict{index}.test")), 1, 99));
        (entries(&cache), counters)
    }).collect()
}

fn reject_unchanged(cache: &mut Cache, counters: CacheCounters, local: &mut LocalDnsService,
                    packet: &[u8], now: i64) {
    let before_entries = entries(cache);
    let before_evictions = eviction_trace(cache, counters);
    let before_hosts = local.hosts.entries().to_vec();
    let before_leases = Arc::clone(&local.leases);
    let before_config = Arc::clone(&local.config);
    let before_buffer = local.cached_reply_buffer.clone();
    let before_capacity = local.cached_reply_buffer.capacity();
    let witness = name("other0.test");
    let (_, hint) = cache.inspect_name(&witness, 100);
    let witness_id = cache.single_fresh_address_id_with_hint(&witness, Kind::Ipv4, 100, hint.as_ref());
    let mut scratch = Vec::with_capacity(64);
    assert!(in_place_answer(cache, packet, local, now, &mut scratch).is_none());
    assert_eq!(entries(cache), before_entries, "fallback changed records/expiry");
    assert_eq!(eviction_trace(cache, counters), before_evictions, "fallback changed LRU/eviction counts");
    assert_eq!(cache.single_fresh_address_id_with_hint(&witness, Kind::Ipv4, 100, hint.as_ref()), witness_id,
        "fallback invalidated an existing name-revision hint");
    assert!(Arc::ptr_eq(&before_leases, &local.leases), "fallback detached lease publication");
    assert!(Arc::ptr_eq(&before_config, &local.config));
    assert_eq!(local.hosts.entries(), before_hosts);
    assert_eq!(local.cached_reply_buffer, before_buffer);
    assert_eq!(local.cached_reply_buffer.capacity(), before_capacity);
    assert!(local.take_query_events().is_empty());
}

#[test]
fn plain_hit_matches_original_bytes_ttl_lru_and_counted_eviction() {
    for owner in [name("hit.test"), name("HiT.test"), Name::root()] {
        for rrtype in [1, 28] {
            for policy in [Policy::default(), Policy { max_reply_ttl: 7, ..Policy::default() },
                           Policy { stale: StalePolicy::Forever, ..Policy::default() }] {
                for now in [99, 100, 159, 160] {
                    if now == 160 && policy.stale == StalePolicy::Disabled { continue; }
                    for capacity in [0, 64, 128, 512] {
                        let (mut left, counters, mut reference) = fixture(&owner, rrtype, policy);
                        let mut right = left.snapshot();
                        let mut candidate = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
                        reference.cached_reply_buffer = vec![0xab; capacity];
                        candidate.cached_reply_buffer = vec![0xab; capacity];
                        let packet = query(&owner, rrtype);
                        let expected = general(&mut left, &mut reference, &packet, now).unwrap();
                        let mut scratch = Vec::with_capacity(64);
                        let actual = in_place_answer(&mut right, &packet, &mut candidate, now, &mut scratch)
                            .expect("fresh single address is eligible").unwrap();
                        assert_eq!(expected, QueryResult::Cached(actual.clone()));
                        let message = Message::parse(&actual).unwrap();
                        let answer = message.records(Section::Answer).next().unwrap();
                        let ttl = (160i64 - now) as u32;
                        assert_eq!(answer.ttl, if policy.max_reply_ttl == 0 { ttl } else { ttl.min(7) });
                        assert_eq!(entries(&left), entries(&right));
                        assert_eq!(eviction_trace(&left, counters), eviction_trace(&right, counters));
                        assert!(reference.take_query_events().is_empty());
                        assert!(candidate.take_query_events().is_empty());
                        assert!(scratch.capacity() >= owner.as_wire().len());
                        // A subsequent client must receive its own ID; the
                        // reusable reply must not retain previous packet data.
                        candidate.recycle_cached_reply(actual);
                        let mut next = packet.clone();
                        next[..2].copy_from_slice(&0x5678u16.to_be_bytes());
                        let answer = in_place_answer(&mut right, &next, &mut candidate, now, &mut scratch)
                            .unwrap().unwrap();
                        assert_eq!(&answer[..2], &0x5678u16.to_be_bytes());
                    }
                }
            }
        }
    }
}

#[test]
fn plain_packet_rejections_leave_semantics_untouched() {
    let owner = name("hit.test");
    let original = query(&owner, 1);
    let mut packets = Vec::new();
    for bit in 0..16 {
        let mut packet = original.clone();
        packet[2..4].copy_from_slice(&(0x0100u16 ^ (1 << bit)).to_be_bytes());
        packets.push(packet);
    }
    for offset in [4, 6, 8, 10] {
        let mut packet = original.clone();
        packet[offset..offset + 2].copy_from_slice(&2u16.to_be_bytes());
        packets.push(packet);
    }
    for rrtype in [5, 16, 255] { packets.push(query(&owner, rrtype)); }
    let mut wrong_class = original.clone();
    let length = wrong_class.len();
    wrong_class[length - 2..].copy_from_slice(&3u16.to_be_bytes());
    packets.push(wrong_class);
    let mut opt = original.clone();
    opt[10..12].copy_from_slice(&1u16.to_be_bytes());
    opt.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    packets.push(opt);
    let mut trailing = original.clone(); trailing.push(0); packets.push(trailing);
    packets.push(vec![0; 1233]);
    // The valid pointer resolves to the original name after the fixed fields.
    let mut compressed = original[..12].to_vec();
    compressed.extend_from_slice(&[0xc0, 18, 0, 1, 0, 1]);
    compressed.extend_from_slice(owner.as_wire());
    assert!(Question::parse(&compressed).is_ok());
    packets.push(compressed);
    for end in 0..original.len() { packets.push(original[..end].to_vec()); }
    for packet in packets {
        let (mut cache, counters, mut local) = fixture(&owner, 1, Policy::default());
        reject_unchanged(&mut cache, counters, &mut local, &packet, 101);
    }
}

#[test]
fn cache_miss_stale_expired_multiple_negative_and_cname_fall_back() {
    let owner = name("hit.test");
    let packet = query(&owner, 1);
    for (policy, now) in [(Policy::default(), 160), (Policy::default(), 161),
        (Policy { stale: StalePolicy::Forever, ..Policy::default() }, 161),
        (Policy { stale: StalePolicy::Seconds(30), ..Policy::default() }, 190)] {
        let (mut cache, counters, mut local) = fixture(&owner, 1, policy);
        reject_unchanged(&mut cache, counters, &mut local, &packet, now);
    }
    for mode in ["missing", "wrong-family", "multiple", "negative", "cname", "invalid-address"] {
        let (mut cache, mut counters, mut local) = fixture(&owner, 1, Policy::default());
        cache.clear();
        match mode {
            "missing" => {},
            "wrong-family" => { insert(&mut cache, &mut counters, address(owner.clone(), 28, 7)); },
            "multiple" => {
                cache.start_insert();
                cache.insert(address(owner.clone(), 1, 7), 100, 60).unwrap();
                cache.insert(address(owner.clone(), 1, 8), 100, 60).unwrap();
                assert!(cache.commit_counted(&mut counters));
                assert_eq!(cache.entries().count(), 2);
            },
            "negative" => { insert(&mut cache, &mut counters,
                Record { name: owner.clone(), kind: Kind::NxDomain, negative: true, data: vec![] }); },
            "cname" => {
                cache.start_insert();
                let target = cache.insert(address(name("target.test"), 1, 9), 100, 60).unwrap();
                let alias = cache.insert(Record { name: owner.clone(), kind: Kind::Cname,
                    negative: false, data: name("target.test").as_wire().to_vec() }, 100, 60).unwrap();
                assert!(cache.set_cname_target(alias, target));
                assert!(cache.commit_counted(&mut counters));
            },
            "invalid-address" => { insert(&mut cache, &mut counters,
                Record { name: owner.clone(), kind: Kind::Ipv4, negative: false, data: vec![1, 2, 3] }); },
            _ => unreachable!(),
        }
        reject_unchanged(&mut cache, counters, &mut local, &packet, 101);
    }
}

#[test]
fn local_configuration_owns_fallback_before_cache() {
    for directive in [
        "cname=hit.test,target.test", "dns-rr=hit.test,1,c0000263",
        "address=/hit.test/192.0.2.99", "address=/hit.test/#", "local=/hit.test/",
        "interface-name=hit.test,eth0", "synth-domain=test,192.0.2.1,192.0.2.20,host-",
        "filter-A", "add-mac",
    ] {
        let owner = name("hit.test");
        let (mut cache, counters, mut local) = fixture(&owner, 1, Policy::default());
        Arc::make_mut(&mut local.config).apply(&lex_line(directive.as_bytes()).unwrap().unwrap()).unwrap();
        reject_unchanged(&mut cache, counters, &mut local, &query(&owner, 1), 101);
    }
    for mode in ["host", "unpublished-hosts", "logging"] {
        let owner = name("localhost");
        let (mut cache, counters, mut local) = fixture(&owner, 1, Policy::default());
        match mode {
            "host" => { assert!(local.hosts.insert(b"localhost".to_vec(), Ipv4Addr::LOCALHOST.into(), 60, 0)); },
            "unpublished-hosts" => { local.hosts.begin_bulk(1232, 4, 4).unwrap(); },
            "logging" => { local.query_logging = true; },
            _ => unreachable!(),
        }
        let packet = query(&owner, 1);
        reject_unchanged(&mut cache, counters, &mut local, &packet, 101);
        if mode == "host" {
            assert!(matches!(general(&mut cache, &mut local, &packet, 101), Some(QueryResult::Local(_))));
        }
    }
}

#[test]
fn lease_ownership_and_sticky_expiry_are_left_to_original_lookup() {
    let owner = name("hit.test");
    for (lease_name, expires, now) in [
        (b"hit.test".as_slice(), Some(150), 101),
        (b"hit.test".as_slice(), Some(100), 101),
        (b"hit.test".as_slice(), None, 101),
    ] {
        let (mut cache, counters, mut local) = fixture(&owner, 1, Policy::default());
        local.leases = Arc::new(LeaseNames::build(&[DnsLeaseRecord {
            name: lease_name, address: Ipv4Addr::new(192, 0, 2, 99), expires,
        }], &mut local.hosts, &[], LeasePolicy::default(), &mut ()));
        let packet = query(&owner, 1);
        reject_unchanged(&mut cache, counters, &mut local, &packet, now);
        if lease_name == b"hit.test" && expires == Some(100) {
            assert_eq!(local.leases.active_entries().count(), 1);
            assert!(matches!(general(&mut cache, &mut local, &packet, now), Some(QueryResult::Cached(_))));
            assert_eq!(local.leases.active_entries().count(), 0);
            assert!(local.leases.lookup(lease_name, 99).next().is_none(), "expiry stays removed after clock rollback");
        }
    }
}

#[test]
fn replacement_generation_and_rejected_parse_cannot_reuse_an_old_answer() {
    let owner = name("hit.test");
    let packet = query(&owner, 1);
    let (mut cache, mut counters, mut local) = fixture(&owner, 1, Policy::default());
    let mut scratch = Vec::with_capacity(64);
    let first = in_place_answer(&mut cache, &packet, &mut local, 101, &mut scratch).unwrap().unwrap();
    local.recycle_cached_reply(first);
    assert!(in_place_answer(&mut cache, &packet[..packet.len() - 1], &mut local, 101, &mut scratch).is_none());
    cache.clear();
    insert(&mut cache, &mut counters, address(owner, 1, 99));
    let actual = in_place_answer(&mut cache, &packet, &mut local, 101, &mut scratch).unwrap().unwrap();
    let mut reference_cache = cache.snapshot();
    let mut reference_local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
    assert_eq!(general(&mut reference_cache, &mut reference_local, &packet, 101), Some(QueryResult::Cached(actual.clone())));
    assert_eq!(Message::parse(&actual).unwrap().records(Section::Answer).next().unwrap().rdata, &[192, 0, 2, 99]);
}

#[test]
fn in_place_bounds_and_long_names_preserve_fallback_bytes() {
    let longest = ["A".repeat(63), "b".repeat(63), "C".repeat(63), "d".repeat(61)].join(".");
    for owner in [name("short.test"), name(&longest)] {
        for rrtype in [1, 28] {
            let query = query(&owner, rrtype);
            let answer_len = query.len() + if rrtype == 1 { 16 } else { 28 };
            for capacity in [query.len(), answer_len - 1, answer_len, 512] {
                let (mut left, counters, mut reference) = fixture(&owner, rrtype, Policy::default());
                let mut right = left.snapshot();
                let mut candidate = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
                let mut packet = vec![0xa5; capacity];
                packet[..query.len()].copy_from_slice(&query);
                let before = packet.clone();
                let mut scratch = Vec::with_capacity(256);
                let actual = CacheContext::try_plain_udp_in_place(
                    &mut right, &mut packet, query.len(), &mut candidate, 101, &mut scratch);
                if capacity < answer_len {
                    assert!(actual.is_none());
                    assert_eq!(packet, before);
                    assert_eq!(eviction_trace(&left, counters), eviction_trace(&right, counters));
                } else {
                    assert_eq!(actual, Some(answer_len));
                    assert_eq!(general(&mut left, &mut reference, &query, 101),
                        Some(QueryResult::Cached(packet[..answer_len].to_vec())));
                    assert_eq!(&packet[answer_len..], &before[answer_len..]);
                }
            }
            let (mut cache, counters, mut local) = fixture(&owner, rrtype, Policy::default());
            local.max_udp = answer_len - 1;
            reject_unchanged(&mut cache, counters, &mut local, &query, 101);
        }
    }
}

#[test]
fn unrelated_expired_lease_does_not_disable_a_plain_hit_or_expire_globally() {
    let owner = name("hit.test");
    let (mut left, counters, mut reference) = fixture(&owner, 1, Policy::default());
    reference.leases = Arc::new(LeaseNames::build(&[DnsLeaseRecord {
        name: b"unrelated.test", address: Ipv4Addr::new(192, 0, 2, 99), expires: Some(100),
    }], &mut reference.hosts, &[], LeasePolicy::default(), &mut ()));
    let mut right = left.snapshot();
    let mut candidate = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
    candidate.leases = Arc::clone(&reference.leases);
    let generation = Arc::clone(&candidate.leases);
    let packet = query(&owner, 1);
    let expected = general(&mut left, &mut reference, &packet, 101);
    let actual = in_place_answer(&mut right, &packet, &mut candidate, 101, &mut Vec::with_capacity(64))
        .expect("an unrelated lease does not own this name").unwrap();
    assert_eq!(expected, Some(QueryResult::Cached(actual)));
    assert!(Arc::ptr_eq(&generation, &candidate.leases));
    assert_eq!(candidate.leases.active_entries().count(), 1);
    assert_eq!(eviction_trace(&left, counters), eviction_trace(&right, counters));
}
