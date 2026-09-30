use super::*;
use crate::dns::cache::{Policy, Record};
use crate::dns::wire::{Header, Message, Section};

fn record(name: &str, kind: Kind, negative: bool, data: Vec<u8>) -> Record {
    Record {
        name: Name::from_ascii(name).unwrap(),
        kind,
        negative,
        data,
    }
}

#[test]
fn positive_hit_projects_remaining_ttl_into_wire() {
    let mut cache = Cache::new(4, Policy::default());
    cache.start_insert();
    cache
        .insert(
            record("router.test", Kind::Ipv4, false, vec![192, 0, 2, 1]),
            100,
            30,
        )
        .unwrap();
    assert!(cache.commit());

    let packet = answer_from_cache(
        &mut cache,
        CacheQuery {
            name: &Name::from_ascii("router.test").unwrap(),
            qtype: 1,
            qclass: 1,
            id: 0x1234,
            base_flags: 0x0080,
            now: 110,
            limit: 512,
            round_robin: false,
        },
    )
    .unwrap()
    .unwrap();
    let header = Header::parse(&packet).unwrap();
    assert_eq!(header.id, 0x1234);
    assert_eq!(header.flags & 0x8000, 0x8000);
    assert_eq!(header.answers, 1);
    let message = Message::parse(&packet).unwrap();
    let answer = message.records(Section::Answer).next().unwrap();
    assert_eq!(answer.rrtype, 1);
    assert_eq!(answer.ttl, 20);
    assert_eq!(answer.rdata, &[192, 0, 2, 1]);
}

#[test]
fn nxdomain_hit_sets_rcode_without_answer_rrs() {
    let mut cache = Cache::new(2, Policy::default());
    cache.start_insert();
    cache
        .insert(
            record("missing.test", Kind::NxDomain, true, Vec::new()),
            100,
            30,
        )
        .unwrap();
    assert!(cache.commit());

    let packet = answer_from_cache(
        &mut cache,
        CacheQuery {
            name: &Name::from_ascii("missing.test").unwrap(),
            qtype: 28,
            qclass: 1,
            id: 9,
            base_flags: 0x0080,
            now: 100,
            limit: 512,
            round_robin: false,
        },
    )
    .unwrap()
    .unwrap();
    let header = Header::parse(&packet).unwrap();
    assert_eq!(header.rcode(), 3);
    assert_eq!(header.questions, 1);
    assert_eq!(header.answers, 0);
}

#[test]
fn negative_nodata_hit_is_distinct_from_forward_miss() {
    let mut cache = Cache::new(2, Policy::default());
    cache.start_insert();
    cache
        .insert(record("nodata.test", Kind::Ipv4, true, Vec::new()), 100, 30)
        .unwrap();
    assert!(cache.commit());

    let packet = answer_from_cache(
        &mut cache,
        CacheQuery {
            name: &Name::from_ascii("nodata.test").unwrap(),
            qtype: 1,
            qclass: 1,
            id: 1,
            base_flags: 0x0080,
            now: 100,
            limit: 512,
            round_robin: false,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(Header::parse(&packet).unwrap().answers, 0);
    assert!(answer_from_cache(
        &mut cache,
        CacheQuery {
            name: &Name::from_ascii("other.test").unwrap(),
            qtype: 1,
            qclass: 1,
            id: 1,
            base_flags: 0x0080,
            now: 100,
            limit: 512,
            round_robin: false,
        },
    )
    .unwrap()
    .is_none());
}

#[test]
fn cname_hit_emits_alias_and_terminal_address() {
    let mut cache = Cache::new(4, Policy::default());
    cache.start_insert();
    let cname = cache
        .insert(
            record(
                "alias.test",
                Kind::Cname,
                false,
                Name::from_ascii("target.test").unwrap().as_wire().to_vec(),
            ),
            100,
            30,
        )
        .unwrap();
    let target = cache
        .insert(
            record("target.test", Kind::Ipv4, false, vec![192, 0, 2, 9]),
            100,
            20,
        )
        .unwrap();
    assert!(cache.set_cname_target(cname, target));
    assert!(cache.commit());

    let packet = answer_from_cache(
        &mut cache,
        CacheQuery {
            name: &Name::from_ascii("alias.test").unwrap(),
            qtype: 1,
            qclass: 1,
            id: 2,
            base_flags: 0x0080,
            now: 100,
            limit: 512,
            round_robin: false,
        },
    )
    .unwrap()
    .unwrap();
    let message = Message::parse(&packet).unwrap();
    let records: Vec<_> = message.records(Section::Answer).collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].rrtype, 5);
    assert_eq!(records[1].rrtype, 1);
    assert_eq!(records[1].rdata, &[192, 0, 2, 9]);
}
