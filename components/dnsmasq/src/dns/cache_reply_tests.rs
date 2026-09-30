use super::*;
use crate::dns::cache::{Policy, Record, StalePolicy};
use crate::dns::wire::{Header, Message, Name};

fn record(kind: Kind, negative: bool, data: Vec<u8>) -> Record {
    Record {
        name: Name::from_ascii("cache.test").unwrap(),
        kind,
        negative,
        data,
    }
}

fn writer(qtype: u16, limit: usize) -> PacketWriter {
    let mut writer = PacketWriter::new(0x1234, 0x8190, limit).unwrap();
    writer
        .question(&Name::from_ascii("cache.test").unwrap(), qtype, 1)
        .unwrap();
    writer
}

#[test]
fn positive_record_has_remaining_ttl_and_does_not_rewrite_header() {
    let mut cache = Cache::new(2, Policy::default());
    cache.start_insert();
    let id = cache
        .insert(record(Kind::Ipv4, false, vec![192, 0, 2, 1]), 100, 30)
        .unwrap();
    assert!(cache.commit());
    let mut output = writer(1, 512);
    assert!(append_positive_record(&mut output, &cache, id, Section::Answer, 110, None).unwrap());
    let packet = output.finish();
    let message = Message::parse(&packet).unwrap();
    assert_eq!(message.header.id, 0x1234);
    assert_eq!(message.header.flags, 0x8190);
    assert_eq!(message.header.answers, 1);
    let answer = message.records(Section::Answer).next().unwrap();
    assert_eq!(answer.rrtype, 1);
    assert_eq!(answer.ttl, 20);
    assert_eq!(answer.rdata, &[192, 0, 2, 1]);
}

#[test]
fn expired_entry_is_omitted_and_stale_policy_keeps_zero_ttl() {
    for (stale, written) in [(StalePolicy::Disabled, false), (StalePolicy::Forever, true)] {
        let mut cache = Cache::new(
            1,
            Policy {
                stale,
                ..Policy::default()
            },
        );
        cache.start_insert();
        let id = cache
            .insert(record(Kind::Ipv6, false, vec![0; 16]), 100, 10)
            .unwrap();
        assert!(cache.commit());
        let mut output = writer(28, 512);
        assert_eq!(
            append_positive_record(&mut output, &cache, id, Section::Answer, 110, None).unwrap(),
            written
        );
        let packet = output.finish();
        let message = Message::parse(&packet).unwrap();
        assert_eq!(message.header.answers, u16::from(written));
        if written {
            assert_eq!(message.records(Section::Answer).next().unwrap().ttl, 0);
        }
    }
}

#[test]
fn generic_record_uses_own_type_and_caller_selected_section() {
    let mut cache = Cache::new(
        1,
        Policy {
            max_reply_ttl: 7,
            ..Policy::default()
        },
    );
    cache.start_insert();
    let id = cache
        .insert(
            record(Kind::Generic(65280), false, vec![0xc0, 0x0c, 0xff]),
            100,
            30,
        )
        .unwrap();
    assert!(cache.commit());
    let mut output = writer(1, 512);
    assert!(
        append_positive_record(&mut output, &cache, id, Section::Authority, 101, None).unwrap()
    );
    let packet = output.finish();
    let message = Message::parse(&packet).unwrap();
    assert_eq!(message.header.answers, 0);
    let rr = message.records(Section::Authority).next().unwrap();
    assert_eq!(rr.rrtype, 65280);
    assert_eq!(rr.ttl, 7);
    assert_eq!(rr.rdata, &[0xc0, 0x0c, 0xff]);
}

#[test]
fn negative_and_cname_entries_are_left_to_the_caller() {
    for kind in [Kind::Ipv4, Kind::Generic(16), Kind::NxDomain, Kind::Cname] {
        let mut cache = Cache::new(2, Policy::default());
        cache.start_insert();
        let id = cache
            .insert(record(kind, kind != Kind::Cname, vec![0; 4]), 100, 30)
            .unwrap();
        if kind == Kind::Cname {
            let target = cache
                .insert(
                    Record {
                        name: Name::from_ascii("target.test").unwrap(),
                        kind: Kind::Ipv4,
                        negative: false,
                        data: vec![192, 0, 2, 2],
                    },
                    100,
                    30,
                )
                .unwrap();
            assert!(cache.set_cname_target(id, target));
        }
        assert!(cache.commit());
        let mut output = writer(1, 512);
        assert!(
            !append_positive_record(&mut output, &cache, id, Section::Answer, 100, None).unwrap()
        );
        assert_eq!(Header::parse(&output.finish()).unwrap().answers, 0);
    }
}

#[test]
fn full_writer_keeps_complete_records_and_marks_tc() {
    let mut cache = Cache::new(2, Policy::default());
    cache.start_insert();
    let first = cache
        .insert(record(Kind::Ipv4, false, vec![192, 0, 2, 1]), 100, 30)
        .unwrap();
    let second = cache
        .insert(record(Kind::Ipv4, false, vec![192, 0, 2, 2]), 100, 30)
        .unwrap();
    assert!(cache.commit());
    let mut output = writer(1, 54);
    assert!(
        append_positive_record(&mut output, &cache, first, Section::Answer, 100, None).unwrap()
    );
    assert_eq!(
        append_positive_record(&mut output, &cache, second, Section::Answer, 100, None),
        Err(WireError::Full)
    );
    let packet = output.finish();
    let message = Message::parse(&packet).unwrap();
    assert_eq!(packet.len(), 54);
    assert_eq!(message.header.answers, 1);
    assert_ne!(message.header.flags & 0x0200, 0);
    assert_eq!(
        message.records(Section::Answer).next().unwrap().rdata,
        &[192, 0, 2, 1]
    );
}

#[test]
fn malformed_address_is_rejected_before_mutating_writer() {
    let mut cache = Cache::new(1, Policy::default());
    cache.start_insert();
    let id = cache
        .insert(record(Kind::Ipv4, false, vec![192, 0, 2]), 100, 30)
        .unwrap();
    assert!(cache.commit());
    let mut output = writer(1, 512);
    assert_eq!(
        append_positive_record(&mut output, &cache, id, Section::Answer, 100, None),
        Err(WireError::InvalidName)
    );
    assert_eq!(Header::parse(&output.finish()).unwrap().answers, 0);
}
