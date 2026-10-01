//! Storage invariants for the private reverse candidate. Packet equivalence
//! is checked separately against the independent frozen native C gate.
use super::*;

fn reverse(name: &str, last: u8) -> Record {
    Record {
        name: Name::from_ascii(name).unwrap(),
        kind: Kind::ReverseIpv4,
        negative: false,
        data: vec![192, 0, 2, last],
    }
}

fn forward(name: &str) -> Record {
    Record {
        name: Name::from_ascii(name).unwrap(),
        kind: Kind::Ipv4,
        negative: false,
        data: vec![192, 0, 2, 200],
    }
}

#[test]
fn reverse_stays_outside_forward_answers_and_pending_lookup() {
    let mut cache = Cache::new(4, Policy::default());
    let name = Name::from_ascii("TaRgEt.test").unwrap();
    let address = IpAddr::from([192, 0, 2, 1]);
    cache.start_insert();
    let pending = cache.insert(reverse("TaRgEt.test", 1), 100, 120).unwrap();
    assert!(cache.lookup_reverse(address, 300).is_empty());
    assert!(cache.get(pending).is_some());
    assert!(cache.commit());
    assert_eq!(cache.lookup_reverse(address, 100), [pending]);
    assert_eq!(
        cache.get(pending).unwrap().record.name.as_wire(),
        name.as_wire()
    );
    assert!(cache.lookup(&name, &[Kind::Ipv4], 100, false).is_empty());
    assert!(!cache.contains_forward_name(&name, 100));
    cache.start_insert();
    let forward = cache.insert(forward("target.test"), 100, 120).unwrap();
    assert!(cache.commit());
    cache.start_insert();
    cache
        .insert(reverse("replacement.test", 1), 101, 120)
        .unwrap();
    assert!(cache.commit());
    assert!(cache.get(pending).is_none());
    assert_eq!(cache.lookup(&name, &[Kind::Ipv4], 101, false), [forward]);
}

#[test]
fn forward_cname_replacement_does_not_remove_live_reverse_target() {
    let mut cache = Cache::new(3, Policy::default());
    cache.start_insert();
    let reverse = cache.insert(reverse("same.test", 1), 100, 120).unwrap();
    assert!(cache.commit());
    cache.start_insert();
    let name = Name::from_ascii("same.test").unwrap();
    let alias = cache
        .insert(
            Record {
                name: name.clone(),
                kind: Kind::Cname,
                negative: false,
                data: Name::from_ascii("terminal.test").unwrap().canonical_wire(),
            },
            100,
            120,
        )
        .unwrap();
    let target = cache.insert(forward("terminal.test"), 100, 120).unwrap();
    assert!(cache.set_cname_target(alias, target));
    assert!(cache.commit());
    assert!(cache.get(reverse).is_some());
    assert_eq!(cache.lookup(&name, &[Kind::Cname], 100, false), [alias]);
    assert_eq!(
        cache.lookup_reverse(IpAddr::from([192, 0, 2, 1]), 100),
        [reverse]
    );
}

#[test]
fn reverse_lookup_and_insertion_have_distinct_expiry_scopes() {
    let mut cache = Cache::new(4, Policy::default());
    cache.start_insert();
    let old_reverse = cache.insert(reverse("old.test", 1), 100, 10).unwrap();
    let old_forward = cache.insert(forward("forward.test"), 100, 10).unwrap();
    let live = cache.insert(reverse("live.test", 2), 100, 120).unwrap();
    assert!(cache.commit());
    assert_eq!(
        cache.lookup_reverse(IpAddr::from([192, 0, 2, 2]), 110),
        [live]
    );
    assert!(cache.get(old_reverse).is_none());
    assert!(cache.get(old_forward).is_some());
    cache.start_insert();
    cache.insert(reverse("new.test", 3), 110, 120).unwrap();
    assert!(cache.get(old_forward).is_none());
    assert!(cache.commit());
}

#[test]
fn reverse_victim_removes_address_rrset_and_counts_one_eviction() {
    let mut cache = Cache::new(3, Policy::default());
    let mut counters = CacheCounters::default();
    cache.start_insert();
    cache
        .insert_counted(reverse("one.test", 1), 100, 120, &mut counters)
        .unwrap();
    cache
        .insert_counted(reverse("two.test", 1), 100, 120, &mut counters)
        .unwrap();
    cache
        .insert_counted(forward("sentinel.test"), 100, 120, &mut counters)
        .unwrap();
    assert!(cache.commit_counted(&mut counters));
    cache.lookup_reverse(IpAddr::from([192, 0, 2, 1]), 100);
    cache.lookup(
        &Name::from_ascii("sentinel.test").unwrap(),
        &[Kind::Ipv4],
        100,
        false,
    );
    cache.start_insert();
    cache
        .insert_counted(forward("new.test"), 100, 120, &mut counters)
        .unwrap();
    assert!(cache.commit_counted(&mut counters));
    assert!(cache
        .lookup_reverse(IpAddr::from([192, 0, 2, 1]), 100)
        .is_empty());
    assert_eq!(
        counters,
        CacheCounters {
            inserted: 4,
            live_freed: 1
        }
    );
}

#[test]
fn invalid_reverse_payload_fails_transaction_without_panicking() {
    for (kind, length) in [(Kind::ReverseIpv4, 3), (Kind::ReverseIpv6, 15)] {
        let mut cache = Cache::new(2, Policy::default());
        let mut record = reverse("bad.test", 1);
        record.kind = kind;
        record.data.resize(length, 0);
        assert_eq!(
            cache.insert(record, 100, 120),
            Err(InsertError::InvalidReverseRecord)
        );
        assert!(!cache.commit());
        assert_eq!(
            cache.insert(forward("next.test"), 100, 120),
            Err(InsertError::PreviousFailure)
        );
        cache.start_insert();
        assert!(cache.insert(forward("next.test"), 100, 120).is_ok());
    }
}
