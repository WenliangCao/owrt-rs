use super::*;
use std::collections::HashSet;

fn record(name: &str, kind: Kind, value: u8) -> Record {
    Record {
        name: Name::from_ascii(name).unwrap(),
        kind,
        negative: false,
        data: vec![value],
    }
}

fn lookup(cache: &mut Cache, name: &str, kind: Kind, now: i64) -> Vec<u8> {
    cache
        .lookup(&Name::from_ascii(name).unwrap(), &[kind], now, false)
        .into_iter()
        .map(|id| cache.get(id).unwrap().record.data[0])
        .collect()
}

fn check_ownership(cache: &Cache) {
    let mut linked = HashSet::new();
    let mut previous = None;
    let mut at = cache.head;
    while let Some(index) = at {
        assert!(linked.insert(index), "cycle or duplicated slot");
        let slot = &cache.slots[index];
        assert_eq!(slot.prev, previous);
        assert!(slot.entry.as_ref().is_none_or(|entry| entry.committed));
        previous = at;
        at = slot.next;
    }
    assert_eq!(previous, cache.tail);
    for &slot in &cache.pending {
        assert!(linked.insert(slot));
        assert!(!cache.slots[slot].entry.as_ref().unwrap().committed);
    }
    assert_eq!(linked.len(), cache.slots.len());
    let mut indexed = HashSet::new();
    for (name, indices) in &cache.names {
        assert!(!indices.is_empty());
        for &slot in indices {
            assert!(indexed.insert(slot));
            let entry = cache.slots[slot].entry.as_ref().unwrap();
            assert!(entry.committed);
            assert_eq!(&entry.record.name.canonical_wire(), name);
        }
    }
    assert_eq!(
        indexed.len(),
        cache
            .slots
            .iter()
            .filter(|slot| slot.entry.as_ref().is_some_and(|entry| entry.committed))
            .count()
    );
}

#[test]
fn lease_publication_selectively_removes_ipv4_and_nodata() {
    let mut cache = Cache::new(8, Policy::default());
    cache.start_insert();
    for (kind, value, negative) in [
        (Kind::Ipv4, 1, false),
        (Kind::Ipv4, 2, true),
        (Kind::Ipv6, 3, false),
        (Kind::Generic(16), 4, false),
        (Kind::NxDomain, 5, true),
    ] {
        let mut entry = record("lease.test", kind, value);
        entry.negative = negative;
        cache.insert(entry, 100, 90).unwrap();
    }
    cache
        .insert(record("other.test", Kind::Ipv4, 6), 100, 90)
        .unwrap();
    assert!(cache.commit());
    cache.prepare_name(ForwardPublication {
        name: b"LEASE.test",
        blockers: &[],
        no_round_robin: false,
    });
    assert!(lookup(&mut cache, "lease.test", Kind::Ipv4, 100).is_empty());
    for (kind, value) in [(Kind::Ipv6, 3), (Kind::Generic(16), 4), (Kind::NxDomain, 5)] {
        assert_eq!(lookup(&mut cache, "lease.test", kind, 100), [value]);
    }
    assert_eq!(lookup(&mut cache, "other.test", Kind::Ipv4, 100), [6]);
    assert!(!cache.reverse_owned("192.0.2.7".parse().unwrap()));
    check_ownership(&cache);
}

#[test]
fn lease_publication_mortal_blocker_can_stop_after_partial_deletion() {
    use super::super::lease_names::PublicationBlocker;
    for (reverse, immortal, no_round_robin, expected) in [
        (true, true, false, vec![1, 2]),
        (false, true, false, vec![]),
        (false, false, true, vec![]),
        (false, false, false, vec![2]),
    ] {
        let mut cache = Cache::new(4, Policy::default());
        cache.start_insert();
        cache
            .insert(record("lease.test", Kind::Ipv4, 1), 100, 90)
            .unwrap();
        cache
            .insert(record("lease.test", Kind::Ipv4, 2), 100, 90)
            .unwrap();
        assert!(cache.commit());
        cache.prepare_name(ForwardPublication {
            name: b"lease.test",
            no_round_robin,
            blockers: &[PublicationBlocker {
                kind: BlockerKind::Ipv4,
                reverse,
                immortal,
            }],
        });
        assert_eq!(lookup(&mut cache, "lease.test", Kind::Ipv4, 100), expected);
        check_ownership(&cache);
    }
}

#[test]
fn lease_publication_invalidates_external_cname_without_rebinding_reused_slot() {
    let mut cache = Cache::new(3, Policy::default());
    cache.start_insert();
    let alias = cache
        .insert(record("alias.test", Kind::Cname, 0), 100, 90)
        .unwrap();
    let target = cache
        .insert(record("lease.test", Kind::Ipv4, 1), 100, 90)
        .unwrap();
    assert!(cache.set_cname_target(alias, target));
    assert!(cache.commit());
    cache.prepare_name(ForwardPublication {
        name: b"lease.test",
        blockers: &[],
        no_round_robin: false,
    });
    assert!(cache.get(target).is_none());
    assert!(!cache.is_valid(alias, 100));
    for i in 0..100 {
        cache.start_insert();
        cache
            .insert(
                record(&format!("replacement{i}.test"), Kind::Ipv4, 2),
                100,
                90,
            )
            .unwrap();
        assert!(cache.commit());
        assert!(!cache.is_valid(alias, 100));
        assert!(!cache.is_valid(target, 100));
        assert!(lookup(&mut cache, "alias.test", Kind::Cname, 100).is_empty());
        check_ownership(&cache);
    }
}

#[test]
fn lease_publication_cname_trigger_conflicts_with_other_families() {
    use super::super::lease_names::PublicationBlocker;
    for protected in [false, true] {
        let mut cache = Cache::new(8, Policy::default());
        cache.start_insert();
        let alias = cache
            .insert(record("lease.test", Kind::Cname, 0), 100, 90)
            .unwrap();
        for (kind, value) in [
            (Kind::Ipv4, 1),
            (Kind::Ipv6, 2),
            (Kind::Generic(16), 3),
            (Kind::NxDomain, 4),
        ] {
            cache
                .insert(record("lease.test", kind, value), 100, 90)
                .unwrap();
        }
        let target = cache
            .insert(record("target.test", Kind::Ipv4, 5), 100, 90)
            .unwrap();
        assert!(cache.set_cname_target(alias, target));
        assert!(cache.commit());
        let blockers = [PublicationBlocker {
            kind: BlockerKind::Ipv6,
            reverse: true,
            immortal: true,
        }];
        cache.prepare_name(ForwardPublication {
            name: b"lease.test",
            no_round_robin: false,
            blockers: if protected { &blockers } else { &[] },
        });
        for kind in [
            Kind::Ipv4,
            Kind::Ipv6,
            Kind::Generic(16),
            Kind::NxDomain,
            Kind::Cname,
        ] {
            assert_eq!(
                !lookup(&mut cache, "lease.test", kind, 100).is_empty(),
                protected
            );
        }
        assert_eq!(lookup(&mut cache, "target.test", Kind::Ipv4, 100), [5]);
        check_ownership(&cache);
    }
}

#[test]
fn reload_clears_committed_and_failed_pending_records_without_reusing_handles() {
    for capacity in [0, 1, 10] {
        let policy = Policy {
            min_ttl: 7,
            ..Policy::default()
        };
        let mut cache = Cache::new(capacity, policy);
        let mut handles = Vec::new();
        if capacity > 0 {
            cache.start_insert();
            handles.push(cache.insert(record("old", Kind::Ipv4, 1), 100, 10).unwrap());
            assert!(cache.commit());
            cache.start_insert();
            handles.push(
                cache
                    .insert(record("pending", Kind::Ipv4, 2), 100, 10)
                    .unwrap(),
            );
            assert!(cache
                .insert(record("overflow", Kind::Ipv4, 3), i64::MAX, 10)
                .is_err());
            assert!(!cache.commit());
        }
        cache.clear();
        cache.clear();
        assert_eq!(cache.policy().min_ttl, policy.min_ttl);
        assert_eq!(cache.policy().max_ttl, policy.max_ttl);
        assert_eq!(cache.policy().max_reply_ttl, policy.max_reply_ttl);
        assert_eq!(cache.policy().stale, policy.stale);
        check_ownership(&cache);
        assert!(lookup(&mut cache, "old", Kind::Ipv4, 100).is_empty());
        assert!(lookup(&mut cache, "pending", Kind::Ipv4, 100).is_empty());
        for index in 0..capacity {
            cache
                .insert(record(&format!("new-{index}"), Kind::Ipv4, 4), 100, 1)
                .unwrap();
        }
        assert!(cache.commit());
        for handle in handles {
            assert!(cache.get(handle).is_none());
        }
        check_ownership(&cache);
    }
}

#[test]
fn failed_transaction_does_not_restore_removed_old_records() {
    let mut cache = Cache::new(2, Policy::default());
    cache.start_insert();
    cache.insert(record("a", Kind::Ipv4, 1), 100, 10).unwrap();
    assert!(cache.commit());
    cache.start_insert();
    let pending = cache.insert(record("a", Kind::Ipv4, 2), 100, 10).unwrap();
    assert_eq!(
        cache.insert(record("b", Kind::Ipv4, 3), 100, 0),
        Err(InsertError::ZeroTtl)
    );
    assert!(!cache.commit());
    assert!(lookup(&mut cache, "a", Kind::Ipv4, 100).is_empty());
    cache.start_insert();
    assert!(cache.get(pending).is_none());
    check_ownership(&cache);
}

#[test]
fn cname_preserves_same_name_replacement_but_not_evicted_target() {
    let mut cache = Cache::new(3, Policy::default());
    cache.start_insert();
    let alias = cache
        .insert(record("alias", Kind::Cname, 0), 100, 100)
        .unwrap();
    let target = cache
        .insert(record("target", Kind::Ipv4, 1), 100, 20)
        .unwrap();
    assert!(cache.set_cname_target(alias, target));
    assert!(cache.commit());
    cache.start_insert();
    let replacement = cache
        .insert(record("TARGET", Kind::Ipv4, 2), 110, 20)
        .unwrap();
    assert_eq!(replacement, target);
    assert!(cache.commit());
    assert_eq!(lookup(&mut cache, "alias", Kind::Cname, 110), [0]);
    assert!(lookup(&mut cache, "target", Kind::Ipv4, 130).is_empty());
    cache.start_insert();
    let unrelated = cache
        .insert(record("other", Kind::Ipv4, 3), 130, 20)
        .unwrap();
    assert_ne!(unrelated, target);
    assert!(cache.commit());
    assert!(lookup(&mut cache, "alias", Kind::Cname, 130).is_empty());
    check_ownership(&cache);
}

#[test]
fn eviction_spills_whole_rrset() {
    let mut cache = Cache::new(2, Policy::default());
    cache.start_insert();
    cache.insert(record("a", Kind::Ipv4, 1), 100, 100).unwrap();
    cache.insert(record("a", Kind::Ipv4, 2), 100, 100).unwrap();
    cache.commit();
    cache.start_insert();
    cache.insert(record("b", Kind::Ipv4, 3), 100, 100).unwrap();
    cache.commit();
    assert!(lookup(&mut cache, "a", Kind::Ipv4, 100).is_empty());
    assert_eq!(lookup(&mut cache, "b", Kind::Ipv4, 100), [3]);
    check_ownership(&cache);
}

#[test]
fn stale_and_ttl_boundaries_are_distinct() {
    let policy = Policy {
        min_ttl: 30,
        max_ttl: 20,
        max_reply_ttl: 5,
        stale: StalePolicy::Seconds(5),
    };
    let mut cache = Cache::new(1, policy);
    cache.start_insert();
    let id = cache.insert(record("a", Kind::Ipv4, 1), 100, 0).unwrap();
    cache.commit();
    assert_eq!(cache.get(id).unwrap().expires, 130);
    assert_eq!(cache.get(id).unwrap().reply_ttl(100, policy), 5);
    assert_eq!(lookup(&mut cache, "a", Kind::Ipv4, 130), [1]);
    assert!(!cache.get(id).unwrap().is_stale(130));
    assert!(cache.get(id).unwrap().is_stale(131));
    assert_eq!(lookup(&mut cache, "a", Kind::Ipv4, 134), [1]);
    assert!(lookup(&mut cache, "a", Kind::Ipv4, 135).is_empty());
}

#[test]
fn zero_stale_allowance_disables_zero_ttl_insertion() {
    let mut cache = Cache::new(
        1,
        Policy {
            stale: StalePolicy::Seconds(0),
            ..Policy::default()
        },
    );
    cache.start_insert();
    assert_eq!(
        cache.insert(record("a", Kind::Ipv4, 1), 100, 0),
        Err(InsertError::ZeroTtl)
    );
    check_ownership(&cache);
}

#[test]
fn negative_insert_prefers_soa_ttl_and_applies_cache_policy() {
    let mut cache = Cache::new(
        2,
        Policy {
            min_ttl: 20,
            max_ttl: 60,
            ..Policy::default()
        },
    );
    cache.start_insert();
    let id = cache
        .insert_negative(
            Record {
                name: Name::from_ascii("missing.test").unwrap(),
                kind: Kind::NxDomain,
                negative: true,
                data: vec![0xaa],
            },
            100,
            Some(10),
            50,
        )
        .unwrap()
        .unwrap();
    assert!(cache.commit());
    // SOA TTL wins, then min-cache-ttl raises it to the configured floor.
    assert_eq!(cache.get(id).unwrap().expires, 120);
}

#[test]
fn negative_insert_uses_fallback_only_without_soa_and_zero_disables_it() {
    let mut cache = Cache::new(2, Policy::default());
    cache.start_insert();
    let no_soa = cache
        .insert_negative(
            Record {
                name: Name::from_ascii("missing.test").unwrap(),
                kind: Kind::NxDomain,
                negative: true,
                data: Vec::new(),
            },
            100,
            None,
            30,
        )
        .unwrap()
        .unwrap();
    assert!(cache.commit());
    assert_eq!(cache.get(no_soa).unwrap().expires, 130);

    cache.start_insert();
    assert_eq!(
        cache
            .insert_negative(
                Record {
                    name: Name::from_ascii("other.test").unwrap(),
                    kind: Kind::NxDomain,
                    negative: true,
                    data: Vec::new(),
                },
                100,
                None,
                0,
            )
            .unwrap(),
        None
    );
    assert!(cache.commit());
}

#[test]
fn negative_insert_does_not_replace_soa_zero_with_fallback() {
    let mut cache = Cache::new(1, Policy::default());
    cache.start_insert();
    assert_eq!(
        cache.insert_negative(
            Record {
                name: Name::from_ascii("missing.test").unwrap(),
                kind: Kind::NxDomain,
                negative: true,
                data: Vec::new(),
            },
            100,
            Some(0),
            30,
        ),
        Err(InsertError::ZeroTtl)
    );
    assert!(!cache.commit());
}

#[test]
fn question_lookup_includes_name_wide_nxdomain() {
    let mut cache = Cache::new(2, Policy::default());
    cache.start_insert();
    let id = cache
        .insert(
            Record {
                name: Name::from_ascii("missing.test").unwrap(),
                kind: Kind::NxDomain,
                negative: true,
                data: Vec::new(),
            },
            100,
            30,
        )
        .unwrap();
    assert!(cache.commit());
    assert_eq!(
        cache.lookup_question(
            &Name::from_ascii("missing.test").unwrap(),
            Kind::Ipv4,
            100,
            false,
        ),
        vec![id]
    );
    assert!(cache
        .lookup(
            &Name::from_ascii("missing.test").unwrap(),
            &[Kind::Ipv4],
            100,
            false
        )
        .is_empty());
}

#[test]
fn nx_domain_coexists_with_addresses_and_generic_types_replace_separately() {
    let mut cache = Cache::new(4, Policy::default());
    for (kind, value) in [
        (Kind::Ipv4, 1),
        (Kind::NxDomain, 2),
        (Kind::Generic(16), 3),
        (Kind::Generic(33), 4),
    ] {
        cache.start_insert();
        cache.insert(record("a", kind, value), 100, 100).unwrap();
        cache.commit();
    }
    assert_eq!(lookup(&mut cache, "a", Kind::Ipv4, 100), [1]);
    assert_eq!(lookup(&mut cache, "a", Kind::NxDomain, 100), [2]);
    let mut rr = lookup(&mut cache, "a", Kind::Generic(16), 100);
    rr.sort();
    assert_eq!(rr, [3, 4]);
    check_ownership(&cache);
}

#[test]
fn bounded_state_survives_repeated_abort_expiry_and_reuse() {
    let mut cache = Cache::new(10, Policy::default());
    for round in 0..2000 {
        cache.start_insert();
        for i in 0..(round % 13) {
            let _ = cache.insert(
                record(&format!("n{}", (round + i) % 12), Kind::Ipv4, i as u8),
                round,
                3,
            );
            check_ownership(&cache);
        }
        if round % 5 != 0 {
            cache.commit();
        }
        check_ownership(&cache);
        for i in 0..12 {
            lookup(&mut cache, &format!("n{i}"), Kind::Ipv4, round);
            check_ownership(&cache);
        }
    }
}
