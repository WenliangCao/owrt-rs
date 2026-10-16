use super::*;

#[test]
fn dual_family_hint_rechecks_other_family_expiry_and_replacement() {
    let mut cache = Cache::new(8, Policy::default());
    let name = Name::from_ascii("dual.example").unwrap();
    cache.start_insert();
    let ipv4 = cache.insert(Record { name: name.clone(), kind: Kind::Ipv4,
        negative: false, data: vec![192, 0, 2, 7] }, 100, 60).unwrap();
    let ipv6 = cache.insert(Record { name: name.clone(), kind: Kind::Ipv6,
        negative: false, data: vec![7; 16] }, 100, 1).unwrap();
    assert!(cache.commit());
    let (_, hint) = cache.inspect_name(&name, 100);
    assert_eq!(cache.single_fresh_address_id_with_hint(&name, Kind::Ipv4, 100, hint.as_ref()), Some(ipv4));
    let before = (cache.head, cache.tail, cache.name_revision);
    assert_eq!(cache.single_fresh_address_with_hint(&name, Kind::Ipv4, 102, hint.as_ref()), None);
    assert_eq!((cache.head, cache.tail, cache.name_revision), before);
    assert!(cache.get(ipv6).is_some(), "fallback still owns expiry");
    assert_eq!(cache.lookup_with_hint(&name, &[Kind::Ipv4], 102, true, hint.as_ref()), [ipv4]);
    assert!(cache.get(ipv6).is_none());
    assert_eq!(cache.single_fresh_address_with_hint(&name, Kind::Ipv4, 100, hint.as_ref()), None,
        "the old dual-family hint must not survive removal");
}

#[test]
fn fresh_address_hint_promotes_only_an_eligible_single_and_preserves_fallback() {
    let address = |name: &str, value| Record { name: Name::from_ascii(name).unwrap(),
        kind: Kind::Ipv4, negative: false, data: vec![192,0,2,value] };
    let mut cache = Cache::new(4, Policy::default());
    cache.start_insert();
    let id = cache.insert(address("fresh.test",7),100,60).unwrap();
    cache.insert(address("other.test",8),100,60).unwrap();
    assert!(cache.commit());
    let name = Name::from_ascii("fresh.test").unwrap();
    let (_, hint) = cache.inspect_name(&name,100);
    let before = (cache.head,cache.tail,cache.name_revision);
    assert_eq!(cache.single_fresh_address_with_hint(&name,Kind::Ipv6,100,hint.as_ref()),None);
    let other_question = name.clone();
    assert_eq!(cache.single_fresh_address_with_hint(&other_question,Kind::Ipv4,100,hint.as_ref()),None);
    assert_eq!((cache.head,cache.tail,cache.name_revision),before);
    assert_eq!(cache.single_fresh_address_id_with_hint(&name,Kind::Ipv4,100,hint.as_ref()),Some(id));
    assert_eq!((cache.head,cache.tail,cache.name_revision),before,"read-only selection cannot promote before local ownership");
    assert_eq!(cache.single_fresh_address_with_hint(&name,Kind::Ipv4,100,hint.as_ref()),Some(id));
    assert_eq!(cache.head,Some(id.slot));
    let (_, hint) = cache.inspect_name(&name,100);
    let before = (cache.head,cache.tail,cache.name_revision);
    assert_eq!(cache.single_fresh_address_with_hint(&name,Kind::Ipv4,160,hint.as_ref()),None);
    assert_eq!((cache.head,cache.tail,cache.name_revision),before);
    assert!(cache.get(id).is_some(),"fast rejection must not expire the fallback's entry");
    assert!(cache.lookup_with_hint(&name,&[Kind::Ipv4],160,true,hint.as_ref()).is_empty());
    assert!(cache.get(id).is_none());

    cache.start_insert();
    cache.insert(address("fresh.test",1),200,60).unwrap();
    assert!(cache.commit());
    let (_, old_hint) = cache.inspect_name(&name,200);
    cache.start_insert();
    cache.insert(address("fresh.test",2),200,60).unwrap();
    cache.insert(address("fresh.test",3),200,60).unwrap();
    assert!(cache.commit());
    let before = (cache.head,cache.tail,cache.name_revision);
    assert_eq!(cache.single_fresh_address_with_hint(&name,Kind::Ipv4,200,old_hint.as_ref()),None);
    let (_, many) = cache.inspect_name(&name,200);
    assert!(many.is_none());
    assert_eq!(cache.single_fresh_address_with_hint(&name,Kind::Ipv4,200,many.as_ref()),None);
    assert_eq!((cache.head,cache.tail,cache.name_revision),before);
    assert_eq!(cache.lookup_with_hint(&name,&[Kind::Ipv4],200,true,many.as_ref()).len(),2);
}

#[test]
fn name_hint_keeps_inspection_read_only_and_lookup_expiry_effects() {
    let mut cache = Cache::new(8, Policy::default());
    cache.start_insert();
    let id = cache.insert(record("hint.test", Kind::Ipv4, 7), 100, 60).unwrap();
    cache.insert(record("other.test", Kind::Ipv4, 8), 100, 60).unwrap();
    assert!(cache.commit());
    let name = Name::from_ascii("hint.test").unwrap();
    let before = (cache.head, cache.tail, cache.name_revision);
    let (cname, hint) = cache.inspect_name(&name, 100);
    assert!(!cname);
    assert_eq!((cache.head, cache.tail, cache.name_revision), before);
    assert_eq!(cache.lookup_with_hint(&name, &[Kind::Ipv4], 100, true, hint.as_ref()), [id]);
    assert_eq!(cache.head, Some(id.slot));
    let (_, hint) = cache.inspect_name(&name, 100);
    assert!(cache.lookup_with_hint(&name, &[Kind::Ipv4], 160, true, hint.as_ref()).is_empty());
    assert!(cache.get(id).is_none(), "expiry removal must happen in actual lookup");
}

#[test]
fn name_hint_rejects_new_members_and_a_different_question() {
    let mut cache = Cache::new(8, Policy::default());
    let name = Name::from_ascii("hint.test").unwrap();
    let (_, absent) = cache.inspect_name(&name, 100);
    cache.start_insert();
    let first = cache.insert(record("hint.test", Kind::Ipv4, 1), 100, 60).unwrap();
    assert!(cache.commit());
    assert_eq!(cache.lookup_with_hint(&name, &[Kind::Ipv4], 100, false, absent.as_ref()), [first]);
    let (_, single) = cache.inspect_name(&name, 100);
    let other = Name::from_ascii("other.test").unwrap();
    assert!(cache.lookup_with_hint(&other, &[Kind::Ipv4], 100, false, single.as_ref()).is_empty());
    cache.start_insert();
    cache.insert(record("hint.test", Kind::Ipv6, 2), 100, 60).unwrap();
    assert!(cache.commit());
    assert!(cache.get(first).is_some(), "old handle validity alone cannot detect the new member");
    assert_eq!(cache.lookup_with_hint(&name, &[Kind::Ipv4, Kind::Ipv6], 100, false, single.as_ref()).len(), 2);
}

#[test]
fn name_hint_rejects_cache_replacement_and_saturated_revisions() {
    let make = |rows: &[(&str, u8)]| {
        let mut cache = Cache::new(8, Policy::default());
        cache.start_insert();
        for (name, value) in rows {
            cache.insert(record(name, Kind::Ipv4, *value), 100, 60).unwrap();
        }
        assert!(cache.commit());
        cache
    };
    let mut cache = make(&[("hint.test", 11), ("other.test", 22)]);
    let mut replacement = make(&[("other.test", 44), ("hint.test", 33)]);
    assert_eq!(cache.name_revision, replacement.name_revision);
    let name = Name::from_ascii("hint.test").unwrap();
    let (_, hint) = cache.inspect_name(&name, 100);
    std::mem::swap(&mut cache, &mut replacement);
    let rows = cache.lookup_with_hint(&name, &[Kind::Ipv4], 100, false, hint.as_ref());
    assert_eq!(cache.get(rows[0]).unwrap().record.data, [33]);
    let (_, hint) = cache.inspect_name(&name, 100);
    let mut moved = Box::new(cache);
    let rows = moved.lookup_with_hint(&name, &[Kind::Ipv4], 100, false, hint.as_ref());
    assert_eq!(moved.get(rows[0]).unwrap().record.data, [33]);

    let mut cache = Cache::new(8, Policy::default());
    cache.name_revision = u64::MAX;
    let (_, hint) = cache.inspect_name(&name, 100);
    cache.start_insert();
    let id = cache.insert(record("hint.test", Kind::Ipv4, 55), 100, 60).unwrap();
    assert!(cache.commit());
    assert_eq!(cache.name_revision, u64::MAX);
    assert_eq!(cache.lookup_with_hint(&name, &[Kind::Ipv4], 100, false, hint.as_ref()), [id]);
}

#[test]
fn name_hint_does_not_pin_multi_record_lists_or_create_rotation_cow() {
    let mut cache = Cache::new(8, Policy::default());
    cache.start_insert();
    for value in [1, 2] {
        cache.insert(record("hint.test", Kind::Ipv4, value), 100, 60).unwrap();
    }
    assert!(cache.commit());
    let name = Name::from_ascii("hint.test").unwrap();
    let key = name.canonical_wire();
    let SlotIndices::Many(indices) = cache.names_for(&key).unwrap() else { panic!() };
    let buffer = indices.as_ptr();
    assert_eq!(Arc::strong_count(indices), 1);
    let (_, hint) = cache.inspect_name(&name, 100);
    let SlotIndices::Many(indices) = cache.names_for(&key).unwrap() else { panic!() };
    assert!(hint.is_none(), "multi-record lookup keeps the ordinary loop");
    assert_eq!(Arc::strong_count(indices), 1);
    assert_eq!(cache.lookup_with_hint(&name, &[Kind::Ipv4], 100, true, hint.as_ref()).len(), 2);
    let SlotIndices::Many(indices) = cache.names_for(&key).unwrap() else { panic!() };
    assert_eq!(indices.as_ptr(), buffer);
}

#[test]
fn real_mixed_rrset_rotation_keeps_unique_many_allocation_and_snapshot_order() {
    let mut parent = Cache::new(8, Policy::default());
    let name = Name::from_ascii("mixed.index.test").unwrap();
    let key = name.canonical_wire();
    parent.start_insert();
    for (kind, value) in [(Kind::Ipv4, 1), (Kind::Ipv6, 2), (Kind::Generic(16), 3),
                          (Kind::Ipv4, 4), (Kind::Generic(15), 5)] {
        parent.insert(record("mixed.index.test", kind, value), 100, 60).unwrap();
    }
    assert!(parent.commit());
    let SlotIndices::Many(indices) = parent.names_for(&key).unwrap() else { panic!() };
    let unique = indices.as_ptr();
    parent.lookup(&name, &[Kind::Ipv4], 100, true);
    let SlotIndices::Many(indices) = parent.names_for(&key).unwrap() else { panic!() };
    assert_eq!(indices.as_ptr(), unique, "lookup's temporary snapshot must be gone before unique rotation");
    let order = |cache: &Cache| cache.names_for(&key).unwrap().iter()
        .map(|&slot| cache.entry(slot).unwrap().record.data[0]).collect::<Vec<_>>();
    assert_eq!(order(&parent), [5, 1, 4, 3, 2]);
    let mut child = parent.snapshot();
    child.lookup(&name, &[Kind::Generic(16)], 100, true);
    assert_eq!(order(&parent), [5, 1, 4, 3, 2]);
    assert_eq!(order(&child), [3, 5, 1, 4, 2]);
    check_ownership(&parent);
    check_ownership(&child);
}

#[test]
fn shard_detach_shares_many_indices_until_order_write_and_keeps_canonical_key_alive() {
    let mut parent = Cache::new(8, Policy::default());
    let name = Name::from_ascii("shared.rrset.test").unwrap();
    let key = name.canonical_wire();
    let shard = Cache::key_shard(&key);
    parent.start_insert();
    parent.insert(record("shared.rrset.test", Kind::Ipv4, 1), 100, 60).unwrap();
    parent.insert(record("shared.rrset.test", Kind::Ipv4, 2), 100, 60).unwrap();
    assert!(parent.commit());
    let parent_key = parent.names[shard].keys().find(|old| old.as_ref() == key.as_slice()).unwrap();
    // Only the immutable key has a Weak observer. Content/index root weak
    // references would change Arc::make_mut's detach behavior.
    let key_lifetime = Arc::downgrade(parent_key);
    let parent_key = parent_key.as_ptr();
    let mut child = parent.snapshot();
    // Write another name in this shard so the map detaches while its existing
    // multi-record value must still share the immutable ordered index slice.
    let other = (0..4096).map(|i| format!("neighbor-{i}.test")).find(|text| {
        Cache::key_shard(&Name::from_ascii(text).unwrap().canonical_wire()) == shard
    }).unwrap();
    child.start_insert();
    child.insert(record(&other, Kind::Ipv4, 3), 100, 60).unwrap();
    assert!(child.commit());
    let (SlotIndices::Many(parent_indices), SlotIndices::Many(child_indices)) =
        (parent.names_for(&key).unwrap(), child.names_for(&key).unwrap()) else { panic!() };
    assert!(Arc::ptr_eq(parent_indices, child_indices));
    assert!(!Arc::ptr_eq(&parent.names[shard], &child.names[shard]));
    let old_order = parent_indices.to_vec();
    child.lookup(&name, &[Kind::Ipv4], 100, true);
    assert_eq!(&**parent.names_for(&key).unwrap(), old_order.as_slice());
    assert_ne!(&**child.names_for(&key).unwrap(), old_order.as_slice());
    parent.clear();
    let child_key = child.names[shard].keys().find(|old| old.as_ref() == key.as_slice()).unwrap().as_ptr();
    assert_eq!(child_key, parent_key, "detached map retains the canonical key payload");
    assert_eq!(child.lookup(&name, &[Kind::Ipv4], 100, false).len(), 2);
    assert!(key_lifetime.upgrade().is_some());
    drop(child);
    assert!(key_lifetime.upgrade().is_none(), "last view must release its canonical key");
}

#[test]
fn tcp_retained_view_keeps_negative_reverse_lease_and_rotation_private() {
    let mut parent = Cache::new(16, Policy::default());
    parent.start_insert();
    let negative = parent
        .insert(
            Record {
                name: Name::from_ascii("negative.snapshot.test").unwrap(),
                kind: Kind::NxDomain,
                negative: true,
                data: Vec::new(),
            },
            100,
            60,
        )
        .unwrap();
    parent.set_negative_authority(negative, Name::from_ascii("old.authority.test").unwrap());
    parent
        .insert(
            Record {
                name: Name::from_ascii("reverse.snapshot.test").unwrap(),
                kind: Kind::ReverseIpv4,
                negative: false,
                data: vec![192, 0, 2, 17],
            },
            100,
            60,
        )
        .unwrap();
    let alias = parent
        .insert(record("lease-alias.snapshot.test", Kind::Cname, 0), 100, 60)
        .unwrap();
    let lease = parent.local_target(Name::from_ascii("lease.snapshot.test").unwrap(), true);
    assert!(parent.set_local_cname_target(alias, lease));
    parent
        .insert(record("rrset.snapshot.test", Kind::Ipv4, 1), 100, 60)
        .unwrap();
    parent
        .insert(record("rrset.snapshot.test", Kind::Ipv4, 2), 100, 60)
        .unwrap();
    assert!(parent.commit());
    let name = Name::from_ascii("rrset.snapshot.test").unwrap();
    let before_order = parent.names_for(&name.canonical_wire()).unwrap().clone();
    let mut child = parent.snapshot();

    assert!(child.set_negative_authority(negative, Name::from_ascii("new.authority.test").unwrap()));
    assert_eq!(
        parent
            .get(negative)
            .unwrap()
            .negative_authority_name()
            .unwrap(),
        &Name::from_ascii("old.authority.test").unwrap()
    );
    assert_eq!(
        child
            .get(negative)
            .unwrap()
            .negative_authority_name()
            .unwrap(),
        &Name::from_ascii("new.authority.test").unwrap()
    );
    child.lookup(&name, &[Kind::Ipv4], 100, true);
    assert_eq!(
        parent.names_for(&name.canonical_wire()).unwrap(),
        &before_order
    );
    assert_ne!(
        child.names_for(&name.canonical_wire()).unwrap(),
        &before_order
    );
    assert!(child
        .lookup_reverse("192.0.2.17".parse().unwrap(), 160)
        .is_empty());
    assert_eq!(
        parent
            .lookup_reverse("192.0.2.17".parse().unwrap(), 100)
            .len(),
        1
    );
    child.first_lease_entry();
    assert!(lookup(&mut child, "lease-alias.snapshot.test", Kind::Cname, 100).is_empty());
    assert_eq!(
        parent
            .lookup(
                &Name::from_ascii("lease-alias.snapshot.test").unwrap(),
                &[Kind::Cname],
                100,
                false
            )
            .len(),
        1
    );
    child.clear();
    assert!(child.get(negative).is_none());
    assert!(parent.get(negative).is_some());
    check_ownership(&parent);
    check_ownership(&child);
}

#[test]
fn tcp_snapshot_clear_is_private_at_zero_small_and_large_capacity() {
    for capacity in [0, 1, 150, 4096] {
        let mut parent = Cache::new(capacity, Policy::default());
        parent.start_insert();
        let inserted = parent.insert(record("capacity.snapshot.test", Kind::Ipv4, 7), 100, 60);
        if capacity == 0 {
            assert_eq!(inserted, Err(InsertError::Full));
        } else {
            assert!(inserted.is_ok());
            assert!(parent.commit());
        }
        let mut child = parent.snapshot();
        child.clear();
        assert_eq!(
            lookup(&mut parent, "capacity.snapshot.test", Kind::Ipv4, 100),
            if capacity == 0 { Vec::new() } else { vec![7] }
        );
        assert!(lookup(&mut child, "capacity.snapshot.test", Kind::Ipv4, 100).is_empty());
        check_ownership(&parent);
        check_ownership(&child);
    }
}

#[test]
fn clear_reuses_only_unique_roots_without_allocated_buckets() {
    let mut cache = Cache::new(128, Policy::default());
    let empty_root = Arc::as_ptr(&cache.names[0]);
    cache.clear();
    assert_eq!(Arc::as_ptr(&cache.names[0]), empty_root);
    assert_eq!(cache.names[0].capacity(), 0);

    let retained = cache.snapshot();
    cache.clear();
    for (parent, child) in retained.names.iter().zip(&cache.names) {
        assert!(!Arc::ptr_eq(parent, child), "clear must detach even shared empty roots");
        assert_eq!(Arc::strong_count(child), 1);
        assert_eq!(child.capacity(), 0);
    }

    cache.start_insert();
    let name = Name::from_ascii("allocated.root.test").unwrap();
    cache.insert(record("allocated.root.test", Kind::Ipv4, 1), 100, 60).unwrap();
    assert!(cache.commit());
    let shard = Cache::key_shard(&name.canonical_wire());
    assert!(cache.names[shard].capacity() > 0);
    cache.clear();
    assert_eq!(cache.names[shard].capacity(), 0, "clear still releases allocated buckets");
    assert_eq!(Arc::strong_count(&cache.names[shard]), 1);
}

#[test]
fn compact_slot_links_preserve_zero_absence_and_production_capacity_limit() {
    assert_eq!(slot_index(None), None);
    for index in [0, 1, 149, 4095, 4_999_999, u32::MAX as usize - 1] {
        assert_eq!(slot_index(Some(slot_link(index))), Some(index));
    }
    assert_eq!(std::mem::size_of::<Option<NonZeroU32>>(), 4);
    assert_eq!(std::mem::size_of::<Slot>(), 16);
}

#[test]
fn tcp_snapshot_content_and_name_roots_detach_only_on_mutation() {
    let name = Name::from_ascii("shared-root.test").unwrap();
    let mut parent = Cache::new(128, Policy::default());
    parent.start_insert();
    let old = parent
        .insert(record("shared-root.test", Kind::Ipv4, 1), 100, 60)
        .unwrap();
    assert!(parent.commit());

    let mut child = parent.snapshot();
    let block = old.slot / CONTENT_BLOCK_SLOTS;
    assert!(Arc::ptr_eq(&parent.content[block], &child.content[block]));
    let key = name.canonical_wire();
    let shard = Cache::key_shard(&key);
    assert!(Arc::ptr_eq(&parent.names[shard], &child.names[shard]));

    // A cache hit only updates the owner's LRU; shared content/index roots
    // remain shared and the parent cannot observe that promotion.
    assert_eq!(child.lookup(&name, &[Kind::Ipv4], 100, false).len(), 1);
    assert!(Arc::ptr_eq(&parent.content[block], &child.content[block]));
    assert!(Arc::ptr_eq(&parent.names[shard], &child.names[shard]));

    // Replacing the record detaches just the touched content block and its
    // conflicting name shard while the parent keeps its old roots.
    child.start_insert();
    child
        .insert(record("shared-root.test", Kind::Ipv4, 2), 100, 60)
        .unwrap();
    assert!(!Arc::ptr_eq(&parent.content[block], &child.content[block]));
    assert!(!Arc::ptr_eq(&parent.names[shard], &child.names[shard]));
    assert!(child.commit());
    assert!(!Arc::ptr_eq(&parent.names[shard], &child.names[shard]));
    assert_eq!(
        lookup(&mut parent, "shared-root.test", Kind::Ipv4, 100),
        [1]
    );
    assert_eq!(lookup(&mut child, "shared-root.test", Kind::Ipv4, 100), [2]);
}

#[test]
fn tcp_view_isolates_mutation_shares_payload_and_imports_only_child_transaction() {
    let a = Name::from_ascii("a.snapshot.test").unwrap();
    let b = Name::from_ascii("b.snapshot.test").unwrap();
    let record = |name: Name, address: u8| Record {
        name,
        kind: Kind::Ipv4,
        negative: false,
        data: vec![198, 51, 100, address],
    };
    let mut parent = Cache::new(8, Policy::default());
    parent.start_insert();
    let old = parent.insert(record(a.clone(), 7), 100, 60).unwrap();
    assert!(parent.commit());
    let mut child = parent.snapshot();
    assert!(Arc::ptr_eq(
        &parent.get(old).unwrap().record,
        &child.get(old).unwrap().record
    ));
    parent.start_insert();
    parent.insert(record(a.clone(), 8), 101, 60).unwrap();
    assert!(parent.commit());
    let id = child.lookup(&a, &[Kind::Ipv4], 100, false)[0];
    assert_eq!(child.get(id).unwrap().record.data, [198, 51, 100, 7]);
    child.start_insert();
    child.insert(record(b.clone(), 9), 100, 60).unwrap();
    let transaction = child
        .capture_commit_counted(&mut CacheCounters::default())
        .unwrap();
    assert!(parent.lookup(&b, &[Kind::Ipv4], 101, false).is_empty());
    assert!(parent.import_counted(transaction, 101, &mut CacheCounters::default(), |_| None));
    let parent_a = parent.lookup(&a, &[Kind::Ipv4], 101, false)[0];
    let parent_b = parent.lookup(&b, &[Kind::Ipv4], 101, false)[0];
    assert_eq!(parent.get(parent_a).unwrap().record.data, [198, 51, 100, 8]);
    assert_eq!(parent.get(parent_b).unwrap().record.data, [198, 51, 100, 9]);
    assert_eq!(child.get(id).unwrap().record.data, [198, 51, 100, 7]);
}
use std::collections::HashSet;

#[test]
fn wrapped_minimum_ttl_expires_before_now_instead_of_saturating() {
    let mut cache = Cache::new(
        8,
        Policy {
            min_ttl: u64::MAX,
            ..Policy::default()
        },
    );
    cache.start_insert();
    let id = cache
        .insert(record("wrapped.ttl.test", Kind::Ipv4, 7), 100, 600)
        .unwrap();
    assert_eq!(cache.get(id).unwrap().expires, 99);
    assert!(cache.commit());
    assert!(cache
        .lookup(
            &Name::from_ascii("wrapped.ttl.test").unwrap(),
            &[Kind::Ipv4],
            100,
            false
        )
        .is_empty());
    assert_eq!(
        Extraction::from_source(true, true, false, false),
        Extraction::ExtractOnly
    );
    assert_eq!(
        Extraction::from_source(false, true, false, false),
        Extraction::Unsupported
    );
}

#[test]
fn live_maximum_ttl_follows_cname_scan_and_leaves_other_sections_alone() {
    use super::super::wire::{Message, PacketWriter, Section};
    let alias = Name::from_ascii("alias.clip.test").unwrap();
    let target = Name::from_ascii("target.clip.test").unwrap();
    let other = Name::from_ascii("other.clip.test").unwrap();
    let mut writer = PacketWriter::new(1, 0x8180, 1232).unwrap();
    writer.question(&alias, 1, 1).unwrap();
    writer
        .record_at(Section::Answer, 12, 5, 1, 600, target.as_wire())
        .unwrap();
    writer
        .record_at(Section::Answer, 12, 1, 1, 600, &[198, 51, 100, 1])
        .unwrap();
    writer
        .record(Section::Answer, &target, 1, 1, 400, &[198, 51, 100, 2])
        .unwrap();
    writer
        .record(Section::Answer, &other, 1, 1, 700, &[198, 51, 100, 3])
        .unwrap();
    writer
        .record_at(Section::Answer, 12, 1, 3, 800, &[198, 51, 100, 4])
        .unwrap();
    writer
        .record(Section::Authority, &target, 16, 1, 900, &[1, b'x'])
        .unwrap();
    let mut packet = writer.finish();
    clip_live_reply_ttls(&mut packet, 100, 0).unwrap();
    let message = Message::parse(&packet).unwrap();
    let ttls: Vec<_> = message
        .records(Section::Answer)
        .chain(message.records(Section::Authority))
        .map(|record| record.ttl)
        .collect();
    assert_eq!(ttls, [100, 600, 100, 700, 800, 900]);
}

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

#[test]
fn forward_name_presence_keeps_index_links_and_expired_records_untouched() {
    let mut cache = Cache::new(4, Policy::default());
    cache.start_insert();
    let address = cache
        .insert(record("address.test", Kind::Ipv4, 1), 100, 10)
        .unwrap();
    let mut nodata = record("nodata.test", Kind::Ipv6, 0);
    nodata.negative = true;
    cache.insert(nodata, 100, 60).unwrap();
    let mut nx = record("nx.test", Kind::NxDomain, 0);
    nx.negative = true;
    cache.insert(nx, 100, 60).unwrap();
    assert!(cache.commit());
    let names = cache.names.clone();
    let links = || {
        cache
            .slots
            .iter()
            .map(|slot| (slot.prev, slot.next, slot.generation))
            .collect::<Vec<_>>()
    };
    let before_links = links();
    let ends = (cache.head, cache.tail);
    for (name, now, expected) in [
        ("ADDRESS.TEST", 100, true),
        ("address.test", 110, false),
        ("address.test", 100, true),
        ("nodata.test", 100, true),
        ("nx.test", 100, false),
        ("test", 100, false),
    ] {
        assert_eq!(
            cache.contains_forward_name(&Name::from_ascii(name).unwrap(), now),
            expected
        );
    }
    assert_eq!(cache.names, names);
    assert_eq!(links(), before_links);
    assert_eq!((cache.head, cache.tail), ends);
    assert!(
        cache.get(address).is_some(),
        "presence check must not purge expiry"
    );
}

fn check_ownership(cache: &Cache) {
    assert!(cache.entries().filter(|entry| entry.committed)
        .all(|entry| cache.expiry_lower_bound <= entry.expires));
    let mut linked = HashSet::new();
    let mut previous = None;
    let mut at = cache.head;
    while let Some(index) = at {
        assert!(linked.insert(index), "cycle or duplicated slot");
        let slot = &cache.slots[index];
        assert_eq!(slot_index(slot.prev), previous);
        assert!(cache.entry(index).is_none_or(|entry| entry.committed));
        previous = at;
        at = slot_index(slot.next);
    }
    assert_eq!(previous, cache.tail);
    for &slot in &cache.pending {
        assert!(linked.insert(slot));
        assert!(!cache.entry(slot).unwrap().committed);
    }
    assert_eq!(linked.len(), cache.slots.len());
    let mut indexed = HashSet::new();
    for shard in &cache.names {
        for (name, indices) in shard.iter() {
            assert!(!indices.is_empty());
            for &slot in indices {
                assert!(indexed.insert(slot));
                let entry = cache.entry(slot).unwrap();
                assert!(entry.committed);
                assert_eq!(entry.record.name.canonical_wire().as_slice(), name.as_ref());
            }
        }
    }
    assert_eq!(
        indexed.len(),
        cache
            .slots
            .iter()
            .enumerate()
            .filter(|(index, _)| cache.entry(*index).is_some_and(|entry| entry.committed))
            .count()
    );
}

#[test]
fn expiry_bound_matches_forced_scan_across_pressure_and_clock_changes() {
    fn same_state(left: &Cache, right: &Cache) {
        assert_eq!((left.head, left.tail, &left.pending, left.failed, left.long_names),
                   (right.head, right.tail, &right.pending, right.failed, right.long_names));
        assert_eq!(left.names, right.names);
        assert_eq!(left.reverse_chain, right.reverse_chain);
        assert_eq!(left.name_revision, right.name_revision);
        for slot in 0..left.slots.len() {
            let a = &left.slots[slot];
            let b = &right.slots[slot];
            assert_eq!((a.generation, a.prev, a.next), (b.generation, b.prev, b.next));
            assert_eq!(format!("{:?}", left.entry(slot)), format!("{:?}", right.entry(slot)));
        }
        check_ownership(left);
        check_ownership(right);
    }

    for stale in [StalePolicy::Disabled, StalePolicy::Seconds(5), StalePolicy::Forever] {
        for capacity in [0, 1, 8, 64] {
            let mut candidate = Cache::new(capacity, Policy { stale, ..Policy::default() });
            let mut reference = candidate.snapshot();
            let mut actual = CacheCounters::default();
            let mut expected = CacheCounters::default();
            for round in 0usize..500 {
                let now = match round % 101 {
                    97 => i64::MIN + 10,
                    98 => i64::MAX - 10,
                    99 => -100,
                    _ => 100 + (round / 7) as i64,
                };
                if round % 97 == 0 {
                    candidate.clear_counted(&mut actual);
                    reference.clear_counted(&mut expected);
                }
                candidate.start_insert();
                reference.start_insert();
                for offset in 0..2 {
                    let name = format!("e{}", (round * 7 + offset) % (capacity * 3 + 1));
                    let kind = if round % 17 == 0 { Kind::ReverseIpv4 } else { Kind::Ipv4 };
                    let ttl = [0, 1, 3, 60, u64::MAX][(round + offset) % 5];
                    // i64::MIN is a conservative bound that forces the original
                    // scan whenever any representable expiry could be expired.
                    reference.expiry_lower_bound = i64::MIN;
                    assert_eq!(
                        candidate.insert_ttl_counted(record(&name, kind, round as u8), now, ttl, &mut actual),
                        reference.insert_ttl_counted(record(&name, kind, round as u8), now, ttl, &mut expected),
                    );
                    same_state(&candidate, &reference);
                }
                if round % 11 != 0 {
                    assert_eq!(candidate.commit_counted(&mut actual), reference.commit_counted(&mut expected));
                }
                let name = format!("e{}", round % (capacity * 3 + 1));
                assert_eq!(lookup(&mut candidate, &name, Kind::Ipv4, now),
                           lookup(&mut reference, &name, Kind::Ipv4, now));
                assert_eq!(actual, expected);
                same_state(&candidate, &reference);
            }
        }
    }
}

#[test]
fn expiry_bound_is_private_to_snapshots_and_tracks_imported_deadlines() {
    let mut parent = Cache::new(4, Policy::default());
    parent.start_insert();
    let early = parent.insert(record("early.test", Kind::Ipv4, 1), 100, 5).unwrap();
    parent.insert(record("later.test", Kind::Ipv4, 2), 100, 60).unwrap();
    assert!(parent.commit());
    assert_eq!(parent.expiry_lower_bound, 105);
    let mut child = parent.snapshot();
    child.remove(early.slot);
    assert_eq!(child.expiry_lower_bound, 105, "deleting a minimum may leave a conservative bound");
    child.start_insert();
    child.insert(record("import.test", Kind::Ipv4, 3), 100, 2).unwrap();
    let transaction = child.capture_commit_counted(&mut CacheCounters::default()).unwrap();
    assert_eq!(child.expiry_lower_bound, 102);
    assert_eq!(parent.expiry_lower_bound, 105);
    assert!(parent.import_counted(transaction, 101, &mut CacheCounters::default(), |_| None));
    assert_eq!(parent.expiry_lower_bound, 102);
    child.clear();
    assert_eq!(child.expiry_lower_bound, i64::MAX);
    assert_eq!(parent.expiry_lower_bound, 102);
    assert!(parent.get(early).is_some());
    check_ownership(&parent);
    check_ownership(&child);
}

#[test]
fn counted_pressure_remains_visible_after_failure_and_reload_resets_only_window() {
    let mut cache = Cache::new(1, Policy::default());
    let mut counters = CacheCounters::default();
    cache.start_insert();
    cache
        .insert_counted(record("old.test", Kind::Ipv4, 7), 100, 60, &mut counters)
        .unwrap();
    assert_eq!(counters, CacheCounters::default());
    assert!(cache.commit_counted(&mut counters));
    assert_eq!(
        counters,
        CacheCounters {
            inserted: 1,
            live_freed: 0
        }
    );
    cache.start_insert();
    let long = format!("{}.{}", "a".repeat(60), "b".repeat(16));
    assert_eq!(
        cache.insert_counted(record(&long, Kind::Ipv4, 8), 101, 60, &mut counters),
        Err(InsertError::LongNameLimit)
    );
    assert!(!cache.commit_counted(&mut counters));
    assert_eq!(
        counters,
        CacheCounters {
            inserted: 1,
            live_freed: 1
        }
    );
    assert!(lookup(&mut cache, "old.test", Kind::Ipv4, 101).is_empty());
    cache.clear_counted(&mut counters);
    assert_eq!(counters, CacheCounters::default());
    check_ownership(&cache);
}

#[test]
fn counted_negative_path_obeys_zero_soa_and_u32_commit_width() {
    let mut cache = Cache::new(1, Policy::default());
    let mut counters = CacheCounters {
        inserted: u32::MAX,
        live_freed: 0,
    };
    let negative = || {
        let mut value = record("negative.test", Kind::Ipv4, 0);
        value.negative = true;
        value
    };
    cache.start_insert();
    assert_eq!(
        cache.insert_negative_counted(negative(), 100, Some(0), 60, &mut counters),
        Err(InsertError::ZeroTtl)
    );
    assert!(!cache.commit_counted(&mut counters));
    assert_eq!(counters.inserted, u32::MAX);
    cache.start_insert();
    assert!(cache
        .insert_negative_counted(negative(), 100, None, 60, &mut counters)
        .unwrap()
        .is_some());
    assert!(cache.commit_counted(&mut counters));
    assert_eq!(counters, CacheCounters::default());
    assert_eq!(lookup(&mut cache, "negative.test", Kind::Ipv4, 100), [0]);
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
fn local_insert_failure_aborts_pending_batch_without_restoring_removed_records() {
    let mut cache = Cache::new(4, Policy::default());
    cache.start_insert();
    cache
        .insert(record("changed.test", Kind::Ipv4, 1), 100, 90)
        .unwrap();
    assert!(cache.commit());
    cache.start_insert();
    let pending = cache
        .insert(record("changed.test", Kind::Ipv4, 2), 100, 90)
        .unwrap();
    assert_eq!(
        cache.insert_against_local(90, false),
        Err(InsertError::LocalConflict)
    );
    assert!(!cache.commit());
    assert_eq!(
        cache.insert_against_local(90, true),
        Err(InsertError::PreviousFailure)
    );
    assert!(lookup(&mut cache, "changed.test", Kind::Ipv4, 100).is_empty());
    cache.start_insert();
    assert!(cache.get(pending).is_none());
    assert!(cache.insert_against_local(90, true).is_ok());
    assert!(cache.commit());
    assert!(cache.names.iter().all(|shard| shard.is_empty()));
    check_ownership(&cache);
}

#[test]
fn local_cname_metadata_is_bounded_and_static_targets_ignore_lease_publication() {
    let mut cache = Cache::new(4, Policy::default());
    cache.first_lease_entry();
    cache.start_insert();
    let static_alias = cache
        .insert(record("static-alias.test", Kind::Cname, 0), 100, 90)
        .unwrap();
    let lease_alias = cache
        .insert(record("lease-alias.test", Kind::Cname, 0), 100, 90)
        .unwrap();
    let static_target = cache.local_target(Name::from_ascii("static.test").unwrap(), false);
    let lease_target = cache.local_target(Name::from_ascii("lease.test").unwrap(), true);
    let static_weak = Arc::downgrade(&static_target);
    let lease_weak = Arc::downgrade(&lease_target);
    assert!(cache.set_local_cname_target(static_alias, static_target));
    assert!(cache.set_local_cname_target(lease_alias, lease_target));
    assert!(cache.commit());
    cache.first_lease_entry();
    assert!(cache.is_valid(static_alias, 100));
    assert!(!cache.is_valid(lease_alias, 100));
    assert!(lookup(&mut cache, "lease-alias.test", Kind::Cname, 100).is_empty());
    assert!(lease_weak.upgrade().is_none());
    assert!(static_weak.upgrade().is_some());
    let mut handles = Vec::new();
    for i in 0..100 {
        cache.start_insert();
        let alias = cache
            .insert(record(&format!("alias{i}.test"), Kind::Cname, 0), 100, 90)
            .unwrap();
        let target = cache.local_target(Name::from_ascii("lease.test").unwrap(), true);
        handles.push(Arc::downgrade(&target));
        assert!(cache.set_local_cname_target(alias, target));
        assert!(cache.commit());
        assert!(
            handles
                .iter()
                .filter(|target| target.upgrade().is_some())
                .count()
                <= 4
        );
        check_ownership(&cache);
    }
    cache.clear();
    assert!(handles.iter().all(|target| target.upgrade().is_none()));
    assert!(static_weak.upgrade().is_none());
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

#[test]
fn cname_terminal_preview_does_not_expire_terminal_or_mutate_lookup_order() {
    let alias = Name::from_ascii("alias.interface.test").unwrap();
    let target = Name::from_ascii("target.interface.test").unwrap();
    let mut cache = Cache::new(8, Policy::default());
    cache.start_insert();
    let alias_id = cache
        .insert(
            Record {
                name: alias.clone(),
                kind: Kind::Cname,
                negative: false,
                data: target.as_wire().to_vec(),
            },
            100,
            60,
        )
        .unwrap();
    let target_id = cache
        .insert(
            Record {
                name: target.clone(),
                kind: Kind::Ipv4,
                negative: false,
                data: vec![198, 51, 100, 7],
            },
            100,
            1,
        )
        .unwrap();
    assert!(cache.set_cname_target(alias_id, target_id));
    assert!(cache.commit());
    let before = (cache.head, cache.tail, cache.names.clone());
    assert_eq!(cache.cname_terminal_name(&alias, 102), Some(target.clone()));
    assert_eq!((cache.head, cache.tail, cache.names.clone()), before);
    assert!(cache.get(target_id).is_some());
    assert_eq!(cache.cname_terminal_name(&alias, 160), None);
    cache.start_insert();
    assert_eq!(
        cache.cname_terminal_name(&Name::from_ascii("other.test").unwrap(), 102),
        None
    );
}

#[test]
fn reverse_ip_rrsets_coexist_with_forward_names_and_replace_by_address() {
    let target = Name::from_ascii("target.reverse.test").unwrap();
    let changed = Name::from_ascii("changed.reverse.test").unwrap();
    let address: IpAddr = "192.0.2.17".parse().unwrap();
    let other: IpAddr = "192.0.2.18".parse().unwrap();
    let mut cache = Cache::new(8, Policy::default());
    cache.start_insert();
    cache
        .insert(
            Record {
                name: target.clone(),
                kind: Kind::ReverseIpv4,
                negative: false,
                data: vec![192, 0, 2, 17],
            },
            100,
            60,
        )
        .unwrap();
    cache
        .insert(
            Record {
                name: target.clone(),
                kind: Kind::ReverseIpv4,
                negative: false,
                data: vec![192, 0, 2, 18],
            },
            100,
            60,
        )
        .unwrap();
    assert!(cache.commit());
    assert!(!cache.contains_forward_name(&target, 100));
    assert!(!cache.has_forward_candidate(&target, 1, 100));
    assert!(cache.has_reverse_candidate(address, 100));
    cache.start_insert();
    cache
        .insert(
            Record {
                name: target.clone(),
                kind: Kind::Ipv4,
                negative: false,
                data: vec![198, 51, 100, 7],
            },
            100,
            60,
        )
        .unwrap();
    assert!(cache.commit());
    assert_eq!(cache.lookup_reverse(address, 100).len(), 1);
    assert_eq!(cache.lookup(&target, &[Kind::Ipv4], 100, false).len(), 1);
    cache.start_insert();
    cache
        .insert(
            Record {
                name: changed.clone(),
                kind: Kind::ReverseIpv4,
                negative: false,
                data: vec![192, 0, 2, 17],
            },
            101,
            30,
        )
        .unwrap();
    assert!(cache.commit());
    let id = cache.lookup_reverse(address, 101)[0];
    assert_eq!(cache.get(id).unwrap().record.name, changed);
    let id = cache.lookup_reverse(other, 101)[0];
    assert_eq!(cache.get(id).unwrap().record.name, target);
    assert_eq!(cache.lookup(&target, &[Kind::Ipv4], 101, false).len(), 1);
}

#[test]
fn reverse_snapshot_transfer_preserves_child_and_absolute_expiry() {
    let address: IpAddr = "2001:db8::17".parse().unwrap();
    let target = Name::from_ascii("target.transfer.test").unwrap();
    let mut parent = Cache::new(4, Policy::default());
    let mut child = parent.snapshot();
    child.start_insert();
    child
        .insert(
            Record {
                name: target.clone(),
                kind: Kind::ReverseIpv6,
                negative: false,
                data: address
                    .to_string()
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
            },
            100,
            60,
        )
        .unwrap();
    let transfer = child
        .capture_commit_counted(&mut CacheCounters::default())
        .unwrap();
    assert!(parent.lookup_reverse(address, 103).is_empty());
    assert!(parent.import_counted(transfer, 103, &mut CacheCounters::default(), |_| None));
    let id = parent.lookup_reverse(address, 103)[0];
    assert_eq!(parent.get(id).unwrap().expires, 160);
    assert_eq!(parent.get(id).unwrap().record.name, target);
    assert_eq!(child.lookup_reverse(address, 100).len(), 1);
    assert!(parent.lookup_reverse(address, 160).is_empty());
    assert_eq!(child.lookup_reverse(address, 100).len(), 1);
}

#[test]
fn reverse_import_does_not_consult_forward_local_conflicts() {
    let target = Name::from_ascii("Alias.reverse.test").unwrap();
    for address in ["192.0.2.17", "2001:db8::17"] {
        let address: IpAddr = address.parse().unwrap();
        let (kind, data) = match address {
            IpAddr::V4(address) => (Kind::ReverseIpv4, address.octets().to_vec()),
            IpAddr::V6(address) => (Kind::ReverseIpv6, address.octets().to_vec()),
        };
        let mut child = Cache::new(4, Policy::default());
        child.start_insert();
        child.insert(Record {
            name: target.clone(), kind, negative: false, data,
        }, 100, 60).unwrap();
        let transfer = child.capture_commit_counted(&mut CacheCounters::default()).unwrap();
        let mut parent = Cache::new(4, Policy::default());
        let mut counters = CacheCounters::default();
        let mut calls = 0;
        assert!(parent.import_counted(transfer, 103, &mut counters, |_| {
            calls += 1;
            Some(LocalCacheMatch { same_address: false, from_lease: false })
        }));
        assert_eq!(calls, 0, "C's reverse scan never returns a forward local conflict");
        assert_eq!((counters.inserted, counters.live_freed), (1, 0));
        let ids = parent.lookup_reverse(address, 103);
        assert_eq!(ids.len(), 1);
        let imported = parent.get(ids[0]).unwrap();
        assert_eq!(imported.record.name, target);
        assert_eq!(imported.expires, 160);
        assert_eq!(child.lookup_reverse(address, 100).len(), 1);

        // A forward insertion for the same configured alias must still fail.
        let mut forward = Cache::new(4, Policy::default());
        forward.start_insert();
        forward.insert(Record {
            name: target.clone(), kind: Kind::Ipv4, negative: false,
            data: vec![192, 0, 2, 99],
        }, 100, 60).unwrap();
        let transfer = forward.capture_commit_counted(&mut CacheCounters::default()).unwrap();
        assert!(!parent.import_counted(transfer, 104, &mut counters, |_| {
            calls += 1;
            Some(LocalCacheMatch { same_address: false, from_lease: false })
        }));
        assert_eq!(calls, 1);
        assert_eq!((counters.inserted, counters.live_freed), (1, 0));
        assert_eq!(parent.lookup_reverse(address, 104).len(), 1);
    }
}
