// Generated private byte-storage and copy-on-write invariant gate.
/* CACHE_MODULES */
/* ALLOCATION_AND_CLOCK */
/* IMAGE_API */

use cache::{Cache, Kind, Policy, Record};

fn main() {
    let lengths = [0, 1, 4, 15, 16, 17, 257];
    drop(Cache::new(0, Policy::default()));
    for length in lengths {
        let bytes: Vec<u8> = (0..length).map(|index| (index * 37) as u8).collect();
        for retain_first in [false, true] {
            let before = allocation::snapshot()[3];
            {
                let mut cache = Cache::new(4, Policy::default());
                cache.start_insert();
                let id = cache
                    .insert(
                        Record {
                            name: wire::Name::from_ascii("payload.test").unwrap(),
                            kind: Kind::Generic(16),
                            negative: true,
                            data: screen_data(&bytes),
                        },
                        100,
                        60,
                    )
                    .unwrap();
                assert!(cache.commit());
                let retained = cache.clone();
                // This mutates the actual entry through Arc::make_mut in the
                // candidate, exercising deep payload cloning for the heap arm.
                assert!(cache
                    .set_negative_authority(id, wire::Name::from_ascii("authority.test").unwrap()));
                assert!(retained
                    .get(id)
                    .unwrap()
                    .negative_authority_name()
                    .is_none());
                assert!(cache.get(id).unwrap().negative_authority_name().is_some());
                assert_eq!(cache.get(id).unwrap().record.data.as_slice(), bytes);
                assert_eq!(retained.get(id).unwrap().record.data.as_slice(), bytes);
                cache.start_insert();
                cache
                    .insert(
                        Record {
                            name: wire::Name::from_ascii("payload.test").unwrap(),
                            kind: Kind::Generic(16),
                            negative: false,
                            data: screen_data(&[0xfe]),
                        },
                        101,
                        60,
                    )
                    .unwrap();
                assert!(cache.commit());
                assert_eq!(retained.get(id).unwrap().record.data.as_slice(), bytes);
                if retain_first {
                    drop(retained);
                    let ids = cache.lookup(
                        &wire::Name::from_ascii("payload.test").unwrap(),
                        &[Kind::Generic(16)],
                        102,
                        false,
                    );
                    assert_eq!(ids.len(), 1);
                    assert_eq!(cache.get(ids[0]).unwrap().record.data.as_slice(), &[0xfe]);
                } else {
                    drop(cache);
                    assert_eq!(retained.get(id).unwrap().record.data.as_slice(), bytes);
                }
            }
            assert_eq!(
                allocation::snapshot()[3],
                before,
                "payload/cache drops leaked"
            );
        }
    }
    println!("{{\"lengths\":{lengths:?},\"drop_orders\":2,\"retained_detachment\":true,\"balanced\":true}}");
}
