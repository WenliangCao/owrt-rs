// Appended to both generated cache modules; only the index type/adapter vary.
type ScreenIndex = /* INDEX_TYPE */;

fn screen_index_insert(value: &mut ScreenIndex, at: usize, extra: &[usize]) {
    /* INSERT_BEFORE */
}

pub fn screen_index_checks(retained_first: bool) {
    let mut value = ScreenIndex::default();
    assert_eq!(value.as_slice(), &[]);
    value.push(0);
    assert_eq!(value.as_slice(), &[0]);
    let one_hold = value.clone();
    value.push(1);
    value.push(2);
    assert_eq!(value.as_slice(), &[0, 1, 2]);
    assert_eq!(one_hold.as_slice(), &[0]);
    value.retain(|slot| *slot != 1);
    assert_eq!(value.as_slice(), &[0, 2]);
    let many_hold = value.clone();
    screen_index_insert(&mut value, 1, &[3, 4]);
    assert_eq!(value.as_slice(), &[0, 3, 4, 2]);
    assert_eq!(many_hold.as_slice(), &[0, 2]);
    screen_index_insert(&mut value, 0, &[]);
    assert_eq!(value.as_slice(), &[0, 3, 4, 2]);
    value.retain(|slot| *slot >= 3);
    assert_eq!(value.as_slice(), &[3, 4]);
    value.retain(|slot| *slot == 4);
    assert_eq!(value.as_slice(), &[4]);
    value.retain(|_| false);
    assert_eq!(value.as_slice(), &[]);
    let empty_hold = value.clone();
    value.push(7);
    assert_eq!(value.as_slice(), &[7]);
    assert_eq!(empty_hold.as_slice(), &[]);
    screen_index_insert(&mut value, 0, &[8]);
    screen_index_insert(&mut value, 2, &[9]);
    assert_eq!(value.as_slice(), &[8, 7, 9]);
    value = [5, 6, 5, 4].into_iter().collect();
    assert_eq!(value.as_slice(), &[5, 6, 5, 4]);
    let rebuilt_hold = value.clone();
    let mut visits = Vec::new();
    value.retain(|slot| {
        visits.push(*slot);
        *slot % 2 == 0
    });
    assert_eq!(visits, [5, 6, 5, 4]);
    assert_eq!(value.as_slice(), &[6, 4]);
    assert_eq!(rebuilt_hold.as_slice(), &[5, 6, 5, 4]);
    let empty: ScreenIndex = [].into_iter().collect();
    let singleton: ScreenIndex = [0].into_iter().collect();
    assert_eq!(empty.as_slice(), &[]);
    assert_eq!(singleton.as_slice(), &[0]);
    let filtered: ScreenIndex = [Some(8), None, Some(0), Some(8)]
        .into_iter()
        .flatten()
        .collect();
    let filtered_empty: ScreenIndex = [None::<usize>, None].into_iter().flatten().collect();
    assert_eq!(filtered.as_slice(), &[8, 0, 8]);
    assert_eq!(filtered_empty.as_slice(), &[]);
    if retained_first {
        drop((one_hold, many_hold, empty_hold, rebuilt_hold));
        assert_eq!(value.as_slice(), &[6, 4]);
    } else {
        drop(value);
        assert_eq!(one_hold.as_slice(), &[0]);
        assert_eq!(many_hold.as_slice(), &[0, 2]);
        assert_eq!(empty_hold.as_slice(), &[]);
        assert_eq!(rebuilt_hold.as_slice(), &[5, 6, 5, 4]);
    }
}
