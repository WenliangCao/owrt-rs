//! Shared stable sorting for configuration and reload paths.
//!
//! Sorting indices through one erased comparator avoids generating the full
//! standard-library sort for every record type. The temporary index vector
//! costs `len * size_of::<usize>()` bytes (8 bytes per entry on AArch64).
//! Keep allocation-free sorts on frequently executed request/lease paths.

use std::cmp::Ordering;

/// Stable O(n log n) sorting with one O(n) index buffer and O(n) swaps.
pub fn sort_by<T>(values: &mut [T], mut compare: impl FnMut(&T, &T) -> Ordering) {
    if values.len() < 2 {
        return;
    }
    let mut order: Vec<usize> = (0..values.len()).collect();
    sort_indices(&mut order, &mut |a, b| compare(&values[a], &values[b]));

    // Each index gives the original element for that destination. Follow its
    // permutation cycle, then mark visited entries as identity mappings.
    for start in 0..order.len() {
        let mut current = start;
        let mut next = order[current];
        while next != start {
            values.swap(current, next);
            order[current] = current;
            current = next;
            next = order[current];
        }
        order[current] = current;
    }
}

#[inline(never)]
fn sort_indices(order: &mut [usize], compare: &mut dyn FnMut(usize, usize) -> Ordering) {
    // Original positions make equal records stable while the one shared
    // usize sort uses the allocation-free standard-library implementation.
    order.sort_unstable_by(|&a, &b| compare(a, b).then_with(|| a.cmp(&b)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn all_small_permutations_sort_without_losing_elements() {
        fn permutations(values: &mut [usize], start: usize) {
            if start == values.len() {
                let mut actual = values.to_vec();
                sort_by(&mut actual, Ord::cmp);
                assert_eq!(actual, (0..values.len()).collect::<Vec<_>>());
                return;
            }
            for next in start..values.len() {
                values.swap(start, next);
                permutations(values, start + 1);
                values.swap(start, next);
            }
        }
        for len in 0..=8 {
            permutations(&mut (0..len).collect::<Vec<_>>(), 0);
        }
    }

    #[test]
    fn equal_keys_keep_input_order_across_large_permutations() {
        let mut actual: Vec<_> = (0..1024).map(|index| ((index * 37) % 19, index)).collect();
        let mut expected = actual.clone();
        expected.sort_by_key(|value| value.0);
        sort_by(&mut actual, |a, b| a.0.cmp(&b.0));
        assert_eq!(actual, expected);
    }

    #[test]
    fn comparisons_remain_bounded_for_large_input() {
        let mut values: Vec<_> = (0..16384).map(|index| (index * 15991) % 16384).collect();
        let mut comparisons = 0;
        sort_by(&mut values, |a, b| {
            comparisons += 1;
            a.cmp(b)
        });
        assert!(values.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(comparisons < 8 * 16384 * 14, "{comparisons} comparisons");
    }

    #[test]
    fn owned_values_are_dropped_exactly_once() {
        struct Record<'a> {
            name: String,
            id: usize,
            drops: &'a RefCell<Vec<usize>>,
        }
        impl Drop for Record<'_> {
            fn drop(&mut self) {
                self.drops.borrow_mut()[self.id] += 1;
            }
        }
        let drops = RefCell::new(vec![0; 3]);
        {
            let mut values: Vec<_> = ["c", "a", "b"]
                .into_iter()
                .enumerate()
                .map(|(id, name)| Record {
                    name: name.to_owned(),
                    id,
                    drops: &drops,
                })
                .collect();
            sort_by(&mut values, |a, b| a.name.cmp(&b.name));
            assert_eq!(
                values.iter().map(|value| value.id).collect::<Vec<_>>(),
                [1, 2, 0]
            );
            assert_eq!(*drops.borrow(), [0, 0, 0]);
        }
        assert_eq!(*drops.borrow(), [1, 1, 1]);
    }

    #[test]
    fn panicking_comparison_keeps_original_records() {
        let mut values = [String::from("b"), String::from("a")];
        let before = values.clone();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sort_by(&mut values, |_, _| panic!("comparison failed"));
        }))
        .is_err());
        assert_eq!(values, before);
    }
}
