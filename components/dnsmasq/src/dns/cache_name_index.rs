//! Private ordered slot lists for one canonical name. Shard copies share
//! multi-record lists; a singleton has no separate allocation.

use std::ops::Deref;
use std::sync::Arc;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) enum SlotIndices {
    #[default]
    Empty,
    One(usize),
    // A thin shared owner keeps the original vector's amortized growth and
    // in-place removal when unique. Shard copies clone only this Arc.
    Many(Arc<Vec<usize>>),
}

impl Deref for SlotIndices {
    type Target = [usize];

    fn deref(&self) -> &[usize] {
        match self {
            Self::Empty => &[],
            Self::One(slot) => std::slice::from_ref(slot),
            Self::Many(slots) => slots,
        }
    }
}

impl<'a> IntoIterator for &'a SlotIndices {
    type Item = &'a usize;
    type IntoIter = std::slice::Iter<'a, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<usize> for SlotIndices {
    fn from_iter<T: IntoIterator<Item = usize>>(values: T) -> Self {
        let mut values = values.into_iter();
        let Some(first) = values.next() else { return Self::Empty };
        let Some(second) = values.next() else { return Self::One(first) };
        let mut many = vec![first, second];
        many.extend(values);
        Self::Many(Arc::new(many))
    }
}

impl SlotIndices {
    pub(super) fn push(&mut self, slot: usize) {
        match self {
            Self::Empty => *self = Self::One(slot),
            Self::One(first) => *self = Self::Many(Arc::new(vec![*first, slot])),
            Self::Many(slots) => {
                Arc::make_mut(slots).push(slot);
            }
        }
    }

    pub(super) fn remove(&mut self, slot: usize) {
        let Some(position) = self.iter().position(|old| *old == slot) else { return };
        match self {
            Self::Empty => (),
            Self::One(_) => *self = Self::Empty,
            Self::Many(slots) if slots.len() == 2 => *self = Self::One(slots[1 - position]),
            Self::Many(slots) => {
                Arc::make_mut(slots).remove(position);
            }
        }
    }

    /// cache_find_by_name moves the later matching records before its first
    /// match. They arrive in this list's order; unrelated kinds keep theirs.
    /// Unique lists rotate in place, while a shared list detaches once.
    pub(super) fn rotate_matches(&mut self, matches: &[usize]) {
        if matches.len() < 2 {
            return;
        }
        let Self::Many(slots) = self else { unreachable!("several matches require several indices") };
        let slots = Arc::make_mut(slots);
        for slot in &matches[1..] {
            let first = slots.iter().position(|old| *old == matches[0]).unwrap();
            let next = slots.iter().position(|old| old == slot).unwrap();
            debug_assert!(next > first, "matches retain the existing list order");
            slots[first..=next].rotate_right(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_and_absent_removal_do_not_allocate_a_singleton_or_detach_many() {
        assert!(matches!([].into_iter().collect::<SlotIndices>(), SlotIndices::Empty));
        assert!(matches!([3].into_iter().collect::<SlotIndices>(), SlotIndices::One(3)));
        let parent: SlotIndices = [3, 5].into_iter().collect();
        let mut child = parent.clone();
        child.remove(8);
        let (SlotIndices::Many(left), SlotIndices::Many(right)) = (&parent, &child) else { panic!() };
        assert!(Arc::ptr_eq(left, right), "an absent removal must not detach");
        child.remove(5);
        assert!(matches!(child, SlotIndices::One(3)));
        let mut child = parent.clone();
        child.remove(3);
        assert!(matches!(child, SlotIndices::One(5)));
    }

    #[test]
    fn ordered_zero_one_many_transitions_leave_inherited_list_unchanged() {
        let mut parent = SlotIndices::default();
        parent.push(7);
        assert!(matches!(parent, SlotIndices::One(7)));
        parent.push(2);
        parent.push(9);
        let mut child = parent.clone();
        let (SlotIndices::Many(left), SlotIndices::Many(right)) = (&parent, &child) else { panic!() };
        assert!(Arc::ptr_eq(left, right), "cloning a shard must not clone this list");
        child.remove(2);
        assert_eq!(&*parent, &[7, 2, 9]);
        assert_eq!(&*child, &[7, 9]);
        child.remove(7);
        assert!(matches!(child, SlotIndices::One(9)));
        child.remove(9);
        assert!(matches!(child, SlotIndices::Empty));
    }

    #[test]
    fn mixed_kind_rotation_detaches_once_and_then_preserves_the_unique_buffer() {
        let parent: SlotIndices = [0, 1, 2, 3, 4, 5].into_iter().collect();
        let mut child = parent.clone();
        child.rotate_matches(&[1, 3, 5]);
        assert_eq!(&*parent, &[0, 1, 2, 3, 4, 5]);
        assert_eq!(&*child, &[0, 3, 5, 1, 2, 4]);
        let SlotIndices::Many(values) = &child else { panic!() };
        let unique = values.as_ptr();
        child.rotate_matches(&[3, 5, 1]);
        let SlotIndices::Many(values) = &child else { panic!() };
        assert_eq!(values.as_ptr(), unique, "ordinary unique rotation must not allocate another list");
        assert_eq!(&*child, &[0, 5, 1, 3, 2, 4]);
    }
}
