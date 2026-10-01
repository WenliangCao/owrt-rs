// Appended only to the generated private shared_one_index cache module.
#[derive(Clone, Debug)]
enum NameSlots {
    One(usize),
    Many(Vec<usize>),
}

impl Default for NameSlots {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl NameSlots {
    fn as_slice(&self) -> &[usize] {
        match self {
            Self::One(slot) => std::slice::from_ref(slot),
            Self::Many(slots) => slots,
        }
    }

    fn to_vec(&self) -> Vec<usize> {
        self.as_slice().to_vec()
    }

    fn push(&mut self, slot: usize) {
        match self {
            Self::One(first) => {
                let mut slots = Vec::new();
                slots.push(*first);
                slots.push(slot);
                *self = Self::Many(slots);
            }
            Self::Many(slots) if slots.is_empty() => *self = Self::One(slot),
            Self::Many(slots) => slots.push(slot),
        }
    }

    fn retain(&mut self, mut keep: impl FnMut(&usize) -> bool) {
        match self {
            Self::One(slot) => {
                if !keep(slot) {
                    *self = Self::default();
                }
            }
            Self::Many(slots) => slots.retain(keep),
        }
    }

    fn insert_before(&mut self, at: usize, extra: &[usize]) {
        assert!(at <= self.len());
        if extra.is_empty() {
            return;
        }
        if let Self::One(slot) = self {
            let mut slots = Vec::new();
            slots.push(*slot);
            *self = Self::Many(slots);
        }
        if let Self::Many(slots) = self {
            slots.splice(at..at, extra.iter().copied());
        }
    }
}

impl std::ops::Deref for NameSlots {
    type Target = [usize];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl FromIterator<usize> for NameSlots {
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        let mut slots = Self::default();
        for slot in iter {
            slots.push(slot);
        }
        slots
    }
}
