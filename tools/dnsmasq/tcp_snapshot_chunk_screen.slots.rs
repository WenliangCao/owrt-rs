// Private source fragment appended only to the chunk32 experiment.
// The final slice is short: unused slots must not inflate parent heap.
const SCREEN_CHUNK: usize = 32;

#[derive(Debug, Clone)]
struct ScreenSlots {
    chunks: Vec<Arc<[Slot]>>,
    len: usize,
}

impl FromIterator<Slot> for ScreenSlots {
    fn from_iter<T: IntoIterator<Item = Slot>>(slots: T) -> Self {
        let mut slots = slots.into_iter();
        let mut chunks = Vec::with_capacity(slots.size_hint().0.div_ceil(SCREEN_CHUNK));
        let mut len = 0;
        while let Some(first) = slots.next() {
            let mut chunk = Vec::with_capacity(SCREEN_CHUNK);
            chunk.push(first);
            chunk.extend(slots.by_ref().take(SCREEN_CHUNK - 1));
            len += chunk.len();
            chunks.push(Arc::<[Slot]>::from(chunk));
        }
        Self { chunks, len }
    }
}

impl ScreenSlots {
    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, index: usize) -> Option<&Slot> {
        if index >= self.len {
            return None;
        }
        Some(&self.chunks[index / SCREEN_CHUNK][index % SCREEN_CHUNK])
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut Slot> {
        if index >= self.len {
            return None;
        }
        Some(&mut Arc::make_mut(&mut self.chunks[index / SCREEN_CHUNK])[index % SCREEN_CHUNK])
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut Slot> {
        self.chunks
            .iter_mut()
            .flat_map(|chunk| Arc::make_mut(chunk).iter_mut())
    }
}

impl std::ops::Index<usize> for ScreenSlots {
    type Output = Slot;

    fn index(&self, index: usize) -> &Slot {
        self.get(index).expect("slot index outside cache capacity")
    }
}

impl std::ops::IndexMut<usize> for ScreenSlots {
    fn index_mut(&mut self, index: usize) -> &mut Slot {
        self.get_mut(index)
            .expect("slot index outside cache capacity")
    }
}
