// Appended to cache.rs in the ignored companion only. No Weak or extra strong
// references: either would change Arc::make_mut behavior and pin allocations.
#[derive(Default)]
struct M6bRoot {
    version: u64, ever_parent: bool, parent: bool, view: bool,
}

#[cfg(test)]
mod m6b_root_controls {
    use super::*;

    fn reset() {
        let _scope = crate::m6b_resource_diag::ObserverScope::enter();
        M6B_ROOTS.with(|registry| *registry.borrow_mut() = M6bRoots::default());
    }

    fn summary(parent: &Cache, views: &[&Cache]) -> M6bRootSummary {
        Cache::m6b_begin_root_sample();
        parent.m6b_observe_roots(true);
        for view in views { view.m6b_observe_roots(false); }
        Cache::m6b_finish_root_sample()
    }

    #[test]
    fn snapshots_and_detach_track_actual_owners_without_extra_arcs() {
        reset();
        let mut parent = Cache::new(150, Policy::default());
        parent.m6b_mark_parent_roots();
        let mut child = parent.snapshot();
        let first = Arc::as_ptr(&parent.content[0]);
        assert_eq!(Arc::strong_count(&parent.content[0]), 2);
        assert_eq!(Arc::weak_count(&parent.content[0]), 0);
        let initial = summary(&parent, &[&child]);
        assert_eq!((initial.content, initial.index, initial.registry_len), (3, 64, 67));
        assert_eq!(initial.missing_creation_hooks, 0);
        assert_eq!(Arc::as_ptr(&parent.content[0]), first);
        assert_eq!(Arc::strong_count(&parent.content[0]), 2, "observer may not pin a root");
        m6b_root_mut(0, &mut parent.content[0]).entries[0] = None;
        m6b_root_mut(1, &mut parent.names[0]).reserve(1);
        let detached = summary(&parent, &[&child]);
        assert_eq!((detached.old_content, detached.old_index), (1, 1));
        assert_eq!((detached.content, detached.index), (4, 65));
        m6b_root_mut(0, &mut child.content[1]).entries[0] = None;
        m6b_root_mut(1, &mut child.names[1]).reserve(1);
        let private = summary(&parent, &[&child]);
        assert_eq!((private.private_content, private.private_index), (1, 1));
        assert_eq!(private.missing_creation_hooks, 0);
        drop(child);
        let released = summary(&parent, &[]);
        assert_eq!((released.content, released.index, released.registry_len), (3, 64, 67));
        assert_eq!((released.old_content, released.old_index, released.private_content, released.private_index), (0, 0, 0, 0));
        registry_effective_capacity_is_not_allocated_bytes();
        println!("M6B_RESOURCE_LAYOUT slot={} entry={} record={} content={} cache={} indices={} index={}",
            std::mem::size_of::<Slot>(), std::mem::size_of::<Entry>(), std::mem::size_of::<Record>(),
            std::mem::size_of::<ContentBlock>(), std::mem::size_of::<Cache>(),
            std::mem::size_of::<SlotIndices>(), std::mem::size_of::<NameIndex>());
    }

    // A deterministic collision cluster leaves DELETED buckets when removing
    // an interior key. Insert elsewhere to restore the same cardinality.
    // The insertion lower bound changes without changing the
    // backing allocation; the six copied method entry points remain unchanged.
    fn registry_effective_capacity_is_not_allocated_bytes() {
        #[derive(Default)]
        struct CollisionHasher(u64);
        impl std::hash::Hasher for CollisionHasher {
            fn finish(&self) -> u64 { self.0 }
            fn write(&mut self, _: &[u8]) {}
            fn write_usize(&mut self, key: usize) { self.0 = if key == 128 { 128 } else { 0 }; }
        }
        type Map = HashMap<usize, usize, std::hash::BuildHasherDefault<CollisionHasher>>;
        let before = crate::m6b_resource_diag::allocation();
        let mut values;
        {
            let _scope = crate::m6b_resource_diag::ObserverScope::enter();
            values = Map::with_capacity_and_hasher(128, Default::default());
            for key in 0..128 { values.insert(key, key); }
        }
        let populated = crate::m6b_resource_diag::allocation();
        let effective_before = values.capacity();
        {
            let _scope = crate::m6b_resource_diag::ObserverScope::enter();
            assert_eq!(values.remove(&64), Some(64));
            // Insert into a distinct EMPTY group rather than reuse DELETED.
            values.insert(128, 128);
            values.shrink_to(values.len());
        }
        let removed = crate::m6b_resource_diag::allocation();
        assert_eq!(values.len(), 128);
        assert!(values.capacity() < effective_before,
            "a real tombstone must change the effective insertion lower bound");
        assert_eq!(removed.live, populated.live);
        assert_eq!(removed.observer_live, populated.observer_live);
        assert_eq!(removed.objects, populated.objects);
        assert_eq!(removed.alloc, populated.alloc);
        assert_eq!(removed.realloc, populated.realloc);
        assert_eq!(removed.free, populated.free);
        {
            let _scope = crate::m6b_resource_diag::ObserverScope::enter();
            drop(values);
        }
        let after = crate::m6b_resource_diag::allocation();
        assert_eq!(after.live, before.live);
        assert_eq!(after.observer_live, before.observer_live);
        assert_eq!(after.objects, before.objects);
        assert_eq!(after.balance_errors, before.balance_errors);
    }

    #[test]
    fn missing_constructor_and_detach_are_detected() {
        reset();
        let mut parent = Cache::new(150, Policy::default());
        parent.m6b_mark_parent_roots();
        let child = parent.snapshot();
        // Deliberately bypass the diagnostic detach hook. The product Arc
        // operation remains real, so an observed unregistered allocation is a
        // genuine negative control rather than a pre-filled report boolean.
        Arc::make_mut(&mut parent.content[0]).entries[0] = None;
        let missing_detach = summary(&parent, &[&child]);
        assert!(missing_detach.missing_creation_hooks > 0);
        // Deliberately bypass the constructor hook as well.
        parent.names[0] = Arc::new(NameIndex::new());
        let missing_new = summary(&parent, &[&child]);
        assert!(missing_new.missing_creation_hooks > missing_detach.missing_creation_hooks);
    }

    #[test]
    fn creation_stamp_replaces_old_parent_history_at_same_address() {
        reset();
        let parent = Cache::new(1, Policy::default());
        parent.m6b_mark_parent_roots();
        let address = Arc::as_ptr(&parent.names[0]) as usize;
        let old = M6B_ROOTS.with(|registry| registry.borrow().roots[&(1, address)].version);
        // Exercise the constructor's reuse rule on a real root address. This
        // checks stamping, not a promise about System's address reuse policy.
        m6b_fresh_root(1, address);
        M6B_ROOTS.with(|registry| {
            let registry = registry.borrow();
            let replacement = &registry.roots[&(1, address)];
            assert!(replacement.version > old);
            assert!(!replacement.ever_parent);
        });
    }
}
#[derive(Default)]
struct M6bRoots {
    next_version: u64, roots: HashMap<(u8, usize), M6bRoot>, missing: u64,
}
impl Drop for M6bRoots {
    fn drop(&mut self) {
        let _scope = crate::m6b_resource_diag::ObserverScope::enter();
        self.roots.clear();
        self.roots.shrink_to_fit();
    }
}
thread_local! { static M6B_ROOTS: std::cell::RefCell<M6bRoots> = Default::default(); }

fn m6b_fresh_root(kind: u8, address: usize) {
    let _scope = crate::m6b_resource_diag::ObserverScope::enter();
    M6B_ROOTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.next_version += 1;
        let version = registry.next_version;
        // A root constructor reusing a freed address overwrites its old stamp.
        // COW creates a new address while the shared old allocation is live.
        registry.roots.insert((kind, address), M6bRoot { version, ..Default::default() });
    });
}
fn m6b_root_new<T>(kind: u8, value: T) -> Arc<T> {
    let root = Arc::new(value);
    m6b_fresh_root(kind, Arc::as_ptr(&root) as usize);
    root
}
fn m6b_root_mut<T: Clone>(kind: u8, root: &mut Arc<T>) -> &mut T {
    let before = Arc::as_ptr(root) as usize;
    let value = Arc::make_mut(root);
    let after = value as *mut T as usize;
    if before != after { m6b_fresh_root(kind, after); }
    value
}

#[derive(Default, Clone, Copy)]
pub struct M6bRootSummary {
    pub content: usize, pub index: usize, pub old_content: usize, pub old_index: usize,
    pub private_content: usize, pub private_index: usize, pub registry_len: usize,
    // HashMap::capacity is an insertion lower bound, reduced by tombstones.
    // Allocated registry bytes come only from the scoped allocator counter.
    pub registry_capacity: usize, pub missing_creation_hooks: u64,
}

impl Cache {
    pub fn m6b_mark_parent_roots(&self) {
        self.m6b_observe_roots(true);
    }
    pub fn m6b_begin_root_sample() {
        let _scope = crate::m6b_resource_diag::ObserverScope::enter();
        M6B_ROOTS.with(|registry| {
            for root in registry.borrow_mut().roots.values_mut() { root.parent = false; root.view = false; }
        });
    }
    pub fn m6b_observe_roots(&self, parent: bool) {
        let _scope = crate::m6b_resource_diag::ObserverScope::enter();
        M6B_ROOTS.with(|registry| {
            let mut registry = registry.borrow_mut();
            let addresses = self.content.iter().map(|root| (0, Arc::as_ptr(root) as usize))
                .chain(self.names.iter().map(|root| (1, Arc::as_ptr(root) as usize)));
            for key in addresses {
                if !registry.roots.contains_key(&key) {
                    registry.missing += 1; registry.next_version += 1;
                    let version = registry.next_version;
                    registry.roots.insert(key, M6bRoot { version, ..Default::default() });
                }
                if let Some(root) = registry.roots.get_mut(&key) {
                    root.ever_parent |= parent; root.parent |= parent; root.view |= !parent;
                }
            }
        });
    }
    pub fn m6b_finish_root_sample() -> M6bRootSummary {
        let _scope = crate::m6b_resource_diag::ObserverScope::enter();
        M6B_ROOTS.with(|registry| {
            let mut registry = registry.borrow_mut();
            registry.roots.retain(|_, root| root.parent || root.view);
            let live = registry.roots.len();
            registry.roots.shrink_to(live);
            let mut result = M6bRootSummary { registry_len: live,
                registry_capacity: registry.roots.capacity(), missing_creation_hooks: registry.missing,
                ..Default::default() };
            for (&(kind, _), root) in &registry.roots {
                let _version_identity = root.version;
                if kind == 0 { result.content += 1; } else { result.index += 1; }
                if root.view && !root.parent {
                    if root.ever_parent {
                        if kind == 0 { result.old_content += 1; } else { result.old_index += 1; }
                    } else if kind == 0 { result.private_content += 1; } else { result.private_index += 1; }
                }
            }
            result
        })
    }
    pub fn m6b_owner_capacities(&self) -> (usize, usize, usize, usize) {
        (self.slots.capacity() * std::mem::size_of::<Slot>(),
         self.pending.len(), self.pending.capacity() * std::mem::size_of::<usize>(),
         self.reverse_chain.capacity() * std::mem::size_of::<usize>())
    }
}
