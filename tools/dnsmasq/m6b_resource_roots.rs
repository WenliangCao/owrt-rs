// Appended to cache.rs in the ignored companion only. No Weak or extra strong
// references: either would change Arc::make_mut behavior and pin allocations.
#[derive(Default)]
struct M6bRoot {
    version: u64, ever_parent: bool, parent: bool, view: bool,
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
