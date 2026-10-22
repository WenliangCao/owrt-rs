//! Objects, object types and subscriptions.
//!
//! The C daemon links these with pointers; here everything is addressed by id
//! so the graph stays acyclic and checkable. List order matters and is
//! preserved: libubox `list_add` inserts at the head, so `subscribers`,
//! `targets` and a client's object list all iterate in reverse insertion
//! order, and the path index is a byte-ordered map (avl_strcmp).

use std::collections::BTreeMap;
use std::collections::{HashMap, hash_map::Entry};
use std::rc::Rc;

/// Ids below this are reserved for the built-in system objects.
pub const SYSTEM_OBJECT_MAX: u32 = 1024;
pub const SYSTEM_OBJECT_EVENT: u32 = 1;
pub const SYSTEM_OBJECT_ACL: u32 = 2;
pub const SYSTEM_OBJECT_MONITOR: u32 = 3;

/// One validated method: the canonical blobmsg attribute C emits on lookup.
/// The ACL name is read from that same blob so registration does not retain a
/// second allocation for identical bytes.
pub struct Method {
    blob: Vec<u8>,
}

/// A method attribute's declared name is missing, truncated or unterminated.
#[derive(Debug)]
pub struct InvalidMethodName;

impl std::fmt::Display for InvalidMethodName {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("method attribute lacks a complete NUL-terminated name")
    }
}

impl std::error::Error for InvalidMethodName {}

impl TryFrom<Vec<u8>> for Method {
    type Error = InvalidMethodName;

    /// Validate the name extent before retaining canonical signature bytes.
    ///
    /// # Errors
    /// Returns [`InvalidMethodName`] for missing length bytes or a missing name terminator.
    fn try_from(blob: Vec<u8>) -> Result<Self, Self::Error> {
        let header = blob.get(4..6).ok_or(InvalidMethodName)?;
        let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
        if blob.get(6 + length) != Some(&0) {
            return Err(InvalidMethodName);
        }
        Ok(Self { blob })
    }
}

impl Method {
    /// `blob` must be a validated, canonical method attribute.
    ///
    /// # Panics
    /// Panics if the attribute does not contain its complete, terminated name.
    pub fn new(blob: Vec<u8>) -> Self {
        Self::try_from(blob).expect("canonical method name must fit and end in NUL")
    }

    /// Borrow the canonical signature without allowing its name bounds to change.
    pub fn as_bytes(&self) -> &[u8] {
        &self.blob
    }

    pub fn name(&self) -> &[u8] {
        let len = u16::from_be_bytes([self.blob[4], self.blob[5]]) as usize;
        &self.blob[6..6 + len]
    }
}

pub struct ObjType {
    pub refcount: u32,
    pub methods: Vec<Method>,
}

pub struct Object {
    pub type_id: Option<u32>,
    /// Registered path, without the trailing NUL. `None` for anonymous objects.
    pub path: Option<Rc<[u8]>>,
    /// Owning client id; `None` for the three built-in system objects.
    pub client: Option<u32>,
    /// Objects subscribed to this one, newest first.
    pub subscribers: Vec<u32>,
    /// Objects this one subscribes to, newest first.
    pub targets: Vec<u32>,
    pub invoke_seq: u16,
    pub event_seen: u32,
}

impl Object {
    fn new(type_id: Option<u32>) -> Self {
        Object {
            type_id,
            path: None,
            client: None,
            subscribers: Vec::new(),
            targets: Vec::new(),
            invoke_seq: 0,
            event_seen: 0,
        }
    }
}

#[derive(Default)]
pub struct Registry {
    pub objects: HashMap<u32, Object>,
    pub types: HashMap<u32, ObjType>,
    /// path -> object id, ordered by strcmp so lookup can walk prefixes.
    pub paths: BTreeMap<Rc<[u8]>, u32>,
}

impl Registry {
    /// Allocate an id that is free in `taken`, at least SYSTEM_OBJECT_MAX.
    pub fn alloc_id<F>(exists: F) -> std::io::Result<u32>
    where
        F: Fn(u32) -> bool,
    {
        loop {
            let id = crate::sys::random_id(SYSTEM_OBJECT_MAX)?;
            if !exists(id) {
                return Ok(id);
            }
        }
    }

    pub fn new_type(&mut self, methods: Vec<Method>) -> std::io::Result<u32> {
        loop {
            let id = crate::sys::random_id(SYSTEM_OBJECT_MAX)?;
            if let Entry::Vacant(slot) = self.types.entry(id) {
                slot.insert(ObjType { refcount: 1, methods });
                return Ok(id);
            }
        }
    }

    /// Take a reference to an existing type, as `ubus_get_obj_type` does.
    pub fn ref_type(&mut self, id: u32) -> Option<u32> {
        let t = self.types.get_mut(&id)?;
        t.refcount += 1;
        Some(id)
    }

    pub fn unref_type(&mut self, id: u32) {
        if let Entry::Occupied(mut slot) = self.types.entry(id) {
            let t = slot.get_mut();
            t.refcount -= 1;
            if t.refcount == 0 {
                slot.remove();
            }
        }
    }

    /// Create an object with a fresh random id (or the given fixed id, for the
    /// three system objects). Takes a reference on `type_id` when present.
    pub fn create(&mut self, type_id: Option<u32>, fixed_id: Option<u32>) -> std::io::Result<u32> {
        loop {
            let id = match fixed_id {
                Some(id) => id,
                None => crate::sys::random_id(SYSTEM_OBJECT_MAX)?,
            };
            match self.objects.entry(id) {
                Entry::Occupied(_) if fixed_id.is_some() => {
                    return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "object id in use"));
                }
                Entry::Occupied(_) => continue,
                Entry::Vacant(slot) => {
                    if let Some(t) = type_id.and_then(|t| self.types.get_mut(&t)) {
                        t.refcount += 1;
                    }
                    slot.insert(Object::new(type_id));
                    return Ok(id);
                }
            }
        }
    }

    pub fn get(&self, id: u32) -> Option<&Object> {
        self.objects.get(&id)
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Object> {
        self.objects.get_mut(&id)
    }

    pub fn by_path(&self, path: &[u8]) -> Option<u32> {
        self.paths.get(path).copied()
    }

    /// Bind an unclaimed path to an existing, unnamed object.
    /// Returns false without mutation if the object is missing or either side is bound.
    pub fn set_path(&mut self, id: u32, path: &[u8]) -> bool {
        let Some(obj) = self.objects.get_mut(&id) else {
            return false;
        };
        if obj.path.is_some() || self.paths.contains_key(path) {
            return false;
        }
        // Both indexes own the same immutable bytes. The single-threaded
        // registry needs neither atomics nor a second path allocation.
        let path: Rc<[u8]> = path.into();
        self.paths.insert(path.clone(), id);
        obj.path = Some(path);
        true
    }

    /// Object ids in path order -- the order `lookup` without a pattern walks.
    #[cfg(test)]
    pub fn path_order(&self) -> Vec<u32> {
        self.paths.values().copied().collect()
    }

    /// Path-ordered ids whose path starts with `prefix`.
    #[cfg(test)]
    pub fn path_prefix(&self, prefix: &[u8]) -> Vec<u32> {
        self.paths
            .range::<[u8], _>((std::ops::Bound::Included(prefix), std::ops::Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(_, v)| *v)
            .collect()
    }

    /// Record a subscription. Returns true when this is the first subscriber,
    /// which is when the target's owner has to be told the object went active.
    pub fn subscribe(&mut self, subscriber: u32, target: u32) -> bool {
        let first = self.objects.get(&target).is_some_and(|o| o.subscribers.is_empty());
        if let Some(t) = self.objects.get_mut(&target) {
            t.subscribers.insert(0, subscriber);
        }
        if let Some(s) = self.objects.get_mut(&subscriber) {
            s.targets.insert(0, target);
        }
        first
    }

    /// Drop one subscription. Returns true when the target lost its last
    /// subscriber and its owner has to be told it went inactive.
    pub fn unsubscribe(&mut self, subscriber: u32, target: u32) -> bool {
        if let Some(s) = self.objects.get_mut(&subscriber) {
            if let Some(i) = s.targets.iter().position(|&t| t == target) {
                s.targets.remove(i);
            }
        }
        let mut emptied = false;
        if let Some(t) = self.objects.get_mut(&target) {
            if let Some(i) = t.subscribers.iter().position(|&s| s == subscriber) {
                t.subscribers.remove(i);
            }
            emptied = t.subscribers.is_empty();
        }
        emptied
    }

    /// Remove the object from every index. Callers must already have sent the
    /// unsubscribe notifications and the object-remove event.
    pub fn destroy(&mut self, id: u32) -> Option<Object> {
        let obj = self.objects.remove(&id)?;
        if let Some(p) = &obj.path {
            self.paths.remove(p);
        }
        if let Some(t) = obj.type_id {
            self.unref_type(t);
        }
        Some(obj)
    }
}

/// C strings on the wire stop at the first NUL; blob strings also carry a
/// trailing NUL. Both are dropped here so keys compare like strcmp.
pub fn cstr_bytes(raw: &[u8]) -> &[u8] {
    match raw.iter().position(|&b| b == 0) {
        Some(i) => &raw[..i],
        None => raw,
    }
}

/// `ubus_strmatch_len`: the number of leading bytes two C strings share, and
/// whether they are equal. Both slices are NUL-free.
pub fn strmatch_len(a: &[u8], b: &[u8]) -> (bool, usize) {
    let mut i = 0;
    while i < a.len() && i < b.len() && a[i] == b[i] {
        i += 1;
    }
    let full = i == a.len() && i == b.len();
    (full, i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_name_preserves_binary_bytes_inside_its_validated_extent() {
        let bytes = [0x82, 0, 0, 12, 0, 3, b'p', 0xff, b'g', 0, 0, 0];
        let method = Method::new(bytes.to_vec());
        assert_eq!(method.name(), &[b'p', 0xff, b'g']);
        assert_eq!(method.as_bytes(), bytes);
    }

    #[test]
    fn method_constructor_rejects_a_name_beyond_its_storage() {
        for bytes in [
            vec![],
            vec![0x82, 0, 0, 8, 0, 4, b'x', 0],
            vec![0x82, 0, 0, 8, 0, 1, b'x', b'y'],
        ] {
            assert!(Method::try_from(bytes).is_err());
        }
    }

    #[test]
    fn strmatch_matches_c_semantics() {
        assert_eq!(strmatch_len(b"network", b"network"), (true, 7));
        assert_eq!(strmatch_len(b"network.interface", b"network"), (false, 7));
        assert_eq!(strmatch_len(b"net", b"network"), (false, 3));
        assert_eq!(strmatch_len(b"", b""), (true, 0));
        assert_eq!(strmatch_len(b"a", b"b"), (false, 0));
    }

    #[test]
    fn cstr_stops_at_nul() {
        assert_eq!(cstr_bytes(b"path\0"), b"path");
        assert_eq!(cstr_bytes(b"a\0b\0"), b"a");
        assert_eq!(cstr_bytes(b"none"), b"none");
    }

    #[test]
    fn path_prefix_walks_in_strcmp_order() {
        let mut r = Registry::default();
        for (i, p) in [&b"network"[..], b"network.device", b"network.interface", b"system"]
            .iter()
            .enumerate()
        {
            let id = 2000 + i as u32;
            r.objects.insert(id, Object::new(None));
            assert!(r.set_path(id, p));
        }
        assert_eq!(r.path_prefix(b"network").len(), 3);
        assert_eq!(r.path_prefix(b"network.").len(), 2);
        assert_eq!(r.path_prefix(b"sys").len(), 1);
        assert_eq!(r.path_order().len(), 4);
        // duplicate path is refused, which makes add_object fail in the C daemon
        r.objects.insert(3000, Object::new(None));
        assert!(!r.set_path(3000, b"network"));
    }

    #[test]
    fn failed_path_binding_preserves_both_registry_indexes() {
        let mut registry = Registry::default();
        assert!(!registry.set_path(2000, b"missing"));
        assert!(registry.by_path(b"missing").is_none());
        registry.objects.insert(2000, Object::new(None));
        assert!(registry.set_path(2000, b"original"));
        assert!(!registry.set_path(2000, b"replacement"));
        assert_eq!(registry.by_path(b"original"), Some(2000));
        assert!(registry.by_path(b"replacement").is_none());
        registry.destroy(2000).unwrap();
        assert!(registry.paths.is_empty());
    }

    #[test]
    fn subscriptions_are_head_inserted_and_reversible() {
        let mut r = Registry::default();
        for id in [10u32, 11, 12] {
            r.objects.insert(id, Object::new(None));
        }
        assert!(r.subscribe(11, 10));
        assert!(!r.subscribe(12, 10));
        assert_eq!(r.get(10).unwrap().subscribers, vec![12, 11]);
        assert!(!r.unsubscribe(12, 10));
        assert!(r.unsubscribe(11, 10));
        assert!(r.get(10).unwrap().subscribers.is_empty());
        assert!(r.get(11).unwrap().targets.is_empty());
    }

    #[test]
    fn type_refcount_frees_on_last_use() {
        let mut r = Registry::default();
        let t = r.new_type(vec![]).unwrap();
        assert_eq!(r.types[&t].refcount, 1);
        let a = r.create(Some(t), None).unwrap();
        r.unref_type(t); // create() took its own reference
        assert_eq!(r.types[&t].refcount, 1);
        r.destroy(a);
        assert!(!r.types.contains_key(&t));
    }
}
