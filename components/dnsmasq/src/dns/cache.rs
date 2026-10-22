//! Dynamic forward-cache primitives traced to dnsmasq 2.93 cache.c.
//!
//! This module does not decide whether an upstream packet is cacheable, extract
//! SOA metadata, or store local hosts/leases. Callers must perform those checks.
//! The insertion transaction intentionally preserves C's failure behavior:
//! removals take effect immediately, but new entries become visible at commit.

use super::lease_names::{BlockerKind, ForwardPublication, PublicationCache};
use super::wire::Name;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

#[path = "cache_name_index.rs"]
mod name_index;
use name_index::SlotIndices;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ipv4,
    Ipv6,
    ReverseIpv4,
    ReverseIpv6,
    Generic(u16),
    Cname,
    NxDomain,
}

impl Kind {
    fn is_reverse(self) -> bool {
        matches!(self, Self::ReverseIpv4 | Self::ReverseIpv6)
    }

    fn conflicts(self, other: Self) -> bool {
        !self.is_reverse()
            && !other.is_reverse()
            && (self == other || self == Self::Cname || other == Self::Cname)
    }

    fn matches(self, requested: Self) -> bool {
        self == requested || matches!((self, requested), (Self::Generic(_), Self::Generic(_)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalePolicy {
    Disabled,
    Forever,
    Seconds(u32),
}

/// A cache sink receives authenticated source policy separately from query
/// metadata support. CD/NO_CACHE still extract and remove old records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Extraction {
    Unsupported,
    ExtractOnly,
    Commit,
}

impl Extraction {
    pub fn from_source(
        supported: bool,
        no_cache: bool,
        request_cd: bool,
        upstream_cd: bool,
    ) -> Self {
        if !supported {
            Self::Unsupported
        } else if no_cache || request_cd || upstream_cd {
            Self::ExtractOnly
        } else {
            Self::Commit
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub min_ttl: u64,
    pub max_ttl: u64,
    pub max_reply_ttl: u64,
    pub stale: StalePolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_ttl: 0,
            max_ttl: 0,
            max_reply_ttl: 0,
            stale: StalePolicy::Disabled,
        }
    }
}

impl Policy {
    pub fn cache_ttl(self, ttl: u64) -> u64 {
        let ttl = if self.max_ttl != 0 {
            ttl.min(self.max_ttl)
        } else {
            ttl
        };
        ttl.max(self.min_ttl)
    }

    fn expired(self, expires: i64, now: i64) -> bool {
        match self.stale {
            StalePolicy::Forever => false,
            StalePolicy::Seconds(seconds) => {
                i128::from(now) - i128::from(expires) >= i128::from(seconds)
            }
            StalePolicy::Disabled => now >= expires,
        }
    }
}

/// Slot generation prevents an evicted CNAME target from becoming a new target
/// when its storage is reused. IDs are valid only for the cache that created them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryId {
    slot: usize,
    generation: u64,
}

/// A local CNAME terminal owns its name rather than borrowing a lease's
/// storage. DHCP identity changes on an actual new publication; static hosts
/// remain valid until the containing cache is cleared on reload.
#[derive(Clone, Debug)]
pub struct LocalTarget {
    pub name: Name,
    lease_generation: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum CnameTarget {
    Dynamic(EntryId),
    Local(Arc<LocalTarget>),
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: Name,
    pub kind: Kind,
    pub negative: bool,
    /// Canonical uncompressed RDATA. Negative entries carry no RDATA; an
    /// upstream SOA is a separate `Generic(6)` cache record.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Record payloads are immutable after insertion. A TCP fork view shares
    /// these bytes while owning its own expiry, links and generation state.
    pub record: Arc<Record>,
    pub expires: i64,
    target: Option<CnameTarget>,
    authority_name: Option<Name>,
    referenced: bool,
    committed: bool,
}

impl Entry {
    /// C marks a record stale strictly after expiry, unlike its expiry test.
    pub fn is_stale(&self, now: i64) -> bool {
        now > self.expires
    }

    pub fn reply_ttl(&self, now: i64, policy: Policy) -> u32 {
        let ttl = (i128::from(self.expires) - i128::from(now)).clamp(0, u32::MAX as i128) as u32;
        if policy.max_reply_ttl == 0 {
            ttl
        } else {
            u64::from(ttl).min(policy.max_reply_ttl) as u32
        }
    }

    pub fn cname_target(&self) -> Option<CnameTarget> {
        self.target.clone()
    }

    pub fn negative_authority_name(&self) -> Option<&Name> {
        self.authority_name.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    PreviousFailure,
    ZeroTtl,
    Full,
    LongNameLimit,
    TimeOverflow,
    NotNegative,
    LocalConflict,
}

/// Caller-owned C metrics for one cache. Keep this beside the cache so the
/// primitive's layout and allocation budget do not change. Count independently
/// of whether ubus is enabled; publish snapshots without consuming/resetting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheCounters {
    pub inserted: u32,
    pub live_freed: u32,
}

/// Owned committed records in C's child-to-parent pipe order. Child slot IDs,
/// local targets and counters deliberately never cross this boundary.
/// No production sender or cache snapshot representation is implied.
#[derive(Debug)]
pub struct CacheTransaction {
    records: Vec<TransferredRecord>,
}

#[derive(Debug)]
struct TransferredRecord {
    record: Record,
    expires: i64,
    authority_name: Option<Name>,
}

/// Current parent local-name match at cache_scan_free's existing boundary.
/// The caller supplies its usual hosts/lease/configured-CNAME precedence.
#[derive(Clone, Copy, Debug)]
pub struct LocalCacheMatch {
    pub same_address: bool,
    pub from_lease: bool,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    prev: Option<NonZeroU32>,
    next: Option<NonZeroU32>,
}

fn slot_link(index: usize) -> NonZeroU32 {
    // Cache::new validates the capacity before constructing any slot. The
    // one-based representation reserves zero for an absent link.
    index
        .checked_add(1)
        .and_then(|index| u32::try_from(index).ok())
        .and_then(NonZeroU32::new)
        .expect("validated one-based cache slot index")
}

fn slot_index(link: Option<NonZeroU32>) -> Option<usize> {
    link.map(|index| index.get() as usize - 1)
}

#[derive(Clone)]
struct ContentBlock {
    entries: Box<[Option<Entry>]>,
}

type NameIndex = HashMap<Arc<[u8]>, SlotIndices>;

#[derive(Clone, Copy)]
enum NameSelection {
    Missing,
    One(EntryId),
    AddressPair { ipv4: EntryId, ipv6: EntryId },
}

/// A read-only inspection already required by the local/CNAME ordering. This
/// query-scoped hint owns no index references, so it cannot create extra COW
/// allocations. Only a fresh A/AAAA pair can share the single-address shortcut;
/// other multi-record names retain the ordinary indexed lookup path.
pub(crate) struct NameLookup<'a> {
    name: &'a Name,
    owner: usize,
    roots: usize,
    revision: u64,
    selection: NameSelection,
}

const CONTENT_BLOCK_SLOTS: usize = 64;
const NAME_SHARDS: usize = 64;

/// Fixed number of records, with an index per name and an intrusive LRU of slot
/// indices. Pending inserts are outside the LRU and invisible to lookups.
/// Capacity is measured in records, including CNAME and negative records.
#[derive(Clone)]
pub struct Cache {
    policy: Policy,
    slots: Vec<Slot>,
    content: Vec<Arc<ContentBlock>>,
    names: Vec<Arc<NameIndex>>,
    reverse_chain: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    pending: Vec<usize>,
    failed: bool,
    long_names: usize,
    lease_generation: u64,
    name_revision: u64,
    // Deletion may leave this early, but never later than a committed expiry.
    expiry_lower_bound: i64,
}

impl Cache {
    /// C's nondebug TCP child inherits the accepted cache. Share immutable
    /// payloads; mutable indices, pending insertions and LRU state are private.
    /// The containing owner supplies the fixed accept clock separately.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    fn entry(&self, slot: usize) -> Option<&Entry> {
        self.content[slot / CONTENT_BLOCK_SLOTS].entries[slot % CONTENT_BLOCK_SLOTS].as_ref()
    }

    fn entry_mut(&mut self, slot: usize) -> &mut Option<Entry> {
        &mut Arc::make_mut(&mut self.content[slot / CONTENT_BLOCK_SLOTS]).entries
            [slot % CONTENT_BLOCK_SLOTS]
    }

    fn key_shard(key: &[u8]) -> usize {
        // Stable high FNV-1a bits select the 64 owner roots independently of
        // HashMap's randomized bucket hasher, as the scheme-A contract specifies.
        let mut hash = 0xcbf29ce484222325u64;
        for byte in key {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        (hash >> (64 - NAME_SHARDS.ilog2())) as usize
    }

    fn names_for(&self, key: &[u8]) -> Option<&SlotIndices> {
        self.names[Self::key_shard(key)].get(key)
    }

    fn names_for_mut(&mut self, key: &[u8]) -> Option<&mut SlotIndices> {
        self.name_revision = self.name_revision.saturating_add(1);
        Arc::make_mut(&mut self.names[Self::key_shard(key)]).get_mut(key)
    }

    fn names_shard_mut(&mut self, key: &[u8]) -> &mut NameIndex {
        self.name_revision = self.name_revision.saturating_add(1);
        Arc::make_mut(&mut self.names[Self::key_shard(key)])
    }

    pub fn set_max_reply_ttl(&mut self, maximum: u64) {
        self.policy.max_reply_ttl = maximum;
    }
    /// Create a fixed-capacity cache with the supplied TTL and stale-record policy.
    ///
    /// # Panics
    /// Panics if `capacity` exceeds the `u32` slot-link range.
    pub fn new(capacity: usize, mut policy: Policy) -> Self {
        // Production cache-size is capped at 5,000,000. Keep the public
        // primitive's link representation checked too, without truncating
        // indices or shortening its u64 anti-ABA generation.
        assert!(
            capacity <= u32::MAX as usize,
            "cache capacity exceeds slot link range"
        );
        // C represents a zero stale allowance as the option being disabled.
        if policy.stale == StalePolicy::Seconds(0) {
            policy.stale = StalePolicy::Disabled;
        }
        let content = (0..capacity.div_ceil(CONTENT_BLOCK_SLOTS))
            .map(|block| {
                let start = block * CONTENT_BLOCK_SLOTS;
                let len = (capacity - start).min(CONTENT_BLOCK_SLOTS);
                Arc::new(ContentBlock {
                    entries: vec![None; len].into_boxed_slice(),
                })
            })
            .collect();
        Self {
            policy,
            slots: (0..capacity)
                .map(|i| Slot {
                    generation: 0,
                    prev: i.checked_sub(1).map(slot_link),
                    next: (i + 1 < capacity).then_some(i + 1).map(slot_link),
                })
                .collect(),
            content,
            names: (0..NAME_SHARDS)
                .map(|_| Arc::new(NameIndex::new()))
                .collect(),
            reverse_chain: Vec::new(),
            head: (capacity > 0).then_some(0),
            tail: capacity.checked_sub(1),
            pending: Vec::new(),
            failed: false,
            long_names: 0,
            lease_generation: 0,
            name_revision: 0,
            expiry_lower_bound: i64::MAX,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = &Entry> {
        (0..self.slots.len()).filter_map(|slot| self.entry(slot))
            .filter(|entry| entry.committed)
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Drop all forwarded records, including an unfinished insertion, on
    /// SIGHUP (`cache.c::cache_reload`). Local hosts and DHCP names are owned
    /// separately. Keep the allocation and generations so old handles cannot
    /// become valid again when the empty slots are reused.
    pub fn clear(&mut self) {
        self.name_revision = self.name_revision.saturating_add(1);
        self.expiry_lower_bound = i64::MAX;
        let capacity = self.slots.len();
        // Each root's uniqueness is a block-level property. Detach once before
        // clearing that block, in the same record order, instead of repeating
        // Arc's atomic ownership check for every slot in the block.
        for block in 0..self.content.len() {
            for entry in &mut Arc::make_mut(&mut self.content[block]).entries {
                *entry = None;
            }
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            slot.prev = index.checked_sub(1).map(slot_link);
            slot.next = (index + 1 < capacity).then_some(index + 1).map(slot_link);
        }
        for root in &mut self.names {
            // An unused unique root is already the reset state. Do not retain
            // allocated buckets or a shared empty root: both must be replaced
            // here, preserving memory release and the next insertion's COW
            // allocation boundary.
            let unused = Arc::get_mut(root).is_some_and(|names| names.capacity() == 0);
            if !unused {
                *root = Arc::new(NameIndex::new());
            }
        }
        self.reverse_chain.clear();
        self.pending.clear();
        self.failed = false;
        self.long_names = 0;
        self.head = (capacity > 0).then_some(0);
        self.tail = capacity.checked_sub(1);
    }

    /// The production owner must clear the cache and its two metric windows
    /// together. Other DNS/DHCP counters are unaffected by cache_reload.
    pub fn clear_counted(&mut self, counters: &mut CacheCounters) {
        self.clear();
        *counters = CacheCounters::default();
    }

    pub fn get(&self, id: EntryId) -> Option<&Entry> {
        self.slots
            .get(id.slot)
            .filter(|slot| slot.generation == id.generation)?;
        self.entry(id.slot)
    }

    /// C cache_find_non_terminal: any live exact-name forward record except
    /// NXDOMAIN establishes existence, including NODATA and dynamic CNAMEs.
    /// Do not promote, rotate or remove records as a normal lookup would.
    pub fn contains_forward_name(&self, name: &Name, now: i64) -> bool {
        let key = name.canonical_wire();
        self.names_for(&key).is_some_and(|slots| {
            slots.iter().any(|&slot| {
                self.entry(slot).is_some_and(|entry| {
                    entry.record.kind != Kind::NxDomain && !entry.record.kind.is_reverse()
                }) && !self.invalid(slot, now)
            })
        })
    }

    /// Read-only candidate test used before local synthetic answers. This has
    /// no LRU, expiry removal, or round-robin side effects. A matching CNAME
    /// or NXDOMAIN marker is a candidate for every ordinary address query;
    /// generic requests match any cached generic RR at the name.
    pub fn has_forward_candidate(&self, name: &Name, rrtype: u16, now: i64) -> bool {
        let key = name.canonical_wire();
        let Some(slots) = self.names_for(&key) else {
            return false;
        };
        slots.iter().any(|&slot| {
            let Some(entry) = self.entry(slot) else {
                return false;
            };
            if self.invalid(slot, now) || entry.record.kind.is_reverse() {
                return false;
            }
            match (rrtype, entry.record.kind) {
                (255, Kind::NxDomain) => false,
                (255, _) => true,
                (1, Kind::Ipv4 | Kind::Cname | Kind::NxDomain) => true,
                (28, Kind::Ipv6 | Kind::Cname | Kind::NxDomain) => true,
                (12, Kind::Generic(12) | Kind::Cname | Kind::NxDomain) => true,
                (requested, Kind::Generic(actual)) => requested == actual,
                (_, Kind::Cname | Kind::NxDomain) => true,
                _ => false,
            }
        })
    }

    /// A live CNAME changes the lookup name before configured RR processing.
    /// Leave promotion and expiry removal to the subsequent cache answer.
    pub fn has_cname(&self, name: &Name, now: i64) -> bool {
        let canonical;
        let key = if name.as_wire().iter().any(u8::is_ascii_uppercase) {
            canonical = name.canonical_wire();
            canonical.as_slice()
        } else {
            name.as_wire()
        };
        self.names_for(key).is_some_and(|slots| {
            slots.iter().any(|&slot| {
                self.entry(slot)
                    .is_some_and(|entry| entry.record.kind == Kind::Cname)
                    && !self.invalid(slot, now)
            })
        })
    }

    /// Inspect without expiry removal, LRU promotion or rotation, exactly as
    /// has_cname does. Keep the query name borrowed until this synchronous
    /// answer operation ends; object/root identities also reject replacement
    /// or movement of the owning cache. Saturation permanently disables reuse.
    pub(super) fn inspect_name<'a>(&self, name: &'a Name, now: i64) -> (bool, Option<NameLookup<'a>>) {
        let canonical;
        let key = if name.as_wire().iter().any(u8::is_ascii_uppercase) {
            canonical = name.canonical_wire();
            canonical.as_slice()
        } else {
            name.as_wire()
        };
        let indices = self.names_for(key);
        let cname = indices.is_some_and(|slots| slots.iter().any(|&slot| {
            self.entry(slot).is_some_and(|entry| entry.record.kind == Kind::Cname)
                && !self.invalid(slot, now)
        }));
        if self.name_revision == u64::MAX {
            return (cname, None);
        }
        let selection = match indices {
            None | Some(SlotIndices::Empty) => NameSelection::Missing,
            Some(SlotIndices::One(slot)) => NameSelection::One(self.id(*slot)),
            Some(SlotIndices::Many(slots)) => {
                let [first, second] = slots.as_slice() else { return (cname, None) };
                let (ipv4, ipv6) = match (self.entry(*first), self.entry(*second)) {
                    (Some(a), Some(b)) if a.record.kind == Kind::Ipv4 && b.record.kind == Kind::Ipv6 =>
                        (*first, *second),
                    (Some(a), Some(b)) if a.record.kind == Kind::Ipv6 && b.record.kind == Kind::Ipv4 =>
                        (*second, *first),
                    _ => return (cname, None),
                };
                // Ordinary lookup expires every name member before selecting
                // a family. Reject both stale/invalid records without mutation
                // so that the general path retains those expiry side effects.
                if !self.fresh_address_slot(ipv4, Kind::Ipv4, now)
                    || !self.fresh_address_slot(ipv6, Kind::Ipv6, now)
                { return (cname, None); }
                NameSelection::AddressPair { ipv4: self.id(ipv4), ipv6: self.id(ipv6) }
            },
        };
        (cname, Some(NameLookup {
            name,
            owner: self as *const Self as usize,
            roots: self.names.as_ptr() as usize,
            revision: self.name_revision,
            selection,
        }))
    }

    /// The common one-address hit can keep its ID on the stack. A rejected
    /// hint changes nothing; the ordinary lookup still owns all fallback,
    /// expiry, negative, CNAME and RRset behavior.
    pub(super) fn single_fresh_address_with_hint(
        &mut self, name: &Name, kind: Kind, now: i64, hint: Option<&NameLookup<'_>>,
    ) -> Option<EntryId> {
        let id = self.single_fresh_address_id_with_hint(name, kind, now, hint)?;
        // Exactly the existing single-slot lookup promotion, without a Vec.
        self.unlink(id.slot);
        self.link_head(id.slot);
        Some(self.id(id.slot))
    }

    /// Read-only eligibility for a query-local shortcut before local ownership.
    pub(super) fn single_fresh_address_id_with_hint(
        &self, name: &Name, kind: Kind, now: i64, hint: Option<&NameLookup<'_>>,
    ) -> Option<EntryId> {
        let hint = hint?;
        if !std::ptr::eq(name, hint.name)
            || hint.owner != self as *const Self as usize
            || hint.roots != self.names.as_ptr() as usize
            || hint.revision != self.name_revision
            || self.name_revision == u64::MAX
        { return None; }
        let id = match hint.selection {
            NameSelection::One(id) => id,
            NameSelection::AddressPair { ipv4, ipv6 } => {
                // Hints may outlive the inspection's clock value. Both members
                // must still be fresh before bypassing the ordinary expiry walk.
                self.get(ipv4)?;
                self.get(ipv6)?;
                if !self.fresh_address_slot(ipv4.slot, Kind::Ipv4, now)
                    || !self.fresh_address_slot(ipv6.slot, Kind::Ipv6, now)
                { return None; }
                match kind { Kind::Ipv4 => ipv4, Kind::Ipv6 => ipv6, _ => return None }
            },
            NameSelection::Missing => return None,
        };
        let expected_length = match kind { Kind::Ipv4 => 4, Kind::Ipv6 => 16, _ => return None };
        let entry = self.get(id)?;
        if entry.record.kind != kind || entry.record.negative
            || entry.record.data.len() != expected_length || entry.is_stale(now)
            || !self.is_valid(id, now)
        { return None; }
        Some(id)
    }

    fn fresh_address_slot(&self, slot: usize, kind: Kind, now: i64) -> bool {
        let length = match kind { Kind::Ipv4 => 4, Kind::Ipv6 => 16, _ => return false };
        self.entry(slot).is_some_and(|entry| entry.record.kind == kind
            && !entry.record.negative && entry.record.data.len() == length
            && !entry.is_stale(now) && !self.invalid(slot, now))
    }

    pub(super) fn lookup_with_hint(
        &mut self,
        name: &Name,
        kinds: &[Kind],
        now: i64,
        round_robin: bool,
        hint: Option<&NameLookup<'_>>,
    ) -> Vec<EntryId> {
        let usable = hint.filter(|hint| {
            std::ptr::eq(name, hint.name)
                && hint.owner == self as *const Self as usize
                && hint.roots == self.names.as_ptr() as usize
                && hint.revision == self.name_revision
                && self.name_revision != u64::MAX
        });
        match usable.map(|hint| hint.selection) {
            Some(NameSelection::Missing) => Vec::new(),
            Some(NameSelection::One(id)) if self.get(id).is_some() => {
                let mut found = Vec::new();
                // Same single-slot step as lookup; leave its multi-slot loop
                // intact so it has no extra per-record dispatch or calls.
                if self.invalid(id.slot, now) {
                    self.remove(id.slot);
                } else if kinds.iter().any(|kind| self.entry(id.slot).unwrap().record.kind.matches(*kind)) {
                    self.unlink(id.slot);
                    self.link_head(id.slot);
                    found.push(self.id(id.slot));
                }
                found
            }
            _ => self.lookup(name, kinds, now, round_robin),
        }
    }

    /// A generic NX marker is inspected before local interface/synthetic
    /// answers. Owners may defer an initial local answer into CacheContext so
    /// that marker's cached SOA is retained by the final authority footer.
    pub fn has_nxdomain(&self, name: &Name, now: i64) -> bool {
        let key = name.canonical_wire();
        self.names_for(&key).is_some_and(|slots| {
            slots.iter().any(|&slot| {
                self.entry(slot).is_some_and(|entry| {
                    entry.record.kind == Kind::NxDomain && entry.record.negative
                }) && !self.invalid(slot, now)
            })
        })
    }

    /// Read-only reverse candidate test. Positive IP records precede local
    /// synthesis, and a CNAME changes the reverse cursor. Generic PTR/NX
    /// markers are a later forward-name tier and must not suppress synthesis.
    pub fn has_reverse_candidate(&self, address: IpAddr, now: i64) -> bool {
        let (kind, bytes) = reverse_key(address);
        self.reverse_chain.iter().any(|&slot| {
            !self.invalid(slot, now)
                && self
                    .entry(slot)
                    .is_some_and(|entry| entry.record.kind == kind && entry.record.data == bytes)
        }) || self
            .names_for(&reverse_name(address).canonical_wire())
            .is_some_and(|slots| {
                slots.iter().any(|&slot| {
                    self.entry(slot)
                        .is_some_and(|entry| entry.record.kind == Kind::Cname)
                        && !self.invalid(slot, now)
                })
            })
    }

    /// Follow a live dynamic CNAME chain without promoting or removing any
    /// cache entry. The returned name is the terminal owner that the local
    /// interface-record resolver may override before ordinary cached RDATA is
    /// emitted. A broken, expired, or cyclic chain is not a terminal.
    pub fn cname_terminal_name(&self, name: &Name, now: i64) -> Option<Name> {
        let key = name.canonical_wire();
        let mut ids = self.names_for(&key)?.iter().map(|&slot| self.id(slot));
        let mut id = ids.find(|id| {
            self.get(*id).is_some_and(|entry| {
                entry.record.kind == Kind::Cname && !self.invalid(id.slot, now)
            })
        })?;
        for _ in 0..10 {
            let entry = self.get(id)?;
            if self.invalid(id.slot, now) {
                return None;
            }
            match entry.cname_target()? {
                CnameTarget::Local(target) => return Some(target.name.clone()),
                CnameTarget::Dynamic(target) => {
                    let target_entry = self.get(target)?;
                    if target_entry.record.kind == Kind::Cname {
                        id = target;
                    } else {
                        return Some(target_entry.record.name.clone());
                    }
                }
            }
        }
        None
    }

    /// Check that a handle still refers to a live cache entry at `now`.
    ///
    /// Handles are intentionally read-only; callers that need the normal
    /// lookup side effect of removing an expired slot should still use
    /// [`Cache::lookup`].  This predicate is for CNAME target traversal,
    /// where the target is reached through an `EntryId` rather than a name
    /// lookup.
    pub fn is_valid(&self, id: EntryId, now: i64) -> bool {
        let Some(slot) = self.slots.get(id.slot) else {
            return false;
        };
        slot.generation == id.generation
            && self.entry(id.slot).is_some()
            && !self.invalid(id.slot, now)
    }

    pub fn start_insert(&mut self) {
        while let Some(slot) = self.pending.pop() {
            self.free(slot);
        }
        self.failed = false;
    }

    fn fail(&mut self, error: InsertError) -> Result<EntryId, InsertError> {
        self.failed = true;
        Err(error)
    }

    /// The caller found a local record in C's scan_free position. A matching
    /// address returns that local target without allocating a dynamic slot;
    /// any other local conflict fails the entire insertion transaction.
    pub(super) fn insert_against_local(
        &mut self,
        ttl: u64,
        same_address: bool,
    ) -> Result<(), InsertError> {
        self.check_local_insert(self.policy.cache_ttl(ttl) == 0, same_address)
    }

    fn check_local_insert(
        &mut self,
        zero_ttl: bool,
        same_address: bool,
    ) -> Result<(), InsertError> {
        if self.failed {
            return Err(InsertError::PreviousFailure);
        }
        let error = if zero_ttl && self.policy.stale == StalePolicy::Disabled {
            Some(InsertError::ZeroTtl)
        } else if !same_address {
            Some(InsertError::LocalConflict)
        } else {
            None
        };
        if let Some(error) = error {
            self.failed = true;
            Err(error)
        } else {
            Ok(())
        }
    }

    pub fn insert(&mut self, record: Record, now: i64, ttl: u32) -> Result<EntryId, InsertError> {
        self.insert_counted(record, now, ttl, &mut CacheCounters::default())
    }

    /// Preserve immediate pressure-removal effects even when this insertion or
    /// a later insertion fails. C increments live_freed once for a live LRU
    /// victim selection, not once per record removed from that victim's RRset.
    pub fn insert_counted(
        &mut self,
        record: Record,
        now: i64,
        ttl: u32,
        counters: &mut CacheCounters,
    ) -> Result<EntryId, InsertError> {
        self.insert_ttl_counted(record, now, u64::from(ttl), counters)
    }

    /// Wide TTL is C's unsigned long. A wrapped negative int becomes a large
    /// ulong whose time_t cast is negative, e.g. min-cache-ttl=-1 expires at
    /// now-1. Do not saturate it into a far-future expiry.
    pub fn insert_ttl_counted(
        &mut self,
        record: Record,
        now: i64,
        ttl: u64,
        counters: &mut CacheCounters,
    ) -> Result<EntryId, InsertError> {
        if self.failed {
            return Err(InsertError::PreviousFailure);
        }
        let ttl = self.policy.cache_ttl(ttl);
        if ttl == 0 && self.policy.stale == StalePolicy::Disabled {
            return self.fail(InsertError::ZeroTtl);
        }
        let Some(expires) = now.checked_add(ttl as i64) else {
            return self.fail(InsertError::TimeOverflow);
        };
        self.insert_at_counted(record, now, expires, counters)
    }

    /// Already selected absolute expiry; never run the ordinary TTL clamps.
    fn insert_at_counted(
        &mut self,
        record: Record,
        now: i64,
        expires: i64,
        counters: &mut CacheCounters,
    ) -> Result<EntryId, InsertError> {
        if self.failed {
            return Err(InsertError::PreviousFailure);
        }
        if expires == now && self.policy.stale == StalePolicy::Disabled {
            return self.fail(InsertError::ZeroTtl);
        }
        let key = record.name.canonical_wire();
        let mut preserved = None;
        if record.kind.is_reverse() {
            // Reverse insertion scans all dynamic hash buckets and removes
            // this IP's old RRset. Forward names and other IPs are independent.
            for slot in 0..self.slots.len() {
                if self.entry(slot).is_some_and(|entry| {
                    entry.committed
                        && (self.policy.expired(entry.expires, now)
                            || (entry.record.kind == record.kind
                                && entry.record.data == record.data))
                }) {
                    self.remove(slot);
                }
            }
        } else if let Some(indices) = self.names_for(&key).cloned() {
            for &slot in indices.iter() {
                let entry = self.entry(slot).unwrap();
                if record.kind.conflicts(entry.record.kind) {
                    if entry.referenced {
                        preserved = Some(self.id(slot));
                    }
                    self.remove(slot);
                } else if self.invalid(slot, now) {
                    self.remove(slot);
                }
            }
        }
        let slot = if let Some(id) = preserved {
            id.slot
        } else {
            if self.tail.is_some_and(|slot| self.entry(slot).is_some())
                && self.policy.expired(self.expiry_lower_bound, now)
            {
                // Same pressure trigger as C: reclaim expired entries globally
                // before spilling any live entry. A conservative deadline can
                // prove this pass has no removals; otherwise keep slot order.
                self.expiry_lower_bound = i64::MAX;
                for slot in 0..self.slots.len() {
                    if let Some(entry) = self.entry(slot).filter(|entry| entry.committed) {
                        if self.policy.expired(entry.expires, now) {
                            self.remove(slot);
                        } else {
                            self.expiry_lower_bound = self.expiry_lower_bound.min(entry.expires);
                        }
                    }
                }
            }
            let Some(mut slot) = self.tail else {
                return self.fail(InsertError::Full);
            };
            if let Some(entry) = self.entry(slot) {
                if now < entry.expires {
                    counters.live_freed = counters.live_freed.wrapping_add(1);
                }
                let victim_key = entry.record.name.canonical_wire();
                let victim_kind = entry.record.kind;
                let victim_address = entry.record.data.clone();
                // C spills the conflicting name/type or reverse-IP RRset,
                // not only its oldest member.
                let victims = if victim_kind.is_reverse() {
                    self.reverse_chain.clone()
                } else {
                    self.names_for(&victim_key).map(|indices| indices.to_vec()).unwrap_or_default()
                };
                for victim in victims {
                    let entry = self.entry(victim).unwrap();
                    if (victim_kind.is_reverse()
                        && entry.record.kind == victim_kind
                        && entry.record.data == victim_address)
                        || victim_kind.conflicts(entry.record.kind)
                        || self.invalid(victim, now)
                    {
                        self.remove(victim);
                    }
                }
                slot = self.tail.expect("spilling a committed entry frees a slot");
            }
            slot
        };
        let long = record.name.dnsmasq_bytes_len() >= 75;
        if long && self.long_names >= self.slots.len() / 10 {
            return self.fail(InsertError::LongNameLimit);
        }
        self.unlink(slot);
        if let Some(id) = preserved {
            self.slots[slot].generation = id.generation;
        } else {
            // Exhausting a u64 generation requires > 584 years even at 10^9/s.
            // Refuse wrap rather than let a stale handle become valid again.
            self.slots[slot].generation = self.slots[slot]
                .generation
                .checked_add(1)
                .expect("cache generation exhausted");
        }
        self.long_names += usize::from(long);
        *self.entry_mut(slot) = Some(Entry {
            record: Arc::new(record),
            expires,
            target: None,
            authority_name: None,
            referenced: preserved.is_some(),
            committed: false,
        });
        self.pending.push(slot);
        Ok(self.id(slot))
    }

    /// Insert a negative forward answer using dnsmasq's SOA/`--neg-ttl`
    /// selection rule.  An SOA-derived TTL always wins; the configured
    /// fallback is used only when no SOA was present.  A zero fallback means
    /// that a reply without an SOA is not cacheable.  The ordinary insertion
    /// path still applies min/max cache TTL and stale-cache policy.
    ///
    /// This mirrors `rfc1035.c::extract_addresses`: callers pass the SOA
    /// minimum/TTL when one was found, otherwise `configured_ttl` (the
    /// daemon's `neg_ttl`) is considered.  `no-negcache` is represented by
    /// simply not calling this method.
    pub fn insert_negative(
        &mut self,
        record: Record,
        now: i64,
        soa_ttl: Option<u32>,
        configured_ttl: u64,
    ) -> Result<Option<EntryId>, InsertError> {
        self.insert_negative_counted(
            record,
            now,
            soa_ttl,
            configured_ttl,
            &mut CacheCounters::default(),
        )
    }

    pub fn insert_negative_counted(
        &mut self,
        record: Record,
        now: i64,
        soa_ttl: Option<u32>,
        configured_ttl: u64,
        counters: &mut CacheCounters,
    ) -> Result<Option<EntryId>, InsertError> {
        if !record.negative {
            return Err(InsertError::NotNegative);
        }
        let ttl = soa_ttl
            .map(u64::from)
            .or((configured_ttl != 0).then_some(configured_ttl));
        let Some(ttl) = ttl else {
            return Ok(None);
        };
        self.insert_ttl_counted(record, now, ttl, counters)
            .map(Some)
    }

    /// Attach the owner of the independent SOA used for a negative answer.
    /// Keeping only the owner lets later SOA replacement/reuse be observed by
    /// lookup, as in `cache.c::find_soa`; the authority itself consumes a
    /// normal cache slot.
    pub fn set_negative_authority(&mut self, negative: EntryId, authority: Name) -> bool {
        if self
            .slots
            .get(negative.slot)
            .is_none_or(|slot| slot.generation != negative.generation)
        {
            return false;
        }
        let Some(entry) = self.entry_mut(negative.slot).as_mut() else {
            return false;
        };
        if !entry.record.negative {
            return false;
        }
        entry.authority_name = Some(authority);
        true
    }

    /// Called while assembling the CNAME chain, including pending targets.
    pub fn set_cname_target(&mut self, cname: EntryId, target: EntryId) -> bool {
        if self
            .get(cname)
            .is_none_or(|entry| entry.record.kind != Kind::Cname)
            || self.get(target).is_none()
        {
            return false;
        }
        self.entry_mut(target.slot).as_mut().unwrap().referenced = true;
        self.entry_mut(cname.slot).as_mut().unwrap().target = Some(CnameTarget::Dynamic(target));
        true
    }

    pub(super) fn local_target(&self, name: Name, from_lease: bool) -> Arc<LocalTarget> {
        Arc::new(LocalTarget {
            name,
            lease_generation: from_lease.then_some(self.lease_generation),
        })
    }

    pub(super) fn set_local_cname_target(
        &mut self,
        cname: EntryId,
        target: Arc<LocalTarget>,
    ) -> bool {
        if self
            .get(cname)
            .is_none_or(|entry| entry.record.kind != Kind::Cname)
        {
            return false;
        }
        self.entry_mut(cname.slot).as_mut().unwrap().target = Some(CnameTarget::Local(target));
        true
    }

    pub fn commit(&mut self) -> bool {
        self.commit_counted(&mut CacheCounters::default())
    }

    /// Count each newly committed record after discarding invalid CNAMEs.
    /// Pending entries, aborts and failed commits do not increment inserted.
    pub fn commit_counted(&mut self, counters: &mut CacheCounters) -> bool {
        self.commit_inner(counters, None)
    }

    /// Capture only a successful commit. Some(empty) is significant: C sends
    /// an empty transaction, which clears prior parent pending insertions.
    /// Owned names/data allocate only on this opt-in path; allocation failure
    /// follows Rust's allocator policy. This is not a fallible pipe sender.
    pub fn capture_commit_counted(
        &mut self,
        counters: &mut CacheCounters,
    ) -> Option<CacheTransaction> {
        let mut records = Vec::new();
        self.commit_inner(counters, Some(&mut records))
            .then_some(CacheTransaction { records })
    }

    fn commit_inner(
        &mut self,
        counters: &mut CacheCounters,
        mut capture: Option<&mut Vec<TransferredRecord>>,
    ) -> bool {
        if self.failed {
            return false;
        }
        while let Some(slot) = self.pending.pop() {
            if self.outdated_cname(slot) {
                self.free(slot);
                continue;
            }
            let capacity = self.slots.len();
            let (key, reverse_name, expires) = {
                let entry = self.entry_mut(slot).as_mut().unwrap();
                entry.committed = true;
                (
                    entry.record.name.canonical_wire(),
                    entry.record.kind.is_reverse().then(|| entry.record.name.clone()),
                    entry.expires,
                )
            };
            self.expiry_lower_bound = self.expiry_lower_bound.min(expires);
            self.names_shard_mut(&key)
                .entry(Arc::from(key.into_boxed_slice()))
                .or_default()
                .push(slot);
            if let Some(name) = reverse_name {
                let bucket = reverse_bucket(&name, capacity);
                let mut at = self.reverse_chain.partition_point(|&old| {
                    reverse_bucket(&self.entry(old).unwrap().record.name, self.slots.len()) < bucket
                });
                while at < self.reverse_chain.len() {
                    let old = self.entry(self.reverse_chain[at]).unwrap();
                    if reverse_bucket(&old.record.name, self.slots.len()) != bucket
                        || !old.record.name.eq_ignore_ascii_case(&name)
                    {
                        break;
                    }
                    at += 1;
                }
                self.reverse_chain.insert(at, slot);
            }
            self.link_head(slot);
            counters.inserted = counters.inserted.wrapping_add(1);
            if let Some(records) = &mut capture {
                let entry = self.entry(slot).unwrap();
                records.push(TransferredRecord {
                    record: Record {
                        name: entry.record.name.clone(),
                        kind: entry.record.kind,
                        negative: entry.record.negative,
                        // C sends no CNAME target name. Parent import derives
                        // it from the preceding received insertion result.
                        data: if entry.record.kind == Kind::Cname {
                            Vec::new()
                        } else {
                            entry.record.data.clone()
                        },
                    },
                    expires: entry.expires,
                    authority_name: entry.authority_name.clone(),
                });
            }
        }
        true
    }

    /// Apply a whole received transaction against the parent's current state.
    /// `local_match` is a read-only forward lookup using the caller's current
    /// local precedence; reverse records conflict by address, not target name.
    /// Ordered removals/evictions survive a later failure, as in C. Counters
    /// come only from these actual parent operations, never the child totals.
    pub fn import_counted(
        &mut self,
        transaction: CacheTransaction,
        now: i64,
        counters: &mut CacheCounters,
        mut local_match: impl FnMut(&Record) -> Option<LocalCacheMatch>,
    ) -> bool {
        self.start_insert();
        let mut previous: Option<CnameTarget> = None;
        for transferred in transaction.records {
            if self.failed {
                break;
            }
            let mut record = transferred.record;
            let cname = record.kind == Kind::Cname;
            if cname {
                record.data = match &previous {
                    Some(CnameTarget::Dynamic(id)) => self
                        .get(*id)
                        .map_or_else(Vec::new, |entry| entry.record.name.canonical_wire()),
                    Some(CnameTarget::Local(target)) => target.name.canonical_wire(),
                    None => Vec::new(),
                };
            }
            // The two pinned source oracles saturate a negative remaining
            // TTL to zero. Encode that observed conversion explicitly rather
            // than reproduce C's out-of-range floating-to-unsigned cast.
            // Positive remaining lifetimes retain the original deadline.
            let expires = transferred.expires.max(now);
            if expires == now && self.policy.stale == StalePolicy::Disabled {
                self.failed = true;
                break;
            }
            // cache_scan_free consults protected names only for F_FORWARD.
            // Reverse inserts coexist with local records, including a CNAME
            // whose alias happens to be the PTR target.
            let local = if record.kind.is_reverse() {
                None
            } else {
                local_match(&record)
            };
            let inserted = if let Some(local) = local {
                self.check_local_insert(expires == now, local.same_address)
                    .ok()
                    .map(|()| CnameTarget::Local(self.local_target(record.name, local.from_lease)))
            } else {
                self.insert_at_counted(record, now, expires, counters)
                    .ok()
                    .map(CnameTarget::Dynamic)
            };
            if let Some(CnameTarget::Dynamic(id)) = &inserted {
                if let Some(authority) = transferred.authority_name {
                    self.set_negative_authority(*id, authority);
                }
                if cname {
                    match &previous {
                        Some(CnameTarget::Dynamic(target)) => {
                            self.set_cname_target(*id, *target);
                        }
                        Some(CnameTarget::Local(target)) => {
                            self.set_local_cname_target(*id, Arc::clone(target));
                        }
                        None => {}
                    }
                }
            }
            if !cname || inserted.is_some() {
                previous = inserted;
            }
        }
        self.commit_counted(counters)
    }

    /// `Generic(_)` selects all generic RR types, as C's F_RR lookup does.
    /// The caller filters their actual types. Ordering includes C round-robin.
    pub fn lookup(
        &mut self,
        name: &Name,
        kinds: &[Kind],
        now: i64,
        round_robin: bool,
    ) -> Vec<EntryId> {
        let canonical;
        let key = if name.as_wire().iter().any(u8::is_ascii_uppercase) {
            canonical = name.canonical_wire();
            canonical.as_slice()
        } else {
            name.as_wire()
        };
        let mut found = Vec::new();
        let indices = self.names_for(key).cloned().unwrap_or_default();
        for &slot in indices.iter() {
            if self.invalid(slot, now) {
                self.remove(slot);
            } else if kinds
                .iter()
                .any(|kind| self.entry(slot).unwrap().record.kind.matches(*kind))
            {
                self.unlink(slot);
                self.link_head(slot);
                found.push(self.id(slot));
            }
        }
        // The iteration snapshot must not force an otherwise unique Many
        // list to detach for a round-robin rotation after the lookup.
        drop(indices);
        if round_robin && found.len() > 1 {
            // Move subsequent matching entries before the first match, leaving
            // unrelated kinds in their positions relative to that first match.
            let slots: Vec<_> = found.iter().map(|id| id.slot).collect();
            self.names_for_mut(key).unwrap().rotate_matches(&slots);
        }
        found.reverse();
        found
    }

    /// Lookup records for a DNS question, including an NXDOMAIN marker.
    ///
    /// `cache_find_by_name(..., F_RR | F_NXDOMAIN)` in C returns both the
    /// requested RRset and the name-wide NXDOMAIN marker; `answer_request`
    /// then decides whether the marker answers this question.  Keeping that
    /// union explicit avoids making the lower-level `lookup` unexpectedly
    /// match NXDOMAIN for callers that are iterating one exact flag group.
    pub fn lookup_question(
        &mut self,
        name: &Name,
        requested: Kind,
        now: i64,
        round_robin: bool,
    ) -> Vec<EntryId> {
        if requested == Kind::NxDomain {
            self.lookup(name, &[requested], now, round_robin)
        } else {
            self.lookup(name, &[requested, Kind::NxDomain], now, round_robin)
        }
    }

    /// cache_find_by_addr scans every reverse hash prefix, removes expired
    /// reverse records, and promotes matches. It never applies round-robin.
    pub fn lookup_reverse(&mut self, address: IpAddr, now: i64) -> Vec<EntryId> {
        let (kind, data) = reverse_key(address);
        let mut found = Vec::new();
        for slot in self.reverse_chain.clone() {
            if self.policy.expired(self.entry(slot).unwrap().expires, now) {
                self.remove(slot);
            } else if self
                .entry(slot)
                .is_some_and(|entry| entry.record.kind == kind && entry.record.data == data)
            {
                self.unlink(slot);
                self.link_head(slot);
                found.push(self.id(slot));
            }
        }
        found.reverse();
        found
    }

    fn id(&self, slot: usize) -> EntryId {
        EntryId {
            slot,
            generation: self.slots[slot].generation,
        }
    }

    fn outdated_cname(&self, slot: usize) -> bool {
        let entry = self.entry(slot).unwrap();
        entry.record.kind == Kind::Cname
            && match &entry.target {
                None => true,
                Some(CnameTarget::Dynamic(id)) => self.get(*id).is_none(),
                Some(CnameTarget::Local(target)) => target
                    .lease_generation
                    .is_some_and(|generation| generation != self.lease_generation),
            }
    }

    fn invalid(&self, slot: usize, now: i64) -> bool {
        let entry = self.entry(slot).unwrap();
        self.policy.expired(entry.expires, now)
            || (entry.record.kind == Kind::Cname && self.outdated_cname(slot))
    }

    fn remove(&mut self, slot: usize) {
        self.reverse_chain.retain(|&entry| entry != slot);
        let key = self.entry(slot).unwrap().record.name.canonical_wire();
        let indices = self.names_for_mut(&key).unwrap();
        indices.remove(slot);
        if indices.is_empty() {
            self.names_shard_mut(&key).remove(key.as_slice());
        }
        self.unlink(slot);
        self.free(slot);
    }

    fn free(&mut self, slot: usize) {
        let entry = self.entry_mut(slot).take().unwrap();
        self.long_names -= usize::from(entry.record.name.dnsmasq_bytes_len() >= 75);
        self.slots[slot].prev = self.tail.map(slot_link);
        self.slots[slot].next = None;
        if let Some(tail) = self.tail {
            self.slots[tail].next = Some(slot_link(slot));
        } else {
            self.head = Some(slot);
        }
        self.tail = Some(slot);
    }

    fn unlink(&mut self, slot: usize) {
        let prev = slot_index(self.slots[slot].prev);
        let next = slot_index(self.slots[slot].next);
        if let Some(prev) = prev {
            self.slots[prev].next = next.map(slot_link);
        } else {
            self.head = next;
        }
        if let Some(next) = next {
            self.slots[next].prev = prev.map(slot_link);
        } else {
            self.tail = prev;
        }
        self.slots[slot].prev = None;
        self.slots[slot].next = None;
    }

    fn link_head(&mut self, slot: usize) {
        self.slots[slot].next = self.head.map(slot_link);
        self.slots[slot].prev = None;
        if let Some(head) = self.head {
            self.slots[head].prev = Some(slot_link(slot));
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);
    }
}

/// extract_addresses clips only matching IN Answer records. Reverse PTR first
/// scans matching PTRs; otherwise each CNAME target restarts the ordinary scan.
/// The owner calls this for admitted upstream packets, after doctor and before
/// filtering/client limits. Local records and Authority/Additional TTLs stay
/// on their independent C paths. Preserve original full RCODE after OPT strip.
pub fn clip_live_reply_ttls(
    packet: &mut [u8],
    maximum: u64,
    original_rcode: u16,
) -> Result<(), super::wire::WireError> {
    use super::wire::{decode_name, Header, Question, RecordRef};
    if maximum == 0 {
        return Ok(());
    }
    let header = Header::parse(packet)?;
    if header.questions != 1
        || header.opcode() != 0
        || !matches!(original_rcode, 0 | 3)
        || header.flags & 0x200 != 0
    {
        return Ok(());
    }
    let question = Question::parse(packet, 12)?;
    if question.class != 1 {
        return Ok(());
    }
    let clip = |packet: &mut [u8], fixed: usize, ttl: u32| {
        if u64::from(ttl) > maximum {
            packet[fixed + 4..fixed + 8].copy_from_slice(&(maximum as u32).to_be_bytes());
        }
    };
    if question.qtype == 12
        && header.rcode() != 3
        && super::local::arpa_address(&question.name.dnsmasq_bytes()).is_some()
    {
        let mut found = false;
        let mut at = question.end;
        for _ in 0..header.answers {
            let rr = RecordRef::parse(packet, at)?;
            at = rr.end;
            if rr.class == 1 && rr.rrtype == 12 && rr.name()?.eq_ignore_ascii_case(&question.name) {
                let (fixed, ttl) = (rr.fixed, rr.ttl);
                clip(packet, fixed, ttl);
                found = true;
            }
        }
        if found {
            return Ok(());
        }
    }
    let mut current = question.name;
    let mut remaining = 10;
    'cname: loop {
        let mut at = question.end;
        for _ in 0..header.answers {
            let rr = RecordRef::parse(packet, at)?;
            at = rr.end;
            if rr.class != 1 || !rr.name()?.eq_ignore_ascii_case(&current) {
                continue;
            }
            let (fixed, ttl, kind) = (rr.fixed, rr.ttl, rr.rrtype);
            clip(packet, fixed, ttl);
            if kind == 5 {
                if remaining == 0 {
                    return Ok(());
                }
                remaining -= 1;
                let (target, _) = decode_name(packet, fixed + 10, 0)?;
                if question.qtype != 5 {
                    current = target;
                    continue 'cname;
                }
            }
        }
        return Ok(());
    }
}

impl PublicationCache for Cache {
    fn first_lease_entry(&mut self) {
        self.lease_generation = self
            .lease_generation
            .checked_add(1)
            .expect("lease cache identity exhausted");
    }

    fn prepare_name(&mut self, publication: ForwardPublication<'_>) {
        let Ok(name) = Name::from_dotted_bytes(publication.name) else {
            return;
        };
        // cache_find_by_name promotes all matching dynamic entries before
        // cache_add_dhcp_entry selects the first one (the last hash match).
        // Time zero is intentional: lease publication is not an expiry tick.
        let hits = self.lookup(&name, &[Kind::Ipv4, Kind::Cname], 0, false);
        let Some(trigger) = hits.first().and_then(|id| self.get(*id)) else {
            return;
        };
        let trigger = trigger.record.kind;
        let key = name.canonical_wire();

        #[derive(Clone, Copy)]
        struct Row {
            slot: Option<usize>,
            kind: Kind,
            flags: u8,
        }
        let blocker = |entry: &super::lease_names::PublicationBlocker| Row {
            slot: None,
            kind: match entry.kind {
                BlockerKind::Ipv4 => Kind::Ipv4,
                BlockerKind::Ipv6 => Kind::Ipv6,
                BlockerKind::Cname => Kind::Cname,
            },
            flags: u8::from(entry.reverse) | (u8::from(entry.immortal) << 1),
        };
        // Existing dynamic entries are mortal/non-reverse. Publication adds
        // prior DHCP names afterward in that same group; static immortal
        // non-reverse entries follow it, and all reverse owners precede it.
        let mut rows: Vec<_> = publication
            .blockers
            .iter()
            .filter(|b| b.reverse)
            .map(blocker)
            .collect();
        rows.extend(self.names_for(&key).into_iter().flatten().map(|&slot| Row {
            slot: Some(slot),
            kind: self.entry(slot).unwrap().record.kind,
            flags: 0,
        }));
        for immortal in [false, true] {
            rows.extend(
                publication
                    .blockers
                    .iter()
                    .filter(|b| !b.reverse && b.immortal == immortal)
                    .map(blocker),
            );
        }
        let matches = |row: &Row| matches!(row.kind, Kind::Ipv4 | Kind::Cname);
        if !publication.no_round_robin {
            if let Some(first) = rows.iter().position(matches) {
                let moves = |row: &Row| matches(row) && row.flags == rows[first].flags;
                let mut rotated = Vec::with_capacity(rows.len());
                rotated.extend_from_slice(&rows[..first]);
                rotated.extend(rows[first + 1..].iter().filter(|row| moves(row)));
                rotated.push(rows[first]);
                rotated.extend(rows[first + 1..].iter().filter(|row| !moves(row)));
                rows = rotated;
            }
        }
        // A protected RRset still observes the lookup's rotation. A mortal
        // DHCP blocker can itself move before the first dynamic match and
        // stop deletion partway through this order.
        *self.names_for_mut(&key).unwrap() = rows.iter().filter_map(|row| row.slot).collect();
        for row in rows {
            if trigger.conflicts(row.kind) {
                if let Some(slot) = row.slot {
                    self.remove(slot);
                } else {
                    break;
                }
            }
        }
    }

    fn reverse_owned(&mut self, address: std::net::Ipv4Addr) -> bool {
        // cache_add_dhcp_entry does not apply expiry at this ownership probe.
        self.reverse_chain.iter().any(|&slot| {
            let entry = self.entry(slot).unwrap();
            entry.record.kind == Kind::ReverseIpv4 && entry.record.data == address.octets()
        })
    }
}

fn reverse_key(address: IpAddr) -> (Kind, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (Kind::ReverseIpv4, address.octets().to_vec()),
        IpAddr::V6(address) => (Kind::ReverseIpv6, address.octets().to_vec()),
    }
}

/// cache.c hashes names through the first four type/name pointer rows of
/// typestr. Pointer bytes vary with the executable and ASLR; preserve its
/// mixing algorithm and bucket/chain invariant using this executable's rows.
fn reverse_bucket(name: &Name, capacity: usize) -> usize {
    crate::hosts::name_hash_bucket(&name.dnsmasq_bytes(), capacity)
}

fn reverse_name(address: IpAddr) -> Name {
    let dotted = match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(address) => {
            address
                .octets()
                .iter()
                .rev()
                .flat_map(|byte| [byte & 0x0f, byte >> 4])
                .map(|nibble| format!("{nibble:x}"))
                .collect::<Vec<_>>()
                .join(".")
                + ".ip6.arpa"
        }
    };
    Name::from_ascii(&dotted).expect("IP reverse name is always valid")
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cache_transfer_tests.rs"]
mod transfer_tests;
