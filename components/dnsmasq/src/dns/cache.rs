//! Dynamic forward-cache primitives traced to dnsmasq 2.93 cache.c.
//!
//! This module does not decide whether an upstream packet is cacheable, extract
//! SOA metadata, or store local hosts/leases. Callers must perform those checks.
//! The insertion transaction intentionally preserves C's failure behavior:
//! removals take effect immediately, but new entries become visible at commit.

use super::lease_names::{BlockerKind, ForwardPublication, PublicationCache};
use super::wire::Name;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ipv4,
    Ipv6,
    Generic(u16),
    Cname,
    NxDomain,
}

impl Kind {
    fn conflicts(self, other: Self) -> bool {
        self == other || self == Self::Cname || other == Self::Cname
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

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub max_reply_ttl: u32,
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
    pub fn cache_ttl(self, ttl: u32) -> u32 {
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
    pub record: Record,
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
            ttl.min(policy.max_reply_ttl)
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
    pub(super) records: Vec<TransferredRecord>,
}

#[derive(Debug)]
pub(super) struct TransferredRecord {
    pub(super) record: Record,
    pub(super) expires: i64,
    pub(super) authority_name: Option<Name>,
}

/// Current parent local-name match at cache_scan_free's existing boundary.
/// The caller supplies its usual hosts/lease/configured-CNAME precedence.
#[derive(Clone, Copy, Debug)]
pub struct LocalCacheMatch {
    pub same_address: bool,
    pub from_lease: bool,
}

#[derive(Clone)]
struct Slot {
    entry: Option<Entry>,
    generation: u64,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Fixed number of records, with an index per name and an intrusive LRU of slot
/// indices. Pending inserts are outside the LRU and invisible to lookups.
/// Capacity is measured in records, including CNAME and negative records.
// PRIVATE TCP correctness reference only; not a product representation.
#[derive(Clone)]
pub struct Cache {
    policy: Policy,
    slots: Vec<Slot>,
    names: HashMap<Vec<u8>, Vec<usize>>,
    head: Option<usize>,
    tail: Option<usize>,
    pending: Vec<usize>,
    failed: bool,
    long_names: usize,
    lease_generation: u64,
}

impl Cache {
    pub fn new(capacity: usize, mut policy: Policy) -> Self {
        // C represents a zero stale allowance as the option being disabled.
        if policy.stale == StalePolicy::Seconds(0) {
            policy.stale = StalePolicy::Disabled;
        }
        Self {
            policy,
            slots: (0..capacity)
                .map(|i| Slot {
                    entry: None,
                    generation: 0,
                    prev: i.checked_sub(1),
                    next: (i + 1 < capacity).then_some(i + 1),
                })
                .collect(),
            names: HashMap::new(),
            head: (capacity > 0).then_some(0),
            tail: capacity.checked_sub(1),
            pending: Vec::new(),
            failed: false,
            long_names: 0,
            lease_generation: 0,
        }
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Drop all forwarded records, including an unfinished insertion, on
    /// SIGHUP (`cache.c::cache_reload`). Local hosts and DHCP names are owned
    /// separately. Keep the allocation and generations so old handles cannot
    /// become valid again when the empty slots are reused.
    pub fn clear(&mut self) {
        let capacity = self.slots.len();
        for (index, slot) in self.slots.iter_mut().enumerate() {
            slot.entry = None;
            slot.prev = index.checked_sub(1);
            slot.next = (index + 1 < capacity).then_some(index + 1);
        }
        self.names.clear();
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
            .filter(|slot| slot.generation == id.generation)?
            .entry
            .as_ref()
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
        slot.generation == id.generation && slot.entry.is_some() && !self.invalid(id.slot, now)
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
        ttl: u32,
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
        if self.failed {
            return Err(InsertError::PreviousFailure);
        }
        let ttl = self.policy.cache_ttl(ttl);
        if ttl == 0 && self.policy.stale == StalePolicy::Disabled {
            return self.fail(InsertError::ZeroTtl);
        }
        let Some(expires) = now.checked_add(i64::from(ttl)) else {
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
        if let Some(indices) = self.names.get(&key).cloned() {
            for slot in indices {
                let entry = self.slots[slot].entry.as_ref().unwrap();
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
            if self
                .tail
                .is_some_and(|slot| self.slots[slot].entry.is_some())
            {
                // Same pressure trigger as C: reclaim expired entries globally
                // before spilling any live entry. The scan is a baseline cost.
                for slot in 0..self.slots.len() {
                    if self.slots[slot].entry.as_ref().is_some_and(|entry| {
                        entry.committed && self.policy.expired(entry.expires, now)
                    }) {
                        self.remove(slot);
                    }
                }
            }
            let Some(mut slot) = self.tail else {
                return self.fail(InsertError::Full);
            };
            if let Some(entry) = &self.slots[slot].entry {
                if now < entry.expires {
                    counters.live_freed = counters.live_freed.wrapping_add(1);
                }
                let victim_key = entry.record.name.canonical_wire();
                let victim_kind = entry.record.kind;
                // C spills the conflicting RRset, not only its oldest member.
                for victim in self.names.get(&victim_key).cloned().unwrap_or_default() {
                    if victim_kind.conflicts(self.slots[victim].entry.as_ref().unwrap().record.kind)
                        || self.invalid(victim, now)
                    {
                        self.remove(victim);
                    }
                }
                slot = self.tail.expect("spilling a committed entry frees a slot");
            }
            slot
        };
        let long = record.name.dnsmasq_bytes().len() >= 75;
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
        self.slots[slot].entry = Some(Entry {
            record,
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
        configured_ttl: u32,
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
        configured_ttl: u32,
        counters: &mut CacheCounters,
    ) -> Result<Option<EntryId>, InsertError> {
        if !record.negative {
            return Err(InsertError::NotNegative);
        }
        let ttl = soa_ttl.or((configured_ttl != 0).then_some(configured_ttl));
        let Some(ttl) = ttl else {
            return Ok(None);
        };
        self.insert_counted(record, now, ttl, counters).map(Some)
    }

    /// Attach the owner of the independent SOA used for a negative answer.
    /// Keeping only the owner lets later SOA replacement/reuse be observed by
    /// lookup, as in `cache.c::find_soa`; the authority itself consumes a
    /// normal cache slot.
    pub fn set_negative_authority(&mut self, negative: EntryId, authority: Name) -> bool {
        let Some(entry) = self
            .slots
            .get_mut(negative.slot)
            .filter(|slot| slot.generation == negative.generation)
            .and_then(|slot| slot.entry.as_mut())
        else {
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
        self.slots[target.slot].entry.as_mut().unwrap().referenced = true;
        self.slots[cname.slot].entry.as_mut().unwrap().target = Some(CnameTarget::Dynamic(target));
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
        self.slots[cname.slot].entry.as_mut().unwrap().target = Some(CnameTarget::Local(target));
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
            let entry = self.slots[slot].entry.as_mut().unwrap();
            entry.committed = true;
            self.names
                .entry(entry.record.name.canonical_wire())
                .or_default()
                .push(slot);
            self.link_head(slot);
            counters.inserted = counters.inserted.wrapping_add(1);
            if let Some(records) = &mut capture {
                let entry = self.slots[slot].entry.as_ref().unwrap();
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
    /// `local_match` is a read-only lookup using the caller's existing local
    /// precedence; it must not use the child's old local-name generation.
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
            let inserted = if let Some(local) = local_match(&record) {
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
        let key = name.canonical_wire();
        let mut found = Vec::new();
        for slot in self.names.get(&key).cloned().unwrap_or_default() {
            if self.invalid(slot, now) {
                self.remove(slot);
            } else if kinds.iter().any(|kind| {
                self.slots[slot]
                    .entry
                    .as_ref()
                    .unwrap()
                    .record
                    .kind
                    .matches(*kind)
            }) {
                self.unlink(slot);
                self.link_head(slot);
                found.push(slot);
            }
        }
        if round_robin && found.len() > 1 {
            // Move subsequent matching entries before the first match, leaving
            // unrelated kinds in their positions relative to that first match.
            let entries = self.names.get_mut(&key).unwrap();
            for &slot in &found[1..] {
                entries.retain(|index| *index != slot);
            }
            let at = entries.iter().position(|index| *index == found[0]).unwrap();
            entries.splice(at..at, found[1..].iter().copied());
        }
        found.into_iter().rev().map(|slot| self.id(slot)).collect()
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

    fn id(&self, slot: usize) -> EntryId {
        EntryId {
            slot,
            generation: self.slots[slot].generation,
        }
    }

    fn outdated_cname(&self, slot: usize) -> bool {
        let entry = self.slots[slot].entry.as_ref().unwrap();
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
        self.policy
            .expired(self.slots[slot].entry.as_ref().unwrap().expires, now)
            || self.outdated_cname(slot)
    }

    fn remove(&mut self, slot: usize) {
        let key = self.slots[slot]
            .entry
            .as_ref()
            .unwrap()
            .record
            .name
            .canonical_wire();
        let indices = self.names.get_mut(&key).unwrap();
        indices.retain(|index| *index != slot);
        if indices.is_empty() {
            self.names.remove(&key);
        }
        self.unlink(slot);
        self.free(slot);
    }

    fn free(&mut self, slot: usize) {
        let entry = self.slots[slot].entry.take().unwrap();
        self.long_names -= usize::from(entry.record.name.dnsmasq_bytes().len() >= 75);
        self.slots[slot].prev = self.tail;
        self.slots[slot].next = None;
        if let Some(tail) = self.tail {
            self.slots[tail].next = Some(slot);
        } else {
            self.head = Some(slot);
        }
        self.tail = Some(slot);
    }

    fn unlink(&mut self, slot: usize) {
        let prev = self.slots[slot].prev;
        let next = self.slots[slot].next;
        if let Some(prev) = prev {
            self.slots[prev].next = next;
        } else {
            self.head = next;
        }
        if let Some(next) = next {
            self.slots[next].prev = prev;
        } else {
            self.tail = prev;
        }
        self.slots[slot].prev = None;
        self.slots[slot].next = None;
    }

    fn link_head(&mut self, slot: usize) {
        self.slots[slot].next = self.head;
        self.slots[slot].prev = None;
        if let Some(head) = self.head {
            self.slots[head].prev = Some(slot);
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);
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
        rows.extend(self.names[&key].iter().map(|&slot| Row {
            slot: Some(slot),
            kind: self.slots[slot].entry.as_ref().unwrap().record.kind,
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
        *self.names.get_mut(&key).unwrap() = rows.iter().filter_map(|row| row.slot).collect();
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

    fn reverse_owned(&mut self, _: std::net::Ipv4Addr) -> bool {
        // This forward-only cache does not admit upstream PTR/reverse entries.
        // Reverse-cache ownership must be implemented with that capability.
        false
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cache_transfer_tests.rs"]
mod transfer_tests;
