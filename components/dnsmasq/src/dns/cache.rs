//! Dynamic forward-cache primitives traced to dnsmasq 2.93 cache.c.
//!
//! This module does not decide whether an upstream packet is cacheable, extract
//! SOA metadata, or store local hosts/leases. Callers must perform those checks.
//! The insertion transaction intentionally preserves C's failure behavior:
//! removals take effect immediately, but new entries become visible at commit.

use super::wire::Name;
use std::collections::HashMap;

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

#[derive(Debug)]
pub struct Record {
    pub name: Name,
    pub kind: Kind,
    pub negative: bool,
    /// Canonical uncompressed RDATA, or caller-owned negative SOA metadata.
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct Entry {
    pub record: Record,
    pub expires: i64,
    target: Option<EntryId>,
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

    pub fn cname_target(&self) -> Option<EntryId> {
        self.target
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
}

struct Slot {
    entry: Option<Entry>,
    generation: u64,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Fixed number of records, with an index per name and an intrusive LRU of slot
/// indices. Pending inserts are outside the LRU and invisible to lookups.
/// Capacity is measured in records, including CNAME and negative records.
pub struct Cache {
    policy: Policy,
    slots: Vec<Slot>,
    names: HashMap<Vec<u8>, Vec<usize>>,
    head: Option<usize>,
    tail: Option<usize>,
    pending: Vec<usize>,
    failed: bool,
    long_names: usize,
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
        }
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    pub fn get(&self, id: EntryId) -> Option<&Entry> {
        self.slots
            .get(id.slot)
            .filter(|slot| slot.generation == id.generation)?
            .entry
            .as_ref()
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

    pub fn insert(&mut self, record: Record, now: i64, ttl: u32) -> Result<EntryId, InsertError> {
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
        if !record.negative {
            return Err(InsertError::NotNegative);
        }
        let ttl = soa_ttl.or((configured_ttl != 0).then_some(configured_ttl));
        let Some(ttl) = ttl else {
            return Ok(None);
        };
        self.insert(record, now, ttl).map(Some)
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
        self.slots[cname.slot].entry.as_mut().unwrap().target = Some(target);
        true
    }

    pub fn commit(&mut self) -> bool {
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
        }
        true
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
        entry.record.kind == Kind::Cname && entry.target.is_none_or(|id| self.get(id).is_none())
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

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
