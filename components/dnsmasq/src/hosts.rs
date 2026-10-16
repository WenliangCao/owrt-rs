//! Local hosts ingestion, traced to cache.c:1322–1545 and util.c:135–295.
//! The hosts/config generation is separate from dynamic DNS and DHCP records;
//! reloading it cannot accidentally discard leases.

use std::collections::{HashMap, HashSet, TryReserveError};
use std::io::Read;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;

/// Exact no-IDN check_name/canonicalise behavior. Preserve case, strip one
/// trailing dot, allow printable ASCII (including internal empty labels).
pub fn canonicalise(input: &[u8]) -> Option<Vec<u8>> {
    try_copy(canonical_name(input)?).ok()
}

/// Hosts-file growth must follow C whine_malloc: allocation failure skips the
/// affected record instead of invoking Rust's aborting allocation handler.
pub fn try_copy<T: Copy>(input: &[T]) -> Result<Vec<T>, TryReserveError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(input.len())?;
    copy.extend_from_slice(input);
    Ok(copy)
}

fn canonical_name(input: &[u8]) -> Option<&[u8]> {
    let input = input.split(|&b| b == 0).next()?;
    if input.is_empty() {
        return None;
    }
    let trailing_dot = input.last() == Some(&b'.');
    let input = if trailing_dot {
        &input[..input.len() - 1]
    } else {
        input
    };
    let mut label = 0;
    let mut wire = 0;
    let mut nonwhite = trailing_dot;
    for &byte in input {
        if byte == b'.' {
            wire += label + 1;
            label = 0;
        } else {
            label += 1;
            if label > 63 || !byte.is_ascii() || byte.is_ascii_control() {
                return None;
            }
            nonwhite |= byte != b' ';
        }
    }
    (nonwhite && wire + label + 2 <= 255).then_some(input)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Host {
    pub name: Vec<u8>,
    pub address: IpAddr,
    pub ttl: u32,
    pub source: u32,
    pub configured: bool,
    pub reverse: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadStats {
    /// C names_done counts accepted names even if add_hosts_entry deduplicates.
    pub accepted: usize,
    pub inserted: usize,
    pub bad_addresses: usize,
    pub bad_names: usize,
    /// The caller must discard an incomplete replacement before logging or
    /// publishing it, so the failed load releases its memory first.
    pub allocation_failed: bool,
}

/// Owned during ingestion, shared only when a TCP child takes a snapshot.
/// Keeping an owned empty value avoids adding infallible allocations to the
/// fallible hosts loader. Publishing a TCP snapshot performs one allocation.
#[derive(Clone)]
enum Snapshot<T> {
    Owned(T),
    Shared(Arc<T>),
}

impl<T: Default> Default for Snapshot<T> {
    fn default() -> Self {
        Self::Owned(T::default())
    }
}

impl<T> Deref for Snapshot<T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Self::Owned(value) => value,
            Self::Shared(value) => value,
        }
    }
}

impl<T: Default> Snapshot<T> {
    fn snapshot(&mut self) -> Self {
        if let Self::Owned(value) = self {
            *self = Self::Shared(Arc::new(std::mem::take(value)));
        }
        match self {
            Self::Shared(value) => Self::Shared(Arc::clone(value)),
            Self::Owned(_) => unreachable!(),
        }
    }

    fn get_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Owned(value) => Some(value),
            Self::Shared(value) => Arc::get_mut(value),
        }
    }
}

#[derive(Clone, Default)]
struct HostsRecords {
    entries: Vec<Host>,
    sources: HashMap<u32, Vec<u8>>,
    // Existence needs only a count; individual records and answer order live
    // in HashOrder. Avoid allocating an index vector for each distinct name.
    forward: HashMap<Vec<u8>, usize>,
    reverse: HashMap<IpAddr, usize>,
    // Most addresses have one owner. Allocate another list only when C's
    // bulk reverse chain gives the same address additional F_REVERSE records.
    reverse_extra: HashMap<IpAddr, Vec<usize>>,
    name_hash_capacity: usize,
    non_terminals: HashSet<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BulkLink {
    Host(usize),
    Lease(usize),
    End,
}

#[derive(Clone)]
struct BulkLease {
    name: Vec<u8>,
    address: IpAddr,
    reverse: bool,
    immortal: bool,
    next: BulkLink,
}

fn name_hash_size(capacity: usize) -> usize {
    let mut size = 64usize;
    while size < capacity / 10 {
        size *= 2;
    }
    size
}

/// cache.c's per-process typestr mixer, also used by the dynamic cache.
/// Pointer bytes differ across executables/ASLR; do not hardcode an Oracle seed.
pub(crate) fn name_hash_bucket(name: &[u8], capacity: usize) -> usize {
    let mut mixer = [0u8; 64];
    for (index, label) in [b"A\0".as_slice(), b"NS\0", b"MD\0", b"MF\0"]
        .iter()
        .enumerate()
    {
        mixer[index * 16..index * 16 + 4].copy_from_slice(&((index + 1) as u32).to_le_bytes());
        mixer[index * 16 + 8..index * 16 + 16]
            .copy_from_slice(&(label.as_ptr() as u64).to_le_bytes());
    }
    let mut value = 0o17465u32;
    for byte in name {
        let byte = byte.to_ascii_lowercase();
        value = value.rotate_left(7).wrapping_add(u32::from(
            mixer[(value.wrapping_add(u32::from(byte)) & 63) as usize] ^ byte,
        ));
    }
    ((value ^ (value >> 16)) as usize) & (name_hash_size(capacity) - 1)
}

/// cache_reload borrows one packet buffer for an address hash spanning all
/// bulk inputs. Its links are also overwritten by duplicate-name lookup.
/// This state belongs to the loader, never to a published TCP snapshot.
#[derive(Clone)]
struct BulkReverse {
    active: bool,
    buckets: Vec<BulkLink>,
    next: Vec<BulkLink>,
    leases: Vec<BulkLease>,
    name_count: usize,
    rehash_checkpoint: usize,
}

impl BulkReverse {
    fn new(packet_size: usize, cache_size: usize) -> Result<Self, TryReserveError> {
        let count = (packet_size / std::mem::size_of::<usize>()).max(1);
        let mut buckets = Vec::new();
        buckets.try_reserve_exact(count)?;
        buckets.resize(count, BulkLink::End);
        Ok(Self {
            active: true,
            buckets,
            next: Vec::new(),
            leases: Vec::new(),
            name_count: cache_size,
            rehash_checkpoint: cache_size,
        })
    }

    fn try_clone(&self) -> Result<Self, TryReserveError> {
        let mut leases = Vec::new();
        leases.try_reserve_exact(self.leases.len())?;
        for lease in &self.leases {
            leases.push(BulkLease {
                name: try_copy(&lease.name)?,
                address: lease.address,
                reverse: lease.reverse,
                immortal: lease.immortal,
                next: lease.next,
            });
        }
        Ok(Self {
            active: self.active,
            buckets: try_copy(&self.buckets)?,
            next: try_copy(&self.next)?,
            leases,
            name_count: self.name_count,
            rehash_checkpoint: self.rehash_checkpoint,
        })
    }

    fn bucket(&self, address: IpAddr) -> usize {
        let hash = |bytes: &[u8]| {
            bytes.iter().fold(0, |value, byte| {
                (value * 2 + usize::from(*byte)) % self.buckets.len()
            })
        };
        match address {
            IpAddr::V4(address) => hash(&address.octets()),
            IpAddr::V6(address) => hash(&address.octets()),
        }
    }

    fn set_next(next: &mut [BulkLink], leases: &mut [BulkLease], from: BulkLink, to: BulkLink) {
        match from {
            BulkLink::Host(id) => next[id] = to,
            BulkLink::Lease(id) => leases[id].next = to,
            BulkLink::End => (),
        }
    }

    fn next_link(&self, link: BulkLink) -> BulkLink {
        match link {
            BulkLink::Host(id) => self.next[id],
            BulkLink::Lease(id) => self.leases[id].next,
            BulkLink::End => BulkLink::End,
        }
    }

    fn lookup_name(&mut self, nodes: &[usize]) {
        let mut previous = BulkLink::End;
        for &node in nodes {
            let link = if node < self.leases.len() {
                BulkLink::Lease(node)
            } else {
                BulkLink::Host(node - self.leases.len())
            };
            Self::set_next(&mut self.next, &mut self.leases, previous, link);
            previous = link;
        }
        Self::set_next(&mut self.next, &mut self.leases, previous, BulkLink::End);
    }

    fn contains(&self, address: IpAddr, entries: &[Host]) -> bool {
        let mut id = self.buckets[self.bucket(address)];
        while id != BulkLink::End {
            let found = match id {
                BulkLink::Host(id) => entries[id].address,
                BulkLink::Lease(id) => self.leases[id].address,
                BulkLink::End => unreachable!(),
            };
            if found == address {
                return true;
            }
            id = self.next_link(id);
        }
        false
    }

    fn push(&mut self, address: IpAddr, reverse: bool) {
        let bucket = self.bucket(address);
        let id = self.next.len();
        self.next.push(if reverse {
            self.buckets[bucket]
        } else {
            BulkLink::End
        });
        if reverse {
            self.buckets[bucket] = BulkLink::Host(id);
        }
    }

    fn try_remap(&self, relocated: &[Option<usize>]) -> Result<Self, TryReserveError> {
        if !self.active {
            return self.try_clone();
        }
        let remap = |mut link: BulkLink| {
            while let BulkLink::Host(id) = link {
                if let Some(new) = relocated[id] {
                    return BulkLink::Host(new);
                }
                link = self.next[id];
            }
            link
        };
        let mut next = Vec::new();
        next.try_reserve_exact(relocated.iter().filter(|id| id.is_some()).count())?;
        for (old, new) in relocated.iter().enumerate() {
            if new.is_some() {
                next.push(remap(self.next[old]));
            }
        }
        let mut buckets = Vec::new();
        buckets.try_reserve_exact(self.buckets.len())?;
        buckets.extend(self.buckets.iter().map(|&id| remap(id)));
        let mut result = self.try_clone()?;
        result.buckets = buckets;
        result.next = next;
        for lease in &mut result.leases {
            lease.next = remap(lease.next);
        }
        Ok(result)
    }
}

// Both next links and bucket heads use bounded, independent copy-on-write
// pages. There are no query histories, registries or per-client table copies.
const ROTATION_PAGE_ENTRIES: usize = 64;
const CHAIN_END: usize = usize::MAX;

#[derive(Clone, Default)]
struct LinkPages {
    pages: Vec<Snapshot<Vec<usize>>>,
    len: usize,
}

impl LinkPages {
    fn with_len(len: usize) -> Result<Self, TryReserveError> {
        let mut result = Self::default();
        result.resize(len)?;
        Ok(result)
    }

    fn resize(&mut self, len: usize) -> Result<(), TryReserveError> {
        let count = len.div_ceil(ROTATION_PAGE_ENTRIES);
        self.pages
            .try_reserve(count.saturating_sub(self.pages.len()))?;
        while self.pages.len() < count {
            let mut page = Vec::new();
            page.try_reserve_exact(ROTATION_PAGE_ENTRIES)?;
            page.resize(ROTATION_PAGE_ENTRIES, CHAIN_END);
            self.pages.push(Snapshot::Owned(page));
        }
        self.pages.truncate(count);
        self.len = len;
        Ok(())
    }

    fn get(&self, id: usize) -> usize {
        self.pages[id / ROTATION_PAGE_ENTRIES][id % ROTATION_PAGE_ENTRIES]
    }

    fn prepare(&mut self, id: usize) -> Result<(), TryReserveError> {
        let page = &mut self.pages[id / ROTATION_PAGE_ENTRIES];
        if page.get_mut().is_none() {
            *page = Snapshot::Owned(try_copy(page)?);
        }
        Ok(())
    }

    fn set(&mut self, id: usize, value: usize) {
        self.pages[id / ROTATION_PAGE_ENTRIES].get_mut().unwrap()[id % ROTATION_PAGE_ENTRIES] =
            value;
    }

    fn snapshot(&mut self) -> Self {
        Self {
            pages: self.pages.iter_mut().map(Snapshot::snapshot).collect(),
            len: self.len,
        }
    }

    fn try_clone(&self) -> Result<Self, TryReserveError> {
        let mut pages = Vec::new();
        pages.try_reserve_exact(self.pages.len())?;
        for page in &self.pages {
            pages.push(Snapshot::Owned(try_copy(page)?));
        }
        Ok(Self {
            pages,
            len: self.len,
        })
    }
}

#[derive(Clone, Default)]
struct HashOrder {
    heads: LinkPages,
    next: LinkPages,
}

struct Chain<'a> {
    links: &'a LinkPages,
    next: usize,
}
impl Iterator for Chain<'_> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        if self.next == CHAIN_END {
            return None;
        }
        let id = self.next;
        self.next = self.links.get(id);
        Some(id)
    }
}

struct HashRecord<'a> {
    name: &'a [u8],
    address: IpAddr,
    reverse: bool,
    immortal: bool,
}
fn hash_record<'a>(id: usize, entries: &'a [Host], leases: &'a [BulkLease]) -> HashRecord<'a> {
    if id < leases.len() {
        let lease = &leases[id];
        HashRecord {
            name: &lease.name,
            address: lease.address,
            reverse: lease.reverse,
            immortal: lease.immortal,
        }
    } else {
        let host = &entries[id - leases.len()];
        HashRecord {
            name: &host.name,
            address: host.address,
            reverse: host.reverse,
            immortal: true,
        }
    }
}

impl HashOrder {
    fn first_reverse(
        &self,
        address: IpAddr,
        entries: &[Host],
        leases: &[BulkLease],
    ) -> Option<usize> {
        for bucket in 0..self.heads.len {
            for node in self.bucket(bucket) {
                let record = hash_record(node, entries, leases);
                if !record.reverse {
                    break;
                }
                if record.address == address {
                    return Some(node);
                }
            }
        }
        None
    }

    fn bucket(&self, bucket: usize) -> Chain<'_> {
        Chain {
            links: &self.next,
            next: if self.heads.len == 0 {
                CHAIN_END
            } else {
                self.heads.get(bucket)
            },
        }
    }

    fn snapshot(&mut self) -> Self {
        Self {
            heads: self.heads.snapshot(),
            next: self.next.snapshot(),
        }
    }

    fn try_clone(&self) -> Result<Self, TryReserveError> {
        Ok(Self {
            heads: self.heads.try_clone()?,
            next: self.next.try_clone()?,
        })
    }

    fn prepare_insert(
        &mut self,
        host: HashRecord<'_>,
        entries: &[Host],
        leases: &[BulkLease],
        capacity: usize,
    ) -> Result<(usize, usize, usize), TryReserveError> {
        let id = self.next.len;
        self.prepare_insert_at(id, host, entries, leases, capacity)
    }

    fn prepare_insert_at(
        &mut self,
        id: usize,
        host: HashRecord<'_>,
        entries: &[Host],
        leases: &[BulkLease],
        capacity: usize,
    ) -> Result<(usize, usize, usize), TryReserveError> {
        let bucket = name_hash_bucket(host.name, capacity);
        if self.heads.len == 0 {
            self.heads.resize(name_hash_size(capacity))?;
        }
        let old_len = self.next.len;
        self.next.resize(old_len.max(id + 1))?;
        let mut previous = CHAIN_END;
        let mut current = self.heads.get(bucket);
        if !host.reverse {
            while current != CHAIN_END && hash_record(current, entries, leases).reverse {
                previous = current;
                current = self.next.get(current);
            }
            if host.immortal {
                while current != CHAIN_END && !hash_record(current, entries, leases).immortal {
                    previous = current;
                    current = self.next.get(current);
                }
            }
        }
        while current != CHAIN_END {
            let old = hash_record(current, entries, leases);
            if (old.reverse, old.immortal) != (host.reverse, host.immortal)
                || !old.name.eq_ignore_ascii_case(host.name)
            {
                break;
            }
            previous = current;
            current = self.next.get(current);
        }
        let prepared = (|| {
            self.next.prepare(id)?;
            if previous == CHAIN_END {
                self.heads.prepare(bucket)?;
            } else {
                self.next.prepare(previous)?;
            }
            Ok::<(), TryReserveError>(())
        })();
        if let Err(error) = prepared {
            self.next.len = old_len;
            return Err(error);
        }
        Ok((bucket, previous, current))
    }

    fn commit_insert(&mut self, id: usize, (bucket, previous, current): (usize, usize, usize)) {
        self.next.set(id, current);
        if previous == CHAIN_END {
            self.heads.set(bucket, id);
        } else {
            self.next.set(previous, id);
        }
    }

    fn rehashed(
        &self,
        entries: &[Host],
        leases: &[BulkLease],
        capacity: usize,
    ) -> Result<Self, TryReserveError> {
        let mut result = Self {
            heads: LinkPages::with_len(name_hash_size(capacity))?,
            next: LinkPages::with_len(entries.len() + leases.len())?,
        };
        for bucket in 0..self.heads.len {
            for id in self.bucket(bucket) {
                let record = hash_record(id, entries, leases);
                let new_bucket = name_hash_bucket(record.name, capacity);
                let mut previous = CHAIN_END;
                let mut current = result.heads.get(new_bucket);
                if !record.reverse {
                    while current != CHAIN_END && hash_record(current, entries, leases).reverse {
                        previous = current;
                        current = result.next.get(current);
                    }
                    if record.immortal {
                        while current != CHAIN_END
                            && !hash_record(current, entries, leases).immortal
                        {
                            previous = current;
                            current = result.next.get(current);
                        }
                    }
                }
                while current != CHAIN_END {
                    let old = hash_record(current, entries, leases);
                    if (old.reverse, old.immortal) != (record.reverse, record.immortal)
                        || !old.name.eq_ignore_ascii_case(record.name)
                    {
                        break;
                    }
                    previous = current;
                    current = result.next.get(current);
                }
                result.commit_insert(id, (new_bucket, previous, current));
            }
        }
        Ok(result)
    }

    /// Prepare every changed page before writing any pointer. Failure leaves
    /// the old chain usable; already-private copies still contain old values.
    fn replace_bucket(&mut self, bucket: usize, ids: &[usize]) -> Result<(), TryReserveError> {
        let head = ids.first().copied().unwrap_or(CHAIN_END);
        if self.heads.get(bucket) != head {
            self.heads.prepare(bucket)?;
        }
        for (index, &id) in ids.iter().enumerate() {
            let next = ids.get(index + 1).copied().unwrap_or(CHAIN_END);
            if self.next.get(id) != next {
                self.next.prepare(id)?;
            }
        }
        if self.heads.get(bucket) != head {
            self.heads.set(bucket, head);
        }
        for (index, &id) in ids.iter().enumerate() {
            let next = ids.get(index + 1).copied().unwrap_or(CHAIN_END);
            if self.next.get(id) != next {
                self.next.set(id, next);
            }
        }
        Ok(())
    }

    fn rotate(
        &mut self,
        key: &[u8],
        ipv6: Option<bool>,
        entries: &[Host],
        leases: &[BulkLease],
        capacity: usize,
    ) -> Result<(), TryReserveError> {
        let bucket = name_hash_bucket(key, capacity);
        let matches = |id: usize| {
            let host = hash_record(id, entries, leases);
            host.name.eq_ignore_ascii_case(key)
                && ipv6.is_none_or(|family| host.address.is_ipv6() == family)
        };
        let mut ids = Vec::new();
        for id in self.bucket(bucket) {
            ids.try_reserve(1)?;
            ids.push(id);
        }
        let Some(first) = ids.iter().position(|&id| matches(id)) else {
            return Ok(());
        };
        let first_record = hash_record(ids[first], entries, leases);
        let flags = (first_record.reverse, first_record.immortal);
        let mut insertion = first;
        let mut position = first + 1;
        while position < ids.len() {
            let id = ids[position];
            let record = hash_record(id, entries, leases);
            if matches(id) && (record.reverse, record.immortal) == flags {
                ids[insertion..=position].rotate_right(1);
                insertion += 1;
            }
            position += 1;
        }
        self.replace_bucket(bucket, &ids)
    }

    fn with_lease_prefix(&self, count: usize) -> Result<Self, TryReserveError> {
        let mut result = Self {
            heads: LinkPages::with_len(self.heads.len)?,
            next: LinkPages::with_len(self.next.len + count)?,
        };
        let shift = |id| {
            if id == CHAIN_END {
                CHAIN_END
            } else {
                id + count
            }
        };
        for bucket in 0..self.heads.len {
            result.heads.set(bucket, shift(self.heads.get(bucket)));
        }
        for id in 0..self.next.len {
            result.next.set(id + count, shift(self.next.get(id)));
        }
        Ok(result)
    }

    fn remapped(
        &self,
        relocated: &[Option<usize>],
        lease_count: usize,
    ) -> Result<Self, TryReserveError> {
        let mut result = Self {
            heads: LinkPages::with_len(self.heads.len)?,
            next: LinkPages::with_len(
                lease_count + relocated.iter().filter(|id| id.is_some()).count(),
            )?,
        };
        for bucket in 0..self.heads.len {
            let mut previous = CHAIN_END;
            for old in self.bucket(bucket) {
                let mapped = if old < lease_count {
                    Some(old)
                } else {
                    relocated[old - lease_count].map(|id| id + lease_count)
                };
                if let Some(id) = mapped {
                    if previous == CHAIN_END {
                        result.heads.set(bucket, id);
                    } else {
                        result.next.set(previous, id);
                    }
                    previous = id;
                }
            }
        }
        Ok(result)
    }

    fn remove_leases(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        assert!(
            self.heads
                .pages
                .iter_mut()
                .all(|page| page.get_mut().is_some())
        );
        assert!(
            self.next
                .pages
                .iter_mut()
                .all(|page| page.get_mut().is_some())
        );
        let skip = |mut id: usize, links: &LinkPages| {
            while id != CHAIN_END && id < count {
                id = links.get(id);
            }
            if id == CHAIN_END {
                CHAIN_END
            } else {
                id - count
            }
        };
        for bucket in 0..self.heads.len {
            self.heads
                .set(bucket, skip(self.heads.get(bucket), &self.next));
        }
        let len = self.next.len - count;
        // Every source lies above its destination, so this forward compaction
        // cannot overwrite a yet-unread host link or retained lease link.
        for id in count..self.next.len {
            let next = skip(self.next.get(id), &self.next);
            self.next.set(id, next);
        }
        for id in 0..len {
            self.next.set(id, self.next.get(id + count));
        }
        self.next.len = len;
        self.next
            .pages
            .truncate(len.div_ceil(ROTATION_PAGE_ENTRIES));
    }
}

/// One reload generation. TCP children share records and 64-link order pages,
/// retaining both their accepted generation and private query order after HUP.
#[derive(Clone, Default)]
pub struct Hosts {
    records: Snapshot<HostsRecords>,
    order: HashOrder,
    no_round_robin: bool,
    bulk: Option<BulkReverse>,
}

impl Hosts {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.records.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.entries.is_empty()
    }
    pub(crate) fn is_published(&self) -> bool {
        self.bulk.is_none()
    }
    pub fn entries(&self) -> &[Host] {
        &self.records.entries
    }

    /// Start before configured records. packet_size is the entire C packet
    /// buffer, max(edns_packet_max, 512) + MAXDNAME + RRFIXEDSZ.
    pub fn begin_bulk(
        &mut self,
        packet_size: usize,
        cache_size: usize,
        minimum_hash_capacity: usize,
    ) -> Result<(), TryReserveError> {
        assert!(
            self.is_empty(),
            "bulk loading must start with a fresh generation"
        );
        let bulk = BulkReverse::new(packet_size, cache_size)?;
        self.set_name_hash_capacity(cache_size.max(minimum_hash_capacity))?;
        self.bulk = Some(bulk);
        Ok(())
    }

    /// Stop bulk address-hash ingestion before provider lookups/publication.
    /// Retained lease nodes remain in the global name chain until finish_bulk.
    pub fn seal_bulk(&mut self) {
        if let Some(bulk) = &mut self.bulk {
            bulk.active = false;
            bulk.buckets = Vec::new();
            bulk.next = Vec::new();
        }
    }

    pub fn finish_bulk(&mut self) {
        if let Some(bulk) = &self.bulk {
            self.order.remove_leases(bulk.leases.len());
        }
        self.bulk = None;
    }

    fn retained_leases(&self) -> &[BulkLease] {
        self.bulk
            .as_ref()
            .map_or(&[], |bulk| bulk.leases.as_slice())
    }

    /// Retained DHCP cache entries can appear in duplicate-name lookup while
    /// the static generation loads. They are never static published answers.
    pub fn add_bulk_lease(
        &mut self,
        name: &[u8],
        address: IpAddr,
        reverse: bool,
        immortal: bool,
    ) -> Result<(), TryReserveError> {
        let bulk = self
            .bulk
            .as_mut()
            .expect("begin_bulk must precede retained leases");
        assert!(bulk.active && self.records.entries.is_empty());
        let name = try_copy(name)?;
        bulk.leases.try_reserve(1)?;
        let plan = self.order.prepare_insert(
            HashRecord {
                name: &name,
                address,
                reverse,
                immortal,
            },
            &self.records.entries,
            &bulk.leases,
            self.records.name_hash_capacity,
        )?;
        let id = bulk.leases.len();
        bulk.leases.push(BulkLease {
            name,
            address,
            reverse,
            immortal,
            next: BulkLink::End,
        });
        self.order.commit_insert(id, plan);
        Ok(())
    }

    /// Retain C's largest name-hash table across reloads. Rehashing traverses
    /// old buckets in order and prepends reverse records to their new bucket.
    fn set_name_hash_capacity(&mut self, capacity: usize) -> Result<(), TryReserveError> {
        if name_hash_size(capacity) <= name_hash_size(self.records.name_hash_capacity) {
            return Ok(());
        }
        let order = self
            .order
            .rehashed(&self.records.entries, self.retained_leases(), capacity)?;
        self.writable_records()?.name_hash_capacity = capacity;
        self.order = order;
        Ok(())
    }

    pub fn name_hash_capacity(&self) -> usize {
        self.records.name_hash_capacity
    }

    fn advance_bulk_names(
        &mut self,
        accepted: usize,
        file_end: bool,
    ) -> Result<(), TryReserveError> {
        let Some(bulk) = self.bulk.as_mut().filter(|bulk| bulk.active) else {
            return Ok(());
        };
        bulk.name_count = bulk.name_count.saturating_add(accepted);
        let count = bulk.name_count;
        if file_end || count - bulk.rehash_checkpoint > 1000 {
            self.set_name_hash_capacity(count)?;
            self.bulk.as_mut().unwrap().rehash_checkpoint = count;
        }
        Ok(())
    }

    /// Dropping this owner cannot release records retained by a TCP snapshot.
    pub fn has_shared_records(&self) -> bool {
        matches!(&self.records, Snapshot::Shared(records) if Arc::strong_count(records) > 1)
    }

    /// Like fork's copy-on-write view: snapshot both the accepted generation
    /// and its current round-robin order without copying any hosts records.
    pub fn tcp_snapshot(&mut self) -> Self {
        assert!(
            self.bulk.is_none(),
            "TCP snapshots require a published hosts generation"
        );
        Self {
            records: self.records.snapshot(),
            order: self.order.snapshot(),
            no_round_robin: self.no_round_robin,
            bulk: None,
        }
    }

    /// Structural changes fork records and the current link order together.
    /// All copying remains fallible for hostsdir ingestion.
    fn writable_records(&mut self) -> Result<&mut HostsRecords, TryReserveError> {
        if self.records.get_mut().is_none() {
            *self = self.try_clone()?;
        }
        Ok(self.records.get_mut().unwrap())
    }

    /// Keep the loader's actual file identity beside this immutable generation.
    pub fn set_source_name(&mut self, source: u32, name: Vec<u8>) {
        let _ = self.set_source_name_checked(source, name);
    }

    pub fn set_source_name_checked(
        &mut self,
        source: u32,
        name: Vec<u8>,
    ) -> Result<(), TryReserveError> {
        let records = self.writable_records()?;
        records.sources.try_reserve(1)?;
        records.sources.insert(source, name);
        Ok(())
    }

    pub fn source_name(&self, source: u32) -> Option<&[u8]> {
        self.records
            .sources
            .get(&source)
            .map(Vec::as_slice)
            .or((source == 0).then_some(b"/etc/hosts".as_slice()))
    }

    /// Current static records in the actual global bucket order.
    pub fn addresses<'a>(&'a self, name: &'a [u8]) -> impl Iterator<Item = &'a Host> {
        let bucket = name_hash_bucket(name, self.records.name_hash_capacity);
        self.addresses_in_bucket(name, bucket)
    }

    /// Reuse a bucket only for the same name and current name_hash_capacity.
    /// Lease publication pairs this scan with lookup before any hosts update.
    pub(crate) fn addresses_in_bucket<'a>(
        &'a self,
        name: &'a [u8],
        bucket: usize,
    ) -> impl Iterator<Item = &'a Host> {
        let offset = self.retained_leases().len();
        self.order.bucket(bucket).filter_map(move |node| {
            let host = self.records.entries.get(node.checked_sub(offset)?)?;
            host.name.eq_ignore_ascii_case(name).then_some(host)
        })
    }

    pub fn set_round_robin(&mut self, enabled: bool) {
        self.no_round_robin = !enabled;
    }

    /// Apply the current bulk/incremental reverse-owner contract and deduplicate
    /// same-name/address records across input files in this generation.
    pub fn insert(&mut self, name: Vec<u8>, address: IpAddr, ttl: u32, source: u32) -> bool {
        self.insert_with_origin(name, address, ttl, source, source == 1)
    }

    /// Fallible configured-record ingestion, including best-effort ancestor
    /// metadata: an incomplete replacement must not be published.
    pub fn insert_checked(
        &mut self,
        name: Vec<u8>,
        address: IpAddr,
        ttl: u32,
        source: u32,
    ) -> Result<bool, ()> {
        let mut allocation_failed = false;
        let inserted = self
            .try_insert(
                name,
                address,
                ttl,
                source,
                source == 1,
                &mut allocation_failed,
            )
            .map_err(|_| ())?;
        if allocation_failed {
            Err(())
        } else {
            Ok(inserted)
        }
    }

    fn insert_with_origin(
        &mut self,
        name: Vec<u8>,
        address: IpAddr,
        ttl: u32,
        source: u32,
        configured: bool,
    ) -> bool {
        let mut allocation_failed = false;
        self.try_insert(
            name,
            address,
            ttl,
            source,
            configured,
            &mut allocation_failed,
        )
        .unwrap_or(false)
    }

    fn try_insert(
        &mut self,
        name: Vec<u8>,
        address: IpAddr,
        ttl: u32,
        source: u32,
        configured: bool,
        allocation_failed: &mut bool,
    ) -> Result<bool, TryReserveError> {
        let mut key = try_copy(&name)?;
        key.make_ascii_lowercase();
        self.writable_records()?;
        let bucket = name_hash_bucket(&key, self.records.name_hash_capacity);
        let mut selected = Vec::new();
        let leases = self.retained_leases();
        for node in self.order.bucket(bucket) {
            let record = hash_record(node, &self.records.entries, leases);
            if record.name.eq_ignore_ascii_case(&key)
                && record.address.is_ipv6() == address.is_ipv6()
            {
                selected.try_reserve(1)?;
                selected.push(node);
            }
        }
        let duplicate = selected.iter().any(|&node| {
            node >= leases.len() && self.records.entries[node - leases.len()].address == address
        });
        if let Some(bulk) = self.bulk.as_mut().filter(|bulk| bulk.active) {
            bulk.lookup_name(&selected);
        }
        if !self.no_round_robin && selected.len() > 1 {
            let leases = self
                .bulk
                .as_ref()
                .map_or(&[][..], |bulk| bulk.leases.as_slice());
            self.order.rotate(
                &key,
                Some(address.is_ipv6()),
                &self.records.entries,
                leases,
                self.records.name_hash_capacity,
            )?;
        }
        if duplicate {
            return Ok(false);
        }
        let records = self.records.get_mut().unwrap();
        let bulk = &mut self.bulk;
        // Reserve all mandatory indexes before publishing any new entry. An
        // unsuccessful reservation leaves existing entries and PTR ownership live.
        records.entries.try_reserve(1)?;
        records.forward.try_reserve(1)?;
        let reverse = match bulk.as_mut().filter(|bulk| bulk.active) {
            Some(bulk) => {
                bulk.next.try_reserve(1)?;
                !bulk.contains(address, &records.entries)
            }
            None => {
                let leases = bulk.as_ref().map_or(&[][..], |bulk| bulk.leases.as_slice());
                if leases.is_empty() {
                    !records.reverse.contains_key(&address)
                } else {
                    // Incremental add_hosts_entry clears F_REVERSE only when
                    // the first current reverse record is a hosts record.
                    self.order
                        .first_reverse(address, &records.entries, leases)
                        .is_none_or(|node| node < leases.len())
                }
            }
        };
        let mut fresh_reverse = Vec::new();
        if reverse {
            if records.reverse.contains_key(&address) {
                if let Some(extra) = records.reverse_extra.get_mut(&address) {
                    extra.try_reserve(1)?;
                } else {
                    records.reverse_extra.try_reserve(1)?;
                    fresh_reverse.try_reserve(1)?;
                }
            } else {
                records.reverse.try_reserve(1)?;
            }
        }
        // C make_non_terminals is best-effort too; the real record survives an
        // ancestor allocation failure. A replacement reader still needs the
        // failure signal so it can release this incomplete generation.
        records.non_terminals.remove(&key);
        for (index, &byte) in key.iter().enumerate() {
            let suffix = &key[index + 1..];
            if byte == b'.' && !records.non_terminals.contains(suffix) {
                match try_copy(suffix) {
                    Ok(ancestor) => {
                        if records.non_terminals.try_reserve(1).is_ok() {
                            records.non_terminals.insert(ancestor);
                        } else {
                            *allocation_failed = true;
                        }
                    }
                    Err(_) => *allocation_failed = true,
                }
            }
        }
        let leases = bulk.as_ref().map_or(&[][..], |bulk| bulk.leases.as_slice());
        let node = records.entries.len() + leases.len();
        let plan = self.order.prepare_insert(
            HashRecord {
                name: &name,
                address,
                reverse,
                immortal: true,
            },
            &records.entries,
            leases,
            records.name_hash_capacity,
        )?;
        if let Some(bulk) = bulk.as_mut().filter(|bulk| bulk.active) {
            bulk.push(address, reverse);
        }
        let id = records.entries.len();
        *records.forward.entry(key).or_insert(0) += 1;
        if reverse {
            if records.reverse.contains_key(&address) {
                records
                    .reverse_extra
                    .entry(address)
                    .or_insert(fresh_reverse)
                    .push(id);
            } else {
                records.reverse.insert(address, id);
            }
        }
        records.entries.push(Host {
            name,
            address,
            ttl,
            source,
            configured,
            reverse,
        });
        self.order.commit_insert(node, plan);
        Ok(true)
    }

    /// Preserve both published owner views if a replacement snapshot cannot be
    /// copied. In particular, do not use derived Clone after a fallible read.
    pub fn try_clone(&self) -> Result<Self, TryReserveError> {
        let mut copy = HostsRecords::default();
        let records = &self.records;
        copy.name_hash_capacity = records.name_hash_capacity;
        copy.entries.try_reserve_exact(records.entries.len())?;
        copy.sources.try_reserve(records.sources.len())?;
        copy.forward.try_reserve(records.forward.len())?;
        copy.reverse.try_reserve(records.reverse.len())?;
        copy.reverse_extra
            .try_reserve(records.reverse_extra.len())?;
        copy.non_terminals
            .try_reserve(records.non_terminals.len())?;
        for host in &records.entries {
            copy.entries.push(Host {
                name: try_copy(&host.name)?,
                ..*host
            });
        }
        for (&source, name) in &records.sources {
            copy.sources.insert(source, try_copy(name)?);
        }
        for (name, &count) in &records.forward {
            copy.forward.insert(try_copy(name)?, count);
        }
        copy.reverse
            .extend(records.reverse.iter().map(|(&address, &id)| (address, id)));
        for (&address, ids) in &records.reverse_extra {
            copy.reverse_extra.insert(address, try_copy(ids)?);
        }
        for name in &records.non_terminals {
            copy.non_terminals.insert(try_copy(name)?);
        }
        Ok(Self {
            records: Snapshot::Owned(copy),
            order: self.order.try_clone()?,
            no_round_robin: self.no_round_robin,
            bulk: self.bulk.as_ref().map(BulkReverse::try_clone).transpose()?,
        })
    }

    /// Build one complete hostsdir replacement without changing this owner.
    /// Every error means allocation failure, including source metadata and
    /// best-effort ancestor indexes that ordinary insert otherwise tolerates.
    pub fn try_replace_source(
        &self,
        source: u32,
        source_name: &[u8],
        records: Vec<(Vec<u8>, IpAddr)>,
        ttl: u32,
    ) -> Result<(Self, usize), ()> {
        let count = records.len();
        self.try_replace_source_with_leases(
            source,
            source_name,
            records,
            ttl,
            std::iter::empty::<(&[u8], IpAddr, bool, bool)>(),
            1..=count,
        )
    }

    /// Incremental reads see currently published DHCP reverse records until
    /// the entire source is read and lease DNS is republished. Build that
    /// bounded mixed view once; an existing pending view already has it.
    pub fn try_replace_source_with_leases<'a>(
        &self,
        source: u32,
        source_name: &[u8],
        records: Vec<(Vec<u8>, IpAddr)>,
        ttl: u32,
        leases: impl IntoIterator<Item = (&'a [u8], IpAddr, bool, bool)>,
        line_ends: impl IntoIterator<Item = usize>,
    ) -> Result<(Self, usize), ()> {
        let mut replacement = self.try_clone().map_err(|_| ())?;
        if replacement.bulk.is_none() {
            let mut retained = Vec::new();
            for (name, address, reverse, immortal) in leases {
                let name = try_copy(name).map_err(|_| ())?;
                retained.try_reserve(1).map_err(|_| ())?;
                retained.push(BulkLease {
                    name,
                    address,
                    reverse,
                    immortal,
                    next: BulkLink::End,
                });
            }
            if !retained.is_empty() {
                let mut order = replacement
                    .order
                    .with_lease_prefix(retained.len())
                    .map_err(|_| ())?;
                for id in 0..retained.len() {
                    let record = hash_record(id, &replacement.records.entries, &retained);
                    let plan = order
                        .prepare_insert_at(
                            id,
                            record,
                            &replacement.records.entries,
                            &retained,
                            replacement.records.name_hash_capacity,
                        )
                        .map_err(|_| ())?;
                    order.commit_insert(id, plan);
                }
                replacement.order = order;
                replacement.bulk = Some(BulkReverse {
                    active: false,
                    buckets: Vec::new(),
                    next: Vec::new(),
                    leases: retained,
                    name_count: 0,
                    rehash_checkpoint: 0,
                });
            }
        }
        let removed = replacement.try_remove_uid(source).map_err(|_| ())?;
        let name = try_copy(source_name).map_err(|_| ())?;
        let owned = replacement.records.get_mut().unwrap();
        owned.sources.try_reserve(1).map_err(|_| ())?;
        owned.sources.insert(source, name);
        let count = records.len();
        let mut line_ends = line_ends.into_iter().peekable();
        let mut previous_end = 0;
        for (index, (name, address)) in records.into_iter().enumerate() {
            let accepted = index + 1;
            if line_ends.peek().is_none_or(|&end| end < accepted) {
                return Err(());
            }
            let mut allocation_failed = false;
            replacement
                .try_insert(
                    name,
                    address,
                    ttl,
                    source,
                    source == 1,
                    &mut allocation_failed,
                )
                .map_err(|_| ())?;
            if allocation_failed {
                return Err(());
            }
            if line_ends.peek() == Some(&accepted) {
                replacement
                    .advance_bulk_names(accepted - previous_end, false)
                    .map_err(|_| ())?;
                previous_end = accepted;
                line_ends.next();
            }
        }
        if previous_end != count || line_ends.next().is_some() {
            return Err(());
        }
        replacement.advance_bulk_names(0, true).map_err(|_| ())?;
        Ok((replacement, removed))
    }

    pub fn reverse(&self, address: IpAddr) -> Option<&Host> {
        self.reverse_all(address).next()
    }

    pub fn reverse_all(&self, address: IpAddr) -> impl Iterator<Item = &Host> {
        let single = (!self.records.reverse_extra.contains_key(&address))
            .then(|| self.records.reverse.get(&address).copied())
            .flatten();
        let multiple = self.records.reverse_extra.contains_key(&address);
        let leases = self.retained_leases();
        let offset = leases.len();
        single
            .into_iter()
            .chain(
                (0..if multiple { self.order.heads.len } else { 0 })
                    .flat_map(move |bucket| {
                        self.order.bucket(bucket).take_while(move |&node| {
                            hash_record(node, &self.records.entries, leases).reverse
                        })
                    })
                    .filter_map(move |node| node.checked_sub(offset))
                    .filter(move |&id| self.records.entries[id].address == address),
            )
            .map(|id| &self.records.entries[id])
    }

    /// DHCP host_from_dns only renames from a static first reverse record.
    /// A retained DHCP record first in the real chain suppresses that rename.
    pub fn provider_reverse(&self, address: IpAddr) -> Option<&Host> {
        let leases = self.retained_leases();
        if leases.is_empty() {
            return self.reverse_all(address).next();
        }
        self.order
            .first_reverse(address, &self.records.entries, leases)?
            .checked_sub(leases.len())
            .map(|id| &self.records.entries[id])
    }

    /// cache_remove_uid removes this path's accepted entries, without reloading
    /// other paths or promoting their previously suppressed PTR ownership.
    pub fn remove_uid(&mut self, source: u32) -> usize {
        self.try_remove_uid(source).unwrap_or(0)
    }

    pub fn try_remove_uid(&mut self, source: u32) -> Result<usize, TryReserveError> {
        let before = self.records.entries.len();
        if !self
            .records
            .entries
            .iter()
            .any(|entry| entry.source == source)
        {
            return Ok(0);
        }
        let mut relocated = Vec::new();
        relocated.try_reserve_exact(before)?;
        let mut new = 0;
        for entry in &self.records.entries {
            relocated.push(if entry.source == source {
                None
            } else {
                new += 1;
                Some(new - 1)
            });
        }
        let bulk = self
            .bulk
            .as_ref()
            .map(|bulk| bulk.try_remap(&relocated))
            .transpose()?;
        let lease_count = self.retained_leases().len();
        let order = self
            .order
            .remapped(&relocated, lease_count)?;
        let mut canonical = Vec::new();
        let capacity = self.records.entries.iter()
            .filter(|entry| entry.source == source && entry.name.iter().any(u8::is_ascii_uppercase))
            .map(|entry| entry.name.len()).max().unwrap_or(0);
        canonical.try_reserve_exact(capacity)?;
        let records = self.writable_records()?;
        // Touch each removed name once; no record-index remap or surviving
        // name search is needed. Scratch growth precedes every state change.
        for entry in records.entries.iter().filter(|entry| entry.source == source) {
            let key = if entry.name.iter().any(u8::is_ascii_uppercase) {
                canonical.clear();
                canonical.extend_from_slice(&entry.name);
                canonical.make_ascii_lowercase();
                canonical.as_slice()
            } else {
                entry.name.as_slice()
            };
            *records.forward.get_mut(key).unwrap() -= 1;
        }
        records.entries.retain(|entry| entry.source != source);
        records.forward.retain(|_, count| *count != 0);
        for extra in records.reverse_extra.values_mut() {
            extra.retain_mut(|id| {
                if let Some(next) = relocated[*id] {
                    *id = next;
                    true
                } else {
                    false
                }
            });
        }
        records.reverse.retain(|address, id| {
            if let Some(next) = relocated[*id] {
                *id = next;
                true
            } else if let Some(extra) = records
                .reverse_extra
                .get_mut(address)
                .filter(|ids| !ids.is_empty())
            {
                *id = extra.remove(0);
                true
            } else {
                false
            }
        });
        records.reverse_extra.retain(|_, ids| !ids.is_empty());
        // Fresh C non-terminals have their own zero UID; their ancestor names
        // are not reconstructed from remaining address records on removal.
        let removed = before - records.entries.len();
        self.bulk = bulk;
        self.order = order;
        Ok(removed)
    }

    pub fn name_exists(&self, name: &[u8]) -> bool {
        if self.records.forward.is_empty() && self.records.non_terminals.is_empty() {
            return false;
        }
        let canonical;
        let key = if name.iter().any(u8::is_ascii_uppercase) {
            canonical = name.to_ascii_lowercase();
            canonical.as_slice()
        } else {
            name
        };
        self.name_exists_canonical(key)
    }

    /// Query-local dotted converters already fold ASCII case. Reuse that
    /// spelling without another uppercase scan.
    pub(crate) fn name_exists_canonical(&self, name: &[u8]) -> bool {
        debug_assert!(!name.iter().any(u8::is_ascii_uppercase));
        if self.records.forward.is_empty() && self.records.non_terminals.is_empty() {
            return false;
        }
        self.records.forward.contains_key(name) || self.records.non_terminals.contains(name)
    }

    /// Return current static bucket order, then apply C's first matching
    /// flags-group rotation, including retained lease nodes before publication.
    pub fn lookup(&mut self, name: &[u8], ipv6: Option<bool>, no_round_robin: bool) -> Vec<&Host> {
        let bucket = name_hash_bucket(name, self.records.name_hash_capacity);
        self.lookup_in_bucket(name, ipv6, no_round_robin, bucket)
    }

    /// Same-name companion to addresses_in_bucket. Neither operation changes
    /// hash capacity; lookup retains its answer allocation and rotation order.
    pub(crate) fn lookup_in_bucket(
        &mut self,
        name: &[u8],
        ipv6: Option<bool>,
        no_round_robin: bool,
        bucket: usize,
    ) -> Vec<&Host> {
        let records = &self.records;
        let leases = self
            .bulk
            .as_ref()
            .map_or(&[][..], |bulk| bulk.leases.as_slice());
        let mut matched = 0;
        let mut answer = Vec::new();
        for node in self.order.bucket(bucket) {
            let record = hash_record(node, &records.entries, leases);
            if record.name.eq_ignore_ascii_case(name)
                && ipv6.is_none_or(|family| record.address.is_ipv6() == family)
            {
                matched += 1;
                if let Some(id) = node.checked_sub(leases.len()) {
                    if answer.try_reserve(1).is_err() {
                        return Vec::new();
                    }
                    answer.push(&records.entries[id]);
                }
            }
        }
        // The complete answer is allocated before any chain link changes.
        if !no_round_robin && !self.no_round_robin && matched > 1 {
            let _ = self.order.rotate(
                name,
                ipv6,
                &records.entries,
                leases,
                records.name_hash_capacity,
            );
        }
        answer
    }

    /// The caller opens the file and records any open errors before this method.
    /// `domain` implements get_domain/get_domain6 (including address ranges).
    pub fn read(
        &mut self,
        input: &[u8],
        source: u32,
        ttl: u32,
        expand: bool,
        domain: impl FnMut(IpAddr) -> Option<Vec<u8>>,
    ) -> ReadStats {
        self.read_from(input, source, ttl, expand, domain)
    }

    /// Like C gettok, EOF or a read error completes the received prefix. The
    /// token and input buffers stay bounded regardless of line or file length.
    pub fn read_from(
        &mut self,
        input: impl Read,
        source: u32,
        ttl: u32,
        expand: bool,
        domain: impl FnMut(IpAddr) -> Option<Vec<u8>>,
    ) -> ReadStats {
        self.read_from_with_diagnostics(input, source, ttl, expand, domain, |_, _| {})
    }

    /// Diagnostics are emitted as tokens complete, never accumulated with the
    /// hosts generation. The boolean distinguishes bad addresses from names.
    /// Allocation failure stops after the current bounded input chunk; unlike
    /// EOF or a read error, it marks the replacement as incomplete.
    pub fn read_from_with_diagnostics(
        &mut self,
        mut input: impl Read,
        source: u32,
        ttl: u32,
        expand: bool,
        mut domain: impl FnMut(IpAddr) -> Option<Vec<u8>>,
        mut invalid: impl FnMut(usize, bool),
    ) -> ReadStats {
        let mut parser = HostsParser::default();
        let mut inserted = 0;
        let mut allocation_failed = false;
        let mut buffer = [0; 8192];
        let mut line_names = 0;
        let mut consume = |parser: &mut HostsParser, bytes: &[u8]| {
            for line in bytes.split_inclusive(|&byte| byte == b'\n') {
                let before = parser.stats.accepted;
                parser.feed(
                    line,
                    expand,
                    &mut domain,
                    |name, address| match self.try_insert(
                        name,
                        address,
                        ttl,
                        source,
                        false,
                        &mut allocation_failed,
                    ) {
                        Ok(added) => inserted += usize::from(added),
                        Err(_) => allocation_failed = true,
                    },
                    &mut invalid,
                );
                line_names += parser.stats.accepted - before;
                if line.last() == Some(&b'\n') {
                    if self.advance_bulk_names(line_names, false).is_err() {
                        allocation_failed = true;
                    }
                    line_names = 0;
                }
                if allocation_failed || parser.allocation_failed {
                    break;
                }
            }
            allocation_failed || parser.allocation_failed
        };
        let mut failed = false;
        while let Ok(length) = input.read(&mut buffer) {
            if length == 0 {
                break;
            }
            if consume(&mut parser, &buffer[..length]) {
                failed = true;
                break;
            }
        }
        if !failed {
            failed = consume(&mut parser, b"\n");
        }
        if !failed {
            failed = self.advance_bulk_names(0, true).is_err();
        }
        let mut stats = parser.stats;
        stats.inserted = inserted;
        stats.allocation_failed = failed;
        stats
    }
}

/// cache.c gettok retains at most MAXDNAMESTR - 1 bytes and consumes the rest.
/// Keeping token state, rather than a whole line, also bounds long comments and
/// tokens in regular files, FIFOs and incremental hostsdir reads.
pub(crate) struct HostsParser {
    token: [u8; 502],
    token_len: usize,
    comment: bool,
    line: usize,
    first: bool,
    address: Option<IpAddr>,
    suffix: Option<Vec<u8>>,
    pub stats: ReadStats,
    pub allocation_failed: bool,
}

impl Default for HostsParser {
    fn default() -> Self {
        Self {
            token: [0; 502],
            token_len: 0,
            comment: false,
            line: 1,
            first: true,
            address: None,
            suffix: None,
            stats: ReadStats::default(),
            allocation_failed: false,
        }
    }
}

impl HostsParser {
    /// Feed a final newline on EOF/read error to complete a partial last token.
    pub fn feed(
        &mut self,
        input: &[u8],
        expand: bool,
        domain: impl FnMut(IpAddr) -> Option<Vec<u8>>,
        emit: impl FnMut(Vec<u8>, IpAddr),
        invalid: impl FnMut(usize, bool),
    ) {
        self.feed_with_line_end(input, expand, domain, emit, invalid, |_| {});
    }

    /// Report the cumulative accepted count at each physical line boundary.
    /// Staged readers retain only increasing endpoints, so blank/invalid lines
    /// need no per-line allocation while aliases and expansions stay together.
    pub fn feed_with_line_end(
        &mut self,
        input: &[u8],
        expand: bool,
        mut domain: impl FnMut(IpAddr) -> Option<Vec<u8>>,
        mut emit: impl FnMut(Vec<u8>, IpAddr),
        mut invalid: impl FnMut(usize, bool),
        mut line_end: impl FnMut(usize),
    ) {
        for &byte in input {
            if !self.comment {
                // C isspace includes vertical tab as well as Rust's ASCII set.
                if byte == b'#' || byte.is_ascii_whitespace() || byte == 0x0b {
                    if self.token_len != 0 {
                        let value = self.token[..self.token_len]
                            .split(|&b| b == 0)
                            .next()
                            .unwrap_or_default();
                        if self.first {
                            self.first = false;
                            self.address = std::str::from_utf8(value)
                                .ok()
                                .and_then(|value| value.parse::<IpAddr>().ok());
                            self.suffix =
                                expand.then(|| self.address.and_then(&mut domain)).flatten();
                            if self.address.is_none() {
                                self.stats.bad_addresses += 1;
                                invalid(self.line, true);
                            }
                        } else if let Some(address) = self.address {
                            if let Some(name) = canonical_name(value) {
                                if expand && !value.contains(&b'.') {
                                    if let Some(suffix) = &self.suffix {
                                        let mut expanded = Vec::new();
                                        if expanded
                                            .try_reserve_exact(name.len() + 1 + suffix.len())
                                            .is_ok()
                                        {
                                            expanded.extend_from_slice(name);
                                            expanded.push(b'.');
                                            expanded.extend_from_slice(suffix);
                                            self.stats.accepted += 1;
                                            emit(expanded, address);
                                        } else {
                                            self.allocation_failed = true;
                                            self.stats.allocation_failed = true;
                                        }
                                    }
                                }
                                if let Ok(name) = try_copy(name) {
                                    self.stats.accepted += 1;
                                    emit(name, address);
                                } else {
                                    self.allocation_failed = true;
                                    self.stats.allocation_failed = true;
                                }
                            } else {
                                self.stats.bad_names += 1;
                                invalid(self.line, false);
                            }
                        }
                        self.token_len = 0;
                    }
                    self.comment = byte == b'#';
                } else if self.token_len < self.token.len() {
                    self.token[self.token_len] = byte;
                    self.token_len += 1;
                }
            }
            if byte == b'\n' {
                self.comment = false;
                self.first = true;
                self.address = None;
                self.suffix = None;
                self.line += 1;
                line_end(self.stats.accepted);
            }
        }
    }
}

/// Visit every accepted hosts name, including duplicates. Runtime directory
/// readers stage these records; publication applies cache duplicate/PTR rules.
pub fn visit_hosts(
    input: &[u8],
    expand: bool,
    mut domain: impl FnMut(IpAddr) -> Option<Vec<u8>>,
    mut emit: impl FnMut(Vec<u8>, IpAddr),
) -> ReadStats {
    let mut parser = HostsParser::default();
    parser.feed(input, expand, &mut domain, &mut emit, |_, _| {});
    parser.feed(b"\n", expand, domain, emit, |_, _| {});
    parser.stats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn colliding_name(name: &[u8], capacity: usize) -> Vec<u8> {
        (0..10000)
            .map(|id| format!("cross{id}.test").into_bytes())
            .find(|candidate| {
                name_hash_bucket(candidate, capacity) == name_hash_bucket(name, capacity)
            })
            .expect("bounded name pool has a matching bucket")
    }

    fn colliding_pair(capacity: usize) -> (Vec<u8>, Vec<u8>) {
        let mut names = vec![None; name_hash_size(capacity)];
        // A fixed pool need not cover a preselected name's process-seeded
        // bucket. One more distinct name than buckets guarantees some pair.
        for id in 0..=names.len() {
            let name = format!("pair{id}.test").into_bytes();
            let bucket = name_hash_bucket(&name, capacity);
            if let Some(first) = names[bucket].take() {
                return (first, name);
            }
            names[bucket] = Some(name);
        }
        unreachable!("more distinct names than buckets must collide")
    }

    fn crossed_hosts(y: &[u8]) -> Hosts {
        let mut hosts = Hosts::new();
        hosts.begin_bulk(1497, 0, 0).unwrap();
        let mut fixture =
            b"192.0.2.1 x.test\n10.0.63.213 a.test\n192.0.4.2 a.test\n192.0.2.1 ".to_vec();
        fixture.extend_from_slice(y);
        fixture.extend_from_slice(b"\n192.0.4.1 x.test\n");
        assert!(
            !hosts
                .read(&fixture, 2, 37, false, |_| None)
                .allocation_failed
        );
        hosts.finish_bulk();
        hosts
    }

    #[test]
    fn forward_rotation_moves_cross_name_ptr_links_privately_in_tcp_snapshot() {
        let y = colliding_name(b"x.test", 0);
        let mut parent = crossed_hosts(&y);
        let mut child = parent.tcp_snapshot();
        let address = "192.0.2.1".parse().unwrap();
        let names = |hosts: &Hosts| {
            hosts
                .reverse_all(address)
                .map(|host| host.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&parent), [y.clone(), b"x.test".to_vec()]);
        let before = child
            .lookup(b"x.test", Some(false), false)
            .into_iter()
            .map(|host| host.address)
            .collect::<Vec<_>>();
        assert_eq!(before, ["192.0.4.1".parse::<IpAddr>().unwrap(), address]);
        assert_eq!(names(&child), [b"x.test".to_vec(), y.clone()]);
        assert_eq!(names(&parent), [y.clone(), b"x.test".to_vec()]);
        let held = child.try_clone().unwrap();
        assert_eq!(names(&held), names(&child));
        parent.lookup(b"x.test", Some(false), false);
        assert_eq!(names(&parent), names(&child));
    }

    #[test]
    fn rehash_reinserts_old_bucket_chain_instead_of_sorting_ptr_owners() {
        let y = colliding_name(b"x.test", 1000);
        let mut hosts = crossed_hosts(&y);
        let address = "192.0.2.1".parse().unwrap();
        assert_eq!(
            hosts
                .addresses(b"x.test")
                .map(|host| host.address)
                .collect::<Vec<_>>(),
            ["192.0.4.1".parse::<IpAddr>().unwrap(), address]
        );
        hosts.set_name_hash_capacity(1000).unwrap();
        assert_eq!(
            hosts
                .addresses(b"x.test")
                .map(|host| host.address)
                .collect::<Vec<_>>(),
            [address, "192.0.4.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            hosts
                .reverse_all(address)
                .map(|host| host.name.clone())
                .collect::<Vec<_>>(),
            [b"x.test".to_vec(), y]
        );
    }

    #[test]
    fn sealing_bulk_keeps_retained_first_kind_until_allocation_free_finish() {
        let mut hosts = Hosts::new();
        hosts.begin_bulk(1497, 0, 0).unwrap();
        hosts
            .add_bulk_lease(b"same.test", "192.0.2.1".parse().unwrap(), true, true)
            .unwrap();
        hosts
            .insert_checked(b"same.test".to_vec(), "192.0.2.1".parse().unwrap(), 37, 2)
            .unwrap();
        hosts.seal_bulk();
        assert!(
            hosts
                .provider_reverse("192.0.2.1".parse().unwrap())
                .is_none()
        );
        assert_eq!(hosts.reverse_all("192.0.2.1".parse().unwrap()).count(), 1);
        // Sealed ingestion uses actual reverse ownership, not the discarded
        // temporary address chain. Retained leases never become static hosts.
        hosts
            .insert_checked(b"late.test".to_vec(), "192.0.2.1".parse().unwrap(), 37, 3)
            .unwrap();
        assert!(hosts.addresses(b"late.test").next().unwrap().reverse);
        hosts.finish_bulk();
        assert!(hosts.bulk.is_none());
        assert_eq!(
            reverse_names(&hosts, "192.0.2.1"),
            [b"late.test".to_vec(), b"same.test".to_vec()]
        );
        assert_eq!(hosts.order.next.len, hosts.len());
        let mut child = hosts.tcp_snapshot();
        assert_eq!(child.lookup(b"same.test", Some(false), false).len(), 1);
    }

    #[test]
    fn incremental_file_keeps_dhcp_first_record_until_all_aliases_are_read() {
        let address = "192.0.2.1".parse().unwrap();
        let mut published = Hosts::new();
        published.begin_bulk(1497, 1000, 1000).unwrap();
        published
            .insert_checked(b"ready.test".to_vec(), "192.0.2.41".parse().unwrap(), 0, 1)
            .unwrap();
        published.finish_bulk();
        let held = published.tcp_snapshot();
        for immortal in [false, true] {
            let input = vec![
                (b"lease.test".to_vec(), address),
                (b"alias.test".to_vec(), address),
            ];
            let (mut replacement, removed) = published
                .try_replace_source_with_leases(
                    2,
                    b"/hostsdir/new",
                    input,
                    37,
                    [(b"lease.test".as_slice(), address, true, immortal)],
                    [2],
                )
                .unwrap();
            assert_eq!(removed, 0);
            assert!(!replacement.bulk.as_ref().unwrap().active);
            replacement.finish_bulk();
            let names = reverse_names(&replacement, "192.0.2.1");
            if immortal {
                assert_eq!(names, [b"alias.test".to_vec(), b"lease.test".to_vec()]);
            } else {
                assert_eq!(names, [b"lease.test".to_vec()]);
            }
            assert_eq!(replacement.len(), 3);
            assert_eq!(published.len(), 1);
            assert_eq!(held.len(), 1);
            assert!(held.reverse(address).is_none());
        }
    }

    #[test]
    fn incremental_without_leases_does_not_create_a_pending_loader_view() {
        let original = Hosts::new();
        let (replacement, _) = original
            .try_replace_source(
                2,
                b"/hostsdir/new",
                vec![(b"one.test".to_vec(), "192.0.2.1".parse().unwrap())],
                37,
            )
            .unwrap();
        assert!(replacement.bulk.is_none());
        assert_eq!(replacement.len(), 1);
    }

    #[test]
    fn staged_alias_line_rehashes_only_after_the_same_boundary_as_streaming_read() {
        let (x, y) = colliding_pair(2100);
        let mut seed = Hosts::new();
        seed.begin_bulk(1497, 1000, 1000).unwrap();
        let mut initial = b"192.0.2.1 ".to_vec();
        initial.extend_from_slice(&x);
        initial.extend_from_slice(b"\n10.0.63.213 a.test\n192.0.4.2 a.test\n192.0.2.1 ");
        initial.extend_from_slice(&y);
        initial.extend_from_slice(b"\n192.0.4.1 ");
        initial.extend_from_slice(&x);
        initial.push(b'\n');
        assert!(
            !seed
                .read(&initial, 2, 37, false, |_| None)
                .allocation_failed
        );
        let mut input = b"192.0.2.1".to_vec();
        for i in 0..1001 {
            input.extend_from_slice(format!(" extra{i:04}.test").as_bytes());
        }
        input.push(b' ');
        input.extend_from_slice(&x);
        input.push(b'\n');
        let mut records = Vec::new();
        let mut ends = Vec::new();
        let mut parser = HostsParser::default();
        // Exercise a line crossing real reader chunks and the final newline.
        for chunk in input.chunks(4096) {
            parser.feed_with_line_end(
                chunk,
                false,
                |_| None,
                |name, address| records.push((name, address)),
                |_, _| {},
                |end| ends.push(end),
            );
        }
        assert_eq!(ends, [1002]);
        let (mut staged, _) = seed
            .try_replace_source_with_leases(
                3,
                b"/hostsdir/aliases",
                records,
                37,
                std::iter::empty::<(&[u8], IpAddr, bool, bool)>(),
                ends,
            )
            .unwrap();
        let mut streaming = seed.try_clone().unwrap();
        assert!(
            !streaming
                .read(&input, 3, 37, false, |_| None)
                .allocation_failed
        );
        staged.finish_bulk();
        streaming.finish_bulk();
        let address = "192.0.2.1".parse().unwrap();
        assert_eq!(
            staged
                .addresses(&x)
                .map(|host| host.address)
                .collect::<Vec<_>>(),
            streaming
                .addresses(&x)
                .map(|host| host.address)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            staged
                .reverse_all(address)
                .map(|host| &host.name)
                .collect::<Vec<_>>(),
            streaming
                .reverse_all(address)
                .map(|host| &host.name)
                .collect::<Vec<_>>()
        );
        assert_eq!(staged.entries(), streaming.entries());
    }

    const REPEATED_ADDRESS_FIXTURE: &[u8] = b"192.0.2.2 old.test\n192.0.2.1 x.test\n192.0.3.186 a.test\n192.0.3.185 a.test\n192.0.2.1 y.test\n192.0.2.2 y.test\n";

    fn bulk_fixture(retained_lease: Option<(&[u8], bool)>, input: &[u8]) -> Hosts {
        let mut hosts = Hosts::new();
        hosts.begin_bulk(1497, 1000, 1000).unwrap();
        if let Some((name, immortal)) = retained_lease {
            hosts
                .add_bulk_lease(name, "192.0.2.1".parse().unwrap(), true, immortal)
                .unwrap();
        }
        assert!(!hosts.read(input, 2, 37, false, |_| None).allocation_failed);
        hosts
    }

    fn reverse_names(hosts: &Hosts, address: &str) -> Vec<Vec<u8>> {
        let mut names = hosts
            .reverse_all(address.parse().unwrap())
            .map(|host| host.name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[test]
    fn bulk_reverse_link_reuse_preserves_multiple_ptr_owners_and_mixed_rotation() {
        let mut hosts = bulk_fixture(None, REPEATED_ADDRESS_FIXTURE);
        assert_eq!(
            reverse_names(&hosts, "192.0.2.1"),
            [b"x.test".to_vec(), b"y.test".to_vec()]
        );
        assert_eq!(reverse_names(&hosts, "192.0.2.2"), [b"old.test".to_vec()]);
        let expected = hosts
            .addresses(b"y.test")
            .map(|host| host.address)
            .collect::<Vec<_>>();
        for _ in 0..4 {
            assert_eq!(
                hosts
                    .lookup(b"y.test", Some(false), false)
                    .iter()
                    .map(|host| host.address)
                    .collect::<Vec<_>>(),
                expected
            );
        }
        hosts.finish_bulk();
        hosts
            .insert_checked(b"later.test".to_vec(), "192.0.2.1".parse().unwrap(), 37, 3)
            .unwrap();
        assert!(!hosts.addresses(b"later.test").next().unwrap().reverse);
        assert_eq!(reverse_names(&hosts, "192.0.2.1").len(), 2);
    }

    #[test]
    fn retained_finite_and_immortal_lease_links_follow_exact_c_counterexample() {
        // Both earlier names must be outside the retained lease's bucket.
        // Either can separate the immortal lease from the later same-name host,
        // reversing their lookup links and suppressing y.test's PTR too.
        // Name hashing includes process pointers, so fixed names cannot ensure it.
        let lease = (0..10000)
            .map(|id| format!("a{id}.test"))
            .find(|name| {
                let bucket = name_hash_bucket(name.as_bytes(), 1000);
                bucket != name_hash_bucket(b"old.test", 1000)
                    && bucket != name_hash_bucket(b"x.test", 1000)
            })
            .expect("bounded name pool has a separate bucket");
        let input = std::str::from_utf8(REPEATED_ADDRESS_FIXTURE)
            .unwrap()
            .replace("a.test", &lease);
        let finite = bulk_fixture(Some((lease.as_bytes(), false)), input.as_bytes());
        let immortal = bulk_fixture(Some((lease.as_bytes(), true)), input.as_bytes());
        assert_eq!(reverse_names(&finite, "192.0.2.1"), [b"x.test".to_vec()]);
        assert_eq!(
            reverse_names(&immortal, "192.0.2.1"),
            [b"x.test".to_vec(), b"y.test".to_vec()]
        );
        assert_eq!(finite.entries().len(), 6);
        assert_eq!(immortal.entries().len(), 6);
        assert!(finite.entries().iter().all(|entry| entry.name != lease.as_bytes()
            || entry.address != "192.0.2.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn bulk_three_address_duplicate_and_no_round_robin_keep_reverse_groups() {
        for no_rr in [false, true] {
            let mut hosts = bulk_fixture(None, REPEATED_ADDRESS_FIXTURE);
            hosts.set_round_robin(!no_rr);
            let before = hosts.len();
            assert!(
                !hosts
                    .insert_checked(b"a.test".to_vec(), "192.0.3.185".parse().unwrap(), 37, 2)
                    .unwrap()
            );
            assert_eq!(hosts.len(), before);
            hosts
                .insert_checked(b"y.test".to_vec(), "192.0.3.184".parse().unwrap(), 37, 2)
                .unwrap();
            let first = hosts
                .lookup(b"y.test", Some(false), false)
                .into_iter()
                .map(|host| (host.address, host.reverse))
                .collect::<Vec<_>>();
            let second = hosts
                .lookup(b"y.test", Some(false), false)
                .into_iter()
                .map(|host| (host.address, host.reverse))
                .collect::<Vec<_>>();
            assert_eq!(
                first
                    .iter()
                    .map(|(_, reverse)| *reverse)
                    .collect::<Vec<_>>(),
                [true, true, false]
            );
            if no_rr {
                assert_eq!(first, second);
            } else {
                assert_eq!(second, [first[1], first[0], first[2]]);
            }
        }
    }

    #[test]
    fn bulk_ipv6_links_and_multiple_files_share_one_address_hash() {
        let mut hosts = Hosts::new();
        hosts.begin_bulk(1497, 1000, 1000).unwrap();
        hosts.read(
            b"::2 old.test\n::1 x.test\n::bc a.test\n",
            2,
            37,
            false,
            |_| None,
        );
        hosts.read(
            b"::bb a.test\n::1 y.test\n::2 y.test\n",
            3,
            37,
            false,
            |_| None,
        );
        assert_eq!(
            reverse_names(&hosts, "::1"),
            [b"x.test".to_vec(), b"y.test".to_vec()]
        );
        assert_eq!(reverse_names(&hosts, "::2"), [b"old.test".to_vec()]);
        hosts.try_remove_uid(2).unwrap();
        assert_eq!(reverse_names(&hosts, "::1"), [b"y.test".to_vec()]);
        assert!(hosts.reverse_all("::2".parse().unwrap()).next().is_none());
        assert!(hosts.bulk.as_ref().unwrap().next.len() == hosts.len());
        let copied = hosts.try_clone().unwrap();
        assert_eq!(copied.entries(), hosts.entries());
        assert_eq!(reverse_names(&copied, "::1"), [b"y.test".to_vec()]);
    }

    #[test]
    fn bulk_large_repeated_fixture_matches_exact_c_reverse_flag_counts() {
        let mut hosts = Hosts::new();
        hosts.begin_bulk(1497, 1000, 1000).unwrap();
        hosts
            .insert_checked(b"ready.test".to_vec(), "192.0.2.41".parse().unwrap(), 0, 1)
            .unwrap();
        let mut input = String::new();
        use std::fmt::Write;
        for i in 0..30000 {
            for family in [2, 3] {
                writeln!(&mut input, "192.0.{family}.{} host{i:06}.test", i % 250 + 1).unwrap();
            }
        }
        let stats = hosts.read(input.as_bytes(), 2, 0, false, |_| None);
        assert_eq!(stats.accepted, 60000);
        assert!(!stats.allocation_failed);
        assert_eq!(
            (0..30000)
                .filter(|i| {
                    let name = format!("host{i:06}.test");
                    let mut entries = hosts.addresses(name.as_bytes());
                    let first = entries.next().unwrap();
                    let second = entries.next().unwrap();
                    entries.next().is_none() && first.reverse != second.reverse
                })
                .count(),
            835
        );
        assert_eq!(hosts.records.reverse_extra.len(), 374);
        assert_eq!(hosts.bulk.as_ref().unwrap().name_count, 61000);
        hosts.finish_bulk();
        let mut snapshot = hosts.tcp_snapshot();
        assert!(snapshot.bulk.is_none());
        assert_eq!(
            snapshot
                .lookup(b"host000313.test", Some(false), false)
                .iter()
                .map(|host| host.reverse)
                .collect::<Vec<_>>(),
            [true, false]
        );
    }

    #[test]
    fn repeated_small_hup_keeps_hash_size_without_accumulating_old_name_count() {
        let mut large = Hosts::new();
        large.begin_bulk(1497, 1000, 1000).unwrap();
        let input = "192.0.2.1 duplicate.test\n".repeat(3000);
        large.read(input.as_bytes(), 2, 37, false, |_| None);
        assert_eq!(large.len(), 1);
        assert_eq!(large.bulk.as_ref().unwrap().name_count, 4000);
        let capacity = large.name_hash_capacity();
        assert_eq!(name_hash_size(capacity), 512);
        for _ in 0..20 {
            let mut next = Hosts::new();
            next.begin_bulk(1497, 1000, capacity).unwrap();
            next.read(REPEATED_ADDRESS_FIXTURE, 2, 37, false, |_| None);
            assert_eq!(next.bulk.as_ref().unwrap().name_count, 1006);
            assert_eq!(next.name_hash_capacity(), capacity);
        }
    }

    fn paired_hosts(count: usize) -> Hosts {
        let mut hosts = Hosts::new();
        for i in 0..count {
            for address in ["192.0.2.1", "192.0.2.2"] {
                hosts.insert(
                    format!("name{i}.test").into_bytes(),
                    address.parse().unwrap(),
                    37,
                    2,
                );
            }
        }
        hosts
    }

    #[test]
    fn warm_parent_order_copies_only_one_page_per_child_query() {
        let mut parent = paired_hosts(2048);
        let seed = parent.tcp_snapshot();
        for i in 0..2048 {
            parent.lookup(format!("name{i}.test").as_bytes(), Some(false), false);
        }
        let mut children: Vec<_> = (0..20).map(|_| parent.tcp_snapshot()).collect();
        for (i, child) in children.iter_mut().enumerate() {
            let name = format!("name{}.test", i * 97);
            let expected: Vec<_> = parent.addresses(name.as_bytes()).cloned().collect();
            let actual: Vec<_> = child
                .lookup(name.as_bytes(), Some(false), false)
                .into_iter()
                .cloned()
                .collect();
            assert_eq!(actual, expected);
            assert_eq!(child.order.next.pages.len(), parent.order.next.pages.len());
            let private: Vec<_> = child
                .order
                .next
                .pages
                .iter()
                .filter_map(|page| {
                    if let Snapshot::Owned(page) = page {
                        Some(page)
                    } else {
                        None
                    }
                })
                .collect();
            assert!(private.len() <= 4);
            assert!(private[0].len() <= ROTATION_PAGE_ENTRIES);
            assert!(std::ptr::eq(child.entries(), parent.entries()));
        }
        drop((children, seed));
        for page in &parent.order.next.pages {
            let Snapshot::Shared(page) = page else {
                panic!("published page");
            };
            assert_eq!(Arc::strong_count(page), 1);
        }
    }

    #[test]
    fn rolling_tcp_accepts_and_parent_queries_keep_order_without_history() {
        let mut parent = paired_hosts(128);
        let mut reference = parent.try_clone().unwrap();
        let mut old = parent.tcp_snapshot();
        let mut old_reference = reference.try_clone().unwrap();
        let addresses = |hosts: &mut Hosts, name: &[u8]| {
            hosts
                .lookup(name, Some(false), false)
                .into_iter()
                .map(|h| h.address)
                .collect::<Vec<_>>()
        };
        for i in 0..2048 {
            let name = format!("name{}.test", i % 128);
            assert_eq!(
                addresses(&mut parent, name.as_bytes()),
                addresses(&mut reference, name.as_bytes())
            );
            // Accept before dropping the previous connection: delta chains
            // can otherwise hide unbounded history behind the latest owner.
            let new = parent.tcp_snapshot();
            let new_reference = reference.try_clone().unwrap();
            assert_eq!(
                addresses(&mut old, name.as_bytes()),
                addresses(&mut old_reference, name.as_bytes())
            );
            old = new;
            old_reference = new_reference;
            assert!(parent.order.next.pages.len() <= 256usize.div_ceil(ROTATION_PAGE_ENTRIES));
        }
        drop(old);
        for page in &parent.order.next.pages {
            let Snapshot::Shared(page) = page else {
                panic!("published page");
            };
            assert_eq!(Arc::strong_count(page), 1);
        }
    }

    #[test]
    fn tcp_snapshot_shares_records_but_keeps_each_familys_rotation_private() {
        let mut parent = Hosts::new();
        parent.read(b"192.0.2.1 many.test\n192.0.2.2 many.test\n2001:db8::1 many.test\n2001:db8::2 many.test\n192.0.2.9 single.test\n", 2, 37, false, |_| None);
        let mut reference = parent.try_clone().unwrap();
        let mut first = parent.tcp_snapshot();
        let mut second = parent.tcp_snapshot();
        let same_records =
            |a: &Hosts, b: &Hosts| std::ptr::eq(a.entries().as_ptr(), b.entries().as_ptr());
        assert!(same_records(&parent, &first) && same_records(&parent, &second));
        for family in [Some(false), Some(true), None] {
            let expected: Vec<_> = reference
                .lookup(b"many.test", family, false)
                .into_iter()
                .cloned()
                .collect();
            assert_eq!(
                first
                    .lookup(b"many.test", family, false)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                second
                    .lookup(b"many.test", family, false)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                parent
                    .lookup(b"many.test", family, false)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(same_records(&parent, &first) && same_records(&parent, &second));
        }
        let mut later = parent.tcp_snapshot();
        let expected: Vec<_> = reference
            .lookup(b"many.test", None, false)
            .into_iter()
            .cloned()
            .collect();
        assert_eq!(
            later
                .lookup(b"many.test", None, false)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>(),
            expected
        );
        assert!(same_records(&parent, &later));
        parent.remove_uid(2);
        parent.read(b"192.0.2.99 many.test\n", 2, 37, false, |_| None);
        assert_eq!(parent.len(), 1);
        assert_eq!(first.len(), 5);
        assert_eq!(later.len(), 5);
        assert!(!same_records(&parent, &first));
        assert_eq!(first.source_name(0), Some(b"/etc/hosts".as_slice()));
        assert_eq!(first.source_name(2), None);
        assert_eq!(
            first.reverse("2001:db8::1".parse().unwrap()).unwrap().name,
            b"many.test"
        );
        assert_eq!(
            first
                .try_clone()
                .unwrap()
                .addresses(b"many.test")
                .collect::<Vec<_>>(),
            first.addresses(b"many.test").collect::<Vec<_>>()
        );
    }

    #[test]
    fn incremental_source_removal_keeps_skipped_duplicates_and_ptr_suppressed() {
        let mut hosts = Hosts::new();
        let address = "192.0.2.7".parse().unwrap();
        assert!(hosts.insert(b"first.records.test".to_vec(), address, 0, 7));
        assert!(!hosts.insert(b"first.records.test".to_vec(), address, 0, 8));
        assert!(hosts.insert(b"second.records.test".to_vec(), address, 0, 8));
        assert_eq!(hosts.remove_uid(7), 1);
        assert!(hosts.addresses(b"first.records.test").next().is_none());
        assert_eq!(hosts.addresses(b"second.records.test").count(), 1);
        assert!(hosts.reverse(address).is_none());
        assert_eq!(hosts.remove_uid(7), 0);
        assert!(hosts.insert(b"new.records.test".to_vec(), address, 0, 7));
        assert_eq!(hosts.reverse(address).unwrap().name, b"new.records.test");
    }

    #[test]
    fn source_removal_preserves_presence_until_the_last_static_name_record() {
        for retained_lease in [false, true] {
            let mut hosts = Hosts::new();
            hosts.begin_bulk(1497, 1000, 1000).unwrap();
            if retained_lease {
                hosts.add_bulk_lease(b"same.test", "192.0.2.9".parse().unwrap(), true, false).unwrap();
            }
            hosts.insert_checked(b"same.test".to_vec(), "192.0.2.1".parse().unwrap(), 37, 2).unwrap();
            hosts.insert_checked(b"same.test".to_vec(), "192.0.2.2".parse().unwrap(), 37, 3).unwrap();
            hosts.seal_bulk();
            assert_eq!(hosts.try_remove_uid(2).unwrap(), 1);
            assert!(hosts.name_exists(b"same.test") && hosts.name_exists(b"SAME.TEST"));
            assert_eq!(hosts.addresses(b"same.test").count(), 1);
            assert_eq!(hosts.try_remove_uid(3).unwrap(), 1);
            assert!(!hosts.name_exists(b"same.test") && !hosts.name_exists(b"SAME.TEST"));
            assert_eq!(hosts.addresses(b"same.test").count(), 0);
        }
    }

    #[test]
    fn source_removal_preserves_forward_rotation_and_real_name_ancestor_takeover() {
        let mut hosts = Hosts::new();
        for (source, address) in [(1, "192.0.2.1"), (2, "192.0.2.2"), (3, "192.0.2.3")] {
            hosts.insert(
                b"one.records.test".to_vec(),
                address.parse().unwrap(),
                0,
                source,
            );
        }
        hosts.lookup(b"one.records.test", Some(false), false);
        assert_eq!(hosts.remove_uid(1), 1);
        let addresses: Vec<_> = hosts
            .addresses(b"one.records.test")
            .map(|host| host.address)
            .collect();
        assert_eq!(
            addresses,
            [
                "192.0.2.3".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse().unwrap()
            ]
        );
        assert!(hosts.name_exists(b"records.test"));
        hosts.insert(b"records.test".to_vec(), "192.0.2.4".parse().unwrap(), 0, 4);
        hosts.remove_uid(4);
        assert!(!hosts.name_exists(b"records.test"));
    }

    #[test]
    fn canonical_names_preserve_c_edge_cases() {
        assert_eq!(canonicalise(b"Name."), Some(b"Name".to_vec()));
        assert_eq!(canonicalise(b"."), Some(Vec::new()));
        assert_eq!(canonicalise(b"a..b"), Some(b"a..b".to_vec()));
        assert_eq!(canonicalise(b".."), Some(b".".to_vec()));
        assert_eq!(canonicalise(b"a b"), Some(b"a b".to_vec()));
        for name in [&b""[..], b" ", b"a\x7f", b"\xff"] {
            assert_eq!(canonicalise(name), None);
        }
    }

    #[test]
    fn expanded_first_name_owns_reverse_duplicates_still_count() {
        let mut hosts = Hosts::new();
        let stats = hosts.read(
            b"192.0.2.1 First alias\n192.0.2.1 First\n2001:db8::1 v6\n",
            1,
            20,
            true,
            |_| Some(b"test".to_vec()),
        );
        assert_eq!(stats.accepted, 8);
        assert_eq!(stats.inserted, 6);
        assert_eq!(
            hosts.reverse("192.0.2.1".parse().unwrap()).unwrap().name,
            b"First.test"
        );
        assert!(hosts.name_exists(b"TEST"));
        assert_eq!(hosts.lookup(b"FIRST", Some(false), true)[0].ttl, 20);
    }

    #[test]
    fn comments_bad_lines_nul_and_dot_disable_expansion() {
        let mut hosts = Hosts::new();
        let stats = hosts.read(
            b"bad example\n192.0.2.1 host.#comment\n192.0.2.2 mixed\0tail\n192.0.2.3 \xff\n",
            1,
            0,
            true,
            |_| Some(b"test".to_vec()),
        );
        assert_eq!(stats.bad_addresses, 1);
        assert_eq!(stats.bad_names, 1);
        assert_eq!(stats.accepted, 3);
        assert!(!hosts.name_exists(b"host.test"));
        assert!(hosts.name_exists(b"mixed.test"));
    }

    #[test]
    fn streaming_errors_keep_token_count_and_line_numbers_across_chunks() {
        struct Chunks<'a>(&'a [u8]);
        impl Read for Chunks<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                let length = self.0.len().min(output.len()).min(31);
                output[..length].copy_from_slice(&self.0[..length]);
                self.0 = &self.0[length..];
                Ok(length)
            }
        }
        let mut input =
            b"\n# skip\n192.0.2.1 good \xff \x01 last\nbad ignored\n192.0.2.2 ".to_vec();
        input.extend(std::iter::repeat_n(b'a', 100_000));
        input.extend_from_slice(b" final\n192.0.2.3 \xff");
        let mut errors = Vec::new();
        let mut hosts = Hosts::new();
        let stats = hosts.read_from_with_diagnostics(
            Chunks(&input),
            1,
            0,
            false,
            |_| None,
            |line, address| errors.push((line, address)),
        );
        assert_eq!(
            errors,
            [(3, false), (3, false), (4, true), (5, false), (6, false)]
        );
        assert_eq!(stats.bad_names, 4);
        assert_eq!(stats.bad_addresses, 1);
        assert_eq!(stats.accepted, 3);
        for name in [b"good".as_slice(), b"last", b"final"] {
            assert!(hosts.name_exists(name));
        }
    }

    #[test]
    fn multi_address_order_rotates_after_current_lookup() {
        let mut hosts = Hosts::new();
        hosts.read(
            b"192.0.2.1 host\n192.0.2.2 host\n192.0.2.3 host\n",
            1,
            0,
            false,
            |_| None,
        );
        let first = |records: Vec<&Host>| records[0].address.to_string();
        assert_eq!(
            first(hosts.lookup(b"host", Some(false), false)),
            "192.0.2.2"
        );
        assert_eq!(
            first(hosts.lookup(b"host", Some(false), false)),
            "192.0.2.1"
        );
        assert_eq!(first(hosts.lookup(b"host", Some(false), true)), "192.0.2.3");
        assert_eq!(first(hosts.lookup(b"host", Some(false), true)), "192.0.2.3");
    }

    #[test]
    fn readonly_addresses_do_not_change_round_robin_state() {
        let mut hosts = Hosts::new();
        hosts.read(
            b"192.0.2.1 host\n192.0.2.2 host\n192.0.2.3 host\n",
            1,
            20,
            false,
            |_| None,
        );
        let before: Vec<_> = hosts.addresses(b"HOST").map(|host| host.address).collect();
        let again: Vec<_> = hosts.addresses(b"host").map(|host| host.address).collect();
        assert_eq!(before, again);
        assert_eq!(
            before,
            hosts
                .lookup(b"host", Some(false), false)
                .iter()
                .map(|host| host.address)
                .collect::<Vec<_>>()
        );
    }
}
