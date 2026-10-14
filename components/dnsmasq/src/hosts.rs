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
    forward: HashMap<Vec<u8>, Vec<usize>>,
    reverse: HashMap<IpAddr, usize>,
    non_terminals: HashSet<Vec<u8>>,
}

// Stable entry IDs partition query order into bounded copy-on-write pages.
// A TCP snapshot copies the page handles; its first mutation copies at most
// this many names' orders, irrespective of how many names the parent queried.
// There is no chain of historical deltas to retain after clients disconnect.
const ROTATION_PAGE_ENTRIES: usize = 64;
type RotationPage = HashMap<usize, Vec<usize>>;

#[derive(Clone, Default)]
struct RotationPages {
    pages: Vec<Snapshot<RotationPage>>,
    populated: bool,
}

impl RotationPages {
    fn is_empty(&self) -> bool {
        !self.populated
    }

    fn get(&self, key: &usize) -> Option<&Vec<usize>> {
        self.pages.get(key / ROTATION_PAGE_ENTRIES)?.get(key)
    }

    fn snapshot(&mut self) -> Self {
        Self {
            pages: self.pages.iter_mut().map(Snapshot::snapshot).collect(),
            populated: self.populated,
        }
    }

    fn page_mut(&mut self, key: usize) -> Result<&mut RotationPage, TryReserveError> {
        let page_id = key / ROTATION_PAGE_ENTRIES;
        if page_id >= self.pages.len() {
            self.pages.try_reserve(page_id + 1 - self.pages.len())?;
            self.pages.resize_with(page_id + 1, Snapshot::default);
        }
        let page = &mut self.pages[page_id];
        if page.get_mut().is_none() {
            let mut copy = HashMap::new();
            copy.try_reserve(page.len())?;
            for (&id, indices) in page.iter() {
                copy.insert(id, try_copy(indices)?);
            }
            *page = Snapshot::Owned(copy);
        }
        Ok(page.get_mut().unwrap())
    }
}

/// One reload generation. TCP children share its records and indexes, retaining
/// their accepted generation after HUP. Only queried multi-address names need
/// private ordering pages; querying a single-address name never copies a page.
#[derive(Clone, Default)]
pub struct Hosts {
    records: Snapshot<HostsRecords>,
    rotations: RotationPages,
    no_round_robin: bool,
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
    pub fn entries(&self) -> &[Host] {
        &self.records.entries
    }

    /// Dropping this owner cannot release records retained by a TCP snapshot.
    pub fn has_shared_records(&self) -> bool {
        matches!(&self.records, Snapshot::Shared(records) if Arc::strong_count(records) > 1)
    }

    /// Like fork's copy-on-write view: snapshot both the accepted generation
    /// and its current round-robin order without copying any hosts records.
    pub fn tcp_snapshot(&mut self) -> Self {
        Self {
            records: self.records.snapshot(),
            rotations: self.rotations.snapshot(),
            no_round_robin: self.no_round_robin,
        }
    }

    /// Structural changes fork the generation, folding private query order
    /// into its indexes. All copying remains fallible for hostsdir ingestion.
    fn writable_records(&mut self) -> Result<&mut HostsRecords, TryReserveError> {
        if !self.rotations.is_empty() || self.records.get_mut().is_none() {
            *self = self.try_clone()?;
        }
        Ok(self.records.get_mut().unwrap())
    }

    /// Keep the loader's actual file identity beside this immutable generation.
    pub fn set_source_name(&mut self, source: u32, name: Vec<u8>) {
        let Ok(records) = self.writable_records() else {
            return;
        };
        if records.sources.try_reserve(1).is_ok() {
            records.sources.insert(source, name);
        }
    }

    pub fn source_name(&self, source: u32) -> Option<&[u8]> {
        self.records
            .sources
            .get(&source)
            .map(Vec::as_slice)
            .or((source == 0).then_some(b"/etc/hosts".as_slice()))
    }

    fn ordered<'a>(&'a self, indices: &'a [usize]) -> &'a [usize] {
        indices
            .first()
            .and_then(|id| self.rotations.get(id))
            .map_or(indices, Vec::as_slice)
    }

    /// Current static address order without the lookup/round-robin mutation.
    pub fn addresses(&self, name: &[u8]) -> impl Iterator<Item = &Host> {
        self.records
            .forward
            .get(&name.to_ascii_lowercase())
            .into_iter()
            .flat_map(|indices| self.ordered(indices))
            .map(|&id| &self.records.entries[id])
    }

    pub fn set_round_robin(&mut self, enabled: bool) {
        self.no_round_robin = !enabled;
    }

    /// Preserves first-address PTR ownership and same-name/address deduplication
    /// across all input files in this generation.
    pub fn insert(&mut self, name: Vec<u8>, address: IpAddr, ttl: u32, source: u32) -> bool {
        self.insert_with_origin(name, address, ttl, source, source == 1)
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
        let no_round_robin = self.no_round_robin;
        let records = self.writable_records()?;
        // Duplicate lookup rotates the same flags group as cache_find_by_name,
        // but must not allocate a temporary result/positions Vec while loading.
        if let Some(indices) = records.forward.get_mut(&key) {
            let duplicate = indices
                .iter()
                .any(|&id| records.entries[id].address == address);
            if !no_round_robin {
                rotate_indices(indices, &records.entries, Some(address.is_ipv6()));
            }
            if duplicate {
                return Ok(false);
            }
        }
        // Reserve all mandatory indexes before publishing any new entry. An
        // unsuccessful reservation leaves existing entries and PTR ownership live.
        records.entries.try_reserve(1)?;
        records.reverse.try_reserve(1)?;
        records.forward.try_reserve(1)?;
        let mut fresh_indices = Vec::new();
        if let Some(indices) = records.forward.get_mut(&key) {
            indices.try_reserve(1)?;
        } else {
            fresh_indices.try_reserve(1)?;
        }
        let reverse = !records.reverse.contains_key(&address);
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
        let indices = records.forward.entry(key).or_insert(fresh_indices);
        let id = records.entries.len();
        let at = if reverse {
            indices
                .iter()
                .position(|&id| !records.entries[id].reverse)
                .unwrap_or(indices.len())
        } else {
            indices.len()
        };
        indices.insert(at, id);
        if reverse {
            records.reverse.insert(address, id);
        }
        records.entries.push(Host {
            name,
            address,
            ttl,
            source,
            configured,
            reverse,
        });
        Ok(true)
    }

    /// Preserve both published owner views if a replacement snapshot cannot be
    /// copied. In particular, do not use derived Clone after a fallible read.
    pub fn try_clone(&self) -> Result<Self, TryReserveError> {
        let mut copy = HostsRecords::default();
        let records = &self.records;
        copy.entries.try_reserve_exact(records.entries.len())?;
        copy.sources.try_reserve(records.sources.len())?;
        copy.forward.try_reserve(records.forward.len())?;
        copy.reverse.try_reserve(records.reverse.len())?;
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
        for (name, indices) in &records.forward {
            copy.forward
                .insert(try_copy(name)?, try_copy(self.ordered(indices))?);
        }
        copy.reverse
            .extend(records.reverse.iter().map(|(&address, &id)| (address, id)));
        for name in &records.non_terminals {
            copy.non_terminals.insert(try_copy(name)?);
        }
        Ok(Self {
            records: Snapshot::Owned(copy),
            rotations: RotationPages::default(),
            no_round_robin: self.no_round_robin,
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
        let mut replacement = self.try_clone().map_err(|_| ())?;
        let removed = replacement.try_remove_uid(source).map_err(|_| ())?;
        let name = try_copy(source_name).map_err(|_| ())?;
        let owned = replacement.records.get_mut().unwrap();
        owned.sources.try_reserve(1).map_err(|_| ())?;
        owned.sources.insert(source, name);
        for (name, address) in records {
            let mut allocation_failed = false;
            replacement
                .try_insert(name, address, ttl, source, source == 1, &mut allocation_failed)
                .map_err(|_| ())?;
            if allocation_failed {
                return Err(());
            }
        }
        Ok((replacement, removed))
    }

    pub fn reverse(&self, address: IpAddr) -> Option<&Host> {
        self.records
            .reverse
            .get(&address)
            .map(|&id| &self.records.entries[id])
    }

    /// cache_remove_uid removes this path's accepted entries, without reloading
    /// other paths or promoting their previously suppressed PTR ownership.
    pub fn remove_uid(&mut self, source: u32) -> usize {
        self.try_remove_uid(source).unwrap_or(0)
    }

    pub fn try_remove_uid(&mut self, source: u32) -> Result<usize, TryReserveError> {
        let before = self.records.entries.len();
        let mut relocated = Vec::new();
        relocated.try_reserve_exact(before)?;
        relocated.resize(before, None);
        let records = self.writable_records()?;
        let mut old = 0;
        let mut new = 0;
        records.entries.retain(|entry| {
            let keep = entry.source != source;
            if keep {
                relocated[old] = Some(new);
                new += 1;
            }
            old += 1;
            keep
        });
        records.forward.retain(|_, indices| {
            indices.retain_mut(|id| {
                if let Some(next) = relocated[*id] {
                    *id = next;
                    true
                } else {
                    false
                }
            });
            !indices.is_empty()
        });
        records.reverse.retain(|_, id| {
            if let Some(next) = relocated[*id] {
                *id = next;
                true
            } else {
                false
            }
        });
        // Fresh C non-terminals have their own zero UID; their ancestor names
        // are not reconstructed from remaining address records on removal.
        Ok(before - new)
    }

    pub fn name_exists(&self, name: &[u8]) -> bool {
        let key = name.to_ascii_lowercase();
        self.records.forward.contains_key(&key) || self.records.non_terminals.contains(&key)
    }

    fn rotate_shared(&mut self, key: usize, initial: &[usize], ipv6: Option<bool>) {
        // A failed page reservation preserves the last valid order and answer.
        let Ok(rotations) = self.rotations.page_mut(key) else {
            return;
        };
        if !rotations.contains_key(&key) {
            let Ok(indices) = try_copy(initial) else {
                return;
            };
            if rotations.try_reserve(1).is_err() {
                return;
            }
            rotations.insert(key, indices);
        }
        rotate_indices(
            rotations.get_mut(&key).unwrap(),
            &self.records.entries,
            ipv6,
        );
        self.rotations.populated = true;
    }

    /// Returns the current order, then rotates the first matching flags group
    /// for the next call, as cache_find_by_name does. `ipv6=None` means both.
    pub fn lookup(&mut self, name: &[u8], ipv6: Option<bool>, no_round_robin: bool) -> Vec<&Host> {
        if self.records.forward.is_empty() {
            return Vec::new();
        }
        let canonical;
        let key = if name.iter().any(u8::is_ascii_uppercase) {
            canonical = name.to_ascii_lowercase();
            canonical.as_slice()
        } else {
            name
        };
        let Some(indices) = self.records.forward.get(key) else {
            return Vec::new();
        };
        let rotation_key = indices[0];
        let ordered = self.ordered(indices);
        let selected: Vec<_> = ordered
            .iter()
            .copied()
            .filter(|&id| ipv6.is_none_or(|v| self.records.entries[id].address.is_ipv6() == v))
            .collect();
        if !no_round_robin && !self.no_round_robin && selected.len() > 1 {
            if self.rotations.is_empty() && self.records.get_mut().is_some() {
                let records = self.records.get_mut().unwrap();
                rotate_indices(
                    records.forward.get_mut(key).unwrap(),
                    &records.entries,
                    ipv6,
                );
            } else {
                // The initial index remains immutable while shared; copy only
                // this name's order before taking the mutable view.
                let initial = match try_copy(self.ordered(&self.records.forward[key])) {
                    Ok(indices) => indices,
                    Err(_) => {
                        return selected
                            .into_iter()
                            .map(|id| &self.records.entries[id])
                            .collect();
                    }
                };
                self.rotate_shared(rotation_key, &initial, ipv6);
            }
        }
        selected
            .into_iter()
            .map(|id| &self.records.entries[id])
            .collect()
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
        let mut consume = |parser: &mut HostsParser, bytes: &[u8]| {
            parser.feed(
                bytes,
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
        let mut stats = parser.stats;
        stats.inserted = inserted;
        stats.allocation_failed = failed;
        stats
    }
}

// Rotate only the first matching address-family/reverse flags group.
fn rotate_indices(indices: &mut [usize], entries: &[Host], ipv6: Option<bool>) {
    let matches = |id: usize| ipv6.is_none_or(|v| entries[id].address.is_ipv6() == v);
    let Some(first_pos) = indices.iter().position(|&id| matches(id)) else {
        return;
    };
    let first = indices[first_pos];
    let reverse = entries[first].reverse;
    let mut previous = first_pos;
    for pos in first_pos + 1..indices.len() {
        let id = indices[pos];
        if matches(id) && entries[id].reverse == reverse {
            indices[previous] = id;
            previous = pos;
        }
    }
    indices[previous] = first;
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
        mut domain: impl FnMut(IpAddr) -> Option<Vec<u8>>,
        mut emit: impl FnMut(Vec<u8>, IpAddr),
        mut invalid: impl FnMut(usize, bool),
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
            assert_eq!(child.rotations.pages.len(), parent.rotations.pages.len());
            let private: Vec<_> = child
                .rotations
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
            assert_eq!(private.len(), 1);
            assert!(private[0].len() <= ROTATION_PAGE_ENTRIES);
            assert!(std::ptr::eq(child.entries(), parent.entries()));
        }
        drop((children, seed));
        for page in &parent.rotations.pages {
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
            assert!(parent.rotations.pages.len() <= 256usize.div_ceil(ROTATION_PAGE_ENTRIES));
        }
        drop(old);
        for page in &parent.rotations.pages {
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
