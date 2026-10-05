//! Local hosts ingestion, traced to cache.c:1322–1545 and util.c:135–295.
//! The hosts/config generation is separate from dynamic DNS and DHCP records;
//! reloading it cannot accidentally discard leases.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Exact no-IDN check_name/canonicalise behavior. Preserve case, strip one
/// trailing dot, allow printable ASCII (including internal empty labels).
pub fn canonicalise(input: &[u8]) -> Option<Vec<u8>> {
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
    (nonwhite && wire + label + 2 <= 255).then(|| input.to_vec())
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
}

/// One reload generation. Address and name indexes remain live after bulk
/// load; C discards its bulk reverse index and scans every bucket for PTR.
#[derive(Clone, Default)]
pub struct Hosts {
    entries: Vec<Host>,
    sources: HashMap<u32, Vec<u8>>,
    read_reports: Vec<(u32, usize)>,
    forward: HashMap<Vec<u8>, Vec<usize>>,
    reverse: HashMap<IpAddr, usize>,
    non_terminals: HashSet<Vec<u8>>,
    no_round_robin: bool,
}

impl Hosts {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn entries(&self) -> &[Host] {
        &self.entries
    }

    /// Keep the loader's actual file identity beside this immutable generation.
    pub fn set_source_name(&mut self, source: u32, name: Vec<u8>) {
        self.sources.insert(source, name);
    }

    pub fn source_name(&self, source: u32) -> Option<&[u8]> {
        self.sources
            .get(&source)
            .map(Vec::as_slice)
            .or((source == 0).then_some(b"/etc/hosts".as_slice()))
    }

    /// Completed read_hostsfile calls, in loader order. The owner emits their
    /// startup/reload notices, then clears this finite generation metadata.
    pub fn take_read_reports(&mut self) -> Vec<(u32, usize)> {
        std::mem::take(&mut self.read_reports)
    }

    /// Current static address order without the lookup/round-robin mutation.
    pub fn addresses(&self, name: &[u8]) -> impl Iterator<Item = &Host> {
        self.forward
            .get(&name.to_ascii_lowercase())
            .into_iter()
            .flatten()
            .map(|&id| &self.entries[id])
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
        // C duplicate detection calls cache_find_by_name, which performs its
        // usual round-robin mutation even while bulk-loading hosts files.
        if self
            .lookup(&name, Some(address.is_ipv6()), false)
            .iter()
            .any(|host| host.address == address)
        {
            return false;
        }
        let key = name.to_ascii_lowercase();
        // make_non_terminals deletes an empty ancestor when a real name takes
        // its place. Deleting that later real entry does not restore it.
        self.non_terminals.remove(&key);
        let indices = self.forward.entry(key.clone()).or_default();
        let id = self.entries.len();
        let reverse =
            if let std::collections::hash_map::Entry::Vacant(v) = self.reverse.entry(address) {
                v.insert(id);
                true
            } else {
                false
            };
        // cache_hash keeps reverse entries before non-reverse ones, and
        // preserves insertion order for identical name/flag groups.
        let at = if reverse {
            indices
                .iter()
                .position(|&id| !self.entries[id].reverse)
                .unwrap_or(indices.len())
        } else {
            indices.len()
        };
        indices.insert(at, id);
        for (index, &byte) in key.iter().enumerate() {
            if byte == b'.' {
                self.non_terminals.insert(key[index + 1..].to_vec());
            }
        }
        self.entries.push(Host {
            name,
            address,
            ttl,
            source,
            configured,
            reverse,
        });
        true
    }

    pub fn reverse(&self, address: IpAddr) -> Option<&Host> {
        self.reverse.get(&address).map(|&id| &self.entries[id])
    }

    /// cache_remove_uid removes this path's accepted entries, without reloading
    /// other paths or promoting their previously suppressed PTR ownership.
    pub fn remove_uid(&mut self, source: u32) -> usize {
        let before = self.entries.len();
        let mut relocated = vec![None; before];
        let mut old = 0;
        let mut new = 0;
        self.entries.retain(|entry| {
            let keep = entry.source != source;
            if keep {
                relocated[old] = Some(new);
                new += 1;
            }
            old += 1;
            keep
        });
        self.forward.retain(|_, indices| {
            *indices = indices.iter().filter_map(|&id| relocated[id]).collect();
            !indices.is_empty()
        });
        self.reverse.retain(|_, id| {
            if let Some(next) = relocated[*id] {
                *id = next;
                true
            } else {
                false
            }
        });
        // Fresh C non-terminals have their own zero UID; their ancestor names
        // are not reconstructed from remaining address records on removal.
        before - new
    }

    pub fn name_exists(&self, name: &[u8]) -> bool {
        let key = name.to_ascii_lowercase();
        self.forward.contains_key(&key) || self.non_terminals.contains(&key)
    }

    /// Returns the current order, then rotates the first matching flags group
    /// for the next call, as cache_find_by_name does. `ipv6=None` means both.
    pub fn lookup(&mut self, name: &[u8], ipv6: Option<bool>, no_round_robin: bool) -> Vec<&Host> {
        let Some(indices) = self.forward.get_mut(&name.to_ascii_lowercase()) else {
            return Vec::new();
        };
        let selected: Vec<_> = indices
            .iter()
            .copied()
            .filter(|&id| ipv6.is_none_or(|v| self.entries[id].address.is_ipv6() == v))
            .collect();
        if !no_round_robin && !self.no_round_robin && selected.len() > 1 {
            let reverse = self.entries[selected[0]].reverse;
            let positions: Vec<_> = indices
                .iter()
                .enumerate()
                .filter_map(|(pos, &id)| {
                    (self.entries[id].reverse == reverse
                        && ipv6.is_none_or(|v| self.entries[id].address.is_ipv6() == v))
                    .then_some(pos)
                })
                .collect();
            if positions.len() > 1 {
                let first = indices[positions[0]];
                for pair in positions.windows(2) {
                    indices[pair[0]] = indices[pair[1]];
                }
                indices[*positions.last().unwrap()] = first;
            }
        }
        selected.into_iter().map(|id| &self.entries[id]).collect()
    }

    /// The caller opens the file and records any I/O errors before this method.
    /// `domain` implements get_domain/get_domain6 (including address ranges).
    pub fn read(
        &mut self,
        input: &[u8],
        source: u32,
        ttl: u32,
        expand: bool,
        mut domain: impl FnMut(IpAddr) -> Option<Vec<u8>>,
    ) -> ReadStats {
        let mut stats = ReadStats::default();
        for line in input.split(|&b| b == b'\n') {
            let line = line.split(|&b| b == b'#').next().unwrap_or_default();
            let mut tokens = line
                .split(|b| b.is_ascii_whitespace())
                .filter(|v| !v.is_empty());
            let Some(address) = tokens.next() else {
                continue;
            };
            // gettok retains at most MAXDNAMESTR - 1 = 502 bytes, then C
            // consumers see the prefix before an embedded NUL.
            let token = |v: &[u8]| {
                v[..v.len().min(502)]
                    .split(|&b| b == 0)
                    .next()
                    .unwrap_or_default()
                    .to_vec()
            };
            let address = token(address);
            let Some(address) = std::str::from_utf8(&address)
                .ok()
                .and_then(|v| v.parse::<IpAddr>().ok())
            else {
                stats.bad_addresses += 1;
                continue;
            };
            let suffix = domain(address);
            for value in tokens {
                let value = token(value);
                let fqdn = value.contains(&b'.');
                let Some(name) = canonicalise(&value) else {
                    stats.bad_names += 1;
                    continue;
                };
                if expand && !fqdn {
                    if let Some(suffix) = &suffix {
                        let mut expanded = name.clone();
                        expanded.push(b'.');
                        expanded.extend_from_slice(suffix);
                        stats.accepted += 1;
                        stats.inserted += usize::from(
                            self.insert_with_origin(expanded, address, ttl, source, false),
                        );
                    }
                }
                stats.accepted += 1;
                stats.inserted +=
                    usize::from(self.insert_with_origin(name, address, ttl, source, false));
            }
        }
        self.read_reports.push((source, stats.accepted));
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
