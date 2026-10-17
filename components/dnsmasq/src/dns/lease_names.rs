//! DHCP DNS publication generation, from lease.c:564-620 and cache.c:1742-1911.
//!
//! DHCP publication replaces this source, not hosts or the forwarded cache.
//! The caller publishes the completed generation before transmitting its ACK.
//! Every input is retained, including names hidden by hosts, so SIGHUP can
//! rebuild it against the new hosts generation without losing lease state.

use super::cache::StalePolicy;
use crate::config::records::Cname;
use crate::dhcp::persistence::DnsLeaseRecord;
use crate::hosts::{name_hash_bucket, Hosts};
use std::borrow::Cow;
use std::collections::{hash_map::Entry, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub struct LeasePolicy {
    pub local_ttl: u32,
    pub dhcp_ttl: Option<u32>,
    pub stale: StalePolicy,
    pub no_round_robin: bool,
}

impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            local_ttl: 0,
            dhcp_ttl: None,
            stale: StalePolicy::Disabled,
            no_round_robin: false,
        }
    }
}

impl LeasePolicy {
    fn live(self, expires: Option<i64>, now: i64) -> bool {
        let Some(expires) = expires else {
            return true;
        };
        match self.stale {
            StalePolicy::Forever => true,
            StalePolicy::Seconds(seconds) if seconds != 0 => {
                now.wrapping_sub(expires) < i64::from(seconds)
            }
            _ => now.wrapping_sub(expires) < 0,
        }
    }

    fn ttl(self, expires: Option<i64>, now: i64) -> u32 {
        let configured = self.dhcp_ttl.unwrap_or(self.local_ttl);
        expires.map_or(configured, |expires| {
            // crec_ttl is capped by lease duration. With use-stale-cache C
            // also retains DHCP entries and writes a negative difference as
            // a wire u32; lease pruning normally removes them first.
            // C first narrows its configured unsigned long into signed int.
            // Values above INT_MAX therefore bypass a positive lease cap.
            expires.wrapping_sub(now).min(i64::from(configured as i32)) as u32
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockerKind {
    Ipv4,
    Ipv6,
    Cname,
}

/// A local record that can stop C's cache_scan_free before a forwarded entry.
/// Reverse records precede ordinary records; immortal non-reverse records
/// follow them. A dynamic CNAME conflicts with either address family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationBlocker {
    pub kind: BlockerKind,
    pub reverse: bool,
    pub immortal: bool,
}

pub struct ForwardPublication<'a> {
    pub name: &'a [u8],
    pub no_round_robin: bool,
    pub blockers: &'a [PublicationBlocker],
}

/// The small mutable boundary between a new DHCP generation and the existing
/// forwarded cache. Implementations must preserve unrelated names/types and
/// NXDOMAIN records (which have neither F_IPV4 nor F_CNAME).
pub trait PublicationCache {
    /// Called once immediately before the first actual address insertion in
    /// a publication. Empty replacement or statically suppressed records do
    /// not reuse a C configuration-cache entry and do not reach this hook.
    fn first_lease_entry(&mut self) {}

    /// Called even when static addresses will later suppress this lease name.
    /// Select the same IPv4/CNAME trigger as cache_find_by_name at time zero,
    /// then apply cache_scan_free until the first conflicting local blocker.
    fn prepare_name(&mut self, publication: ForwardPublication<'_>);

    /// C looks up at time zero. A positive forwarded PTR keeps ownership;
    /// negative reverse entries are removed and allow the lease to own PTR.
    /// Local hosts and earlier lease owners are checked before this method.
    fn reverse_owned(&mut self, address: Ipv4Addr) -> bool;
}

/// Appropriate only when no forwarded cache is present, e.g. initial startup.
impl PublicationCache for () {
    fn prepare_name(&mut self, _: ForwardPublication<'_>) {}
    fn reverse_owned(&mut self, _: Ipv4Addr) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseInput {
    pub name: Arc<[u8]>,
    pub address: Ipv4Addr,
    pub expires: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseName {
    pub name: Arc<[u8]>,
    pub address: Ipv4Addr,
    pub expires: Option<i64>,
    /// Publication-time ownership. Expiring a different PTR owner does not
    /// promote this entry; only a subsequent complete publication does.
    pub reverse: bool,
}

impl LeaseName {
    pub fn ttl(&self, now: i64, policy: LeasePolicy) -> u32 {
        policy.ttl(self.expires, now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationWarning {
    /// C emits this warning but still permits the DHCP address entry.
    ConfiguredCname { name: Vec<u8>, address: Ipv4Addr },
    StaticAddress {
        name: Vec<u8>,
        address: Ipv4Addr,
        configured_address: Ipv4Addr,
        source: u32,
    },
}

#[derive(Clone, Default)]
pub struct LeaseNames {
    inputs: Vec<LeaseInput>,
    entries: Vec<LeaseName>,
    /// Per-reader cache visibility. Arc copy-on-write preserves the state a
    /// TCP child inherited while expiry removals remain local to that reader.
    active: Vec<bool>,
    forward: HashMap<Arc<[u8]>, LeaseIds>,
    reverse: HashMap<Ipv4Addr, usize>,
    non_terminals: HashMap<Vec<u8>, Option<i64>>,
    warnings: Vec<PublicationWarning>,
    policy: LeasePolicy,
}

#[derive(Clone)]
enum LeaseIds {
    One(usize),
    Many(Vec<usize>),
}

impl LeaseIds {
    fn as_slice(&self) -> &[usize] {
        match self {
            Self::One(id) => std::slice::from_ref(id),
            Self::Many(ids) => ids,
        }
    }

    fn insert(&mut self, at: usize, id: usize) {
        match self {
            Self::One(previous) => {
                assert!(at <= 1);
                let pair = if at == 0 { [id, *previous] } else { [*previous, id] };
                let mut ids = Vec::new();
                ids.push(pair[0]);
                ids.push(pair[1]);
                *self = Self::Many(ids);
            }
            Self::Many(ids) => ids.insert(at, id),
        }
    }
}

impl LeaseNames {
    /// `records` is lease_update_dns order: newest lease first, FQDN before
    /// short name. fqdn-only filtering belongs to the lease publisher.
    pub fn build(
        records: &[DnsLeaseRecord<'_>],
        hosts: &mut Hosts,
        cnames: &[Cname],
        policy: LeasePolicy,
        cache: &mut impl PublicationCache,
    ) -> Self {
        Self::build_reusing_names(records, hosts, cnames, policy, cache, None)
    }

    /// Reuse only immutable, byte-identical input names. Rebuild every visible
    /// entry and repeat all publication side effects, including on expiry-only
    /// renewals. An older TCP generation can keep sharing these name bytes.
    pub(crate) fn build_reusing_names(
        records: &[DnsLeaseRecord<'_>],
        hosts: &mut Hosts,
        cnames: &[Cname],
        policy: LeasePolicy,
        cache: &mut impl PublicationCache,
        previous: Option<&Self>,
    ) -> Self {
        let mut result = Self {
            inputs: records
                .iter()
                .enumerate()
                .map(|(index, record)| LeaseInput {
                    name: previous
                        .and_then(|names| names.inputs.get(index))
                        .filter(|input| input.name.as_ref() == record.name)
                        .map_or_else(|| Arc::from(record.name), |input| Arc::clone(&input.name)),
                    address: record.address,
                    expires: record.expires,
                })
                .collect(),
            policy,
            ..Self::default()
        };
        for (index, record) in records.iter().enumerate() {
            result.add(*record, index, hosts, cnames, cache);
        }
        result
    }

    pub fn rebuild(
        &self,
        hosts: &mut Hosts,
        cnames: &[Cname],
        cache: &mut impl PublicationCache,
    ) -> Self {
        let records: Vec<_> = self
            .inputs
            .iter()
            .map(|record| DnsLeaseRecord {
                name: &record.name,
                address: record.address,
                expires: record.expires,
            })
            .collect();
        Self::build_reusing_names(&records, hosts, cnames, self.policy, cache, Some(self))
    }

    pub fn inputs(&self) -> &[LeaseInput] {
        &self.inputs
    }
    /// Original publication records; `active_entries` excludes cache entries
    /// removed by a later lookup in this reader.
    pub fn entries(&self) -> &[LeaseName] {
        &self.entries
    }
    pub fn active_entries(&self) -> impl Iterator<Item = &LeaseName> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(id, entry)| self.active[id].then_some(entry))
    }
    pub fn warnings(&self) -> &[PublicationWarning] {
        &self.warnings
    }
    pub fn policy(&self) -> LeasePolicy {
        self.policy
    }

    pub fn non_terminals(&self) -> impl Iterator<Item = (&[u8], Option<i64>)> {
        self.non_terminals
            .iter()
            .map(|(name, &expiry)| (name.as_slice(), expiry))
    }

    /// Address presence does not answer other types locally. In particular,
    /// an IPv4 lease alone must not synthesize an AAAA NODATA response.
    pub fn lookup(&self, name: &[u8], now: i64) -> impl Iterator<Item = &LeaseName> {
        (!self.forward.is_empty())
            .then(|| self.forward.get(name_key(name).as_ref()))
            .flatten()
            .into_iter()
            .flat_map(|ids| ids.as_slice())
            .filter_map(move |&id| {
                let entry = &self.entries[id];
                (self.active[id] && self.policy.live(entry.expires, now)).then_some(entry)
            })
    }

    /// cache_scan_free checks matching local blockers before its expiry
    /// removal. A still-hashed expired lease therefore blocks insertion until
    /// an actual lookup (or publication) has removed it.
    pub(crate) fn active_lookup(&self, name: &[u8]) -> impl Iterator<Item = &LeaseName> {
        self.forward
            .get(name_key(name).as_ref())
            .into_iter()
            .flat_map(|ids| ids.as_slice())
            .filter_map(|&id| self.active[id].then_some(&self.entries[id]))
    }

    pub fn reverse(&self, address: Ipv4Addr, now: i64) -> Option<&LeaseName> {
        let &id = self.reverse.get(&address)?;
        let entry = &self.entries[id];
        (self.active[id] && self.policy.live(entry.expires, now)).then_some(entry)
    }

    /// check_for_local_domain / upstream NXDOMAIN conversion only. A live
    /// non-terminal is not a locally answerable empty RRset.
    pub fn name_exists(&self, name: &[u8], now: i64) -> bool {
        let key = name_key(name);
        self.lookup(&key, now).next().is_some()
            || self
                .non_terminals
                .get(key.as_ref())
                .is_some_and(|&expiry| self.policy.live(expiry, now))
    }

    /// Test before Arc::make_mut so an ordinary live lookup does not clone a
    /// generation shared with a TCP child. Presence checks intentionally do
    /// not call this: cache_find_non_terminal does not remove expired data.
    pub(crate) fn has_expired_name(&self, name: &[u8], now: i64) -> bool {
        let key = name_key(name);
        self.forward.get(key.as_ref()).is_some_and(|ids| {
            ids.as_slice().iter()
                .any(|&id| self.active[id] && !self.policy.live(self.entries[id].expires, now))
        }) || self
            .non_terminals
            .get(key.as_ref())
            .is_some_and(|&expiry| !self.policy.live(expiry, now))
    }

    pub(crate) fn expire_name(&mut self, name: &[u8], now: i64) {
        let key = name_key(name);
        if let Some(ids) = self.forward.get(key.as_ref()) {
            for &id in ids.as_slice() {
                if !self.policy.live(self.entries[id].expires, now) {
                    self.active[id] = false;
                }
            }
        }
        if self
            .non_terminals
            .get(key.as_ref())
            .is_some_and(|&expiry| !self.policy.live(expiry, now))
        {
            self.non_terminals.remove(key.as_ref());
        }
    }

    pub(crate) fn has_expired_reverse(&self, now: i64) -> bool {
        self.reverse
            .values()
            .any(|&id| self.active[id] && !self.policy.live(self.entries[id].expires, now))
    }

    /// cache_find_by_addr scans all reverse owners, not just the requested
    /// address. Non-reverse aliases and non-terminals are not pruned here.
    pub(crate) fn expire_reverse(&mut self, now: i64) {
        for &id in self.reverse.values() {
            if !self.policy.live(self.entries[id].expires, now) {
                self.active[id] = false;
            }
        }
    }

    fn add(
        &mut self,
        record: DnsLeaseRecord<'_>,
        input: usize,
        hosts: &mut Hosts,
        cnames: &[Cname],
        cache: &mut impl PublicationCache,
    ) {
        let key = name_key(record.name);
        // Hosts capacity cannot change between the blocker scan and lookup.
        // Keep both scans and the lookup's IPv4-only rotation in their order.
        let host_bucket = name_hash_bucket(record.name, hosts.name_hash_capacity());
        let mut blockers: Vec<_> = hosts
            .addresses_in_bucket(record.name, host_bucket)
            .map(|host| PublicationBlocker {
                kind: if host.address.is_ipv4() {
                    BlockerKind::Ipv4
                } else {
                    BlockerKind::Ipv6
                },
                reverse: host.reverse,
                immortal: true,
            })
            .collect();
        let cname = cnames
            .iter()
            .any(|cname| cname.alias.eq_ignore_ascii_case(record.name));
        if cname {
            blockers.push(PublicationBlocker {
                kind: BlockerKind::Cname,
                reverse: false,
                immortal: true,
            });
            self.warnings.push(PublicationWarning::ConfiguredCname {
                name: record.name.to_vec(),
                address: record.address,
            });
        }
        if let Some(ids) = self.forward.get(key.as_ref()) {
            blockers.extend(ids.as_slice().iter().map(|&id| PublicationBlocker {
                kind: BlockerKind::Ipv4,
                reverse: self.entries[id].reverse,
                immortal: self.entries[id].expires.is_none(),
            }));
        }
        let static_addresses = hosts.lookup_in_bucket(
            record.name, Some(false), self.policy.no_round_robin, host_bucket,
        );
        cache.prepare_name(ForwardPublication {
            name: record.name,
            no_round_robin: self.policy.no_round_robin,
            blockers: &blockers,
        });

        let mut conflict = None;
        for host in static_addresses {
            if let IpAddr::V4(address) = host.address {
                if address == record.address {
                    return; // any same address wins over all mismatched ones
                }
                conflict = Some((address, host.source));
            }
        }
        if let Some((configured_address, source)) = conflict {
            self.warnings.push(PublicationWarning::StaticAddress {
                name: record.name.to_vec(),
                address: record.address,
                configured_address,
                source,
            });
            return;
        }

        let reverse = hosts.reverse(IpAddr::V4(record.address)).is_none()
            && !self.reverse.contains_key(&record.address)
            && !cache.reverse_owned(record.address);
        if self.entries.is_empty() {
            cache.first_lease_entry();
        }
        let id = self.entries.len();
        let expires = record.expires.filter(|&expires| expires != 0);
        let immortal = expires.is_none();
        // Borrowed canonical bytes are identical to the retained input. Mixed
        // case keeps its original spelling and gets a separate lowercase key.
        let forward_key = if matches!(key, Cow::Borrowed(_)) {
            Arc::clone(&self.inputs[input].name)
        } else {
            Arc::from(key.as_ref())
        };
        match self.forward.entry(forward_key) {
            Entry::Vacant(entry) => {
                entry.insert(LeaseIds::One(id));
            }
            Entry::Occupied(mut entry) => {
                let ids = entry.get_mut();
                let current = ids.as_slice();
                // cache_hash: reverse first; mortal before immortal for
                // non-reverse; preserve order within each flags group.
                let mut at = 0;
                if !reverse {
                    while at < current.len() && self.entries[current[at]].reverse {
                        at += 1;
                    }
                    if immortal {
                        while at < current.len() && self.entries[current[at]].expires.is_some() {
                            at += 1;
                        }
                    }
                }
                while at < current.len()
                    && self.entries[current[at]].reverse == reverse
                    && self.entries[current[at]].expires.is_none() == immortal
                {
                    at += 1;
                }
                ids.insert(at, id);
            }
        }
        self.entries.push(LeaseName {
            name: Arc::clone(&self.inputs[input].name),
            address: record.address,
            expires,
            reverse,
        });
        self.active.push(true);
        if reverse {
            self.reverse.insert(record.address, id);
        }
        self.non_terminals.remove(key.as_ref());
        for (index, &byte) in key.iter().enumerate() {
            if byte != b'.' {
                continue;
            }
            let parent = &key[index + 1..];
            // C extends the first existing DHCP record even when it is a
            // real address, not just a synthetic non-terminal.
            if let Some(ids) = self.forward.get(parent) {
                extend_expiry(&mut self.entries[ids.as_slice()[0]].expires, expires);
            } else if let Some(expiry) = self.non_terminals.get_mut(parent) {
                extend_expiry(expiry, expires);
            } else {
                self.non_terminals.insert(parent.to_vec(), expires);
            }
        }
    }
}

fn name_key(name: &[u8]) -> Cow<'_, [u8]> {
    if name.iter().any(u8::is_ascii_uppercase) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

fn extend_expiry(current: &mut Option<i64>, incoming: Option<i64>) {
    if let Some(expiry) = current {
        *current = incoming.map(|incoming| incoming.max(*expiry));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(name: &[u8], address: u8, expires: Option<i64>) -> DnsLeaseRecord<'_> {
        DnsLeaseRecord {
            name,
            address: Ipv4Addr::new(192, 0, 2, address),
            expires,
        }
    }

    #[test]
    fn same_name_entries_keep_reverse_finite_and_immortal_order() {
        let records = [
            input(b"ptr-owner.test", 1, Some(900)),
            input(b"same.test", 1, None),
            input(b"same.test", 2, Some(800)),
            input(b"same.test", 1, Some(700)),
            input(b"same.test", 3, None),
        ];
        let names = LeaseNames::build(&records, &mut Hosts::new(), &[], LeasePolicy::default(), &mut ());
        assert_eq!(names.lookup(b"same.test", 100).map(|entry|
            (entry.address.octets()[3], entry.expires, entry.reverse)
        ).collect::<Vec<_>>(), [
            (3, None, true), (2, Some(800), true),
            (1, Some(700), false), (1, None, false),
        ]);
    }

    #[test]
    fn canonical_index_does_not_change_retained_or_reverse_name_spelling() {
        let records = [input(b"MiXeD.Example", 7, Some(1000))];
        let names = LeaseNames::build(&records, &mut Hosts::new(), &[], LeasePolicy::default(), &mut ());
        for generation in [&names, &names.rebuild(&mut Hosts::new(), &[], &mut ())] {
            assert_eq!(generation.inputs()[0].name.as_ref(), b"MiXeD.Example");
            assert_eq!(generation.lookup(b"mixed.example", 100).next().unwrap().name.as_ref(), b"MiXeD.Example");
            assert_eq!(generation.reverse(records[0].address, 100).unwrap().name.as_ref(), b"MiXeD.Example");
        }
    }

    // Expected cases were first observed using exact C cache.c and
    // rfc1035.c, indexed in docs/dnsmasq/LEASE_NAMES_PHASE.md.
    #[test]
    fn fqdn_owns_ptr_until_expiry_and_parent_is_only_presence() {
        let records = [
            input(b"lease.example", 7, Some(1000)),
            input(b"lease", 7, Some(1000)),
            input(b"other.example", 8, Some(1010)),
        ];
        let policy = LeasePolicy {
            local_ttl: 37,
            ..LeasePolicy::default()
        };
        let names = LeaseNames::build(&records, &mut Hosts::new(), &[], policy, &mut ());
        assert_eq!(
            names.reverse(records[0].address, 999).unwrap().name.as_ref(),
            b"lease.example"
        );
        assert_eq!(
            names
                .lookup(b"LEASE.EXAMPLE", 999)
                .next()
                .unwrap()
                .ttl(999, policy),
            1
        );
        assert!(names.lookup(b"lease.example", 1000).next().is_none());
        assert!(names.reverse(records[0].address, 1000).is_none());
        assert!(names.lookup(b"example", 999).next().is_none());
        assert!(names.name_exists(b"example", 1009));
        assert!(!names.name_exists(b"example", 1010));
    }

    #[test]
    fn suppressed_input_is_retained_for_reload_and_other_family_coexists() {
        let records = [input(b"lease.example", 7, Some(1000))];
        let mut hosts = Hosts::new();
        hosts.insert(
            b"lease.example".to_vec(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            37,
            1,
        );
        let names = LeaseNames::build(&records, &mut hosts, &[], LeasePolicy::default(), &mut ());
        assert_eq!(names.inputs().len(), 1);
        assert!(names.entries().is_empty());
        assert!(matches!(
            names.warnings(),
            [PublicationWarning::StaticAddress { .. }]
        ));
        let mut hosts = Hosts::new();
        hosts.insert(
            b"lease.example".to_vec(),
            "2001:db8::7".parse().unwrap(),
            37,
            1,
        );
        let names = names.rebuild(&mut hosts, &[], &mut ());
        assert_eq!(names.entries().len(), 1);
        assert!(names.entries()[0].reverse);
    }

    #[test]
    fn renamed_retained_lease_publication_preserves_c_post_hup_address_order() {
        use crate::config::dns::DnsConfig;
        use crate::dns::local::configured_hosts_bulk;

        // Exact-image finite/infinite restored-lease HUP controls read these
        // hosts after retaining a.test/a. lease_update_from_configs renames
        // the lease to x before lease_update_dns publishes its new names.
        let fixture = b"192.0.2.2 old.test\n192.0.2.1 x.test\n\
            192.0.3.186 a.test\n192.0.3.185 a.test\n\
            192.0.2.1 y.test\n192.0.2.2 y.test\n";
        let order = |hosts: &Hosts| hosts.addresses(b"a.test")
            .map(|host| host.address.to_string()).collect::<Vec<_>>();
        for expires in [None, Some(1000)] {
            let records = [input(b"a.test", 1, expires), input(b"a", 1, expires)];
            let previous = LeaseNames::build(
                &records, &mut Hosts::new(), &[], LeasePolicy::default(), &mut (),
            );
            let mut hosts = configured_hosts_bulk(
                &DnsConfig::default(), 37, 1497, 1000, 1000, &previous,
            ).unwrap();
            assert!(!hosts.read(fixture, 2, 37, false, |_| None).allocation_failed);
            hosts.finish_bulk();
            let mut premature = hosts.try_clone().unwrap();
            let renamed = [input(b"x.test", 1, expires), input(b"x", 1, expires)];
            let names = LeaseNames::build(
                &renamed, &mut hosts, &[], LeasePolicy::default(), &mut (),
            );
            assert_eq!(order(&hosts), ["192.0.3.186", "192.0.3.185"]);
            assert!(names.lookup(b"a.test", 1).next().is_none());
            assert!(names.lookup(b"x", 1).next().is_some());

            // A speculative rebuild before the provider renames this lease
            // performs an extra lookup of the stale a.test name. Even its
            // rejected address rotates the static RRset; the final x-name
            // publication cannot undo that query side effect.
            let stale = previous.rebuild(&mut premature, &[], &mut ());
            assert!(matches!(stale.warnings(), [PublicationWarning::StaticAddress { .. }]));
            LeaseNames::build(
                &renamed, &mut premature, &[], LeasePolicy::default(), &mut (),
            );
            assert_eq!(order(&premature), ["192.0.3.185", "192.0.3.186"]);
        }
    }

    #[test]
    fn cname_warning_does_not_reject_lease() {
        let cnames = [Cname {
            alias: b"lease.example".to_vec(),
            target: b"target.example".to_vec(),
            ttl: None,
        }];
        let names = LeaseNames::build(
            &[input(b"lease.example", 7, Some(1000))],
            &mut Hosts::new(),
            &cnames,
            LeasePolicy::default(),
            &mut (),
        );
        assert_eq!(names.entries().len(), 1);
        assert!(matches!(
            names.warnings(),
            [PublicationWarning::ConfiguredCname { .. }]
        ));
        assert!(names.entries()[0].reverse);
    }

    #[test]
    fn existing_forwarded_ptr_is_not_replaced_or_later_promoted() {
        struct Cache;
        impl PublicationCache for Cache {
            fn prepare_name(&mut self, _: ForwardPublication<'_>) {}
            fn reverse_owned(&mut self, _: Ipv4Addr) -> bool {
                true
            }
        }
        let names = LeaseNames::build(
            &[input(b"lease.example", 7, Some(1000))],
            &mut Hosts::new(),
            &[],
            LeasePolicy::default(),
            &mut Cache,
        );
        assert_eq!(names.entries().len(), 1);
        assert!(!names.entries()[0].reverse);
        assert!(names.reverse(Ipv4Addr::new(192, 0, 2, 7), 999).is_none());
    }

    #[test]
    fn actual_local_answer_keeps_lease_ttl_and_wrong_type_forwarding() {
        use crate::config::dns::DnsConfig;
        use crate::dns::service::LocalDnsService;
        use crate::dns::wire::{Message, Name, PacketWriter, Section};
        use std::sync::Arc;

        let mut service = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 37, 512);
        service.leases = Arc::new(LeaseNames::build(
            &[input(b"lease.example", 7, Some(1000))],
            &mut service.hosts,
            &[],
            LeasePolicy {
                local_ttl: 37,
                ..LeasePolicy::default()
            },
            &mut (),
        ));
        let query = |name, kind| {
            let mut writer = PacketWriter::new(0x2930, 0x100, 512).unwrap();
            writer
                .question(&Name::from_ascii(name).unwrap(), kind, 1)
                .unwrap();
            writer.finish()
        };
        let wire = service
            .handle_udp_at(&query("lease.example", 1), 999)
            .unwrap()
            .unwrap();
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.header.flags, 0x8580); // exact C baseline
        assert_eq!(message.header.answers, 1);
        let answer = message.records(Section::Answer).next().unwrap();
        assert_eq!(answer.ttl, 1);
        assert_eq!(answer.rdata, &[192, 0, 2, 7]);
        assert!(service
            .handle_udp_at(&query("lease.example", 28), 999)
            .unwrap()
            .is_none());
        assert!(service
            .handle_tcp_payload_at(&query("example", 1), 999)
            .unwrap()
            .is_none());
        assert!(service
            .handle_udp_at(&query("lease.example", 1), 1000)
            .unwrap()
            .is_none());
    }

    #[test]
    fn dhcp_ttl_uses_the_image_signed_ceiling() {
        for (configured, finite) in [
            (0, 0),
            (700, 600),
            (2_147_483_647, 600),
            (2_147_483_648, 2_147_483_648),
            (u32::MAX, u32::MAX),
        ] {
            let policy = LeasePolicy {
                dhcp_ttl: Some(configured),
                ..LeasePolicy::default()
            };
            assert_eq!(policy.ttl(Some(700), 100), finite);
            assert_eq!(policy.ttl(None, 100), configured);
        }
    }

    #[test]
    fn stale_dhcp_ttl_preserves_measured_c_wire_narrowing() {
        let policy = LeasePolicy {
            local_ttl: 37,
            stale: StalePolicy::Seconds(2),
            ..LeasePolicy::default()
        };
        let names = LeaseNames::build(
            &[input(b"lease.example", 7, Some(1000))],
            &mut Hosts::new(),
            &[],
            policy,
            &mut (),
        );
        assert_eq!(
            names
                .lookup(b"lease.example", 1000)
                .next()
                .unwrap()
                .ttl(1000, policy),
            0
        );
        assert_eq!(
            names
                .lookup(b"lease.example", 1001)
                .next()
                .unwrap()
                .ttl(1001, policy),
            u32::MAX
        );
        assert!(names.lookup(b"lease.example", 1002).next().is_none());
    }

    #[test]
    fn renewed_generation_reuses_only_name_bytes_and_keeps_old_snapshot() {
        let policy = LeasePolicy { dhcp_ttl: Some(600), ..LeasePolicy::default() };
        let previous = Arc::new(LeaseNames::build(
            &[input(b"lease.example", 7, Some(1000))],
            &mut Hosts::new(), &[], policy, &mut (),
        ));
        let child = Arc::clone(&previous);
        let records = [input(b"lease.example", 9, Some(2000))];
        let renewed = LeaseNames::build_reusing_names(
            &records, &mut Hosts::new(), &[], policy, &mut (), Some(&previous),
        );
        let ordinary = LeaseNames::build(&records, &mut Hosts::new(), &[], policy, &mut ());
        assert!(Arc::ptr_eq(&previous.inputs[0].name, &renewed.inputs[0].name));
        assert_eq!(renewed.inputs(), ordinary.inputs());
        assert_eq!(renewed.entries(), ordinary.entries());
        assert_eq!(renewed.lookup(b"lease.example", 1100).next().unwrap().ttl(1100, policy), 600);
        assert!(child.lookup(b"lease.example", 1100).next().is_none());
        assert_eq!(child.lookup(b"lease.example", 999).next().unwrap().address,
                   Ipv4Addr::new(192, 0, 2, 7));
    }

    #[test]
    fn reordered_renamed_and_case_changed_inputs_keep_exact_new_bytes() {
        let old = [input(b"Alpha", 7, Some(1000)), input(b"beta", 8, Some(1000))];
        let previous = LeaseNames::build(
            &old, &mut Hosts::new(), &[], LeasePolicy::default(), &mut (),
        );
        for records in [
            vec![input(b"beta", 8, Some(2000)), input(b"Alpha", 7, Some(2000))],
            vec![input(b"alpha", 7, Some(2000)), input(b"renamed", 8, Some(2000))],
            vec![input(b"extra", 9, Some(2000))],
            vec![],
        ] {
            let actual = LeaseNames::build_reusing_names(
                &records, &mut Hosts::new(), &[], LeasePolicy::default(), &mut (), Some(&previous),
            );
            let expected = LeaseNames::build(
                &records, &mut Hosts::new(), &[], LeasePolicy::default(), &mut (),
            );
            assert_eq!(actual.inputs(), expected.inputs());
            assert_eq!(actual.entries(), expected.entries());
            for (new, old) in actual.inputs.iter().zip(&previous.inputs) {
                assert!(!Arc::ptr_eq(&new.name, &old.name));
            }
        }
    }

    #[test]
    fn name_reuse_repeats_all_publication_callbacks() {
        #[derive(Default, Debug, PartialEq)]
        struct Calls { first: usize, names: Vec<Vec<u8>>, reverse: Vec<Ipv4Addr> }
        impl PublicationCache for Calls {
            fn first_lease_entry(&mut self) { self.first += 1; }
            fn prepare_name(&mut self, item: ForwardPublication<'_>) {
                self.names.push(item.name.to_vec());
            }
            fn reverse_owned(&mut self, address: Ipv4Addr) -> bool {
                self.reverse.push(address);
                false
            }
        }
        let records = [input(b"alpha.example", 7, Some(1000)), input(b"beta.example", 8, Some(1000))];
        let previous = LeaseNames::build(
            &records, &mut Hosts::new(), &[], LeasePolicy::default(), &mut (),
        );
        let mut actual_calls = Calls::default();
        let actual = LeaseNames::build_reusing_names(
            &records, &mut Hosts::new(), &[], LeasePolicy::default(), &mut actual_calls, Some(&previous),
        );
        let mut expected_calls = Calls::default();
        let expected = LeaseNames::build(
            &records, &mut Hosts::new(), &[], LeasePolicy::default(), &mut expected_calls,
        );
        assert_eq!(actual.entries(), expected.entries());
        assert_eq!(actual_calls, expected_calls);
        assert_eq!(actual_calls.first, 1);
        assert_eq!(actual_calls.names.len(), 2);
        assert_eq!(actual_calls.reverse.len(), 2);
    }

    #[test]
    fn expiry_detaches_only_the_reader_that_touched_the_name() {
        use crate::config::dns::DnsConfig;
        use crate::dns::service::LocalDnsService;
        use crate::dns::wire::{Name, PacketWriter};
        use std::sync::Arc;

        let mut parent = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 37, 512);
        parent.leases = Arc::new(LeaseNames::build(
            &[input(b"lease", 7, Some(1000))],
            &mut parent.hosts,
            &[],
            LeasePolicy::default(),
            &mut (),
        ));
        let mut child = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 37, 512);
        child.leases = Arc::clone(&parent.leases);
        let mut query = PacketWriter::new(0x2930, 0x100, 512).unwrap();
        query
            .question(&Name::from_ascii("lease").unwrap(), 1, 1)
            .unwrap();
        let query = query.finish();
        assert!(parent.handle_udp_at(&query, 999).unwrap().is_some());
        assert!(Arc::ptr_eq(&parent.leases, &child.leases));
        assert!(parent.handle_udp_at(&query, 1000).unwrap().is_none());
        assert!(!Arc::ptr_eq(&parent.leases, &child.leases));
        // The exact C trace removes a looked-up expired name permanently,
        // while a child holding the earlier generation can still use it.
        assert!(parent.handle_udp_at(&query, 999).unwrap().is_none());
        assert!(child.handle_tcp_payload_at(&query, 999).unwrap().is_some());
        assert!(child.leases.name_exists(b"lease", 999));
        assert_eq!(parent.leases.inputs().len(), 1); // reload source retained
    }
}
