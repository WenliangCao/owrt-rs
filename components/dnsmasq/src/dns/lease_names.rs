//! Immutable DHCP DNS generation, from lease.c:564-620 and cache.c:1742-1911.
//!
//! DHCP publication replaces this source, not hosts or the forwarded cache.
//! The caller publishes the completed generation before transmitting its ACK.
//! Every input is retained, including names hidden by hosts, so SIGHUP can
//! rebuild it against the new hosts generation without losing lease state.

use super::cache::StalePolicy;
use crate::config::records::Cname;
use crate::dhcp::persistence::DnsLeaseRecord;
use crate::hosts::Hosts;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug)]
pub struct LeasePolicy {
    pub local_ttl: u32,
    pub dhcp_ttl: Option<u32>,
    pub stale: StalePolicy,
}

impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            local_ttl: 0,
            dhcp_ttl: None,
            stale: StalePolicy::Disabled,
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
                i128::from(now) - i128::from(expires) < i128::from(seconds)
            }
            _ => now < expires,
        }
    }

    fn ttl(self, expires: Option<i64>, now: i64) -> u32 {
        let configured = self.dhcp_ttl.unwrap_or(self.local_ttl);
        expires.map_or(configured, |expires| {
            // crec_ttl is capped by lease duration. With use-stale-cache C
            // also retains DHCP entries and writes a negative difference as
            // a wire u32; lease pruning normally removes them first.
            (i128::from(expires) - i128::from(now)).min(i128::from(configured)) as u32
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
    pub blockers: &'a [PublicationBlocker],
}

/// The small mutable boundary between a new DHCP generation and the existing
/// forwarded cache. Implementations must preserve unrelated names/types and
/// NXDOMAIN records (which have neither F_IPV4 nor F_CNAME).
pub trait PublicationCache {
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
    pub name: Vec<u8>,
    pub address: Ipv4Addr,
    pub expires: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseName {
    pub name: Vec<u8>,
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
    forward: HashMap<Vec<u8>, Vec<usize>>,
    reverse: HashMap<Ipv4Addr, usize>,
    non_terminals: HashMap<Vec<u8>, Option<i64>>,
    warnings: Vec<PublicationWarning>,
    policy: LeasePolicy,
}

impl LeaseNames {
    /// `records` is lease_update_dns order: newest lease first, FQDN before
    /// short name. fqdn-only filtering belongs to the lease publisher.
    pub fn build(
        records: &[DnsLeaseRecord<'_>],
        hosts: &Hosts,
        cnames: &[Cname],
        policy: LeasePolicy,
        cache: &mut impl PublicationCache,
    ) -> Self {
        let mut result = Self {
            inputs: records
                .iter()
                .map(|record| LeaseInput {
                    name: record.name.to_vec(),
                    address: record.address,
                    expires: record.expires,
                })
                .collect(),
            policy,
            ..Self::default()
        };
        for record in records {
            result.add(*record, hosts, cnames, cache);
        }
        result
    }

    pub fn rebuild(
        &self,
        hosts: &Hosts,
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
        Self::build(&records, hosts, cnames, self.policy, cache)
    }

    pub fn inputs(&self) -> &[LeaseInput] {
        &self.inputs
    }
    pub fn entries(&self) -> &[LeaseName] {
        &self.entries
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
        self.forward
            .get(&name.to_ascii_lowercase())
            .into_iter()
            .flatten()
            .map(|&id| &self.entries[id])
            .filter(move |entry| self.policy.live(entry.expires, now))
    }

    pub fn reverse(&self, address: Ipv4Addr, now: i64) -> Option<&LeaseName> {
        let entry = self.reverse.get(&address).map(|&id| &self.entries[id])?;
        self.policy.live(entry.expires, now).then_some(entry)
    }

    /// check_for_local_domain / upstream NXDOMAIN conversion only. A live
    /// non-terminal is not a locally answerable empty RRset.
    pub fn name_exists(&self, name: &[u8], now: i64) -> bool {
        self.lookup(name, now).next().is_some()
            || self
                .non_terminals
                .get(&name.to_ascii_lowercase())
                .is_some_and(|&expiry| self.policy.live(expiry, now))
    }

    fn add(
        &mut self,
        record: DnsLeaseRecord<'_>,
        hosts: &Hosts,
        cnames: &[Cname],
        cache: &mut impl PublicationCache,
    ) {
        let key = record.name.to_ascii_lowercase();
        let mut blockers: Vec<_> = hosts
            .addresses(record.name)
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
        if let Some(ids) = self.forward.get(&key) {
            blockers.extend(ids.iter().map(|&id| PublicationBlocker {
                kind: BlockerKind::Ipv4,
                reverse: self.entries[id].reverse,
                immortal: self.entries[id].expires.is_none(),
            }));
        }
        cache.prepare_name(ForwardPublication {
            name: record.name,
            blockers: &blockers,
        });

        let mut conflict = None;
        for host in hosts.addresses(record.name) {
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
        let id = self.entries.len();
        let expires = record.expires.filter(|&expires| expires != 0);
        let immortal = expires.is_none();
        let ids = self.forward.entry(key.clone()).or_default();
        // cache_hash: reverse first; mortal before immortal for non-reverse;
        // preserve order within the same (reverse, immortal) flags group.
        let mut at = 0;
        if !reverse {
            while at < ids.len() && self.entries[ids[at]].reverse {
                at += 1;
            }
            if immortal {
                while at < ids.len() && self.entries[ids[at]].expires.is_some() {
                    at += 1;
                }
            }
        }
        while at < ids.len()
            && self.entries[ids[at]].reverse == reverse
            && self.entries[ids[at]].expires.is_none() == immortal
        {
            at += 1;
        }
        ids.insert(at, id);
        self.entries.push(LeaseName {
            name: record.name.to_vec(),
            address: record.address,
            expires,
            reverse,
        });
        if reverse {
            self.reverse.insert(record.address, id);
        }
        self.non_terminals.remove(&key);
        for (index, &byte) in key.iter().enumerate() {
            if byte != b'.' {
                continue;
            }
            let parent = &key[index + 1..];
            // C extends the first existing DHCP record even when it is a
            // real address, not just a synthetic non-terminal.
            if let Some(ids) = self.forward.get(parent) {
                extend_expiry(&mut self.entries[ids[0]].expires, expires);
            } else {
                self.non_terminals
                    .entry(parent.to_vec())
                    .and_modify(|expiry| extend_expiry(expiry, expires))
                    .or_insert(expires);
            }
        }
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
        let names = LeaseNames::build(&records, &Hosts::new(), &[], policy, &mut ());
        assert_eq!(
            names.reverse(records[0].address, 999).unwrap().name,
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
        let names = LeaseNames::build(&records, &hosts, &[], LeasePolicy::default(), &mut ());
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
        let names = names.rebuild(&hosts, &[], &mut ());
        assert_eq!(names.entries().len(), 1);
        assert!(names.entries()[0].reverse);
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
            &Hosts::new(),
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
            &Hosts::new(),
            &[],
            LeasePolicy::default(),
            &mut Cache,
        );
        assert_eq!(names.entries().len(), 1);
        assert!(!names.entries()[0].reverse);
        assert!(names.reverse(Ipv4Addr::new(192, 0, 2, 7), 999).is_none());
    }
}
