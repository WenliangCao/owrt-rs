//! Direct DHCPv6 server engine. Sockets and acknowledged route writes belong to the daemon.
use crate::config::{Config, HostConfig, PoolConfig};
use crate::leases::{hostname_valid, Lease, LeaseAddress, LeaseKind};
use crate::model::{remaining, Address, Clock, KernelState, Link, Prefix, Route, INFINITE};
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};

const CLIENT_ID: u16 = 1;
const SERVER_ID: u16 = 2;
const IA_NA: u16 = 3;
const IA_ADDR: u16 = 5;
const ORO: u16 = 6;
const STATUS: u16 = 13;
const RAPID_COMMIT: u16 = 14;
const IA_PD: u16 = 25;
const IA_PREFIX: u16 = 26;
const MAX_LEASES: usize = 4096;
const IA_REPLY_LIMIT: usize = 512;

pub struct RequestContext<'a> {
    pub source: SocketAddrV6,
    pub destination: Ipv6Addr,
    pub link: &'a Link,
    pub pool: &'a PoolConfig,
    pub config: &'a Config,
    pub clock: Clock,
}

#[derive(Default)]
pub struct Dhcpv6 {
    leases: Vec<Lease>,
    // Successful kernel writes remain here until a successful deletion ACK.
    installed_routes: Vec<Route>,
}

#[derive(Clone, Copy)]
struct OptionRef<'a> {
    code: u16,
    value: &'a [u8],
}

fn options(mut bytes: &[u8]) -> Option<Vec<OptionRef<'_>>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 || result.len() >= 1024 {
            return None;
        }
        let code = u16::from_be_bytes([bytes[0], bytes[1]]);
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if length > bytes.len() - 4 {
            return None;
        }
        if code == 0 {
            break;
        }
        result.push(OptionRef {
            code,
            value: &bytes[4..4 + length],
        });
        bytes = &bytes[4 + length..];
    }
    Some(result)
}

fn push_option(bytes: &mut Vec<u8>, code: u16, value: &[u8]) {
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn status_option(bytes: &mut Vec<u8>, status: u16) {
    push_option(bytes, STATUS, &status.to_be_bytes());
}

fn deadline(now: u64, lifetime: u32) -> u64 {
    if lifetime == u32::MAX {
        INFINITE
    } else {
        now.saturating_add(lifetime as u64)
    }
}

fn cap(value: u32, maximum: u32) -> u32 {
    if maximum == 0 {
        value
    } else {
        value.min(maximum)
    }
}

fn server_id(context: &RequestContext<'_>) -> Vec<u8> {
    if let Some(duid) = &context.config.default_duid {
        return duid.clone();
    }
    let mut duid = vec![0, 3, 0, 1];
    duid.extend_from_slice(&context.link.mac);
    duid
}

pub fn dns_addresses(pool: &PoolConfig, link: &Link, now: u64) -> Vec<Ipv6Addr> {
    if !pool.dns.is_empty() {
        return pool.dns.clone();
    }
    if !pool.dns_service {
        return Vec::new();
    }
    let mut selected: Option<&Address> = None;
    let addresses: Vec<_> = link
        .addresses
        .iter()
        .filter(|address| address.scope == 0 && remaining(address.valid_until, now) != 0)
        .collect();
    for address in addresses {
        let Some(previous) = selected else {
            selected = Some(address);
            continue;
        };
        let preferred = address.preferred_until;
        let previous_preferred = previous.preferred_until;
        if previous_preferred >= now && preferred < now {
            continue;
        }
        let ula = address.prefix().is_ula();
        let previous_ula = previous.prefix().is_ula();
        if ula && !previous_ula || ula == previous_ula && preferred > previous_preferred {
            selected = Some(address);
        }
    }
    selected
        .map(|address| address.address)
        .or_else(|| link.link_local())
        .into_iter()
        .collect()
}

fn wire_domains(domains: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for domain in domains {
        let mut name = Vec::new();
        let mut valid = true;
        for label in domain.trim_end_matches('.').split('.') {
            if label.is_empty() || label.len() > 63 {
                valid = false;
                break;
            }
            name.push(label.len() as u8);
            name.extend_from_slice(label.as_bytes());
        }
        if valid && name.len() < 255 {
            name.push(0);
            bytes.extend(name);
        }
    }
    bytes
}

fn request_hostname(parsed: &[OptionRef<'_>]) -> Option<Vec<u8>> {
    let fqdn = parsed.iter().rev().find(|option| option.code == 39)?.value;
    if fqdn.len() < 2 || fqdn.len() > 255 {
        return None;
    }
    let length = fqdn[1] as usize;
    if length == 0 || length > 63 || length > fqdn.len() - 2 {
        return None;
    }
    Some(fqdn[2..length + 2].to_vec())
}

fn host_for<'a>(config: &'a Config, duid: &[u8], iaid: u32) -> Option<&'a HostConfig> {
    if let Some(host) = config.hosts.iter().find(|host| {
        host.duids
            .iter()
            .any(|id| id.duid == duid && id.iaid.is_none_or(|value| value == iaid))
    }) {
        return Some(host);
    }
    let mac = match duid {
        [0, 1, ..] if duid.len() == 14 => &duid[8..14],
        [0, 3, ..] if duid.len() == 10 => &duid[4..10],
        _ => return None,
    };
    config.hosts.iter().find(|host| {
        host.macs
            .iter()
            .any(|candidate| candidate.as_slice() == mac)
    })
}

fn refresh_host(lease: &mut Lease, config: &Config, pool: &PoolConfig) -> bool {
    let current = host_for(config, &lease.duid, lease.iaid).or_else(|| {
        // Decline zeros the client's DUID but keeps its lease/config association
        // until quarantine expires. A host without a fixed IID is still dynamic.
        if lease.bound || lease.duid.iter().any(|byte| *byte != 0) {
            return None;
        }
        let previous = lease.configured_host.as_ref()?;
        config
            .hosts
            .iter()
            .find(|host| host.duids == previous.duids && host.macs == previous.macs)
    });
    let Some(previous) = lease.configured_host.as_ref() else {
        return current.is_none();
    };
    let Some(current) = current else { return false };
    if current.ignore_v6
        || previous.duids != current.duids
        || previous.macs != current.macs
        || previous.host_id != current.host_id
    {
        return false;
    }
    if previous != current {
        lease.hostname = current
            .hostname
            .as_ref()
            .map(|name| name.as_bytes().to_vec());
        lease.hostname_valid = lease.hostname.as_deref().is_some_and(hostname_valid);
        lease.lease_time = current.lease_time.unwrap_or(pool.lease_time);
        lease.configured_host = Some(current.clone());
    }
    true
}

fn valid_sources<'a>(
    link: &'a Link,
    pool: &PoolConfig,
    now: u64,
    kind: LeaseKind,
) -> Vec<&'a Address> {
    let addresses: Vec<_> = link
        .addresses
        .iter()
        .filter(|address| {
            address.scope == 0
                && address.length <= 96
                && address.flags & 0x20 == 0
                && remaining(address.preferred_until, now) != 0
                && remaining(address.valid_until, now) != 0
        })
        .collect();
    if kind == LeaseKind::Pd || pool.dhcpv6_assign_all {
        return addresses;
    }
    let preferred = addresses
        .iter()
        .max_by_key(|address| (address.preferred_until, address.address))
        .copied();
    addresses
        .into_iter()
        .filter(|address| {
            address.length > 64 || preferred.is_some_and(|best| std::ptr::eq(best, *address))
        })
        .collect()
}

fn allocated_address(source: &Address, lease: &Lease) -> Option<Ipv6Addr> {
    if lease.prefix_length <= source.length {
        return None;
    }
    if lease.kind == LeaseKind::Na {
        let bits = (128 - source.length).min(64);
        let mask = (1u128 << bits) - 1;
        Some(Ipv6Addr::from(
            (u128::from(source.address) & !mask) | (lease.assigned as u128 & mask),
        ))
    } else {
        if source.length >= 64
            || lease.assigned == 0
            || !lease
                .assigned
                .is_multiple_of(1u64 << (64 - lease.prefix_length))
            || lease
                .assigned
                .checked_add(1u64 << (64 - lease.prefix_length))?
                > (1u64 << (64 - source.length))
        {
            return None;
        }
        Some(Ipv6Addr::from(
            (u128::from(source.prefix().address) | ((lease.assigned as u128) << 64))
                & (u128::MAX << 64),
        ))
    }
}

fn addresses_for(
    lease: &Lease,
    link: &Link,
    pool: &PoolConfig,
    now: u64,
    refresh: bool,
) -> Vec<LeaseAddress> {
    valid_sources(link, pool, now, lease.kind)
        .into_iter()
        .filter_map(|source| {
            let address = allocated_address(source, lease)?;
            let valid = remaining(source.valid_until, now);
            let preferred = remaining(source.preferred_until, now);
            // C clamps finite source lifetimes, but infinite sources bypass
            // those prefix caps. The configured lease time still bounds both.
            let valid = if valid == u32::MAX {
                valid
            } else {
                cap(valid, pool.max_valid_lifetime)
            }
            .min(lease.lease_time);
            let preferred = if preferred == u32::MAX {
                preferred
            } else {
                cap(preferred, pool.max_preferred_lifetime)
            }
            .min(valid);
            let mut result = LeaseAddress {
                address,
                length: lease.prefix_length,
                preferred_until: deadline(now, preferred),
                valid_until: deadline(now, valid),
            };
            if !refresh {
                result.preferred_until = result
                    .preferred_until
                    .min(lease.preferred_until)
                    .min(lease.valid_until);
                result.valid_until = result.valid_until.min(lease.valid_until);
            }
            Some(result)
        })
        .collect()
}

fn binding_routes(lease: &Lease) -> Vec<Route> {
    if lease.kind != LeaseKind::Pd || !lease.bound {
        return Vec::new();
    }
    lease
        .addresses
        .iter()
        .map(|address| Route {
            destination: Prefix::new(address.address, address.length).expect("allocated PD prefix"),
            source: Prefix::new(Ipv6Addr::UNSPECIFIED, 0).expect("zero prefix"),
            gateway: Some(*lease.peer.ip()),
            interface: lease.interface_index,
            table: 254,
            metric: 1024,
            kind: 1,
            protocol: 4,
        })
        .collect()
}

impl Dhcpv6 {
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }

    pub fn pending_routes(&self) -> &[Route] {
        &self.installed_routes
    }

    fn install_routes(
        &mut self,
        lease: &Lease,
        apply: &mut impl FnMut(&Route, bool) -> io::Result<()>,
    ) -> io::Result<()> {
        for route in binding_routes(lease) {
            if !self.installed_routes.contains(&route) {
                apply(&route, true)?;
                self.installed_routes.push(route);
            }
        }
        Ok(())
    }

    fn remove_unused_routes(
        &mut self,
        apply: &mut impl FnMut(&Route, bool) -> io::Result<()>,
    ) -> io::Result<()> {
        let desired: Vec<_> = self.leases.iter().flat_map(binding_routes).collect();
        let mut error = None;
        self.installed_routes.retain(|route| {
            if desired.contains(route) {
                return true;
            }
            if let Err(failure) = apply(route, false) {
                if error.is_none() {
                    error = Some(failure);
                }
                true
            } else {
                false
            }
        });
        error.map_or(Ok(()), Err)
    }

    /// Run after a kernel/config update and periodically. Failed deletions remain tracked.
    pub fn reconcile(
        &mut self,
        config: &Config,
        kernel: &KernelState,
        clock: Clock,
        apply: &mut impl FnMut(&Route, bool) -> io::Result<()>,
    ) -> io::Result<()> {
        let now = clock.seconds();
        let mut first_error = None;
        self.installed_routes
            .retain(|route| kernel.routes.contains(route));
        self.leases.retain_mut(|lease| {
            let Some(pool) = config
                .pools
                .iter()
                .find(|pool| pool.name == lease.pool && pool.dhcpv6)
            else {
                return false;
            };
            let Some(link) = kernel
                .links
                .iter()
                .find(|link| pool.ifname.as_deref().unwrap_or(&lease.device) == link.name)
            else {
                return false;
            };
            if !link.running() || !lease.valid(now) || !refresh_host(lease, config, pool) {
                return false;
            }
            lease.device = link.name.clone();
            lease.interface_index = link.index;
            // C's ubus view enumerates the current prefix set for offers and
            // declined IIDs too. Only bound leases enter hosts/state exports.
            lease.addresses = addresses_for(lease, link, pool, now, false);
            true
        });
        for index in 0..self.leases.len() {
            let lease = self.leases[index].clone();
            if let Err(error) = self.install_routes(&lease, apply) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                // Do not publish an unreachable delegated prefix. The next reconcile
                // derives the desired addresses again from the live prefix pool.
                self.leases[index].addresses.retain(|address| {
                    self.installed_routes.iter().any(|route| {
                        route.destination
                            == Prefix::new(address.address, address.length).expect("lease prefix")
                            && route.interface == lease.interface_index
                            && route.gateway == Some(*lease.peer.ip())
                    })
                });
            }
        }
        if let Err(error) = self.remove_unused_routes(apply) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn allocate_na(&self, context: &RequestContext<'_>, duid: &[u8], fixed: u64) -> Option<u64> {
        let used = |id| {
            self.leases.iter().any(|lease| {
                lease.pool == context.pool.name
                    && lease.kind == LeaseKind::Na
                    && lease.assigned == id
                    && lease.valid(context.clock.seconds())
            })
        };
        if fixed != 0 {
            return (!used(fixed)).then_some(fixed);
        }
        let end = if context.pool.hostid_length >= 64 {
            u64::MAX
        } else {
            (1u64 << context.pool.hostid_length) - 1
        };
        let size = end.checked_sub(0x100)?.checked_add(1)?;
        let mut seed = [0u8; 8];
        let tail = &duid[duid.len().saturating_sub(6)..];
        seed[..tail.len()].copy_from_slice(tail);
        let mut state = u64::from_le_bytes(seed);
        let mut draw = || {
            state = state.wrapping_mul(0x5deece66d).wrapping_add(0xb) & ((1 << 48) - 1);
            (state >> 16) as u32
        };
        let random = (u64::from(draw()) << 32) | u64::from(draw());
        let mut id = 0x100 + random % size;
        for _ in 0..100 {
            let reserved = id == 0
                || id & 0xffffffffff000000 == 0x02005efffe000000
                || id & 0xffffffffffffff80 == 0xfdffffffffffff80;
            if !reserved && !used(id) && !context.config.hosts.iter().any(|host| host.host_id == id)
            {
                return Some(id);
            }
            id = if id == end { 0x100 } else { id + 1 };
        }
        None
    }

    fn allocate_pd(
        &self,
        context: &RequestContext<'_>,
        requested: u8,
        hint: u32,
    ) -> Option<(u64, u8)> {
        let largest_source = valid_sources(
            context.link,
            context.pool,
            context.clock.seconds(),
            LeaseKind::Pd,
        )
        .into_iter()
        .filter(|address| address.length > 32 && address.length < 64)
        .map(|address| address.length)
        .max()?;
        let border = 1u64 << (64 - largest_source);
        for length in requested.max(context.pool.pd_min_len).clamp(33, 64)..=64 {
            let size = 1u64 << (64 - length);
            let mut occupied: Vec<_> = self
                .leases
                .iter()
                .filter(|lease| {
                    lease.pool == context.pool.name
                        && lease.kind == LeaseKind::Pd
                        && lease.valid(context.clock.seconds())
                })
                .map(|lease| (lease.assigned, 1u64 << (64 - lease.prefix_length)))
                .collect();
            occupied.sort_unstable();
            let available = |id: u64| {
                id > 0
                    && id.is_multiple_of(size)
                    && id.checked_add(size).is_some_and(|end| {
                        end <= border
                            && occupied
                                .iter()
                                .all(|(other, span)| end <= *other || id >= other + span)
                    })
            };
            if available(u64::from(hint)) {
                return Some((u64::from(hint), length));
            }
            let mut current = size;
            for (id, span) in occupied.iter().copied().chain(std::iter::once((border, 0))) {
                if current + size <= id.min(border) {
                    return Some((current, length));
                }
                if id >= border {
                    break;
                }
                current = current.max(id + span).div_ceil(size) * size;
            }
        }
        None
    }

    /// The route callback must return only after the kernel ACK. A failed PD
    /// installation yields NoPrefixAvail, never a successful binding reply.
    pub fn handle(
        &mut self,
        packet: &[u8],
        context: RequestContext<'_>,
        apply: &mut impl FnMut(&Route, bool) -> io::Result<()>,
    ) -> Option<Vec<u8>> {
        if packet.len() < 4
            || !context.pool.dhcpv6
            || !matches!(packet[0], 1 | 3 | 4 | 5 | 6 | 8 | 9 | 11)
        {
            return None;
        }
        let message = packet[0];
        let parsed = options(&packet[4..])?;
        // Validate every IA before changing state, including later IAs in a packet.
        for option in parsed
            .iter()
            .filter(|option| matches!(option.code, IA_NA | IA_PD))
        {
            if option.value.len() < 12 {
                return None;
            }
            options(&option.value[12..])?;
        }
        let server = server_id(&context);
        if parsed
            .iter()
            .any(|option| option.code == SERVER_ID && option.value != server)
        {
            return None;
        }
        let client = parsed
            .iter()
            .rev()
            .find(|option| option.code == CLIENT_ID)
            .map(|option| option.value);
        if let Some(client) = client {
            if parsed
                .iter()
                .filter(|option| matches!(option.code, IA_NA | IA_PD))
                .any(|ia| {
                    let iaid =
                        u32::from_be_bytes(ia.value[..4].try_into().expect("validated IA header"));
                    host_for(context.config, client, iaid).is_some_and(|host| host.ignore_v6)
                })
            {
                return None;
            }
        }
        if client == Some(server.as_slice()) {
            return None;
        }
        if !context.destination.is_multicast() && matches!(message, 1 | 4 | 6 | 11) {
            return None;
        }
        let rapid = message == 1 && parsed.iter().any(|option| option.code == RAPID_COMMIT);
        let mut reply = vec![
            if message == 1 && !rapid { 2 } else { 7 },
            packet[1],
            packet[2],
            packet[3],
        ];
        push_option(&mut reply, SERVER_ID, &server);
        if let Some(client) = client.filter(|client| client.len() <= 130) {
            push_option(&mut reply, CLIENT_ID, client);
        }
        if !context.destination.is_multicast() && matches!(message, 3 | 5 | 8 | 9) {
            status_option(&mut reply, 5);
            return Some(reply);
        }
        push_option(
            &mut reply,
            if message == 11 { 83 } else { 82 },
            &60u32.to_be_bytes(),
        );
        if rapid {
            push_option(&mut reply, RAPID_COMMIT, &[]);
        }
        let dns: Vec<_> = dns_addresses(context.pool, context.link, context.clock.seconds())
            .into_iter()
            .flat_map(|address| address.octets())
            .collect();
        if !dns.is_empty() {
            push_option(&mut reply, 23, &dns);
        }
        let domains = wire_domains(&context.pool.domains);
        if !domains.is_empty() {
            push_option(&mut reply, 24, &domains);
        }
        let mut ias = Vec::new();
        if message == 11 {
            push_option(&mut ias, 32, &600u32.to_be_bytes());
        } else if let Some(duid) = client.filter(|client| (10..=130).contains(&client.len())) {
            let hostname = request_hostname(&parsed);
            let mut confirm_on_link = true;
            let mut confirm_has_binding = false;
            let mut confirm_has_address = false;
            for ia in parsed
                .iter()
                .filter(|option| matches!(option.code, IA_NA | IA_PD))
            {
                let kind = if ia.code == IA_NA {
                    LeaseKind::Na
                } else {
                    LeaseKind::Pd
                };
                let iaid = u32::from_be_bytes(ia.value[..4].try_into().ok()?);
                let suboptions = options(&ia.value[12..])?;
                let host = host_for(context.config, duid, iaid);
                if host.is_some_and(|host| host.ignore_v6) {
                    return None;
                }
                let mut existing = self.leases.iter().position(|lease| {
                    lease.pool == context.pool.name
                        && lease.kind == kind
                        && lease.duid == duid
                        && lease.iaid == iaid
                        && lease.valid(context.clock.seconds())
                });
                if let Some(index) = existing {
                    if !refresh_host(&mut self.leases[index], context.config, context.pool) {
                        self.leases.remove(index);
                        existing = None;
                    }
                }
                if message == 4 {
                    let has_address = kind == LeaseKind::Na
                        && suboptions
                            .iter()
                            .any(|option| option.code == IA_ADDR && option.value.len() >= 24);
                    confirm_has_address |= has_address;
                    if has_address && !on_link(&suboptions, kind, &context) {
                        confirm_on_link = false;
                    }
                    confirm_has_binding |= existing.is_some_and(|index| self.leases[index].bound);
                    continue;
                }
                let status = if matches!(message, 5 | 8 | 9) && existing.is_none() {
                    3
                } else {
                    0
                };
                let mut candidate = existing.map(|index| self.leases[index].clone());
                if matches!(message, 8 | 9) && status == 0 {
                    let index = existing?;
                    let fixed_iid = self.leases[index]
                        .configured_host
                        .as_ref()
                        .is_some_and(|host| host.host_id == self.leases[index].assigned);
                    if message == 8 || kind == LeaseKind::Na && fixed_iid {
                        self.leases.remove(index);
                    } else if kind == LeaseKind::Na {
                        let lease = &mut self.leases[index];
                        lease.bound = false;
                        lease.duid.fill(0);
                        lease.valid_until = context.clock.seconds() + 3600;
                        lease.addresses = addresses_for(
                            lease,
                            context.link,
                            context.pool,
                            context.clock.seconds(),
                            false,
                        );
                    }
                    continue;
                }
                let mut status = status;
                if status == 0 && candidate.is_none() {
                    // A configured DUID without IAID permits an NA to move from
                    // one client interface/IAID to another, as in C's host match.
                    if kind == LeaseKind::Na
                        && host.is_some_and(|host| {
                            host.duids
                                .iter()
                                .any(|entry| entry.duid == duid && entry.iaid.is_none())
                        })
                    {
                        self.leases.retain(|lease| {
                            !(lease.pool == context.pool.name
                                && lease.kind == kind
                                && lease.duid == duid
                                && lease.is_static)
                        });
                        existing = None;
                    }
                    let permitted = if kind == LeaseKind::Na {
                        context.pool.dhcpv6_na && (context.pool.dynamic_dhcp || host.is_some())
                    } else {
                        context.pool.dhcpv6_pd && context.pool.dynamic_dhcp
                    };
                    if permitted && self.leases.len() < MAX_LEASES {
                        let assignment = if kind == LeaseKind::Na {
                            self.allocate_na(&context, duid, host.map_or(0, |host| host.host_id))
                                .map(|id| (id, 128))
                        } else {
                            let hint = suboptions.iter().rfind(|option| {
                                option.code == IA_PREFIX && option.value.len() >= 25
                            });
                            let length = hint
                                .filter(|option| option.value[8] != 0)
                                .map_or(62, |option| option.value[8])
                                .min(64);
                            let hint = hint.map_or(0, |option| {
                                u32::from_be_bytes(
                                    option.value[13..17]
                                        .try_into()
                                        .expect("prefix option length"),
                                )
                            });
                            self.allocate_pd(&context, length, hint)
                        };
                        if let Some((assigned, prefix_length)) = assignment {
                            candidate = Some(Lease {
                                pool: context.pool.name.clone(),
                                device: context.link.name.clone(),
                                interface_index: context.link.index,
                                duid: duid.to_vec(),
                                iaid,
                                kind,
                                assigned,
                                prefix_length,
                                hostname: None,
                                hostname_valid: false,
                                bound: false,
                                is_static: host.is_some(),
                                configured_host: host.cloned(),
                                lease_time: host
                                    .and_then(|host| host.lease_time)
                                    .unwrap_or(context.pool.lease_time),
                                valid_until: context.clock.seconds(),
                                preferred_until: context.clock.seconds(),
                                peer: context.source,
                                addresses: Vec::new(),
                            });
                        }
                    }
                    if candidate.is_none() {
                        status = if kind == LeaseKind::Na { 2 } else { 6 };
                    }
                }
                if status == 0 && message == 3 && !on_link(&suboptions, kind, &context) {
                    status = 4;
                }
                if let Some(lease) = candidate.as_mut().filter(|_| status == 0) {
                    lease.interface_index = context.link.index;
                    lease.device = context.link.name.clone();
                    lease.addresses = addresses_for(
                        lease,
                        context.link,
                        context.pool,
                        context.clock.seconds(),
                        true,
                    );
                    if kind == LeaseKind::Pd && lease.addresses.is_empty() {
                        if let Some((assigned, length)) =
                            self.allocate_pd(&context, lease.prefix_length, 0)
                        {
                            lease.assigned = assigned;
                            lease.prefix_length = length;
                            lease.addresses = addresses_for(
                                lease,
                                context.link,
                                context.pool,
                                context.clock.seconds(),
                                true,
                            );
                        }
                    }
                    if lease.addresses.is_empty()
                        && !(existing.is_some() && matches!(message, 5 | 6))
                    {
                        status = if kind == LeaseKind::Na { 2 } else { 6 };
                    } else {
                        lease.valid_until = lease
                            .addresses
                            .iter()
                            .map(|address| address.valid_until)
                            .fold(
                                deadline(
                                    context.clock.seconds(),
                                    cap(lease.lease_time, context.pool.max_valid_lifetime),
                                ),
                                u64::min,
                            );
                        lease.preferred_until = lease
                            .addresses
                            .iter()
                            .map(|address| address.preferred_until)
                            .fold(
                                deadline(
                                    context.clock.seconds(),
                                    cap(lease.lease_time, context.pool.max_preferred_lifetime),
                                ),
                                u64::min,
                            );
                        lease.bound = message != 1 || rapid;
                        if matches!(message, 1 | 3 | 6) {
                            let name = host
                                .and_then(|host| host.hostname.as_ref())
                                .map(|name| name.as_bytes().to_vec())
                                .or_else(|| hostname.clone());
                            if let Some(name) = name {
                                lease.hostname_valid = hostname_valid(&name);
                                lease.hostname = Some(name);
                            }
                        }
                        if self.install_routes(lease, apply).is_err() {
                            status = 6;
                        }
                    }
                }
                let encoded = encode_ia(
                    ia.code,
                    iaid,
                    status,
                    candidate.as_ref(),
                    &suboptions,
                    matches!(message, 5 | 6),
                    context.clock.seconds(),
                );
                if ias.len() + encoded.len() > IA_REPLY_LIMIT {
                    break;
                }
                ias.extend(encoded);
                if status == 0 {
                    let mut lease = candidate?;
                    if !lease.bound {
                        lease.valid_until = context.clock.seconds() + 60;
                    }
                    if let Some(index) = existing {
                        self.leases[index] = lease;
                    } else {
                        self.leases.push(lease);
                    }
                }
            }
            if message == 4 {
                if !confirm_has_address || confirm_on_link && !confirm_has_binding {
                    return None;
                }
                status_option(&mut ias, if confirm_on_link { 0 } else { 4 });
            } else if matches!(message, 8 | 9) {
                status_option(&mut ias, 0);
            }
        }
        self.leases.sort_by_key(|lease| {
            (
                lease.pool.clone(),
                lease.kind == LeaseKind::Pd,
                lease.assigned,
            )
        });
        let _ = self.remove_unused_routes(apply);
        if matches!(message, 4 | 6) && ias.is_empty() {
            return None;
        }
        reply.extend(ias);
        let requested = parsed
            .iter()
            .find(|option| option.code == ORO)
            .map(|option| option.value)
            .unwrap_or_default();
        if context.config.enable_tz {
            for (code, text) in [
                (41u16, context.config.timezone.as_ref()),
                (42, context.config.zonename.as_ref()),
            ] {
                if requested
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|bytes| *bytes == code.to_be_bytes())
                {
                    if let Some(text) = text.filter(|text| !text.is_empty()) {
                        push_option(&mut reply, code, text.as_bytes());
                    }
                }
            }
        }
        Some(reply)
    }
}

fn on_link(options: &[OptionRef<'_>], kind: LeaseKind, context: &RequestContext<'_>) -> bool {
    options.iter().all(|option| {
        let (address, length) = if kind == LeaseKind::Na
            && option.code == IA_ADDR
            && option.value.len() >= 24
        {
            (
                Ipv6Addr::from(<[u8; 16]>::try_from(&option.value[..16]).expect("IAADDR length")),
                128,
            )
        } else if kind == LeaseKind::Pd && option.code == IA_PREFIX && option.value.len() >= 25 {
            (
                Ipv6Addr::from(
                    <[u8; 16]>::try_from(&option.value[9..25]).expect("IAPREFIX length"),
                ),
                option.value[8],
            )
        } else {
            return true;
        };
        valid_sources(context.link, context.pool, context.clock.seconds(), kind)
            .iter()
            .any(|source| source.length <= length && source.prefix().contains(address))
    })
}

fn encode_ia(
    code: u16,
    iaid: u32,
    status: u16,
    lease: Option<&Lease>,
    previous: &[OptionRef<'_>],
    invalidate: bool,
    now: u64,
) -> Vec<u8> {
    let mut body = iaid.to_be_bytes().to_vec();
    let preferred = lease
        .filter(|_| status == 0)
        .map_or(0, |lease| remaining(lease.preferred_until, now));
    let (t1, t2) = if preferred == u32::MAX {
        (u32::MAX, u32::MAX)
    } else if lease.is_some() && status == 0 {
        (
            ((preferred as u64 * 5 / 10) as u32).max(1),
            ((preferred as u64 * 8 / 10) as u32).max(1),
        )
    } else {
        (0, 0)
    };
    body.extend_from_slice(&t1.to_be_bytes());
    body.extend_from_slice(&t2.to_be_bytes());
    if status != 0 {
        status_option(&mut body, status);
    } else if let Some(lease) = lease {
        for address in &lease.addresses {
            encode_address(&mut body, address, now);
        }
        if invalidate {
            for option in previous {
                let prior = if code == IA_NA && option.code == IA_ADDR && option.value.len() >= 24 {
                    Some((
                        Ipv6Addr::from(
                            <[u8; 16]>::try_from(&option.value[..16]).expect("IAADDR length"),
                        ),
                        128,
                    ))
                } else if code == IA_PD && option.code == IA_PREFIX && option.value.len() >= 25 {
                    Some((
                        Ipv6Addr::from(
                            <[u8; 16]>::try_from(&option.value[9..25]).expect("IAPREFIX length"),
                        ),
                        option.value[8],
                    ))
                } else {
                    None
                };
                if let Some((address, length)) = prior.filter(|(address, length)| {
                    !lease
                        .addresses
                        .iter()
                        .any(|current| current.address == *address && current.length == *length)
                }) {
                    encode_address(
                        &mut body,
                        &LeaseAddress {
                            address,
                            length,
                            preferred_until: now,
                            valid_until: now,
                        },
                        now,
                    );
                }
            }
        }
    }
    let mut result = Vec::new();
    push_option(&mut result, code, &body);
    result
}

fn encode_address(output: &mut Vec<u8>, address: &LeaseAddress, now: u64) {
    let preferred = remaining(address.preferred_until, now).to_be_bytes();
    let valid = remaining(address.valid_until, now).to_be_bytes();
    let mut body = Vec::with_capacity(25);
    if address.length == 128 {
        body.extend_from_slice(&address.address.octets());
        body.extend_from_slice(&preferred);
        body.extend_from_slice(&valid);
        push_option(output, IA_ADDR, &body);
    } else {
        body.extend_from_slice(&preferred);
        body.extend_from_slice(&valid);
        body.push(address.length);
        body.extend_from_slice(&address.address.octets());
        push_option(output, IA_PREFIX, &body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HostDuid;

    const CLIENT: &[u8] = &[0, 3, 0, 1, 2, 3, 4, 5, 6, 7];

    fn fixture() -> (Config, Link) {
        let mut pool = PoolConfig::new("lan");
        pool.ifname = Some("br-lan".into());
        pool.dhcpv6 = true;
        let config = Config {
            pools: vec![pool],
            timezone: Some("CET-1CEST,M3.5.0,M10.5.0/3".into()),
            zonename: Some("Europe/Berlin".into()),
            ..Config::default()
        };
        let link = Link {
            name: "br-lan".into(),
            index: 7,
            flags: 0x41,
            mtu: 1500,
            mac: [0x02, 0, 0, 0, 0, 1],
            addresses: vec![
                Address {
                    address: "2001:db8:1::1".parse().unwrap(),
                    length: 64,
                    preferred_until: 10_000,
                    valid_until: 20_000,
                    flags: 0,
                    scope: 0,
                },
                Address {
                    address: "fd00:1::1".parse().unwrap(),
                    length: 60,
                    preferred_until: INFINITE,
                    valid_until: INFINITE,
                    flags: 0,
                    scope: 0,
                },
            ],
        };
        (config, link)
    }

    fn context<'a>(config: &'a Config, link: &'a Link) -> RequestContext<'a> {
        RequestContext {
            source: "[fe80::10%7]:546".parse().unwrap(),
            destination: "ff02::1:2".parse().unwrap(),
            link,
            pool: &config.pools[0],
            config,
            clock: Clock {
                monotonic_ms: 100_000,
                unix_seconds: 2_000_000_000,
            },
        }
    }

    fn packet(message: u8, kind: u16, iaid: u32, old: Option<LeaseAddress>) -> Vec<u8> {
        let mut packet = vec![message, 0x12, 0x34, 0x56];
        push_option(&mut packet, CLIENT_ID, CLIENT);
        let mut ia = iaid.to_be_bytes().to_vec();
        ia.extend_from_slice(&[0; 8]);
        if let Some(old) = old {
            encode_address(&mut ia, &old, 100);
        }
        push_option(&mut packet, kind, &ia);
        packet
    }

    fn ia_status(reply: &[u8], kind: u16) -> u16 {
        let options = options(&reply[4..]).unwrap();
        let ia = options.iter().find(|option| option.code == kind).unwrap();
        super::options(&ia.value[12..])
            .unwrap()
            .iter()
            .find(|option| option.code == STATUS)
            .map_or(0, |status| {
                u16::from_be_bytes(status.value.try_into().unwrap())
            })
    }

    #[test]
    fn rapid_commit_has_two_na_addresses_and_no_reconfigure_handshake() {
        let (config, link) = fixture();
        let mut engine = Dhcpv6::default();
        let mut packet = packet(1, IA_NA, 1, None);
        push_option(&mut packet, RAPID_COMMIT, &[]);
        push_option(&mut packet, 20, &[]); // Client Reconfigure Accept.
        let reply = engine
            .handle(&packet, context(&config, &link), &mut |_, _| {
                panic!("NA must not write routes")
            })
            .unwrap();
        assert_eq!(reply[0], 7);
        assert_eq!(&reply[1..4], &[0x12, 0x34, 0x56]);
        assert!(engine.leases()[0].bound);
        assert_eq!(engine.leases()[0].addresses.len(), 2);
        assert!(options(&reply[4..])
            .unwrap()
            .iter()
            .all(|option| !matches!(option.code, 11 | 20)));
        assert_eq!(engine.leases()[0].preferred_until, 2800);
        assert_eq!(engine.leases()[0].valid_until, 5500);
    }

    #[test]
    fn pd_uses_ula_space_only_and_requires_route_ack() {
        let (config, link) = fixture();
        let mut failed = Dhcpv6::default();
        let reply = failed
            .handle(
                &packet(3, IA_PD, 3, None),
                context(&config, &link),
                &mut |_, _| Err(io::Error::other("injected ACK failure")),
            )
            .unwrap();
        assert_eq!(ia_status(&reply, IA_PD), 6);
        assert!(failed.leases().is_empty());
        let mut engine = Dhcpv6::default();
        let mut operations = Vec::new();
        let reply = engine
            .handle(
                &packet(3, IA_PD, 3, None),
                context(&config, &link),
                &mut |route, add| {
                    operations.push((route.clone(), add));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(ia_status(&reply, IA_PD), 0);
        assert_eq!(operations.len(), 1);
        assert_eq!(
            operations[0].0.destination,
            Prefix::new("fd00:1:0:4::".parse().unwrap(), 62).unwrap()
        );
        assert_eq!(operations[0].0.protocol, 4);
        assert_eq!(engine.leases()[0].addresses.len(), 1);
    }

    #[test]
    fn renew_withdraws_old_address_even_when_all_prefixes_disappear() {
        let (config, mut link) = fixture();
        let mut engine = Dhcpv6::default();
        engine
            .handle(
                &packet(3, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        let old = engine.leases()[0].addresses[0].clone();
        link.addresses.clear();
        let reply = engine
            .handle(
                &packet(5, IA_NA, 1, Some(old.clone())),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!(ia_status(&reply, IA_NA), 0);
        let parsed = options(&reply[4..]).unwrap();
        let ia = parsed.iter().find(|option| option.code == IA_NA).unwrap();
        let addresses = options(&ia.value[12..]).unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(&addresses[0].value[..16], &old.address.octets());
        assert_eq!(&addresses[0].value[16..24], &[0; 8]);
    }

    #[test]
    fn failed_route_delete_is_retained_and_retried_after_release() {
        let (config, link) = fixture();
        let mut engine = Dhcpv6::default();
        engine
            .handle(
                &packet(3, IA_PD, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        engine
            .handle(
                &packet(8, IA_PD, 1, None),
                context(&config, &link),
                &mut |_, add| {
                    assert!(!add);
                    Err(io::Error::other("delete failed"))
                },
            )
            .unwrap();
        assert!(engine.leases().is_empty());
        assert_eq!(engine.pending_routes().len(), 1);
        let mut retries = 0;
        let kernel = KernelState {
            links: vec![link],
            routes: engine.pending_routes().to_vec(),
        };
        engine
            .reconcile(
                &config,
                &kernel,
                Clock {
                    monotonic_ms: 101_000,
                    unix_seconds: 2_000_000_001,
                },
                &mut |_, add| {
                    assert!(!add);
                    retries += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(retries, 1);
        assert!(engine.pending_routes().is_empty());
    }

    #[test]
    fn malformed_later_ia_does_not_create_first_lease() {
        let (config, link) = fixture();
        let mut engine = Dhcpv6::default();
        let mut packet = packet(3, IA_NA, 1, None);
        push_option(&mut packet, IA_PD, &[0; 11]);
        assert!(engine
            .handle(&packet, context(&config, &link), &mut |_, _| panic!(
                "no route writes"
            ))
            .is_none());
        assert!(engine.leases().is_empty());
    }

    #[test]
    fn requested_timezone_defaults_and_information_request_without_clientid() {
        let (config, link) = fixture();
        let mut engine = Dhcpv6::default();
        let mut packet = vec![11, 1, 2, 3];
        push_option(&mut packet, ORO, &[0, 41, 0, 42]);
        let reply = engine
            .handle(&packet, context(&config, &link), &mut |_, _| {
                panic!("no routes")
            })
            .unwrap();
        let parsed = options(&reply[4..]).unwrap();
        assert_eq!(
            parsed
                .iter()
                .find(|option| option.code == 41)
                .unwrap()
                .value,
            b"CET-1CEST,M3.5.0,M10.5.0/3"
        );
        assert_eq!(
            parsed
                .iter()
                .find(|option| option.code == 42)
                .unwrap()
                .value,
            b"Europe/Berlin"
        );
        assert!(engine.leases().is_empty());
    }

    #[test]
    fn unicast_renew_does_not_allocate_and_unknown_multicast_renew_reports_no_binding() {
        let (config, link) = fixture();
        let mut engine = Dhcpv6::default();
        let mut unicast = context(&config, &link);
        unicast.destination = "2001:db8:1::1".parse().unwrap();
        let reply = engine
            .handle(&packet(5, IA_NA, 1, None), unicast, &mut |_, _| {
                panic!("no routes")
            })
            .unwrap();
        assert_eq!(
            options(&reply[4..])
                .unwrap()
                .iter()
                .find(|option| option.code == STATUS)
                .unwrap()
                .value,
            &[0, 5]
        );
        let reply = engine
            .handle(
                &packet(5, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| panic!("no routes"),
            )
            .unwrap();
        assert_eq!(ia_status(&reply, IA_NA), 3);
        assert!(engine.leases().is_empty());
    }

    #[test]
    fn configured_duid_without_iaid_can_move_to_a_new_iaid() {
        let (mut config, link) = fixture();
        config.hosts.push(HostConfig {
            duids: vec![HostDuid {
                duid: CLIENT.to_vec(),
                iaid: None,
            }],
            host_id: 0x123,
            hostname: Some("fixed".into()),
            ..HostConfig::default()
        });
        let mut engine = Dhcpv6::default();
        engine
            .handle(
                &packet(3, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        let reply = engine
            .handle(
                &packet(3, IA_NA, 2, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!(ia_status(&reply, IA_NA), 0);
        assert_eq!(engine.leases().len(), 1);
        assert_eq!(engine.leases()[0].iaid, 2);
        assert_eq!(engine.leases()[0].assigned, 0x123);
    }

    #[test]
    fn allocation_and_infinite_lifetimes_match_the_observed_c_packet() {
        let (config, mut link) = fixture();
        for address in &mut link.addresses {
            address.preferred_until = INFINITE;
            address.valid_until = INFINITE;
        }
        let mut engine = Dhcpv6::default();
        // Exact isolated C fixture observed by tools/odhcpd_baseline.py.
        let duid = [0, 3, 0, 1, 2, 0, 0, 0, 0, 2];
        let mut request = packet(3, IA_NA, 1, None);
        request[8..18].copy_from_slice(&duid);
        let reply = engine
            .handle(&request, context(&config, &link), &mut |_, _| Ok(()))
            .unwrap();
        assert_eq!(engine.leases()[0].assigned, 0x9ed);
        let parsed = options(&reply[4..]).unwrap();
        let ia = parsed.iter().find(|option| option.code == IA_NA).unwrap();
        assert_eq!(&ia.value[4..8], &1350u32.to_be_bytes());
        assert_eq!(&ia.value[8..12], &2160u32.to_be_bytes());
        for address in options(&ia.value[12..]).unwrap() {
            assert_eq!(&address.value[16..20], &43200u32.to_be_bytes());
            assert_eq!(&address.value[20..24], &43200u32.to_be_bytes());
        }
        assert_eq!(engine.leases()[0].preferred_until, 2800);
        assert_eq!(engine.leases()[0].valid_until, 5500);
    }

    #[test]
    fn managed_prefix_replacement_removes_the_old_pd_route() {
        let (mut config, mut link) = fixture();
        config.pools[0].ra_flags = 0xc0;
        let mut engine = Dhcpv6::default();
        engine
            .handle(
                &packet(3, IA_PD, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        let old = engine.pending_routes()[0].clone();
        link.addresses[1].address = "fd00:2::1".parse().unwrap();
        let kernel = KernelState {
            links: vec![link],
            routes: vec![old.clone()],
        };
        let mut changes = Vec::new();
        engine
            .reconcile(
                &config,
                &kernel,
                Clock {
                    monotonic_ms: 101_000,
                    unix_seconds: 2_000_000_001,
                },
                &mut |route, add| {
                    changes.push((route.clone(), add));
                    Ok(())
                },
            )
            .unwrap();
        assert!(changes.contains(&(old.clone(), false)));
        assert_eq!(engine.pending_routes().len(), 1);
        assert_ne!(engine.pending_routes()[0], old);
        assert_eq!(
            engine.pending_routes()[0].destination,
            Prefix::new("fd00:2:0:4::".parse().unwrap(), 62).unwrap()
        );
    }

    #[test]
    fn partial_pd_install_failure_keeps_failed_cleanup_for_retry() {
        let (config, mut link) = fixture();
        let mut second = link.addresses[1].clone();
        second.address = "fd00:2::1".parse().unwrap();
        link.addresses.push(second);
        let mut engine = Dhcpv6::default();
        let mut installs = 0;
        let reply = engine
            .handle(
                &packet(3, IA_PD, 1, None),
                context(&config, &link),
                &mut |_, add| {
                    if add {
                        installs += 1;
                    }
                    if add && installs == 1 {
                        Ok(())
                    } else {
                        Err(io::Error::other("injected install/cleanup failure"))
                    }
                },
            )
            .unwrap();
        assert_eq!(ia_status(&reply, IA_PD), 6);
        assert!(engine.leases().is_empty());
        assert_eq!(engine.pending_routes().len(), 1);
        let kernel = KernelState {
            links: vec![link],
            routes: engine.pending_routes().to_vec(),
        };
        let mut deletes = 0;
        engine
            .reconcile(
                &config,
                &kernel,
                Clock {
                    monotonic_ms: 101_000,
                    unix_seconds: 2_000_000_001,
                },
                &mut |_, add| {
                    assert!(!add);
                    deletes += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(deletes, 1);
        assert!(engine.pending_routes().is_empty());
    }

    #[test]
    fn adding_a_host_replaces_the_prior_dynamic_binding_on_request() {
        let (mut config, link) = fixture();
        let mut engine = Dhcpv6::default();
        engine
            .handle(
                &packet(3, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        config.hosts.push(HostConfig {
            duids: vec![HostDuid {
                duid: CLIENT.to_vec(),
                iaid: Some(1),
            }],
            host_id: 0x234,
            hostname: Some("new-host".into()),
            ..HostConfig::default()
        });
        let reply = engine
            .handle(
                &packet(5, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!(ia_status(&reply, IA_NA), 3);
        assert!(engine.leases().is_empty());
        engine
            .handle(
                &packet(3, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!(engine.leases()[0].assigned, 0x234);
        assert_eq!(
            engine.leases()[0].hostname.as_deref(),
            Some(b"new-host".as_slice())
        );
        assert!(engine.leases()[0].is_static);
    }

    #[test]
    fn declined_iid_keeps_current_ubus_addresses_without_a_bound_lease() {
        use owrt_ubus::{convert::fields_to_json, json::Json};
        let (config, mut link) = fixture();
        let mut engine = Dhcpv6::default();
        engine
            .handle(
                &packet(3, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        let assigned = engine.leases()[0].assigned;
        engine
            .handle(
                &packet(9, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| panic!("NA has no routes"),
            )
            .unwrap();
        assert_eq!(engine.leases()[0].addresses.len(), 2);
        link.addresses[0].address = "2001:db8:2::1".parse().unwrap();
        link.addresses[1].address = "fd00:2::1".parse().unwrap();
        let clock = context(&config, &link).clock;
        let kernel = KernelState {
            links: vec![link.clone()],
            routes: Vec::new(),
        };
        engine
            .reconcile(&config, &kernel, clock, &mut |_, _| {
                panic!("NA has no routes")
            })
            .unwrap();
        let json = fields_to_json(&crate::leases::ubus_leases(
            engine.leases(),
            &[link.name.clone()],
            clock,
        ));
        let entry = &json
            .get("device")
            .unwrap()
            .get("br-lan")
            .unwrap()
            .get("leases")
            .unwrap()
            .as_array()
            .unwrap()[0];
        assert_eq!(
            entry.get("duid").unwrap().as_str(),
            Some("00000000000000000000")
        );
        assert_eq!(entry.get("flags"), Some(&Json::Array(Vec::new())));
        assert_eq!(entry.get("valid"), Some(&Json::Int(3600)));
        let addresses = entry.get("ipv6-addr").unwrap().as_array().unwrap();
        assert_eq!(addresses.len(), 2);
        for (address, prefix) in addresses.iter().zip(["2001:db8:2", "fd00:2"]) {
            assert_eq!(
                address.get("address").unwrap().as_str().unwrap(),
                format!("{prefix}::{assigned:x}")
            );
            assert_eq!(address.get("preferred-lifetime"), Some(&Json::Int(2700)));
            assert_eq!(address.get("valid-lifetime"), Some(&Json::Int(3600)));
        }
        assert!(!engine.leases()[0].bound);
        engine
            .handle(
                &packet(3, IA_NA, 1, None),
                context(&config, &link),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        assert!(engine
            .leases()
            .iter()
            .any(|lease| lease.bound && lease.assigned != assigned));
    }

    #[test]
    fn decline_quarantines_a_named_host_without_a_fixed_iid() {
        for fixed in [0, 0x234] {
            let (mut config, link) = fixture();
            config.hosts.push(HostConfig {
                duids: vec![HostDuid {
                    duid: CLIENT.to_vec(),
                    iaid: None,
                }],
                host_id: fixed,
                hostname: Some("named-host".into()),
                ..HostConfig::default()
            });
            let mut engine = Dhcpv6::default();
            engine
                .handle(
                    &packet(3, IA_NA, 1, None),
                    context(&config, &link),
                    &mut |_, _| Ok(()),
                )
                .unwrap();
            engine
                .handle(
                    &packet(9, IA_NA, 1, None),
                    context(&config, &link),
                    &mut |_, _| Ok(()),
                )
                .unwrap();
            let kernel = KernelState {
                links: vec![link.clone()],
                routes: Vec::new(),
            };
            engine
                .reconcile(
                    &config,
                    &kernel,
                    context(&config, &link).clock,
                    &mut |_, _| Ok(()),
                )
                .unwrap();
            assert_eq!(engine.leases().len(), usize::from(fixed == 0));
            if fixed == 0 {
                assert!(engine.leases()[0].is_static);
                assert!(!engine.leases()[0].bound);
                assert_eq!(engine.leases()[0].addresses.len(), 2);
                assert_eq!(remaining(engine.leases()[0].valid_until, 100), 3600);
            }
        }
    }

    #[test]
    fn interface_down_clears_na_and_pd_and_retries_failed_route_cleanup() {
        let (config, mut link) = fixture();
        let mut engine = Dhcpv6::default();
        for kind in [IA_NA, IA_PD] {
            engine
                .handle(
                    &packet(3, kind, 1, None),
                    context(&config, &link),
                    &mut |_, _| Ok(()),
                )
                .unwrap();
        }
        assert_eq!(engine.leases().len(), 2);
        link.flags &= !0x40;
        let clock = context(&config, &link).clock;
        let kernel = KernelState {
            links: vec![link],
            routes: engine.pending_routes().to_vec(),
        };
        assert!(engine
            .reconcile(&config, &kernel, clock, &mut |_, add| {
                assert!(!add);
                Err(io::Error::other("injected delete failure"))
            })
            .is_err());
        assert!(engine.leases().is_empty());
        assert_eq!(engine.pending_routes().len(), 1);
        let mut retries = 0;
        engine
            .reconcile(&config, &kernel, clock, &mut |_, add| {
                assert!(!add);
                retries += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(retries, 1);
        assert!(engine.pending_routes().is_empty());
    }
}
