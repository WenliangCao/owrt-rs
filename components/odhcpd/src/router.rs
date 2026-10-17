//! Server RA packets and successfully advertised PIO history. The caller owns
//! sockets and calls `sent` only after sending the most recently built packet.
//! No candidate PIO change reaches the state file before that success boundary.

use crate::config::PoolConfig;
use crate::model::{remaining, Address, Clock, KernelState, Prefix};
use owrt_ubus::json::{self, Json};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::Ipv6Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

pub struct RaContext<'a> {
    pub pool: &'a PoolConfig,
    pub kernel: &'a KernelState,
    /// Current interface hop_limit sysctl; zero when it cannot be read.
    pub hop_limit: u8,
    pub clock: Clock,
    /// Four random bytes, interpreted like C's signed int in calc_adv_interval.
    pub random: u32,
}

#[derive(Clone, Debug)]
pub struct Advertisement {
    /// ICMPv6 packet, with zero checksum for the raw socket to fill.
    pub bytes: Vec<u8>,
    pub destination: Ipv6Addr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Pio {
    // C stores the original address, including host bits, and original length.
    // The on-wire prefix is separately masked and is at least /64.
    address: Ipv6Addr,
    length: u8,
    stale_until: Option<u64>,
}

impl Pio {
    fn expired(&self, now: u64) -> bool {
        self.stale_until.is_some_and(|until| now > until)
    }

    fn matches(&self, address: &Address) -> bool {
        let length = 64.max(self.length).max(address.length);
        Prefix::new(self.address, length) == Prefix::new(address.address, length)
    }
}

pub struct Router {
    device: String,
    pios: Vec<Pio>,
    pending: Option<(Vec<Pio>, bool)>,
    sent_count: u32,
    next_ms: Option<u64>,
    dirty: bool,
}

impl Router {
    pub fn new(device: impl Into<String>, clock: Clock) -> Self {
        Self {
            device: device.into(),
            pios: Vec::new(),
            pending: None,
            sent_count: 0,
            next_ms: Some(clock.monotonic_ms.saturating_add(1000)),
            dirty: false,
        }
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    pub fn deadline(&self) -> Option<u64> {
        self.next_ms
    }

    /// Address/default-route changes and an enabled-interface reload use the
    /// same one-second timer as router_setup_interface/router_netevent_cb.
    pub fn trigger(&mut self, clock: Clock) {
        self.next_ms = Some(clock.monotonic_ms.saturating_add(1000));
    }

    pub fn timer(&mut self, context: &RaContext<'_>) -> Option<Advertisement> {
        if context.clock.monotonic_ms < self.next_ms? {
            return None;
        }
        let (packet, interval) = self.build(context, None);
        self.next_ms = Some(context.clock.monotonic_ms.saturating_add(interval));
        packet
    }

    /// Call after valid_solicitation and ingress-interface validation. A reply
    /// contributes to ra_sent, but does not move the periodic deadline.
    pub fn solicit(&mut self, context: &RaContext<'_>, source: Ipv6Addr) -> Option<Advertisement> {
        self.next_ms?;
        self.build(context, Some(source)).0
    }

    pub fn shutdown(&mut self, context: &RaContext<'_>) -> Option<Advertisement> {
        self.next_ms = None;
        self.build(context, None).0
    }

    /// Commit only the most recently returned packet after a successful send.
    /// A failed send must not call this; the next build discards its candidate.
    pub fn sent(&mut self) {
        if let Some((pios, changed)) = self.pending.take() {
            self.pios = pios;
            self.dirty |= changed;
            self.sent_count = self.sent_count.wrapping_add(1);
        }
    }

    fn build(
        &mut self,
        context: &RaContext<'_>,
        destination: Option<Ipv6Addr>,
    ) -> (Option<Advertisement>, u64) {
        self.pending = None;
        let Some(link) = context.kernel.link(&self.device) else {
            return (None, 1000);
        };
        let pool = context.pool;
        let now = context.clock.seconds();
        // Kernel snapshots preserve C's ordering at address-dump time:
        // relative preferred lifetime descending, with ULA's sort key = 1.
        // Do not re-sort or reset deprecated deadlines when handling a packet.
        let mut addresses: Vec<_> = link
            .addresses
            .iter()
            .filter(|address| address.scope == 0)
            .cloned()
            .collect();
        if self.next_ms.is_none() {
            addresses.clear();
        }
        let current_count = addresses.len();
        let mut pios = self.pios.clone();
        pios.retain(|pio| !pio.expired(now));
        for pio in &pios {
            if !addresses[..current_count]
                .iter()
                .any(|address| pio.matches(address))
            {
                addresses.push(Address {
                    address: pio.address,
                    length: pio.length,
                    preferred_until: 0,
                    valid_until: now.saturating_add(5400),
                    flags: 0,
                    scope: 0,
                });
            }
        }

        let mut default_route = pool.ra_default != 0;
        let mut delegated_lengths = vec![0; current_count];
        // C only scans /proc routes when there are current addresses and no
        // configured ra_default override. Preserve this also for RIO discovery.
        if current_count != 0 && !default_route {
            for route in &context.kernel.routes {
                let is_loopback = context
                    .kernel
                    .links
                    .iter()
                    .any(|item| item.index == route.interface && item.name == "lo");
                if route.destination.length == 0 && !is_loopback {
                    default_route = true;
                } else if is_loopback && route.kind == 7 && route.destination.length > 0 {
                    // RTN_UNREACHABLE on lo corresponds to the source-prefix
                    // RTF_NONEXTHOP|RTF_REJECT entry inspected by router.c.
                    for (index, address) in addresses[..current_count].iter().enumerate() {
                        if address.length <= 64
                            && address.length >= route.destination.length
                            && route.destination.contains(address.address)
                        {
                            delegated_lengths[index] = route.destination.length;
                            break;
                        }
                    }
                }
            }
        }

        let mut valid_prefix = pool.ra_default > 1;
        let mut lowest_lifetime = u32::MAX;
        let mut highest_lifetime = 0;
        let mut changed = false;
        let mut prefix_options: Vec<[u8; 32]> = Vec::new();
        for (index, address) in addresses.iter().enumerate() {
            if address.length > 96
                || (index < current_count && remaining(address.valid_until, now) == 0)
            {
                continue;
            }
            let valid = capped(remaining(address.valid_until, now), pool.max_valid_lifetime);
            let preferred = capped(
                remaining(address.preferred_until, now),
                pool.max_preferred_lifetime,
            )
            .min(valid);
            lowest_lifetime = lowest_lifetime.min(valid);
            let ula = address.prefix().is_ula();
            if (!ula || pool.ra_default != 0) && valid != 0 {
                valid_prefix = true;
            }
            if !ula {
                highest_lifetime = highest_lifetime.max(valid);
            }

            let mut option = [0; 32];
            option[0] = 3;
            option[1] = 4;
            option[2] = address.length.max(64);
            option[3] = if pool.ra_offlink { 0 } else { 0x80 }
                | if pool.ra_slaac && address.length <= 64 {
                    0x40
                } else {
                    0
                };
            option[16..32].copy_from_slice(&address.prefix().address.octets());
            if index >= current_count || preferred == 0 {
                if let Some(pio) = pios.iter_mut().find(|pio| pio.matches(address)) {
                    if pio.stale_until.is_none() {
                        pio.stale_until =
                            Some(now.saturating_add(u64::from(pool.max_valid_lifetime)));
                        changed = true;
                    }
                }
            } else {
                option[4..8].copy_from_slice(&valid.to_be_bytes());
                option[8..12].copy_from_slice(&preferred.to_be_bytes());
                match pios.iter_mut().find(|pio| pio.matches(address)) {
                    Some(pio) => {
                        if pio.address != address.address
                            || pio.length != address.length
                            || pio.stale_until.is_some()
                        {
                            pio.address = address.address;
                            pio.length = address.length;
                            pio.stale_until = None;
                            changed = true;
                        }
                    }
                    None => {
                        pios.push(Pio {
                            address: address.address,
                            length: address.length,
                            stale_until: None,
                        });
                        changed = true;
                    }
                }
            }
            // C compares the original length against the already adjusted
            // wire length. Keep that behavior for prefixes shorter than /64.
            if let Some(previous) = prefix_options.iter_mut().find(|previous| {
                previous[2] == address.length
                    && Prefix::new(
                        Ipv6Addr::from(<[u8; 16]>::try_from(&previous[16..32]).unwrap()),
                        address.length,
                    ) == Some(address.prefix())
            }) {
                *previous = option;
            } else {
                prefix_options.push(option);
            }
        }
        let mut index = 0;
        while index < pios.len() {
            let mut following = index + 1;
            while following < pios.len() {
                if pios[index].address == pios[following].address
                    && pios[index].length == pios[following].length
                {
                    pios.swap_remove(following);
                } else {
                    following += 1;
                }
            }
            index += 1;
        }

        let maximum = pool.ra_max_interval.min(lowest_lifetime);
        let interval = interval_ms(
            pool.ra_min_interval,
            maximum,
            self.sent_count,
            context.random,
        );
        let mut lifetime = if pool.ra_lifetime != 0 {
            pool.ra_lifetime
        } else {
            pool.max_preferred_lifetime
        };
        if lifetime > 0 && lifetime < maximum {
            lifetime = maximum;
        } else if lifetime > 5400 {
            lifetime = 5400;
        }
        if highest_lifetime == 0 {
            highest_lifetime = lifetime;
        }
        if link.link_local().is_none() {
            return (None, interval);
        }

        let mut packet = vec![0; 32];
        packet[0] = 134;
        packet[4] = if pool.ra_hop_limit == 0 {
            context.hop_limit
        } else {
            pool.ra_hop_limit
        };
        packet[5] = pool.ra_flags | preference_bits(pool.ra_preference);
        if default_route && valid_prefix {
            packet[6..8].copy_from_slice(&(lifetime.min(u16::MAX as u32) as u16).to_be_bytes());
        }
        packet[8..12].copy_from_slice(&pool.ra_reachable_time.to_be_bytes());
        packet[12..16].copy_from_slice(&pool.ra_retrans_time.to_be_bytes());
        packet[16] = 1;
        packet[17] = 1;
        packet[18..24].copy_from_slice(&link.mac);
        packet[24] = 5;
        packet[25] = 1;
        let mut mtu = pool.ra_mtu.unwrap_or(link.mtu);
        if link.mtu != 0 {
            mtu = mtu.min(link.mtu);
        }
        packet[28..32].copy_from_slice(&mtu.to_be_bytes());
        for prefix in prefix_options {
            packet.extend_from_slice(&prefix);
        }

        for (address, length) in addresses[..current_count].iter().zip(delegated_lengths) {
            if length == 0 || length >= 64 || remaining(address.valid_until, now) == 0 {
                continue;
            }
            let mut option = [0; 24];
            option[0] = 24;
            option[1] = 3;
            option[2] = length;
            option[3] = preference_bits(pool.ra_preference);
            option[4..8].copy_from_slice(
                &capped(remaining(address.valid_until, now), pool.max_valid_lifetime).to_be_bytes(),
            );
            option[8..24].copy_from_slice(
                &Prefix::new(address.address, length)
                    .unwrap()
                    .address
                    .octets(),
            );
            packet.extend_from_slice(&option);
        }
        if pool.ra_dns {
            let dns: Vec<_> = crate::dhcpv6::dns_addresses(pool, link, now)
                .into_iter()
                .take(127)
                .collect();
            if !dns.is_empty() {
                packet.extend_from_slice(&[25, 1 + 2 * dns.len() as u8, 0, 0]);
                packet.extend_from_slice(&highest_lifetime.to_be_bytes());
                for address in dns {
                    packet.extend_from_slice(&address.octets());
                }
            }
            if let Some(search) = search_option(&pool.domains, highest_lifetime) {
                packet.extend_from_slice(&search);
            }
        }
        packet.extend_from_slice(&[7, 1, 0, 0]);
        packet.extend_from_slice(&maximum.wrapping_mul(1000).to_be_bytes());
        self.pending = Some((pios, changed));
        (
            Some(Advertisement {
                bytes: packet,
                destination: destination
                    .filter(|address| !address.is_unspecified())
                    .unwrap_or(ALL_NODES),
            }),
            interval,
        )
    }

    /// One interface's array, for {"interfaces": {device: array}} aggregation.
    pub fn ipv6ra(&self, clock: Clock) -> Json {
        let now = clock.seconds();
        Json::Array(
            self.pios
                .iter()
                .filter(|pio| !pio.expired(now))
                .map(|pio| {
                    let mut fields = Vec::new();
                    if let Some(until) = pio.stale_until {
                        let lifetime = remaining(until, now);
                        if lifetime != 0 {
                            fields.push(("lifetime".into(), Json::Int(lifetime as i64)));
                        }
                    }
                    fields.push(("prefix".into(), Json::Str(pio.address.to_string())));
                    fields.push(("length".into(), Json::Int(pio.length as i64)));
                    fields.push(("stale".into(), Json::Bool(pio.stale_until.is_some())));
                    Json::Object(fields)
                })
                .collect(),
        )
    }

    fn state_path(&self, directory: &Path) -> io::Result<PathBuf> {
        if self.device.is_empty() || self.device.contains('/') || self.device.contains('\0') {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Ok(directory.join(format!("odhcpd.pio.{}", self.device)))
    }

    /// Missing state is normal. Malformed files leave existing history intact.
    pub fn load_state(&mut self, directory: &Path, clock: Clock) -> io::Result<()> {
        let bytes = match fs::read(self.state_path(directory)?) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let value = json::parse_bytes(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let Some(entries) = value.get("slaac").and_then(Json::as_array) else {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        let mut pios = Vec::new();
        for entry in entries {
            let Some(address) = entry
                .get("prefix")
                .and_then(Json::as_str)
                .and_then(|text| text.parse().ok())
            else {
                continue;
            };
            let Some(Json::Int(length)) = entry.get("length") else {
                continue;
            };
            if !(0..=128).contains(length) {
                continue;
            }
            let stale_until = match entry.get("time") {
                None | Some(Json::Int(0)) => None,
                Some(Json::Int(time)) => {
                    if i128::from(*time) < i128::from(clock.seconds()) || *time < clock.unix_seconds
                    {
                        continue;
                    }
                    let deadline = i128::from(*time) + i128::from(clock.seconds())
                        - i128::from(clock.unix_seconds);
                    let Ok(deadline) = u64::try_from(deadline) else {
                        continue;
                    };
                    Some(deadline)
                }
                _ => continue,
            };
            pios.push(Pio {
                address,
                length: *length as u8,
                stale_until,
            });
        }
        self.pios = pios;
        self.pending = None;
        self.dirty = false;
        Ok(())
    }

    /// Atomic replacement of successfully advertised state. Errors retain the
    /// dirty flag, so the caller can retry after a subsequent successful send.
    pub fn save_state(&mut self, directory: &Path, clock: Clock) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let path = self.state_path(directory)?;
        fs::create_dir_all(directory)?;
        let temporary = directory.join(format!(
            ".odhcpd.pio.{}.{}.tmp",
            self.device,
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temporary)?;
        let entries = self
            .pios
            .iter()
            .filter(|pio| !pio.expired(clock.seconds()))
            .map(|pio| {
                let mut fields = vec![
                    ("prefix".into(), Json::Str(pio.address.to_string())),
                    ("length".into(), Json::Int(pio.length as i64)),
                ];
                if let Some(until) = pio.stale_until {
                    let time = i128::from(until) + i128::from(clock.unix_seconds)
                        - i128::from(clock.seconds());
                    fields.push((
                        "time".into(),
                        Json::Int(time.clamp(i64::MIN as i128, i64::MAX as i128) as i64),
                    ));
                }
                Json::Object(fields)
            })
            .collect();
        let bytes = Json::Object(vec![("slaac".into(), Json::Array(entries))]).to_bytes();
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, path)
        })();
        if result.is_ok() {
            self.dirty = false;
        } else {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

/// The raw ICMPv6 socket verifies checksum; the caller checks pktinfo ingress.
pub fn valid_solicitation(packet: &[u8], source: Ipv6Addr, hop_limit: u8) -> bool {
    if packet.len() < 8 || packet[0] != 133 || packet[1] != 0 || hop_limit != 255 {
        return false;
    }
    let mut offset = 8;
    while offset < packet.len() {
        if packet.len() - offset < 8 {
            return false;
        }
        let length = packet[offset + 1] as usize * 8;
        if length == 0 || length > packet.len() - offset {
            return false;
        }
        if packet[offset] == 1 && source.is_unspecified() {
            return false;
        }
        offset += length;
    }
    true
}

fn capped(lifetime: u32, limit: u32) -> u32 {
    if limit == 0 {
        lifetime
    } else {
        lifetime.min(limit)
    }
}

fn preference_bits(preference: i8) -> u8 {
    match preference.cmp(&0) {
        std::cmp::Ordering::Less => 0x18,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 0x08,
    }
}

fn interval_ms(minimum: u32, maximum: u32, sent: u32, random: u32) -> u64 {
    // Keep C's unsigned subtraction/multiplication and final signed int. A
    // prefix can expire below MinRtrAdvInterval; do not silently retune it.
    let range = if maximum != minimum {
        maximum.wrapping_sub(minimum).wrapping_mul(1000)
    } else {
        500
    };
    let absolute = i64::from(random as i32).unsigned_abs();
    let mut interval =
        (absolute % u64::from(range.max(1)) + u64::from(minimum.wrapping_mul(1000))) as i32;
    if sent.wrapping_add(1) < 3 && interval > 16_000 {
        interval = 16_000;
    }
    // A C timeout scheduled in the past is immediately due in the event loop.
    interval.max(0) as u64
}

fn search_option(domains: &[String], lifetime: u32) -> Option<Vec<u8>> {
    if domains.is_empty() {
        return None;
    }
    let mut option = vec![31, 0, 0, 0];
    option.extend_from_slice(&lifetime.to_be_bytes());
    for domain in domains {
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        let start = option.len();
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            option.push(label.len() as u8);
            option.extend_from_slice(label.as_bytes());
        }
        option.push(0);
        if option.len() - start > 255 {
            return None;
        }
    }
    option.resize((option.len() + 7) & !7, 0);
    if option.len() / 8 > 255 {
        return None;
    }
    option[1] = (option.len() / 8) as u8;
    Some(option)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Link, Route, INFINITE};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn ip(value: &str) -> Ipv6Addr {
        value.parse().unwrap()
    }

    fn clock(milliseconds: u64) -> Clock {
        Clock {
            monotonic_ms: milliseconds,
            unix_seconds: 1_700_000_000 + (milliseconds / 1000) as i64,
        }
    }

    fn pool() -> PoolConfig {
        let mut pool = PoolConfig::new("lan".to_owned());
        pool.ifname = Some("br-lan".into());
        pool.ra = true;
        pool.dhcpv6 = true;
        pool.ra_flags = 0xc0;
        pool
    }

    fn address(value: &str, length: u8) -> Address {
        Address {
            address: ip(value),
            length,
            preferred_until: INFINITE,
            valid_until: INFINITE,
            flags: 0,
            scope: 0,
        }
    }

    fn kernel() -> KernelState {
        let mut local = address("fe80::1234", 64);
        local.scope = 253;
        KernelState {
            links: vec![
                Link {
                    name: "br-lan".into(),
                    index: 11,
                    flags: 0x40,
                    mtu: 1500,
                    mac: [2, 0, 0, 0, 0, 1],
                    addresses: vec![
                        address("2001:db8:1:1::1", 64),
                        address("fd00:1234:5600:ab::1", 60),
                        local,
                    ],
                },
                Link {
                    name: "lo".into(),
                    index: 7,
                    flags: 0,
                    mtu: 65536,
                    mac: [0; 6],
                    addresses: vec![],
                },
                Link {
                    name: "wan".into(),
                    index: 9,
                    flags: 0x40,
                    mtu: 1500,
                    mac: [0; 6],
                    addresses: vec![],
                },
            ],
            routes: vec![
                Route {
                    destination: Prefix::new(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
                    source: Prefix::new(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
                    gateway: Some(ip("fe80::1")),
                    interface: 9,
                    table: 254,
                    metric: 512,
                    kind: 1,
                    protocol: 16,
                },
                Route {
                    destination: Prefix::new(ip("fd00:1234:5600::"), 48).unwrap(),
                    source: Prefix::new(Ipv6Addr::UNSPECIFIED, 0).unwrap(),
                    gateway: None,
                    interface: 7,
                    table: 254,
                    metric: 0x7fff_ffff,
                    kind: 7,
                    protocol: 3,
                },
            ],
        }
    }

    fn context<'a>(
        pool: &'a PoolConfig,
        kernel: &'a KernelState,
        milliseconds: u64,
    ) -> RaContext<'a> {
        RaContext {
            pool,
            kernel,
            hop_limit: 64,
            clock: clock(milliseconds),
            random: 0,
        }
    }

    fn options(packet: &[u8], kind: u8) -> Vec<&[u8]> {
        let mut offset = 16;
        let mut found = Vec::new();
        while offset < packet.len() {
            let length = packet[offset + 1] as usize * 8;
            assert!(length != 0 && offset + length <= packet.len());
            if packet[offset] == kind {
                found.push(&packet[offset..offset + length]);
            }
            offset += length;
        }
        found
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn prefix_option(packet: &[u8], prefix: &str) -> Vec<u8> {
        options(packet, 3)
            .into_iter()
            .find(|option| option[16..32] == ip(prefix).octets())
            .unwrap()
            .to_vec()
    }

    #[test]
    fn actual_prefix_lengths_rio_dns_and_wire_order() {
        let pool = pool();
        let kernel = kernel();
        let mut router = Router::new("br-lan", clock(0));
        let packet = router.timer(&context(&pool, &kernel, 1000)).unwrap();
        assert_eq!(packet.destination, ALL_NODES);
        assert_eq!(&packet.bytes[..6], &[134, 0, 0, 0, 64, 0xc0]);
        assert_eq!(
            u16::from_be_bytes(packet.bytes[6..8].try_into().unwrap()),
            1800
        );
        assert_eq!(u32_at(options(&packet.bytes, 5)[0], 4), 1500);
        let pios = options(&packet.bytes, 3);
        assert_eq!(pios.len(), 2);
        assert_eq!(&pios[0][16..32], &ip("2001:db8:1:1::").octets());
        assert_eq!(&pios[1][16..32], &ip("fd00:1234:5600:a0::").octets());
        for pio in pios {
            assert_eq!(&pio[..4], &[3, 4, 64, 0xc0]);
            assert_eq!(u32_at(pio, 4), 5400);
            assert_eq!(u32_at(pio, 8), 2700);
        }
        let routes = options(&packet.bytes, 24);
        assert_eq!(routes.len(), 1);
        assert_eq!(&routes[0][..4], &[24, 3, 48, 0]);
        assert_eq!(&routes[0][8..24], &ip("fd00:1234:5600::").octets());
        let dns = options(&packet.bytes, 25);
        assert_eq!(dns.len(), 1);
        assert_eq!(&dns[0][8..24], &ip("fd00:1234:5600:ab::1").octets());
        assert_eq!(u32_at(dns[0], 4), 5400);
        assert_eq!(u32_at(options(&packet.bytes, 7)[0], 4), 600_000);
        assert!(options(&packet.bytes, 31).is_empty());
        router.sent();
        let state = router.ipv6ra(clock(1000));
        let ula = &state.as_array().unwrap()[1];
        assert_eq!(
            ula.get("prefix"),
            Some(&Json::Str("fd00:1234:5600:ab::1".into()))
        );
        assert_eq!(ula.get("length"), Some(&Json::Int(60)));
        assert_eq!(ula.get("stale"), Some(&Json::Bool(false)));
    }

    #[test]
    fn first_three_advertisements_and_solicited_reply_timing() {
        let pool = pool();
        let kernel = kernel();
        let mut router = Router::new("br-lan", clock(0));
        assert!(router.timer(&context(&pool, &kernel, 999)).is_none());
        for (time, next) in [(1000, 17_000), (17_000, 33_000), (33_000, 233_000)] {
            router.timer(&context(&pool, &kernel, time)).unwrap();
            assert_eq!(router.deadline(), Some(next));
            router.sent();
        }
        let unicast = router
            .solicit(&context(&pool, &kernel, 34_000), ip("fe80::4321"))
            .unwrap();
        assert_eq!(unicast.destination, ip("fe80::4321"));
        assert_eq!(router.deadline(), Some(233_000));
        router.sent();
        let multicast = router
            .solicit(&context(&pool, &kernel, 35_000), Ipv6Addr::UNSPECIFIED)
            .unwrap();
        assert_eq!(multicast.destination, ALL_NODES);
        router.trigger(clock(36_000));
        assert_eq!(router.deadline(), Some(37_000));
    }

    #[test]
    fn lost_wan_withdraws_old_gua_but_retains_ula_and_dns() {
        let pool = pool();
        let mut kernel = kernel();
        let mut router = Router::new("br-lan", clock(0));
        router.timer(&context(&pool, &kernel, 1000)).unwrap();
        router.sent();
        kernel.routes.retain(|route| route.destination.length != 0);
        kernel.links[0]
            .addresses
            .retain(|address| address.address != ip("2001:db8:1:1::1"));
        router.trigger(clock(2000));
        let packet = router.timer(&context(&pool, &kernel, 3000)).unwrap();
        assert_eq!(&packet.bytes[6..8], &[0, 0]);
        let old = prefix_option(&packet.bytes, "2001:db8:1:1::");
        assert_eq!(old[3], 0xc0);
        assert_eq!(&old[4..12], &[0; 8]);
        let ula = prefix_option(&packet.bytes, "fd00:1234:5600:a0::");
        assert_eq!(u32_at(&ula, 4), 5400);
        assert_eq!(u32_at(options(&packet.bytes, 25)[0], 4), 5400);
        router.sent();
        let state = router.ipv6ra(clock(3000));
        let old = &state.as_array().unwrap()[0];
        assert_eq!(old.get("stale"), Some(&Json::Bool(true)));
        assert_eq!(old.get("lifetime"), Some(&Json::Int(5400)));
        router
            .solicit(&context(&pool, &kernel, 4000), ip("fe80::4321"))
            .unwrap();
        router.sent();
        assert_eq!(
            router.ipv6ra(clock(4000)).as_array().unwrap()[0].get("lifetime"),
            Some(&Json::Int(5399))
        );
        kernel.links[0]
            .addresses
            .push(address("2001:db8:1:1::1", 64));
        router
            .solicit(&context(&pool, &kernel, 5000), ip("fe80::4321"))
            .unwrap();
        router.sent();
        assert_eq!(
            router.ipv6ra(clock(5000)).as_array().unwrap()[0].get("stale"),
            Some(&Json::Bool(false))
        );
    }

    #[test]
    fn prefix_replacement_advertises_new_and_zeroes_old_and_shutdown_stops_timer() {
        let pool = pool();
        let mut kernel = kernel();
        let mut router = Router::new("br-lan", clock(0));
        router.timer(&context(&pool, &kernel, 1000)).unwrap();
        router.sent();
        kernel.links[0].addresses[0] = address("2001:db8:2:1::1", 64);
        let packet = router
            .solicit(&context(&pool, &kernel, 2000), ip("fe80::4321"))
            .unwrap();
        assert_eq!(
            u32_at(&prefix_option(&packet.bytes, "2001:db8:2:1::"), 4),
            5400
        );
        assert_eq!(
            u32_at(&prefix_option(&packet.bytes, "2001:db8:1:1::"), 4),
            0
        );
        router.sent();
        let packet = router.shutdown(&context(&pool, &kernel, 3000)).unwrap();
        assert_eq!(router.deadline(), None);
        assert_eq!(&packet.bytes[6..8], &[0, 0]);
        assert!(options(&packet.bytes, 3)
            .iter()
            .all(|pio| pio[4..12] == [0; 8]));
        assert!(router
            .solicit(&context(&pool, &kernel, 4000), ip("fe80::4321"))
            .is_none());
    }

    #[test]
    fn same_prefix_new_interface_host_bits_replace_history_without_withdrawal() {
        let directory = Temporary::new();
        let pool = pool();
        let mut kernel = kernel();
        kernel.links[0].addresses[0] = address("2001:db8:1::1", 64);
        kernel.links[0].addresses[1] = address("fd12:3456:789a::1", 60);
        let mut router = Router::new("br-lan", clock(0));
        router.timer(&context(&pool, &kernel, 1000)).unwrap();
        router.sent();
        router.save_state(&directory.0, clock(1000)).unwrap();
        let state =
            json::parse_bytes(&fs::read(directory.0.join("odhcpd.pio.br-lan")).unwrap()).unwrap();
        assert_eq!(
            state,
            Json::Object(vec![(
                "slaac".into(),
                Json::Array(vec![
                    Json::Object(vec![
                        ("prefix".into(), Json::Str("2001:db8:1::1".into())),
                        ("length".into(), Json::Int(64))
                    ]),
                    Json::Object(vec![
                        ("prefix".into(), Json::Str("fd12:3456:789a::1".into())),
                        ("length".into(), Json::Int(60))
                    ]),
                ])
            )])
        );
        kernel.links[0].addresses[0].address = ip("2001:db8:1::2");
        let packet = router
            .solicit(&context(&pool, &kernel, 2000), ip("fe80::1"))
            .unwrap();
        assert_eq!(options(&packet.bytes, 3).len(), 2);
        assert_eq!(
            u32_at(&prefix_option(&packet.bytes, "2001:db8:1::"), 4),
            5400
        );
        router.sent();
        assert_eq!(
            router.ipv6ra(clock(2000)).as_array().unwrap()[0].get("prefix"),
            Some(&Json::Str("2001:db8:1::2".into()))
        );
        router.save_state(&directory.0, clock(2000)).unwrap();
        let saved = fs::read_to_string(directory.0.join("odhcpd.pio.br-lan")).unwrap();
        assert!(saved.contains("2001:db8:1::2"));
        assert!(!saved.contains("2001:db8:1::1"));
        assert!(!saved.contains("\"time\""));
    }

    #[test]
    fn deprecated_address_is_withdrawn_and_failed_send_does_not_commit_it() {
        let pool = pool();
        let mut kernel = kernel();
        let mut router = Router::new("br-lan", clock(0));
        router.timer(&context(&pool, &kernel, 1000)).unwrap();
        router.sent();
        let before = router.ipv6ra(clock(1000));
        kernel.links[0].addresses[0].flags = 0x20;
        kernel.links[0].addresses[0].preferred_until = 2;
        let packet = router
            .solicit(&context(&pool, &kernel, 2000), ip("fe80::4321"))
            .unwrap();
        assert_eq!(
            &prefix_option(&packet.bytes, "2001:db8:1:1::")[4..12],
            &[0; 8]
        );
        // Deliberately omit sent(), as for a failed sendmsg.
        assert_eq!(router.ipv6ra(clock(2000)), before);
        kernel.links[0].addresses[0].flags = 0;
        kernel.links[0].addresses[0].preferred_until = INFINITE;
        router
            .solicit(&context(&pool, &kernel, 3000), ip("fe80::4321"))
            .unwrap();
        router.sent();
        assert_eq!(router.ipv6ra(clock(3000)), before);
    }

    #[test]
    fn missing_link_local_suppresses_transmit_without_claiming_success() {
        let pool = pool();
        let mut kernel = kernel();
        kernel.links[0]
            .addresses
            .retain(|address| address.scope == 0);
        let mut router = Router::new("br-lan", clock(0));
        assert!(router.timer(&context(&pool, &kernel, 1000)).is_none());
        assert_eq!(router.deadline(), Some(17_000));
        router.sent();
        assert!(router.ipv6ra(clock(1000)).as_array().unwrap().is_empty());
        assert_eq!(router.sent_count, 0);
    }

    #[test]
    fn rs_requires_complete_options_hoplimit_and_unspecified_source_rule() {
        let plain = [133, 0, 0, 0, 0, 0, 0, 0];
        assert!(valid_solicitation(&plain, Ipv6Addr::UNSPECIFIED, 255));
        assert!(!valid_solicitation(&plain, ip("fe80::1"), 64));
        assert!(!valid_solicitation(&plain[..7], ip("fe80::1"), 255));
        let mut packet = plain.to_vec();
        packet.extend_from_slice(&[1, 1, 2, 0, 0, 0, 0, 1]);
        assert!(valid_solicitation(&packet, ip("fe80::1"), 255));
        assert!(!valid_solicitation(&packet, Ipv6Addr::UNSPECIFIED, 255));
        packet[8] = 99;
        assert!(valid_solicitation(&packet, Ipv6Addr::UNSPECIFIED, 255));
        packet[9] = 0;
        assert!(!valid_solicitation(&packet, ip("fe80::1"), 255));
        packet[9] = 2;
        assert!(!valid_solicitation(&packet, ip("fe80::1"), 255));
        packet.truncate(9);
        assert!(!valid_solicitation(&packet, ip("fe80::1"), 255));
    }

    #[test]
    fn explicit_dns_search_and_no_dns_service_have_distinct_meanings() {
        let mut pool = pool();
        let kernel = kernel();
        pool.dns_service = false;
        pool.dns = vec![ip("2001:db8::53")];
        pool.domains = vec!["example.test".into()];
        let mut router = Router::new("br-lan", clock(0));
        let packet = router.timer(&context(&pool, &kernel, 1000)).unwrap();
        assert_eq!(
            &options(&packet.bytes, 25)[0][8..24],
            &ip("2001:db8::53").octets()
        );
        assert_eq!(
            &options(&packet.bytes, 31)[0][8..22],
            b"\x07example\x04test\0"
        );
        pool.dns.clear();
        let packet = router
            .solicit(&context(&pool, &kernel, 2000), ip("fe80::1"))
            .unwrap();
        assert!(options(&packet.bytes, 25).is_empty());
        assert!(!options(&packet.bytes, 31).is_empty());
        pool.ra_dns = false;
        let packet = router
            .solicit(&context(&pool, &kernel, 3000), ip("fe80::1"))
            .unwrap();
        assert!(options(&packet.bytes, 31).is_empty());
    }

    static TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct Temporary(PathBuf);
    impl Temporary {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "odhcpd-ra-test-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn atomic_state_tracks_only_successful_transmits_and_recovers_wall_time() {
        let directory = Temporary::new();
        let pool = pool();
        let mut kernel = kernel();
        let mut router = Router::new("br-lan", clock(0));
        router.timer(&context(&pool, &kernel, 1000)).unwrap();
        router.save_state(&directory.0, clock(1000)).unwrap();
        assert!(!directory.0.join("odhcpd.pio.br-lan").exists());
        router.sent();
        router.save_state(&directory.0, clock(1000)).unwrap();
        let active = fs::read(directory.0.join("odhcpd.pio.br-lan")).unwrap();
        assert!(!String::from_utf8_lossy(&active).contains("\"time\""));
        kernel.links[0]
            .addresses
            .retain(|address| address.address != ip("2001:db8:1:1::1"));
        router
            .solicit(&context(&pool, &kernel, 2000), ip("fe80::1"))
            .unwrap();
        router.save_state(&directory.0, clock(2000)).unwrap();
        assert_eq!(
            fs::read(directory.0.join("odhcpd.pio.br-lan")).unwrap(),
            active
        );
        router.sent();
        router.save_state(&directory.0, clock(2000)).unwrap();
        let later = Clock {
            monotonic_ms: 10_000,
            unix_seconds: clock(2000).unix_seconds + 20,
        };
        let mut recovered = Router::new("br-lan", later);
        recovered.load_state(&directory.0, later).unwrap();
        let state = recovered.ipv6ra(later);
        assert_eq!(
            state.as_array().unwrap()[0].get("lifetime"),
            Some(&Json::Int(5380))
        );
        assert_eq!(
            state.as_array().unwrap()[1].get("length"),
            Some(&Json::Int(60))
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
        fs::write(directory.0.join("odhcpd.pio.br-lan"), b"{broken").unwrap();
        assert!(recovered.load_state(&directory.0, later).is_err());
        assert_eq!(recovered.ipv6ra(later), state);
    }
}
