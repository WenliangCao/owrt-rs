//! DHCP address-conflict cache and Linux ICMP dependency.
//! Exact references: dhcp.c:769-826, dnsmasq.c:2350-2505.
//!
//! Cache hits and documented C bypasses are distinct from I/O failures.
//! Failures are never cached as an available address; callers must retain
//! the error and return `ProbeResult::Failed` to stop an allocation scan.

use super::allocation::ProbeResult;
use std::io;
use std::net::Ipv4Addr;

pub const CACHE_SECONDS: i64 = 30;
pub const WAIT_SECONDS: u64 = 3;
// C: (int)(0.6 * (PING_CACHE_TIME / PING_WAIT)). No more than six
// successful checks can be live, so six fixed slots also hold expired nodes.
const CACHE_CAPACITY: usize = 6;

#[derive(Clone, Copy, Debug)]
struct Entry {
    address: Ipv4Addr,
    checked_at: i64,
    offer_hash: u32,
}

#[derive(Debug)]
pub struct PingCache {
    entries: [Entry; CACHE_CAPACITY],
    len: usize,
}

impl Default for PingCache {
    fn default() -> Self {
        Self {
            entries: [Entry {
                address: Ipv4Addr::UNSPECIFIED,
                checked_at: 0,
                offer_hash: 0,
            }; CACHE_CAPACITY],
            len: 0,
        }
    }
}

impl PingCache {
    /// Entries remain in C linked-list order; the last expired entry is the
    /// victim. Cache hits retain the original offer hash, including hash 0.
    pub fn check(
        &mut self,
        now: i64,
        address: Ipv4Addr,
        offer_hash: u32,
        no_ping: bool,
        loopback: bool,
        mut ping: impl FnMut(Ipv4Addr) -> io::Result<bool>,
    ) -> io::Result<ProbeResult> {
        let mut victim = None;
        let mut live = 0;
        for (index, entry) in self.entries[..self.len].iter().enumerate() {
            if now.saturating_sub(entry.checked_at) > CACHE_SECONDS {
                victim = Some(index);
            } else {
                live += 1;
                if entry.address == address {
                    return Ok(ProbeResult::Available {
                        offer_hash: entry.offer_hash,
                    });
                }
            }
        }
        if live >= CACHE_CAPACITY || no_ping || loopback {
            return Ok(ProbeResult::Available { offer_hash });
        }
        if ping(address)? {
            return Ok(ProbeResult::InUse);
        }
        let index = match victim {
            Some(index) => index,
            None => {
                // Six live entries returned above; an expired slot would
                // have supplied a victim. Thus this shift always fits.
                self.entries.copy_within(0..self.len, 1);
                self.len += 1;
                0
            }
        };
        self.entries[index] = Entry {
            address,
            checked_at: now,
            offer_hash,
        };
        Ok(ProbeResult::Available { offer_hash })
    }

    /// Observation boundary for the C state differential, without mutable
    /// access to the cache or leaking its representation into the allocator.
    pub fn entries(&self) -> impl Iterator<Item = (Ipv4Addr, i64, u32)> + '_ {
        self.entries[..self.len]
            .iter()
            .map(|entry| (entry.address, entry.checked_at, entry.offer_hash))
    }
}

/// Exact Linux `struct icmp` echo body: 28 bytes, native-endian random ID,
/// zero sequence/payload, and the C one's-complement checksum convention.
pub fn echo_request(id: u16) -> [u8; 28] {
    let mut packet = [0; 28];
    packet[0] = 8;
    packet[4..6].copy_from_slice(&id.to_ne_bytes());
    let mut sum: u32 = packet
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = if sum == 0xffff { 0xffff } else { !(sum as u16) };
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// C reads exactly a fixed 20-byte IPv4 header plus its 28-byte echo body.
/// recvfrom's fixed buffer also accepts a longer datagram truncated to 48.
pub fn echo_reply_matches(packet: &[u8], peer: Ipv4Addr, target: Ipv4Addr, id: u16) -> bool {
    packet.len() == 48
        && peer == target
        && packet[20] == 0
        && packet[26..28] == [0, 0]
        && packet[24..26] == id.to_ne_bytes()
}

/// `delay_dhcp` uses whole-second wall time with an inclusive bound and a
/// twelve-timeout fallback. A readiness event does not consume a timeout.
pub fn wait_pending(start: i64, now: i64, timeout_count: u32) -> bool {
    now.saturating_sub(start) <= WAIT_SECONDS as i64 && timeout_count < WAIT_SECONDS as u32 * 4
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn wall_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs().min(i64::MAX as u64) as i64,
        Err(error) => {
            let elapsed = error.duration();
            -(elapsed
                .as_secs()
                .saturating_add(u64::from(elapsed.subsec_nanos() != 0))
                .min(i64::MAX as u64) as i64)
        }
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub struct IcmpProbe {
    cache: PingCache,
    random: std::fs::File,
    no_ping: bool,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl IcmpProbe {
    pub fn new(no_ping: bool) -> io::Result<Self> {
        Ok(Self {
            cache: PingCache::default(),
            random: std::fs::File::open("/dev/urandom")?,
            no_ping,
        })
    }

    pub fn set_no_ping(&mut self, no_ping: bool) {
        self.no_ping = no_ping;
    }

    pub fn check(
        &mut self,
        now: i64,
        address: Ipv4Addr,
        hash: u32,
        loopback: bool,
    ) -> io::Result<ProbeResult> {
        self.check_with_stop(now, address, hash, loopback, || false)
    }

    pub fn check_with_stop(
        &mut self,
        now: i64,
        address: Ipv4Addr,
        hash: u32,
        loopback: bool,
        mut should_stop: impl FnMut() -> bool,
    ) -> io::Result<ProbeResult> {
        use std::io::Read;
        if should_stop() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "ICMP probe stopped",
            ));
        }
        self.cache
            .check(now, address, hash, self.no_ping, loopback, |address| {
                let mut bytes = [0; 2];
                self.random.read_exact(&mut bytes)?;
                ping(address, u16::from_ne_bytes(bytes), &mut should_stop)
            })
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn ping(address: Ipv4Addr, id: u16, should_stop: &mut impl FnMut() -> bool) -> io::Result<bool> {
    use std::time::Duration;
    let socket = crate::net::IcmpSocket::open()?;
    let request = echo_request(id);
    let mut retries = 0;
    loop {
        if should_stop() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "ICMP probe stopped",
            ));
        }
        match socket.send(&request, address) {
            Ok(()) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && retries < 1000 => {
                retries += 1;
                std::thread::sleep(Duration::from_micros(10));
            }
            Err(error) => return Err(error),
        }
    }
    let start = wall_seconds();
    let mut now = start;
    let mut timeout_count = 0;
    let mut packet = [0; 48];
    while wait_pending(start, now, timeout_count) {
        if should_stop() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "ICMP probe stopped",
            ));
        }
        let ready = match socket.wait(Duration::from_millis(250)) {
            Ok(ready) => ready,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        now = wall_seconds();
        if !ready {
            timeout_count += 1;
            continue;
        }
        match socket.receive(&mut packet) {
            Ok((length, peer)) if echo_reply_matches(&packet[..length], peer, address, id) => {
                return Ok(true)
            }
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_hash_expires_strictly_after_thirty_seconds() {
        let mut cache = PingCache::default();
        let address = Ipv4Addr::new(192, 0, 2, 10);
        assert_eq!(
            cache
                .check(100, address, 7, false, false, |_| Ok(false))
                .unwrap(),
            ProbeResult::Available { offer_hash: 7 }
        );
        assert_eq!(
            cache
                .check(130, address, 9, false, false, |_| panic!("cached"))
                .unwrap(),
            ProbeResult::Available { offer_hash: 7 }
        );
        assert_eq!(
            cache
                .check(99, address, 9, true, true, |_| panic!("cached"))
                .unwrap(),
            ProbeResult::Available { offer_hash: 7 }
        );
        assert_eq!(
            cache
                .check(131, address, 9, false, false, |_| Ok(true))
                .unwrap(),
            ProbeResult::InUse
        );
    }

    #[test]
    fn high_load_and_expired_victim_follow_c_list_order() {
        let mut cache = PingCache::default();
        for last in 1..=6 {
            cache
                .check(
                    100,
                    Ipv4Addr::new(192, 0, 2, last),
                    u32::from(last),
                    false,
                    false,
                    |_| Ok(false),
                )
                .unwrap();
        }
        let target = Ipv4Addr::new(192, 0, 2, 7);
        assert_eq!(
            cache
                .check(130, target, 7, false, false, |_| panic!("high load"))
                .unwrap(),
            ProbeResult::Available { offer_hash: 7 }
        );
        assert_eq!(cache.entries().count(), 6);
        cache
            .check(131, target, 7, false, false, |_| Ok(false))
            .unwrap();
        assert_eq!(cache.entries().last().unwrap(), (target, 131, 7));
    }

    #[test]
    fn probe_errors_never_become_negative_cache_entries() {
        let mut cache = PingCache::default();
        assert_eq!(
            cache
                .check(100, Ipv4Addr::LOCALHOST, 1, false, false, |_| Err(
                    io::Error::from(io::ErrorKind::PermissionDenied)
                ))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(cache.entries().count(), 0);
    }

    #[test]
    fn requested_address_failure_stops_scan_and_retains_pruned_outcome() {
        use crate::dhcp::{
            allocation::{AddressRange, RangeKind},
            lease::{ClientIdentity, LeaseStore},
            packet::COOKIE,
            runtime::{OutcomeProvider, StateProvider},
            service::{dispatch, Ingress, Listener},
            state::{Environment, Reply},
        };
        let server = Ipv4Addr::new(192, 0, 2, 1);
        let requested = Ipv4Addr::new(192, 0, 2, 10);
        let expired = Ipv4Addr::new(192, 0, 2, 20);
        let mut bytes = vec![0; 240];
        bytes[..3].copy_from_slice(&[1, 1, 6]);
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes.extend_from_slice(&[53, 1, 1, 50, 4, 192, 0, 2, 10, 255]);
        let dispatch = dispatch(
            &bytes,
            Ingress {
                listener: Listener::Dhcp,
                interface_index: 7,
                unicast_destination: false,
            },
            &[],
        )
        .unwrap();
        let mut store = LeaseStore::new(4);
        store
            .allocate(
                expired,
                ClientIdentity {
                    hardware_type: 1,
                    hardware_address: vec![2; 6],
                    client_id: None,
                },
            )
            .unwrap();
        store
            .set_hostname(expired, Some(b"expired"), false, None, false)
            .unwrap();
        store.set_expires(expired, 1, 98).unwrap();
        let mut ranges = [AddressRange {
            start: requested,
            end: expired,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: server,
            local: server,
            lease_time: 600,
            kind: RangeKind::Dynamic,
            filter: Vec::new(),
            epoch: 0,
        }];
        let environment = Environment {
            now: 100,
            interface: 7,
            authoritative: true,
            unicast_destination: false,
            ignored: false,
            ignore_client_id: false,
            fqdn_only: false,
            rapid_commit: false,
            bootp_dynamic: false,
            consecutive_addresses: false,
            override_server: None,
            fallback_server: server,
            server_aliases: &[],
        };
        let calls = std::cell::Cell::new(0);
        let mut provider = StateProvider::new(
            &mut store,
            &mut ranges,
            &[],
            None,
            &[],
            environment,
            |address, hash| {
                assert_eq!((address, hash), (requested, 0));
                calls.set(calls.get() + 1);
                ProbeResult::Failed
            },
        );
        let outcome = provider.resolve(&dispatch).unwrap();
        assert_eq!(outcome.reply, Reply::Ignore);
        assert_eq!(calls.get(), 1);
        assert_eq!(outcome.removed.len(), 1);
        assert_eq!(outcome.removed[0].address, expired);
        assert_eq!(outcome.lost_names[0].name, b"expired");
        assert!(provider.store.is_empty());
        assert_eq!(provider.ranges[0].epoch, 0);
    }
}
