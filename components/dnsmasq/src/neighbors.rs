//! One nonblocking Linux neighbor snapshot shared by TFTP and script-arp.
//! Keys include the interface index, including for scoped IPv6 addresses.
//! A dump is published only after NLMSG_DONE; partial/error dumps never replace
//! the last complete snapshot. No request waits on the socket.
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacLookup {
    Ready(Option<[u8; 6]>),
    Pending,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighborChange {
    pub added: bool,
    pub address: IpAddr,
    pub interface: u32,
    pub hardware_address: Vec<u8>,
}
type Key = (IpAddr, u32);
const MAX_WAITERS: usize = 256;
const MAX_NEGATIVE: usize = 256;
#[repr(C)]
struct Address {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}
extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn bind(fd: i32, address: *const u8, length: u32) -> i32;
    fn sendto(
        fd: i32,
        bytes: *const u8,
        length: usize,
        flags: i32,
        address: *const u8,
        address_length: u32,
    ) -> isize;
    fn recvfrom(
        fd: i32,
        bytes: *mut u8,
        length: usize,
        flags: i32,
        address: *mut u8,
        address_length: *mut u32,
    ) -> isize;
}
struct Dump {
    sequence: u32,
    deadline: u64,
    entries: BTreeMap<Key, Vec<u8>>,
}
pub struct NeighborCache {
    socket: OwnedFd,
    sequence: u32,
    entries: BTreeMap<Key, Vec<u8>>,
    negative: BTreeMap<Key, u64>,
    waiting: BTreeSet<Key>,
    refreshed: Option<u64>,
    dump: Option<Dump>,
    changes: Vec<NeighborChange>,
}
impl NeighborCache {
    pub fn new() -> io::Result<Self> {
        // SAFETY: socket returns a new descriptor with no borrowed arguments.
        let fd = unsafe { socket(16, 3 | 0x80000 | 0x800, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor is fresh and transferred to exactly one owner.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let address = Address {
            family: 16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        // SAFETY: initialized Linux sockaddr_nl occupies exactly 12 bytes.
        if unsafe { bind(fd, (&address as *const Address).cast(), 12) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            socket,
            sequence: 0,
            entries: BTreeMap::new(),
            negative: BTreeMap::new(),
            waiting: BTreeSet::new(),
            refreshed: None,
            dump: None,
            changes: Vec::new(),
        })
    }
    pub fn append_poll_fds(&self, fds: &mut Vec<owrt_ubus::sys::PollFd>) {
        if self.dump.is_some() {
            fds.push(owrt_ubus::sys::PollFd {
                fd: self.socket.as_raw_fd(),
                events: owrt_ubus::sys::POLLIN,
                revents: 0,
            });
        }
    }
    /// Trigger a snapshot for script-arp without waiting for a MAC consumer.
    pub fn refresh(&mut self, now: u64) -> io::Result<()> {
        if self.dump.is_some() {
            return Ok(());
        }
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let mut request = [0u8; 28];
        request[..4].copy_from_slice(&28u32.to_ne_bytes());
        request[4..6].copy_from_slice(&30u16.to_ne_bytes()); // RTM_GETNEIGH
        request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST|DUMP
        request[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        let address = Address {
            family: 16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        // SAFETY: live initialized request and kernel destination; no retained pointer.
        let sent = unsafe {
            sendto(
                self.socket.as_raw_fd(),
                request.as_ptr(),
                request.len(),
                0,
                (&address as *const Address).cast(),
                12,
            )
        };
        if sent != request.len() as isize {
            return Err(if sent < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::new(io::ErrorKind::WriteZero, "short neighbor request")
            });
        }
        self.dump = Some(Dump {
            sequence: self.sequence,
            deadline: now.saturating_add(2),
            entries: BTreeMap::new(),
        });
        Ok(())
    }
    pub fn query(&mut self, address: IpAddr, interface: u32, now: u64) -> MacLookup {
        let key = (address, interface);
        if self
            .refreshed
            .is_some_and(|last| now.saturating_sub(last) < 90)
        {
            if let Some(mac) = self.entries.get(&key) {
                return MacLookup::Ready(mac.as_slice().try_into().ok());
            }
        }
        // A failed dump suppresses retries briefly without refreshing the
        // positive snapshot. Lazy misses never extend old MAC lifetimes.
        if self.negative.get(&key).is_some_and(|until| now < *until) {
            return MacLookup::Ready(None);
        }
        if self.waiting.len() >= MAX_WAITERS && !self.waiting.contains(&key) {
            return MacLookup::Ready(None);
        }
        self.waiting.insert(key);
        if self.refresh(now).is_err() {
            self.fail_waiters(now);
            return MacLookup::Ready(None);
        }
        MacLookup::Pending
    }
    fn fail_waiters(&mut self, now: u64) {
        self.dump = None;
        for key in std::mem::take(&mut self.waiting) {
            self.remember_absent(key, now.saturating_add(1));
        }
    }
    fn remember_absent(&mut self, key: Key, until: u64) {
        if self.negative.len() >= MAX_NEGATIVE && !self.negative.contains_key(&key) {
            if let Some(oldest) = self
                .negative
                .iter()
                .min_by_key(|(_, deadline)| *deadline)
                .map(|(key, _)| *key)
            {
                self.negative.remove(&oldest);
            }
        }
        self.negative.insert(key, until);
    }
    /// At most sixteen datagrams per owner step. Kernel timeout/error abandons
    /// the incomplete dump; waiting RRQs can then use the ordinary root.
    pub fn step(&mut self, now: u64) -> io::Result<()> {
        self.negative.retain(|_, until| now < *until);
        if self.dump.as_ref().is_some_and(|dump| now >= dump.deadline) {
            self.fail_waiters(now);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "neighbor snapshot timeout",
            ));
        }
        let mut bytes = [0u8; 32768];
        for _ in 0..16 {
            if self.dump.is_none() {
                break;
            }
            let mut sender = Address {
                family: 0,
                pad: 0,
                pid: u32::MAX,
                groups: 0,
            };
            let mut sender_len = 12;
            // SAFETY: initialized writable buffers exactly match supplied lengths.
            let count = unsafe {
                recvfrom(
                    self.socket.as_raw_fd(),
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    32,
                    (&mut sender as *mut Address).cast(),
                    &mut sender_len,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    break;
                }
                self.fail_waiters(now);
                return Err(error);
            }
            if sender_len != 12 || sender.pid != 0 {
                continue;
            }
            if count as usize > bytes.len() {
                self.fail_waiters(now);
                return Err(malformed());
            }
            let result = parse_messages(&bytes[..count as usize], self.dump.as_mut().unwrap());
            match result {
                Ok(true) => self.publish(now),
                Ok(false) => {}
                Err(error) => {
                    self.fail_waiters(now);
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    fn publish(&mut self, now: u64) {
        let next = self.dump.take().unwrap().entries;
        for (&(address, interface), mac) in &self.entries {
            if next.get(&(address, interface)) != Some(mac) {
                self.changes.push(NeighborChange {
                    added: false,
                    address,
                    interface,
                    hardware_address: mac.clone(),
                });
            }
        }
        for (&(address, interface), mac) in &next {
            if self.entries.get(&(address, interface)) != Some(mac) {
                self.changes.push(NeighborChange {
                    added: true,
                    address,
                    interface,
                    hardware_address: mac.clone(),
                });
            }
        }
        self.entries = next;
        self.refreshed = Some(now);
        for key in std::mem::take(&mut self.waiting) {
            if !self.entries.contains_key(&key) {
                self.remember_absent(key, now.saturating_add(90));
            }
        }
    }
    pub fn take_changes(&mut self) -> Vec<NeighborChange> {
        std::mem::take(&mut self.changes)
    }
}
fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid neighbor snapshot")
}
fn aligned(n: usize) -> usize {
    (n + 3) & !3
}
fn parse_messages(bytes: &[u8], dump: &mut Dump) -> io::Result<bool> {
    let mut at = 0;
    let mut done = false;
    while at < bytes.len() {
        if bytes.len() - at < 16 {
            return Err(malformed());
        }
        let length = u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        if length < 16 || length > bytes.len() - at {
            return Err(malformed());
        }
        let kind = u16::from_ne_bytes(bytes[at + 4..at + 6].try_into().unwrap());
        let flags = u16::from_ne_bytes(bytes[at + 6..at + 8].try_into().unwrap());
        let sequence = u32::from_ne_bytes(bytes[at + 8..at + 12].try_into().unwrap());
        if sequence == dump.sequence {
            if flags & 0x10 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "interrupted neighbor dump",
                ));
            }
            let payload = &bytes[at + 16..at + length];
            match kind {
                2 | 3 => {
                    if kind == 2 || !payload.is_empty() {
                        if payload.len() < 4 {
                            return Err(malformed());
                        }
                        let error = i32::from_ne_bytes(payload[..4].try_into().unwrap());
                        if error != 0 {
                            return Err(io::Error::from_raw_os_error(error.saturating_neg()));
                        }
                    }
                    done |= kind == 3;
                }
                28 => {
                    if let Some((key, mac)) = parse_neighbor(payload)? {
                        dump.entries.insert(key, mac);
                    }
                }
                _ => {}
            }
        }
        at += aligned(length);
    }
    Ok(done)
}
fn parse_neighbor(bytes: &[u8]) -> io::Result<Option<(Key, Vec<u8>)>> {
    if bytes.len() < 12 {
        return Err(malformed());
    }
    let family = bytes[0];
    if !matches!(family, 2 | 10) {
        return Ok(None);
    }
    let index = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    let state = u16::from_ne_bytes(bytes[8..10].try_into().unwrap());
    if index == 0 || state & (0x40 | 0x01 | 0x20) != 0 {
        return Ok(None);
    }
    let mut at = 12;
    let mut address = None;
    let mut mac = None;
    while at < bytes.len() {
        if bytes.len() - at < 4 {
            return Err(malformed());
        }
        let length = u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
        if length < 4 || length > bytes.len() - at {
            return Err(malformed());
        }
        let kind = u16::from_ne_bytes(bytes[at + 2..at + 4].try_into().unwrap());
        let value = &bytes[at + 4..at + length];
        match kind {
            1 => {
                address = Some(match family {
                    2 if value.len() == 4 => {
                        IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(value).unwrap()))
                    }
                    10 if value.len() == 16 => {
                        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(value).unwrap()))
                    }
                    _ => return Err(malformed()),
                })
            }
            2 if !value.is_empty() && value.len() <= 16 => mac = Some(value.to_vec()),
            _ => {}
        }
        at += aligned(length);
    }
    Ok(address
        .zip(mac)
        .map(|(address, mac)| ((address, index), mac)))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn payload(family: u8, index: u32, address: &[u8], mac: &[u8]) -> Vec<u8> {
        let mut data = vec![0; 12];
        data[0] = family;
        data[4..8].copy_from_slice(&index.to_ne_bytes());
        data[8] = 2;
        for (kind, value) in [(1u16, address), (2, mac)] {
            data.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
            data.extend_from_slice(&kind.to_ne_bytes());
            data.extend_from_slice(value);
            data.resize(aligned(data.len()), 0);
        }
        data
    }
    #[test]
    fn scoped_neighbors_and_kernel_states() {
        let ip = Ipv6Addr::LOCALHOST.octets();
        let a = payload(10, 2, &ip, &[2, 0, 0, 0, 0, 1]);
        let mut b = a.clone();
        b[4..8].copy_from_slice(&3u32.to_ne_bytes());
        assert_ne!(parse_neighbor(&a).unwrap(), parse_neighbor(&b).unwrap());
        for state in [1, 0x20, 0x40] {
            b[8] = state;
            assert!(parse_neighbor(&b).unwrap().is_none());
        }
        let p = payload(2, 2, &[192, 0, 2, 1], &[2, 0, 0, 0, 0, 1]);
        assert_eq!(parse_neighbor(&p).unwrap().unwrap().1, [2, 0, 0, 0, 0, 1]);
    }
    #[test]
    fn malformed_attributes_never_publish_a_partial_snapshot() {
        let p = payload(2, 2, &[192, 0, 2, 1], &[2, 0, 0, 0, 0, 1]);
        for length in 0..12 {
            assert!(parse_neighbor(&p[..length]).is_err());
        }
        let mut broken = p.clone();
        broken[12..14].copy_from_slice(&3u16.to_ne_bytes());
        assert!(parse_neighbor(&broken).is_err());
        broken = p.clone();
        broken[12..14].copy_from_slice(&500u16.to_ne_bytes());
        assert!(parse_neighbor(&broken).is_err());
        let mut dump = Dump {
            sequence: 7,
            deadline: 1,
            entries: BTreeMap::new(),
        };
        let mut done = vec![0; 20];
        done[..4].copy_from_slice(&20u32.to_ne_bytes());
        done[4..6].copy_from_slice(&3u16.to_ne_bytes());
        done[8..12].copy_from_slice(&7u32.to_ne_bytes());
        assert!(parse_messages(&done, &mut dump).unwrap());
        done[6] = 0x10;
        assert!(parse_messages(&done, &mut dump).is_err());
    }
    fn cache_without_network() -> NeighborCache {
        NeighborCache {
            socket: std::fs::File::open("/dev/null").unwrap().into(),
            sequence: 0,
            entries: BTreeMap::new(),
            negative: BTreeMap::new(),
            waiting: BTreeSet::new(),
            refreshed: None,
            dump: None,
            changes: Vec::new(),
        }
    }
    #[test]
    fn dump_failure_does_not_make_expired_positive_entries_fresh() {
        let mut cache = cache_without_network();
        let key = ("192.0.2.1".parse().unwrap(), 2);
        cache.entries.insert(key, vec![2, 0, 0, 0, 0, 1]);
        cache.refreshed = Some(1);
        cache.waiting.insert(key);
        cache.fail_waiters(100);
        assert_eq!(cache.refreshed, Some(1));
        assert_eq!(cache.query(key.0, key.1, 100), MacLookup::Ready(None));
        assert_eq!(cache.entries[&key], [2, 0, 0, 0, 0, 1]);
    }
    #[test]
    fn lazy_negative_and_waiter_tables_are_bounded() {
        let mut cache = cache_without_network();
        for value in 1..1024u32 {
            let key = (IpAddr::V4(Ipv4Addr::from(value)), 2);
            cache.remember_absent(key, 100);
        }
        assert_eq!(cache.negative.len(), MAX_NEGATIVE);
        for value in 1..=MAX_WAITERS as u32 {
            cache.waiting.insert((IpAddr::V4(Ipv4Addr::from(value)), 2));
        }
        assert_eq!(
            cache.query("192.0.2.1".parse().unwrap(), 2, 1),
            MacLookup::Ready(None)
        );
        assert_eq!(cache.waiting.len(), MAX_WAITERS);
    }
}
