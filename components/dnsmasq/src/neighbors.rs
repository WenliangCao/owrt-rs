//! One nonblocking Linux neighbor snapshot shared by TFTP and script-arp.
//! Keys include the interface index, including for scoped IPv6 addresses.
//! A dump is published only after NLMSG_DONE; partial/error dumps never replace
//! the last complete snapshot. No request waits on the socket.
use rustix::net::{
    self, netlink::SocketAddrNetlink, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};

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
/// EDNS raw identity; C indexes its ARP cache by IP without interface scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EdnsMacLookup {
    Ready(Option<Vec<u8>>),
    Pending,
}
#[derive(Clone)]
struct EdnsRecord {
    address: IpAddr,
    hardware_address: Vec<u8>,
    status: RecordStatus,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RecordStatus {
    Mark,
    Found,
    New,
    Empty,
}
type Key = (IpAddr, u32);
const MAX_WAITERS: usize = 256;
const MAX_NEGATIVE: usize = 256;
struct Dump {
    sequence: u32,
    deadline: u64,
    entries: BTreeMap<Key, Vec<u8>>,
    edns: Vec<EdnsRecord>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum EdnsWaiter {
    Pending,
    /// The dump completed, but its negative record could not be allocated.
    /// Resume the current lookup once without inventing a cached absence.
    UncachedAbsent,
}
pub struct NeighborCache {
    socket: OwnedFd,
    sequence: u32,
    entries: BTreeMap<Key, Vec<u8>>,
    negative: BTreeMap<Key, u64>,
    waiting: BTreeSet<Key>,
    refreshed: Option<u64>,
    dump: Option<Dump>,
    edns_records: Vec<EdnsRecord>,
    edns_waiting: BTreeMap<IpAddr, EdnsWaiter>,
    old_records: Vec<EdnsRecord>,
    script_arp: bool,
}
impl NeighborCache {
    pub fn new() -> io::Result<Self> {
        let socket = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        net::bind(&socket, &SocketAddrNetlink::new(0, 0))?;
        Ok(Self {
            socket,
            sequence: 0,
            entries: BTreeMap::new(),
            negative: BTreeMap::new(),
            waiting: BTreeSet::new(),
            refreshed: None,
            dump: None,
            edns_records: Vec::new(),
            edns_waiting: BTreeMap::new(),
            old_records: Vec::new(),
            script_arp: false,
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

    /// Only an in-flight dump owns an independent timeout. C's90s freshness
    /// check and cached-negative expiry stay driven by service/query activity.
    pub fn active_dump_deadline(&self) -> Option<u64> {
        self.dump.as_ref().map(|dump| dump.deadline)
    }

    pub fn enable_script_arp(&mut self, enabled: bool) {
        self.script_arp = enabled;
        if !enabled {
            self.discard_script_changes();
        }
    }

    /// C checks freshness when its main loop wakes; there is no ARP timer.
    /// The owner supplies actual service/signal/poll activity, excluding its
    /// own housekeeping timeout. An existing dump remains nonblocking.
    pub fn refresh_script_arp(&mut self, now: u64, awake: bool) -> io::Result<()> {
        if self.script_arp
            && awake
            && self
                .refreshed
                .is_none_or(|last| now.saturating_sub(last) >= 90)
        {
            self.refresh(now)?;
        }
        Ok(())
    }

    /// Keep ownership until the one helper command slot accepts the event.
    /// C drains its old stack before traversing newly added records.
    pub fn front_script_change(&self) -> Option<NeighborChange> {
        if !self.script_arp {
            return None;
        }
        let (added, record) = if let Some(record) = self.old_records.last() {
            (false, record)
        } else {
            (
                true,
                self.edns_records
                    .iter()
                    .find(|record| record.status == RecordStatus::New)?,
            )
        };
        Some(NeighborChange {
            added,
            address: record.address,
            // C ARP identity and helper payload do not carry interface scope.
            interface: 0,
            hardware_address: record.hardware_address.clone(),
        })
    }

    pub fn pop_script_change(&mut self) {
        if self.old_records.pop().is_none() {
            if let Some(record) = self
                .edns_records
                .iter_mut()
                .find(|record| record.status == RecordStatus::New)
            {
                record.status = RecordStatus::Found;
            }
        }
    }

    /// TERM flushes the already serialized helper command, not unsent ARP
    /// records. No helper has the same record-draining effect without calls.
    pub fn discard_script_changes(&mut self) {
        self.old_records.clear();
        for record in &mut self.edns_records {
            if record.status == RecordStatus::New {
                record.status = RecordStatus::Found;
            }
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
        let sent = net::sendto(
            &self.socket,
            &request,
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )?;
        if sent != request.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short neighbor request",
            ));
        }
        self.dump = Some(Dump {
            sequence: self.sequence,
            deadline: now.saturating_add(2),
            entries: BTreeMap::new(),
            edns: Vec::new(),
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
    /// A new UDP request uses lazy=true. A TCP accept uses false once, to
    /// refresh a cached negative as arp.c does before fork. If Pending is
    /// returned, park the request and resume with lazy=true after owner.step;
    /// capture Ready once for the whole TCP connection. Never query per frame.
    pub fn query_edns(&mut self, address: IpAddr, lazy: bool, now: u64) -> EdnsMacLookup {
        // A nonlazy accept may have started a refresh of a fresh negative.
        // Its lazy owner resume must wait for that snapshot, rather than
        // capturing the old absence for the entire TCP connection.
        if let Some(state) = self.edns_waiting.get(&address).copied() {
            if state == EdnsWaiter::Pending {
                return EdnsMacLookup::Pending;
            }
            self.edns_waiting.remove(&address);
            return EdnsMacLookup::Ready(None);
        }
        if self
            .refreshed
            .is_some_and(|last| now.saturating_sub(last) < 90)
        {
            if let Some(record) = self
                .edns_records
                .iter()
                .find(|record| record.address == address)
            {
                if record.status != RecordStatus::Empty || lazy {
                    return EdnsMacLookup::Ready(
                        (!record.hardware_address.is_empty())
                            .then(|| record.hardware_address.clone()),
                    );
                }
            }
        }
        // Dump failure only suppresses retries briefly; it does not publish a
        // partial snapshot or make an expired positive record fresh.
        if self
            .negative
            .get(&(address, 0))
            .is_some_and(|until| now < *until)
        {
            return EdnsMacLookup::Ready(None);
        }
        if self.edns_waiting.len() >= MAX_WAITERS && !self.edns_waiting.contains_key(&address) {
            return EdnsMacLookup::Ready(None);
        }
        self.edns_waiting.insert(address, EdnsWaiter::Pending);
        if self.refresh(now).is_err() {
            self.fail_waiters(now);
            return EdnsMacLookup::Ready(None);
        }
        EdnsMacLookup::Pending
    }
    fn publish_edns(&mut self, dump: Vec<EdnsRecord>) {
        // Preserve filter_mac's list order: old confirmed identities remain in
        // place, and newly discovered identities are prepended in dump order.
        let mut records = std::mem::take(&mut self.edns_records);
        for record in &mut records {
            if record.status != RecordStatus::Empty {
                record.status = RecordStatus::Mark;
            }
        }
        for mut next in dump {
            if let Some(record) = records.iter_mut().find(|record| {
                record.status != RecordStatus::New
                    && record.address == next.address
                    && (record.status == RecordStatus::Empty
                        || record.hardware_address == next.hardware_address)
            }) {
                if record.status == RecordStatus::Empty {
                    record.hardware_address = next.hardware_address;
                    record.status = RecordStatus::New;
                } else {
                    record.status = RecordStatus::Found;
                }
            } else {
                // C whine_malloc failure skips this fresh cache record.
                // Reserve retirement storage here too, so moving an old
                // record later cannot introduce a second allocation boundary.
                let needed = records.len() + 1;
                if records.try_reserve_exact(1).is_err()
                    || (self.script_arp && self.old_records.try_reserve_exact(needed).is_err())
                {
                    continue;
                }
                next.status = RecordStatus::New;
                records.insert(0, next);
            }
        }
        let mut index = 0;
        while index < records.len() {
            if records[index].status == RecordStatus::Mark {
                let record = records.remove(index);
                if self.script_arp {
                    self.old_records.push(record);
                }
            } else {
                index += 1;
            }
        }
        self.edns_records = records;
        let mut waiting = std::mem::take(&mut self.edns_waiting);
        waiting.retain(|address, state| {
            if !self
                .edns_records
                .iter()
                .any(|record| record.address == *address)
            {
                if self
                    .edns_records
                    .iter()
                    .filter(|record| record.status == RecordStatus::Empty)
                    .count()
                    >= MAX_NEGATIVE
                {
                    if let Some(at) = self
                        .edns_records
                        .iter()
                        .rposition(|record| record.status == RecordStatus::Empty)
                    {
                        self.edns_records.remove(at);
                    }
                }
                if self.edns_records.try_reserve_exact(1).is_err()
                    || (self.script_arp
                        && self
                            .old_records
                            .try_reserve_exact(self.edns_records.len() + 1)
                            .is_err())
                {
                    *state = EdnsWaiter::UncachedAbsent;
                    return true;
                }
                self.edns_records.insert(
                    0,
                    EdnsRecord {
                        address: *address,
                        hardware_address: Vec::new(),
                        status: RecordStatus::Empty,
                    },
                );
            }
            false
        });
        self.edns_waiting = waiting;
        if !self.script_arp {
            self.discard_script_changes();
        }
    }
    fn fail_waiters(&mut self, now: u64) {
        self.dump = None;
        for (address, _) in std::mem::take(&mut self.edns_waiting) {
            self.remember_absent((address, 0), now.saturating_add(1));
        }
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
            let (_, count, sender) = match net::recvfrom(&self.socket, &mut bytes, RecvFlags::TRUNC)
            {
                Ok(result) => result,
                Err(error) => {
                    let error = io::Error::from(error);
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) {
                        break;
                    }
                    self.fail_waiters(now);
                    return Err(error);
                }
            };
            let kernel = sender
                .filter(|sender| sender.addr_len() == 12)
                .and_then(|sender| SocketAddrNetlink::try_from(sender).ok())
                .is_some_and(|sender| sender.pid() == 0);
            if !kernel {
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
        let dump = self.dump.take().unwrap();
        self.publish_edns(dump.edns);
        let next = dump.entries;
        self.entries = next;
        self.refreshed = Some(now);
        for key in std::mem::take(&mut self.waiting) {
            if !self.entries.contains_key(&key) {
                self.remember_absent(key, now.saturating_add(90));
            }
        }
    }
    pub fn take_changes(&mut self) -> Vec<NeighborChange> {
        let mut result = Vec::new();
        while let Some(change) = self.front_script_change() {
            result.push(change);
            self.pop_script_change();
        }
        result
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
                        dump.edns.push(EdnsRecord {
                            address: key.0,
                            hardware_address: mac.clone(),
                            status: RecordStatus::New,
                        });
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
            2 if value.len() <= 16 => mac = Some(value.to_vec()),
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
            edns: Vec::new(),
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
            edns_records: Vec::new(),
            edns_waiting: BTreeMap::new(),
            old_records: Vec::new(),
            script_arp: false,
        }
    }

    #[test]
    fn active_dump_timeout_clears_waiters_without_any_receive_event() {
        let mut cache = cache_without_network();
        let address = "192.0.2.17".parse().unwrap();
        cache.waiting.insert((address, 0));
        cache.edns_waiting.insert(address, EdnsWaiter::Pending);
        cache.dump = Some(Dump {
            sequence: 1,
            deadline: 102,
            entries: BTreeMap::new(),
            edns: Vec::new(),
        });
        assert_eq!(cache.active_dump_deadline(), Some(102));
        // The expiration check precedes recvfrom; no fd event or new query
        // is needed to abandon a dump missing NLMSG_DONE.
        assert_eq!(cache.step(102).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(cache.active_dump_deadline(), None);
        assert!(cache.waiting.is_empty());
        assert!(cache.edns_waiting.is_empty());
        assert_eq!(
            cache.query_edns(address, true, 102),
            EdnsMacLookup::Ready(None)
        );
    }

    #[test]
    fn idle_arp_freshness_and_negative_entries_do_not_schedule_a_timer() {
        let mut cache = cache_without_network();
        cache.enable_script_arp(true);
        cache.refreshed = Some(1);
        cache
            .negative
            .insert(("192.0.2.17".parse().unwrap(), 0), 100);
        assert_eq!(cache.active_dump_deadline(), None);
        cache.refresh_script_arp(200, false).unwrap();
        assert_eq!(cache.active_dump_deadline(), None);
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
    fn edns_raw_identity_ignores_interface_and_keeps_c_list_order() {
        let mut cache = cache_without_network();
        let address = "192.0.2.17".parse().unwrap();
        cache.publish_edns(vec![
            EdnsRecord {
                address,
                hardware_address: vec![1],
                status: RecordStatus::New,
            },
            EdnsRecord {
                address,
                hardware_address: vec![2; 16],
                status: RecordStatus::New,
            },
        ]);
        cache.refreshed = Some(1);
        assert_eq!(
            cache.query_edns(address, true, 2),
            EdnsMacLookup::Ready(Some(vec![2; 16]))
        );
        // Existing confirmed record stays in position on the next dump.
        cache.publish_edns(vec![EdnsRecord {
            address,
            hardware_address: vec![2; 16],
            status: RecordStatus::New,
        }]);
        assert_eq!(
            cache.query_edns(address, true, 2),
            EdnsMacLookup::Ready(Some(vec![2; 16]))
        );
    }
    #[test]
    fn edns_negative_accept_refresh_and_owner_failure_are_nonblocking() {
        let mut cache = cache_without_network();
        let address = "192.0.2.18".parse().unwrap();
        cache.edns_waiting.insert(address, EdnsWaiter::Pending);
        cache.publish_edns(Vec::new());
        cache.refreshed = Some(1);
        assert_eq!(
            cache.query_edns(address, true, 2),
            EdnsMacLookup::Ready(None)
        );
        // /dev/null send fails immediately; a negative TCP lookup still tries
        // refresh and receives the same absent result without a blocking wait.
        assert_eq!(
            cache.query_edns(address, false, 2),
            EdnsMacLookup::Ready(None)
        );
        assert!(cache.negative.contains_key(&(address, 0)));
        assert_eq!(cache.refreshed, Some(1));
    }
    #[test]
    fn lazy_resume_waits_for_the_accepts_negative_refresh() {
        let mut cache = cache_without_network();
        let address = "192.0.2.18".parse().unwrap();
        cache.edns_waiting.insert(address, EdnsWaiter::Pending);
        cache.publish_edns(Vec::new());
        cache.refreshed = Some(1);
        cache.edns_waiting.insert(address, EdnsWaiter::Pending);
        assert_eq!(cache.query_edns(address, true, 2), EdnsMacLookup::Pending);
        cache.publish_edns(vec![EdnsRecord {
            address,
            hardware_address: vec![2, 0, 0, 0, 0, 1],
            status: RecordStatus::New,
        }]);
        assert_eq!(
            cache.query_edns(address, true, 2),
            EdnsMacLookup::Ready(Some(vec![2, 0, 0, 0, 0, 1]))
        );
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

    #[test]
    fn script_order_backpressure_and_discard_follow_the_image() {
        let mut cache = cache_without_network();
        cache.enable_script_arp(true);
        let record = |last, mac| EdnsRecord {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
            hardware_address: vec![mac],
            status: RecordStatus::New,
        };
        cache.publish_edns(vec![record(17, 1), record(18, 2), record(19, 3)]);
        let first = cache.front_script_change().unwrap();
        assert_eq!(first.address, record(19, 3).address);
        assert_eq!(cache.front_script_change(), Some(first));
        let added = cache.take_changes();
        assert_eq!(
            added
                .iter()
                .map(|change| change.hardware_address[0])
                .collect::<Vec<_>>(),
            [3, 2, 1]
        );
        cache.publish_edns(vec![record(17, 1), record(18, 4)]);
        let changed = cache.take_changes();
        assert_eq!(
            changed
                .iter()
                .map(|change| (change.added, change.hardware_address[0]))
                .collect::<Vec<_>>(),
            [(false, 2), (false, 3), (true, 4)]
        );
        cache.publish_edns(vec![record(17, 5)]);
        assert!(cache.front_script_change().is_some());
        cache.discard_script_changes();
        assert!(cache.front_script_change().is_none());
        assert_eq!(cache.edns_records[0].hardware_address, [5]);
    }

    #[test]
    fn zero_positive_stays_positive_and_idle_timeout_does_not_refresh() {
        let mut cache = cache_without_network();
        let address = "192.0.2.18".parse().unwrap();
        cache.enable_script_arp(true);
        cache.publish_edns(vec![EdnsRecord {
            address,
            hardware_address: Vec::new(),
            status: RecordStatus::New,
        }]);
        cache.refreshed = Some(1);
        cache.pop_script_change();
        assert_eq!(
            cache.query_edns(address, true, 2),
            EdnsMacLookup::Ready(None)
        );
        assert_eq!(
            cache.query_edns(address, false, 2),
            EdnsMacLookup::Ready(None)
        );
        assert!(cache.edns_waiting.is_empty());
        assert!(cache.negative.is_empty());
        cache.refresh_script_arp(92, false).unwrap();
        assert!(cache.dump.is_none());
        assert_eq!(cache.refreshed, Some(1));
        assert!(cache.refresh_script_arp(92, true).is_err());
    }

    #[test]
    fn failed_negative_record_resumes_once_without_caching_the_absence() {
        let mut cache = cache_without_network();
        let address = "192.0.2.18".parse().unwrap();
        cache
            .edns_waiting
            .insert(address, EdnsWaiter::UncachedAbsent);
        assert_eq!(
            cache.query_edns(address, true, 1),
            EdnsMacLookup::Ready(None)
        );
        assert!(cache.edns_waiting.is_empty());
        assert_eq!(cache.sequence, 0);
        // The next lazy caller must enumerate again, as find_mac(updated=0)
        // does after C's negative whine_malloc failure.
        assert_eq!(
            cache.query_edns(address, true, 1),
            EdnsMacLookup::Ready(None)
        );
        assert_eq!(cache.sequence, 1);
    }
}
