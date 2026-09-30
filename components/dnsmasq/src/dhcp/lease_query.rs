//! RFC4388 state from rfc2131.c:1066-1235, including dnsmasq's PRL semantics.
//! Context/tag/config resolution from stored relay/vendor data is an explicit
//! caller responsibility. The caller prunes expired leases before invocation.

use super::allocation::{available, narrow, AddressRange};
use super::lease::{ClientIdentity, LeaseStore};
use super::packet::Packet;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Unassigned = 11,
    Unknown = 12,
    Active = 13,
}

pub struct Query<'a> {
    pub packet: Packet<'a>,
    pub source: Ipv4Addr,
    pub enabled: bool,
    /// Empty means no configured ACL; IPv6-only entries deny IPv4 queries.
    pub allowed_sources: &'a [(IpAddr, u8)],
    pub tags: &'a [&'a [u8]],
    pub now: i64,
    pub ignore_client_id: bool,
    pub configured_lease_time: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseQueryReply {
    pub status: Status,
    pub client_address: Ipv4Addr,
    pub hardware_type: u8,
    pub hardware_address: Vec<u8>,
    pub context: Option<usize>,
    pub client_id: Option<Vec<u8>>,
    pub lease_time: Option<u32>,
    pub renewal_time: Option<u32>,
    pub rebinding_time: Option<u32>,
    pub last_transaction: Option<u32>,
    pub agent_id: Option<Vec<u8>>,
}

pub fn allowed_source(source: Ipv4Addr, allowed: &[(IpAddr, u8)]) -> bool {
    !source.is_unspecified()
        && (allowed.is_empty()
            || allowed.iter().any(|&(network, prefix)| {
                let IpAddr::V4(network) = network else {
                    return false;
                };
                if prefix > 32 {
                    return false;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(source) & mask == u32::from(network) & mask
            }))
}

pub fn query(
    store: &LeaseStore,
    ranges: &[AddressRange],
    query: Query<'_>,
) -> Option<LeaseQueryReply> {
    if query.packet.message_type() != 10
        || !query.enabled
        || !allowed_source(query.source, query.allowed_sources)
    {
        return None;
    }
    let packet = query.packet;
    let client = ClientIdentity {
        hardware_type: u32::from(packet.hardware_type()),
        hardware_address: packet.hardware_address().to_vec(),
        client_id: (!query.ignore_client_id)
            .then(|| packet.client_id().map(<[u8]>::to_vec))
            .flatten(),
    };
    let lease = if packet.effective_ciaddr().is_unspecified() {
        store.find_client(&client)
    } else {
        store.get(packet.effective_ciaddr())
    };
    let mut reply = LeaseQueryReply {
        status: Status::Unknown,
        client_address: Ipv4Addr::UNSPECIFIED,
        hardware_type: packet.hardware_type(),
        hardware_address: packet.hardware_address().to_vec(),
        context: None,
        client_id: None,
        lease_time: None,
        renewal_time: None,
        rebinding_time: None,
        last_transaction: None,
        agent_id: None,
    };
    if lease.is_none()
        && !packet.effective_ciaddr().is_unspecified()
        && available(ranges, packet.effective_ciaddr(), query.tags).is_some()
    {
        reply.status = Status::Unassigned;
        reply.client_address = packet.effective_ciaddr();
    }
    if let Some(lease) = lease {
        if let Some(context) = narrow(ranges, lease.address, query.tags) {
            reply.status = Status::Active;
            reply.client_address = lease.address;
            reply.hardware_type = lease.identity.hardware_type as u8;
            reply
                .hardware_address
                .clone_from(&lease.identity.hardware_address);
            reply.context = Some(context);
            if packet.requests(61) {
                reply.client_id.clone_from(&lease.identity.client_id);
            }
            if packet.requests(82) {
                reply.agent_id.clone_from(&lease.agent_id);
            }
            let remaining = lease
                .expires
                .map(|expires| expires.saturating_sub(query.now) as u32);
            if packet.requests(51) {
                reply.lease_time = Some(remaining.unwrap_or(u32::MAX));
            }
            if let Some(remaining) = remaining {
                let duration = query
                    .configured_lease_time
                    .unwrap_or(ranges[context].lease_time);
                if packet.requests(58) && remaining > duration / 2 {
                    reply.renewal_time = Some(remaining - duration / 2);
                }
                if packet.requests(59) && remaining > duration / 8 {
                    reply.rebinding_time = Some(remaining - duration / 8);
                }
                if packet.requests(91) && remaining < duration {
                    reply.last_transaction = Some(duration - remaining);
                }
            }
        }
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::super::allocation::RangeKind;
    use super::*;

    #[test]
    fn ipv6_only_acl_does_not_become_allow_all_for_ipv4() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        assert!(allowed_source(source, &[]));
        assert!(!allowed_source(Ipv4Addr::UNSPECIFIED, &[]));
        assert!(!allowed_source(
            source,
            &[(IpAddr::V6("::1".parse().unwrap()), 128)]
        ));
        assert!(allowed_source(
            source,
            &[(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)]
        ));
        assert!(!allowed_source(
            source,
            &[(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)]
        ));
    }

    #[test]
    fn leasequery_remaining_timers_and_infinite_values() {
        let address = Ipv4Addr::new(192, 0, 2, 10);
        let range = AddressRange {
            start: address,
            end: address,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 0, 2, 1),
            local: Ipv4Addr::new(192, 0, 2, 1),
            lease_time: 120,
            kind: RangeKind::Dynamic,
            filter: vec![],
            epoch: 0,
        };
        let mut bytes = vec![0; 240];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[12..16].copy_from_slice(&address.octets());
        bytes[236..240].copy_from_slice(&super::super::packet::COOKIE);
        bytes.extend_from_slice(&[53, 1, 10]);
        let packet = Packet::parse(&bytes).unwrap();
        let mut store = LeaseStore::new(1);
        store
            .allocate(
                address,
                ClientIdentity {
                    hardware_type: 1,
                    hardware_address: vec![2, 0, 0, 0, 0, 1],
                    client_id: Some(vec![1, 2, 3]),
                },
            )
            .unwrap();
        store.set_expires(address, 120, 120).unwrap();
        let make_query = || Query {
            packet,
            source: Ipv4Addr::LOCALHOST,
            enabled: true,
            allowed_sources: &[],
            tags: &[],
            now: 150,
            ignore_client_id: false,
            configured_lease_time: None,
        };
        let reply = query(&store, std::slice::from_ref(&range), make_query()).unwrap();
        assert_eq!(reply.status, Status::Active);
        assert_eq!(
            (
                reply.lease_time,
                reply.renewal_time,
                reply.rebinding_time,
                reply.last_transaction
            ),
            (Some(90), Some(30), Some(75), Some(30))
        );
        store.set_expires(address, u32::MAX, 150).unwrap();
        let reply = query(&store, &[range], make_query()).unwrap();
        assert_eq!(reply.lease_time, Some(u32::MAX));
        assert_eq!(
            (
                reply.renewal_time,
                reply.rebinding_time,
                reply.last_transaction
            ),
            (None, None, None)
        );
    }
}
