//! Actual parent publication/import boundary; expected conflicts follow C.
use super::*;
use dnsmasq_rs::dhcp::persistence::{DnsLeaseRecord, DnsPublisher};
use dnsmasq_rs::dns::cache::{Cache, CacheCounters, CacheTransaction, Kind, Record, StalePolicy};
use dnsmasq_rs::dns::wire::{Message, Name, PacketWriter, Section};

const HOST: &str = "leaseold.cache.test";

fn parent() -> Rc<RefCell<ParentDns>> {
    let mut config = DnsConfig::default();
    config.no_resolv = true;
    config.no_hosts = true;
    let mut daemon =
        DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions::default()).unwrap();
    daemon.enable_cache(150, 0, 0, StalePolicy::Disabled);
    Rc::new(RefCell::new(ParentDns {
        query_ids: Default::default(),
        local: LocalDnsService::new(config, Hosts::new(), 0, 1232),
        daemon: Some(daemon),
        pending_hosts: None,
        hosts_initializing: false,
    }))
}

fn publish(parent: &Rc<RefCell<ParentDns>>, address: Option<&str>) {
    let records: Vec<_> = address
        .into_iter()
        .map(|address| DnsLeaseRecord {
            name: HOST.as_bytes(),
            address: address.parse().unwrap(),
            expires: Some(220),
        })
        .collect();
    LeasePublisher {
        parent: Rc::clone(parent),
        policy: LeasePolicy {
            dhcp_ttl: Some(120),
            ..LeasePolicy::default()
        },
    }
    .replace(&records)
    .unwrap();
}

fn child(parent: &Rc<RefCell<ParentDns>>) -> Cache {
    parent
        .borrow()
        .daemon
        .as_ref()
        .unwrap()
        .tcp_cache_view()
        .unwrap()
}

fn commit(cache: &mut Cache, address: [u8; 4]) -> CacheTransaction {
    cache.start_insert();
    cache
        .insert(
            Record {
                name: Name::from_ascii(HOST).unwrap(),
                kind: Kind::Ipv4,
                negative: false,
                data: address.to_vec(),
            },
            100,
            600,
        )
        .unwrap();
    cache
        .capture_commit_counted(&mut CacheCounters::default())
        .unwrap()
}

fn addresses(cache: &mut Cache) -> Vec<Vec<u8>> {
    cache
        .lookup(&Name::from_ascii(HOST).unwrap(), &[Kind::Ipv4], 101, false)
        .into_iter()
        .map(|id| cache.get(id).unwrap().record.data.clone())
        .collect()
}

#[test]
fn lease_import_uses_current_publication_and_preserves_old_child() {
    let parent = parent();
    let mut old = child(&parent);
    // Publication happens while this pre-lease child's upstream reply is held.
    publish(&parent, Some("192.0.2.42"));
    let transaction = commit(&mut old, [198, 51, 100, 7]);
    assert!(!parent
        .borrow_mut()
        .import_tcp_cache_transfer(transaction, 101));
    assert_eq!(addresses(&mut old), [vec![198, 51, 100, 7]]);
    assert!(
        addresses(&mut child(&parent)).is_empty(),
        "no conflicting forwarded record reaches a new view"
    );
    let mut query = PacketWriter::new(7, 0x100, 1232).unwrap();
    query
        .question(&Name::from_ascii(HOST).unwrap(), 1, 1)
        .unwrap();
    let reply = parent
        .borrow_mut()
        .local
        .handle_udp_at(&query.finish(), 101)
        .unwrap()
        .unwrap();
    let message = Message::parse(&reply).unwrap();
    let answer = message.records(Section::Answer).next().unwrap();
    assert_eq!(answer.rdata, [192, 0, 2, 42]);
    assert_eq!(answer.ttl, 119);
}

#[test]
fn lease_import_discards_same_address_without_forwarded_cache_entry() {
    let parent = parent();
    let mut old = child(&parent);
    publish(&parent, Some("192.0.2.42"));
    let transaction = commit(&mut old, [192, 0, 2, 42]);
    assert!(parent
        .borrow_mut()
        .import_tcp_cache_transfer(transaction, 101));
    assert!(addresses(&mut child(&parent)).is_empty());
}

#[test]
fn lease_import_uses_release_instead_of_the_previous_generation() {
    let parent = parent();
    publish(&parent, Some("192.0.2.42"));
    let mut old = child(&parent);
    publish(&parent, None);
    let transaction = commit(&mut old, [198, 51, 100, 7]);
    assert!(parent
        .borrow_mut()
        .import_tcp_cache_transfer(transaction, 101));
    assert_eq!(addresses(&mut child(&parent)), [vec![198, 51, 100, 7]]);
}

#[test]
fn lease_import_observes_current_hosts_from_the_same_parent() {
    let parent = parent();
    let mut old = child(&parent);
    parent.borrow_mut().local.hosts.insert(
        HOST.as_bytes().to_vec(),
        "192.0.2.42".parse().unwrap(),
        0,
        1,
    );
    let transaction = commit(&mut old, [198, 51, 100, 7]);
    assert!(!parent
        .borrow_mut()
        .import_tcp_cache_transfer(transaction, 101));
    assert_eq!(addresses(&mut old), [vec![198, 51, 100, 7]]);
    assert!(addresses(&mut child(&parent)).is_empty());
}
