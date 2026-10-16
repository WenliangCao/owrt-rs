//! NEWADDR is not an eager interface-name/domain publication boundary.
use super::*;
use dnsmasq_rs::config::lex_line;
use dnsmasq_rs::dns::interface_collect::InterfaceCollector;
use dnsmasq_rs::dns::interface_records::{InterfaceAddress, InterfaceRecords};
use dnsmasq_rs::dns::wire::{Header, Name, PacketWriter};

fn config(extra: &[&[u8]]) -> DnsConfig {
    let mut config = DnsConfig::default();
    config.no_hosts = true;
    config.no_resolv = true;
    for line in [b"interface-name=iface.records.test,lo".as_slice(),
        b"domain=chosen.records.test,lo".as_slice()].into_iter().chain(extra.iter().copied())
    {
        config.apply_resolved(&lex_line(line).unwrap().unwrap()).unwrap();
    }
    config.finalize().unwrap();
    config
}

fn query() -> Vec<u8> {
    let mut writer = PacketWriter::new(19, 0x100, 1232).unwrap();
    writer.question(&Name::from_ascii("iface.records.test").unwrap(), 1, 1).unwrap();
    writer.finish()
}

fn finish_collection(owner: &mut SinglePoll) {
    for _ in 0..64 {
        if !owner.interface_work_pending() {
            break;
        }
        owner.wait_for_files().unwrap();
        owner.step().unwrap();
    }
    assert!(!owner.interface_work_pending(), "the original caller must finish on its real dump fd");
    assert!(owner.interfaces_enumerated);
    assert!(owner.pending_interface_udp.is_none());
    assert!(owner.pending_interface_tcp.is_none());
}

#[test]
fn ordinary_host_and_acl_address_events_leave_published_generation_and_collector_idle() {
    for extra in [
        vec![],
        vec![b"local-service=host".as_slice()],
        vec![b"local-service=net".as_slice(), b"interface=lo".as_slice()],
        vec![b"local-service=net".as_slice(), b"listen-address=127.0.0.1".as_slice()],
        vec![b"local-service=net".as_slice(), b"except-interface=absent".as_slice()],
    ] {
        let config = config(&extra);
        assert!(!config.local_service_net, "the production finalize must apply C's ACL override");
        let mut owner = tests::test_owner(config, None);
        let old = Arc::new(InterfaceRecords::from_addresses(
            &owner.config.interface_records.rules,
            &[InterfaceAddress { label: b"lo".to_vec(), address: "192.0.2.77".parse().unwrap(),
                prefix: 24, flags: 0 }],
        ));
        owner.service.borrow_mut().local.interfaces = Arc::clone(&old);
        let domains = Arc::clone(&owner.config.domain_interfaces);
        owner.interface_collector = Some(InterfaceCollector::new().unwrap());
        owner.apply_network_events(NetworkEvents { address: true, ..Default::default() });
        assert!(!owner.interface_refresh.requested, "ordinary NEWADDR must not pre-empt the next C caller");
        assert!(!owner.address_refresh_requires_enumeration());
        owner.step().unwrap();
        assert!(!owner.interface_work_pending());
        assert!(!owner.interfaces_enumerated);
        assert!(owner.interfaces.borrow().is_empty(), "no listener snapshot must consume a control-socket fault first");
        assert!(Arc::ptr_eq(&old, &owner.service.borrow().local.interfaces));
        assert!(Arc::ptr_eq(&domains, &owner.config.domain_interfaces));
    }
}

#[test]
fn dynamic_net_and_unfinished_dad_address_events_keep_their_real_wake() {
    for (extra, dad) in [
        (vec![b"bind-dynamic".as_slice()], false),
        (vec![b"local-service=net".as_slice()], false),
        (vec![b"bind-interfaces".as_slice()], true),
    ] {
        let mut owner = tests::test_owner(config(&extra), None);
        if dad {
            owner.interface_refresh.complete(Instant::now(), true);
        }
        owner.apply_network_events(NetworkEvents { address: true, ..Default::default() });
        assert!(owner.address_refresh_requires_enumeration());
        assert!(owner.interface_refresh.requested);
        assert!(owner.interface_refresh.due(Instant::now()));
        assert_eq!(owner_poll_timeout(Some(Instant::now() + Duration::from_secs(60)),
            Instant::now(), owner.interface_refresh.requested), 0);
        owner.interface_refresh.complete(Instant::now(), false);
        if dad {
            assert!(!owner.address_refresh_requires_enumeration(), "a completed DAD retry is not a permanent scan");
        }
    }
}

#[test]
fn ordinary_udp_forward_query_still_starts_and_resumes_its_own_enumeration() {
    let config = config(&[]);
    let daemon = DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions::default()).unwrap();
    let mut owner = tests::test_owner(config, Some(daemon));
    let udp = Rc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    peer.send_to(&query(), udp.local_addr().unwrap()).unwrap();
    owner.add_listener(SocketToken(41), Some(udp), None);
    owner.apply_network_events(NetworkEvents { address: true, ..Default::default() });
    assert!(!owner.interface_refresh.requested);
    owner.wait_for_files().unwrap();
    owner.step().unwrap();
    assert!(owner.interface_work_pending(), "rfc1035.c's A/AAAA/ANY caller remains lazy and active");
    assert!(owner.pending_interface_udp.is_some());
    finish_collection(&mut owner);
    let mut response = [0; 1232];
    let count = peer.recv(&mut response).unwrap();
    let header = Header::parse(&response[..count]).unwrap();
    assert_eq!(header.id, 19);
    assert_eq!(header.rcode(), 0);
    assert!(header.answers > 0);
    assert_eq!(owner.service.borrow().local.interfaces.reverse("127.0.0.1".parse().unwrap()),
        Some(b"iface.records.test".as_slice()));
}

#[test]
fn ordinary_accept_before_first_query_still_refreshes_the_parent_snapshot() {
    let mut owner = tests::test_owner(config(&[]), None);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    owner.add_listener(SocketToken(42), None, Some(listener));
    owner.apply_network_events(NetworkEvents { address: true, ..Default::default() });
    assert!(!owner.interface_refresh.requested);
    owner.wait_for_files().unwrap();
    owner.step().unwrap();
    assert!(owner.interface_work_pending(), "dnsmasq.c's accept caller remains eager before the first frame");
    assert!(owner.pending_interface_tcp.is_some());
    assert!(owner.clients.is_empty());
    finish_collection(&mut owner);
    assert_eq!(owner.clients.len(), 1);
    assert_eq!(owner.service.borrow().local.interfaces.reverse("127.0.0.1".parse().unwrap()),
        Some(b"iface.records.test".as_slice()));
}
