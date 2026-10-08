//! Ordinary UDP admission uses live ingress; only a failed ACL enumerates.
use super::*;
use dnsmasq_rs::config::lex_line;
use dnsmasq_rs::dns::wire::{Header, Name, PacketWriter};

fn owner(interface: &[u8]) -> SinglePoll {
    let mut config = DnsConfig::default();
    config.no_hosts = true;
    config.no_resolv = true;
    config.interfaces.push(Some(interface.to_vec()));
    config.apply_resolved(&lex_line(b"host-record=ready.test,192.0.2.42").unwrap().unwrap()).unwrap();
    config.finalize().unwrap();
    assert!(config.interface_records.rules.is_empty() && !config.needs_domain_interfaces());
    let daemon = DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions::default()).unwrap();
    tests::test_owner(config, Some(daemon))
}

fn query() -> Vec<u8> {
    let mut writer = PacketWriter::new(0x7123, 0x100, 1232).unwrap();
    writer.question(&Name::from_ascii("ready.test").unwrap(), 1, 1).unwrap();
    writer.finish()
}

fn assert_reply(peer: &std::net::UdpSocket) {
    let mut response = [0; 1232];
    let length = peer.recv(&mut response).unwrap();
    let header = Header::parse(&response[..length]).unwrap();
    assert_eq!(header.id, 0x7123);
    assert_eq!(header.rcode(), 0);
    assert_eq!(header.answers, 1);
    assert_eq!(&response[length - 4..length], &[192, 0, 2, 42]);
}

#[test]
fn udp_live_ingress_accepts_a_real_received_index_absent_from_the_old_snapshot() {
    let mut owner = owner(b"lo");
    let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    assert!(owner.interfaces.borrow().is_empty(), "the accepted ingress is absent from the old generation");
    peer.send_to(&query(), udp.local_addr().unwrap()).unwrap();
    owner.add_listener(SocketToken(71), Some(Arc::clone(&udp)), None);
    owner.wait_for_files().unwrap();
    assert!(owner.step_udp(0));
    assert_reply(&peer);
    assert!(owner.interfaces.borrow().is_empty(), "direct live name acceptance must not publish a snapshot");
    assert!(!owner.interfaces_enumerated);
    assert!(owner.interface_collector.is_none());
    assert!(owner.pending_udp_admission.is_none());

    // This index cannot pass SIOCGIFNAME. A literal destination, and then
    // no ACL at all, must still take their existing zero-ioctl path.
    let incoming = listeners::Incoming { len: 12, peer: peer.local_addr().unwrap(),
        destination: "127.0.0.1".parse().unwrap(), interface: u32::MAX };
    owner.config.listen_addresses.push(incoming.destination);
    assert!(matches!(owner.admit_udp(&udp, incoming), UdpAdmission::Accept));
    owner.config.listen_addresses.clear();
    owner.config.interfaces.clear();
    assert!(matches!(owner.admit_udp(&udp, incoming), UdpAdmission::Accept));
    assert!(owner.interface_collector.is_none());
}

#[test]
fn udp_alias_admission_collects_without_publication_rules_and_resumes_the_original_packet() {
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"),
        "the alias actor must run in its private network namespace");
    struct Alias;
    impl Drop for Alias {
        fn drop(&mut self) {
            let _ = std::process::Command::new("ip")
                .args(["addr", "del", "127.0.0.42/8", "dev", "lo"]).output();
        }
    }
    let mut owner = owner(b"lo:acl42");
    assert!(std::process::Command::new("ip")
        .args(["addr", "add", "127.0.0.42/8", "dev", "lo", "label", "lo:acl42"])
        .status().unwrap().success());
    let _alias = Alias;
    let udp = Arc::new(DnsSocket::bind("0.0.0.0:0".parse().unwrap()).unwrap());
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let destination = SocketAddr::new("127.0.0.42".parse().unwrap(), udp.local_addr().unwrap().port());
    owner.add_listener(SocketToken(72), Some(udp), None);
    peer.send_to(&query(), destination).unwrap();
    owner.wait_for_files().unwrap();
    assert!(owner.step_udp(0));
    assert!(owner.interface_work_pending(), "failed live ACL must collect even with no interface-name/domain");
    let pending = owner.pending_udp_admission.as_ref().unwrap();
    assert_eq!(pending.incoming.destination, destination.ip());
    assert_eq!(pending.incoming.peer, peer.local_addr().unwrap());
    assert_eq!(pending.query, query());
    for _ in 0..64 {
        if !owner.interface_work_pending() { break; }
        owner.wait_for_files().unwrap();
        owner.step().unwrap();
    }
    assert!(!owner.interface_work_pending());
    assert!(owner.pending_udp_admission.is_none());
    assert!(owner.interfaces.borrow().iter().any(|row|
        row.name == b"lo:acl42" && row.address == destination.ip()));
    assert_reply(&peer);
    // No extra DNS input supplied the wake or produced the reply.
    assert_eq!(owner.parent_events.borrow().local_answered, 1);
}
