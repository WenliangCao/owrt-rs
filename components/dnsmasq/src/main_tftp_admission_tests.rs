//! Real TFTP receive and shared interface-collector callers, without a second RRQ.
use super::*;
use dnsmasq_rs::config::tftp::TftpConfig;
use std::net::UdpSocket;
use std::os::unix::ffi::OsStrExt;

fn owner(label: &str, dns: DnsConfig, dedicated: bool) -> (SinglePoll, std::path::PathBuf) {
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = std::env::temp_dir().join(format!("tftp-admission-{label}-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("boot.bin"), b"admitted").unwrap();
    let tftp = TftpConfig {
        enabled: true,
        root: Some(root.as_os_str().as_bytes().to_vec()),
        interfaces: if dedicated {
            vec![Some(b"lo".to_vec())]
        } else {
            Vec::new()
        },
        ..TftpConfig::default()
    };
    let mut listener = TftpListener::bind_config(&tftp, &dns, &[], &[], 0, 0, 1497).unwrap();
    listener.use_shared_listener_owner();
    let mut owner = tests::test_owner(dns, None);
    owner.tftp = Some(listener);
    (owner, root)
}

fn rrq(destination: &str) -> UdpSocket {
    let peer = UdpSocket::bind(if destination.starts_with('[') {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    })
    .unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    peer.send_to(b"\0\x01boot.bin\0octet\0", destination)
        .unwrap();
    peer
}

fn stale_loopback(owner: &mut SinglePoll, ipv6: bool, name: &[u8]) {
    let address: IpAddr = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
    let mut row = dnsmasq_rs::interfaces::dns_interfaces()
        .unwrap()
        .into_iter()
        .find(|row| row.loopback && row.address == address)
        .unwrap();
    row.name = name.to_vec();
    row.loopback = false;
    owner
        .tftp
        .as_mut()
        .unwrap()
        .refresh_listener_interfaces(&[row.clone()]);
    owner.interfaces.borrow_mut().push(row);
}

fn start_and_collect(owner: &mut SinglePoll) {
    owner.wait_for_files().unwrap();
    owner.step_tftp();
    assert!(owner.interface_work_pending());
    assert!(owner.tftp.as_ref().unwrap().needs_interface_admission());
    assert_eq!(owner.tftp.as_ref().unwrap().active_transfers(), 0);
    let mut fds = Vec::new();
    owner.tftp.as_ref().unwrap().append_poll_fds(&mut fds);
    assert!(
        fds.is_empty(),
        "unread listener input must not spin while its shared dump runs"
    );
    for _ in 0..64 {
        if !owner.interface_work_pending() {
            break;
        }
        owner.wait_for_files().unwrap();
        owner.step().unwrap();
    }
    assert!(!owner.interface_work_pending());
    assert!(!owner.tftp.as_ref().unwrap().needs_interface_admission());
    // The existing completion sets readiness, so no second network packet or
    // MAC callback is required to resume the captured original datagram.
    owner.step_tftp();
}

fn data(peer: &UdpSocket) {
    let mut response = [0; 512];
    let (length, source) = peer.recv_from(&mut response).unwrap();
    assert_eq!(&response[..length], b"\0\x03\0\x01admitted");
    peer.send_to(b"\0\x04\0\x01", source).unwrap();
}

#[test]
#[ignore = "requires run_isolated.sh network namespace"]
fn tftp_live_name_rejects_old_ipv6_name_after_the_shared_collector() {
    let mut dns = DnsConfig::default();
    dns.interfaces.push(Some(b"lan".to_vec()));
    dns.excluded_interfaces.push(Some(b"lo".to_vec()));
    let (mut owner, root) = owner("reject", dns, false);
    stale_loopback(&mut owner, true, b"lan");
    let peer = rrq("[::1]:69");
    start_and_collect(&mut owner);
    assert_eq!(owner.tftp.as_ref().unwrap().active_transfers(), 0);
    assert!(peer.recv(&mut [0; 512]).is_err());
    assert!(owner
        .interfaces
        .borrow()
        .iter()
        .any(|row| row.name == b"lo" && row.loopback));
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires run_isolated.sh network namespace"]
fn tftp_label_exception_resumes_the_original_rrq_without_another_packet() {
    struct Alias;
    impl Drop for Alias {
        fn drop(&mut self) {
            let _ = std::process::Command::new("ip")
                .args(["addr", "del", "127.0.0.42/8", "dev", "lo"])
                .output();
        }
    }
    assert!(std::process::Command::new("ip")
        .args([
            "addr",
            "add",
            "127.0.0.42/8",
            "dev",
            "lo",
            "label",
            "lo:acl42"
        ])
        .status()
        .unwrap()
        .success());
    let _alias = Alias;
    let mut dns = DnsConfig::default();
    dns.interfaces.push(Some(b"lo:acl42".to_vec()));
    dns.excluded_interfaces.push(Some(b"lo".to_vec()));
    let (mut owner, root) = owner("label", dns, false);
    let peer = rrq("127.0.0.42:69");
    start_and_collect(&mut owner);
    data(&peer);
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires run_isolated.sh network namespace"]
fn tftp_static_ipv4_keeps_its_cached_owner_and_dedicated_keeps_its_live_name() {
    for bound in [true, false] {
        let mut dns = DnsConfig::default();
        dns.bind_interfaces = bound;
        dns.interfaces.push(Some(if bound {
            b"lo".to_vec()
        } else {
            b"lan".to_vec()
        }));
        let (mut owner, root) = owner(if bound { "static" } else { "dedicated" }, dns, true);
        stale_loopback(&mut owner, !bound, if bound { b"retired0" } else { b"lan" });
        let peer = rrq(if bound { "127.0.0.1:69" } else { "[::1]:69" });
        owner.wait_for_files().unwrap();
        owner.step_tftp();
        data(&peer);
        assert!(owner.interface_collector.is_none());
        assert!(!owner.tftp.as_ref().unwrap().needs_interface_admission());
        drop(owner);
        std::fs::remove_dir_all(root).unwrap();
    }
}
