//! Real file/socket owner guards for init finishing after hosts publication.

use super::*;
use super::tests::test_owner;
use dnsmasq_rs::dns::hostsdir::{HostSource, HostsRead};
use dnsmasq_rs::dns::wire::{Name, PacketWriter};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

fn query() -> Vec<u8> {
    let mut packet = PacketWriter::new(7, 0x100, 1232).unwrap();
    packet.question(&Name::from_ascii("ready.test").unwrap(), 1, 1).unwrap();
    packet.finish()
}

fn config() -> DnsConfig {
    let mut config = DnsConfig::default();
    config.no_resolv = true;
    config.no_hosts = true;
    config.bind_interfaces = true;
    config
}

fn owner(config: DnsConfig) -> SinglePoll {
    let daemon = DnsDaemon::new(config.clone(), read_hosts(&config, 37), &[],
        DaemonOptions::default()).unwrap();
    let mut owner = test_owner(config.clone(), Some(daemon));
    owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
    owner.dns_files.as_mut().unwrap().request(ReloadReason::Init);
    owner
}

fn queued_dns(owner: &mut SinglePoll) -> (Arc<DnsSocket>, std::net::UdpSocket) {
    let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    peer.send_to(&query(), udp.local_addr().unwrap()).unwrap();
    owner.add_listener(SocketToken(1), Some(Arc::clone(&udp)), None);
    (udp, peer)
}

fn answer_queued(owner: &mut SinglePoll, peer: &std::net::UdpSocket) {
    assert!(!owner.files_initializing());
    owner.wait_for_files().unwrap();
    owner.step().unwrap();
    let mut reply = [0; 1232];
    let size = peer.recv(&mut reply).unwrap();
    assert_eq!(&reply[..2], &[0, 7], "the original queued request completes");
    assert!(reply[..size].ends_with(&[192, 0, 2, 42]));
}

#[test]
fn hostsdir_init_finishes_without_another_event_and_releases_queued_dns() {
    let directory = std::env::temp_dir().join(format!("hostsdir-init-owner-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("one"), b"192.0.2.42 ready.test\n").unwrap();
    let mut config = config();
    config.hosts_dirs = vec![Some(directory.clone())];
    let mut owner = owner(config);
    let (udp, peer) = queued_dns(&mut owner);
    owner.step_dns_files(); // Init cache barrier queues the real hosts source.
    owner.step_hosts_files(); // Open the regular file.
    assert!(owner.files_initializing() && owner.hosts_work_pending());
    for _ in 0..2 {
        owner.wait_for_files().unwrap();
        assert!(!owner.poll_fds.iter().any(|fd| fd.fd == udp.as_raw_fd()));
        owner.step_dns_files(); // The hosts owner temporarily blocks DNS-file work.
        owner.step_hosts_files(); // Read, then EOF/publication.
    }
    assert!(!owner.hosts_work_pending());
    assert!(owner.files_initializing());
    assert!(!owner.files_runnable, "the old FileStep flag was cleared behind hosts");
    assert!(owner.dns_file_work_runnable(), "init finish is logical work without a new fd event");
    let started = Instant::now();
    owner.wait_for_files().unwrap();
    assert!(started.elapsed() < Duration::from_millis(50));
    assert!(!owner.poll_fds.iter().any(|fd| fd.fd == udp.as_raw_fd()),
        "startup admission remains closed until the finish turn");
    owner.step_dns_files();
    assert!(!owner.dns_file_work_runnable(), "completed init must return to real event waits");
    answer_queued(&mut owner, &peer);
    drop(owner);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn held_hosts_fifo_keeps_init_finish_blocked_without_spinning_or_losing_dns() {
    let path = std::env::temp_dir().join(format!("hostsdir-init-held-fifo-{}", std::process::id()));
    assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
    let config = config();
    let mut owner = owner(config.clone());
    owner.step_dns_files(); // The same Init cache barrier has not finished yet.
    owner.hosts_read = Some(HostsRead::open(HostSource { path: path.clone(), uid: 1 },
        &config, 37).unwrap());
    let mut writer = std::fs::OpenOptions::new().write(true).custom_flags(0o4000).open(&path).unwrap();
    writer.write_all(b"192.0.2.42 ready.test\n").unwrap();
    owner.step_dns_files(); // Clears the cached runnable flag behind this FIFO.
    owner.step_hosts_files(); // Consume the prefix, but held writer prevents EOF.
    let (udp, peer) = queued_dns(&mut owner);
    assert!(owner.files_initializing() && owner.hosts_work_pending());
    assert!(owner.dns_files.as_ref().unwrap().runnable(), "DNS init is still pending");
    assert!(!owner.reload_file_work_runnable(), "pending init cannot overtake a held hosts source");
    let started = Instant::now();
    owner.wait_for_files().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(50),
        "no signal pipe means the 100ms fallback, not a zero-timeout spin");
    assert!(!owner.poll_fds.iter().any(|fd| fd.fd == udp.as_raw_fd()));
    assert!(!owner.step_udp(0), "the queued startup query must remain unread");
    drop(writer);
    owner.wait_for_files().unwrap(); // Real FIFO HUP/EOF is now ready.
    owner.step_hosts_files();
    assert!(!owner.hosts_work_pending());
    assert!(owner.dns_file_work_runnable(), "EOF releases the saved init finishing turn");
    owner.wait_for_files().unwrap();
    owner.step_dns_files();
    answer_queued(&mut owner, &peer);
    drop(owner);
    std::fs::remove_file(path).unwrap();
}
