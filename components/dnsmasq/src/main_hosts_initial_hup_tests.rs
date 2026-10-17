//! HUP must not turn an unfinished first hosts load into runtime admission.

use super::*;
use super::hostsdir_init_tests::{answer_queued, config, owner, queued_dns};
use dnsmasq_rs::dns::hostsdir::{HostSource, HostsRead};
use std::os::unix::fs::OpenOptionsExt;

fn hold_scanned_reader(owner: &mut SinglePoll, path: &Path) -> std::fs::File {
    owner.step_hosts_files();
    let source = owner.hosts_read.take().expect("scan must open its source").finish().source;
    assert!(std::process::Command::new("mkfifo").arg(path).status().unwrap().success());
    owner.hosts_read = Some(HostsRead::open(HostSource {
        path: path.to_path_buf(), uid: source.uid,
    }, 37).unwrap());
    let mut writer = std::fs::OpenOptions::new()
        .write(true).custom_flags(0o4000).open(path).unwrap();
    writer.write_all(b"192.0.2.42 ready.test\n").unwrap();
    owner.step_hosts_files(); // Consume a complete prefix without observing EOF.
    owner.step_dns_files();
    assert!(owner.hosts_work_pending());
    assert!(!owner.hosts_read.as_ref().unwrap().runnable());
    writer
}

#[test]
fn hup_during_first_hosts_fifo_keeps_dns_dhcp_and_helper_admission_closed() {
    let root = std::env::temp_dir().join(format!("hosts-initial-hup-{}", std::process::id()));
    let directory = root.join("hosts");
    let resolver_directory = root.join("resolvers");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::create_dir(&resolver_directory).unwrap();
    std::fs::write(directory.join("one"), b"192.0.2.42 ready.test\n").unwrap();
    let resolver = resolver_directory.join("resolv.conf");
    std::fs::write(&resolver, b"nameserver 192.0.2.53\n").unwrap();
    let mut config = config();
    config.no_resolv = false;
    config.resolv_files = vec![resolver];
    config.hosts_dirs = vec![Some(directory)];
    let mut owner = owner(config.clone());
    for _ in 0..16 {
        owner.step_dns_files();
        if owner.hosts_work_pending() { break; }
    }
    assert!(!owner.dns_files.as_ref().unwrap().initializing(),
        "resolver polling has finished before the first hosts publication");
    assert!(owner.hosts_bulk && !owner.hosts_full_reload);
    let first_writer = hold_scanned_reader(&mut owner, &root.join("initial-fifo"));
    assert!(owner.files_initializing());

    let leases = root.join("leases");
    std::fs::write(&leases, b"0 02:00:00:00:00:01 192.0.2.42 restored *\n").unwrap();
    let mut provider = DhcpProvider::new(DhcpConfig {
        no_ping: true, script: Some(b"/bin/true".to_vec()),
        lease_file: Some(leases.as_os_str().as_encoded_bytes().to_vec()),
        ..Default::default()
    }, Vec::new(), 53, || false).unwrap();
    provider.set_dns_config(&config).unwrap();
    provider.set_dns_publisher(Box::new(LeasePublisher {
        parent: Rc::clone(&owner.service), policy: LeasePolicy::default(),
    }));
    provider.initialize(now_seconds());
    assert!(!provider.files_initializing());
    assert!(provider.has_frozen_script_delivery());
    let dhcp_peer = super::tests::attach_test_dhcp(&mut owner, provider);
    dhcp_peer.send(b"queued-dhcp").unwrap();
    owner.helper = Some(super::tests::ready_test_helper());
    let (dns, dns_peer) = queued_dns(&mut owner);
    assert!(!owner.dhcp_packet_work_allowed());
    assert!(owner.helper_next_due(Instant::now()).is_none());

    // Exercise the real reload entry, not a direct flip of hosts_full_reload.
    // It cancels the initial reader and schedules a new scan while no complete
    // hosts generation has ever been admitted to client or helper work.
    owner.reload_data(37).unwrap();
    assert!(owner.hosts_bulk && owner.hosts_full_reload);
    assert!(!owner.dns_files.as_ref().unwrap().initializing());
    let hup_writer = hold_scanned_reader(&mut owner, &root.join("hup-fifo"));
    let initial_gate = owner.files_initializing();
    let dhcp_allowed = owner.dhcp_packet_work_allowed();
    let helper_due = owner.helper_next_due(Instant::now()).is_some();
    owner.wait_for_files().unwrap();
    let mut dhcp_fds = Vec::new();
    owner.dhcp.as_ref().unwrap().listener.append_poll_fds(&mut dhcp_fds);
    let dns_polled = owner.poll_fds.iter().any(|fd| fd.fd == dns.as_raw_fd());
    let dhcp_polled = owner.poll_fds.iter()
        .any(|fd| dhcp_fds.iter().any(|dhcp| dhcp.fd == fd.fd));
    eprintln!("initial HUP admission: gate={initial_gate} dhcp_allowed={dhcp_allowed} \
        helper_due={helper_due} dns_polled={dns_polled} dhcp_polled={dhcp_polled}");

    // Complete the same held input and prove the original queued DNS request
    // can subsequently run. Keep the failing gate observations until cleanup.
    drop(first_writer);
    drop(hup_writer);
    owner.step_hosts_files();
    for _ in 0..16 {
        if !owner.dns_file_work_runnable() { break; }
        owner.step_dns_files();
    }
    assert!(!owner.hosts_work_pending());
    assert!(owner.service.borrow().pending_hosts.is_none());
    assert!(!owner.files_initializing());
    assert!(owner.dhcp_packet_work_allowed());
    assert!(owner.helper_next_due(Instant::now()).is_some());
    assert!(owner.dhcp.as_ref().unwrap().listener.has_input().unwrap(),
        "the startup DHCP request has remained queued throughout the hold");
    super::tests::finish_test_helper(owner.helper.as_mut().unwrap());
    owner.helper = None;
    answer_queued(&mut owner, &dns_peer);
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();

    assert!(initial_gate && !dhcp_allowed && !helper_due && !dns_polled && !dhcp_polled,
        "HUP reopened initial admission before any complete hosts publication: \
         gate={initial_gate}, dhcp_allowed={dhcp_allowed}, helper_due={helper_due}, \
         dns_polled={dns_polled}, dhcp_polled={dhcp_polled}");
}
