//! Real file/socket owner guards for init finishing after hosts publication.

use super::tests::test_owner;
use super::*;
use dnsmasq_rs::dns::hostsdir::{HostSource, HostsRead};
use dnsmasq_rs::dns::wire::{Name, PacketWriter};
use std::os::unix::fs::OpenOptionsExt;

fn query() -> Vec<u8> {
    let mut packet = PacketWriter::new(7, 0x100, 1232).unwrap();
    packet
        .question(&Name::from_ascii("ready.test").unwrap(), 1, 1)
        .unwrap();
    packet.finish()
}

pub(super) fn config() -> DnsConfig {
    let mut config = DnsConfig::default();
    config.no_resolv = true;
    config.no_hosts = true;
    config.bind_interfaces = true;
    config
}

pub(super) fn owner(config: DnsConfig) -> SinglePoll {
    let daemon = DnsDaemon::new(
        config.clone(),
        read_hosts(&config, 37),
        &[],
        DaemonOptions::default(),
    )
    .unwrap();
    let mut owner = test_owner(config.clone(), Some(daemon));
    owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
    owner
        .dns_files
        .as_mut()
        .unwrap()
        .request(ReloadReason::Init);
    owner
}

#[cfg(target_pointer_width = "64")]
#[test]
fn initial_hosts_rename_precedes_lease_retention_in_both_mixed_chain_orders() {
    use dnsmasq_rs::dhcp::lease::ScriptAction;

    let address = "127.0.0.40".parse::<std::net::Ipv4Addr>().unwrap();
    // Select both real mixed-chain outcomes using this process's existing
    // pointer-seeded hash. No fixed bucket seed or ASLR-dependent expectation.
    let mut names = None;
    for lease_index in 0..64 {
        let original = format!("original{lease_index}");
        let fqdn = format!("{original}.records.test");
        let mut orders: [Option<String>; 2] = [None, None];
        for host_index in 0..256 {
            let hostname = format!("fromhosts{host_index}.records.test");
            let mut hosts = Hosts::new();
            // test_owner's initial hosts generation keeps this capacity.
            hosts.begin_bulk(1497, 0, 1000).unwrap();
            hosts
                .add_bulk_lease(fqdn.as_bytes(), address.into(), true, false)
                .unwrap();
            hosts
                .insert_checked(hostname.as_bytes().to_vec(), address.into(), 37, 2)
                .unwrap();
            hosts.seal_bulk();
            let static_first = hosts.provider_reverse(address.into()).is_some();
            orders[usize::from(static_first)].get_or_insert(hostname);
            if orders.iter().all(Option::is_some) {
                break;
            }
        }
        if let [Some(blocked), Some(allowed)] = orders {
            names = Some((original, fqdn, [blocked, allowed]));
            break;
        }
    }
    let (original, fqdn, hostnames) = names.expect("both mixed reverse-chain orders exist");
    let mut observations = Vec::new();
    for (static_first, hostname) in hostnames.iter().enumerate() {
        for phase in ["initial", "initial-hup", "runtime-hup"] {
            let root = std::env::temp_dir().join(format!(
                "initial-lease-retention-{}-{static_first}-{phase}",
                std::process::id(),
            ));
            let directory = root.join("hosts");
            std::fs::create_dir_all(&directory).unwrap();
            let leases = root.join("leases");
            std::fs::write(
                &leases,
                format!(
                    "{} 02:00:00:00:00:01 {address} {original} *\n",
                    now_seconds() + 3600,
                ),
            )
            .unwrap();
            std::fs::write(directory.join("one"), format!("{address} {hostname}\n")).unwrap();
            let mut config = config();
            config
                .apply(
                    &dnsmasq_rs::config::lex_line(b"domain=records.test")
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
            config.hosts_dirs = vec![Some(directory)];
            let mut owner = owner(config.clone());
            owner.packet_limit = 1497;
            let mut provider = DhcpProvider::new(
                DhcpConfig {
                    no_ping: true,
                    script: Some(b"/bin/true".to_vec()),
                    lease_file: Some(leases.as_os_str().as_encoded_bytes().to_vec()),
                    ..Default::default()
                },
                Vec::new(),
                53,
                || false,
            )
            .unwrap();
            provider.set_dns_config(&config).unwrap();
            let parent = Rc::clone(&owner.service);
            provider.set_reverse_host_lookup(move |address| {
                let parent = parent.borrow();
                Ok(parent
                    .provider_hosts()
                    .provider_reverse(IpAddr::V4(address))
                    .map(|host| host.name.clone()))
            });
            provider.set_dns_publisher(Box::new(LeasePublisher {
                parent: Rc::clone(&owner.service),
                policy: LeasePolicy::default(),
            }));
            provider.initialize(now_seconds());
            assert!(provider.has_frozen_script_delivery());
            assert_eq!(
                owner
                    .service
                    .borrow()
                    .local
                    .leases
                    .lookup(fqdn.as_bytes(), now_seconds())
                    .count(),
                1
            );
            super::tests::attach_test_dhcp(&mut owner, provider);
            if phase == "runtime-hup" {
                // Model a completed first publication; this HUP must retain
                // the existing mixed-chain contract, including suppressed rename.
                owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
                owner.reload_data(37).unwrap();
            } else {
                owner.step_dns_files();
                assert!(owner.service.borrow().hosts_initializing);
                owner.step_hosts_files(); // Open the first source before EOF.
                if phase == "initial-hup" {
                    owner.reload_data(37).unwrap();
                    assert!(owner.service.borrow().hosts_initializing);
                }
            }
            for _ in 0..16 {
                owner.step_hosts_files();
                owner.step_dns_files();
                if !owner.hosts_work_pending() && !owner.files_initializing() {
                    break;
                }
            }
            assert!(!owner.hosts_work_pending() && !owner.files_initializing());
            let provider = owner.dhcp.as_ref().unwrap().provider.as_ref().unwrap();
            let mut events = Vec::new();
            while let Some(delivery) = provider.borrow_mut().take_script_delivery() {
                events.push((delivery.event.action, delivery.event.name));
            }
            let renamed = phase != "runtime-hup" || static_first != 0;
            let expected = if renamed {
                vec![
                    (ScriptAction::Old, Some(fqdn.as_bytes().to_vec())),
                    (ScriptAction::OldHostname, Some(fqdn.as_bytes().to_vec())),
                    (ScriptAction::Old, Some(hostname.as_bytes().to_vec())),
                ]
            } else {
                vec![(ScriptAction::Old, Some(fqdn.as_bytes().to_vec())); 2]
            };
            let persisted = std::fs::read_to_string(&leases).unwrap();
            let expected_name = if renamed {
                hostname.split('.').next().unwrap()
            } else {
                &original
            };
            let persisted_name = persisted.split_whitespace().nth(3).unwrap();
            observations.push((
                phase,
                static_first,
                events == expected && persisted_name == expected_name,
            ));
            eprintln!(
                "{phase} static-first={static_first} events={events:?} persisted={persisted_name}"
            );
            drop(owner);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    assert!(
        observations.iter().all(|(_, _, matched)| *matched),
        "{observations:?}"
    );
}

pub(super) fn queued_dns(owner: &mut SinglePoll) -> (Arc<DnsSocket>, std::net::UdpSocket) {
    let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    peer.send_to(&query(), udp.local_addr().unwrap()).unwrap();
    owner.add_listener(SocketToken(1), Some(Arc::clone(&udp)), None);
    (udp, peer)
}

pub(super) fn answer_queued(owner: &mut SinglePoll, peer: &std::net::UdpSocket) {
    assert!(!owner.files_initializing());
    owner.wait_for_files().unwrap();
    owner.step().unwrap();
    let mut reply = [0; 1232];
    let size = peer.recv(&mut reply).unwrap();
    assert_eq!(
        &reply[..2],
        &[0, 7],
        "the original queued request completes"
    );
    assert!(reply[..size].ends_with(&[192, 0, 2, 42]));
}

#[test]
fn hostsdir_init_finishes_without_another_event_and_releases_queued_dns() {
    let directory =
        std::env::temp_dir().join(format!("hostsdir-init-owner-{}", std::process::id()));
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
    assert!(
        !owner.files_runnable,
        "the old FileStep flag was cleared behind hosts"
    );
    assert!(
        owner.dns_file_work_runnable(),
        "init finish is logical work without a new fd event"
    );
    let started = Instant::now();
    owner.wait_for_files().unwrap();
    assert!(started.elapsed() < Duration::from_millis(50));
    assert!(
        !owner.poll_fds.iter().any(|fd| fd.fd == udp.as_raw_fd()),
        "startup admission remains closed until the finish turn"
    );
    owner.step_dns_files();
    assert!(
        !owner.dns_file_work_runnable(),
        "completed init must return to real event waits"
    );
    answer_queued(&mut owner, &peer);
    drop(owner);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn held_hosts_fifo_keeps_init_finish_blocked_without_spinning_or_losing_dns() {
    let path = std::env::temp_dir().join(format!("hostsdir-init-held-fifo-{}", std::process::id()));
    assert!(std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap()
        .success());
    let config = config();
    let mut owner = owner(config.clone());
    owner.step_dns_files(); // The same Init cache barrier has not finished yet.
    owner.hosts_read = Some(
        HostsRead::open(
            HostSource {
                path: path.clone(),
                uid: 1,
            },
            37,
        )
        .unwrap(),
    );
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(0o4000)
        .open(&path)
        .unwrap();
    writer.write_all(b"192.0.2.42 ready.test\n").unwrap();
    owner.step_dns_files(); // Clears the cached runnable flag behind this FIFO.
    owner.step_hosts_files(); // Consume the prefix, but held writer prevents EOF.
    let (udp, peer) = queued_dns(&mut owner);
    assert!(owner.files_initializing() && owner.hosts_work_pending());
    assert!(
        owner.dns_files.as_ref().unwrap().runnable(),
        "DNS init is still pending"
    );
    assert!(
        !owner.reload_file_work_runnable(),
        "pending init cannot overtake a held hosts source"
    );
    let started = Instant::now();
    owner.wait_for_files().unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(50),
        "no signal pipe means the 100ms fallback, not a zero-timeout spin"
    );
    assert!(!owner.poll_fds.iter().any(|fd| fd.fd == udp.as_raw_fd()));
    assert!(
        !owner.step_udp(0),
        "the queued startup query must remain unread"
    );
    drop(writer);
    owner.wait_for_files().unwrap(); // Real FIFO HUP/EOF is now ready.
    owner.step_hosts_files();
    assert!(!owner.hosts_work_pending());
    assert!(
        owner.dns_file_work_runnable(),
        "EOF releases the saved init finishing turn"
    );
    owner.wait_for_files().unwrap();
    owner.step_dns_files();
    answer_queued(&mut owner, &peer);
    drop(owner);
    std::fs::remove_file(path).unwrap();
}

#[cfg(target_pointer_width = "64")]
#[cfg(feature = "process-test-support")]
pub(super) fn polling_resolver_keeps_initial_hostsdir_dhcp_and_helper_work_behind_publication() {
    let root = std::env::temp_dir().join(format!("hostsdir-poll-gate-{}", std::process::id()));
    let directory = root.join("hosts");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("one"), b"192.0.2.42 ready.test\n").unwrap();
    // Resolver polling watches its parent directory. Keep later lease/FIFO
    // setup outside that watch so the idle-wait assertion measures only the
    // deliberately blocked packet and helper sources, not an unrelated event.
    let resolver_dir = root.join("resolvers");
    std::fs::create_dir(&resolver_dir).unwrap();
    let resolver = resolver_dir.join("resolver");
    std::fs::write(&resolver, b"nameserver 192.0.2.53\n").unwrap();
    let mut config = config();
    config.no_resolv = false;
    config.resolv_files = vec![resolver];
    config.hosts_dirs = vec![Some(directory)];
    let mut owner = owner(config.clone());
    for _ in 0..16 {
        owner.step_dns_files();
        if owner.hosts_work_pending() {
            break;
        }
    }
    assert!(
        !owner.dns_files.as_ref().unwrap().initializing(),
        "ordinary polling completed its resolver before queuing hostsdir"
    );
    assert!(owner.hosts_bulk && !owner.hosts_full_reload);
    assert!(
        owner.files_initializing(),
        "the initial hostsdir is still unpublished"
    );
    owner.hosts_full_reload = true;
    assert!(
        owner.files_initializing(),
        "HUP cannot bypass the first hosts publication"
    );
    owner.hosts_full_reload = false;
    owner.step_hosts_files(); // Open the scanned source, retaining its bulk state.
    assert!(owner.hosts_requests.is_empty() && owner.hosts_read.is_some());

    // Hold the active reader without changing the watched directory. This
    // isolates admission scheduling from regular-file readiness and inotify.
    let fifo = root.join("held");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    owner.hosts_read = Some(
        HostsRead::open(
            HostSource {
                path: fifo.clone(),
                uid: 1,
            },
            37,
        )
        .unwrap(),
    );
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(0o4000)
        .open(&fifo)
        .unwrap();
    writer.write_all(b"192.0.2.42 ready.test\n").unwrap();
    owner.step_hosts_files();
    owner.step_dns_files(); // Clear the cached runnable flag behind held hosts.
    assert!(!owner.reload_file_work_runnable());

    let leases = root.join("leases");
    std::fs::write(&leases, b"0 02:00:00:00:00:01 192.0.2.42 restored *\n").unwrap();
    let mut provider = DhcpProvider::new(
        DhcpConfig {
            no_ping: true,
            script: Some(b"/bin/true".to_vec()),
            lease_file: Some(leases.as_os_str().as_encoded_bytes().to_vec()),
            ..Default::default()
        },
        Vec::new(),
        53,
        || false,
    )
    .unwrap();
    provider.set_dns_config(&config).unwrap();
    let parent = Rc::clone(&owner.service);
    provider.set_reverse_host_lookup(move |address| {
        let parent = parent.borrow();
        Ok(parent
            .provider_hosts()
            .reverse(IpAddr::V4(address))
            .map(|host| host.name.clone()))
    });
    provider.set_dns_publisher(Box::new(LeasePublisher {
        parent: Rc::clone(&owner.service),
        policy: LeasePolicy::default(),
    }));
    provider.tick(now_seconds()).unwrap();
    assert!(provider.has_frozen_script_delivery());
    let peer = super::tests::attach_test_dhcp(&mut owner, provider);
    peer.send(b"queued-dhcp").unwrap();
    owner.helper = Some(super::tests::ready_test_helper());
    let (dns, _) = queued_dns(&mut owner);
    assert!(!owner.dhcp_packet_work_allowed());
    assert_eq!(
        owner.helper_next_due(Instant::now()),
        None,
        "a restored callback behind initial hosts cannot request a busy poll"
    );
    let started = Instant::now();
    owner.wait_for_files().unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(50),
        "blocked ready packets and callbacks wait for file progress"
    );
    let mut dhcp_fds = Vec::new();
    owner
        .dhcp
        .as_ref()
        .unwrap()
        .listener
        .append_poll_fds(&mut dhcp_fds);
    assert!(!owner
        .poll_fds
        .iter()
        .any(|fd| fd.fd == dns.as_raw_fd() || dhcp_fds.iter().any(|dhcp| dhcp.fd == fd.fd)));
    owner.step_dhcp();
    assert!(owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
    assert!(owner.pending_delivery.is_none());
    assert!(owner
        .dhcp
        .as_ref()
        .unwrap()
        .provider
        .as_ref()
        .unwrap()
        .borrow()
        .has_frozen_script_delivery());

    drop(writer);
    owner.wait_for_files().unwrap();
    owner.step_hosts_files();
    assert!(!owner.hosts_work_pending() && !owner.files_initializing());
    assert!(
        owner.service.borrow().pending_hosts.is_none(),
        "the real lease publication commits the initial hosts generation"
    );
    assert!(owner.dhcp_packet_work_allowed());
    assert!(owner.helper_next_due(Instant::now()).is_some());
    let delivery = owner
        .dhcp
        .as_ref()
        .unwrap()
        .provider
        .as_ref()
        .unwrap()
        .borrow_mut()
        .take_frozen_script_delivery()
        .unwrap();
    assert_eq!(
        delivery.event.name.as_deref(),
        Some(b"restored".as_slice()),
        "initial publication must preserve the previously frozen helper name"
    );
    owner.pending_delivery = Some(delivery);
    owner.wait_for_files().unwrap();
    owner.step_dhcp();
    assert!(
        !owner.dhcp.as_ref().unwrap().listener.has_input().unwrap(),
        "the original queued packet becomes consumable after publication"
    );
    super::tests::finish_test_helper(owner.helper.as_mut().unwrap());
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn hup_hosts_fifo_keeps_the_previous_generation_until_complete_publication() {
    use dnsmasq_rs::dhcp::persistence::DnsLeaseRecord;
    use dnsmasq_rs::dns::lease_names::{LeaseNames, LeasePolicy};
    for fail_generation in [false, true] {
        let root = std::env::temp_dir().join(format!(
            "hostsdir-hup-atomic-{}-{fail_generation}",
            std::process::id()
        ));
        let directory = root.join("hostsdir");
        std::fs::create_dir_all(&directory).unwrap();
        let ordinary = root.join("ordinary");
        std::fs::write(&ordinary, b"192.0.2.41 ready.test\n").unwrap();
        let source = directory.join("later");
        std::fs::write(&source, b"192.0.2.1 y.test\n192.0.2.2 y.test\n").unwrap();
        let mut config = config();
        config.addn_hosts = vec![Some(ordinary.clone())];
        config.hosts_dirs = vec![Some(directory)];
        let daemon = DnsDaemon::new(
            config.clone(),
            read_hosts(&config, 37),
            &[],
            DaemonOptions::default(),
        )
        .unwrap();
        let mut owner = test_owner(config.clone(), Some(daemon));
        owner.packet_limit = 1232 + 255 + 10;
        owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
        let (held, old_leases, old_pointer) = {
            let mut parent = owner.service.borrow_mut();
            let leases = LeaseNames::build(
                &[DnsLeaseRecord {
                    name: b"lease.test",
                    address: "192.0.2.30".parse().unwrap(),
                    expires: None,
                }],
                &mut parent.local.hosts,
                &[],
                LeasePolicy::default(),
                &mut (),
            );
            parent.local.leases = Arc::new(leases);
            let held = parent.local.hosts.tcp_snapshot();
            (
                held,
                Arc::clone(&parent.local.leases),
                parent.local.hosts.entries().as_ptr(),
            )
        };
        std::fs::write(&ordinary, b"192.0.2.42 ready.test\n192.0.2.2 old.test\n192.0.2.1 x.test\n192.0.3.186 a.test\n192.0.3.185 a.test\n").unwrap();
        owner.reload_data(37).unwrap();
        assert!(owner.hosts_bulk && owner.hosts_staged.is_some());
        assert!(
            !owner.files_initializing(),
            "HUP keeps serving the prior generation"
        );
        // Model a regular source replaced by a FIFO after the directory scan.
        std::fs::remove_file(&source).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(&source)
            .status()
            .unwrap()
            .success());
        owner.step_hosts_files();
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(0o4000)
            .open(&source)
            .unwrap();
        writer
            .write_all(b"192.0.2.1 y.test\n192.0.2.2 y.test\n")
            .unwrap();
        owner.step_hosts_files();
        assert!(owner.hosts_work_pending());
        {
            let parent = owner.service.borrow();
            let daemon_view = parent
                .daemon
                .as_ref()
                .unwrap()
                .try_clone_hosts_source()
                .unwrap();
            for hosts in [&parent.local.hosts, &daemon_view, &held] {
                assert_eq!(
                    hosts.addresses(b"ready.test").next().unwrap().address,
                    "192.0.2.41".parse::<IpAddr>().unwrap()
                );
                assert_eq!(hosts.addresses(b"x.test").count(), 0);
            }
            assert!(Arc::ptr_eq(&parent.local.leases, &old_leases));
        }
        let (_udp, peer) = queued_dns(&mut owner);
        owner.wait_for_files().unwrap();
        owner.step_udp(0);
        let mut response = [0; 1232];
        let length = peer.recv(&mut response).unwrap();
        assert_eq!(&response[length - 4..length], &[192, 0, 2, 41]);
        if fail_generation {
            // The allocator suite drives actual loader failures. Here exercise
            // the owner state after one source failed, with a later EOF still
            // pending: neither that EOF nor bulk completion may publish a prefix.
            owner.hosts_staged = None;
            owner.hosts_reload_failed = true;
        }
        drop(writer);
        owner.wait_for_files().unwrap();
        owner.step_hosts_files();
        assert!(!owner.hosts_work_pending() && !owner.hosts_bulk);
        assert!(owner.hosts_staged.is_none());
        let parent = owner.service.borrow();
        let daemon_view = parent
            .daemon
            .as_ref()
            .unwrap()
            .try_clone_hosts_source()
            .unwrap();
        for hosts in [&parent.local.hosts, &daemon_view] {
            assert_eq!(
                hosts.addresses(b"ready.test").next().unwrap().address,
                if fail_generation {
                    "192.0.2.41"
                } else {
                    "192.0.2.42"
                }
                .parse::<IpAddr>()
                .unwrap()
            );
            assert_eq!(
                hosts.reverse_all("192.0.2.1".parse().unwrap()).count(),
                if fail_generation { 0 } else { 2 }
            );
        }
        if fail_generation {
            assert_eq!(parent.local.hosts.entries().as_ptr(), old_pointer);
            assert!(Arc::ptr_eq(&parent.local.leases, &old_leases));
        }
        assert_eq!(
            held.addresses(b"ready.test").next().unwrap().address,
            "192.0.2.41".parse::<IpAddr>().unwrap()
        );
        assert_eq!(parent.local.leases.lookup(b"lease.test", 0).count(), 1);
        drop(parent);
        if fail_generation {
            owner.publish_hosts_source(
                &HostSource {
                    path: root.join("recovery"),
                    uid: 99,
                },
                vec![(b"recovered.test".to_vec(), "192.0.2.99".parse().unwrap())],
                37,
            );
            assert_eq!(
                owner
                    .service
                    .borrow()
                    .local
                    .hosts
                    .addresses(b"recovered.test")
                    .count(),
                1,
                "a failed bulk generation must not poison later incremental events"
            );
        }
        drop(owner);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn failed_bulk_preparation_does_not_consume_an_existing_incremental_event() {
    use dnsmasq_rs::dns::hostsdir::HostChange;
    let path = std::env::temp_dir().join(format!(
        "hostsdir-failed-bulk-queued-{}",
        std::process::id()
    ));
    std::fs::write(&path, b"192.0.2.42 ready.test\n").unwrap();
    let config = config();
    let daemon = DnsDaemon::new(
        config.clone(),
        read_hosts(&config, 37),
        &[],
        DaemonOptions::default(),
    )
    .unwrap();
    let mut owner = test_owner(config.clone(), Some(daemon));
    owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
    owner.hosts_requests.push_back(HostChange {
        source: HostSource {
            path: path.clone(),
            uid: 10,
        },
        deleted: false,
    });
    // In particular, failure to reserve the deferred queue must leave the
    // existing incremental request available to its original owner path.
    owner.hosts_reload_failed = true;
    owner.scan_hosts_dirs(true);
    assert!(!owner.hosts_bulk);
    assert!(owner.hosts_staged.is_none());
    assert_eq!(owner.hosts_requests.len(), 1);
    assert_eq!(owner.hosts_requests.front().unwrap().source.path, path);
    for _ in 0..3 {
        owner.step_hosts_files();
    }
    assert!(!owner.hosts_work_pending());
    let parent = owner.service.borrow();
    let daemon_view = parent
        .daemon
        .as_ref()
        .unwrap()
        .try_clone_hosts_source()
        .unwrap();
    for hosts in [&parent.local.hosts, &daemon_view] {
        assert_eq!(
            hosts.addresses(b"ready.test").next().unwrap().address,
            "192.0.2.42".parse::<IpAddr>().unwrap()
        );
    }
    drop(parent);
    drop(owner);
    std::fs::remove_file(path).unwrap();
}

#[cfg(target_pointer_width = "64")]
#[test]
fn hup_defers_lease_publication_until_provider_resolves_the_new_hosts_names() {
    use dnsmasq_rs::config::lex_line;
    use dnsmasq_rs::dhcp::persistence::{DnsLeaseRecord, DnsPublisher};
    struct CountedPublisher {
        publisher: LeasePublisher,
        calls: Rc<std::cell::Cell<usize>>,
        contains_old_name: Rc<std::cell::Cell<bool>>,
    }
    impl DnsPublisher for CountedPublisher {
        fn replace(&mut self, records: &[DnsLeaseRecord<'_>]) -> io::Result<()> {
            self.calls.set(self.calls.get() + 1);
            self.contains_old_name
                .set(records.iter().any(|record| record.name == b"a.test"));
            self.publisher.replace(records)
        }
    }
    for slow_options in [false, true] {
        let root = std::env::temp_dir().join(format!(
            "hostsdir-hup-provider-once-{}-{slow_options}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let hosts_path = root.join("hosts");
        let leases_path = root.join("leases");
        let options_path = root.join("options");
        std::fs::write(&options_path, b"option:domain-name,initial\n").unwrap();
        std::fs::write(&hosts_path, b"").unwrap();
        std::fs::write(
            &leases_path,
            format!("{} 02:00:00:00:00:01 192.0.2.1 a *\n", now_seconds() + 3600),
        )
        .unwrap();
        let mut config = config();
        config
            .apply(&lex_line(b"domain=test").unwrap().unwrap())
            .unwrap();
        config.addn_hosts = vec![Some(hosts_path.clone())];
        let daemon = DnsDaemon::new(
            config.clone(),
            read_hosts(&config, 37),
            &[],
            DaemonOptions::default(),
        )
        .unwrap();
        let mut owner = test_owner(config.clone(), Some(daemon));
        owner.packet_limit = 1232 + 255 + 10;
        let mut provider = DhcpProvider::new(
            DhcpConfig {
                no_ping: true,
                lease_file: Some(leases_path.as_os_str().as_encoded_bytes().to_vec()),
                option_files: if slow_options {
                    vec![options_path.as_os_str().as_encoded_bytes().to_vec()]
                } else {
                    Vec::new()
                },
                ..Default::default()
            },
            Vec::new(),
            53,
            || false,
        )
        .unwrap();
        provider.set_dns_config(&config).unwrap();
        let parent = Rc::clone(&owner.service);
        provider.set_reverse_host_lookup(move |address| {
            let parent = parent.borrow();
            Ok(parent
                .provider_hosts()
                .provider_reverse(IpAddr::V4(address))
                .map(|host| host.name.clone()))
        });
        let calls = Rc::new(std::cell::Cell::new(0));
        let contains_old_name = Rc::new(std::cell::Cell::new(false));
        provider.set_dns_publisher(Box::new(CountedPublisher {
            publisher: LeasePublisher {
                parent: Rc::clone(&owner.service),
                policy: LeasePolicy::default(),
            },
            calls: Rc::clone(&calls),
            contains_old_name: Rc::clone(&contains_old_name),
        }));
        if slow_options {
            provider.start_file_owner().unwrap();
            for _ in 0..32 {
                provider.step_files_with_watch_readiness(now_seconds(), false);
                if !provider.files_initializing() {
                    break;
                }
            }
            assert!(!provider.files_initializing());
        } else {
            provider.initialize(now_seconds());
        }
        assert_eq!(
            owner
                .service
                .borrow()
                .local
                .leases
                .lookup(b"a.test", now_seconds())
                .count(),
            1
        );
        let held = owner.service.borrow_mut().local.hosts.tcp_snapshot();
        super::tests::attach_test_dhcp(&mut owner, provider);
        calls.set(0);
        std::fs::write(&hosts_path,
            b"192.0.2.2 old.test\n192.0.2.1 x.test\n192.0.3.186 a.test\n192.0.3.185 a.test\n192.0.2.1 y.test\n192.0.2.2 y.test\n",
        ).unwrap();
        let held_options = if slow_options {
            std::fs::remove_file(&options_path).unwrap();
            assert!(std::process::Command::new("mkfifo")
                .arg(&options_path)
                .status()
                .unwrap()
                .success());
            Some(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(0o4000)
                    .open(&options_path)
                    .unwrap(),
            )
        } else {
            None
        };
        owner.reload_data(37).unwrap();
        if slow_options {
            let provider = owner.dhcp.as_ref().unwrap().provider.as_ref().unwrap();
            for _ in 0..32 {
                let mut provider = provider.borrow_mut();
                if !provider.files_runnable() {
                    break;
                }
                provider.step_files_with_watch_readiness(now_seconds(), false);
            }
            assert!(provider.borrow().file_work_pending());
            assert!(!provider.borrow().files_runnable());
            assert_eq!(
                calls.get(),
                0,
                "held DHCP input must prevent the final lease publication"
            );
            {
                let parent = owner.service.borrow();
                assert!(parent.pending_hosts.is_some());
                assert_eq!(parent.local.hosts.addresses(b"a.test").count(), 0);
                assert_eq!(
                    parent.local.leases.lookup(b"a.test", now_seconds()).count(),
                    1
                );
                assert_eq!(
                    parent
                        .daemon
                        .as_ref()
                        .unwrap()
                        .try_clone_hosts_source()
                        .unwrap()
                        .addresses(b"a.test")
                        .count(),
                    0
                );
                let mut tcp_view = parent.local.hosts.try_clone().unwrap();
                assert_eq!(tcp_view.tcp_snapshot().addresses(b"a.test").count(), 0);
            }
            drop(held_options);
            for _ in 0..32 {
                provider
                    .borrow_mut()
                    .step_files_with_watch_readiness(now_seconds(), false);
                if calls.get() != 0 {
                    break;
                }
            }
            assert!(!provider.borrow().file_work_pending());
        }
        assert_eq!(
            calls.get(),
            1,
            "only the real provider publishes the replacement lease source"
        );
        let parent = owner.service.borrow();
        assert!(parent.pending_hosts.is_none());
        assert_eq!(
            parent.local.leases.lookup(b"a.test", now_seconds()).count(),
            0
        );
        let order: Vec<_> = parent
            .local
            .hosts
            .addresses(b"a.test")
            .map(|host| host.address)
            .collect();
        let mut expected = [
            "192.0.3.186".parse::<IpAddr>().unwrap(),
            "192.0.3.185".parse().unwrap(),
        ];
        if contains_old_name.get() {
            expected.reverse();
        }
        assert_eq!(
            order, expected,
            "rebuilding the stale a.test lease early adds an extra hosts rotation"
        );
        assert_eq!(
            parent
                .local
                .hosts
                .reverse_all("192.0.2.1".parse().unwrap())
                .count(),
            1
        );
        assert_eq!(held.addresses(b"a.test").count(), 0);
        drop(parent);
        drop(owner);
        std::fs::remove_dir_all(root).unwrap();
    }
}
