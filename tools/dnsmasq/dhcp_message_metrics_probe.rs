// Offline primitive adapter for actual-C message-counter observations.
use dnsmasq_rs::config::dhcp::DhcpConfig;
use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::config::loader::{self, Action};
use dnsmasq_rs::config::{Error, ScalarConfig};
use dnsmasq_rs::dhcp::allocation::{AddressRange, ProbeResult, RangeKind};
use dnsmasq_rs::dhcp::lease::{ClientIdentity, LeaseStore};
use dnsmasq_rs::dhcp::message_counters::MessageCounters;
use dnsmasq_rs::dhcp::runtime::{OutcomeProvider, StateProvider};
use dnsmasq_rs::dhcp::service::{self, DispatchKind, Ingress, Listener};
use dnsmasq_rs::dhcp::state::{Environment, HostPolicy, Reply};
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut config = DhcpConfig::default();
    let mut dns = DnsConfig::default();
    let mut scalar = ScalarConfig::default();
    let mut rapid = false;
    assert_eq!(
        loader::load(&args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
            // The state primitive supports rapid commit, while the ordinary
            // daemon configuration still explicitly rejects that runtime mode.
            if directive.name == b"dhcp-rapid-commit" {
                rapid = true;
                return Ok(());
            }
            if config.apply(directive)? || dns.apply(directive)? || scalar.apply(directive)? {
                Ok(())
            } else {
                Err(Error("unsupported message-counter probe option"))
            }
        })?,
        Action::Run
    );
    let local = Ipv4Addr::new(192, 0, 2, 1);
    let mut ranges: Vec<_> = config
        .ranges
        .iter()
        .map(|range| AddressRange {
            start: range.start,
            end: range.end,
            netmask: range.netmask.expect("fixture supplies mask"),
            router: local,
            local,
            lease_time: range.lease_time,
            kind: RangeKind::Dynamic,
            filter: Vec::new(),
            epoch: 0,
        })
        .collect();
    let mut hosts: Vec<_> = config
        .hosts
        .iter()
        .map(|host| HostPolicy {
            address: host.address,
            lease_time: host.lease_time,
            declined_at: None,
            hardware_addresses: host
                .hardware
                .iter()
                .map(|hardware| ClientIdentity {
                    hardware_type: hardware.kind,
                    hardware_address: hardware.address.clone(),
                    client_id: None,
                })
                .collect(),
            ignore_client_id: host.ignore_client_id,
        })
        .collect();
    let reserved: Vec<_> = config
        .hosts
        .iter()
        .filter_map(|host| host.address)
        .collect();
    let mut store = LeaseStore::new(config.lease_max);
    let mut counters = MessageCounters::default();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<_> = line.split_whitespace().collect();
        let mut response = 0;
        match fields[0] {
            "H" => {} // cache_reload does not modify these counters/store
            "M" => {
                let index: usize = fields[1].parse()?;
                let value = fields[2].parse()?;
                let slots = [
                    &mut counters.bootp,
                    &mut counters.pxe,
                    &mut counters.ack,
                    &mut counters.decline,
                    &mut counters.discover,
                    &mut counters.inform,
                    &mut counters.nak,
                    &mut counters.offer,
                    &mut counters.release,
                    &mut counters.request,
                    &mut counters.no_answer,
                ];
                *slots[index] = value;
            }
            "P" => {
                let now = fields[1].parse()?;
                let unicast = fields[2] == "1";
                assert!(fields[3].len().is_multiple_of(2));
                let bytes: Vec<_> = (0..fields[3].len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&fields[3][at..at + 2], 16).unwrap())
                    .collect();
                if let Ok(dispatch) = service::dispatch(
                    &bytes,
                    Ingress {
                        listener: Listener::Dhcp,
                        interface_index: 1,
                        unicast_destination: unicast,
                    },
                    &[],
                ) {
                    if matches!(dispatch.kind, DispatchKind::Dhcp | DispatchKind::Bootp) {
                        let packet = dispatch.packet;
                        let selected = config.find_host(
                            packet.client_id(),
                            u32::from(packet.hardware_type()),
                            Some(packet.hardware_address()),
                            |address| {
                                ranges.iter().any(|range| {
                                    u32::from(address) & u32::from(range.netmask)
                                        == u32::from(range.start) & u32::from(range.netmask)
                                })
                            },
                        );
                        let environment = Environment {
                            now,
                            interface: 1,
                            authoritative: config.authoritative,
                            unicast_destination: unicast,
                            ignored: selected.is_some_and(|index| config.hosts[index].ignore),
                            ignore_client_id: config.ignore_client_id,
                            fqdn_only: false,
                            rapid_commit: rapid,
                            bootp_dynamic: config.bootp_dynamic,
                            consecutive_addresses: config.sequential,
                            override_server: None,
                            fallback_server: local,
                            server_aliases: &[],
                        };
                        let mut provider = StateProvider::new(
                            &mut store,
                            &mut ranges,
                            &[],
                            selected.map(|index| &mut hosts[index]),
                            &reserved,
                            environment,
                            |_, hash, _| ProbeResult::Available { offer_hash: hash },
                        );
                        provider.quiet_dhcp = config.quiet_dhcp;
                        provider.message_counters = Some(&mut counters);
                        let outcome = provider
                            .resolve(&dispatch)
                            .map_err(|error| format!("{error:?}"))?;
                        response = match outcome.reply {
                            Reply::Ignore => 0,
                            Reply::Offer { .. } => 2,
                            Reply::Ack { .. } | Reply::Inform { .. } => 5,
                            Reply::Nak { .. } => 6,
                            Reply::Bootp { .. } => 16,
                        };
                    }
                }
            }
            operation => panic!("unsupported operation {operation}"),
        }
        print!("{} {response} {}", fields[0], store.len());
        for value in counters.as_array() {
            print!(" {value}");
        }
        println!();
    }
    Ok(())
}
