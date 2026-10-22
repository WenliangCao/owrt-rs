//! Narrow offline adapter for state decisions, driven by the isolated C probe.
#![allow(dead_code)]
use dnsmasq_rs::dhcp;

use dhcp::allocation::{AddressRange, ProbeResult, RangeKind};
use dhcp::lease::{ClientIdentity, LeaseStore};
use dhcp::packet::Packet;
use dhcp::state::{self, Environment, HostPolicy, Reply, Request};
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, last)
}
fn client(last: u8) -> ClientIdentity {
    ClientIdentity {
        hardware_type: 1,
        hardware_address: vec![2, 0, 0, 0, 0, last],
        client_id: None,
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let authoritative = args[1] == "1";
    let static_count: u8 = args[2].parse().unwrap();
    let mut host = HostPolicy {
        address: Some(ip(15)),
        hardware_addresses: (1..=static_count).map(client).collect(),
        ..HostPolicy::default()
    };
    let reserved = if static_count == 0 {
        vec![]
    } else {
        vec![ip(15)]
    };
    let mut store = LeaseStore::new(150);
    let mut ranges = [AddressRange {
        start: ip(10),
        end: ip(20),
        netmask: Ipv4Addr::new(255, 0, 0, 0),
        router: ip(1),
        local: ip(1),
        lease_time: 120,
        kind: RangeKind::Dynamic,
        filter: vec![],
        epoch: 0,
    }];
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (now, encoded) = line.split_once(' ').unwrap();
        let now = now.parse().unwrap();
        assert!(encoded.len().is_multiple_of(2), "hex fixture has an unmatched nibble");
        let mut bytes: Vec<_> = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        // dhcp.c's giaddr=INADDR_BROADCAST test transport convention.
        if bytes[24..28] == [255; 4] {
            bytes[24..28].fill(0);
        }
        let packet = Packet::parse(&bytes).unwrap();
        let selected = host
            .hardware_addresses
            .iter()
            .any(|identity| identity.hardware_address == packet.hardware_address());
        let environment = Environment {
            now,
            interface: 1,
            authoritative,
            unicast_destination: true,
            ignored: false,
            ignore_client_id: false,
            fqdn_only: false,
            rapid_commit: args.get(3).is_some_and(|arg| arg == "1"),
            bootp_dynamic: args.get(4).is_some_and(|arg| arg == "1"),
            consecutive_addresses: false,
            override_server: None,
            fallback_server: ip(1),
            server_aliases: &[],
        };
        store.prune(None, now);
        if packet.message_type() == 10 {
            use dhcp::lease_query::{self, Query};
            let mode = args.get(5).map_or("0", |arg| arg.as_str());
            let allowed = match mode {
                "1" => vec![(std::net::IpAddr::V4(ip(0)), 8)],
                "2" => vec![(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)],
                "3" => vec![(std::net::IpAddr::V6("::1".parse().unwrap()), 128)],
                _ => vec![],
            };
            if let Some(reply) = lease_query::query(
                &store,
                &ranges,
                Query {
                    packet,
                    source: ip(1),
                    enabled: mode != "0",
                    allowed_sources: &allowed,
                    tags: &[],
                    now,
                    ignore_client_id: false,
                    configured_lease_time: None,
                },
            ) {
                let number = |value: Option<u32>| {
                    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
                };
                print!(
                    "{} {} {} - 0 - 0 t1={} t2={} last={} mac=",
                    reply.status as u8,
                    reply.client_address,
                    number(reply.lease_time),
                    number(reply.renewal_time),
                    number(reply.rebinding_time),
                    number(reply.last_transaction)
                );
                for byte in reply.hardware_address {
                    print!("{byte:02x}");
                }
                for (key, value) in [("clid", reply.client_id), ("agent", reply.agent_id)] {
                    print!(" {key}=");
                    if let Some(value) = value {
                        for byte in value {
                            print!("{byte:02x}");
                        }
                    } else {
                        print!("-");
                    }
                }
            } else {
                print!("0 - - - - - -");
            }
            let mut leases = Vec::new();
            store.write_leases(&mut leases).unwrap();
            println!(
                " | {}",
                String::from_utf8(leases).unwrap().replace('\n', ";")
            );
            io::stdout().flush().unwrap();
            continue;
        }
        let reply = match packet.message_type() {
            0 => {
                state::bootp(
                    &mut store,
                    &mut ranges,
                    Request {
                        packet,
                        tags: &[],
                        host: selected.then_some(&host),
                        reserved: &reserved,
                        name: None,
                        environment,
                    },
                    |_, hash| ProbeResult::Available { offer_hash: hash },
                )
                .unwrap()
                .reply
            }
            1 => {
                state::discover(
                    &mut store,
                    &mut ranges,
                    Request {
                        packet,
                        tags: &[],
                        host: selected.then_some(&host),
                        reserved: &reserved,
                        name: None,
                        environment,
                    },
                    |_, hash| ProbeResult::Available { offer_hash: hash },
                )
                .unwrap()
                .reply
            }
            3 => {
                state::request(
                    &mut store,
                    &ranges,
                    Request {
                        packet,
                        tags: &[],
                        host: selected.then_some(&host),
                        reserved: &reserved,
                        name: None,
                        environment,
                    },
                )
                .unwrap()
                .reply
            }
            4 => {
                state::decline(
                    &mut store,
                    &mut ranges,
                    packet,
                    selected.then_some(&mut host),
                    environment,
                );
                Reply::Ignore
            }
            7 => {
                state::release(&mut store, &ranges, packet, &[], environment);
                Reply::Ignore
            }
            8 => {
                state::inform(
                    &mut store,
                    &ranges,
                    Request {
                        packet,
                        tags: &[],
                        host: selected.then_some(&host),
                        reserved: &reserved,
                        name: None,
                        environment,
                    },
                )
                .unwrap()
                .reply
            }
            _ => panic!("message type outside probe contract"),
        };
        match reply {
            Reply::Ignore => print!("0 - - - - - -"),
            Reply::Offer {
                address,
                lease_time,
                server,
                ..
            } => print!("2 {address} {lease_time} {server} 0 - 0"),
            Reply::Bootp { address, .. } => print!("16 {address} - - 0 - 0"),
            Reply::Inform {
                lease_time, server, ..
            } => print!(
                "5 0.0.0.0 {} {server} 0 - 0",
                lease_time.map_or_else(|| "-".to_owned(), |value| value.to_string())
            ),
            Reply::Ack {
                address,
                lease_time,
                server,
                rapid_commit,
                ..
            } => print!(
                "5 {address} {lease_time} {server} 0 - {}",
                u8::from(rapid_commit)
            ),
            Reply::Nak {
                server,
                broadcast,
                reason,
            } => {
                print!("6 0.0.0.0 - {server} {} ", u8::from(broadcast));
                for byte in reason.message().bytes() {
                    print!("{byte:02x}");
                }
                print!(" 0");
            }
        }
        print!(" | ");
        let mut leases = Vec::new();
        store.write_leases(&mut leases).unwrap();
        print!("{}", String::from_utf8(leases).unwrap().replace('\n', ";"));
        println!();
        io::stdout().flush().unwrap();
    }
}
