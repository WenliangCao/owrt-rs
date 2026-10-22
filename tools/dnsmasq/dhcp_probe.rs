//! Offline differential adapter; not linked into the product.
use dnsmasq_rs::dhcp;

use dhcp::lease::{ClientIdentity, LeaseStore};
use std::io::{self, BufRead};
use std::net::Ipv4Addr;

fn hex(value: &str) -> Vec<u8> {
    if value == "-" {
        return Vec::new();
    }
    assert!(value.len().is_multiple_of(2), "hex fixture has an unmatched nibble");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn print_option(value: Option<(usize, &[u8])>) {
    if let Some((offset, bytes)) = value {
        print!("{offset}:");
        for byte in bytes {
            print!("{byte:02x}");
        }
        println!();
    } else {
        println!("-");
    }
}

fn identity(words: &mut std::str::SplitWhitespace<'_>) -> ClientIdentity {
    let hardware_type = words.next().unwrap().parse().unwrap();
    let hardware_address = hex(words.next().unwrap());
    let client_id = hex(words.next().unwrap());
    ClientIdentity {
        hardware_type,
        hardware_address,
        client_id: (!client_id.is_empty()).then_some(client_id),
    }
}

fn address(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(index as u32)
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut words = line.split_whitespace();
        match words.next().unwrap() {
            "H" => match dhcp::packet::client_hostname_value(&hex(words.next().unwrap())) {
                Some(name) => {
                    for byte in name {
                        print!("{byte:02x}");
                    }
                    println!();
                }
                None => println!("-"),
            },
            "V" => {
                use dhcp::pxe::{self, Service};
                let architecture = words.next().unwrap().parse().unwrap();
                let custom_prompt = words.next().unwrap() == "1";
                let port4011 = words.next().unwrap() == "1";
                let tag = hex(words.next().unwrap());
                let tags = if tag.is_empty() {
                    vec![]
                } else {
                    vec![tag.as_slice()]
                };
                let count = words.next().unwrap().parse().unwrap();
                let mut services = Vec::new();
                for _ in 0..count {
                    let architecture = words.next().unwrap().parse().unwrap();
                    let service_type = words.next().unwrap().parse().unwrap();
                    let menu = hex(words.next().unwrap());
                    let base = hex(words.next().unwrap());
                    let server = Ipv4Addr::from(words.next().unwrap().parse::<u32>().unwrap());
                    let name = hex(words.next().unwrap());
                    let filter = hex(words.next().unwrap());
                    services.push(Service {
                        architecture,
                        service_type,
                        menu,
                        basename: (!base.is_empty()).then_some(base),
                        server,
                        server_name: (!name.is_empty()).then_some(name),
                        filter: if filter.is_empty() {
                            vec![]
                        } else {
                            vec![filter]
                        },
                    });
                }
                let local = Ipv4Addr::new(192, 0, 2, 1);
                let resolve = |name: &[u8]| {
                    if name == b"server.test" {
                        Ipv4Addr::new(192, 0, 2, 44)
                    } else {
                        Ipv4Addr::UNSPECIFIED
                    }
                };
                let service = pxe::single_uefi_service(architecture, &services, &tags);
                let target = service
                    .filter(|_| port4011)
                    .map(|service| pxe::uefi_target(service, local, resolve));
                print!(
                    "{}:{}:",
                    u8::from(service.is_some()),
                    target
                        .as_ref()
                        .map_or(0, |target| u32::from(target.next_server))
                );
                for value in [
                    target
                        .as_ref()
                        .map(|target| target.filename.as_slice())
                        .unwrap_or_default(),
                    target
                        .as_ref()
                        .map(|target| target.server_name.as_slice())
                        .unwrap_or_default(),
                ] {
                    for byte in value {
                        print!("{byte:02x}");
                    }
                    print!(",");
                }
                print!("|");
                if let Ok(options) = pxe::menu_options(
                    architecture,
                    &services,
                    &tags,
                    local,
                    custom_prompt,
                    resolve,
                ) {
                    for (code, value) in [
                        (6, vec![options.discovery_control]),
                        (
                            10,
                            options.prompt.map_or_else(Vec::new, |value| value.to_vec()),
                        ),
                        (8, options.servers),
                        (9, options.menu),
                    ] {
                        if !value.is_empty() {
                            print!("{code}:");
                            for byte in value {
                                print!("{byte:02x}");
                            }
                            print!(";");
                        }
                    }
                }
                if custom_prompt {
                    print!("10:0743;");
                }
                println!();
            }
            "S" => {
                use dhcp::lease::{ScriptAction, ScriptOptions, ScriptQueue};
                let flags: u32 = words.next().unwrap().parse().unwrap();
                let options = ScriptOptions {
                    lease_file_read_only: flags & 2 != 0,
                    notify_renewals: flags & 4 != 0,
                };
                let count = words.next().unwrap().parse().unwrap();
                let mut store = LeaseStore::new(64);
                let mut queue = ScriptQueue::default();
                for _ in 0..count {
                    match words.next().unwrap() {
                        "a" => {
                            let index: usize = words.next().unwrap().parse().unwrap();
                            store
                                .allocate(
                                    address(index),
                                    ClientIdentity {
                                        hardware_type: 1,
                                        hardware_address: vec![index as u8],
                                        client_id: None,
                                    },
                                )
                                .unwrap();
                            store.set_expires(address(index), 1000, 100).unwrap();
                        }
                        "n" => {
                            let index = words.next().unwrap().parse().unwrap();
                            let name = hex(words.next().unwrap());
                            let domain = hex(words.next().unwrap());
                            let auth = words.next().unwrap() == "1";
                            store
                                .set_hostname(
                                    address(index),
                                    (!name.is_empty()).then_some(name.as_slice()),
                                    auth,
                                    (!domain.is_empty()).then_some(domain.as_slice()),
                                    flags & 1 != 0,
                                )
                                .unwrap();
                        }
                        "r" => {
                            let index = words.next().unwrap().parse().unwrap();
                            let length = words.next().unwrap().parse().unwrap();
                            let now = words.next().unwrap().parse().unwrap();
                            store.set_expires(address(index), length, now).unwrap();
                        }
                        "p" => {
                            let index = words.next().unwrap().parse().unwrap();
                            let now = words.next().unwrap().parse().unwrap();
                            queue.add_pruned(
                                store.prune((index != 0).then_some(address(index)), now),
                            );
                        }
                        "h" => store.rerun_scripts(),
                        "d" => {
                            while let Some(event) = queue.next(&mut store, options) {
                                let action = match event.action {
                                    ScriptAction::Add => 1,
                                    ScriptAction::Old => 2,
                                    ScriptAction::Delete => 3,
                                    ScriptAction::OldHostname => 4,
                                };
                                print!("{action}:{}:", u32::from(event.lease.address));
                                if let Some(name) = event.name {
                                    for byte in name {
                                        print!("{byte:02x}");
                                    }
                                } else {
                                    print!("-");
                                }
                                print!(";");
                            }
                        }
                        other => panic!("bad script operation {other}"),
                    }
                }
                println!();
            }
            "X" => {
                let input = hex(words.next().unwrap());
                let maximum = words.next().unwrap().parse().unwrap();
                let typed = words.next().unwrap() == "1";
                let (value, hardware_type) = dhcp::lease_file::parse_hex(&input, maximum, typed);
                print!("{hardware_type}:");
                if let Some(value) = value {
                    for byte in value {
                        print!("{byte:02x}");
                    }
                } else {
                    print!("-");
                }
                println!();
            }
            "F" => {
                let input = hex(words.next().unwrap());
                let result = dhcp::lease_file::parse(&input);
                print!("{}:{}", u8::from(result.clean_end), result.invalid_records);
                for record in result.records {
                    print!(
                        "|{},{},{},",
                        record.expires, record.hardware_type, record.address
                    );
                    for value in [
                        Some(record.hardware_address),
                        record.hostname,
                        record.client_id,
                        record.agent_id,
                        record.vendor_class,
                    ] {
                        if let Some(value) = value {
                            for byte in value {
                                print!("{byte:02x}");
                            }
                        } else {
                            print!("-");
                        }
                        print!(",");
                    }
                }
                println!();
            }
            "O" => {
                let bytes = hex(words.next().unwrap());
                let code = words.next().unwrap().parse().unwrap();
                let min_len = words.next().unwrap().parse().unwrap();
                print_option(
                    dhcp::packet::find_option(&bytes, code, min_len).map(|v| (v.offset, v.value)),
                );
            }
            "W" => {
                let bytes = hex(words.next().unwrap());
                let code = words.next().unwrap().parse().unwrap();
                let min_len = words.next().unwrap().parse().unwrap();
                let packet = dhcp::packet::Packet::parse(&bytes).unwrap();
                print_option(packet.option(code, min_len).map(|value| {
                    let offset = value.as_ptr() as usize - bytes.as_ptr() as usize;
                    // END is a tag without length, unlike ordinary TLVs.
                    (offset - if code == 255 { 1 } else { 2 }, value)
                }));
            }
            "D" => {
                let range = words.next().unwrap().parse().unwrap();
                let configured = words.next().unwrap();
                let requested = words.next().unwrap();
                println!(
                    "{}",
                    dhcp::request::lease_duration(
                        range,
                        (configured != "-").then(|| configured.parse().unwrap()),
                        (requested != "-").then(|| requested.parse().unwrap())
                    )
                );
            }
            "E" => {
                let length = words.next().unwrap().parse().unwrap();
                let now = words.next().unwrap().parse().unwrap();
                println!("{}", dhcp::lease::expiry_time(length, now).unwrap_or(0));
            }
            "I" => {
                let lookup = identity(&mut words);
                let count: usize = words.next().unwrap().parse().unwrap();
                let mut store = LeaseStore::new(count);
                for index in 1..=count {
                    store
                        .allocate(address(index), identity(&mut words))
                        .unwrap();
                }
                println!(
                    "{}",
                    store
                        .find_client(&lookup)
                        .map_or(0, |lease| u32::from(lease.address))
                );
            }
            "P" => {
                let now = words.next().unwrap().parse().unwrap();
                let target: usize = words.next().unwrap().parse().unwrap();
                let count: usize = words.next().unwrap().parse().unwrap();
                let mut store = LeaseStore::new(count);
                for index in 1..=count {
                    let length = words.next().unwrap().parse().unwrap();
                    store
                        .allocate(
                            address(index),
                            ClientIdentity {
                                hardware_type: 1,
                                hardware_address: vec![index as u8],
                                client_id: None,
                            },
                        )
                        .unwrap();
                    store.set_expires(address(index), length, 100).unwrap();
                }
                let removed = store.prune((target != 0).then_some(address(target)), now);
                println!(
                    "{}",
                    removed
                        .iter()
                        .map(|lease| u32::from(lease.address).to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            op => panic!("invalid operation {op}"),
        }
    }
}
