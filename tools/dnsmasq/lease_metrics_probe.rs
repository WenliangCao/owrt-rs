//! Offline adapter to production lease operations; C supplies all expectations.
use dnsmasq_rs::dhcp::{
    lease::{ClientIdentity, LeaseStore},
    lease_file,
};
use std::{
    io::{self, BufRead},
    net::Ipv4Addr,
};

fn main() {
    let mut store = None;
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut words = line.split_whitespace();
        let op = words.next().unwrap();
        let result = if op == "S" {
            assert!(store.is_none());
            store = Some(LeaseStore::new(words.next().unwrap().parse().unwrap()));
            1
        } else {
            let store = store.as_mut().unwrap();
            match op {
                "A" => {
                    let address = words.next().unwrap().parse::<u32>().unwrap();
                    usize::from(
                        store
                            .allocate(
                                Ipv4Addr::from(address),
                                ClientIdentity {
                                    hardware_type: 1,
                                    hardware_address: address.to_be_bytes().to_vec(),
                                    client_id: None,
                                },
                            )
                            .is_ok(),
                    )
                }
                "E" => {
                    let address = Ipv4Addr::from(words.next().unwrap().parse::<u32>().unwrap());
                    let length = words.next().unwrap().parse().unwrap();
                    let now = words.next().unwrap().parse().unwrap();
                    usize::from(store.set_expires(address, length, now).is_ok())
                }
                "P" => {
                    let target = words.next().unwrap();
                    let address =
                        (target != "-").then(|| Ipv4Addr::from(target.parse::<u32>().unwrap()));
                    let now = words.next().unwrap().parse().unwrap();
                    store.prune(address, now).len()
                }
                "R" => {
                    let now = words.next().unwrap().parse().unwrap();
                    let file = lease_file::parse(&std::fs::read(words.next().unwrap()).unwrap());
                    store.restore(file.records, now).unwrap();
                    1
                }
                "H" => {
                    store.rerun_scripts();
                    1
                }
                "Q" => 1,
                _ => panic!("unknown operation"),
            }
        };
        let store = store.as_ref().unwrap();
        let counters = store.counters();
        println!(
            "{op} {result} {} {} {} {}",
            counters.allocated4,
            counters.pruned4,
            counters.pruned6,
            store.len()
        );
    }
}
