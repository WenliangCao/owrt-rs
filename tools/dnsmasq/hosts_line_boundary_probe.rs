//! Source-level streaming/staged loader comparison under one actual hash seed.
//! rustc --edition=2024 -Awarnings tools/dnsmasq/hosts_line_boundary_probe.rs -o PRIVATE/probe
#[path = "../../components/dnsmasq/src/hosts.rs"]
mod hosts;
use hosts::Hosts;

fn main() {
    let y = (0..10000)
        .map(|i| format!("cross{i}.test"))
        .find(|name| {
            hosts::name_hash_bucket(name.as_bytes(), 2100)
                == hosts::name_hash_bucket(b"x.test", 2100)
        })
        .unwrap();
    let seed = format!("192.0.2.1 x.test\n10.0.63.213 a.test\n192.0.4.2 a.test\n192.0.2.1 {y}\n192.0.4.1 x.test\n");
    let mut base = Hosts::new();
    base.begin_bulk(1497, 1000, 1000).unwrap();
    assert!(!base.read(seed.as_bytes(), 2, 37, false, |_| None).allocation_failed);
    let address = "192.0.2.1".parse().unwrap();
    let names: Vec<_> = (0..1001)
        .map(|i| format!("extra{i:04}.test"))
        .chain(std::iter::once("x.test".to_string()))
        .collect();
    let input = format!("192.0.2.1 {}\n", names.join(" "));
    let records = || names.iter().map(|name| (name.as_bytes().to_vec(), address)).collect();
    let mut streaming = base.try_clone().unwrap();
    assert!(!streaming.read(input.as_bytes(), 3, 37, false, |_| None).allocation_failed);
    // Negative control: falsely treating each accepted alias as its own line
    // reproduces the previous staged-reader rehash placement.
    let (mut per_record, _) = base.try_replace_source(3, b"/staged", records(), 37).unwrap();
    let (mut per_line, _) = base.try_replace_source_with_leases(
        3, b"/staged", records(), 37,
        std::iter::empty::<(&[u8], std::net::IpAddr, bool, bool)>(), [1002],
    ).unwrap();
    streaming.finish_bulk();
    per_record.finish_bulk();
    per_line.finish_bulk();
    let order = |hosts: &Hosts| hosts.addresses(b"x.test").map(|host| host.address.to_string()).collect::<Vec<_>>();
    let ptr = |hosts: &Hosts| hosts.reverse_all(address).map(|host| String::from_utf8_lossy(&host.name).to_string()).collect::<Vec<_>>();
    assert_ne!(order(&streaming), order(&per_record));
    assert_ne!(ptr(&streaming), ptr(&per_record));
    assert_eq!(order(&streaming), order(&per_line));
    assert_eq!(ptr(&streaming), ptr(&per_line));
    assert_eq!(streaming.entries(), per_line.entries());
    println!("{{\"selected\":{y:?},\"accepted_aliases\":1002,\"streaming_a\":{:?},\"per_record_a\":{:?},\"per_line_a\":{:?},\"streaming_ptr\":{:?},\"per_record_ptr\":{:?},\"per_line_ptr\":{:?},\"negative_reproduced\":true,\"line_boundary_matches\":true}}",
        order(&streaming), order(&per_record), order(&per_line), ptr(&streaming), ptr(&per_record), ptr(&per_line));
}
