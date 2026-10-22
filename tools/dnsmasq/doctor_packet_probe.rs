use dnsmasq_rs::dns::doctor::{self, Alias};
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr};

fn unhex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex fixture has an unmatched nibble");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let rules = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let mut aliases = Vec::new();
    for line in rules.lines().filter(|line| !line.is_empty()) {
        let values: Vec<_> = line.split_whitespace().collect();
        let address = |index| Ipv4Addr::from(<[u8; 4]>::try_from(unhex(values[index])).unwrap());
        aliases.push(Alias {
            from: address(1),
            end: address(2),
            to: address(3),
            mask: address(4),
        });
    }
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let words: Vec<_> = line.split_whitespace().collect();
        let mut packet = unhex(words[1]);
        let mut responses = words[2].split(',');
        let mut callback = |name: &[u8], ttl, address: IpAddr| {
            let (family, data) = match address {
                IpAddr::V4(value) => (4, value.octets().to_vec()),
                IpAddr::V6(value) => (6, value.octets().to_vec()),
            };
            println!("E {} {ttl} {family} {}", hex(name), hex(&data));
            match responses.next() {
                Some("=") => Some(address),
                Some(value) => value.parse().ok(),
                None => None,
            }
        };
        let callback = if words[0] == "0" {
            None
        } else {
            Some(&mut callback as &mut doctor::Notify<'_>)
        };
        let outcome = doctor::apply(&mut packet, &aliases, callback);
        println!(
            "R {} {} {} {} {}",
            u8::from(outcome.clear_cache_secure),
            outcome.static_rewrites,
            outcome.ubus_rewrites,
            outcome.notifications,
            hex(&packet)
        );
        eprintln!("stop={:?}", outcome.stopped);
    }
}
