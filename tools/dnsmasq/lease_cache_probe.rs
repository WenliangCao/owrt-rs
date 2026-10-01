use dnsmasq_rs::dns::cache::{Cache, Kind, Policy, Record};
use dnsmasq_rs::dns::lease_names::{
    BlockerKind, ForwardPublication, PublicationBlocker, PublicationCache,
};
use dnsmasq_rs::dns::wire::Name;
use std::collections::HashMap;
use std::io::{self, BufRead};

fn kind(t: u32) -> Kind {
    match t {
        1 => Kind::Ipv4,
        28 => Kind::Ipv6,
        5 => Kind::Cname,
        65536 => Kind::NxDomain,
        _ => Kind::Generic(t as u16),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let capacity = args.next().unwrap().parse().unwrap();
    let no_round_robin = args.next().unwrap() == "1";
    let mut cache = Cache::new(capacity, Policy::default());
    let mut ids = Vec::new();
    let mut blockers: HashMap<String, Vec<PublicationBlocker>> = HashMap::new();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let w: Vec<_> = line.split_whitespace().collect();
        let n = |i: usize| w[i].parse::<u32>().unwrap();
        match w[0] {
            "B" => {
                cache.start_insert();
                println!("B");
            }
            "C" => println!("C {}", u8::from(cache.commit())),
            "I" => {
                let result = cache.insert(
                    Record {
                        name: Name::from_ascii(w[1]).unwrap(),
                        kind: kind(n(2)),
                        negative: n(5) != 0,
                        data: vec![n(4) as u8],
                    },
                    w[6].parse().unwrap(),
                    n(3),
                );
                println!("I {}", u8::from(result.is_ok()));
                ids.push(result.ok());
            }
            "L" => {
                let ok = match (ids[n(1) as usize], ids[n(2) as usize]) {
                    (Some(a), Some(b)) => cache.set_cname_target(a, b),
                    _ => false,
                };
                println!("L {}", u8::from(ok));
            }
            "H" => {
                blockers
                    .entry(w[1].to_ascii_lowercase())
                    .or_default()
                    .push(PublicationBlocker {
                        kind: match n(2) {
                            1 => BlockerKind::Ipv4,
                            28 => BlockerKind::Ipv6,
                            5 => BlockerKind::Cname,
                            _ => panic!(),
                        },
                        reverse: n(3) != 0,
                        immortal: n(4) != 0,
                    });
                println!("H");
            }
            "D" => {
                cache.prepare_name(ForwardPublication {
                    name: w[1].as_bytes(),
                    no_round_robin,
                    blockers: blockers
                        .get(&w[1].to_ascii_lowercase())
                        .map_or(&[], Vec::as_slice),
                });
                println!("D");
            }
            "Q" => {
                print!("Q");
                for id in cache.lookup(
                    &Name::from_ascii(w[1]).unwrap(),
                    &[kind(n(2))],
                    w[3].parse().unwrap(),
                    false,
                ) {
                    let e = cache.get(id).unwrap();
                    let t = match e.record.kind {
                        Kind::Ipv4 => 1,
                        Kind::Ipv6 => 28,
                        Kind::Cname => 5,
                        Kind::NxDomain => 65536,
                        Kind::Generic(t) => t as u32,
                    };
                    let value = if t == 5 { 0 } else { e.record.data[0] };
                    print!(" {t}:{value}:{}:{}", u8::from(e.record.negative), e.expires);
                }
                println!();
            }
            _ => panic!(),
        }
    }
}
