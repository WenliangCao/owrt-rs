#![no_main]

use dnsmasq_rs::config::{dns::DnsConfig, lex_line};
use dnsmasq_rs::dns::local::{configured_hosts, LocalAnswerer};
use dnsmasq_rs::dns::wire::{Message, Name, PacketWriter};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Configuration only: no loader, filesystem access, sockets, or platform
    // hostname discovery. Bounded multiline seeds exercise CNAME chains and
    // MX/SRV target-address composition as well as individual encoders.
    if data.len() > 16_384 {
        return;
    }
    let mut config = DnsConfig::default();
    for line in data.split(|&byte| byte == b'\n').take(128) {
        match lex_line(line) {
            Ok(Some(directive)) => {
                if config.apply(&directive).is_err() {
                    return;
                }
            }
            Ok(None) => {}
            Err(_) => return,
        }
    }
    if config.finalize_hostname(b"fuzz-host").is_err() || config.finalize().is_err() {
        return;
    }
    let mut names: Vec<&[u8]> = vec![b"fuzz-host"];
    names.extend(
        config
            .host_records
            .iter()
            .flat_map(|record| record.names.iter().map(Vec::as_slice)),
    );
    names.extend(
        config
            .records
            .cnames
            .iter()
            .map(|record| record.alias.as_slice()),
    );
    names.extend(
        config
            .records
            .mx
            .iter()
            .map(|record| record.name.as_slice()),
    );
    names.extend(
        config
            .records
            .srv
            .iter()
            .map(|record| record.name.as_slice()),
    );
    names.extend(
        config
            .records
            .txt
            .iter()
            .map(|record| record.name.as_slice()),
    );
    names.extend(
        config
            .records
            .ptr
            .iter()
            .map(|record| record.name.as_slice()),
    );
    names.extend(
        config
            .records
            .raw_records()
            .iter()
            .map(|record| record.name.as_slice()),
    );
    names.extend(
        config
            .records
            .naptr
            .iter()
            .map(|record| record.name.as_slice()),
    );
    let mut hosts = configured_hosts(&config, 37);
    for owner in names.into_iter().take(16) {
        let Ok(owner) = Name::from_dotted_bytes(owner) else {
            continue;
        };
        for rrtype in [1, 28, 5, 12, 15, 16, 33, 35, 255] {
            let mut query = PacketWriter::new(1, 0x100, 512).unwrap();
            if query.question(&owner, rrtype, 1).is_err() {
                continue;
            }
            let request = query.finish();
            for limit in [64, 512, 1232] {
                let mut answerer = LocalAnswerer {
                    config: &config,
                    hosts: &mut hosts,
                    local_ttl: 37,
                    max_packet: limit,
                };
                if let Ok(Some(reply)) = answerer.answer(&request) {
                    assert!(reply.len() <= limit);
                    assert!(Message::parse(&reply).is_ok());
                }
            }
        }
    }
});
