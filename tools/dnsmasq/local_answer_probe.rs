// Isolated Rust local-answer probe used by local_answer_diff.py.
// This is a test binary, not part of the installed daemon.

use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::config::loader::{self, Action};
use dnsmasq_rs::config::{Error, ScalarConfig};
use dnsmasq_rs::dns::service::LocalDnsService;
use std::io::{self, BufRead};
use std::path::Path;

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let mut chars = value.bytes();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let high = (high as char).to_digit(16)? as u8;
        let low = (low as char).to_digit(16)? as u8;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    // local_answer_diff.py appends the shared configuration path as the final
    // argument to every probe command; accept that compact form as -C FILE.
    if args.len() == 1 && !args[0].to_string_lossy().starts_with('-') {
        let path = args.pop().expect("one argument");
        args.extend(["-C".into(), path]);
    }
    let mut scalar = ScalarConfig::default();
    let mut config = DnsConfig::default();
    let action = loader::load(&args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        if scalar.apply(directive)? || config.apply(directive)? {
            Ok(())
        } else {
            Err(Error("unsupported probe option"))
        }
    })?;
    if action != Action::Run {
        return Err("probe requires normal run configuration".into());
    }
    scalar.finalize_runtime()?;
    config.finalize()?;
    config.validate_ready()?;
    let mut hosts = dnsmasq_rs::dns::local::configured_hosts(&config, scalar.local_ttl);
    hosts.set_round_robin(!config.no_round_robin);
    for path in &config.addn_hosts {
        let Some(path) = path else { continue };
        let bytes = std::fs::read(path)?;
        hosts.read(
            &bytes,
            1,
            scalar.local_ttl,
            config.expand_hosts,
            |address| {
                config
                    .domain_for_address(address)
                    .ok()
                    .flatten()
                    .map(ToOwned::to_owned)
            },
        );
    }
    let mut service = LocalDnsService::new_with_limits(
        config,
        hosts,
        scalar.local_ttl,
        usize::from(scalar.edns_packet_max) + 265,
        scalar.edns_packet_max,
    );
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        let first = fields.next().unwrap_or_default();
        let encoded = if matches!(first, "udp" | "tcp") {
            fields.next().unwrap_or_default()
        } else {
            first
        };
        let Some(query) = decode_hex(encoded) else {
            println!("NONE");
            continue;
        };
        let answer = if first == "tcp" {
            service.handle_tcp_payload(&query)
        } else {
            service.handle_udp(&query)
        };
        match answer {
            Ok(Some(packet)) => println!(
                "{}",
                packet
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            Ok(None) | Err(_) => println!("NONE"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn hex_input_is_consumed_completely_or_rejected() {
        assert_eq!(decode_hex("00aF10"), Some(vec![0, 0xaf, 0x10]));
        assert_eq!(decode_hex(""), Some(Vec::new()));
        for malformed in ["0", "00f", "00g", "0g", "é", "00é"] {
            assert_eq!(decode_hex(malformed), None, "{malformed:?}");
        }
    }
}
