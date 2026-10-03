#![no_main]

use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::config::{dhcp::DhcpConfig, lex_line, validate_directive};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(directive)) = lex_line(data) {
        let _ = validate_directive(&directive);
        // Exercise semantic option/tag/host encoders as well as the scanner.
        // apply only changes in-memory configuration; no loader or file I/O.
        let _ = DhcpConfig::default().apply(&directive);
        let mut dns = DnsConfig::default();
        if let Ok(true) = dns.apply(&directive) {
            let _ = dns.finalize_hostname(b"fuzz-host");
            let _ = dns.finalize();
        }
    }
});
