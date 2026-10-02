#![no_main]

use dnsmasq_rs::config::{lex_line, validate_directive};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(directive)) = lex_line(data) {
        let _ = validate_directive(&directive);
    }
});
