#![no_main]

use dnsmasq_rs::dns::wire::{find_pseudoheader, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Message::parse(data);
    let _ = find_pseudoheader(data, true);
});
