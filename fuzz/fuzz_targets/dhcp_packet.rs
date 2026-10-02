#![no_main]

use dnsmasq_rs::dhcp::packet::Packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = Packet::parse(data) {
        let _ = packet.message_type();
        let _ = packet.transaction_id();
        let _ = packet.client_id();
        let _ = packet.client_hostname();
        let _ = packet.requested_address();
        let _ = packet.response_capacity();
    }
});
