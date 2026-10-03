#![no_main]

use dnsmasq_rs::tftp::{encode_netascii, parse_request, Transfer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Pure packet and transfer-state parsing only: no filesystem or sockets.
    if data.len() > 8192 {
        return;
    }
    for (mtu, ipv6, no_blocksize) in [
        (None, false, false),
        (Some(1200), true, false),
        (Some(600), false, true),
    ] {
        if let Ok(Some(request)) = parse_request(data, 8192, mtu, ipv6, no_blocksize) {
            let mut ack = Vec::new();
            request.options.write_ack(4096, &mut ack);
            assert!(ack.len() < 128);
            let mut transfer = Transfer::new(request.options, request.mode, 1);
            for (index, packet) in data.chunks(4).take(128).enumerate() {
                transfer.receive(packet, index as u64 + 1);
                transfer.begin_window(index as u64 + 1);
                transfer.file_offset(4096);
            }
        }
    }
    let mut output = [0u8; 512];
    let result = encode_netascii(&data[..data.len().min(512)], false, &mut output);
    assert!(result.len <= output.len());
});
