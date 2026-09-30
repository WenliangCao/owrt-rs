//! Offline probe used by `tools/dnsmasq/dhcp_reply_diff.py`.
use dnsmasq_rs::dhcp::packet::{Packet, VendorOption, COOKIE};
use dnsmasq_rs::dhcp::reply::{build_reply_with_fuzz, ReplyOption};
use dnsmasq_rs::dhcp::state::{Refusal, Reply};
use std::io::{self, BufRead};
use std::net::Ipv4Addr;

fn decode(value: &str) -> Vec<u8> {
    if value == "-" {
        return Vec::new();
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 5 && fields.len() != 6 {
            eprintln!("expected kind request-options lease rapid options [fuzz]");
            std::process::exit(2);
        }
        let kind = fields[0];
        let request_options = decode(fields[1]);
        let mut request_bytes = vec![0; 240];
        request_bytes[0] = 1;
        request_bytes[1] = 1;
        request_bytes[2] = 6;
        request_bytes[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        request_bytes[236..240].copy_from_slice(&COOKIE);
        request_bytes.extend_from_slice(&request_options);
        let request = Packet::parse(&request_bytes).unwrap();
        let lease: u32 = fields[2].parse().unwrap();
        let rapid = fields[3] == "1";
        let reply = match kind {
            "O" => Reply::Offer {
                address: Ipv4Addr::new(192, 0, 2, 42),
                lease_time: lease,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            "A" => Reply::Ack {
                address: Ipv4Addr::new(192, 0, 2, 42),
                lease_time: lease,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
                rapid_commit: rapid,
            },
            "N" => Reply::Nak {
                reason: Refusal::WrongNetwork,
                broadcast: false,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            "I" | "J" => Reply::Inform {
                lease_time: (kind == "J").then_some(lease),
                context: None,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            _ => panic!("unsupported reply kind"),
        };
        let mut options = Vec::new();
        for option in fields[4]
            .split(',')
            .filter(|value| !value.is_empty() && *value != "-")
        {
            let (code, value) = option.split_once(':').unwrap();
            options.push((code.parse::<u8>().unwrap(), decode(value)));
        }
        let borrowed: Vec<ReplyOption<'_>> = options
            .iter()
            .map(|(code, value)| VendorOption { code: *code, value })
            .collect();
        let mut output = vec![0; 16_384];
        match build_reply_with_fuzz(
            request,
            reply,
            &borrowed,
            request.option(55, 0).is_some(),
            fields.get(5).map_or(0, |word| word.parse().unwrap()),
            &mut output,
        ) {
            Ok(result) => {
                print!("{} {} {} ", result.len, result.omitted, result.overload);
                for byte in &output[..result.len] {
                    print!("{byte:02x}");
                }
                println!();
            }
            Err(error) => println!("ERR:{error:?}"),
        }
    }
}
