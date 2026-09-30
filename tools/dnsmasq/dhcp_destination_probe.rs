//! Offline destination adapter; never opens a DHCP socket.
use dnsmasq_rs::dhcp::packet::COOKIE;
use dnsmasq_rs::dhcp::runtime::destination;
use dnsmasq_rs::dhcp::service::{dispatch, Ingress, Listener};
use dnsmasq_rs::dhcp::state::Reply;
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, SocketAddr};

fn main() {
    for line in io::stdin().lock().lines() {
        let values: Vec<u32> = line
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 8);
        let [inform, ciaddr, yiaddr, peer, port, flags, htype, hlen] = values[..] else {
            unreachable!()
        };
        let mut bytes = vec![0; 244];
        bytes[0] = 1;
        bytes[1] = htype as u8;
        bytes[2] = hlen as u8;
        bytes[10..12].copy_from_slice(&(flags as u16).to_be_bytes());
        bytes[12..16].copy_from_slice(&ciaddr.to_be_bytes());
        bytes[16..20].copy_from_slice(&yiaddr.to_be_bytes());
        for index in 0..16 {
            bytes[28 + index] = index as u8 + 1;
        }
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes[240..244].copy_from_slice(&[53, 1, if inform != 0 { 8 } else { 3 }, 255]);
        let admitted = dispatch(
            &bytes,
            Ingress {
                listener: Listener::Dhcp,
                interface_index: 7,
                unicast_destination: true,
            },
            &[],
        )
        .unwrap();
        let reply = if inform != 0 {
            Reply::Inform {
                lease_time: None,
                context: None,
                server: Ipv4Addr::new(192, 0, 2, 1),
            }
        } else {
            Reply::Ack {
                address: Ipv4Addr::from(yiaddr),
                lease_time: 600,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
                rapid_commit: false,
            }
        };
        let route = destination(
            &admitted,
            SocketAddr::from((Ipv4Addr::from(peer), port as u16)),
            &reply,
            &bytes,
            bytes.len(),
        )
        .unwrap();
        let std::net::IpAddr::V4(address) = route.address.ip() else {
            unreachable!()
        };
        print!("{} {}", u32::from(address), route.address.port());
        if let Some(arp) = route.arp {
            print!(" {} ", arp.hardware_type);
            for byte in arp.hardware_address {
                print!("{byte:02x}");
            }
            println!();
        } else {
            println!(" - -");
        }
    }
}
