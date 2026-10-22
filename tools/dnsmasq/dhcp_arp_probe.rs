//! Linux-only ARP encoding, runtime retry and isolated send adapter.
use dnsmasq_rs::dhcp::packet::{Packet, COOKIE};
use dnsmasq_rs::dhcp::runtime::{
    self, ArpRequest, DatagramSender, Destination, DestinationKind, RuntimeEvent,
};
use dnsmasq_rs::dhcp::service::{Dispatch, DispatchKind, Ingress, Listener, Route};
use dnsmasq_rs::dhcp::state::{Outcome, Reply};
use dnsmasq_rs::net::{ArpEntry, DatagramSocket};
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

fn hex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert!(text.len().is_multiple_of(2), "hex fixture has an unmatched nibble");
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn main() {
    let input = io::stdin();
    let mut lines = input.lock().lines();
    while let Some(line) = lines.next() {
        let line = line.unwrap();
        let words: Vec<_> = line.split_whitespace().collect();
        match words[0] {
            "B" => {
                let request = ArpEntry::new(
                    SocketAddrV4::new(words[1].parse().unwrap(), words[2].parse().unwrap()),
                    words[3].parse().unwrap(),
                    &hex(words[4]),
                    &hex(words[5]),
                )
                .unwrap();
                for byte in request.bytes() {
                    print!("{byte:02x}");
                }
                println!();
            }
            "T" => {
                struct Sender<'a> {
                    sequence: &'a [u8],
                    fail: bool,
                    preparations: usize,
                    attempts: usize,
                }
                impl DatagramSender for Sender<'_> {
                    fn prepare_destination(&mut self, _: &Destination) -> io::Result<()> {
                        self.preparations += 1;
                        if self.fail {
                            Err(io::Error::from_raw_os_error(1))
                        } else {
                            Ok(())
                        }
                    }
                    fn send(&mut self, _: &[u8], _: &Destination) -> io::Result<()> {
                        let value = self.sequence.get(self.attempts).copied().unwrap_or(b'S');
                        self.attempts += 1;
                        match value {
                            b'W' => Err(io::Error::from_raw_os_error(11)),
                            b'I' => Err(io::Error::from_raw_os_error(4)),
                            b'E' => Err(io::Error::from_raw_os_error(13)),
                            _ => Ok(()),
                        }
                    }
                }
                let mut bytes = vec![0; 240];
                bytes[..3].copy_from_slice(&[1, 1, 6]);
                bytes[236..240].copy_from_slice(&COOKIE);
                bytes.extend_from_slice(&[53, 1, 1, 255]);
                let packet = Packet::parse(&bytes).unwrap();
                let dispatch = Dispatch {
                    packet,
                    ingress: Ingress {
                        listener: Listener::Dhcp,
                        interface_index: 1,
                        unicast_destination: false,
                    },
                    kind: DispatchKind::Dhcp,
                    route: Route::Local,
                };
                let mut sender = Sender {
                    sequence: words[1].as_bytes(),
                    fail: words[2] == "1",
                    preparations: 0,
                    attempts: 0,
                };
                let mut provider = |_: &Dispatch<'_>| {
                    Ok(Outcome {
                        reply: Reply::Offer {
                            address: Ipv4Addr::new(192, 0, 2, 2),
                            lease_time: 600,
                            context: 0,
                            server: Ipv4Addr::new(192, 0, 2, 1),
                        },
                        removed: Vec::new(),
                        lost_names: Vec::new(),
                        newly_allocated: false,
                    })
                };
                let result = runtime::process(
                    dispatch,
                    SocketAddr::from(([0, 0, 0, 0], 68)),
                    &mut provider,
                    &mut sender,
                    &[],
                    &mut [0; 548],
                );
                let (ok, events) = match &result {
                    Ok(report) => (true, &report.events),
                    Err(error) => (false, &error.events),
                };
                let warnings = events
                    .iter()
                    .filter(|event| matches!(event, RuntimeEvent::ArpInjectionFailed { .. }))
                    .count();
                println!(
                    "{} {} {} {}",
                    sender.preparations,
                    sender.attempts,
                    u8::from(ok),
                    warnings
                );
            }
            "S" | "L" => {
                assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
                let address: Ipv4Addr = words[1].parse().unwrap();
                let mut destination = Destination {
                    address: SocketAddr::from((address, words[2].parse::<u16>().unwrap())),
                    interface: words[3].parse().unwrap(),
                    kind: DestinationKind::Client,
                    arp: Some(ArpRequest {
                        address,
                        hardware_type: 1,
                        hardware_address: hex(words[4]),
                        interface_name: None,
                    }),
                };
                let mut socket = DatagramSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap();
                if words[0] == "L" {
                    destination.arp.as_mut().unwrap().interface_name =
                        socket.interface_name(destination.interface).unwrap();
                    println!("snapshot");
                    assert_eq!(lines.next().unwrap().unwrap(), "continue");
                }
                let status = |result: io::Result<()>| match result {
                    Ok(()) => 0,
                    Err(error) => error.raw_os_error().unwrap_or(-1),
                };
                let prepared = status(socket.prepare_destination(&destination));
                let sent = status(DatagramSender::send(
                    &mut socket,
                    b"dhcp-arp-probe",
                    &destination,
                ));
                drop(socket);
                println!("{prepared} {sent}");
            }
            _ => panic!("unknown command"),
        }
    }
}
