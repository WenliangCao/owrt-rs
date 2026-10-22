//! Opaque DHCPv4 relay forwarding, rfc2131.c:3060-3264.
//!
//! A rule remembers its downstream interface, not client transactions. The
//! owner supplies fresh interface metadata and performs each nonblocking send.

use crate::config::dhcp_relay::RelayRule;
use std::net::{Ipv4Addr, SocketAddrV4};

pub const MAX_DATAGRAM: usize = 65_507;
const FIXED: usize = 236;
const OPTIONS: usize = 240;
const SPLIT_LIMIT: usize = 548;

#[derive(Clone, Debug)]
pub struct RelayInterface {
    pub index: u32,
    pub name: Vec<u8>,
    pub address: Ipv4Addr,
    pub broadcast: Ipv4Addr,
}

#[derive(Clone, Copy, Debug)]
pub struct RelayIngress {
    pub interface: u32,
    /// The primary or listen-address-selected secondary ingress address.
    pub address: Ipv4Addr,
    pub unicast: bool,
}

pub struct RelayForward<'a> {
    pub packet: &'a [u8],
    pub destination: SocketAddrV4,
    pub source: Ipv4Addr,
    pub local: Ipv4Addr,
    pub broadcast_interface: Option<&'a [u8]>,
}

#[derive(Debug, Default)]
pub struct RelayReport {
    pub sent: usize,
    pub failed: usize,
    pub duplicate_addresses: Vec<Ipv4Addr>,
}

struct RuleState {
    rule: RelayRule,
    interface: u32,
    uplink: Ipv4Addr,
    warned: bool,
}

pub struct Relay {
    rules: Vec<RuleState>,
    // Reused owner-local scratch; never retains an attacker-controlled queue.
    scratch: Vec<u8>,
}

impl Relay {
    /// Rules arrive in C's reverse configuration order.
    pub fn new(rules: &[RelayRule]) -> Self {
        Self {
            rules: rules
                .iter()
                .cloned()
                .map(|rule| RuleState {
                    uplink: rule.uplink,
                    rule,
                    interface: 0,
                    warned: false,
                })
                .collect(),
            scratch: vec![0; MAX_DATAGRAM],
        }
    }

    pub fn invalidate_interfaces(&mut self) {
        for state in &mut self.rules {
            state.interface = 0;
        }
    }

    /// Process an admitted request before the local DHCP allocator. Unlike a
    /// local request parser, C forwards opaque BOOTP bytes and does not require
    /// valid hardware fields, cookie or DHCP options here. The original bytes
    /// remain untouched for the caller's subsequent local server processing.
    pub fn upstream(
        &mut self,
        bytes: &[u8],
        ingress: RelayIngress,
        interfaces: &[RelayInterface],
        mut send: impl FnMut(RelayForward<'_>) -> bool,
    ) -> RelayReport {
        let mut report = RelayReport::default();
        if bytes.len() < FIXED || bytes.len() > MAX_DATAGRAM {
            return report;
        }
        // complete_context happens before relay_upstream4's op/hop guard.
        for state in &mut self.rules {
            if state.rule.split {
                continue;
            }
            let mut count = 0;
            for interface in interfaces {
                if interface.address == state.rule.local {
                    count += 1;
                    if interface.index == ingress.interface {
                        state.interface = interface.index;
                    }
                }
            }
            if count > 1 && !state.warned {
                state.warned = true;
                report.duplicate_addresses.push(state.rule.local);
            }
        }
        if bytes[0] != 1 || bytes[3] > 20 {
            return report;
        }
        let packet = &mut self.scratch;
        packet[..bytes.len()].copy_from_slice(bytes);
        packet[3] = bytes[3] + 1;
        let giaddr = ip(bytes, 24);
        let mut split_end = None;
        for state in &mut self.rules {
            let rule = &state.rule;
            packet[24..28].copy_from_slice(&giaddr.octets());
            if let Some(end) = split_end {
                packet[end] = 255;
            }
            let mut length = bytes.len();
            let source =
                if !rule.split && state.interface != 0 && state.interface == ingress.interface {
                    if giaddr == rule.local {
                        continue;
                    }
                    if giaddr.is_unspecified() {
                        packet[24..28].copy_from_slice(&rule.local.octets());
                    }
                    rule.local
                } else if rule.split && rule.local == ingress.address {
                    if let Some(name) = &rule.interface {
                        let Some(uplink) = named_interface(interfaces, name) else {
                            continue;
                        };
                        state.uplink = uplink.address;
                    }
                    if !giaddr.is_unspecified() && giaddr == state.uplink {
                        continue;
                    }
                    if giaddr.is_unspecified() {
                        packet[24..28].copy_from_slice(&state.uplink.octets());
                        let end = match split_end {
                            Some(end) => end,
                            None => {
                                let Some(end) = find_option(packet, OPTIONS, bytes.len(), 255, 0)
                                else {
                                    continue;
                                };
                                if end + 24 > SPLIT_LIMIT {
                                    continue;
                                }
                                split_end = Some(end);
                                packet[end..end + 24].copy_from_slice(&[
                                    82, 21, 5, 4, 0, 0, 0, 0, 11, 4, 0, 0, 0, 0, 10, 1, 0, 2, 4, 0,
                                    0, 0, 0, 255,
                                ]);
                                // C resets length for every rule but recomputes
                                // this appended length only on the first split.
                                length = end + 24;
                                end
                            }
                        };
                        packet[end] = 82;
                        packet[end + 4..end + 8].copy_from_slice(&rule.local.octets());
                        packet[end + 10..end + 14].copy_from_slice(&rule.local.octets());
                        packet[end + 16] = if ingress.unicast { 0x80 } else { 0 };
                        packet[end + 19..end + 23]
                            .copy_from_slice(&ingress.interface.to_be_bytes());
                    }
                    state.uplink
                } else {
                    continue;
                };
            let destination = if rule.server.is_unspecified() {
                let Some(interface) = rule
                    .interface
                    .as_ref()
                    .and_then(|name| named_interface(interfaces, name))
                else {
                    // C has no initialized ifreq for a zero server without
                    // an interface. Never reproduce uninitialized memory.
                    continue;
                };
                interface.broadcast
            } else {
                rule.server
            };
            if send(RelayForward {
                packet: &packet[..length],
                destination: SocketAddrV4::new(destination, rule.port),
                source,
                local: rule.local,
                broadcast_interface: rule
                    .server
                    .is_unspecified()
                    .then_some(rule.interface.as_deref())
                    .flatten(),
            }) {
                report.sent += 1;
            } else {
                report.failed += 1;
            }
        }
        report
    }

    /// Runs before request interface admission or local Packet::parse. The
    /// caller validates that the selected return interface still exists and
    /// uses the raw reply's ciaddr/flags/yiaddr for its final destination.
    pub fn reply(&mut self, bytes: &mut [u8], arrival_interface: &[u8]) -> Option<u32> {
        if bytes.len() < FIXED || bytes[0] != 2 || ip(bytes, 24).is_unspecified() {
            return None;
        }
        let giaddr = ip(bytes, 24);
        for state in &self.rules {
            let mut index = 0;
            if state.rule.split {
                if giaddr == state.uplink {
                    if let Some(agent) = packet_option(bytes, 82, 1) {
                        let length = usize::from(bytes[agent + 1]);
                        if let Some(remote) =
                            find_option(bytes, agent + 2, agent + 2 + length, 2, 4)
                        {
                            index = u32::from_be_bytes(
                                bytes[remote + 2..remote + 6].try_into().unwrap(),
                            );
                        }
                        // C strips before checking the interface predicate,
                        // even when remote-id is absent or unusable.
                        bytes[agent] = 255;
                        bytes[agent + 1..agent + 2 + length].fill(0);
                    }
                }
            } else if giaddr == state.rule.local {
                index = state.interface;
            }
            if index != 0
                && state
                    .rule
                    .interface
                    .as_ref()
                    .is_none_or(|pattern| matches_name(pattern, arrival_interface))
            {
                return Some(index);
            }
        }
        None
    }
}

fn named_interface<'a>(
    interfaces: &'a [RelayInterface],
    name: &[u8],
) -> Option<&'a RelayInterface> {
    // safe_strncpy(ifr_name, ..., IF_NAMESIZE) retains at most 15 bytes.
    let name = &name[..name.len().min(15)];
    interfaces.iter().find(|interface| interface.name == name)
}

fn matches_name(pattern: &[u8], name: &[u8]) -> bool {
    super::interface_admission::interface_matches(pattern, name)
}

fn ip(bytes: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    )
}

fn find_option(
    bytes: &[u8],
    mut at: usize,
    end: usize,
    wanted: u8,
    minimum: usize,
) -> Option<usize> {
    let end = end.min(bytes.len());
    while at < end {
        match bytes[at] {
            255 => return (wanted == 255).then_some(at),
            0 => at += 1,
            code => {
                if at + 2 > end {
                    return None;
                }
                let length = usize::from(bytes[at + 1]);
                if at + 2 + length > end {
                    return None;
                }
                if code == wanted && length >= minimum {
                    return Some(at);
                }
                at += 2 + length;
            }
        }
    }
    None
}

fn packet_option(bytes: &[u8], wanted: u8, minimum: usize) -> Option<usize> {
    if let Some(found) = find_option(bytes, OPTIONS, bytes.len(), wanted, minimum) {
        return Some(found);
    }
    let overload = find_option(bytes, OPTIONS, bytes.len(), 52, 1)?;
    if bytes[overload + 2] & 1 != 0 {
        if let Some(found) = find_option(bytes, 108, 236, wanted, minimum) {
            return Some(found);
        }
    }
    if bytes[overload + 2] & 2 != 0 {
        return find_option(bytes, 44, 108, wanted, minimum);
    }
    None
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use linux::RelayService;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod linux {
    use super::*;
    use crate::dhcp::interface_admission::{interface_matches, InterfacePolicy, Selection};
    use crate::net::{Datagram, DatagramSocket};
    use std::io;
    use std::net::{IpAddr, SocketAddr, UdpSocket};

    pub struct RelayService {
        relay: Relay,
        policy: InterfacePolicy,
        excluded: Vec<Option<Vec<u8>>>,
        client_port: u16,
        control: UdpSocket,
        network: crate::config::dhcp_network::NetworkConfig,
        notices: Vec<crate::logging::LogEvent>,
        log_options: bool,
        dump: crate::dump::DumpHandle,
    }

    impl RelayService {
        pub fn new(
            rules: &[RelayRule],
            dns: &crate::config::dns::DnsConfig,
            excluded: &[Option<Vec<u8>>],
            client_port: u16,
            network: &crate::config::dhcp_network::NetworkConfig,
        ) -> io::Result<Self> {
            Ok(Self {
                relay: Relay::new(rules),
                policy: InterfacePolicy::from_dns(dns),
                excluded: excluded.to_vec(),
                client_port,
                control: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
                network: network.clone(),
                notices: Vec::new(),
                log_options: false,
                dump: crate::dump::DumpHandle::default(),
            })
        }

        pub fn invalidate_interfaces(&mut self) {
            self.relay.invalidate_interfaces();
        }

        pub fn take_notices(&mut self) -> Vec<crate::logging::LogEvent> {
            std::mem::take(&mut self.notices)
        }

        pub fn set_logging(&mut self, enabled: bool) {
            self.log_options = enabled;
        }

        pub fn set_dump(&mut self, dump: crate::dump::DumpHandle) {
            self.dump = dump;
        }

        /// True consumes a reply or admission failure. False allows the owner
        /// to pass the original request to an optional local DHCP provider.
        pub fn intercept(
            &mut self,
            socket: &DatagramSocket,
            reply_socket: &DatagramSocket,
            pxe: bool,
            bytes: &mut [u8],
            datagram: &Datagram,
        ) -> io::Result<bool> {
            if bytes.len() < FIXED {
                return Ok(true);
            }
            let Ok(name) = crate::net::interface_name(socket, datagram.interface) else {
                return Ok(true);
            };
            let name = &name[..name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len())];
            let bridge = match self.network.bridge_ingress(name) {
                Ok(bridge) => bridge,
                Err(message) => {
                    self.notices.push(crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Warning,
                        message,
                    ));
                    return Ok(true);
                }
            };
            let mut effective_datagram = *datagram;
            let name = if let Some((index, master)) = &bridge {
                effective_datagram.interface = *index;
                master.as_slice()
            } else {
                name
            };
            let datagram = &effective_datagram;
            let all_ones = ip(bytes, 24) == Ipv4Addr::BROADCAST;
            if all_ones {
                bytes[24..28].fill(0);
            }
            let result =
                self.intercept_normalized(socket, reply_socket, pxe, bytes, datagram, name);
            if all_ones {
                bytes[24..28].fill(255);
            }
            result
        }

        fn intercept_normalized(
            &mut self,
            socket: &DatagramSocket,
            reply_socket: &DatagramSocket,
            pxe: bool,
            bytes: &mut [u8],
            datagram: &Datagram,
            name: &[u8],
        ) -> io::Result<bool> {
            if let Some(index) = self.relay.reply(bytes, name) {
                if let Ok(name) = crate::net::interface_name(socket, index) {
                    let result = if pxe {
                        let ciaddr = ip(bytes, 12);
                        let destination = if ciaddr.is_unspecified() {
                            datagram.peer
                        } else {
                            SocketAddr::from((ciaddr, datagram.peer.port()))
                        };
                        if let Ok(source) = reply_socket.local_addr() {
                            self.dump.udp(crate::dump::DHCP, bytes, source, destination);
                        }
                        reply_socket.send_once(bytes, destination, None)
                    } else {
                        send_reply(
                            reply_socket,
                            bytes,
                            index,
                            &name,
                            self.client_port,
                            &self.dump,
                        )
                    };
                    if let Err(error) = result {
                        eprintln!("dnsmasq-rs: DHCP relay reply send: {error}");
                    }
                }
                return Ok(true);
            }
            if self
                .excluded
                .iter()
                .flatten()
                .any(|pattern| interface_matches(pattern, name))
            {
                return Ok(true);
            }
            let Ok(primary) = crate::interfaces::primary_ipv4(datagram.interface, &self.control)
            else {
                return Ok(true);
            };
            let snapshot = crate::interfaces::ipv4_interfaces()?;
            let address =
                match self
                    .policy
                    .select(Some(name), datagram.interface, primary, &snapshot)
                {
                    Some(Selection::Primary) => primary,
                    Some(Selection::Secondary(interface)) => interface.address,
                    None => return Ok(true),
                };
            let interfaces: Vec<_> = snapshot
                .iter()
                .filter_map(|interface| {
                    let name = crate::net::interface_name(socket, interface.index).ok()?;
                    let end = name
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(name.len());
                    Some(RelayInterface {
                        index: interface.index,
                        name: name[..end].to_vec(),
                        address: interface.address,
                        broadcast: interface.broadcast,
                    })
                })
                .collect();
            let report = self.relay.upstream(
                bytes,
                RelayIngress {
                    interface: datagram.interface,
                    address,
                    unicast: datagram.destination != IpAddr::V4(Ipv4Addr::BROADCAST),
                },
                &interfaces,
                |forward| {
                    self.dump.udp(
                        crate::dump::DHCP,
                        forward.packet,
                        SocketAddr::from((
                            forward.source,
                            socket.local_addr().map_or(67, |address| address.port()),
                        )),
                        SocketAddr::V4(forward.destination),
                    );
                    let sent = match socket.send_once(
                        forward.packet,
                        SocketAddr::V4(forward.destination),
                        Some((IpAddr::V4(forward.source), 0)),
                    ) {
                        Ok(()) => true,
                        Err(error) => {
                            eprintln!("dnsmasq-rs: DHCP relay upstream send: {error}");
                            false
                        }
                    };
                    if self.log_options {
                        let destination = if let Some(interface) = forward.broadcast_interface {
                            format!("broadcast via {}", String::from_utf8_lossy(interface))
                        } else {
                            forward.destination.ip().to_string()
                        };
                        self.notices.push(crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Info,
                            format!("DHCP relay at {} -> {destination}", forward.local)
                                .into_bytes(),
                        ));
                    }
                    sent
                },
            );
            for address in report.duplicate_addresses {
                eprintln!(
                    "dnsmasq-rs: DHCP relay address {address} appears on more than one interface"
                );
            }
            // rfc2131.c:3067 post-increments before the hop-limit return,
            // which bypasses the normal restore at the end of the function.
            // The exact image echoes 21 as 22 and 255 as 0 in a subsequent
            // local BOOTP reply, even though neither request is forwarded.
            if bytes[0] == 1 && bytes[3] > 20 {
                bytes[3] = bytes[3].wrapping_add(1);
            }
            Ok(false)
        }
    }

    fn send_reply(
        socket: &DatagramSocket,
        bytes: &[u8],
        interface: u32,
        name: &[u8; 16],
        port: u16,
        dump: &crate::dump::DumpHandle,
    ) -> io::Result<()> {
        let ciaddr = ip(bytes, 12);
        if !ciaddr.is_unspecified() {
            // dhcp.c's ciaddr branch has no outbound pktinfo cmsg.
            let destination = SocketAddr::from((ciaddr, port));
            if let Ok(source) = socket.local_addr() {
                dump.udp(crate::dump::DHCP, bytes, source, destination);
            }
            return socket.send_once(bytes, destination, None);
        }
        let htype = bytes[1];
        let hlen = usize::from(bytes[2]);
        let broadcast = bytes[10] & 0x80 != 0 || hlen == 0 || hlen > 14 || htype == 0;
        let destination = SocketAddr::V4(SocketAddrV4::new(
            if broadcast {
                Ipv4Addr::BROADCAST
            } else {
                ip(bytes, 16)
            },
            port,
        ));
        if !broadcast {
            if let SocketAddr::V4(address) = destination {
                if let Err(error) = crate::net::inject_arp_with_name(
                    socket,
                    address,
                    htype,
                    &bytes[28..28 + hlen],
                    name,
                ) {
                    eprintln!("dnsmasq-rs: DHCP ARP injection: {error}");
                }
            }
        }
        if let Ok(source) = socket.local_addr() {
            dump.udp(crate::dump::DHCP, bytes, source, destination);
        }
        socket.send_on_interface_once(bytes, destination, interface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EncodedArg;

    fn rule(value: &str, split: bool) -> RelayRule {
        RelayRule::parse(&EncodedArg::command_line(value.as_bytes()), split).unwrap()
    }
    fn interfaces() -> Vec<RelayInterface> {
        [
            (3, "lan", "192.0.2.1", "192.0.2.255"),
            (4, "wan", "198.51.100.1", "198.51.100.255"),
        ]
        .map(|(index, name, address, broadcast)| RelayInterface {
            index,
            name: name.as_bytes().to_vec(),
            address: address.parse().unwrap(),
            broadcast: broadcast.parse().unwrap(),
        })
        .to_vec()
    }
    fn ingress() -> RelayIngress {
        RelayIngress {
            interface: 3,
            address: "192.0.2.1".parse().unwrap(),
            unicast: true,
        }
    }
    fn packet() -> Vec<u8> {
        let mut bytes = vec![0; 244];
        bytes[..4].copy_from_slice(&[1, 1, 6, 0]);
        bytes[236..].copy_from_slice(&[99, 130, 83, 99, 53, 1, 1, 255]);
        bytes
    }
    fn forwards(relay: &mut Relay, bytes: &[u8]) -> Vec<(Vec<u8>, SocketAddrV4, Ipv4Addr)> {
        let mut rows = Vec::new();
        relay.upstream(bytes, ingress(), &interfaces(), |forward| {
            rows.push((forward.packet.to_vec(), forward.destination, forward.source));
            true
        });
        rows
    }

    #[test]
    fn opaque_forward_and_cached_reply_have_no_xid_state() {
        let mut relay = Relay::new(&[rule("192.0.2.1,198.51.100.2", false)]);
        let mut reply = packet();
        reply[0] = 2;
        reply[24..28].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(relay.reply(&mut reply, b"wan"), None);
        let original = packet();
        let rows = forwards(&mut relay, &original);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0[3], 1);
        assert_eq!(&rows[0].0[24..28], &[192, 0, 2, 1]);
        assert_eq!(rows[0].1.port(), 67);
        assert_eq!(original, packet());
        assert_eq!(relay.reply(&mut reply, b"wan"), Some(3));
        relay.invalidate_interfaces();
        assert_eq!(relay.reply(&mut reply, b"wan"), None);
        let mut opaque = vec![0xab; 16385];
        opaque[0] = 1;
        opaque[3] = 20;
        opaque[24..28].fill(0);
        assert_eq!(forwards(&mut relay, &opaque)[0].0.len(), 16385);
        opaque[3] = 21;
        assert!(forwards(&mut relay, &opaque).is_empty());
    }

    #[test]
    fn loop_and_failure_do_not_suppress_other_rules() {
        let mut relay = Relay::new(&[
            rule("192.0.2.1,198.51.100.2", false),
            rule("192.0.2.1,198.51.100.3", false),
        ]);
        let mut count = 0;
        let report = relay.upstream(&packet(), ingress(), &interfaces(), |_| {
            count += 1;
            count != 1
        });
        assert_eq!((report.sent, report.failed, count), (1, 1, 2));
        let mut bytes = packet();
        bytes[24..28].copy_from_slice(&[192, 0, 2, 1]);
        assert!(forwards(&mut relay, &bytes).is_empty());
    }

    #[test]
    fn split_exact_option_and_strip_without_length_change() {
        let mut relay = Relay::new(&[rule("192.0.2.1,198.51.100.2,wan", true)]);
        let rows = forwards(&mut relay, &packet());
        let mut reply = rows[0].0.clone();
        assert_eq!(reply.len(), 267);
        assert_eq!(
            &reply[243..],
            &[82, 21, 5, 4, 192, 0, 2, 1, 11, 4, 192, 0, 2, 1, 10, 1, 128, 2, 4, 0, 0, 0, 3, 255]
        );
        reply[0] = 2;
        assert_eq!(relay.reply(&mut reply, b"wan"), Some(3));
        assert_eq!(reply.len(), 267);
        assert_eq!(reply[243], 255);
        assert!(reply[244..266].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn split_append_cap_and_second_rule_c_length() {
        let rules = [
            rule("192.0.2.1,198.51.100.2,wan", true),
            rule("192.0.2.1,198.51.100.3,wan", true),
        ];
        let mut relay = Relay::new(&rules);
        let rows = forwards(&mut relay, &packet());
        assert_eq!((rows[0].0.len(), rows[1].0.len()), (267, 244));
        for (end, accepted) in [(524, true), (525, false)] {
            let mut bytes = packet();
            bytes[243] = 0;
            bytes.resize(end + 1, 0);
            bytes[end] = 255;
            assert_eq!(!forwards(&mut relay, &bytes).is_empty(), accepted);
        }
    }

    #[test]
    fn split_reply_overload_and_minimum_remote_id_length() {
        let mut relay = Relay::new(&[rule("192.0.2.1,198.51.100.2,198.51.100.1", true)]);
        let mut bytes = packet();
        bytes[0] = 2;
        bytes[24..28].copy_from_slice(&[198, 51, 100, 1]);
        bytes[240..].copy_from_slice(&[52, 1, 1, 255]);
        bytes[108..119].copy_from_slice(&[82, 8, 2, 6, 0, 0, 0, 3, 9, 9, 255]);
        assert_eq!(relay.reply(&mut bytes, b"other"), Some(3));
        assert_eq!(bytes[108], 255);
        assert!(bytes[109..118].iter().all(|byte| *byte == 0));
    }
}
