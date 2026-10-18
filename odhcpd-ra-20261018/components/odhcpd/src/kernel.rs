//! Kernel observations and acknowledged DHCPv6-PD routes. No link/address
//! configuration or NDP proxy is performed by this daemon.
use crate::model::{Address, Clock, KernelState, Link, Prefix, Route, INFINITE};
use owrt_netifd::netlink::{self as nl, Attrs, Msg, Netlink};
use std::io;
use std::net::Ipv6Addr;

const NEW_LINK: u16 = 16;
const GET_LINK: u16 = 18;
const NEW_ADDRESS: u16 = 20;
const GET_ADDRESS: u16 = 22;
const NEW_ROUTE: u16 = 24;
const DELETE_ROUTE: u16 = 25;
const GET_ROUTE: u16 = 26;

pub struct Kernel {
    commands: Netlink,
    events: Netlink,
}

impl Kernel {
    pub fn open() -> io::Result<Self> {
        let commands = Netlink::open(0)?;
        let events = Netlink::open(nl::grp(1) | nl::grp(9) | nl::grp(11))?;
        events.set_nonblocking()?;
        Ok(Self { commands, events })
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.events.as_raw_fd()
    }

    /// A missing/overflowed event means resynchronise; it never means that
    /// the previous address set is still valid.
    pub fn changed(&mut self) -> io::Result<bool> {
        let mut changed = false;
        // Bound one drain so packet service is not starved by an event storm.
        for _ in 0..32 {
            match self.events.recv_events() {
                Ok(messages) if messages.is_empty() => break,
                Ok(_) => changed = true,
                Err(error) if error.raw_os_error() == Some(nl::ENOBUFS) => {
                    let _ = self.events.grow_event_buffer();
                    changed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(changed)
    }

    pub fn snapshot(&mut self, clock: Clock) -> io::Result<KernelState> {
        let links = self.commands.dump(GET_LINK, &[0; 16])?;
        let mut addr_header = [0; 8];
        addr_header[0] = 10;
        let addresses = self.commands.dump(GET_ADDRESS, &addr_header)?;
        let mut route_header = [0; 12];
        route_header[0] = 10;
        let routes = self.commands.dump(GET_ROUTE, &route_header)?;
        let mut state = KernelState {
            links: links.iter().filter_map(parse_link).collect(),
            routes: routes.iter().filter_map(parse_route).collect(),
        };
        for message in &addresses {
            if let Some((index, address)) = parse_address(message, clock.seconds()) {
                if let Some(link) = state.links.iter_mut().find(|link| link.index == index) {
                    link.addresses.push(address);
                }
            }
        }
        Ok(state)
    }

    /// The caller owns the successful-install ledger. A failed add remains
    /// an error; an already absent route/device makes deletion idempotent.
    pub fn route(&mut self, route: &Route, add: bool) -> io::Result<()> {
        if route.destination.length > 128 || route.source.length > 128 || route.interface == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid PD route",
            ));
        }
        let mut header = [0; 12];
        header[0] = 10;
        header[1] = route.destination.length;
        header[2] = route.source.length;
        header[4] = u8::try_from(route.table).unwrap_or(0);
        header[5] = route.protocol;
        header[7] = route.kind;
        let mut attributes = Attrs::new();
        attributes.bytes(1, &route.destination.address.octets());
        if route.source.length != 0 {
            attributes.bytes(2, &route.source.address.octets());
        }
        attributes.u32(4, route.interface);
        if let Some(gateway) = route.gateway {
            attributes.bytes(5, &gateway.octets());
        }
        attributes.u32(6, route.metric);
        if route.table > 255 {
            attributes.u32(15, route.table);
        }
        let result = self.commands.request(
            if add { NEW_ROUTE } else { DELETE_ROUTE },
            if add {
                nl::NLM_F_CREATE | nl::NLM_F_REPLACE
            } else {
                0
            },
            &header,
            attributes.as_bytes(),
        );
        match result {
            Err(error) if !add && matches!(error.raw_os_error(), Some(2 | 3 | 19)) => Ok(()),
            result => result,
        }
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn ipv6(bytes: &[u8]) -> Option<Ipv6Addr> {
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(..16)?).ok()?))
}

fn parse_link(message: &Msg) -> Option<Link> {
    if message.ty != NEW_LINK || message.payload.len() < 16 {
        return None;
    }
    let attrs = message.attrs(16);
    let index = u32_at(&message.payload, 4)?;
    if index == 0 || index > i32::MAX as u32 {
        return None;
    }
    let mut mac = [0; 6];
    if let Some(bytes) = nl::attr(&attrs, 1).filter(|bytes| bytes.len() == 6) {
        mac.copy_from_slice(bytes);
    }
    Some(Link {
        name: nl::attr_str(&attrs, 3)?.to_owned(),
        index,
        flags: u32_at(&message.payload, 8)?,
        mtu: nl::attr_u32(&attrs, 4).unwrap_or(1280),
        mac,
        addresses: Vec::new(),
    })
}

fn deadline(relative: u32, now: u64) -> u64 {
    if relative == u32::MAX {
        INFINITE
    } else {
        now.saturating_add(relative as u64)
    }
}

fn parse_address(message: &Msg, now: u64) -> Option<(u32, Address)> {
    let header = &message.payload;
    if message.ty != NEW_ADDRESS || header.len() < 8 || header[0] != 10 || header[1] > 128 {
        return None;
    }
    let attrs = message.attrs(8);
    let address = ipv6(nl::attr(&attrs, 1).or_else(|| nl::attr(&attrs, 2))?)?;
    let cache = nl::attr(&attrs, 6);
    let preferred = cache.and_then(|bytes| u32_at(bytes, 0)).unwrap_or(u32::MAX);
    let valid = cache.and_then(|bytes| u32_at(bytes, 4)).unwrap_or(u32::MAX);
    let flags = nl::attr_u32(&attrs, 8).unwrap_or(header[2] as u32);
    Some((
        u32_at(header, 4)?,
        Address {
            address,
            length: header[1],
            preferred_until: deadline(
                if flags & 0x20 != 0 {
                    0
                } else {
                    preferred.min(valid)
                },
                now,
            ),
            valid_until: deadline(valid, now),
            flags,
            scope: header[3],
        },
    ))
}

fn parse_route(message: &Msg) -> Option<Route> {
    let header = &message.payload;
    if message.ty != NEW_ROUTE || header.len() < 12 || header[0] != 10 {
        return None;
    }
    let attrs = message.attrs(12);
    let destination = nl::attr(&attrs, 1)
        .and_then(ipv6)
        .unwrap_or(Ipv6Addr::UNSPECIFIED);
    let source = nl::attr(&attrs, 2)
        .and_then(ipv6)
        .unwrap_or(Ipv6Addr::UNSPECIFIED);
    Some(Route {
        destination: Prefix::new(destination, header[1])?,
        source: Prefix::new(source, header[2])?,
        gateway: nl::attr(&attrs, 5).and_then(ipv6),
        interface: nl::attr_u32(&attrs, 4).unwrap_or(0),
        table: nl::attr_u32(&attrs, 15).unwrap_or(header[4] as u32),
        metric: nl::attr_u32(&attrs, 6).unwrap_or(0),
        kind: header[7],
        protocol: header[5],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_lifetimes_flags_and_non_64_prefix_survive_dump() {
        let mut header = vec![10, 60, 0, 0, 5, 0, 0, 0];
        let mut attrs = Attrs::new();
        attrs.bytes(1, &"fd00:1::1".parse::<Ipv6Addr>().unwrap().octets());
        let mut cache = Vec::new();
        for value in [0u32, 90, 1, 2] {
            cache.extend_from_slice(&value.to_ne_bytes());
        }
        attrs.bytes(6, &cache).u32(8, 0x20);
        header.extend_from_slice(attrs.as_bytes());
        let (index, address) = parse_address(
            &Msg {
                ty: NEW_ADDRESS,
                flags: 0,
                seq: 1,
                payload: header,
            },
            200,
        )
        .unwrap();
        assert_eq!((index, address.length), (5, 60));
        assert_eq!((address.preferred_until, address.valid_until), (200, 290));
        assert!(!address.usable(200));
        assert_eq!(
            address.prefix().address,
            "fd00:1::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn source_specific_default_remains_scoped_to_its_source_prefix() {
        let mut header = vec![10, 0, 64, 0, 254, 16, 0, 1, 0, 0, 0, 0];
        let mut attrs = Attrs::new();
        attrs
            .bytes(2, &"2001:db8:1::".parse::<Ipv6Addr>().unwrap().octets())
            .u32(4, 7)
            .u32(6, 512);
        header.extend_from_slice(attrs.as_bytes());
        let route = parse_route(&Msg {
            ty: NEW_ROUTE,
            flags: 0,
            seq: 1,
            payload: header,
        })
        .unwrap();
        assert_eq!(route.destination.length, 0);
        assert_eq!(route.source.length, 64);
        assert_eq!((route.interface, route.metric, route.kind), (7, 512, 1));
    }
}
