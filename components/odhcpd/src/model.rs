//! Shared wire-independent IPv6 and kernel observations. Lifetimes are absolute
//! CLOCK_MONOTONIC seconds; u64::MAX is the kernel's infinite lifetime.
use std::net::Ipv6Addr;

pub const INFINITE: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Prefix {
    pub address: Ipv6Addr,
    pub length: u8,
}

impl Prefix {
    pub fn new(address: Ipv6Addr, length: u8) -> Option<Self> {
        if length > 128 {
            return None;
        }
        let mask = if length == 0 {
            0
        } else {
            u128::MAX << (128 - length)
        };
        Some(Self {
            address: Ipv6Addr::from(u128::from(address) & mask),
            length,
        })
    }

    pub fn contains(self, address: Ipv6Addr) -> bool {
        Self::new(address, self.length) == Some(self)
    }

    pub fn is_ula(self) -> bool {
        self.address.octets()[0] & 0xfe == 0xfc
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Clock {
    pub monotonic_ms: u64,
    pub unix_seconds: i64,
}

impl Clock {
    pub fn seconds(self) -> u64 {
        self.monotonic_ms / 1000
    }
}

pub fn remaining(deadline: u64, now: u64) -> u32 {
    if deadline == INFINITE {
        u32::MAX
    } else {
        deadline.saturating_sub(now).min(u32::MAX as u64) as u32
    }
}

#[derive(Clone, Debug)]
pub struct Address {
    pub address: Ipv6Addr,
    pub length: u8,
    pub preferred_until: u64,
    pub valid_until: u64,
    pub flags: u32,
    pub scope: u8,
}

impl Address {
    pub fn prefix(&self) -> Prefix {
        Prefix::new(self.address, self.length).expect("kernel address prefix validated")
    }

    pub fn usable(&self, now: u64) -> bool {
        // IFA_F_DADFAILED | IFA_F_DEPRECATED | IFA_F_TENTATIVE.
        self.scope == 0
            && self.flags & (0x08 | 0x20 | 0x40) == 0
            && remaining(self.preferred_until, now) != 0
            && remaining(self.valid_until, now) != 0
    }
}

#[derive(Clone, Debug)]
pub struct Link {
    pub name: String,
    pub index: u32,
    pub flags: u32,
    pub mtu: u32,
    pub mac: [u8; 6],
    pub addresses: Vec<Address>,
}

impl Link {
    pub fn running(&self) -> bool {
        self.flags & 0x40 != 0 // IFF_RUNNING
    }

    pub fn link_local(&self) -> Option<Ipv6Addr> {
        self.addresses
            .iter()
            .find(|a| a.address.is_unicast_link_local() && a.flags & (0x08 | 0x40) == 0)
            .map(|a| a.address)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub destination: Prefix,
    pub source: Prefix,
    pub gateway: Option<Ipv6Addr>,
    pub interface: u32,
    pub table: u32,
    pub metric: u32,
    pub kind: u8,
    pub protocol: u8,
}

#[derive(Clone, Debug, Default)]
pub struct KernelState {
    pub links: Vec<Link>,
    pub routes: Vec<Route>,
}

impl KernelState {
    pub fn link(&self, name: &str) -> Option<&Link> {
        self.links.iter().find(|link| link.name == name)
    }
}
