//! The kernel-facing operations netifd performs: links, bridges, addresses,
//! routes and the per-device sysctls.
//!
//! Attribute sets and header fields follow `system-linux.c` exactly, including
//! the parts that look arbitrary — `RTM_NEWADDR` carrying `NLM_F_REPLACE`, a
//! route's scope depending on whether a gateway is present, `IFA_CACHEINFO`
//! being written for IPv6 only. Those are observable in the resulting kernel
//! state, so they are reproduced rather than tidied.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use crate::netlink::{self, Attrs, Netlink};

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const FRA_SRC: u16 = 2;
pub const FRA_IIFNAME: u16 = 3;
pub const FRA_PRIORITY: u16 = 6;
pub const FR_ACT_UNREACHABLE: u8 = 7;

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_MASTER: u16 = 10;
pub const IFLA_TXQLEN: u16 = 13;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_STATS64: u16 = 23;

pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;

pub const IFLA_BR_FORWARD_DELAY: u16 = 1;
pub const IFLA_BR_HELLO_TIME: u16 = 2;
pub const IFLA_BR_MAX_AGE: u16 = 3;
pub const IFLA_BR_AGEING_TIME: u16 = 4;
pub const IFLA_BR_STP_STATE: u16 = 5;
pub const IFLA_BR_PRIORITY: u16 = 6;
pub const IFLA_BR_VLAN_FILTERING: u16 = 7;
pub const IFLA_BR_MCAST_SNOOPING: u16 = 23;
pub const IFLA_BR_MCAST_QUERIER: u16 = 25;
pub const IFLA_BR_MCAST_HASH_MAX: u16 = 27;

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_BROADCAST: u16 = 4;
pub const IFA_CACHEINFO: u16 = 6;
pub const IFA_FLAGS: u16 = 8;

pub const IFA_F_NOPREFIXROUTE: u32 = 0x200;

pub const RTA_DST: u16 = 1;
pub const RTA_SRC: u16 = 2;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_METRICS: u16 = 8;
pub const RTA_TABLE: u16 = 15;
pub const RTAX_MTU: u16 = 2;

pub const RT_TABLE_UNSPEC: u8 = 0;
pub const RT_TABLE_MAIN: u32 = 254;
pub const RT_TABLE_LOCAL: u8 = 255;

pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_HOST: u8 = 254;
pub const RT_SCOPE_NOWHERE: u8 = 255;

pub const RTN_UNICAST: u8 = 1;
pub const RTN_LOCAL: u8 = 2;
pub const RTN_BROADCAST: u8 = 3;
pub const RTN_ANYCAST: u8 = 4;
pub const RTN_MULTICAST: u8 = 5;
pub const RTN_BLACKHOLE: u8 = 6;
pub const RTN_UNREACHABLE: u8 = 7;
pub const RTN_PROHIBIT: u8 = 8;
pub const RTN_THROW: u8 = 9;
pub const RTN_NAT: u8 = 10;
pub const RTN_FAILED_POLICY: u8 = 12;
pub const RTPROT_KERNEL: u8 = 2;
pub const RTPROT_STATIC: u8 = 4;
pub const RTNH_F_ONLINK: u32 = 4;
pub const RTM_F_CLONED: u32 = 0x200;
pub const NUD_PERMANENT: u16 = 0x80;
pub const NDA_DST: u16 = 1;
pub const NDA_LLADDR: u16 = 2;
pub const NTF_ROUTER: u8 = 0x80;
pub const NTF_PROXY: u8 = 0x08;

pub const SIOCGIFFLAGS: u64 = 0x8913;
pub const SIOCGIFMTU: u64 = 0x8921;
pub const SIOCGIFHWADDR: u64 = 0x8927;
pub const SIOCGIFTXQLEN: u64 = 0x8942;

pub const IFF_UP: u32 = 0x1;
pub const IFF_PROMISC: u32 = 0x100;
pub const IFF_MULTICAST: u32 = 0x1000;
pub const IFF_LOWER_UP: u32 = 0x10000;

/// `struct ifinfomsg` — 16 bytes.
pub fn ifinfomsg(family: u8, index: i32, flags: u32, change: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = family;
    b[4..8].copy_from_slice(&index.to_le_bytes());
    b[8..12].copy_from_slice(&flags.to_le_bytes());
    b[12..16].copy_from_slice(&change.to_le_bytes());
    b
}

/// `struct ifaddrmsg` — 8 bytes.
pub fn ifaddrmsg(family: u8, prefixlen: u8, flags: u8, scope: u8, index: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = family;
    b[1] = prefixlen;
    b[2] = flags;
    b[3] = scope;
    b[4..8].copy_from_slice(&index.to_le_bytes());
    b
}

/// `struct rtmsg` — 12 bytes.
#[allow(clippy::too_many_arguments)]
pub fn rtmsg(
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    ty: u8,
    flags: u32,
) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = family;
    b[1] = dst_len;
    b[2] = src_len;
    b[3] = tos;
    b[4] = table;
    b[5] = protocol;
    b[6] = scope;
    b[7] = ty;
    b[8..12].copy_from_slice(&flags.to_le_bytes());
    b
}

/// `struct ndmsg` — 12 bytes.
pub fn ndmsg(family: u8, index: u32, flags: u8) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = family;
    b[4..8].copy_from_slice(&index.to_le_bytes());
    b[10] = flags;
    b
}

/// `check_ifaddr`: the address is on this device.
fn check_ifaddr(payload: &[u8], index: u32) -> bool {
    payload.len() >= 8 && u32::from_le_bytes(payload[4..8].try_into().unwrap()) == index
}

/// `check_route`: on this device, and never an IPv6 route the kernel owns.
fn check_route(payload: &[u8], index: u32) -> bool {
    if payload.len() < 12 {
        return false;
    }
    if payload[5] == RTPROT_KERNEL && payload[0] == AF_INET6 {
        return false;
    }
    netlink::parse_attrs(&payload[12..])
        .into_iter()
        .find(|(t, _)| *t == RTA_OIF)
        .and_then(|(_, v)| {
            v.get(..4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        })
        == Some(index)
}

/// `check_neigh`: on this device, and only entries netifd could have
/// installed itself.
fn check_neigh(payload: &[u8], index: u32) -> bool {
    if payload.len() < 12 {
        return false;
    }
    if u32::from_le_bytes(payload[4..8].try_into().unwrap()) != index {
        return false;
    }
    let state = u16::from_le_bytes(payload[8..10].try_into().unwrap());
    state & NUD_PERMANENT != 0 || payload[10] & NTF_PROXY != 0
}

/// `struct ifa_cacheinfo` — 16 bytes; only the two lifetimes are written.
pub fn ifa_cacheinfo(preferred: u32, valid: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&preferred.to_le_bytes());
    b[4..8].copy_from_slice(&valid.to_le_bytes());
    b
}

fn addr_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

fn family_of(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

fn is_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_unspecified(),
        IpAddr::V6(v) => v.is_unspecified(),
    }
}

/// An address to put on a device. `preferred`/`valid` are absolute seconds
/// remaining, already clamped by the caller; IPv4 ignores them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub ip: IpAddr,
    pub mask: u8,
    pub broadcast: Option<Ipv4Addr>,
    pub point_to_point: Option<Ipv4Addr>,
    pub preferred: Option<u32>,
    pub valid: Option<u32>,
    /// `IFA_F_NOPREFIXROUTE`: the prefix route is managed by netifd, not the
    /// kernel. Only meaningful for IPv6 on add, as in `system_addr`.
    pub offlink: bool,
}

impl Address {
    /// `interface_update_proto_addr`: every IPv4 address without an explicit
    /// broadcast gets one computed here, not by the kernel. A /31 or /32 gets
    /// 255.255.255.255, anything shorter gets the address with the host bits
    /// set. Without this the kernel leaves the broadcast unset, which is
    /// visible as a missing `brd` in `ip addr`.
    pub fn with_default_broadcast(mut self) -> Self {
        if let IpAddr::V4(v4) = self.ip {
            if self.broadcast.is_none() {
                self.broadcast = Some(if self.mask >= 31 {
                    Ipv4Addr::new(255, 255, 255, 255)
                } else {
                    let bits = u32::from_be_bytes(v4.octets());
                    Ipv4Addr::from(bits | (u32::MAX >> self.mask))
                });
            }
        }
        self
    }

    pub fn new(ip: IpAddr, mask: u8) -> Self {
        Self {
            ip,
            mask,
            broadcast: None,
            point_to_point: None,
            preferred: None,
            valid: None,
            offlink: false,
        }
    }
}

/// A permanent neighbour entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub addr: IpAddr,
    pub mac: Option<[u8; 6]>,
    pub proxy: bool,
    pub router: bool,
}

/// A route. `nexthop` unspecified means "no gateway", which is what decides
/// `RT_SCOPE_LINK` vs `RT_SCOPE_UNIVERSE` on add.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub target: IpAddr,
    pub mask: u8,
    pub source: Option<IpAddr>,
    pub sourcemask: u8,
    pub nexthop: IpAddr,
    pub metric: u32,
    pub table: u32,
    pub mtu: Option<u32>,
    pub onlink: bool,
    pub proto: Option<u8>,
    /// `RTN_*`. `None` is netifd's default `RTN_UNICAST`; a set value also
    /// moves the route to the local table and picks its scope.
    pub ty: Option<u8>,
    /// No output device: an unreachable route.
    pub nodev: bool,
}

impl Route {
    pub fn v4(target: Ipv4Addr, mask: u8) -> Self {
        Self {
            target: IpAddr::V4(target),
            mask,
            ..Self::v4_default(Ipv4Addr::UNSPECIFIED)
        }
    }

    pub fn v4_default(nexthop: Ipv4Addr) -> Self {
        Self {
            target: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            mask: 0,
            source: None,
            sourcemask: 0,
            nexthop: IpAddr::V4(nexthop),
            metric: 0,
            table: RT_TABLE_MAIN,
            mtu: None,
            onlink: false,
            proto: None,
            ty: None,
            nodev: false,
        }
    }

    pub fn v6(target: Ipv6Addr, mask: u8) -> Self {
        Self {
            target: IpAddr::V6(target),
            mask,
            source: None,
            sourcemask: 0,
            nexthop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            metric: 0,
            table: RT_TABLE_MAIN,
            mtu: None,
            onlink: false,
            proto: None,
            ty: None,
            nodev: false,
        }
    }
}

/// Build the address message exactly as `system_addr` does. Separated from the
/// syscall so it can be asserted byte-for-byte in a unit test.
pub fn encode_addr(index: u32, addr: &Address, add: bool) -> (u16, [u8; 8], Vec<u8>) {
    let v4 = matches!(addr.ip, IpAddr::V4(_));
    let hdr = ifaddrmsg(family_of(addr.ip), addr.mask, 0, 0, index);
    let mut a = Attrs::new();
    a.bytes(IFA_LOCAL, &addr_bytes(addr.ip));
    if v4 {
        if let Some(b) = addr.broadcast {
            a.bytes(IFA_BROADCAST, &b.octets());
        }
        if let Some(p) = addr.point_to_point {
            a.bytes(IFA_ADDRESS, &p.octets());
        }
    } else {
        let ci = ifa_cacheinfo(
            addr.preferred.unwrap_or(u32::MAX),
            addr.valid.unwrap_or(u32::MAX),
        );
        a.bytes(IFA_CACHEINFO, &ci);
        if add && addr.offlink {
            a.u32(IFA_FLAGS, IFA_F_NOPREFIXROUTE);
        }
    }
    let ty = if add { RTM_NEWADDR } else { RTM_DELADDR };
    (ty, hdr, a.as_bytes().to_vec())
}

/// Build the route message exactly as `system_rt` does.
///
/// # Panics
///
/// Panics if the gateway or source has a different address family from the
/// target. Configuration and protocol parsers enforce this model invariant.
pub fn encode_route(index: u32, route: &Route, add: bool) -> (u16, [u8; 12], Vec<u8>) {
    let v4 = matches!(route.target, IpAddr::V4(_));
    assert_eq!(
        route.nexthop.is_ipv4(),
        v4,
        "route gateway and target must have the same address family"
    );
    assert!(
        route.source.is_none_or(|source| source.is_ipv4() == v4),
        "route source and target must have the same address family"
    );
    let alen = if v4 { 4 } else { 16 };
    let have_gw = !is_unspecified(route.nexthop);
    let table = route.table;
    let mut scope = RT_SCOPE_NOWHERE;
    let mut ty = if add { RTN_UNICAST } else { 0 };
    let mut with_dev = !route.nodev;
    if add {
        if with_dev {
            scope = if have_gw {
                RT_SCOPE_UNIVERSE
            } else {
                RT_SCOPE_LINK
            };
        } else {
            scope = RT_SCOPE_UNIVERSE;
            ty = RTN_UNREACHABLE;
        }
    }
    // An explicit route type overrides the type, and can move the route to
    // the local table and change its scope -- and for the reject types it
    // drops the output device, which is how netifd writes a null route.
    let mut table_byte = if table < 256 {
        table as u8
    } else {
        RT_TABLE_UNSPEC
    };
    if let Some(t) = route.ty {
        ty = t;
        if table == RT_TABLE_MAIN && matches!(t, RTN_LOCAL | RTN_BROADCAST | RTN_NAT | RTN_ANYCAST)
        {
            table_byte = RT_TABLE_LOCAL;
        }
        match t {
            RTN_LOCAL | RTN_NAT => scope = RT_SCOPE_HOST,
            RTN_BROADCAST | RTN_MULTICAST | RTN_ANYCAST => scope = RT_SCOPE_LINK,
            RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT | RTN_FAILED_POLICY | RTN_THROW => {
                scope = RT_SCOPE_UNIVERSE;
                with_dev = false;
            }
            _ => {}
        }
    }
    if route.nodev {
        with_dev = false;
    }
    let hdr = rtmsg(
        if v4 { AF_INET } else { AF_INET6 },
        route.mask,
        route.sourcemask,
        0,
        table_byte,
        route.proto.unwrap_or(RTPROT_STATIC),
        scope,
        ty,
        if route.onlink { RTNH_F_ONLINK } else { 0 },
    );
    let mut a = Attrs::new();
    if route.mask != 0 {
        a.bytes(RTA_DST, &addr_bytes(route.target)[..alen]);
    }
    if route.sourcemask != 0 {
        if let Some(src) = route.source {
            let key = if v4 { RTA_PREFSRC } else { RTA_SRC };
            a.bytes(key, &addr_bytes(src)[..alen]);
        }
    }
    if route.metric > 0 {
        a.u32(RTA_PRIORITY, route.metric);
    }
    if have_gw {
        a.bytes(RTA_GATEWAY, &addr_bytes(route.nexthop)[..alen]);
    }
    if with_dev {
        a.u32(RTA_OIF, index);
    }
    if table >= 256 {
        a.u32(RTA_TABLE, table);
    }
    if let Some(mtu) = route.mtu {
        let n = a.nest_start(RTA_METRICS);
        a.u32(RTAX_MTU, mtu);
        a.nest_end(n);
    }
    let cmd = if add { RTM_NEWROUTE } else { RTM_DELROUTE };
    (cmd, hdr, a.as_bytes().to_vec())
}

/// The delegated-prefix source rejection from interface_set_prefix_address.
/// Keep the host bits, as C does: the kernel receives the assignment address
/// with its prefix length, plus the downstream input device.
pub fn encode_prefix_reject(
    dev: &str,
    addr: Ipv6Addr,
    mask: u8,
    add: bool,
) -> (u16, [u8; 12], Vec<u8>) {
    let hdr = rtmsg(
        AF_INET6,
        0,
        mask,
        0,
        RT_TABLE_UNSPEC,
        RTPROT_STATIC,
        RT_SCOPE_UNIVERSE,
        FR_ACT_UNREACHABLE,
        0,
    );
    let mut attrs = Attrs::new();
    attrs.str0(FRA_IIFNAME, dev);
    attrs.bytes(FRA_SRC, &addr.octets());
    attrs.u32(FRA_PRIORITY, 4_200_000_000);
    (
        if add { RTM_NEWRULE } else { RTM_DELRULE },
        hdr,
        attrs.as_bytes().to_vec(),
    )
}

/// Bridge creation parameters. Only the options this device's config can reach
/// are present; anything else would be dead code here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeConfig {
    pub stp: bool,
    pub stp_kernel: bool,
    pub forward_delay: u32,
    pub hello_time: u32,
    pub max_age: u32,
    pub ageing_time: Option<u32>,
    pub igmp_snoop: bool,
    pub multicast_querier: bool,
    pub hash_max: u32,
    pub robustness: u32,
    pub query_interval: u32,
    pub query_response_interval: u32,
    pub last_member_interval: u32,
    pub bridge_empty: bool,
    pub priority: u16,
    pub vlan_filtering: bool,
}

impl Default for BridgeConfig {
    /// netifd's own defaults, from `bridge_config_init` in bridge.c: STP off,
    /// forward delay 8 s, hello 1 s, max age 10 s, snooping **off**, hash max
    /// 512, priority 0x7FFF, ageing time unset. These are not the kernel's
    /// bridge defaults and not iproute2's.
    fn default() -> Self {
        Self {
            stp: false,
            stp_kernel: false,
            forward_delay: 8,
            hello_time: 1,
            max_age: 10,
            ageing_time: None,
            igmp_snoop: false,
            multicast_querier: false,
            hash_max: 512,
            robustness: 2,
            query_interval: 12500,
            query_response_interval: 1000,
            last_member_interval: 100,
            bridge_empty: false,
            priority: 0x7FFF,
            vlan_filtering: false,
        }
    }
}

/// `sec_to_jiffies` in system-linux.c: the kernel's bridge timers are in
/// 1/100 s units regardless of CONFIG_HZ.
fn sec_to_jiffies(s: u32) -> u32 {
    s.saturating_mul(100)
}

pub fn encode_addbr(name: &str, cfg: &BridgeConfig) -> (u16, [u8; 16], Vec<u8>) {
    let hdr = ifinfomsg(AF_UNSPEC, 0, 0, 0);
    let mut a = Attrs::new();
    a.str0(IFLA_IFNAME, name);
    let li = a.nest_start(IFLA_LINKINFO);
    a.str0(IFLA_INFO_KIND, "bridge");
    let data = a.nest_start(IFLA_INFO_DATA);
    a.u32(IFLA_BR_STP_STATE, cfg.stp as u32);
    a.u32(IFLA_BR_FORWARD_DELAY, sec_to_jiffies(cfg.forward_delay));
    a.u8(IFLA_BR_MCAST_SNOOPING, cfg.igmp_snoop as u8);
    a.u8(IFLA_BR_MCAST_QUERIER, cfg.multicast_querier as u8);
    a.u32(IFLA_BR_MCAST_HASH_MAX, cfg.hash_max);
    a.u8(IFLA_BR_VLAN_FILTERING, cfg.vlan_filtering as u8);
    a.u16(IFLA_BR_PRIORITY, cfg.priority);
    a.u32(IFLA_BR_HELLO_TIME, sec_to_jiffies(cfg.hello_time));
    a.u32(IFLA_BR_MAX_AGE, sec_to_jiffies(cfg.max_age));
    if let Some(t) = cfg.ageing_time {
        a.u32(IFLA_BR_AGEING_TIME, sec_to_jiffies(t));
    }
    a.nest_end(data);
    a.nest_end(li);
    (RTM_NEWLINK, hdr, a.as_bytes().to_vec())
}

/// The live kernel handle. All writes go through one socket, one at a time.
pub struct System {
    pub nl: Netlink,
}

impl System {
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            nl: Netlink::open(0)?,
        })
    }

    /// ifindex by name, from a `RTM_GETLINK` with `IFLA_IFNAME` — netifd's
    /// `system_if_resolve`. `Ok(0)` when the device does not exist, which is a
    /// normal state (a device may appear later), not an error.
    pub fn if_index(&mut self, name: &str) -> io::Result<u32> {
        let hdr = ifinfomsg(AF_UNSPEC, 0, 0, 0);
        let mut a = Attrs::new();
        a.str0(IFLA_IFNAME, name);
        let seq_msgs = self.nl.dump_one(RTM_GETLINK, &hdr, a.as_bytes());
        match seq_msgs {
            Ok(Some(m)) => {
                if m.payload.len() < 16 {
                    return Ok(0);
                }
                Ok(
                    i32::from_le_bytes([m.payload[4], m.payload[5], m.payload[6], m.payload[7]])
                        as u32,
                )
            }
            Ok(None) => Ok(0),
            Err(e) if e.raw_os_error() == Some(19) => Ok(0), // ENODEV
            Err(e) => Err(e),
        }
    }

    /// `system_if_flags`: read the current flags, then set exactly the
    /// difference. netifd reads first so it never clears a flag it does not
    /// own.
    pub fn set_link_flags(&mut self, index: u32, add: u32, rem: u32) -> io::Result<()> {
        let hdr = ifinfomsg(AF_UNSPEC, index as i32, add, add | rem);
        self.nl.request(RTM_NEWLINK, 0, &hdr, &[])
    }

    pub fn set_link_up(&mut self, index: u32, up: bool) -> io::Result<()> {
        if up {
            self.set_link_flags(index, IFF_UP, 0)
        } else {
            self.set_link_flags(index, 0, IFF_UP)
        }
    }

    pub fn set_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()> {
        let hdr = ifinfomsg(AF_UNSPEC, index as i32, 0, 0);
        let mut a = Attrs::new();
        a.u32(IFLA_MTU, mtu);
        self.nl.request(RTM_SETLINK, 0, &hdr, a.as_bytes())
    }

    pub fn set_mac(&mut self, index: u32, mac: &[u8; 6]) -> io::Result<()> {
        let hdr = ifinfomsg(AF_UNSPEC, index as i32, 0, 0);
        let mut a = Attrs::new();
        a.bytes(IFLA_ADDRESS, mac);
        self.nl.request(RTM_SETLINK, 0, &hdr, a.as_bytes())
    }

    pub fn set_txqueuelen(&mut self, index: u32, len: u32) -> io::Result<()> {
        let hdr = ifinfomsg(AF_UNSPEC, index as i32, 0, 0);
        let mut a = Attrs::new();
        a.u32(IFLA_TXQLEN, len);
        self.nl.request(RTM_SETLINK, 0, &hdr, a.as_bytes())
    }

    pub fn link_del(&mut self, name: &str) -> io::Result<()> {
        let hdr = ifinfomsg(AF_UNSPEC, 0, 0, 0);
        let mut a = Attrs::new();
        a.str0(IFLA_IFNAME, name);
        self.nl.request(RTM_DELLINK, 0, &hdr, a.as_bytes())
    }

    pub fn bridge_addbr(&mut self, name: &str, cfg: &BridgeConfig) -> io::Result<()> {
        let (ty, hdr, attrs) = encode_addbr(name, cfg);
        self.nl.request(
            ty,
            netlink::NLM_F_CREATE | netlink::NLM_F_EXCL,
            &hdr,
            &attrs,
        )
    }

    pub fn bridge_set_options(&mut self, name: &str, cfg: &BridgeConfig) -> io::Result<()> {
        let (ty, hdr, attrs) = encode_addbr(name, cfg);
        self.nl.request(ty, 0, &hdr, &attrs)
    }

    pub fn bridge_delbr(&mut self, name: &str) -> io::Result<()> {
        self.link_del(name)
    }

    /// Enslave `index` to `master`; `master == 0` detaches it.
    pub fn bridge_setmaster(&mut self, index: u32, master: u32) -> io::Result<()> {
        let hdr = ifinfomsg(AF_UNSPEC, index as i32, 0, 0);
        let mut a = Attrs::new();
        a.u32(IFLA_MASTER, master);
        self.nl.request(RTM_SETLINK, 0, &hdr, a.as_bytes())
    }

    pub fn add_address(&mut self, index: u32, addr: &Address) -> io::Result<()> {
        let (ty, hdr, attrs) = encode_addr(index, addr, true);
        self.nl.request(
            ty,
            netlink::NLM_F_CREATE | netlink::NLM_F_REPLACE,
            &hdr,
            &attrs,
        )
    }

    pub fn del_address(&mut self, index: u32, addr: &Address) -> io::Result<()> {
        let (ty, hdr, attrs) = encode_addr(index, addr, false);
        self.nl.request(ty, 0, &hdr, &attrs)
    }

    pub fn add_route(&mut self, index: u32, route: &Route) -> io::Result<()> {
        let (ty, hdr, attrs) = encode_route(index, route, true);
        self.nl.request(
            ty,
            netlink::NLM_F_CREATE | netlink::NLM_F_REPLACE,
            &hdr,
            &attrs,
        )
    }

    pub fn prefix_reject(
        &mut self,
        dev: &str,
        addr: Ipv6Addr,
        mask: u8,
        add: bool,
    ) -> io::Result<()> {
        let (ty, hdr, attrs) = encode_prefix_reject(dev, addr, mask, add);
        self.nl.request(ty, 0, &hdr, &attrs)
    }

    pub fn del_route(&mut self, index: u32, route: &Route) -> io::Result<()> {
        let (ty, hdr, attrs) = encode_route(index, route, false);
        self.nl.request(ty, 0, &hdr, &attrs)
    }

    /// Every link, for the device registry's initial scan.
    /// `system_if_get_parent`: the device `iflink` names, when it is not the
    /// device itself. For a DSA user port that is the conduit; for a veth it
    /// is the peer.
    pub fn parent_of(&mut self, name: &str) -> Option<String> {
        let text = std::fs::read_to_string(format!("/sys/class/net/{name}/iflink")).ok()?;
        let iflink: u32 = text.trim().parse().ok()?;
        let own = self.if_index(name).unwrap_or(0);
        if iflink == 0 || iflink == own {
            return None;
        }
        // if_indextoname, via the only name the kernel exports for an index
        for e in std::fs::read_dir("/sys/class/net").ok()?.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            let Ok(t) = std::fs::read_to_string(format!("/sys/class/net/{n}/ifindex")) else {
                continue;
            };
            if t.trim().parse::<u32>() == Ok(iflink) {
                return Some(n);
            }
        }
        None
    }

    /// `system_add_neighbor` / `system_del_neighbor`: a permanent neighbour
    /// entry, optionally a proxy or a router.
    pub fn neighbor(&mut self, index: u32, n: &Neighbor, add: bool) -> io::Result<()> {
        let v4 = n.addr.is_ipv4();
        let alen = if v4 { 4 } else { 16 };
        let mut hdr = ndmsg(if v4 { AF_INET } else { AF_INET6 }, index, 0);
        hdr[8..10].copy_from_slice(&NUD_PERMANENT.to_le_bytes());
        hdr[10] = if n.proxy { NTF_PROXY } else { 0 } | if n.router { NTF_ROUTER } else { 0 };
        let mut a = Attrs::new();
        a.bytes(NDA_DST, &addr_bytes(n.addr)[..alen]);
        if let Some(mac) = n.mac {
            a.bytes(NDA_LLADDR, &mac);
        }
        let ty = if add { RTM_NEWNEIGH } else { RTM_DELNEIGH };
        let flags = if add {
            netlink::NLM_F_CREATE | netlink::NLM_F_REPLACE
        } else {
            0
        };
        self.nl
            .request(ty, netlink::NLM_F_REQUEST | flags, &hdr, a.as_bytes())
    }

    /// `system_if_clear_state`: bring the device down, take it out of any
    /// bridge and flush the addresses, routes and permanent neighbours on it.
    ///
    /// netifd runs this from `device_init`, so it happens once for every
    /// device it creates an object for -- including a device it only touches
    /// as another device's parent. That is why an address someone else put on
    /// such a device disappears when netifd starts.
    pub fn clear_state(&mut self, name: &str, external: bool) {
        let index = self.if_index(name).unwrap_or(0);
        if external || index == 0 {
            return;
        }
        let _ = self.set_link_up(index, false);
        if std::path::Path::new(&format!("/sys/class/net/{name}/bridge")).exists() {
            // an existing bridge of this name is deleted, and nothing else
            let _ = self.bridge_delbr(name);
            return;
        }
        if std::path::Path::new(&format!("/sys/class/net/{name}/brport")).exists() {
            let _ = self.bridge_setmaster(index, 0);
        }
        // this order is the C's
        for (kind, af) in [
            (RTM_GETROUTE, AF_INET),
            (RTM_GETADDR, AF_INET),
            (RTM_GETROUTE, AF_INET6),
            (RTM_GETADDR, AF_INET6),
            (RTM_GETNEIGH, AF_INET),
            (RTM_GETNEIGH, AF_INET6),
        ] {
            self.clear_entries(index, kind, af);
        }
        let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "0");
    }

    /// `system_if_clear_entries`: dump, keep what belongs to this device, and
    /// re-send each kept message with the matching delete type. Deletions are
    /// queued until the dump has finished, because an error reply carrying the
    /// dump's sequence number aborts the dump.
    fn clear_entries(&mut self, index: u32, kind: u16, af: u8) {
        let (del_ty, dumps): (u16, usize) = match kind {
            RTM_GETADDR => (RTM_DELADDR, 1),
            RTM_GETROUTE => (RTM_DELROUTE, 1),
            // the kernel dumps proxy entries only when asked for them
            RTM_GETNEIGH => (RTM_DELNEIGH, 2),
            _ => return,
        };
        let new_ty = match kind {
            RTM_GETADDR => RTM_NEWADDR,
            RTM_GETROUTE => RTM_NEWROUTE,
            _ => RTM_NEWNEIGH,
        };
        let mut queued: Vec<Vec<u8>> = Vec::new();
        for pass in 0..dumps {
            let hdr: Vec<u8> = match kind {
                // sizeof(struct rtgenmsg): the family byte alone
                RTM_GETADDR => vec![af],
                RTM_GETROUTE => rtmsg(af, 0, 0, 0, 0, 0, 0, 0, RTM_F_CLONED).to_vec(),
                _ => ndmsg(af, 0, if pass == 0 { 0 } else { NTF_PROXY }).to_vec(),
            };
            let Ok(msgs) = self.nl.dump(kind, &hdr) else {
                continue;
            };
            for m in msgs {
                if m.ty != new_ty {
                    continue;
                }
                let keep = match kind {
                    RTM_GETADDR => check_ifaddr(&m.payload, index),
                    RTM_GETROUTE => check_route(&m.payload, index),
                    _ => check_neigh(&m.payload, index),
                };
                if keep {
                    queued.push(m.payload);
                }
            }
        }
        for payload in queued {
            // an entry that is already gone is not an error worth reporting
            let _ = self
                .nl
                .request(del_ty, netlink::NLM_F_REQUEST, &payload, &[]);
        }
    }

    pub fn dump_links(&mut self) -> io::Result<Vec<netlink::Msg>> {
        self.nl.dump(RTM_GETLINK, &ifinfomsg(AF_UNSPEC, 0, 0, 0))
    }
}

/// The `SIOCGIF*` half of `system_if_get_settings`: an AF_INET datagram socket
/// used only as an ioctl handle, which is what netifd's `sock_ioctl` is.
pub struct IfIoctl {
    fd: std::os::fd::OwnedFd,
}

impl AsRawFd for IfIoctl {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for IfIoctl {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl IfIoctl {
    pub fn open() -> io::Result<Self> {
        let fd = rustix::net::socket_with(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::DGRAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )?;
        Ok(Self { fd })
    }

    /// Only the fixed SIOCGIF* byte layouts used by this component.
    fn call(&self, ifname: &str, req: u64) -> io::Result<[u8; 40]> {
        owrt_platform::netifd::interface_query(&self.fd, ifname, req)
    }

    /// A numeric field of the ifreq union, at `off` bytes into the struct.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the field is outside the
    /// 40-byte ifreq layout, or the error from the interface query.
    pub fn ioctl_u32(&self, ifname: &str, req: u64, off: usize) -> io::Result<u32> {
        if off > 36 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "u32 field is outside the 40-byte ifreq layout",
            ));
        }
        let r = self.call(ifname, req)?;
        Ok(u32::from_le_bytes([
            r[off],
            r[off + 1],
            r[off + 2],
            r[off + 3],
        ]))
    }

    /// `SIOCGIFHWADDR`: `struct sockaddr` at offset 16, so the six address
    /// bytes start at 18 after the two-byte family.
    pub fn get_hwaddr(&self, ifname: &str) -> io::Result<[u8; 6]> {
        let r = self.call(ifname, SIOCGIFHWADDR)?;
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&r[18..24]);
        Ok(mac)
    }
}

/// `/proc/sys/net/...` — netifd reads and writes these per device. Errors are
/// returned rather than swallowed; callers decide whether a missing knob (an
/// interface without IPv6, say) is fatal.
pub fn sysctl_path(kind: &str, dev: &str, key: &str) -> String {
    format!("/proc/sys/net/{kind}/conf/{dev}/{key}")
}

pub fn sysctl_set(path: &str, val: &str) -> io::Result<()> {
    std::fs::write(path, val)
}

/// Zero every bit below the prefix length; the same rule as
/// `clear_if_addr`, kept here so this module stands alone.
fn clear_v6(addr: Ipv6Addr, length: u8) -> Ipv6Addr {
    let mut o = addr.octets();
    let len = length.min(128) as usize;
    for (i, b) in o.iter_mut().enumerate() {
        let bit = i * 8;
        if bit >= len {
            *b = 0;
        } else if bit + 8 > len {
            *b &= !0u8 << (8 - (len - bit));
        }
    }
    Ipv6Addr::from(o)
}

/// C installs a lowest-priority null route for each non-host offlink subnet.
/// This prevents unmatched destinations falling back to the upstream default.
pub fn offlink_route(addr: &Address) -> Option<Route> {
    let bits = if addr.ip.is_ipv6() { 128 } else { 32 };
    if !addr.offlink || addr.mask >= bits {
        return None;
    }
    let mut route = subnet_route(addr, i32::MAX as u32, 0);
    route.nodev = true;
    Some(route)
}

/// The prefix route an on-link address implies.
/// `interface_handle_subnet_route` does two operations, in this order:
/// delete the route as if the kernel had installed it (`proto kernel`), which
/// removes the automatic prefix route, then add netifd's own with the
/// interface's metric and table. Both are needed: without the delete the
/// kernel route stays and shadows netifd's.
pub fn subnet_route(addr: &Address, metric: u32, table: u32) -> Route {
    let target = match addr.ip {
        IpAddr::V4(v) => {
            let bits = u32::from_be_bytes(v.octets());
            let mask = if addr.mask == 0 {
                0
            } else {
                u32::MAX << (32 - addr.mask.min(32))
            };
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(v) => IpAddr::V6(clear_v6(v, addr.mask)),
    };
    Route {
        target,
        mask: addr.mask,
        source: None,
        sourcemask: 0,
        nexthop: match addr.ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        metric,
        table: if table != 0 { table } else { RT_TABLE_MAIN },
        mtu: None,
        onlink: false,
        proto: None,
        ty: None,
        nodev: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{attr, attr_u32, parse_attrs};
    use std::net::Ipv4Addr;

    #[test]
    fn interface_query_rejects_out_of_bounds_fields_before_the_ioctl() {
        let query = IfIoctl::open().unwrap();
        for offset in [37, 40, usize::MAX] {
            let error = query.ioctl_u32("lo", 0, offset).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn offlink_null_routes_cover_subnets_but_not_host_addresses() {
        let mut addr = Address::new("2001:db8:1::1234".parse().unwrap(), 64);
        assert!(offlink_route(&addr).is_none());
        addr.offlink = true;
        let route = offlink_route(&addr).unwrap();
        assert_eq!(route.target, "2001:db8:1::".parse::<IpAddr>().unwrap());
        assert_eq!(route.metric, 2_147_483_647);
        assert!(route.nodev);
        let (_, hdr, attrs) = encode_route(0, &route, true);
        assert_eq!(hdr[7], RTN_UNREACHABLE);
        assert!(attr(&parse_attrs(&attrs), RTA_OIF).is_none());
        addr.mask = 128;
        assert!(offlink_route(&addr).is_none());
        let mut v4 = Address::new("192.0.2.17".parse().unwrap(), 24);
        v4.offlink = true;
        assert_eq!(
            offlink_route(&v4).unwrap().target,
            "192.0.2.0".parse::<IpAddr>().unwrap()
        );
        v4.mask = 32;
        assert!(offlink_route(&v4).is_none());
    }

    #[test]
    fn delegated_prefix_reject_matches_c_rule_wire_format() {
        let address: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        let (ty, hdr, attrs) = encode_prefix_reject("br-lan", address, 64, true);
        assert_eq!(ty, RTM_NEWRULE);
        assert_eq!(hdr, [10, 0, 64, 0, 0, 4, 0, 7, 0, 0, 0, 0]);
        let fields = parse_attrs(&attrs);
        assert_eq!(attr(&fields, FRA_IIFNAME), Some(&b"br-lan\0"[..]));
        assert_eq!(attr(&fields, FRA_SRC), Some(&address.octets()[..]));
        assert_eq!(attr_u32(&fields, FRA_PRIORITY), Some(4_200_000_000));
        let (del, del_hdr, del_attrs) = encode_prefix_reject("br-lan", address, 64, false);
        assert_eq!(del, RTM_DELRULE);
        assert_eq!(del_hdr, hdr);
        assert_eq!(del_attrs, attrs);
    }

    #[test]
    fn ifinfomsg_layout_is_sixteen_bytes() {
        let b = ifinfomsg(AF_INET, 7, IFF_UP, IFF_UP);
        assert_eq!(b.len(), 16);
        assert_eq!(b[0], AF_INET);
        assert_eq!(i32::from_le_bytes([b[4], b[5], b[6], b[7]]), 7);
        assert_eq!(u32::from_le_bytes([b[8], b[9], b[10], b[11]]), IFF_UP);
        assert_eq!(u32::from_le_bytes([b[12], b[13], b[14], b[15]]), IFF_UP);
    }

    #[test]
    fn v4_address_carries_no_cacheinfo() {
        let a = Address::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24);
        let (ty, hdr, attrs) = encode_addr(3, &a, true);
        assert_eq!(ty, RTM_NEWADDR);
        assert_eq!(hdr[0], AF_INET);
        assert_eq!(hdr[1], 24);
        let p = parse_attrs(&attrs);
        assert_eq!(attr(&p, IFA_LOCAL).unwrap(), &[192, 168, 1, 1]);
        assert!(attr(&p, IFA_CACHEINFO).is_none());
    }

    #[test]
    fn v6_address_always_carries_cacheinfo() {
        let a = Address::new("fd00::1".parse::<IpAddr>().unwrap(), 64);
        let (_, hdr, attrs) = encode_addr(3, &a, true);
        assert_eq!(hdr[0], AF_INET6);
        let p = parse_attrs(&attrs);
        let ci = attr(&p, IFA_CACHEINFO).unwrap();
        // no lifetimes set means "infinite", i.e. 0xffffffff for both
        assert_eq!(&ci[0..4], &u32::MAX.to_le_bytes());
        assert_eq!(&ci[4..8], &u32::MAX.to_le_bytes());
        assert!(attr(&p, IFA_FLAGS).is_none());
    }

    #[test]
    fn offlink_only_applies_to_v6_on_add() {
        let mut a = Address::new("fd00::1".parse::<IpAddr>().unwrap(), 64);
        a.offlink = true;
        let (_, _, add) = encode_addr(3, &a, true);
        assert_eq!(
            attr_u32(&parse_attrs(&add), IFA_FLAGS),
            Some(IFA_F_NOPREFIXROUTE)
        );
        let (_, _, del) = encode_addr(3, &a, false);
        assert!(attr(&parse_attrs(&del), IFA_FLAGS).is_none());

        let mut v4 = Address::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24);
        v4.offlink = true;
        let (_, _, v4add) = encode_addr(3, &v4, true);
        assert!(attr(&parse_attrs(&v4add), IFA_FLAGS).is_none());
    }

    #[test]
    fn a_gateway_route_is_universe_scope_a_link_route_is_link() {
        let gw = Route::v4_default(Ipv4Addr::new(10, 0, 0, 1));
        let (_, hdr, attrs) = encode_route(3, &gw, true);
        assert_eq!(hdr[6], RT_SCOPE_UNIVERSE);
        assert_eq!(hdr[7], RTN_UNICAST);
        let p = parse_attrs(&attrs);
        assert_eq!(attr(&p, RTA_GATEWAY).unwrap(), &[10, 0, 0, 1]);
        // a default route has mask 0, so no RTA_DST
        assert!(attr(&p, RTA_DST).is_none());
        assert_eq!(attr_u32(&p, RTA_OIF), Some(3));

        let mut onlink = Route::v4_default(Ipv4Addr::UNSPECIFIED);
        onlink.target = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0));
        onlink.mask = 16;
        let (_, hdr2, attrs2) = encode_route(3, &onlink, true);
        assert_eq!(hdr2[6], RT_SCOPE_LINK);
        let p2 = parse_attrs(&attrs2);
        assert_eq!(attr(&p2, RTA_DST).unwrap(), &[10, 1, 0, 0]);
        assert!(attr(&p2, RTA_GATEWAY).is_none());
    }

    #[test]
    fn deleting_a_route_clears_scope_and_type() {
        let gw = Route::v4_default(Ipv4Addr::new(10, 0, 0, 1));
        let (cmd, hdr, _) = encode_route(3, &gw, false);
        assert_eq!(cmd, RTM_DELROUTE);
        assert_eq!(hdr[6], RT_SCOPE_NOWHERE);
        assert_eq!(hdr[7], 0);
    }

    #[test]
    fn a_null_route_is_unreachable_with_no_oif() {
        let mut r = Route::v4_default(Ipv4Addr::UNSPECIFIED);
        r.nodev = true;
        let (_, hdr, attrs) = encode_route(3, &r, true);
        assert_eq!(hdr[7], RTN_UNREACHABLE);
        assert_eq!(hdr[6], RT_SCOPE_UNIVERSE);
        assert!(attr(&parse_attrs(&attrs), RTA_OIF).is_none());
    }

    #[test]
    fn a_table_above_255_moves_into_rta_table() {
        let mut r = Route::v4_default(Ipv4Addr::new(10, 0, 0, 1));
        r.table = 1000;
        let (_, hdr, attrs) = encode_route(3, &r, true);
        assert_eq!(hdr[4], RT_TABLE_UNSPEC);
        assert_eq!(attr_u32(&parse_attrs(&attrs), RTA_TABLE), Some(1000));

        r.table = 100;
        let (_, hdr2, attrs2) = encode_route(3, &r, true);
        assert_eq!(hdr2[4], 100);
        assert!(attr(&parse_attrs(&attrs2), RTA_TABLE).is_none());
    }

    #[test]
    fn route_mtu_goes_into_a_metrics_nest() {
        let mut r = Route::v4_default(Ipv4Addr::new(10, 0, 0, 1));
        r.mtu = Some(1400);
        let (_, _, attrs) = encode_route(3, &r, true);
        let p = parse_attrs(&attrs);
        let m = attr(&p, RTA_METRICS | crate::netlink::NLA_F_NESTED).unwrap();
        assert_eq!(attr_u32(&parse_attrs(m), RTAX_MTU), Some(1400));
    }

    #[test]
    fn bridge_timers_are_hundredths_of_a_second() {
        let cfg = BridgeConfig::default();
        let (_, _, attrs) = encode_addbr("br-lan", &cfg);
        let top = parse_attrs(&attrs);
        let li = attr(&top, IFLA_LINKINFO | crate::netlink::NLA_F_NESTED).unwrap();
        let lip = parse_attrs(li);
        assert_eq!(
            crate::netlink::attr_str(&lip, IFLA_INFO_KIND),
            Some("bridge")
        );
        let data = parse_attrs(attr(&lip, IFLA_INFO_DATA | crate::netlink::NLA_F_NESTED).unwrap());
        // netifd's defaults are 8 s / 1 s / 10 s, in hundredths of a second,
        // and snooping is off unless configured
        assert_eq!(attr_u32(&data, IFLA_BR_FORWARD_DELAY), Some(800));
        assert_eq!(attr_u32(&data, IFLA_BR_HELLO_TIME), Some(100));
        assert_eq!(attr_u32(&data, IFLA_BR_MAX_AGE), Some(1000));
        assert_eq!(
            crate::netlink::attr_u8(&data, IFLA_BR_MCAST_SNOOPING),
            Some(0)
        );
        assert_eq!(attr_u32(&data, IFLA_BR_MCAST_HASH_MAX), Some(512));
        // ageing_time is absent unless configured, matching BRIDGE_OPT_AGEING_TIME
        assert!(attr(&data, IFLA_BR_AGEING_TIME).is_none());
    }

    #[test]
    fn a_v4_address_gets_a_computed_broadcast() {
        let a = Address::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24).with_default_broadcast();
        assert_eq!(a.broadcast, Some(Ipv4Addr::new(10, 0, 0, 255)));
        let (_, _, attrs) = encode_addr(3, &a, true);
        assert_eq!(
            attr(&parse_attrs(&attrs), IFA_BROADCAST).unwrap(),
            &[10, 0, 0, 255]
        );
    }

    #[test]
    fn a_31_or_32_broadcasts_to_all_ones() {
        for mask in [31u8, 32] {
            let a =
                Address::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), mask).with_default_broadcast();
            assert_eq!(
                a.broadcast,
                Some(Ipv4Addr::new(255, 255, 255, 255)),
                "/{mask}"
            );
        }
    }

    #[test]
    fn a_v6_address_gets_no_broadcast() {
        let a = Address::new("fd00::1".parse().unwrap(), 64).with_default_broadcast();
        assert!(a.broadcast.is_none());
    }

    #[test]
    fn an_explicit_broadcast_is_not_overwritten() {
        let mut a = Address::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24);
        a.broadcast = Some(Ipv4Addr::new(10, 0, 0, 200));
        let a = a.with_default_broadcast();
        assert_eq!(a.broadcast, Some(Ipv4Addr::new(10, 0, 0, 200)));
    }

    #[test]
    fn the_subnet_route_clears_the_host_part_and_takes_the_interface_metric() {
        let a = Address::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24);
        let r = subnet_route(&a, 13, 0);
        assert_eq!(r.target, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(r.mask, 24);
        assert_eq!(r.metric, 13);
        assert_eq!(r.table, RT_TABLE_MAIN);
        assert!(r.nexthop.is_ipv4());
        // no gateway, so the encoded route is link-scoped
        let (_, hdr, _) = encode_route(3, &r, true);
        assert_eq!(hdr[6], RT_SCOPE_LINK);
    }

    #[test]
    fn a_v6_subnet_route_clears_below_the_prefix() {
        let a = Address::new("fd00:1:2:3::5".parse().unwrap(), 60);
        let r = subnet_route(&a, 0, 0);
        assert_eq!(r.target, "fd00:1:2::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ifname_appears_outside_the_linkinfo_nest() {
        let (_, _, attrs) = encode_addbr("br-lan", &BridgeConfig::default());
        let top = parse_attrs(&attrs);
        assert_eq!(crate::netlink::attr_str(&top, IFLA_IFNAME), Some("br-lan"));
    }
}
