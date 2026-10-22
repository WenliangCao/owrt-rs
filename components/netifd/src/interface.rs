//! Interfaces: the state an interface carries and the `network.interface`
//! status projection of it.
//!
//! As with devices, both the field order and the omissions are the interface.
//! `netifd_dump_status` prints the whole IP block only while the interface is
//! `IFS_UP`, and each list is the concatenation of the config-derived entries
//! and the protocol-derived ones, in that order.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use owrt_ubus::blob::BlobBuf;

/// `enum interface_state`. Only the states this build reaches are named.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum State {
    #[default]
    Down,
    Setup,
    Up,
    Teardown,
}

/// `iface->updated`, reported as the `updated` array.
pub mod updated {
    pub const ADDRESS: u32 = 1 << 0;
    pub const ROUTE: u32 = 1 << 1;
    pub const PREFIX: u32 = 1 << 2;
    pub const DATA: u32 = 1 << 3;
}

/// One address on an interface, as the status reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub addr: IpAddr,
    pub mask: u8,
    /// Position in this protocol's address-family list, part of C's vlist key.
    pub index: usize,
    pub point_to_point: Option<IpAddr>,
    /// DEADLINES on the monotonic clock, as `preferred_until`/`valid_until`
    /// are in the C (`parse_address_item` adds `now`); the status prints what
    /// is left. Storing the lifetime the protocol reported printed a constant
    /// forever (R81 F08). `None` means the field is omitted.
    pub preferred_until: Option<u32>,
    pub valid_until: Option<u32>,
    pub class: Option<String>,
    /// What the protocol asked for besides the prefix, kept so the address can
    /// be re-applied (`interface_ip_set_enabled`) without the protocol.
    pub broadcast: Option<std::net::Ipv4Addr>,
    pub offlink: bool,
    /// Applied to the device, as opposed to held back — the `inactive` table.
    pub enabled: bool,
    /// A failed re-apply must be retried even when the next lease is identical.
    pub failed: bool,
}

impl Address {
    pub fn new(addr: IpAddr, mask: u8) -> Self {
        Self {
            addr,
            mask,
            index: 0,
            point_to_point: None,
            preferred_until: None,
            valid_until: None,
            class: None,
            broadcast: None,
            offlink: false,
            enabled: true,
            failed: false,
        }
    }
}

/// `blobmsg_add_u32(&b, "preferred", preferred_until - now)`, clamped at 0
/// the way the C's `int preferred` check does.
fn preferred_left(until: u32, now: u32) -> u32 {
    until.saturating_sub(now)
}

/// `blobmsg_add_u32(&b, "valid", valid_until - now)`: no clamp in the C, so
/// a deadline just past prints as a wrapped u32, exactly like `time_t` cast.
fn valid_left(until: u32, now: u32) -> u32 {
    until.wrapping_sub(now)
}

fn rtime() -> u32 {
    crate::clock::now().min(u32::MAX as u64) as u32
}

/// netifd's `DEVROUTE_*` flags, which decide which route fields are printed.
pub mod devroute {
    pub const MTU: u32 = 1 << 0;
    pub const PROTO: u32 = 1 << 1;
    pub const METRIC: u32 = 1 << 2;
    pub const TABLE: u32 = 1 << 3;
    pub const SRCTABLE: u32 = 1 << 4;
    pub const ONLINK: u32 = 1 << 5;
    pub const TYPE: u32 = 1 << 6;
    /// `DEVROUTE_NODEV`: a `config route` with no interface -- installed with
    /// no output device from `loopback`.
    pub const NODEV: u32 = 1 << 7;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub target: IpAddr,
    pub mask: u8,
    pub nexthop: IpAddr,
    pub source: IpAddr,
    pub sourcemask: u8,
    pub flags: u32,
    pub ty: u32,
    pub proto: u32,
    pub mtu: u32,
    pub metric: u32,
    pub table: u32,
    /// A deadline on the monotonic clock; the status prints what is left.
    pub valid_until: Option<u32>,
    pub enabled: bool,
    pub failed: bool,
}

impl Route {
    pub fn new(target: IpAddr, mask: u8, nexthop: IpAddr) -> Self {
        let source = if target.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        Self {
            target,
            mask,
            nexthop,
            source,
            sourcemask: 0,
            flags: 0,
            ty: 0,
            proto: 0,
            mtu: 0,
            metric: 0,
            table: 0,
            valid_until: None,
            enabled: true,
            failed: false,
        }
    }
}

/// `route_cmp`: longest mask first, then metric, then flags **descending**,
/// then sourcemask, table, source and target. netifd keeps routes in a vlist
/// ordered by this, and the status prints them in that order.
pub fn route_order(a: &Route, b: &Route) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    fn key_bytes(ip: IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        }
    }
    if a.mask != b.mask {
        return b.mask.cmp(&a.mask);
    }
    if a.metric != b.metric {
        return a.metric.cmp(&b.metric);
    }
    if a.flags != b.flags {
        return b.flags.cmp(&a.flags);
    }
    if a.sourcemask != b.sourcemask {
        return a.sourcemask.cmp(&b.sourcemask);
    }
    if a.table != b.table {
        return a.table.cmp(&b.table);
    }
    match key_bytes(a.source).cmp(&key_bytes(b.source)) {
        Ordering::Equal => key_bytes(a.target).cmp(&key_bytes(b.target)),
        o => o,
    }
}

/// A delegated prefix and what has been assigned out of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub addr: Ipv6Addr,
    pub length: u8,
    pub preferred_until: Option<u32>,
    pub valid_until: Option<u32>,
    pub class: String,
    /// interface name → (address, length)
    pub assigned: Vec<(String, Ipv6Addr, u8)>,
}

/// One assignment out of a delegated prefix, from the receiving interface's
/// point of view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixAssignment {
    pub addr: Ipv6Addr,
    pub length: u8,
    /// Deadlines (the parent prefix's); the status prints what is left.
    pub preferred_until: Option<u32>,
    pub valid_until: Option<u32>,
    /// `local-address` is an empty table when the assignment is not enabled.
    pub local: Option<(Ipv6Addr, u8)>,
    /// Which parent prefix produced this assignment: the uplink it came from
    /// (`None` for the ULA) and the parent's address and length.
    ///
    /// `prefix_cmp` keys the prefix vlist on the parent's address AND length,
    /// so `2001:db8:100::/56` and `/60` are two different prefixes that can
    /// hand out the identical `/64` local address. Deciding a withdrawal by
    /// whether that local address survived therefore skips a withdrawal the C
    /// performs -- measured on the reference, where the address ends up
    /// deprecated with the OLD prefix's valid deadline while this build kept
    /// it live. Ownership has to be tracked, not inferred.
    pub owner: Option<(Option<String>, Ipv6Addr, u8)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpSettings {
    /// Device on which successful entries were installed; a reused name is
    /// not sufficient to keep addresses or routes after link replacement.
    pub device_index: Option<u32>,
    pub addresses: Vec<Address>,
    pub routes: Vec<Route>,
    pub prefixes: Vec<Prefix>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub neighbors: Vec<Neighbor>,
    /// `no_dns`: the lists move to `inactive`.
    pub no_dns: bool,
    /// `no_defaultroute`: a mask-0 route moves to `inactive`.
    pub no_defaultroute: bool,
    pub no_delegation: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub addr: IpAddr,
    pub mac: Option<[u8; 6]>,
    pub proxy: u32,
    pub router: u32,
    pub enabled: bool,
}

/// An interface error, as `netifd_add_interface_errors` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfaceError {
    pub subsystem: String,
    pub code: String,
    pub data: Vec<String>,
}

/// `interface_config_state`: what a config change asked for, performed once
/// the interface is down (`interface_handle_config_change`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConfigState {
    #[default]
    Normal,
    Reload,
    Remove,
}

/// One interface.
#[derive(Clone, Debug, Default)]
pub struct Interface {
    pub name: String,
    pub state: State,
    pub config_state: ConfigState,
    pub available: bool,
    pub autostart: bool,
    /// `iface->enabled`: whether the main device is claimed and up. It comes
    /// from `DEV_EVENT_UP`/`DOWN`, not from the `disabled` option, and
    /// `interface_check_state` tears the interface down when it goes false.
    pub enabled: bool,
    pub dynamic: bool,
    /// Daemon-owned monotonic start time. It follows this interface through
    /// sorting and disappears with it on teardown or configuration reload.
    pub started_at: Option<u64>,
    pub l3_device: Option<String>,
    pub proto: Option<String>,
    /// `main_dev`, printed unless the proto handler is `PROTO_FLAG_NODEV`.
    pub device: Option<String>,
    pub updated: u32,
    pub ip4table: u32,
    pub ip6table: u32,
    pub metric: u32,
    pub dns_metric: u32,
    pub assignment_weight: u32,
    /// From the config sections.
    pub config_ip: IpSettings,
    /// From the protocol handler.
    pub proto_ip: IpSettings,
    pub prefix_assignments: Vec<PrefixAssignment>,
    pub zone: Option<String>,
    /// `set_data` entries, in name order (an AVL walk).
    pub data: Vec<(String, owrt_ubus::json::Json)>,
    pub errors: Vec<IfaceError>,
}

/// Find the first matching interface in the daemon's name-ordered list.
/// Call only after additions have been sorted; construction-time lookups
/// may still need a linear scan. Tiny lists avoid the binary-search overhead.
pub fn find_by_name<'a>(interfaces: &'a [Interface], name: &str) -> Option<&'a Interface> {
    if interfaces.len() <= 2 {
        return interfaces.iter().find(|i| i.name == name);
    }
    let at = interfaces.partition_point(|i| i.name.as_str() < name);
    interfaces.get(at).filter(|i| i.name == name)
}

/// An address's text on the stack: the same `Display` output as
/// `to_string()` (longest IPv6 form is 45 bytes) without a heap allocation
/// per field, which a 32-interface dump pays hundreds of times.
struct IpText {
    buf: [u8; 48],
    len: usize,
}

impl IpText {
    fn of(addr: &IpAddr) -> IpText {
        use std::io::Write;
        let mut text = IpText {
            buf: [0u8; 48],
            len: 0,
        };
        let mut cursor = std::io::Cursor::new(&mut text.buf[..]);
        // Display of an IpAddr never exceeds 45 bytes.
        let _ = write!(cursor, "{addr}");
        text.len = cursor.position() as usize;
        text
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

fn put_addr(b: &mut BlobBuf, a: &Address) {
    let t = b.msg_open_table("");
    b.msg_string("address", IpText::of(&a.addr).as_str());
    b.msg_u32("mask", a.mask as u32);
    if let Some(p) = a.point_to_point {
        b.msg_string("ptpaddress", IpText::of(&p).as_str());
    }
    // Only a lifetime-bearing address needs the clock; static addresses are
    // the common case and a dump touches every one of them.
    if a.preferred_until.is_some() || a.valid_until.is_some() {
        let now = rtime();
        if let Some(p) = a.preferred_until {
            b.msg_u32("preferred", preferred_left(p, now));
        }
        if let Some(v) = a.valid_until {
            b.msg_u32("valid", valid_left(v, now));
        }
    }
    if let Some(c) = &a.class {
        b.msg_string("class", c);
    }
    b.msg_close(t);
}

fn put_route(b: &mut BlobBuf, r: &Route) {
    let t = b.msg_open_table("");
    b.msg_string("target", IpText::of(&r.target).as_str());
    b.msg_u32("mask", r.mask as u32);
    b.msg_string("nexthop", IpText::of(&r.nexthop).as_str());
    if r.flags & devroute::TYPE != 0 {
        b.msg_u32("type", r.ty);
    }
    if r.flags & devroute::PROTO != 0 {
        b.msg_u32("proto", r.proto);
    }
    if r.flags & devroute::MTU != 0 {
        b.msg_u32("mtu", r.mtu);
    }
    if r.flags & devroute::METRIC != 0 {
        b.msg_u32("metric", r.metric);
    }
    if r.flags & devroute::TABLE != 0 {
        b.msg_u32("table", r.table);
    }
    if let Some(v) = r.valid_until {
        b.msg_u32("valid", valid_left(v, rtime()));
    }
    // `source` is always printed, as "<address>/<sourcemask>", even when the
    // source is unspecified and the mask is zero.
    b.msg_string("source", &format!("{}/{}", r.source, r.sourcemask));
    b.msg_close(t);
}

fn put_neighbor(b: &mut BlobBuf, n: &Neighbor) {
    let t = b.msg_open_table("");
    if let Some(m) = n.mac {
        b.msg_string("mac", &crate::device::format_macaddr(&m));
    }
    b.msg_string("address", &n.addr.to_string());
    if n.proxy != 0 {
        b.msg_u32("proxy", n.proxy);
    }
    if n.router != 0 {
        b.msg_u32("router", n.router);
    }
    b.msg_close(t);
}

impl IpSettings {
    fn dump_addresses(&self, b: &mut BlobBuf, v6: bool, enabled: bool) {
        for a in self.addresses.iter().filter(|a| a.enabled == enabled) {
            if a.addr.is_ipv6() == v6 {
                put_addr(b, a);
            }
        }
    }

    fn dump_routes(&self, b: &mut BlobBuf, enabled: bool) {
        for r in self.routes.iter().filter(|r| r.enabled == enabled) {
            // a default route is suppressed on the side `no_defaultroute`
            // does not select
            if self.no_defaultroute == enabled && r.mask == 0 {
                continue;
            }
            put_route(b, r);
        }
    }

    fn dump_dns_servers(&self, b: &mut BlobBuf, enabled: bool) {
        if self.no_dns == enabled {
            return;
        }
        for d in &self.dns_servers {
            b.msg_string("", &d.to_string());
        }
    }

    fn dump_dns_search(&self, b: &mut BlobBuf, enabled: bool) {
        if self.no_dns == enabled {
            return;
        }
        for d in &self.dns_search {
            b.msg_string("", d);
        }
    }

    fn dump_neighbors(&self, b: &mut BlobBuf, enabled: bool) {
        for n in self.neighbors.iter().filter(|n| n.enabled == enabled) {
            put_neighbor(b, n);
        }
    }

    fn dump_prefixes(b: &mut BlobBuf, prefixes: &[Prefix]) {
        for p in prefixes {
            let t = b.msg_open_table("");
            b.msg_string("address", &p.addr.to_string());
            b.msg_u32("mask", p.length as u32);
            let now = rtime();
            if let Some(v) = p.preferred_until {
                b.msg_u32("preferred", preferred_left(v, now));
            }
            if let Some(v) = p.valid_until {
                b.msg_u32("valid", valid_left(v, now));
            }
            b.msg_string("class", &p.class);
            let c = b.msg_open_table("assigned");
            for (name, addr, len) in &p.assigned {
                let d = b.msg_open_table(name);
                b.msg_string("address", &addr.to_string());
                b.msg_u32("mask", *len as u32);
                b.msg_close(d);
            }
            b.msg_close(c);
            b.msg_close(t);
        }
    }
}

impl Interface {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Read live elapsed time without searching a second name-keyed list.
    /// Standalone status probes supply uptime directly to the encoder.
    pub fn current_uptime(&self) -> u32 {
        self.started_at
            .map(|t| crate::clock::now().saturating_sub(t) as u32)
            .unwrap_or(0)
    }

    /// The daemon supplies current uptime and its global delegated-prefix
    /// view; every other field is read directly from this interface.
    pub fn dump_status_with(&self, b: &mut BlobBuf, uptime: u32, proto_prefixes: &[Prefix]) {
        b.msg_bool("up", self.state == State::Up);
        b.msg_bool("pending", self.state == State::Setup);
        b.msg_bool("available", self.available);
        b.msg_bool("autostart", self.autostart);
        b.msg_bool("dynamic", self.dynamic);

        if self.state == State::Up {
            b.msg_u32("uptime", uptime);
            if let Some(d) = &self.l3_device {
                b.msg_string("l3_device", d);
            }
        }
        if let Some(p) = &self.proto {
            b.msg_string("proto", p);
        }
        if let Some(d) = &self.device {
            b.msg_string("device", d);
        }

        if self.state == State::Up {
            if self.updated != 0 {
                let a = b.msg_open_array("updated");
                if self.updated & updated::ADDRESS != 0 {
                    b.msg_string("", "addresses");
                }
                if self.updated & updated::ROUTE != 0 {
                    b.msg_string("", "routes");
                }
                if self.updated & updated::PREFIX != 0 {
                    b.msg_string("", "prefixes");
                }
                if self.updated & updated::DATA != 0 {
                    b.msg_string("", "data");
                }
                b.msg_close(a);
            }
            if self.ip4table != 0 {
                b.msg_u32("ip4table", self.ip4table);
            }
            if self.ip6table != 0 {
                b.msg_u32("ip6table", self.ip6table);
            }
            b.msg_u32("metric", self.metric);
            b.msg_u32("dns_metric", self.dns_metric);
            b.msg_bool("delegation", !self.proto_ip.no_delegation);
            if self.assignment_weight != 0 {
                b.msg_u32("ip6weight", self.assignment_weight);
            }

            self.dump_ip_block(b, true, proto_prefixes);

            let inactive = b.msg_open_table("inactive");
            self.dump_inactive_block(b);
            b.msg_close(inactive);
        }

        let a = b.msg_open_table("data");
        if let Some(z) = &self.zone {
            b.msg_string("zone", z);
        }
        for (name, value) in &self.data {
            owrt_ubus::convert::json_to_fields(b, name, value);
        }
        b.msg_close(a);

        if !self.errors.is_empty() {
            let e = b.msg_open_array("errors");
            for err in &self.errors {
                let t = b.msg_open_table("");
                b.msg_string("subsystem", &err.subsystem);
                b.msg_string("code", &err.code);
                if !err.data.is_empty() {
                    let d = b.msg_open_array("data");
                    for v in &err.data {
                        b.msg_string("", v);
                    }
                    b.msg_close(d);
                }
                b.msg_close(t);
            }
            b.msg_close(e);
        }
    }

    /// The enabled lists: config entries then protocol entries, per list.
    fn dump_ip_block(&self, b: &mut BlobBuf, enabled: bool, proto_prefixes: &[Prefix]) {
        let a = b.msg_open_array("ipv4-address");
        self.config_ip.dump_addresses(b, false, enabled);
        self.proto_ip.dump_addresses(b, false, enabled);
        b.msg_close(a);
        let a = b.msg_open_array("ipv6-address");
        self.config_ip.dump_addresses(b, true, enabled);
        self.proto_ip.dump_addresses(b, true, enabled);
        b.msg_close(a);
        let a = b.msg_open_array("ipv6-prefix");
        IpSettings::dump_prefixes(b, &self.config_ip.prefixes);
        IpSettings::dump_prefixes(b, proto_prefixes);
        b.msg_close(a);
        let a = b.msg_open_array("ipv6-prefix-assignment");
        for p in &self.prefix_assignments {
            let t = b.msg_open_table("");
            b.msg_string("address", &p.addr.to_string());
            b.msg_u32("mask", p.length as u32);
            let now = rtime();
            if let Some(v) = p.preferred_until {
                b.msg_u32("preferred", preferred_left(v, now));
            }
            if let Some(v) = p.valid_until {
                b.msg_u32("valid", valid_left(v, now));
            }
            let c = b.msg_open_table("local-address");
            if let Some((addr, len)) = &p.local {
                b.msg_string("address", &addr.to_string());
                b.msg_u32("mask", *len as u32);
            }
            b.msg_close(c);
            b.msg_close(t);
        }
        b.msg_close(a);
        let a = b.msg_open_array("route");
        self.config_ip.dump_routes(b, enabled);
        self.proto_ip.dump_routes(b, enabled);
        b.msg_close(a);
        let a = b.msg_open_array("dns-server");
        self.config_ip.dump_dns_servers(b, enabled);
        self.proto_ip.dump_dns_servers(b, enabled);
        b.msg_close(a);
        let a = b.msg_open_array("dns-search");
        self.config_ip.dump_dns_search(b, enabled);
        self.proto_ip.dump_dns_search(b, enabled);
        b.msg_close(a);
        let a = b.msg_open_array("neighbors");
        self.config_ip.dump_neighbors(b, enabled);
        self.proto_ip.dump_neighbors(b, enabled);
        b.msg_close(a);
    }

    /// The `inactive` table holds the same lists with `enabled == false`, but
    /// not the two prefix lists — those have no inactive form.
    fn dump_inactive_block(&self, b: &mut BlobBuf) {
        let a = b.msg_open_array("ipv4-address");
        self.config_ip.dump_addresses(b, false, false);
        self.proto_ip.dump_addresses(b, false, false);
        b.msg_close(a);
        let a = b.msg_open_array("ipv6-address");
        self.config_ip.dump_addresses(b, true, false);
        self.proto_ip.dump_addresses(b, true, false);
        b.msg_close(a);
        let a = b.msg_open_array("route");
        self.config_ip.dump_routes(b, false);
        self.proto_ip.dump_routes(b, false);
        b.msg_close(a);
        let a = b.msg_open_array("dns-server");
        self.config_ip.dump_dns_servers(b, false);
        self.proto_ip.dump_dns_servers(b, false);
        b.msg_close(a);
        let a = b.msg_open_array("dns-search");
        self.config_ip.dump_dns_search(b, false);
        self.proto_ip.dump_dns_search(b, false);
        b.msg_close(a);
        let a = b.msg_open_array("neighbors");
        self.config_ip.dump_neighbors(b, false);
        self.proto_ip.dump_neighbors(b, false);
        b.msg_close(a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_lookup_preserves_first_match_and_tracks_list_changes() {
        for count in [0, 1, 2, 3, 32, 128] {
            let mut interfaces: Vec<_> = (0..count)
                .map(|n| Interface::new(&format!("interface{n:03}")))
                .collect();
            for n in 0..=count {
                let name = format!("interface{n:03}");
                let found = find_by_name(&interfaces, &name);
                assert_eq!(
                    found.map(|i| i.name.as_str()),
                    (n < count).then_some(name.as_str())
                );
            }
            for missing in ["", "Interface000", "interface", "interface000x", "z"] {
                assert!(find_by_name(&interfaces, missing).is_none());
            }
            let mut first = Interface::new("duplicate");
            first.metric = 42;
            interfaces.push(first);
            interfaces.push(Interface::new("duplicate"));
            interfaces.sort_by(|a, b| a.name.cmp(&b.name));
            assert_eq!(find_by_name(&interfaces, "duplicate").unwrap().metric, 42);
            interfaces.remove(0);
            assert_eq!(find_by_name(&interfaces, "duplicate").unwrap().metric, 0);
            interfaces.retain(|i| i.name != "duplicate");
            assert!(find_by_name(&interfaces, "duplicate").is_none());
        }
    }

    fn json(i: &Interface) -> String {
        let mut b = BlobBuf::new();
        i.dump_status_with(&mut b, 5, &i.proto_ip.prefixes);
        owrt_ubus::convert::fields_to_json(b.payload())
            .unwrap()
            .to_compact()
    }

    #[test]
    fn a_down_interface_stops_before_the_ip_block() {
        let mut i = Interface::new("lan");
        i.proto = Some("static".into());
        i.device = Some("br-lan".into());
        let j = json(&i);
        assert!(j.contains("\"up\":false"), "{j}");
        assert!(!j.contains("uptime"), "{j}");
        assert!(!j.contains("ipv4-address"), "{j}");
        // the data table is emitted whatever the state
        assert!(j.contains("\"data\""), "{j}");
    }

    #[test]
    fn an_up_interface_prints_every_list_even_when_empty() {
        let mut i = Interface::new("lan");
        i.state = State::Up;
        i.available = true;
        i.autostart = true;
        i.l3_device = Some("br-lan".into());
        i.proto = Some("static".into());
        i.device = Some("br-lan".into());
        let j = json(&i);
        for k in [
            "uptime",
            "l3_device",
            "metric",
            "dns_metric",
            "delegation",
            "ipv4-address",
            "ipv6-address",
            "ipv6-prefix",
            "ipv6-prefix-assignment",
            "route",
            "dns-server",
            "dns-search",
            "neighbors",
            "inactive",
        ] {
            assert!(j.contains(&format!("\"{k}\"")), "{k} missing from {j}");
        }
        // updated is omitted when nothing has been updated
        assert!(!j.contains("\"updated\""), "{j}");
    }

    #[test]
    fn the_status_field_order_matches_the_c() {
        let mut i = Interface::new("lan");
        i.state = State::Up;
        i.proto = Some("static".into());
        i.device = Some("br-lan".into());
        i.l3_device = Some("br-lan".into());
        i.updated = updated::ADDRESS;
        let j = json(&i);
        let order = [
            "up",
            "pending",
            "available",
            "autostart",
            "dynamic",
            "uptime",
            "l3_device",
            "proto",
            "device",
            "updated",
            "metric",
            "dns_metric",
            "delegation",
            "ipv4-address",
            "ipv6-address",
            "ipv6-prefix",
            "ipv6-prefix-assignment",
            "route",
            "dns-server",
            "dns-search",
            "neighbors",
            "inactive",
            "data",
        ];
        let mut pos = 0;
        for k in order {
            let at = j[pos..]
                .find(&format!("\"{k}\""))
                .unwrap_or_else(|| panic!("{k} missing or out of order in {j}"));
            pos += at;
        }
    }

    #[test]
    fn config_addresses_come_before_protocol_ones() {
        let mut i = Interface::new("lan");
        i.state = State::Up;
        i.config_ip
            .addresses
            .push(Address::new("192.168.1.1".parse().unwrap(), 24));
        i.proto_ip
            .addresses
            .push(Address::new("10.0.0.1".parse().unwrap(), 8));
        let j = json(&i);
        let a = j.find("192.168.1.1").unwrap();
        let b = j.find("10.0.0.1").unwrap();
        assert!(a < b, "{j}");
    }

    #[test]
    fn daemon_status_overrides_uptime_and_protocol_prefixes_without_mutating_state() {
        use owrt_ubus::json::Json;
        let prefix = |address: &str| Prefix {
            addr: address.parse().unwrap(),
            length: 64,
            preferred_until: None,
            valid_until: None,
            class: "wan6".into(),
            assigned: Vec::new(),
        };
        let mut i = Interface::new("wan6");
        i.state = State::Up;
        i.started_at = Some(1);
        i.config_ip.prefixes.push(prefix("fd00:1::"));
        i.proto_ip.prefixes.push(prefix("2001:db8:1::"));
        i.proto_ip
            .addresses
            .push(Address::new("2001:db8::1".parse().unwrap(), 64));
        let mut current = prefix("2001:db8:2::");
        current
            .assigned
            .push(("lan".into(), "2001:db8:2::".parse().unwrap(), 64));
        let mut b = BlobBuf::new();
        i.dump_status_with(&mut b, 77, &[current]);
        let j = owrt_ubus::convert::fields_to_json(b.payload()).unwrap();
        assert_eq!(j.get("uptime"), Some(&Json::Int(77)));
        let Some(Json::Array(prefixes)) = j.get("ipv6-prefix") else {
            panic!("missing prefixes")
        };
        assert_eq!(prefixes.len(), 2);
        assert_eq!(
            prefixes[0].get("address").and_then(Json::as_str),
            Some("fd00:1::")
        );
        assert_eq!(
            prefixes[1].get("address").and_then(Json::as_str),
            Some("2001:db8:2::")
        );
        assert!(prefixes[1].get("assigned").unwrap().get("lan").is_some());
        assert_eq!(i.started_at, Some(1));
        assert_eq!(
            i.proto_ip.prefixes[0].addr,
            "2001:db8:1::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(i.proto_ip.addresses.len(), 1);
        // An empty live prefix view removes stale delegated prefixes, while
        // configuration-owned prefixes and the base interface remain intact.
        b.reset();
        i.dump_status_with(&mut b, 78, &[]);
        let j = owrt_ubus::convert::fields_to_json(b.payload()).unwrap();
        let Some(Json::Array(prefixes)) = j.get("ipv6-prefix") else {
            panic!("missing prefixes")
        };
        assert_eq!(prefixes.len(), 1);
        i.state = State::Down;
        b.reset();
        i.dump_status_with(&mut b, 79, &[]);
        let j = owrt_ubus::convert::fields_to_json(b.payload()).unwrap();
        assert!(j.get("uptime").is_none() && j.get("ipv6-prefix").is_none());
    }

    #[test]
    fn disabled_addresses_move_to_inactive() {
        let mut i = Interface::new("lan");
        i.state = State::Up;
        let mut a = Address::new("192.168.1.1".parse().unwrap(), 24);
        a.enabled = false;
        i.config_ip.addresses.push(a);
        let j = json(&i);
        let inactive_at = j.find("\"inactive\"").unwrap();
        let addr_at = j.find("192.168.1.1").unwrap();
        assert!(addr_at > inactive_at, "{j}");
    }

    #[test]
    fn a_route_always_prints_its_source_even_when_unset() {
        let mut i = Interface::new("wan");
        i.state = State::Up;
        i.proto_ip.routes.push(Route::new(
            "0.0.0.0".parse().unwrap(),
            0,
            "10.0.0.2".parse().unwrap(),
        ));
        let j = json(&i);
        assert!(j.contains("\"source\":\"0.0.0.0/0\""), "{j}");
        // flags are clear, so none of the optional numeric fields appear
        assert!(!j.contains("\"metric\":0,\"table\""), "{j}");
    }

    #[test]
    fn no_defaultroute_moves_only_the_default_route() {
        let mut i = Interface::new("wan");
        i.state = State::Up;
        i.proto_ip.no_defaultroute = true;
        i.proto_ip.routes.push(Route::new(
            "0.0.0.0".parse().unwrap(),
            0,
            "10.0.0.2".parse().unwrap(),
        ));
        i.proto_ip.routes.push(Route::new(
            "10.9.0.0".parse().unwrap(),
            24,
            "10.0.0.2".parse().unwrap(),
        ));
        let j = json(&i);
        let inactive_at = j.find("\"inactive\"").unwrap();
        assert!(j.find("10.9.0.0").unwrap() < inactive_at, "{j}");
        // the enabled side skips the default route; it is not in inactive
        // either, because its `enabled` flag is still true
        assert!(!j.contains("\"target\":\"0.0.0.0\""), "{j}");
    }

    #[test]
    fn route_order_is_longest_mask_then_metric() {
        let mut a = Route::new("10.0.0.0".parse().unwrap(), 8, "0.0.0.0".parse().unwrap());
        let mut b = Route::new("10.1.0.0".parse().unwrap(), 16, "0.0.0.0".parse().unwrap());
        assert_eq!(route_order(&b, &a), std::cmp::Ordering::Less);
        a.mask = 16;
        a.metric = 5;
        b.metric = 1;
        assert_eq!(route_order(&b, &a), std::cmp::Ordering::Less);
        // equal mask and metric: flags descending
        a.metric = 1;
        a.flags = devroute::METRIC;
        assert_eq!(route_order(&a, &b), std::cmp::Ordering::Less);
    }

    #[test]
    fn delegation_is_the_negation_of_no_delegation() {
        let mut i = Interface::new("lan");
        i.state = State::Up;
        assert!(json(&i).contains("\"delegation\":true"));
        i.proto_ip.no_delegation = true;
        assert!(json(&i).contains("\"delegation\":false"));
    }

    #[test]
    fn an_unassigned_prefix_still_prints_an_empty_local_address_table() {
        let mut i = Interface::new("lan");
        i.state = State::Up;
        i.prefix_assignments.push(PrefixAssignment {
            addr: "2001:db8::".parse().unwrap(),
            length: 64,
            preferred_until: Some(rtime() + 1800),
            valid_until: Some(rtime() + 3600),
            local: None,
            owner: None,
        });
        let j = json(&i);
        assert!(j.contains("\"local-address\":{}"), "{j}");
    }

    #[test]
    fn errors_are_appended_after_data() {
        let mut i = Interface::new("lan");
        i.errors.push(IfaceError {
            subsystem: "interface".into(),
            code: "NO_DEVICE".into(),
            data: vec![],
        });
        let j = json(&i);
        assert!(
            j.find("\"data\"").unwrap() < j.find("\"errors\"").unwrap(),
            "{j}"
        );
        assert!(j.contains("\"code\":\"NO_DEVICE\""), "{j}");
        // no `data` array inside the error when there is none
        assert!(!j.contains("\"data\":[]"), "{j}");
    }
}
