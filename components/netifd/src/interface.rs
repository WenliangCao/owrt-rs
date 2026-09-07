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
    pub point_to_point: Option<IpAddr>,
    /// Seconds remaining; `None` means the field is omitted.
    pub preferred: Option<u32>,
    pub valid: Option<u32>,
    pub class: Option<String>,
    /// Applied to the device, as opposed to held back — the `inactive` table.
    pub enabled: bool,
}

impl Address {
    pub fn new(addr: IpAddr, mask: u8) -> Self {
        Self {
            addr,
            mask,
            point_to_point: None,
            preferred: None,
            valid: None,
            class: None,
            enabled: true,
        }
    }
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
    pub valid: Option<u32>,
    pub enabled: bool,
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
            valid: None,
            enabled: true,
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
    pub preferred: Option<u32>,
    pub valid: Option<u32>,
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
    pub preferred: Option<u32>,
    pub valid: Option<u32>,
    /// `local-address` is an empty table when the assignment is not enabled.
    pub local: Option<(Ipv6Addr, u8)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpSettings {
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

/// One interface.
#[derive(Clone, Debug, Default)]
pub struct Interface {
    pub name: String,
    pub state: State,
    pub available: bool,
    pub autostart: bool,
    pub dynamic: bool,
    /// Seconds since the interface came up; only printed while up.
    pub uptime: u32,
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

fn put_addr(b: &mut BlobBuf, a: &Address) {
    let t = b.msg_open_table("");
    b.msg_string("address", &a.addr.to_string());
    b.msg_u32("mask", a.mask as u32);
    if let Some(p) = a.point_to_point {
        b.msg_string("ptpaddress", &p.to_string());
    }
    if let Some(p) = a.preferred {
        b.msg_u32("preferred", p);
    }
    if let Some(v) = a.valid {
        b.msg_u32("valid", v);
    }
    if let Some(c) = &a.class {
        b.msg_string("class", c);
    }
    b.msg_close(t);
}

fn put_route(b: &mut BlobBuf, r: &Route) {
    let t = b.msg_open_table("");
    b.msg_string("target", &r.target.to_string());
    b.msg_u32("mask", r.mask as u32);
    b.msg_string("nexthop", &r.nexthop.to_string());
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
    if let Some(v) = r.valid {
        b.msg_u32("valid", v);
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

    fn dump_prefixes(&self, b: &mut BlobBuf) {
        for p in &self.prefixes {
            let t = b.msg_open_table("");
            b.msg_string("address", &p.addr.to_string());
            b.msg_u32("mask", p.length as u32);
            if let Some(v) = p.preferred {
                b.msg_u32("preferred", v);
            }
            if let Some(v) = p.valid {
                b.msg_u32("valid", v);
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
        Self { name: name.to_string(), ..Default::default() }
    }

    /// `netifd_dump_status`, field for field.
    pub fn dump_status(&self, b: &mut BlobBuf) {
        b.msg_bool("up", self.state == State::Up);
        b.msg_bool("pending", self.state == State::Setup);
        b.msg_bool("available", self.available);
        b.msg_bool("autostart", self.autostart);
        b.msg_bool("dynamic", self.dynamic);

        if self.state == State::Up {
            b.msg_u32("uptime", self.uptime);
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

            self.dump_ip_block(b, true);

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
    fn dump_ip_block(&self, b: &mut BlobBuf, enabled: bool) {
        let a = b.msg_open_array("ipv4-address");
        self.config_ip.dump_addresses(b, false, enabled);
        self.proto_ip.dump_addresses(b, false, enabled);
        b.msg_close(a);
        let a = b.msg_open_array("ipv6-address");
        self.config_ip.dump_addresses(b, true, enabled);
        self.proto_ip.dump_addresses(b, true, enabled);
        b.msg_close(a);
        let a = b.msg_open_array("ipv6-prefix");
        self.config_ip.dump_prefixes(b);
        self.proto_ip.dump_prefixes(b);
        b.msg_close(a);
        let a = b.msg_open_array("ipv6-prefix-assignment");
        for p in &self.prefix_assignments {
            let t = b.msg_open_table("");
            b.msg_string("address", &p.addr.to_string());
            b.msg_u32("mask", p.length as u32);
            if let Some(v) = p.preferred {
                b.msg_u32("preferred", v);
            }
            if let Some(v) = p.valid {
                b.msg_u32("valid", v);
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

    fn json(i: &Interface) -> String {
        let mut b = BlobBuf::new();
        i.dump_status(&mut b);
        owrt_ubus::convert::fields_to_json(b.payload()).to_compact()
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
        i.uptime = 5;
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
        i.config_ip.addresses.push(Address::new("192.168.1.1".parse().unwrap(), 24));
        i.proto_ip.addresses.push(Address::new("10.0.0.1".parse().unwrap(), 8));
        let j = json(&i);
        let a = j.find("192.168.1.1").unwrap();
        let b = j.find("10.0.0.1").unwrap();
        assert!(a < b, "{j}");
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
            preferred: Some(1800),
            valid: Some(3600),
            local: None,
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
        assert!(j.find("\"data\"").unwrap() < j.find("\"errors\"").unwrap(), "{j}");
        assert!(j.contains("\"code\":\"NO_DEVICE\""), "{j}");
        // no `data` array inside the error when there is none
        assert!(!j.contains("\"data\":[]"), "{j}");
    }
}
