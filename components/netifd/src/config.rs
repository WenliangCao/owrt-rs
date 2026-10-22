//! `/etc/config/network` → the device and interface model.
//!
//! Unsupported sections produce warnings while the remaining configuration
//! stays usable, matching netifd reload behavior. Invalid static IP settings
//! are retained as setup errors for the affected interface.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use owrt_uci::model::{OptionValue, Package, Section};

/// A configuration problem, named by the section it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub section: String,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.section, self.message)
    }
}

impl std::error::Error for ConfigError {}

/// Section types netifd knows but this build does not implement. Naming them
/// separately keeps the error specific ("bonding is not supported") rather
/// than "unknown section".
const OUT_OF_SCOPE: &[&str] = &[
    "rule",
    "rule6",
    "switch",
    "switch_vlan",
    "switch_port",
    "bridge-vlan",
];

/// One `config route` / `config route6` section (`config_parse_route` →
/// `interface_ip_add_route(NULL, ...)`): it lands in the named interface's
/// `config_ip`; with no `interface` it goes to `loopback` with DEVROUTE_NODEV.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRoute {
    pub interface: String,
    pub route: crate::interface::Route,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Globals {
    pub ula_prefix: Option<(Ipv6Addr, u8)>,
    pub packet_steering: Option<u32>,
    pub dhcp_default_duid: Option<String>,
    pub steering_flows: Option<u32>,
}

/// A `config device` section: a device netifd creates or configures, as
/// opposed to one the kernel already provides.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceConfig {
    pub name: String,
    /// `bridge`, `8021q`, … `None` means "settings for an existing device".
    pub kind: Option<String>,
    pub ports: Vec<String>,
    pub macaddr: Option<[u8; 6]>,
    pub mtu: Option<u32>,
    pub mtu6: Option<u32>,
    pub txqueuelen: Option<u32>,
    pub ipv6: Option<bool>,
    pub promisc: Option<bool>,
    pub multicast: Option<bool>,
    pub stp: Option<bool>,
    pub igmp_snooping: Option<bool>,
    pub bridge_empty: Option<bool>,
    pub vlan_filtering: Option<bool>,
    pub priority: Option<u16>,
    pub forward_delay: Option<u32>,
    pub hello_time: Option<u32>,
    pub max_age: Option<u32>,
    pub ageing_time: Option<u32>,
}

/// A `config interface` section.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: String,
    pub device: Option<String>,
    pub proto: String,
    pub auto: Option<bool>,
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub ipv6: Vec<(Ipv6Addr, u8)>,
    pub gateway: Option<Ipv4Addr>,
    pub ip6gw: Option<Ipv6Addr>,
    pub ip6assign: Option<u8>,
    pub ip6hint: Option<u32>,
    pub metric: u32,
    pub dns_metric: u32,
    /// `checkup_interval`: seconds after the setup script exits before an
    /// interface that is still setting up is torn down again.
    pub checkup_interval: Option<u32>,
    pub dns: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub ip4table: Option<u32>,
    pub ip6table: Option<u32>,
    pub delegate: Option<bool>,
    pub force_link: Option<bool>,
    pub defaultroute: Option<bool>,
    pub peerdns: Option<bool>,
    /// `proto_apply_static_settings`'s `goto error`: an unparsable static
    /// option is a warning at parse time but a failed SETUP at run time --
    /// the interface is marked down with this ("proto", code, value) error,
    /// as the C's `interface_add_error` records it (r61 bad-addr).
    pub static_error: Option<(String, String)>,
    /// Options this build does not interpret but the proto handler might;
    /// passed through to proto-shell verbatim.
    pub extra: BTreeMap<String, Vec<String>>,
    /// Every option of the section, in file order, with whether it was written
    /// as a `list`. proto-shell needs this to rebuild the config document the
    /// C hands its scripts.
    pub raw: Vec<RawOpt>,
}

/// One option as it appeared in the file.
#[derive(Clone, PartialEq, Eq)]
pub struct RawOpt {
    pub name: String,
    pub values: Vec<String>,
    /// `list foo 'x'` rather than `option foo 'x'`.
    pub is_list: bool,
}

// Protocol options include passwords and private keys. Debug is an operational
// summary; the original values remain available to the protocol and ubus code.
impl fmt::Debug for InterfaceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceConfig")
            .field("name", &self.name)
            .field("device", &self.device)
            .field("proto", &self.proto)
            .field("auto", &self.auto)
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .field("extra_count", &self.extra.len())
            .field("raw_count", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RawOpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawOpt")
            .field("name", &self.name)
            .field("value_count", &self.values.len())
            .field("is_list", &self.is_list)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub globals: Globals,
    pub devices: Vec<DeviceConfig>,
    pub interfaces: Vec<InterfaceConfig>,
    pub routes: Vec<StaticRoute>,
    /// What was skipped or ignored, one line each. The C never refuses a
    /// configuration over a section it cannot use -- it logs and moves on --
    /// and neither does this build any more: refusing every later reload over
    /// one `config rule` was R81 F14.
    pub warnings: Vec<ConfigError>,
    /// Reserved for a problem that makes the whole document unusable; nothing
    /// the parser sees today is one.
    pub errors: Vec<ConfigError>,
}

fn opt<'a>(s: &'a Section, name: &str) -> Option<&'a OptionValue> {
    s.options.iter().find(|o| o.name == name).map(|o| &o.value)
}

fn s_opt(s: &Section, name: &str) -> Option<String> {
    match opt(s, name)? {
        OptionValue::Str(v) => Some(String::from_utf8_lossy(v).into_owned()),
        // uci_to_blob turns a list into a space-joined string when the target
        // expects a scalar; netifd sees the same
        OptionValue::List(v) => Some(
            v.iter()
                .map(|x| String::from_utf8_lossy(x).into_owned())
                .collect::<Vec<_>>()
                .join(" "),
        ),
    }
}

/// A list option, also accepting the space-separated scalar form netifd's
/// `blobmsg_parse` produces for `BLOBMSG_TYPE_ARRAY` from a plain option.
fn l_opt(s: &Section, name: &str) -> Vec<String> {
    match opt(s, name) {
        Some(OptionValue::List(v)) => v
            .iter()
            .map(|x| String::from_utf8_lossy(x).into_owned())
            .collect(),
        Some(OptionValue::Str(v)) => String::from_utf8_lossy(v)
            .split_whitespace()
            .map(|x| x.to_string())
            .collect(),
        None => Vec::new(),
    }
}

/// UCI's boolean spelling: `1/on/true/enabled/yes` are true, everything else
/// false. netifd goes through blobmsg_parse, which uses the same set.
fn b_opt(s: &Section, name: &str) -> Option<bool> {
    let v = s_opt(s, name)?;
    Some(matches!(
        v.as_str(),
        "1" | "on" | "true" | "enabled" | "yes"
    ))
}

fn n_opt<T: std::str::FromStr>(s: &Section, name: &str) -> Option<T> {
    s_opt(s, name)?.parse().ok()
}

/// `aa:bb:cc:dd:ee:ff`, the only form netifd accepts.
pub fn parse_macaddr(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        m[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(m)
}

/// `1.2.3.4/24`, `1.2.3.4/255.255.255.0` or a bare address with a separate
/// `netmask`. Returns the prefix length.
fn parse_v4(spec: &str, netmask: Option<&str>) -> Option<(Ipv4Addr, u8)> {
    let (addr, mask) = match spec.split_once('/') {
        Some((a, m)) => (a, Some(m.to_string())),
        None => (spec, netmask.map(|s| s.to_string())),
    };
    let ip: Ipv4Addr = addr.trim().parse().ok()?;
    let len = match mask {
        None => 32,
        Some(m) if m.contains('.') => {
            let nm: Ipv4Addr = m.parse().ok()?;
            let bits = u32::from_be_bytes(nm.octets());
            // a netmask must be contiguous; netifd rejects anything else
            if bits.leading_ones() + bits.trailing_zeros() != 32 {
                return None;
            }
            bits.leading_ones() as u8
        }
        Some(m) => {
            let n: u8 = m.trim().parse().ok()?;
            if n > 32 {
                return None;
            }
            n
        }
    };
    Some((ip, len))
}

fn parse_v6(spec: &str) -> Option<(Ipv6Addr, u8)> {
    let (addr, mask) = match spec.split_once('/') {
        Some((a, m)) => (a, m.trim().parse::<u8>().ok()?),
        None => (spec, 128),
    };
    if mask > 128 {
        return None;
    }
    Some((addr.trim().parse().ok()?, mask))
}

/// Option names an `interface` section may carry that this build consumes.
/// Anything else goes into `extra` for the proto handler.
const KNOWN_IFACE_OPTS: &[&str] = &[
    "device",
    "ifname",
    "proto",
    "auto",
    "disabled",
    "ipaddr",
    "netmask",
    "ip6addr",
    "gateway",
    "ip6gw",
    "ip6assign",
    "ip6hint",
    "metric",
    "dns_metric",
    "checkup_interval",
    "dns",
    "dns_search",
    "ip4table",
    "ip6table",
    "delegate",
    "force_link",
    "defaultroute",
    "peerdns",
    "type",
];

/// Parse a loaded `network` package.
pub fn parse(pkg: &Package) -> Config {
    let mut c = Config::default();
    for s in &pkg.sections {
        let where_ = format!("{} '{}'", s.ty, s.name);
        match s.ty.as_str() {
            "globals" => parse_globals(s, &mut c, &where_),
            "device" => parse_device(s, &mut c, &where_),
            "interface" => parse_interface(s, &mut c, &where_),
            "route" => parse_route(s, false, &mut c, &where_),
            "route6" => parse_route(s, true, &mut c, &where_),
            t if OUT_OF_SCOPE.contains(&t) => c.warnings.push(ConfigError {
                section: where_,
                message: format!("section type '{t}' is not supported by this build"),
            }),
            t => c.warnings.push(ConfigError {
                section: where_,
                message: format!("unknown section type '{t}'"),
            }),
        }
    }
    c
}

fn parse_globals(s: &Section, c: &mut Config, where_: &str) {
    if let Some(v) = s_opt(s, "ula_prefix") {
        match parse_v6(&v) {
            Some(p) => c.globals.ula_prefix = Some(p),
            None => c.warnings.push(ConfigError {
                section: where_.to_string(),
                message: format!("ula_prefix '{v}' is not an IPv6 prefix"),
            }),
        }
    }
    c.globals.packet_steering = n_opt(s, "packet_steering");
    c.globals.steering_flows = n_opt(s, "steering_flows");
    c.globals.dhcp_default_duid = s_opt(s, "dhcp_default_duid");
}

fn parse_device(s: &Section, c: &mut Config, where_: &str) {
    let Some(name) = s_opt(s, "name") else {
        c.warnings.push(ConfigError {
            section: where_.to_string(),
            message: "device section without a name".into(),
        });
        return;
    };
    let kind = s_opt(s, "type");
    if let Some(k) = &kind {
        if k != "bridge" {
            c.warnings.push(ConfigError {
                section: where_.to_string(),
                message: format!("device type '{k}' is not supported by this build"),
            });
            return;
        }
    }
    let mut d = DeviceConfig {
        name,
        kind,
        ..Default::default()
    };
    d.ports = l_opt(s, "ports");
    if d.ports.is_empty() {
        // `ifname` is the pre-21.02 spelling and still accepted
        d.ports = l_opt(s, "ifname");
    }
    if let Some(m) = s_opt(s, "macaddr") {
        match parse_macaddr(&m) {
            Some(mac) => d.macaddr = Some(mac),
            None => c.warnings.push(ConfigError {
                section: where_.to_string(),
                message: format!("macaddr '{m}' is not a MAC address"),
            }),
        }
    }
    d.mtu = n_opt(s, "mtu");
    d.mtu6 = n_opt(s, "mtu6");
    d.txqueuelen = n_opt(s, "txqueuelen");
    d.ipv6 = b_opt(s, "ipv6");
    d.promisc = b_opt(s, "promisc");
    d.multicast = b_opt(s, "multicast");
    d.stp = b_opt(s, "stp");
    d.igmp_snooping = b_opt(s, "igmp_snooping");
    d.bridge_empty = b_opt(s, "bridge_empty");
    d.vlan_filtering = b_opt(s, "vlan_filtering");
    d.priority = n_opt(s, "priority");
    d.forward_delay = n_opt(s, "forward_delay");
    d.hello_time = n_opt(s, "hello_time");
    d.max_age = n_opt(s, "max_age");
    d.ageing_time = n_opt(s, "ageing_time");
    c.devices.push(d);
}

/// `interface_ip_add_route` for a UCI section. Field by field what the C
/// parses, and every parse failure drops the whole route with a warning, as
/// its `goto error` does. `valid` is not carried: the C turns it into a
/// deadline at parse time, which no static route on this device uses.
/// `parse_netmask_string` for a route section: a prefix length, or a dotted
/// quad (v4 only, `32 - fls(~mask)`, not a contiguity check). `u32::MAX` is
/// the C's `~0` for a string it rejects.
fn parse_netmask_str(s: &str, v6: bool) -> u32 {
    if !s.contains('.') {
        return s.trim().parse::<u32>().unwrap_or(u32::MAX);
    }
    if v6 {
        return u32::MAX;
    }
    match s.parse::<Ipv4Addr>() {
        Ok(nm) => {
            let inv = !u32::from_be_bytes(nm.octets());
            32 - if inv == 0 {
                0
            } else {
                32 - inv.leading_zeros()
            }
        }
        Err(_) => u32::MAX,
    }
}

fn parse_route(s: &Section, v6: bool, c: &mut Config, where_: &str) {
    use crate::interface::{devroute, Route};
    let warn = |c: &mut Config, m: String| {
        c.warnings.push(ConfigError {
            section: where_.to_string(),
            message: m,
        })
    };
    if b_opt(s, "disabled").unwrap_or(false) {
        return;
    }
    let max: u32 = if v6 { 128 } else { 32 };
    let unspec: IpAddr = if v6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let parse_ip = |s: &str| -> Option<IpAddr> {
        if v6 {
            s.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
        } else {
            s.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
        }
    };
    let mut mask = max as u8;
    if let Some(m) = s_opt(s, "netmask") {
        let n = parse_netmask_str(&m, v6);
        if n > max {
            warn(c, format!("route netmask '{m}' is invalid"));
            return;
        }
        mask = n as u8;
    }
    let mut target = unspec;
    if let Some(t) = s_opt(s, "target") {
        let (astr, m) = match t.split_once('/') {
            Some((a, m)) => {
                let n = parse_netmask_str(m, v6);
                if n > max {
                    warn(c, format!("Failed to parse route target: {t}"));
                    return;
                }
                (a.to_string(), n as u8)
            }
            None => (t.clone(), mask),
        };
        mask = m;
        let Some(a) = parse_ip(&astr) else {
            warn(c, format!("Failed to parse route target: {t}"));
            return;
        };
        target = a;
        // "Mask out IPv4 host bits"
        if let (IpAddr::V4(v4), true) = (target, !v6 && mask < 32) {
            let bits = u32::from_be_bytes(v4.octets());
            let keep = if mask == 0 {
                0
            } else {
                u32::MAX << (32 - mask)
            };
            target = IpAddr::V4(Ipv4Addr::from(bits & keep));
        }
    }
    let mut r = Route::new(target, mask, unspec);
    if let Some(g) = s_opt(s, "gateway") {
        let Some(nh) = parse_ip(&g) else {
            warn(c, format!("Failed to parse route gateway: {g}"));
            return;
        };
        r.nexthop = nh;
    }
    if let Some(m) = n_opt::<u32>(s, "metric") {
        r.metric = m;
        r.flags |= devroute::METRIC;
    }
    if let Some(m) = n_opt::<u32>(s, "mtu") {
        r.mtu = m;
        r.flags |= devroute::MTU;
    }
    if let Some(src) = s_opt(s, "source") {
        let (a, m) = match src.split_once('/') {
            Some((a, m)) => (a.to_string(), Some(m.to_string())),
            None => (src.clone(), None),
        };
        let Some(sa) = parse_ip(&a) else {
            warn(c, format!("Failed to parse route source: {a}"));
            return;
        };
        r.source = sa;
        r.sourcemask = match m {
            Some(m) => match m.parse::<u32>() {
                Ok(v) if v <= max => v as u8,
                _ => {
                    warn(c, format!("Invalid route source mask: {m}"));
                    return;
                }
            },
            None => max as u8,
        };
    }
    if b_opt(s, "onlink").unwrap_or(false) {
        r.flags |= devroute::ONLINK;
    }
    if let Some(t) = s_opt(s, "table") {
        let Some(table) = crate::rt::resolve_rt_table(&t) else {
            warn(c, format!("Failed to resolve routing table: {t}"));
            return;
        };
        // "only set the table flag if not using the main (default) table"
        r.table = if table == 254 { 0 } else { table };
        if r.table != 0 {
            r.flags |= devroute::TABLE;
        }
    }
    if let Some(t) = s_opt(s, "type") {
        let Some(ty) = crate::rt::resolve_rt_type(&t) else {
            warn(c, format!("Failed to resolve routing type: {t}"));
            return;
        };
        r.ty = ty;
        r.flags |= devroute::TYPE;
    }
    if let Some(p) = s_opt(s, "proto") {
        let Some(proto) = crate::rt::resolve_rt_proto(&p) else {
            warn(c, format!("Failed to resolve proto type: {p}"));
            return;
        };
        r.proto = proto;
        r.flags |= devroute::PROTO;
    }
    if s_opt(s, "valid").is_some() {
        warn(
            c,
            "route option 'valid' is not carried by this build".into(),
        );
    }
    let interface = match s_opt(s, "interface") {
        Some(i) => i,
        None => {
            r.flags |= devroute::NODEV;
            "loopback".to_string()
        }
    };
    c.routes.push(StaticRoute {
        interface,
        route: r,
    });
}

fn parse_interface(s: &Section, c: &mut Config, where_: &str) {
    let mut i = InterfaceConfig {
        name: s.name.clone(),
        ..Default::default()
    };
    i.proto = s_opt(s, "proto").unwrap_or_default();
    if i.proto.is_empty() {
        c.warnings.push(ConfigError {
            section: where_.to_string(),
            message: "interface without a proto".into(),
        });
        return;
    }
    i.device = s_opt(s, "device").or_else(|| s_opt(s, "ifname"));
    i.auto = b_opt(s, "auto");
    // `config_parse_interface`: `disabled` "1" or "true" (exactly those) skips
    // the section entirely -- no interface object, no ubus object, nothing
    // in the dump. Creating it with autostart off was R81 F13.
    if matches!(s_opt(s, "disabled").as_deref(), Some("1") | Some("true")) {
        return;
    }

    let netmask = s_opt(s, "netmask");
    for a in l_opt(s, "ipaddr") {
        match parse_v4(&a, netmask.as_deref()) {
            Some(v) => i.ipv4.push(v),
            None => {
                c.warnings.push(ConfigError {
                    section: where_.to_string(),
                    message: format!("ipaddr '{a}' is not an IPv4 address"),
                });
                i.static_error
                    .get_or_insert(("INVALID_ADDRESS".into(), a.clone()));
            }
        }
    }
    for a in l_opt(s, "ip6addr") {
        match parse_v6(&a) {
            Some(v) => i.ipv6.push(v),
            None => {
                c.warnings.push(ConfigError {
                    section: where_.to_string(),
                    message: format!("ip6addr '{a}' is not an IPv6 address"),
                });
                i.static_error
                    .get_or_insert(("INVALID_ADDRESS".into(), a.clone()));
            }
        }
    }
    for (name, code) in [("gateway", "INVALID_GATEWAY"), ("ip6gw", "INVALID_GATEWAY")] {
        if let Some(v) = s_opt(s, name) {
            let ok = if name == "gateway" {
                v.parse::<Ipv4Addr>().is_ok()
            } else {
                v.parse::<Ipv6Addr>().is_ok()
            };
            if !ok {
                c.warnings.push(ConfigError {
                    section: where_.to_string(),
                    message: format!("{name} '{v}' is not an address"),
                });
                i.static_error.get_or_insert((code.into(), v));
            }
        }
    }
    i.gateway = s_opt(s, "gateway").and_then(|v| v.parse().ok());
    i.ip6gw = s_opt(s, "ip6gw").and_then(|v| v.parse().ok());
    if let Some(v) = n_opt::<u8>(s, "ip6assign") {
        if v > 64 {
            c.warnings.push(ConfigError {
                section: where_.to_string(),
                message: format!("ip6assign {v} is longer than a /64"),
            });
        } else {
            i.ip6assign = Some(v);
        }
    }
    i.ip6hint = s_opt(s, "ip6hint").and_then(|v| u32::from_str_radix(v.trim(), 16).ok());
    i.metric = n_opt(s, "metric").unwrap_or(0);
    i.dns_metric = n_opt(s, "dns_metric").unwrap_or(0);
    i.checkup_interval = n_opt(s, "checkup_interval");
    for d in l_opt(s, "dns") {
        match d.parse::<IpAddr>() {
            Ok(a) => i.dns.push(a),
            Err(_) => c.warnings.push(ConfigError {
                section: where_.to_string(),
                message: format!("dns '{d}' is not an IP address"),
            }),
        }
    }
    i.dns_search = l_opt(s, "dns_search");
    i.ip4table = n_opt(s, "ip4table");
    i.ip6table = n_opt(s, "ip6table");
    i.delegate = b_opt(s, "delegate");
    i.force_link = b_opt(s, "force_link");
    i.defaultroute = b_opt(s, "defaultroute");
    i.peerdns = b_opt(s, "peerdns");

    for o in &s.options {
        let is_list = matches!(o.value, OptionValue::List(_));
        i.raw.push(RawOpt {
            name: o.name.clone(),
            values: l_opt(s, &o.name),
            is_list,
        });
        if KNOWN_IFACE_OPTS.contains(&o.name.as_str()) {
            continue;
        }
        i.extra.insert(o.name.clone(), l_opt(s, &o.name));
    }
    c.interfaces.push(i);
}

/// Load and parse `<confdir>/network`.
pub fn load(confdir: &str) -> Result<Config, String> {
    let mut ctx = owrt_uci::context::Context::new();
    ctx.confdir = confdir.to_string();
    let idx = owrt_uci::file::load(&mut ctx, "network").map_err(|e| format!("{e:?}"))?;
    Ok(parse(&ctx.root[idx]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_debug_does_not_disclose_protocol_credentials() {
        let secret = "pppoe-password-that-must-not-be-logged";
        let raw = RawOpt {
            name: "password".into(),
            values: vec![secret.into()],
            is_list: false,
        };
        let mut config = InterfaceConfig {
            name: "wan".into(),
            proto: "pppoe".into(),
            ..Default::default()
        };
        config.extra.insert("password".into(), vec![secret.into()]);
        config.raw.push(raw.clone());
        for debug in [
            format!("{raw:?}"),
            format!("{config:?}"),
            format!("{config:#?}"),
        ] {
            assert!(!debug.contains(secret), "credential leaked: {debug}");
        }
        assert_eq!(config.extra["password"], [secret]);
        assert_eq!(config.raw[0].values, [secret]);
    }

    fn pkg(text: &str) -> Package {
        // tests run in parallel and each writes its own `network` file, so the
        // directory has to be unique per call, not per process
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "netifd-cfg-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("network"), text).unwrap();
        let mut ctx = owrt_uci::context::Context::new();
        ctx.confdir = dir.to_string_lossy().into_owned();
        let idx = owrt_uci::file::load(&mut ctx, "network").unwrap();
        ctx.root[idx].clone()
    }

    #[test]
    fn the_device_config_round_trips() {
        let c = parse(&pkg(
            "config device\n\toption name 'br-lan'\n\toption type 'bridge'\n\
             \tlist ports 'lan2'\n\tlist ports 'lan3'\n\toption macaddr '02:00:00:00:00:01'\n",
        ));
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        assert_eq!(c.devices.len(), 1);
        let d = &c.devices[0];
        assert_eq!(d.name, "br-lan");
        assert_eq!(d.kind.as_deref(), Some("bridge"));
        assert_eq!(d.ports, vec!["lan2", "lan3"]);
        assert_eq!(d.macaddr, Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
    }

    #[test]
    fn an_unsupported_device_type_is_a_warning_and_a_skip() {
        let c = parse(&pkg(
            "config device\n\toption name 'bond0'\n\toption type 'bonding'\n",
        ));
        assert!(c.devices.is_empty());
        assert_eq!(c.warnings.len(), 1);
        assert!(
            c.warnings[0].message.contains("bonding"),
            "{:?}",
            c.warnings
        );
    }

    #[test]
    fn out_of_scope_sections_name_themselves() {
        let c = parse(&pkg("config rule\n\toption lookup '100'\n"));
        assert_eq!(c.warnings.len(), 1);
        assert!(
            c.warnings[0].message.contains("'rule' is not supported"),
            "{:?}",
            c.warnings
        );
    }

    #[test]
    fn an_unknown_section_type_is_reported_separately() {
        let c = parse(&pkg("config wombat 'x'\n"));
        assert_eq!(c.warnings.len(), 1);
        assert!(
            c.warnings[0].message.contains("unknown section type"),
            "{:?}",
            c.warnings
        );
    }

    #[test]
    fn ipaddr_accepts_both_mask_spellings() {
        let c = parse(&pkg(
            "config interface lan\n\toption proto 'static'\n\toption ipaddr '192.168.1.1/24'\n\n\
             config interface old\n\toption proto 'static'\n\toption ipaddr '10.0.0.1'\n\
             \toption netmask '255.255.255.0'\n",
        ));
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        assert_eq!(
            c.interfaces[0].ipv4,
            vec![("192.168.1.1".parse().unwrap(), 24)]
        );
        assert_eq!(
            c.interfaces[1].ipv4,
            vec![("10.0.0.1".parse().unwrap(), 24)]
        );
    }

    #[test]
    fn a_bare_ipaddr_with_no_netmask_is_a_host_route() {
        let c = parse(&pkg(
            "config interface lan\n\toption proto 'static'\n\toption ipaddr '10.0.0.1'\n",
        ));
        assert_eq!(
            c.interfaces[0].ipv4,
            vec![("10.0.0.1".parse().unwrap(), 32)]
        );
    }

    #[test]
    fn a_non_contiguous_netmask_is_rejected() {
        let c = parse(&pkg(
            "config interface lan\n\toption proto 'static'\n\toption ipaddr '10.0.0.1'\n\
             \toption netmask '255.0.255.0'\n",
        ));
        assert!(c.interfaces[0].ipv4.is_empty());
        assert_eq!(c.warnings.len(), 1);
    }

    #[test]
    fn a_list_and_a_space_separated_option_parse_the_same() {
        let a = parse(&pkg(
            "config interface lan\n\toption proto 'static'\n\tlist dns '1.1.1.1'\n\tlist dns '8.8.8.8'\n",
        ));
        let b = parse(&pkg(
            "config interface lan\n\toption proto 'static'\n\toption dns '1.1.1.1 8.8.8.8'\n",
        ));
        assert_eq!(a.interfaces[0].dns, b.interfaces[0].dns);
        assert_eq!(a.interfaces[0].dns.len(), 2);
    }

    #[test]
    fn ip6assign_longer_than_a_64_is_refused() {
        let c = parse(&pkg(
            "config interface lan\n\toption proto 'static'\n\toption ip6assign '80'\n",
        ));
        assert!(c.interfaces[0].ip6assign.is_none());
        assert_eq!(c.warnings.len(), 1);
    }

    #[test]
    fn uci_boolean_spellings_all_work() {
        for (text, want) in [
            ("1", true),
            ("on", true),
            ("true", true),
            ("yes", true),
            ("0", false),
            ("off", false),
        ] {
            let c = parse(&pkg(&format!(
                "config interface lan\n\toption proto 'static'\n\toption auto '{text}'\n"
            )));
            assert_eq!(c.interfaces[0].auto, Some(want), "for {text}");
        }
    }

    #[test]
    fn unknown_interface_options_are_kept_for_the_proto_handler() {
        let c = parse(&pkg(
            "config interface wan\n\toption proto 'dhcp'\n\toption hostname 'router'\n\
             \tlist reqopts '43'\n\tlist reqopts '121'\n",
        ));
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        let e = &c.interfaces[0].extra;
        assert_eq!(e.get("hostname").unwrap(), &vec!["router".to_string()]);
        assert_eq!(
            e.get("reqopts").unwrap(),
            &vec!["43".to_string(), "121".to_string()]
        );
        assert!(!e.contains_key("proto"));
    }

    #[test]
    fn the_raw_options_keep_file_order_and_the_list_flag() {
        let c = parse(&pkg(
            "config interface wan\n\toption proto 'dhcp'\n\toption hostname 'r'\n\
             \tlist reqopts '43'\n\tlist reqopts '121'\n",
        ));
        let raw = &c.interfaces[0].raw;
        assert_eq!(
            raw.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["proto", "hostname", "reqopts"]
        );
        assert!(!raw[1].is_list);
        assert!(raw[2].is_list);
        assert_eq!(raw[2].values, vec!["43", "121"]);
    }

    #[test]
    fn an_interface_without_a_proto_is_a_warning() {
        let c = parse(&pkg("config interface lan\n\toption device 'br-lan'\n"));
        assert!(c.interfaces.is_empty());
        assert_eq!(c.warnings.len(), 1);
    }

    #[test]
    fn globals_parse_the_prefix_and_the_numbers() {
        let c = parse(&pkg(
            "config globals 'globals'\n\toption ula_prefix 'fdfd:3b1d:1c26::/48'\n\
             \toption packet_steering '1'\n",
        ));
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        assert_eq!(
            c.globals.ula_prefix,
            Some(("fdfd:3b1d:1c26::".parse().unwrap(), 48))
        );
        assert_eq!(c.globals.packet_steering, Some(1));
    }

    #[test]
    fn this_devices_own_config_parses_without_errors() {
        // the shape of the real /etc/config/network, values redacted
        let c = parse(&pkg(
            "config interface 'loopback'\n\toption device 'lo'\n\toption proto 'static'\n\
             \toption ipaddr '127.0.0.1/8'\n\n\
             config globals 'globals'\n\toption ula_prefix 'fd00:1:2::/48'\n\
             \toption packet_steering '1'\n\n\
             config device\n\toption name 'br-lan'\n\toption type 'bridge'\n\
             \tlist ports 'lan2'\n\tlist ports 'lan3'\n\tlist ports 'lan4'\n\n\
             config interface 'lan'\n\toption device 'br-lan'\n\toption proto 'static'\n\
             \toption ipaddr '192.168.1.1/24'\n\toption ip6assign '60'\n\n\
             config device\n\toption name 'wan'\n\toption macaddr '02:00:00:00:00:01'\n\n\
             config interface 'wan'\n\toption device 'wan'\n\toption proto 'dhcp'\n\n\
             config interface 'wan6'\n\toption device 'wan'\n\toption proto 'dhcpv6'\n",
        ));
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        assert_eq!(c.devices.len(), 2);
        assert_eq!(c.interfaces.len(), 4);
        assert_eq!(c.interfaces[1].ip6assign, Some(60));
        assert_eq!(c.devices[0].ports.len(), 3);
        assert!(c.devices[1].kind.is_none());
    }
}
