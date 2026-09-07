//! `/etc/config/network` → the device and interface model.
//!
//! Anything this build cannot honour is an error, never a silent skip: a
//! config section that quietly does nothing is how a router ends up half
//! configured with no indication of why (RUST_CORE_CONTROL_PLAN §2).

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

/// Section types netifd knows but this build does not implement. Naming them
/// separately keeps the error specific ("bonding is not supported") rather
/// than "unknown section".
const OUT_OF_SCOPE: &[&str] = &[
    "route", "route6", "rule", "rule6", "switch", "switch_vlan", "switch_port", "bridge-vlan",
];

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: String,
    pub device: Option<String>,
    pub proto: String,
    pub auto: Option<bool>,
    pub disabled: bool,
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub ipv6: Vec<(Ipv6Addr, u8)>,
    pub gateway: Option<Ipv4Addr>,
    pub ip6gw: Option<Ipv6Addr>,
    pub ip6assign: Option<u8>,
    pub ip6hint: Option<u32>,
    pub metric: u32,
    pub dns_metric: u32,
    pub dns: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub ip4table: Option<u32>,
    pub ip6table: Option<u32>,
    pub delegate: Option<bool>,
    pub force_link: Option<bool>,
    pub defaultroute: Option<bool>,
    pub peerdns: Option<bool>,
    /// Options this build does not interpret but the proto handler might;
    /// passed through to proto-shell verbatim.
    pub extra: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub globals: Globals,
    pub devices: Vec<DeviceConfig>,
    pub interfaces: Vec<InterfaceConfig>,
    /// Non-fatal on their own: netifd keeps running with the sections it does
    /// understand, and these are reported so the operator can see what was
    /// refused.
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
        Some(OptionValue::List(v)) => {
            v.iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect()
        }
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
    Some(matches!(v.as_str(), "1" | "on" | "true" | "enabled" | "yes"))
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
    "device", "ifname", "proto", "auto", "disabled", "ipaddr", "netmask", "ip6addr", "gateway",
    "ip6gw", "ip6assign", "ip6hint", "metric", "dns_metric", "dns", "dns_search", "ip4table",
    "ip6table", "delegate", "force_link", "defaultroute", "peerdns", "type",
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
            t if OUT_OF_SCOPE.contains(&t) => c.errors.push(ConfigError {
                section: where_,
                message: format!("section type '{t}' is not supported by this build"),
            }),
            t => c.errors.push(ConfigError {
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
            None => c.errors.push(ConfigError {
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
        c.errors.push(ConfigError {
            section: where_.to_string(),
            message: "device section without a name".into(),
        });
        return;
    };
    let kind = s_opt(s, "type");
    if let Some(k) = &kind {
        if k != "bridge" {
            c.errors.push(ConfigError {
                section: where_.to_string(),
                message: format!("device type '{k}' is not supported by this build"),
            });
            return;
        }
    }
    let mut d = DeviceConfig { name, kind, ..Default::default() };
    d.ports = l_opt(s, "ports");
    if d.ports.is_empty() {
        // `ifname` is the pre-21.02 spelling and still accepted
        d.ports = l_opt(s, "ifname");
    }
    if let Some(m) = s_opt(s, "macaddr") {
        match parse_macaddr(&m) {
            Some(mac) => d.macaddr = Some(mac),
            None => c.errors.push(ConfigError {
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

fn parse_interface(s: &Section, c: &mut Config, where_: &str) {
    let mut i = InterfaceConfig { name: s.name.clone(), ..Default::default() };
    i.proto = s_opt(s, "proto").unwrap_or_default();
    if i.proto.is_empty() {
        c.errors.push(ConfigError {
            section: where_.to_string(),
            message: "interface without a proto".into(),
        });
        return;
    }
    i.device = s_opt(s, "device").or_else(|| s_opt(s, "ifname"));
    i.auto = b_opt(s, "auto");
    i.disabled = b_opt(s, "disabled").unwrap_or(false);

    let netmask = s_opt(s, "netmask");
    for a in l_opt(s, "ipaddr") {
        match parse_v4(&a, netmask.as_deref()) {
            Some(v) => i.ipv4.push(v),
            None => c.errors.push(ConfigError {
                section: where_.to_string(),
                message: format!("ipaddr '{a}' is not an IPv4 address"),
            }),
        }
    }
    for a in l_opt(s, "ip6addr") {
        match parse_v6(&a) {
            Some(v) => i.ipv6.push(v),
            None => c.errors.push(ConfigError {
                section: where_.to_string(),
                message: format!("ip6addr '{a}' is not an IPv6 address"),
            }),
        }
    }
    i.gateway = s_opt(s, "gateway").and_then(|v| v.parse().ok());
    i.ip6gw = s_opt(s, "ip6gw").and_then(|v| v.parse().ok());
    if let Some(v) = n_opt::<u8>(s, "ip6assign") {
        if v > 64 {
            c.errors.push(ConfigError {
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
    for d in l_opt(s, "dns") {
        match d.parse::<IpAddr>() {
            Ok(a) => i.dns.push(a),
            Err(_) => c.errors.push(ConfigError {
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
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        assert_eq!(c.devices.len(), 1);
        let d = &c.devices[0];
        assert_eq!(d.name, "br-lan");
        assert_eq!(d.kind.as_deref(), Some("bridge"));
        assert_eq!(d.ports, vec!["lan2", "lan3"]);
        assert_eq!(d.macaddr, Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
    }

    #[test]
    fn an_unsupported_device_type_is_an_error_not_a_skip() {
        let c = parse(&pkg("config device\n\toption name 'bond0'\n\toption type 'bonding'\n"));
        assert!(c.devices.is_empty());
        assert_eq!(c.errors.len(), 1);
        assert!(c.errors[0].message.contains("bonding"), "{:?}", c.errors);
    }

    #[test]
    fn out_of_scope_sections_name_themselves() {
        let c = parse(&pkg("config rule\n\toption lookup '100'\n"));
        assert_eq!(c.errors.len(), 1);
        assert!(c.errors[0].message.contains("'rule' is not supported"), "{:?}", c.errors);
    }

    #[test]
    fn an_unknown_section_type_is_reported_separately() {
        let c = parse(&pkg("config wombat 'x'\n"));
        assert_eq!(c.errors.len(), 1);
        assert!(c.errors[0].message.contains("unknown section type"), "{:?}", c.errors);
    }

    #[test]
    fn ipaddr_accepts_both_mask_spellings() {
        let c = parse(&pkg(
            "config interface lan\n\toption proto 'static'\n\toption ipaddr '192.168.1.1/24'\n\n\
             config interface old\n\toption proto 'static'\n\toption ipaddr '10.0.0.1'\n\
             \toption netmask '255.255.255.0'\n",
        ));
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        assert_eq!(c.interfaces[0].ipv4, vec![("192.168.1.1".parse().unwrap(), 24)]);
        assert_eq!(c.interfaces[1].ipv4, vec![("10.0.0.1".parse().unwrap(), 24)]);
    }

    #[test]
    fn a_bare_ipaddr_with_no_netmask_is_a_host_route() {
        let c = parse(&pkg("config interface lan\n\toption proto 'static'\n\toption ipaddr '10.0.0.1'\n"));
        assert_eq!(c.interfaces[0].ipv4, vec![("10.0.0.1".parse().unwrap(), 32)]);
    }

    #[test]
    fn a_non_contiguous_netmask_is_rejected() {
        let c = parse(&pkg(
            "config interface lan\n\toption proto 'static'\n\toption ipaddr '10.0.0.1'\n\
             \toption netmask '255.0.255.0'\n",
        ));
        assert!(c.interfaces[0].ipv4.is_empty());
        assert_eq!(c.errors.len(), 1);
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
        assert_eq!(c.errors.len(), 1);
    }

    #[test]
    fn uci_boolean_spellings_all_work() {
        for (text, want) in
            [("1", true), ("on", true), ("true", true), ("yes", true), ("0", false), ("off", false)]
        {
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
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        let e = &c.interfaces[0].extra;
        assert_eq!(e.get("hostname").unwrap(), &vec!["router".to_string()]);
        assert_eq!(e.get("reqopts").unwrap(), &vec!["43".to_string(), "121".to_string()]);
        assert!(!e.contains_key("proto"));
    }

    #[test]
    fn an_interface_without_a_proto_is_an_error() {
        let c = parse(&pkg("config interface lan\n\toption device 'br-lan'\n"));
        assert!(c.interfaces.is_empty());
        assert_eq!(c.errors.len(), 1);
    }

    #[test]
    fn globals_parse_the_prefix_and_the_numbers() {
        let c = parse(&pkg(
            "config globals 'globals'\n\toption ula_prefix 'fdfd:3b1d:1c26::/48'\n\
             \toption packet_steering '1'\n",
        ));
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        assert_eq!(c.globals.ula_prefix, Some(("fdfd:3b1d:1c26::".parse().unwrap(), 48)));
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
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        assert_eq!(c.devices.len(), 2);
        assert_eq!(c.interfaces.len(), 4);
        assert_eq!(c.interfaces[1].ip6assign, Some(60));
        assert_eq!(c.devices[0].ports.len(), 3);
        assert!(c.devices[1].kind.is_none());
    }
}
