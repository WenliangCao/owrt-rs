//! Parsed firewall state: the typed equivalent of the objects fw4.uc builds in
//! `this.state` and hands to the templates.

use crate::val::Num;

#[derive(Clone, Debug, PartialEq)]
pub struct Addr {
    pub family: i64,
    pub addr: String,
    pub mask: Option<String>,
    /// prefix length; -1 for non-contiguous masks; None for ranges
    pub bits: Option<i64>,
    pub addr2: Option<String>,
    pub range: bool,
    pub invert: bool,
}

impl Addr {
    /// ucode `a.bits == -1`
    pub fn is_masked(&self) -> bool {
        self.bits == Some(-1)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Port {
    pub invert: bool,
    pub min: i64,
    pub max: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proto {
    pub invert: bool,
    pub any: bool,
    pub name: Option<String>,
}

impl Proto {
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or("null")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Limit {
    pub invert: bool,
    pub rate: Num,
    pub unit: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Mark {
    pub invert: bool,
    pub mark: i64,
    pub mask: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Dscp {
    pub invert: bool,
    pub dscp: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Mac {
    pub invert: bool,
    pub mac: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DateTime {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub min: i64,
    pub sec: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Time {
    pub hour: i64,
    pub min: i64,
    pub sec: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Weekdays {
    pub invert: bool,
    pub days: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SetMatch {
    pub invert: bool,
    pub name: String,
    pub dir: Vec<Option<String>>,
    pub fields: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Helper {
    pub name: String,
    pub description: Option<String>,
    pub module: Option<String>,
    pub family: Option<i64>,
    pub proto: Option<Vec<Proto>>,
    pub port: Option<Port>,
    pub available: bool,
}

/// `parse_cthelper` result: `{ ...invert/val, ...helper }`
#[derive(Clone, Debug, PartialEq)]
pub struct CtHelper {
    pub invert: bool,
    pub helper: Helper,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IcmpType {
    pub family: i64,
    pub ty: Option<i64>,
    pub code_min: Option<i64>,
    pub code_max: Option<i64>,
    pub ty6: Option<i64>,
    pub code6_min: Option<i64>,
    pub code6_max: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ZoneRef {
    pub any: bool,
    pub zone: Option<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    pub invert: bool,
    pub any: bool,
    pub device: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Network {
    pub invert: bool,
    pub addrs: Option<Vec<Addr>>,
}

/// subnets_group_by_masking() element: [plain, invert_plain, masked]
pub type SubnetGroup = (Option<Vec<Addr>>, Option<Vec<Addr>>, Option<Vec<Addr>>);

#[derive(Clone, Debug, Default)]
pub struct MatchRule {
    pub family: i64,
    pub devices_pos: Option<Vec<String>>,
    pub devices_neg: Option<Vec<String>>,
    pub devices_neg_wildcard: Option<Vec<String>>,
    pub subnets_pos: Option<Vec<String>>,
    pub subnets_neg: Option<Vec<String>>,
    pub subnets_masked: Option<Vec<Addr>>,
}

#[derive(Clone, Debug, Default)]
pub struct Flags(pub Vec<String>);

impl Flags {
    pub fn set(&mut self, key: &str) {
        if !self.0.iter().any(|k| k == key) {
            self.0.push(key.to_owned());
        }
    }
    pub fn has(&self, key: &str) -> bool {
        self.0.iter().any(|k| k == key)
    }
}

#[derive(Clone, Debug)]
pub struct Zone {
    pub name: String,
    pub family: i64,
    pub input: String,
    pub output: String,
    pub forward: String,
    pub masq: bool,
    pub masq_allow_invalid: bool,
    pub masq6: bool,
    pub mtu_fix: bool,
    pub log: Option<Num>,
    pub log_limit: Option<Limit>,
    pub auto_helper: bool,
    /// zone.helper as fw4.uc keeps it in state; the ruleset uses the derived
    /// helper match rules, and the state file writes the fields `fw4 zone`
    /// reads, so nothing reads this back
    #[allow(dead_code)]
    pub helper: Option<Vec<CtHelper>>,
    pub counter: bool,
    pub network: Vec<Device>,
    pub match_rules: Vec<MatchRule>,
    pub masq4_src_subnets: Vec<SubnetGroup>,
    pub masq4_dest_subnets: Vec<SubnetGroup>,
    pub masq6_src_subnets: Vec<SubnetGroup>,
    pub masq6_dest_subnets: Vec<SubnetGroup>,
    pub sflags: Flags,
    pub dflags: Flags,
    pub match_devices: Vec<String>,
    pub match_subnets: Vec<String>,
    pub related_subnets: Vec<Addr>,
    pub related_physdevs: Vec<String>,
}

impl Zone {
    /// ucode `zone.log & 1` etc.
    pub fn log_bits(&self) -> i64 {
        self.log.map(|n| n.as_i64()).unwrap_or(0)
    }
}

/// One emitted filter/mangle rule (rule.uc input).
#[derive(Clone, Debug, Default)]
pub struct Rule {
    pub name: String,
    pub chain: String,
    pub family: i64,
    pub proto: Proto,
    pub src: Option<ZoneRef>,
    pub dest: Option<ZoneRef>,
    pub has_addrs: bool,
    pub has_ports: bool,
    pub saddrs_pos: Option<Vec<String>>,
    pub saddrs_neg: Option<Vec<String>>,
    pub saddrs_masked: Option<Vec<Addr>>,
    pub daddrs_pos: Option<Vec<String>>,
    pub daddrs_neg: Option<Vec<String>>,
    pub daddrs_masked: Option<Vec<Addr>>,
    pub sports_pos: Option<Vec<String>>,
    pub sports_neg: Option<Vec<String>>,
    pub dports_pos: Option<Vec<String>>,
    pub dports_neg: Option<Vec<String>>,
    pub smacs_pos: Option<Vec<String>>,
    pub smacs_neg: Option<Vec<String>>,
    pub icmp_types: Option<Vec<i64>>,
    pub icmp_codes: Option<Vec<String>>,
    pub iifnames: Option<Vec<String>>,
    pub oifnames: Option<Vec<String>>,
    pub helper: Option<CtHelper>,
    pub set_helper: Option<CtHelper>,
    pub limit: Option<Limit>,
    pub limit_burst: Option<Num>,
    pub start_date: Option<DateTime>,
    pub stop_date: Option<DateTime>,
    pub start_time: Option<Time>,
    pub stop_time: Option<Time>,
    pub weekdays: Option<Weekdays>,
    pub mark: Option<Mark>,
    pub set_xmark: Option<Mark>,
    pub dscp: Option<Dscp>,
    pub set_dscp: Option<Dscp>,
    pub ipset: Option<SetMatch>,
    pub log: Option<String>,
    pub log_limit: Option<Limit>,
    pub counter: bool,
    pub target: Option<String>,
    pub jump_chain: Option<String>,
}

impl Default for Proto {
    fn default() -> Proto {
        Proto {
            invert: false,
            any: true,
            name: None,
        }
    }
}

/// One emitted NAT rule (redirect.uc input), from redirect or nat sections.
#[derive(Clone, Debug, Default)]
pub struct Redirect {
    pub name: String,
    pub chain: String,
    pub family: i64,
    pub proto: Proto,
    pub src: Option<ZoneRef>,
    pub dest: Option<ZoneRef>,
    pub device: Option<String>,
    pub has_addrs: bool,
    pub has_ports: bool,
    pub saddrs_pos: Option<Vec<String>>,
    pub saddrs_neg: Option<Vec<String>>,
    pub saddrs_masked: Option<Vec<Addr>>,
    pub daddrs_pos: Option<Vec<String>>,
    pub daddrs_neg: Option<Vec<String>>,
    pub daddrs_masked: Option<Vec<Addr>>,
    pub sports_pos: Option<Vec<String>>,
    pub sports_neg: Option<Vec<String>>,
    pub dports_pos: Option<Vec<String>>,
    pub dports_neg: Option<Vec<String>>,
    pub smacs_pos: Option<Vec<String>>,
    pub smacs_neg: Option<Vec<String>>,
    pub raddr: Option<Addr>,
    pub rport: Option<Port>,
    pub helper: Option<CtHelper>,
    pub limit: Option<Limit>,
    pub limit_burst: Option<Num>,
    pub start_date: Option<DateTime>,
    pub stop_date: Option<DateTime>,
    pub start_time: Option<Time>,
    pub stop_time: Option<Time>,
    pub weekdays: Option<Weekdays>,
    pub mark: Option<Mark>,
    pub ipset: Option<SetMatch>,
    pub log: Option<String>,
    pub log_limit: Option<Limit>,
    pub counter: bool,
    pub target: String,
}

#[derive(Clone, Debug)]
pub struct Ipset {
    pub name: String,
    pub family: i64,
    pub comment: Option<String>,
    pub maxelem: Option<Num>,
    pub timeout: Num,
    pub entries: Vec<Vec<String>>,
    pub loadfile: Option<String>,
    pub fw4types: Vec<String>,
    pub types: Vec<String>,
    pub directions: Vec<String>,
    pub interval: bool,
    pub flags: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct Include {
    pub enabled: bool,
    pub path: String,
    pub ty: String,
    pub fw4_compatible: bool,
    pub position: String,
    pub chain: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Net {
    pub up: bool,
    pub device: Option<String>,
    pub physdev: Option<String>,
    pub zone: Option<String>,
    pub ipaddrs: Vec<Addr>,
}

#[derive(Clone, Debug, Default)]
pub struct Defaults {
    pub input: Option<String>,
    pub output: Option<String>,
    pub forward: Option<String>,
    pub drop_invalid: Option<bool>,
    pub tcp_reject_code: Option<String>,
    pub any_reject_code: Option<String>,
    pub synflood_protect: Option<bool>,
    pub synflood_rate: Option<Limit>,
    pub synflood_burst: Option<Num>,
    pub auto_helper: Option<bool>,
    pub flow_offloading: Option<bool>,
    pub flow_offloading_hw: Option<bool>,
    pub auto_includes: Option<bool>,
}

#[derive(Default)]
pub struct State {
    pub defaults: Option<Defaults>,
    pub helpers: Vec<Helper>,
    pub zones: Vec<Zone>,
    pub rules: Vec<Rule>,
    pub redirects: Vec<Redirect>,
    pub ipsets: Vec<Ipset>,
    pub includes: Vec<Include>,
    /// interface name -> network, in ubus dump order
    pub networks: Vec<(String, Net)>,
    pub ubus_rules: Vec<owrt_ubus::json::Json>,
}

impl State {
    pub fn network(&self, name: &str) -> Option<&Net> {
        self.networks
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, net)| net)
    }
}
