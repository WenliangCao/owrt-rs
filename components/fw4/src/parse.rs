//! Option parsing primitives: the `parse_*` methods of fw4.uc with their exact
//! acceptance rules and warning texts.

use crate::input::Inputs;
use crate::ip::{self};
use crate::state::*;
use crate::uci::Config;
use crate::val::{loose_eq_str, to_array, to_num, to_str, trim, truthy, Num};
use owrt_ubus::json::Json;
use std::io::Write;
use std::rc::Rc;

pub const PARSE_LIST: u32 = 0x01;
pub const FLATTEN_LIST: u32 = 0x02;
pub const NO_INVERT: u32 = 0x04;
pub const UNSUPPORTED: u32 = 0x08;
pub const REQUIRED: u32 = 0x10;
pub const DEPRECATED: u32 = 0x20;

pub struct Fw4 {
    pub inputs: Inputs,
    /// Shared so `load()` can walk the sections while the parsers borrow
    /// `self` mutably, without cloning every section.
    pub firewall: Rc<Config>,
    pub helpers_cfg: Rc<Config>,
    pub state: State,
    pub kernel: i64,
    pub quiet: bool,
    /// Set where ucode would have died with an uncaught exception in the
    /// middle of `load()` (a null member access): `load()` turns it into the
    /// same abort -- nothing rendered, exit 254 (R88 fw4 F1/F2).
    pub aborted: bool,
    pub tty: bool,
}

/// Result of `parse_invert`.
pub struct Inv {
    pub invert: bool,
    pub val: String,
}

pub trait HasInvert {
    fn inverted(&self) -> bool {
        false
    }
}
impl HasInvert for String {}
impl HasInvert for bool {}
impl HasInvert for Num {}
impl HasInvert for i64 {}
impl HasInvert for () {}
impl HasInvert for ZoneRef {}
impl HasInvert for DateTime {}
impl HasInvert for Time {}
impl HasInvert for IcmpType {}
impl HasInvert for (String, String) {}
impl HasInvert for Device {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for Network {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for SetMatch {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for CtHelper {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for Mac {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for Port {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for Limit {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for Mark {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for Dscp {
    fn inverted(&self) -> bool {
        self.invert
    }
}
impl HasInvert for Weekdays {
    fn inverted(&self) -> bool {
        self.invert
    }
}

/// Sequential `parse_options` evaluation over one section.
pub struct Opts<'a> {
    fw: &'a Fw4,
    s: &'a Json,
    keys: Vec<&'static str>,
}

fn is_null(v: Option<&Json>) -> bool {
    matches!(v, None | Some(Json::Null))
}

impl<'a> Opts<'a> {
    pub fn new(fw: &'a Fw4, s: &'a Json) -> Opts<'a> {
        Opts {
            fw,
            s,
            keys: Vec::new(),
        }
    }

    /// `parse_opt` + the per-option checks of `parse_options`.
    pub fn opt<T: HasInvert, F: Fn(&Fw4, &Json) -> Option<T>>(
        &mut self,
        key: &'static str,
        def: Option<Json>,
        flags: u32,
        f: F,
    ) -> Result<Option<T>, ()> {
        self.keys.push(key);
        let s = self.s;
        let mut val = s.get(key);
        if is_null(val) {
            if flags & REQUIRED != 0 {
                self.fw
                    .warn_section(s, &format!("option '{key}' is mandatory but not set"));
                return Err(());
            }
            val = def.as_ref();
        }
        let val = match val {
            Some(Json::Array(_)) => {
                self.fw
                    .warn_section(s, &format!("option '{key}' must not be a list"));
                return Err(());
            }
            None | Some(Json::Null) => return Ok(None),
            Some(v) => v,
        };
        let Some(res) = f(self.fw, val) else {
            self.fw.warn_section(
                s,
                &format!("option '{key}' specifies invalid value '{}'", to_str(val)),
            );
            return Err(());
        };
        if res.inverted() && flags & NO_INVERT != 0 {
            self.fw
                .warn_section(s, &format!("option '{key}' must not be negated"));
            return Err(());
        }
        self.dropped(key, flags, res)
    }

    /// `parse_list`; `f` returns the (possibly flattened) items for one value.
    pub fn list<T, F: Fn(&Fw4, &Json) -> Option<Vec<T>>>(
        &mut self,
        key: &'static str,
        def: Option<Json>,
        flags: u32,
        f: F,
    ) -> Result<Option<Vec<T>>, ()> {
        self.keys.push(key);
        let s = self.s;
        let fw = self.fw;
        let mut val = s.get(key);
        if is_null(val) {
            if flags & REQUIRED != 0 {
                fw.warn_section(s, &format!("option '{key}' is mandatory but not set"));
                return Err(());
            }
            val = def.as_ref();
        }
        let mut rv = Vec::new();
        let mut one = |item: &Json| -> Result<(), ()> {
            let Some(res) = f(fw, item) else {
                fw.warn_section(
                    s,
                    &format!("option '{key}' specifies invalid value '{}'", to_str(item)),
                );
                return Err(());
            };
            rv.extend(res);
            Ok(())
        };
        match val {
            // a list is walked in place; anything else goes through to_array()
            Some(Json::Array(items)) => items.iter().try_for_each(&mut one)?,
            Some(other) => to_array(other).iter().try_for_each(&mut one)?,
            None => {}
        }
        if rv.is_empty() {
            return Ok(None);
        }
        self.dropped(key, flags, rv)
    }

    fn dropped<T>(&self, key: &str, flags: u32, res: T) -> Result<Option<T>, ()> {
        if flags & DEPRECATED != 0 {
            self.fw
                .warn_section(self.s, &format!("option '{key}' is deprecated by fw4"));
            Ok(None)
        } else if flags & UNSUPPORTED != 0 {
            self.fw
                .warn_section(self.s, &format!("option '{key}' is not supported by fw4"));
            Ok(None)
        } else {
            Ok(Some(res))
        }
    }

    /// Unknown-option warnings (end of `parse_options`).
    pub fn finish(self) {
        if let Json::Object(items) = self.s {
            for (k, _) in items {
                if !k.starts_with('.') && k != "type" && !self.keys.contains(&k.as_str()) {
                    self.fw
                        .warn_section(self.s, &format!("specifies unknown option '{k}'"));
                }
            }
        }
    }
}

pub fn s(v: &str) -> Option<Json> {
    Some(Json::Str(v.to_owned()))
}

// ---------------------------------------------------------------- tables

pub fn ipv4_icmptype(name: &str) -> Option<(i64, i64, i64)> {
    Some(match name {
        "any" => (0xFF, 0, 0xFF),
        "echo-reply" | "pong" => (0, 0, 0xFF),
        "destination-unreachable" => (3, 0, 0xFF),
        "network-unreachable" => (3, 0, 0),
        "host-unreachable" => (3, 1, 1),
        "protocol-unreachable" => (3, 2, 2),
        "port-unreachable" => (3, 3, 3),
        "fragmentation-needed" => (3, 4, 4),
        "source-route-failed" => (3, 5, 5),
        "network-unknown" => (3, 6, 6),
        "host-unknown" => (3, 7, 7),
        "network-prohibited" => (3, 9, 9),
        "host-prohibited" => (3, 10, 10),
        "TOS-network-unreachable" => (3, 11, 11),
        "TOS-host-unreachable" => (3, 12, 12),
        "communication-prohibited" => (3, 13, 13),
        "host-precedence-violation" => (3, 14, 14),
        "precedence-cutoff" => (3, 15, 15),
        "source-quench" => (4, 0, 0xFF),
        "redirect" => (5, 0, 0xFF),
        "network-redirect" => (5, 0, 0),
        "host-redirect" => (5, 1, 1),
        "TOS-network-redirect" => (5, 2, 2),
        "TOS-host-redirect" => (5, 3, 3),
        "echo-request" | "ping" => (8, 0, 0xFF),
        "router-advertisement" => (9, 0, 0xFF),
        "router-solicitation" => (10, 0, 0xFF),
        "time-exceeded" | "ttl-exceeded" => (11, 0, 0xFF),
        "ttl-zero-during-transit" => (11, 0, 0),
        "ttl-zero-during-reassembly" => (11, 1, 1),
        "parameter-problem" => (12, 0, 0xFF),
        "ip-header-bad" => (12, 0, 0),
        "required-option-missing" => (12, 1, 1),
        "timestamp-request" => (13, 0, 0xFF),
        "timestamp-reply" => (14, 0, 0xFF),
        "address-mask-request" => (17, 0, 0xFF),
        "address-mask-reply" => (18, 0, 0xFF),
        _ => return None,
    })
}

pub fn ipv6_icmptype(name: &str) -> Option<(i64, i64, i64)> {
    Some(match name {
        "destination-unreachable" => (1, 0, 0xFF),
        "no-route" => (1, 0, 0),
        "communication-prohibited" => (1, 1, 1),
        "address-unreachable" => (1, 3, 3),
        "port-unreachable" => (1, 4, 4),
        "packet-too-big" => (2, 0, 0xFF),
        "time-exceeded" | "ttl-exceeded" => (3, 0, 0xFF),
        "ttl-zero-during-transit" => (3, 0, 0),
        "ttl-zero-during-reassembly" => (3, 1, 1),
        "parameter-problem" => (4, 0, 0xFF),
        "bad-header" => (4, 0, 0),
        "unknown-header-type" => (4, 1, 1),
        "unknown-option" => (4, 2, 2),
        "echo-request" | "ping" => (128, 0, 0xFF),
        "echo-reply" | "pong" => (129, 0, 0xFF),
        "multicast-listener-query" => (130, 0, 0xFF),
        "multicast-listener-report" => (131, 0, 0xFF),
        "multicast-listener-done" => (132, 0, 0xFF),
        "router-solicitation" => (133, 0, 0xFF),
        "router-advertisement" => (134, 0, 0xFF),
        "neighbour-solicitation" | "neighbor-solicitation" => (135, 0, 0xFF),
        "neighbour-advertisement" | "neighbor-advertisement" => (136, 0, 0xFF),
        "redirect" => (137, 0, 0xFF),
        "router-renumbering" => (138, 0, 0xFF),
        "node-info-query" => (139, 0, 0xFF),
        "node-info-response" => (140, 0, 0xFF),
        "inverse-neighbour-discovery-solicitation-message"
        | "inverse-neighbor-discovery-solicitation-message" => (141, 0, 0xFF),
        "inverse-neighbour-discovery-advertisement-message"
        | "inverse-neighbor-discovery-advertisement-message" => (142, 0, 0xFF),
        "v2-multicast-listener-report" => (143, 0, 0xFF),
        "home-agent-address-discovery-request-message" => (144, 0, 0xFF),
        "home-agent-address-discovery-reply-message" => (145, 0, 0xFF),
        "mobile-prefix-solicitation" => (146, 0, 0xFF),
        "mobile-prefix-advertisement" => (147, 0, 0xFF),
        "certification-path-solicitation-message" => (148, 0, 0xFF),
        "certification-path-advertisement-message" => (149, 0, 0xFF),
        "seamoby-protocol-message" => (150, 0, 0xFF),
        "multicast-router-advertisement" => (151, 0, 0xFF),
        "multicast-router-solicitation" => (152, 0, 0xFF),
        "multicast-router-termination" => (153, 0, 0xFF),
        "fmipv6-message" => (154, 0, 0xFF),
        "rpl-control-message" => (155, 0, 0xFF),
        "ilnpv6-locator-update-message" => (156, 0, 0xFF),
        "duplicate-address-request" => (157, 0, 0xFF),
        "duplicate-address-confirmation" => (158, 0, 0xFF),
        "mpl-control-message" => (159, 0, 0xFF),
        "extended-echo-request" | "extended-ping" => (160, 0, 0xFF),
        "extended-echo-reply" | "extended-pong" => (161, 0, 0xFF),
        _ => return None,
    })
}

pub fn dscp_class(name: &str) -> Option<i64> {
    Some(match name {
        "CS0" | "BE" => 0x00,
        "CS1" => 0x08,
        "CS2" => 0x10,
        "CS3" => 0x18,
        "CS4" => 0x20,
        "CS5" => 0x28,
        "CS6" => 0x30,
        "CS7" => 0x38,
        "LE" => 0x01,
        "AF11" => 0x0a,
        "AF12" => 0x0c,
        "AF13" => 0x0e,
        "AF21" => 0x12,
        "AF22" => 0x14,
        "AF23" => 0x16,
        "AF31" => 0x1a,
        "AF32" => 0x1c,
        "AF33" => 0x1e,
        "AF41" => 0x22,
        "AF42" => 0x24,
        "AF43" => 0x26,
        "EF" => 0x2e,
        _ => return None,
    })
}

// ---------------------------------------------------------------- helpers

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn hexdigits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// ucode `+str` restricted to what `match` groups can produce.
fn num_of(s: &str) -> Num {
    crate::val::parse_num_str(s)
}

impl Fw4 {
    pub fn warn(&self, msg: &str) {
        if self.quiet {
            return;
        }
        let mut err = std::io::stderr();
        if self.tty {
            let _ = writeln!(err, "\x1b[33m{msg}\x1b[m");
        } else {
            let _ = writeln!(err, "[!] {msg}");
        }
    }

    /// Plain `warn()` from ucode (no prefix), used for a few messages.
    pub fn raw_warn(&self, msg: &str) {
        let _ = write!(std::io::stderr(), "{msg}");
    }

    pub fn section_id(&self, sid: Option<&str>) -> Option<String> {
        let sec = self.firewall.by_name(sid?)?;
        let ty = sec.get(".type").and_then(Json::as_str).unwrap_or("");
        let name = sec.get(".name").and_then(Json::as_str).unwrap_or("");
        if sec.get(".anonymous").map(truthy).unwrap_or(false) {
            let mut c = 0;
            for other in self.firewall.of_type(ty) {
                if other.get(".name").and_then(Json::as_str) == Some(name) {
                    break;
                }
                c += 1;
            }
            return Some(format!("@{ty}[{c}]"));
        }
        Some(name.to_owned())
    }

    pub fn warn_section(&self, s: &Json, msg: &str) {
        let name = s.get("name").filter(|v| truthy(v)).map(to_str);
        if s.get(".name").map(truthy).unwrap_or(false) {
            let id = self
                .section_id(s.get(".name").and_then(Json::as_str))
                .unwrap_or_else(|| "(null)".into());
            match name {
                Some(n) => self.warn(&format!("Section {id} ({n}) {msg}")),
                None => self.warn(&format!("Section {id} {msg}")),
            }
        } else {
            let ty = s
                .get("type")
                .filter(|v| truthy(v))
                .map(to_str)
                .unwrap_or_else(|| "rule".into());
            match name {
                Some(n) => self.warn(&format!("ubus {ty} ({n}) {msg}")),
                None => self.warn(&format!("ubus {ty} {msg}")),
            }
        }
    }

    pub fn parse_invert(&self, val: &Json) -> Option<Inv> {
        if matches!(val, Json::Null) {
            return None;
        }
        let s = to_str(val);
        let t = s.trim_start_matches([' ', '\t']);
        let (invert, rest) = match t.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, s.as_str()),
        };
        let v = trim(rest).to_owned();
        if v.is_empty() {
            None
        } else {
            Some(Inv { invert, val: v })
        }
    }

    pub fn parse_enum(&self, val: &Json, choices: &[&str]) -> Option<String> {
        let Json::Str(v) = val else { return None };
        if v.is_ascii() && choices.iter().all(|c| c.is_ascii()) {
            // `lc(val)` against the equally long prefix of each choice, with
            // no lowercase copies: ASCII case folding is a byte comparison.
            return choices
                .iter()
                .find(|c| {
                    c.len() >= v.len() && c.as_bytes()[..v.len()].eq_ignore_ascii_case(v.as_bytes())
                })
                .map(|c| c.to_string());
        }
        let v = v.to_lowercase();
        for c in choices {
            let prefix: String = c.chars().take(v.chars().count()).collect();
            if prefix.to_lowercase() == v {
                return Some(c.to_string());
            }
        }
        None
    }

    pub fn parse_policy(&self, val: &Json) -> Option<String> {
        self.parse_enum(val, &["accept", "reject", "drop"])
    }

    pub fn parse_bool(&self, val: &Json) -> Option<bool> {
        if ["1", "on", "true", "yes"]
            .iter()
            .any(|k| loose_eq_str(val, k))
        {
            Some(true)
        } else if ["0", "off", "false", "no"]
            .iter()
            .any(|k| loose_eq_str(val, k))
        {
            Some(false)
        } else {
            None
        }
    }

    pub fn parse_family(&self, val: &Json) -> Option<i64> {
        if ["any", "all", "*"].iter().any(|k| loose_eq_str(val, k)) {
            return Some(0);
        }
        match val {
            Json::Str(s) => {
                if s == "inet" || s.contains('4') {
                    Some(4)
                } else if s.contains('6') {
                    Some(6)
                } else {
                    None
                }
            }
            // index() on a non-string yields null and `null > -1` is true
            _ => Some(4),
        }
    }

    pub fn parse_zone_ref(&self, val: &Json) -> Option<ZoneRef> {
        if matches!(val, Json::Null) {
            return None;
        }
        if loose_eq_str(val, "*") {
            return Some(ZoneRef {
                any: true,
                zone: None,
            });
        }
        for (i, zone) in self.state.zones.iter().enumerate() {
            if loose_eq_str(val, &zone.name) {
                return Some(ZoneRef {
                    any: false,
                    zone: Some(i),
                });
            }
        }
        None
    }

    pub fn parse_device(&self, val: &Json) -> Option<Device> {
        let rv = self.parse_invert(val)?;
        if rv.val == "*" {
            Some(Device {
                invert: rv.invert,
                any: true,
                device: None,
            })
        } else {
            Some(Device {
                invert: rv.invert,
                any: false,
                device: Some(rv.val),
            })
        }
    }

    pub fn parse_direction(&self, val: &Json) -> Option<bool> {
        if loose_eq_str(val, "in") || loose_eq_str(val, "ingress") {
            Some(false)
        } else if loose_eq_str(val, "out") || loose_eq_str(val, "egress") {
            Some(true)
        } else {
            None
        }
    }

    pub fn parse_setmatch(&self, val: &Json) -> Option<SetMatch> {
        let rv = self.parse_invert(val)?;
        let (name, rest) = match rv.val.find([' ', '\t']) {
            Some(i) => (rv.val[..i].to_owned(), trim(&rv.val[i..]).to_owned()),
            None => (rv.val.clone(), String::new()),
        };
        let mut dir: Vec<Option<String>> = Vec::new();
        for (i, tok) in rest.split([' ', '\t', ',']).enumerate() {
            if i >= 3 {
                break;
            }
            let d = match tok {
                "dst" | "dest" => Some("dst"),
                "src" => Some("src"),
                _ => None,
            };
            if let Some(d) = d {
                while dir.len() <= i {
                    dir.push(None);
                }
                dir[i] = Some(d.to_owned());
            }
        }
        if name.is_empty() {
            return None;
        }
        Some(SetMatch {
            invert: rv.invert,
            name,
            dir,
            fields: None,
        })
    }

    pub fn parse_cthelper(&self, val: &Json) -> Option<CtHelper> {
        let rv = self.parse_invert(val)?;
        let helper = self.state.helpers.iter().find(|h| h.name == rv.val)?;
        Some(CtHelper {
            invert: rv.invert,
            helper: helper.clone(),
        })
    }

    pub fn parse_protocol(&self, val: &Json) -> Option<Vec<Proto>> {
        let p = self.parse_invert(val)?;
        let v = if p.val.is_ascii() {
            let mut v = p.val;
            v.make_ascii_lowercase();
            v
        } else {
            p.val.to_lowercase()
        };
        let proto = |name: &str| Proto {
            invert: p.invert,
            any: false,
            name: Some(name.to_owned()),
        };
        let name = match v.as_str() {
            "all" | "any" | "*" => {
                return Some(vec![Proto {
                    invert: p.invert,
                    any: true,
                    name: None,
                }])
            }
            "1" | "icmp" => "icmp",
            "58" | "icmpv6" | "ipv6-icmp" => "ipv6-icmp",
            "tcpudp" => return Some(vec![proto("tcp"), proto("udp")]),
            "6" => "tcp",
            "17" => "udp",
            // the lowercased value itself is the protocol name
            _ => {
                return Some(vec![Proto {
                    invert: p.invert,
                    any: false,
                    name: Some(v),
                }])
            }
        };
        Some(vec![proto(name)])
    }

    pub fn parse_mac(&self, val: &Json) -> Option<Mac> {
        let mac = self.parse_invert(val)?;
        let parts: Vec<&str> = mac.val.split([':', '-']).collect();
        if parts.len() != 6
            || parts
                .iter()
                .any(|p| p.is_empty() || p.len() > 2 || !hexdigits(p))
        {
            return None;
        }
        let bytes: Vec<String> = parts
            .iter()
            .map(|p| format!("{:02x}", i64::from_str_radix(p, 16).unwrap_or(0)))
            .collect();
        Some(Mac {
            invert: mac.invert,
            mac: bytes.join(":"),
        })
    }

    pub fn parse_port(&self, val: &Json) -> Option<Port> {
        let port = self.parse_invert(val)?;
        let (lo, hi) = match port.val.find(['-', ':']) {
            Some(i) => (&port.val[..i], Some(&port.val[i + 1..])),
            None => (port.val.as_str(), None),
        };
        if !digits(lo) || lo.len() > 5 {
            return None;
        }
        let min: i64 = lo.parse().ok()?;
        let max = match hi {
            Some(h) => {
                if !digits(h) || h.len() > 5 {
                    return None;
                }
                h.parse().ok()?
            }
            None => min,
        };
        if min > max || min > 65535 || max > 65535 {
            return None;
        }
        Some(Port {
            invert: port.invert,
            min,
            max,
        })
    }

    pub fn parse_subnet(&self, subnet: &str) -> Option<Vec<Addr>> {
        let parts: Vec<&str> = subnet.split('/').collect();
        match parts.len() {
            2 => {
                let mut a = ip::iptoarr(parts[0])?;
                let m = ip::iptoarr(parts[1]);
                let family = if a.len() == 16 { 6 } else { 4 };
                let (mask, bits) = match m {
                    Some(m) => {
                        if a.len() != m.len() {
                            return None;
                        }
                        let bits = match ip::to_bits(parts[1]) {
                            Some(b) => b,
                            None => {
                                for (x, y) in a.iter_mut().zip(m.iter()) {
                                    *x &= y;
                                }
                                -1
                            }
                        };
                        (ip::arrtoip(&m), bits)
                    }
                    None => {
                        let Num::Int(b) = num_of(parts[1]) else {
                            return None;
                        };
                        (ip::to_mask(b, a.len() == 16), b.max(-1))
                    }
                };
                Some(vec![Addr {
                    family,
                    addr: ip::arrtoip(&a)?,
                    mask,
                    bits: Some(bits),
                    addr2: None,
                    range: false,
                    invert: false,
                }])
            }
            1 => {
                let parts: Vec<&str> = parts[0].split('-').collect();
                match parts.len() {
                    2 => {
                        let a = ip::iptoarr(parts[0]);
                        let b = ip::iptoarr(parts[1]);
                        if let (Some(a), Some(b)) = (a, b) {
                            if a.len() == b.len() {
                                return Some(vec![Addr {
                                    family: if a.len() == 16 { 6 } else { 4 },
                                    addr: ip::arrtoip(&a)?,
                                    mask: None,
                                    bits: None,
                                    addr2: ip::arrtoip(&b),
                                    range: true,
                                    invert: false,
                                }]);
                            }
                        }
                        None
                    }
                    1 => {
                        if let Some(a) = ip::iptoarr(parts[0]) {
                            let v6 = a.len() == 16;
                            return Some(vec![Addr {
                                family: if v6 { 6 } else { 4 },
                                addr: ip::arrtoip(&a)?,
                                mask: ip::to_mask(a.len() as i64 * 8, v6),
                                bits: Some(a.len() as i64 * 8),
                                addr2: None,
                                range: false,
                                invert: false,
                            }]);
                        }
                        self.state.network(parts[0]).map(|n| n.ipaddrs.clone())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn parse_network(&self, val: &Json) -> Option<Network> {
        let rv = self.parse_invert(val)?;
        let nets = self.parse_subnet(&rv.val)?;
        Some(Network {
            invert: rv.invert,
            addrs: if nets.is_empty() { None } else { Some(nets) },
        })
    }

    pub fn parse_icmptype(&self, val: &Json) -> Option<IcmpType> {
        let name = to_str(val);
        let mut rv = IcmpType {
            family: 0,
            ty: None,
            code_min: None,
            code_max: None,
            ty6: None,
            code6_min: None,
            code6_max: None,
        };
        let mut have_family = false;
        if let Some((t, lo, hi)) = ipv4_icmptype(&name) {
            rv.family = 4;
            rv.ty = Some(t);
            rv.code_min = Some(lo);
            rv.code_max = Some(hi);
            have_family = true;
        }
        if let Some((t, lo, hi)) = ipv6_icmptype(&name) {
            rv.family = if have_family { 0 } else { 6 };
            rv.ty6 = Some(t);
            rv.code6_min = Some(lo);
            rv.code6_max = Some(hi);
            have_family = true;
        }
        if !have_family {
            let (t, code) = match name.split_once('/') {
                Some((t, c)) => (t, Some(c)),
                None => (name.as_str(), None),
            };
            if !digits(t) || code.map(|c| !digits(c)).unwrap_or(false) {
                return None;
            }
            let t = num_of(t).as_i64();
            let (lo, hi) = match code {
                Some(c) => {
                    let c = num_of(c).as_i64();
                    (c, c)
                }
                None => (0, 0xFF),
            };
            if t > 0xFF || lo > 0xFF || hi > 0xFF {
                return None;
            }
            rv.family = 0;
            rv.ty = Some(t);
            rv.code_min = Some(lo);
            rv.code_max = Some(hi);
            rv.ty6 = Some(t);
            rv.code6_min = Some(lo);
            rv.code6_max = Some(hi);
        }
        Some(rv)
    }

    pub fn parse_limit(&self, val: &Json) -> Option<Limit> {
        let rv = self.parse_invert(val)?;
        let (n, unit) = match rv.val.split_once('/') {
            Some((n, u)) => (n, Some(u)),
            None => (rv.val.as_str(), None),
        };
        if !digits(n) {
            return None;
        }
        let unit = match unit {
            Some(u) => {
                if u.is_empty() || !u.bytes().all(|b| b.is_ascii_lowercase()) {
                    return None;
                }
                self.parse_enum(
                    &Json::Str(u.to_owned()),
                    &["second", "minute", "hour", "day"],
                )?
            }
            None => "second".to_owned(),
        };
        Some(Limit {
            invert: rv.invert,
            rate: num_of(n),
            unit,
        })
    }

    pub fn parse_int(&self, val: &Json) -> Option<Num> {
        let n = to_num(val);
        if n.is_nan() {
            None
        } else {
            Some(n)
        }
    }

    pub fn parse_date(&self, val: &Json) -> Option<DateTime> {
        let s = to_str(val);
        // ^([0-9]{4})(-([0-9]{1,2})(-([0-9]{1,2})(T([0-9:]+))?)?)?$
        if !s.is_ascii() {
            // the regex cannot match, and split_at below must not land inside a character
            return None;
        }
        let (year, rest) = s.split_at(s.len().min(4));
        if year.len() != 4 || !digits(year) {
            return None;
        }
        let mut month: Option<&str> = None;
        let mut day: Option<&str> = None;
        let mut time: Option<&str> = None;
        if !rest.is_empty() {
            let r = rest.strip_prefix('-')?;
            let (m, r) = match r.find('-') {
                Some(i) => (&r[..i], Some(&r[i + 1..])),
                None => (r, None),
            };
            if !digits(m) || m.len() > 2 {
                return None;
            }
            month = Some(m);
            if let Some(r) = r {
                let (d, r) = match r.find('T') {
                    Some(i) => (&r[..i], Some(&r[i + 1..])),
                    None => (r, None),
                };
                if !digits(d) || d.len() > 2 {
                    return None;
                }
                day = Some(d);
                if let Some(t) = r {
                    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit() || b == b':') {
                        return None;
                    }
                    time = Some(t);
                }
            }
        }
        let y = num_of(year).as_i64();
        if !(1970..=2038).contains(&y) {
            return None;
        }
        if month.map(|m| num_of(m).as_i64() > 12).unwrap_or(false)
            || day.map(|d| num_of(d).as_i64() > 31).unwrap_or(false)
        {
            return None;
        }
        let t = self.parse_time(&Json::Str(time.unwrap_or("0").to_owned()))?;
        let month = month.map(|m| num_of(m).as_i64()).unwrap_or(0);
        let day = day.map(|d| num_of(d).as_i64()).unwrap_or(0);
        Some(DateTime {
            year: y,
            month: if month == 0 { 1 } else { month },
            day: if day == 0 { 1 } else { day },
            hour: t.hour,
            min: t.min,
            sec: t.sec,
        })
    }

    pub fn parse_time(&self, val: &Json) -> Option<Time> {
        let s = to_str(val);
        let parts: Vec<&str> = s.split(':').collect();
        if parts.is_empty() || parts.len() > 3 {
            return None;
        }
        for p in &parts {
            if !digits(p) || p.len() > 2 {
                return None;
            }
        }
        let hour = num_of(parts[0]).as_i64();
        let min = parts.get(1).map(|p| num_of(p).as_i64()).unwrap_or(0);
        let sec = parts.get(2).map(|p| num_of(p).as_i64()).unwrap_or(0);
        if hour > 23 || min > 59 || sec > 59 {
            return None;
        }
        Some(Time { hour, min, sec })
    }

    pub fn parse_weekdays(&self, val: &Json) -> Option<Weekdays> {
        let rv = self.parse_invert(val)?;
        let mut days: Vec<String> = Vec::new();
        for day in to_array(&Json::Str(rv.val.clone())) {
            let d = self.parse_enum(
                &day,
                &[
                    "Monday",
                    "Tuesday",
                    "Wednesday",
                    "Thursday",
                    "Friday",
                    "Saturday",
                    "Sunday",
                ],
            )?;
            if !days.contains(&d) {
                days.push(d);
            }
        }
        if days.is_empty() {
            return None;
        }
        Some(Weekdays {
            invert: rv.invert,
            days,
        })
    }

    pub fn parse_monthdays(&self, val: &Json) -> Option<()> {
        let rv = self.parse_invert(val)?;
        let items = to_array(&Json::Str(rv.val));
        for day in &items {
            let d = to_num(day);
            if !d.is_nan() && (d.as_f64() < 1.0 || d.as_f64() > 31.0) {
                return None;
            }
        }
        if items.is_empty() {
            None
        } else {
            Some(())
        }
    }

    pub fn parse_mark(&self, val: &Json) -> Option<Mark> {
        let rv = self.parse_invert(val)?;
        let (m1, m3) = match rv.val.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (rv.val.as_str(), None),
        };
        // (0?x?[0-9a-f]+) case-insensitive
        let markish = |s: &str| {
            if hexdigits(s) {
                return true;
            }
            let t1 = s.strip_prefix('0');
            let t2 = s.strip_prefix(['x', 'X']);
            let t3 = t1.and_then(|t| t.strip_prefix(['x', 'X']));
            [t1, t2, t3]
                .iter()
                .any(|t| t.map(hexdigits).unwrap_or(false))
        };
        if !markish(m1) || m3.map(|m| !markish(m)).unwrap_or(false) {
            return None;
        }
        let n = num_of(m1);
        if n.is_nan() || n.as_f64() > 0xFFFF_FFFFu32 as f64 {
            return None;
        }
        let mut mark = Mark {
            invert: rv.invert,
            mark: n.as_i64(),
            mask: 0xFFFF_FFFF,
        };
        if let Some(m3) = m3 {
            let n = num_of(m3);
            if n.is_nan() || n.as_f64() > 0xFFFF_FFFFu32 as f64 {
                return None;
            }
            mark.mask = n.as_i64();
        }
        Some(mark)
    }

    pub fn parse_dscp(&self, val: &Json) -> Option<Dscp> {
        let rv = self.parse_invert(val)?;
        let v = rv.val.to_uppercase();
        if let Some(d) = dscp_class(&v) {
            return Some(Dscp {
                invert: rv.invert,
                dscp: d,
            });
        }
        let n = num_of(&v);
        if n.is_nan() || n.as_f64() < 0.0 || n.as_f64() > 0x3F as f64 {
            return None;
        }
        Some(Dscp {
            invert: rv.invert,
            dscp: n.as_i64(),
        })
    }

    pub fn parse_target(&self, val: &Json) -> Option<String> {
        self.parse_enum(
            val,
            &[
                "accept",
                "reject",
                "drop",
                "notrack",
                "helper",
                "mark",
                "dscp",
                "dnat",
                "snat",
                "masquerade",
                "accept",
                "reject",
                "drop",
            ],
        )
    }

    pub fn parse_reject_code(&self, val: &Json) -> Option<String> {
        self.parse_enum(
            val,
            &[
                "tcp-reset",
                "port-unreachable",
                "admin-prohibited",
                "host-unreachable",
                "no-route",
            ],
        )
    }

    pub fn parse_reflection_source(&self, val: &Json) -> Option<String> {
        self.parse_enum(val, &["internal", "external"])
    }

    pub fn parse_ipsettype(&self, val: &Json) -> Option<(String, String)> {
        let s = to_str(val);
        let m = ["src_", "dst_", "dest_"]
            .iter()
            .find_map(|p| s.strip_prefix(p).filter(|r| !r.is_empty()).map(|r| (*p, r)));
        let t = self.parse_enum(
            &Json::Str(m.map(|(_, r)| r.to_owned()).unwrap_or(s.clone())),
            &["ip", "port", "mac", "net", "set"],
        )?;
        let dir = match m {
            None | Some(("src_", _)) => "src",
            _ => "dst",
        };
        Some((dir.to_owned(), t))
    }

    pub fn parse_ipsetentry(&self, val: &str, set: &Ipset) -> Option<Vec<String>> {
        fn split_ws_runs(val: &str) -> Vec<&str> {
            let b = val.as_bytes();
            let n = b.len();
            let mut parts = Vec::new();
            let mut i = 0;
            loop {
                let start = i;
                while i < n && b[i] != b' ' && b[i] != b'\t' {
                    i += 1;
                }
                parts.push(&val[start..i]);
                if i >= n {
                    break;
                }
                while i < n && (b[i] == b' ' || b[i] == b'\t') {
                    i += 1;
                }
                if i >= n {
                    parts.push("");
                    break;
                }
            }
            parts
        }
        // ucode split(val, /[ \t]+/): split on maximal whitespace runs. A
        // leading or trailing run yields one empty element; runs between
        // tokens collapse to a single boundary.
        let values: Vec<&str> = split_ws_runs(val);
        if values.len() != set.types.len() {
            return None;
        }
        let mut rv = Vec::new();
        for (i, t) in set.types.iter().enumerate() {
            match t.as_str() {
                "ipv4_addr" | "ipv6_addr" => {
                    let fam = if t == "ipv4_addr" { 4 } else { 6 };
                    let ip: Vec<Addr> = self
                        .parse_subnet(values[i])
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|a| a.family == fam)
                        .collect();
                    match ip.len() {
                        0 => return None,
                        1 => {}
                        n => {
                            if fam == 4 || n == 2 {
                                self.warn(&format!(
                                    "Set entry '{}' resolves to multiple addresses, using first one",
                                    values[i]
                                ));
                            }
                        }
                    }
                    let a = &ip[0];
                    rv.push(if set.fw4types.iter().any(|x| x == "net") {
                        format!(
                            "{}/{}",
                            a.addr,
                            a.bits
                                .map(|b| b.to_string())
                                .unwrap_or_else(|| "null".into())
                        )
                    } else {
                        a.addr.clone()
                    });
                }
                "ether_addr" => {
                    let mac = self.parse_mac(&Json::Str(values[i].to_owned()))?;
                    if mac.invert {
                        return None;
                    }
                    rv.push(mac.mac);
                }
                "inet_service" => {
                    let port = self.parse_port(&Json::Str(values[i].to_owned()))?;
                    if port.invert || port.min != port.max {
                        return None;
                    }
                    rv.push(port.min.to_string());
                }
                _ => rv.push(values[i].to_owned()),
            }
        }
        if rv.is_empty() {
            None
        } else {
            Some(rv)
        }
    }

    pub fn parse_includetype(&self, val: &Json) -> Option<String> {
        self.parse_enum(val, &["script", "nftables"])
    }

    pub fn parse_includeposition(&self, val: &Json) -> Option<String> {
        let p = self.parse_enum(
            val,
            &[
                "ruleset-prepend",
                "ruleset-postpend",
                "ruleset-append",
                "table-prepend",
                "table-postpend",
                "table-append",
                "chain-prepend",
                "chain-postpend",
                "chain-append",
            ],
        )?;
        Some(p.replace("postpend", "append"))
    }

    pub fn parse_identifier(&self, val: &Json) -> Option<String> {
        let s = to_str(val);
        let mut chars = s.chars();
        let first = chars.next()?;
        if !(first.is_ascii_alphabetic() || first == '_' || first == '.') {
            return None;
        }
        if chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-')) {
            Some(s)
        } else {
            None
        }
    }

    pub fn parse_string(&self, val: &Json) -> Option<String> {
        Some(to_str(val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fw() -> Fw4 {
        Fw4 {
            inputs: Inputs::mock(vec![], false),
            firewall: Rc::new(Config::empty()),
            helpers_cfg: Rc::new(Config::empty()),
            state: State::default(),
            kernel: 0,
            quiet: true,
            aborted: false,
            tty: false,
        }
    }

    fn js(s: &str) -> Json {
        Json::Str(s.to_owned())
    }

    #[test]
    fn primitives() {
        let f = fw();
        assert_eq!(
            f.parse_enum(&js("ACC"), &["accept", "reject"]),
            Some("accept".into())
        );
        assert_eq!(f.parse_enum(&js("x"), &["accept"]), None);
        assert_eq!(f.parse_bool(&Json::Int(0)), Some(false));
        assert_eq!(f.parse_bool(&js("yes")), Some(true));
        assert_eq!(f.parse_family(&js("ipv6")), Some(6));
        assert_eq!(f.parse_family(&js("any")), Some(0));
        let p = f.parse_port(&js("! 80-90")).unwrap();
        assert!(p.invert && p.min == 80 && p.max == 90);
        assert_eq!(f.parse_port(&js("70000")), None);
        assert_eq!(
            f.parse_mac(&js("AA:b-1:2:3:4")).unwrap().mac,
            "aa:0b:01:02:03:04"
        );
        let l = f.parse_limit(&js("25/s")).unwrap();
        assert_eq!(l.unit, "second");
        assert_eq!(f.parse_limit(&js("25/Second")), None);
        let m = f.parse_mark(&js("0x10/0xff")).unwrap();
        assert_eq!((m.mark, m.mask), (16, 255));
        assert_eq!(f.parse_mark(&js("ff")), None);
        let m = f.parse_mark(&js("0/0xffffff51")).unwrap();
        assert_eq!((m.mark, m.mask), (0, 0xffffff51));
        assert_eq!(f.parse_dscp(&js("af11")).unwrap().dscp, 0x0a);
        let d = f.parse_date(&js("2021-03-04T05:06")).unwrap();
        assert_eq!(
            (d.year, d.month, d.day, d.hour, d.min, d.sec),
            (2021, 3, 4, 5, 6, 0)
        );
        let d = f.parse_date(&js("2021")).unwrap();
        assert_eq!((d.month, d.day, d.hour), (1, 1, 0));
        assert_eq!(f.parse_date(&js("1969")), None);
        assert_eq!(f.parse_time(&js("24:00")), None);
        let w = f.parse_weekdays(&js("mon tue mon")).unwrap();
        assert_eq!(w.days, vec!["Monday", "Tuesday"]);
        assert_eq!(f.parse_protocol(&js("tcpudp")).unwrap().len(), 2);
        assert_eq!(f.parse_protocol(&js("58")).unwrap()[0].name(), "ipv6-icmp");
        let i = f.parse_icmptype(&js("echo-request")).unwrap();
        assert_eq!((i.family, i.ty, i.ty6), (0, Some(8), Some(128)));
        let i = f.parse_icmptype(&js("3/4")).unwrap();
        assert_eq!((i.ty, i.code_min, i.code_max), (Some(3), Some(4), Some(4)));
        assert_eq!(
            f.parse_ipsettype(&js("dest_ip")),
            Some(("dst".into(), "ip".into()))
        );
        assert_eq!(
            f.parse_ipsettype(&js("mac")),
            Some(("src".into(), "mac".into()))
        );
        assert_eq!(
            f.parse_includeposition(&js("table-postpend")),
            Some("table-append".into())
        );
        assert_eq!(f.parse_identifier(&js("1abc")), None);
        assert_eq!(f.parse_identifier(&js("_a/b.c-d")), Some("_a/b.c-d".into()));
        let sm = f.parse_setmatch(&js("! myset dst,src")).unwrap();
        assert!(
            sm.invert
                && sm.name == "myset"
                && sm.dir == vec![Some("dst".into()), Some("src".into())]
        );
    }

    #[test]
    fn subnets() {
        let f = fw();
        let a = &f.parse_subnet("10.0.0.5/24").unwrap()[0];
        assert_eq!(
            (a.addr.as_str(), a.bits, a.mask.as_deref()),
            ("10.0.0.5", Some(24), Some("255.255.255.0"))
        );
        let a = &f.parse_subnet("10.0.0.5/255.0.255.0").unwrap()[0];
        assert_eq!((a.addr.as_str(), a.bits), ("10.0.0.0", Some(-1)));
        let a = &f.parse_subnet("10.0.0.1-10.0.0.9").unwrap()[0];
        assert!(a.range && a.addr2.as_deref() == Some("10.0.0.9"));
        let a = &f.parse_subnet("2001:db8::1").unwrap()[0];
        assert_eq!((a.family, a.bits), (6, Some(128)));
        assert_eq!(f.parse_subnet("nosuchnet"), None);
        assert_eq!(f.parse_subnet("10.0.0.1/abc"), None);
        assert_eq!(f.parse_subnet("10.0.0.1/24.0"), None);
    }
}
