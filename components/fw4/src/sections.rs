//! Section parsers (`parse_helper` .. `parse_ipset`), ubus state gathering and
//! `load()` — the second half of fw4.uc.

use crate::emit;
use crate::parse::*;
use crate::state::*;
use crate::val::{loose_eq_str, to_str, truthy, Num};
use owrt_ubus::json::Json;
use std::rc::Rc;

/// `subnets_split_af()` result: [0] IPv4, [1] IPv6, family.
#[derive(Default, Clone)]
pub struct Split {
    pub v4: Option<Vec<Addr>>,
    pub v6: Option<Vec<Addr>>,
    pub family: Option<i64>,
}

impl Split {
    pub fn get(&self, i: usize) -> Option<&Vec<Addr>> {
        if i == 0 {
            self.v4.as_ref()
        } else {
            self.v6.as_ref()
        }
    }
    /// ucode `length(split)` truthiness: any key present
    pub fn non_empty(&self) -> bool {
        self.v4.is_some() || self.v6.is_some()
    }
    pub fn len(&self, i: usize) -> usize {
        self.get(i).map(|v| v.len()).unwrap_or(0)
    }
}

pub fn subnets_split_af(groups: &[Network]) -> Split {
    let mut rv = Split::default();
    for ag in groups {
        for a in ag.addrs.iter().flatten() {
            let mut a = a.clone();
            a.invert = ag.invert;
            if a.family == 4 {
                rv.v4.get_or_insert_with(Vec::new).push(a);
            } else if a.family == 6 {
                rv.v6.get_or_insert_with(Vec::new).push(a);
            }
        }
    }
    if rv.v4.is_some() || rv.v6.is_some() {
        rv.family = Some(match (&rv.v4, &rv.v6) {
            (Some(_), None) => 4,
            (None, Some(_)) => 6,
            _ => 0,
        });
    }
    rv
}

/// Split of a bare address list (`subnets_split_af({ addrs: [...] })`).
pub fn split_addrs(addrs: &[Addr]) -> Split {
    subnets_split_af(&[Network {
        invert: false,
        addrs: Some(addrs.to_vec()),
    }])
}

fn nie<T: Clone>(v: &[T]) -> Option<Vec<T>> {
    if v.is_empty() {
        None
    } else {
        Some(v.to_vec())
    }
}

pub fn subnets_group_by_masking(x: Option<&Vec<Addr>>) -> Vec<SubnetGroup> {
    let mut groups = Vec::new();
    let (mut plain, mut nc, mut invert_plain, mut invert_masked) = (vec![], vec![], vec![], vec![]);
    for a in x.into_iter().flatten() {
        if a.is_masked() && !a.invert {
            nc.push(a.clone());
        } else if !a.invert {
            plain.push(a.clone());
        } else if a.is_masked() {
            invert_masked.push(a.clone());
        } else {
            invert_plain.push(a.clone());
        }
    }
    for a in &nc {
        let mut masked = vec![a.clone()];
        masked.extend(invert_masked.iter().cloned());
        groups.push((None, nie(&invert_plain), Some(masked)));
    }
    if !plain.is_empty() {
        groups.push((Some(plain), nie(&invert_plain), nie(&invert_masked)));
    } else if groups.is_empty() {
        groups.push((None, nie(&invert_plain), nie(&invert_masked)));
    }
    groups
}

pub fn ensure_tcpudp(x: &mut Vec<Proto>) -> bool {
    if x.iter().any(|p| p.name() == "tcp" || p.name() == "udp") {
        return true;
    }
    let any = x.iter().filter(|p| p.any).count();
    let rest = x.iter().filter(|p| !p.any).count();
    if any > 0 && rest == 0 {
        x.clear();
        x.push(Proto {
            invert: false,
            any: false,
            name: Some("tcp".into()),
        });
        x.push(Proto {
            invert: false,
            any: false,
            name: Some("udp".into()),
        });
        return true;
    }
    false
}

/// `infer_family(f, [obj, desc, ...])` with each object's family (0 = none).
pub fn infer_family(f: Option<i64>, objects: &[(Vec<i64>, &str)]) -> Result<Option<i64>, String> {
    let mut res = f;
    for (fams, desc) in objects {
        for fam in fams {
            if *fam == 0 || Some(*fam) == res {
                continue;
            }
            match res {
                None | Some(0) => res = Some(*fam),
                Some(r) => {
                    return Err(format!(
                        "is restricted to IPv{r} but referenced {desc} is IPv{fam} only"
                    ))
                }
            }
        }
    }
    Ok(res)
}

fn fam_of<T>(v: Option<T>, f: impl Fn(T) -> i64) -> Vec<i64> {
    v.map(|x| vec![f(x)]).unwrap_or_default()
}

/// `map_setmatch()`: Err(()) is the NaN "destination MAC" case.
pub fn map_setmatch(
    set: Option<&Ipset>,
    m: &SetMatch,
    proto: &str,
) -> Result<Option<Vec<String>>, ()> {
    let Some(set) = set else { return Ok(None) };
    if set.types.iter().any(|t| t == "inet_service") && proto != "tcp" && proto != "udp" {
        return Ok(None);
    }
    let mut fields = Vec::new();
    for (i, t) in set.types.iter().enumerate() {
        let dir = m
            .dir
            .get(i)
            .cloned()
            .flatten()
            .or_else(|| set.directions.get(i).cloned())
            .unwrap_or_else(|| "src".into());
        let d = if dir == "src" { 's' } else { 'd' };
        match t.as_str() {
            "ipv4_addr" => fields.push(format!("ip {d}addr")),
            "ipv6_addr" => fields.push(format!("ip6 {d}addr")),
            "ether_addr" => {
                if d != 's' {
                    return Err(());
                }
                fields.push("ether saddr".into());
            }
            "inet_service" => fields.push(format!("{proto} {d}port")),
            _ => {}
        }
    }
    Ok(Some(fields))
}

fn filter_pos(v: Option<&Vec<Port>>) -> Option<Vec<String>> {
    let out: Vec<String> = v?.iter().filter(|p| !p.invert).map(emit::port).collect();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn filter_neg(v: Option<&Vec<Port>>) -> Option<Vec<String>> {
    let out: Vec<String> = v?.iter().filter(|p| p.invert).map(emit::port).collect();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn macs(v: Option<&Vec<Mac>>, invert: bool) -> Option<Vec<String>> {
    let out: Vec<String> = v?
        .iter()
        .filter(|m| m.invert == invert)
        .map(|m| m.mac.clone())
        .collect();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn cidrs(v: Option<&Vec<Addr>>) -> Option<Vec<String>> {
    v.map(|a| a.iter().map(emit::cidr).collect())
}

fn to_hostaddr(a: &Addr) -> Addr {
    let bits = if a.family == 4 { 32 } else { 128 };
    Addr {
        family: a.family,
        addr: crate::ip::apply_mask(&a.addr, crate::ip::Mask::Bits(bits))
            .unwrap_or_else(|| "null".into()),
        mask: None,
        bits: Some(bits),
        addr2: None,
        range: false,
        invert: false,
    }
}

fn empty_group() -> SubnetGroup {
    (None, None, None)
}

fn zone_family(state: &State, z: Option<ZoneRef>) -> Vec<i64> {
    match z.and_then(|r| r.zone) {
        Some(i) => vec![state.zones[i].family],
        None => vec![],
    }
}

fn helper_family(h: Option<&CtHelper>) -> Vec<i64> {
    fam_of(h, |h| h.helper.family.unwrap_or(0))
}

pub struct RuleOpts {
    enabled: bool,
    name: Option<String>,
    family: Option<i64>,
    src: Option<ZoneRef>,
    dest: Option<ZoneRef>,
    device: Option<Device>,
    direction: Option<bool>,
    ipset: Option<SetMatch>,
    helper: Option<CtHelper>,
    set_helper: Option<CtHelper>,
    proto: Vec<Proto>,
    src_ip: Option<Vec<Network>>,
    src_mac: Option<Vec<Mac>>,
    src_port: Option<Vec<Port>>,
    dest_ip: Option<Vec<Network>>,
    dest_port: Option<Vec<Port>>,
    icmp_type: Option<Vec<IcmpType>>,
    limit: Option<Limit>,
    limit_burst: Option<Num>,
    start_date: Option<DateTime>,
    stop_date: Option<DateTime>,
    start_time: Option<Time>,
    stop_time: Option<Time>,
    weekdays: Option<Weekdays>,
    mark: Option<Mark>,
    set_mark: Option<Mark>,
    set_xmark: Option<Mark>,
    dscp: Option<Dscp>,
    set_dscp: Option<Dscp>,
    counter: bool,
    log: Option<String>,
    log_limit: Option<Limit>,
    target: Option<String>,
}

impl Fw4 {
    fn zone_name(&self, r: Option<ZoneRef>) -> String {
        match r.and_then(|r| r.zone) {
            Some(i) => self.state.zones[i].name.clone(),
            None => "null".into(),
        }
    }

    fn zone_mut(&mut self, r: Option<ZoneRef>) -> Option<&mut Zone> {
        let i = r?.zone?;
        self.state.zones.get_mut(i)
    }

    fn default_policy(&self, which: &str) -> Json {
        let p = self.state.defaults.as_ref().and_then(|d| match which {
            "input" => d.input.clone(),
            "output" => d.output.clone(),
            _ => d.forward.clone(),
        });
        Json::Str(p.unwrap_or_else(|| "drop".into()))
    }

    // ------------------------------------------------------------ helper

    pub fn parse_helper(&mut self, data: &Json) {
        let parsed = {
            let mut o = Opts::new(self, data);
            let r = (|| {
                let name = o.opt("name", None, REQUIRED, |f, v| f.parse_string(v))?;
                let description = o.opt("description", None, 0, |f, v| f.parse_string(v))?;
                let module = o.opt("module", None, 0, |f, v| f.parse_string(v))?;
                let family = o.opt("family", None, 0, |f, v| f.parse_family(v))?;
                let proto = o.list(
                    "proto",
                    None,
                    PARSE_LIST | FLATTEN_LIST | NO_INVERT,
                    |f, v| f.parse_protocol(v),
                )?;
                let port = o.opt("port", None, NO_INVERT, |f, v| f.parse_port(v))?;
                Ok::<_, ()>((name, description, module, family, proto, port))
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        let label = || {
            data.get("name")
                .filter(|v| truthy(v))
                .or_else(|| data.get(".name"))
                .map(to_str)
                .unwrap_or_else(|| "(null)".into())
        };
        let Ok((name, description, module, family, proto, port)) = parsed else {
            self.warn(&format!(
                "Helper definition '{}' skipped due to invalid options",
                label()
            ));
            return;
        };
        if let Some(p) = &proto {
            if p.len() > 1 {
                self.warn(&format!(
                    "Helper definition '{}' must not specify multiple protocols",
                    label()
                ));
                return;
            }
        }
        let available = self.inputs.stat_is_dir(&format!(
            "/sys/module/{}",
            module.clone().unwrap_or_else(|| "null".into())
        ));
        self.state.helpers.push(Helper {
            name: name.unwrap_or_default(),
            description,
            module,
            family,
            proto,
            port,
            available,
        });
    }

    // ------------------------------------------------------------ defaults

    /// `Err` is ucode aborting: `parse_options()` returns `false` and
    /// `fw4.uc:1978` dereferences it ("Reference error: left-hand side
    /// expression is not an array or object"), so the interpreter exits 254
    /// without rendering anything.  Verified against the upstream ucode fw4,
    /// see `tools/r83_fw4_defaults.sh` / R83.
    pub fn parse_defaults(&mut self, data: &Json) -> Result<(), ()> {
        if self.state.defaults.is_some() {
            self.warn_section(data, ": ignoring duplicate defaults section");
            return Ok(());
        }
        let parsed = {
            let mut o = Opts::new(self, data);
            #[allow(clippy::field_reassign_with_default)]
            // mirrors the option-by-option ucode parse
            let r = (|| {
                let mut d = Defaults::default();
                d.input = o.opt("input", s("drop"), 0, |f, v| f.parse_policy(v))?;
                d.output = o.opt("output", s("drop"), 0, |f, v| f.parse_policy(v))?;
                d.forward = o.opt("forward", s("drop"), 0, |f, v| f.parse_policy(v))?;
                d.drop_invalid = o.opt("drop_invalid", None, 0, |f, v| f.parse_bool(v))?;
                d.tcp_reject_code = o.opt("tcp_reject_code", s("tcp-reset"), 0, |f, v| {
                    f.parse_reject_code(v)
                })?;
                d.any_reject_code =
                    o.opt("any_reject_code", s("port-unreachable"), 0, |f, v| {
                        f.parse_reject_code(v)
                    })?;
                let syn_flood = o.opt("syn_flood", None, 0, |f, v| f.parse_bool(v))?;
                d.synflood_protect = o.opt("synflood_protect", None, 0, |f, v| f.parse_bool(v))?;
                d.synflood_rate =
                    o.opt("synflood_rate", s("25/second"), 0, |f, v| f.parse_limit(v))?;
                d.synflood_burst = o.opt("synflood_burst", s("50"), 0, |f, v| f.parse_int(v))?;
                o.opt("tcp_syncookies", s("1"), 0, |f, v| f.parse_bool(v))?;
                o.opt("tcp_ecn", None, 0, |f, v| f.parse_int(v))?;
                o.opt("tcp_window_scaling", s("1"), 0, |f, v| f.parse_bool(v))?;
                o.opt("accept_redirects", None, 0, |f, v| f.parse_bool(v))?;
                o.opt("accept_source_route", None, 0, |f, v| f.parse_bool(v))?;
                d.auto_helper = o.opt("auto_helper", s("1"), 0, |f, v| f.parse_bool(v))?;
                o.opt("custom_chains", None, UNSUPPORTED, |f, v| f.parse_bool(v))?;
                o.opt("disable_ipv6", None, UNSUPPORTED, |f, v| f.parse_bool(v))?;
                d.flow_offloading = o.opt("flow_offloading", s("0"), 0, |f, v| f.parse_bool(v))?;
                d.flow_offloading_hw =
                    o.opt("flow_offloading_hw", s("0"), 0, |f, v| f.parse_bool(v))?;
                d.auto_includes = o.opt("auto_includes", s("1"), 0, |f, v| f.parse_bool(v))?;
                if d.synflood_protect.is_none() {
                    d.synflood_protect = syn_flood;
                }
                Ok::<_, ()>(d)
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        self.state.defaults = Some(parsed?);
        Ok(())
    }

    // ------------------------------------------------------------ zone

    pub fn parse_zone(&mut self, data: &Json) {
        struct Z {
            enabled: bool,
            name: String,
            family: Option<i64>,
            network: Option<Vec<Device>>,
            device: Option<Vec<Device>>,
            subnet: Option<Vec<Network>>,
            input: String,
            output: String,
            forward: String,
            masq: bool,
            masq_allow_invalid: bool,
            masq_src: Option<Vec<Network>>,
            masq_dest: Option<Vec<Network>>,
            masq6: bool,
            mtu_fix: bool,
            log: Option<Num>,
            log_limit: Option<Limit>,
            auto_helper: bool,
            helper: Option<Vec<CtHelper>>,
            counter: bool,
        }
        let (di, do_, df) = (
            self.default_policy("input"),
            self.default_policy("output"),
            self.default_policy("forward"),
        );
        let parsed = {
            let mut o = Opts::new(self, data);
            let r = (|| {
                let enabled = o
                    .opt("enabled", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let name = o
                    .opt("name", None, REQUIRED, |f, v| f.parse_identifier(v))?
                    .unwrap_or_default();
                let family = o.opt("family", None, 0, |f, v| f.parse_family(v))?;
                let network = o.list("network", None, PARSE_LIST, |f, v| {
                    f.parse_device(v).map(|d| vec![d])
                })?;
                let device = o.list("device", None, PARSE_LIST, |f, v| {
                    f.parse_device(v).map(|d| vec![d])
                })?;
                let subnet = o.list("subnet", None, PARSE_LIST, |f, v| {
                    f.parse_network(v).map(|d| vec![d])
                })?;
                let input = o
                    .opt("input", Some(di), 0, |f, v| f.parse_policy(v))?
                    .unwrap_or_default();
                let output = o
                    .opt("output", Some(do_), 0, |f, v| f.parse_policy(v))?
                    .unwrap_or_default();
                let forward = o
                    .opt("forward", Some(df), 0, |f, v| f.parse_policy(v))?
                    .unwrap_or_default();
                let masq = o
                    .opt("masq", None, 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let masq_allow_invalid = o
                    .opt("masq_allow_invalid", None, 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let masq_src = o.list("masq_src", None, PARSE_LIST, |f, v| {
                    f.parse_network(v).map(|d| vec![d])
                })?;
                let masq_dest = o.list("masq_dest", None, PARSE_LIST, |f, v| {
                    f.parse_network(v).map(|d| vec![d])
                })?;
                let masq6 = o
                    .opt("masq6", None, 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                o.opt("extra", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                o.opt("extra_src", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                o.opt("extra_dest", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                let mtu_fix = o
                    .opt("mtu_fix", None, 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                o.opt("custom_chains", None, UNSUPPORTED, |f, v| f.parse_bool(v))?;
                let log = o.opt("log", None, 0, |f, v| f.parse_int(v))?;
                let log_limit = o.opt("log_limit", None, 0, |f, v| f.parse_limit(v))?;
                let auto_helper = o
                    .opt("auto_helper", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let helper = o.list("helper", None, PARSE_LIST, |f, v| {
                    f.parse_cthelper(v).map(|d| vec![d])
                })?;
                let counter = o
                    .opt("counter", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                Ok::<_, ()>(Z {
                    enabled,
                    name,
                    family,
                    network,
                    device,
                    subnet,
                    input,
                    output,
                    forward,
                    masq,
                    masq_allow_invalid,
                    masq_src,
                    masq_dest,
                    masq6,
                    mtu_fix,
                    log,
                    log_limit,
                    auto_helper,
                    helper,
                    counter,
                })
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        let Ok(mut z) = parsed else {
            self.warn_section(data, "skipped due to invalid options");
            return;
        };
        if !z.enabled {
            self.warn_section(data, "is disabled, ignoring section");
            return;
        }
        for h in z.helper.iter().flatten() {
            if !h.helper.available {
                self.warn_section(data, "uses unavailable ct helper 'null'");
            }
        }
        if z.mtu_fix && self.kernel < 0x040a0000 {
            self.warn_section(data, "option 'mtu_fix' requires kernel 4.10 or later");
            return;
        }
        if self.state.defaults.as_ref().and_then(|d| d.auto_helper) == Some(false) {
            z.auto_helper = false;
        }

        let mut match_devices: Vec<Device> = Vec::new();
        let mut related_physdevs: Vec<String> = Vec::new();
        let mut related_subnets: Vec<Addr> = Vec::new();
        let mut network: Vec<Device> = z.network.clone().unwrap_or_default();
        for (name, net) in &self.state.networks {
            if net.zone.as_deref() == Some(z.name.as_str()) {
                network.push(Device {
                    invert: false,
                    any: false,
                    device: Some(name.clone()),
                });
            }
        }
        for e in &network {
            let Some(net) = e.device.as_deref().and_then(|d| self.state.network(d)) else {
                continue;
            };
            if let Some(dev) = &net.device {
                match_devices.push(Device {
                    invert: e.invert,
                    any: false,
                    device: Some(dev.clone()),
                });
            }
            if net.physdev.is_some() && !e.invert {
                related_physdevs.push(net.physdev.clone().unwrap());
            }
            related_subnets.extend(net.ipaddrs.iter().cloned());
        }
        match_devices.extend(z.device.clone().unwrap_or_default());
        let match_subnets = subnets_split_af(z.subnet.as_deref().unwrap_or(&[]));
        let masq_src_subnets = subnets_split_af(z.masq_src.as_deref().unwrap_or(&[]));
        let masq_dest_subnets = subnets_split_af(z.masq_dest.as_deref().unwrap_or(&[]));
        related_subnets.extend(match_subnets.v4.iter().flatten().cloned());
        related_subnets.extend(match_subnets.v6.iter().flatten().cloned());

        let family = match infer_family(
            z.family,
            &[(
                match_subnets.family.map(|f| vec![f]).unwrap_or_default(),
                "subnet list",
            )],
        ) {
            Ok(f) => f,
            Err(msg) => {
                self.warn_section(data, &format!("{msg}, skipping"));
                return;
            }
        };

        // group non-inverted device matches into wildcard and non-wildcard ones
        let mut wildcard_groups: Vec<String> = Vec::new();
        let mut plain_devices: Vec<String> = Vec::new();
        let mut plain_invert: Vec<String> = Vec::new();
        let mut wildcard_invert: Vec<String> = Vec::new();
        for device in match_devices.iter_mut() {
            let Some(name) = device.device.clone() else {
                self.warn_section(data, "skipping invalid wildcard pattern 'null'");
                continue;
            };
            let (stem, plus) = match name.strip_suffix('+') {
                Some(st) => (st.to_owned(), true),
                None => (name.clone(), false),
            };
            if stem.contains('+') {
                self.warn_section(data, &format!("skipping invalid wildcard pattern '{name}'"));
                continue;
            }
            if !device.invert && name == "+" {
                continue;
            }
            let wildcard = plus;
            if device.invert && name == "+" {
                device.device = Some("/never/".into());
                device.invert = false;
                // ucode sets device.wildcard = !!m[2]; for "!+" the "+"
                // survives the rewrite, so /never/ stays a wildcard group.
            } else if plus {
                device.device = Some(format!("{stem}*"));
            }
            let devname = device.device.clone().unwrap();
            if !device.invert && wildcard {
                wildcard_groups.push(devname);
            } else if !device.invert {
                plain_devices.push(devname);
            } else if wildcard {
                wildcard_invert.push(devname);
            } else {
                plain_invert.push(devname);
            }
        }
        #[allow(clippy::type_complexity)]
        let mut devices: Vec<(Option<Vec<String>>, Vec<String>, Vec<String>)> = wildcard_groups
            .into_iter()
            .map(|d| (Some(vec![d]), plain_invert.clone(), wildcard_invert.clone()))
            .collect();
        if !plain_devices.is_empty() {
            devices.push((
                Some(plain_devices),
                plain_invert.clone(),
                wildcard_invert.clone(),
            ));
        } else if devices.is_empty() {
            devices.push((None, plain_invert.clone(), wildcard_invert.clone()));
        }

        let mut match_rules: Vec<MatchRule> = Vec::new();
        let add_rule = |family: i64,
                        devs: &(Option<Vec<String>>, Vec<String>, Vec<String>),
                        subnets: Option<&SubnetGroup>,
                        out: &mut Vec<MatchRule>| {
            out.push(MatchRule {
                family,
                devices_pos: devs.0.as_ref().and_then(|d| nie(d)),
                devices_neg: nie(&devs.1),
                devices_neg_wildcard: nie(&devs.2),
                subnets_pos: subnets.and_then(|s| cidrs(s.0.as_ref())),
                subnets_neg: subnets.and_then(|s| cidrs(s.1.as_ref())),
                subnets_masked: subnets.and_then(|s| s.2.clone()),
            });
        };
        if !match_devices.is_empty() || match_subnets.len(0) > 0 || match_subnets.len(1) > 0 {
            for devgroup in &devices {
                if family.unwrap_or(0) == 0
                    && match_subnets.len(0) == 0
                    && match_subnets.len(1) == 0
                {
                    add_rule(0, devgroup, None, &mut match_rules);
                } else {
                    if matches!(family, None | Some(0) | Some(4)) {
                        for subnets in subnets_group_by_masking(match_subnets.v4.as_ref()) {
                            add_rule(4, devgroup, Some(&subnets), &mut match_rules);
                        }
                    }
                    if matches!(family, None | Some(0) | Some(6)) {
                        for subnets in subnets_group_by_masking(match_subnets.v6.as_ref()) {
                            add_rule(6, devgroup, Some(&subnets), &mut match_rules);
                        }
                    }
                }
            }
        }

        let mut sflags = Flags::default();
        sflags.set(&z.input);
        let mut dflags = Flags::default();
        dflags.set(&z.output);
        dflags.set(&z.forward);
        if z.masq || z.masq6 {
            dflags.set("snat");
        }
        let zone_index = self.state.zones.len();
        let mut helper_rules: Vec<Rule> = Vec::new();
        if (z.auto_helper && !(z.masq || z.masq6))
            || z.helper.as_ref().map(|h| !h.is_empty()).unwrap_or(false)
        {
            dflags.set("helper");
            let helpers: Vec<&Helper> = match &z.helper {
                Some(h) if !h.is_empty() => h.iter().map(|c| &c.helper).collect(),
                _ => self.state.helpers.iter().collect(),
            };
            let mut aborted = false;
            for helper in helpers {
                if !helper.available {
                    continue;
                }
                // `this.port(helper.port)` with no port: ucode dies on
                // `p.min` of null (no shipped helper lacks a port).
                if helper.port.is_none() {
                    aborted = true;
                    continue;
                }
                for proto in helper.proto.iter().flatten() {
                    helper_rules.push(Rule {
                        chain: format!("helper_{}", z.name),
                        family: helper.family.unwrap_or(0),
                        name: helper
                            .description
                            .clone()
                            .unwrap_or_else(|| helper.name.clone()),
                        proto: proto.clone(),
                        src: Some(ZoneRef {
                            any: false,
                            zone: Some(zone_index),
                        }),
                        dports_pos: Some(vec![helper
                            .port
                            .as_ref()
                            .map(emit::port)
                            .unwrap_or_else(|| "null".into())]),
                        target: Some("helper".into()),
                        set_helper: Some(CtHelper {
                            invert: false,
                            helper: helper.clone(),
                        }),
                        ..Default::default()
                    });
                }
            }
            self.aborted |= aborted;
        }
        let zone = Zone {
            name: z.name,
            family: family.unwrap_or(0),
            input: z.input,
            output: z.output,
            forward: z.forward,
            masq: z.masq,
            masq_allow_invalid: z.masq_allow_invalid,
            masq6: z.masq6,
            mtu_fix: z.mtu_fix,
            log: z.log,
            log_limit: z.log_limit,
            auto_helper: z.auto_helper,
            helper: z.helper,
            counter: z.counter,
            network,
            match_rules,
            masq4_src_subnets: subnets_group_by_masking(masq_src_subnets.v4.as_ref()),
            masq4_dest_subnets: subnets_group_by_masking(masq_dest_subnets.v4.as_ref()),
            masq6_src_subnets: subnets_group_by_masking(masq_src_subnets.v6.as_ref()),
            masq6_dest_subnets: subnets_group_by_masking(masq_dest_subnets.v6.as_ref()),
            sflags,
            dflags,
            match_devices: match_devices
                .iter()
                .filter(|d| !d.invert)
                // Emit concrete device names; the exact image's any-device
                // control is covered by r92_fw4_probe.py.
                .filter_map(|d| d.device.clone())
                .collect(),
            match_subnets: related_subnets
                .iter()
                .filter(|s| !s.invert && !s.is_masked())
                .map(emit::cidr)
                .collect(),
            related_subnets,
            related_physdevs,
        };
        self.state.rules.extend(helper_rules);
        self.state.zones.push(zone);
    }

    // ------------------------------------------------------------ forwarding

    pub fn parse_forwarding(&mut self, data: &Json) {
        let parsed = {
            let mut o = Opts::new(self, data);
            let r = (|| {
                let enabled = o
                    .opt("enabled", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let name = o.opt("name", None, 0, |f, v| f.parse_string(v))?;
                let family = o.opt("family", None, 0, |f, v| f.parse_family(v))?;
                let src = o.opt("src", None, REQUIRED, |f, v| f.parse_zone_ref(v))?;
                let dest = o.opt("dest", None, REQUIRED, |f, v| f.parse_zone_ref(v))?;
                Ok::<_, ()>((enabled, name, family, src, dest))
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        let Ok((enabled, name, family, src, dest)) = parsed else {
            self.warn_section(data, "skipped due to invalid options");
            return;
        };
        if !enabled {
            self.warn_section(data, "is disabled, ignoring section");
            return;
        }
        let family = match infer_family(
            family,
            &[
                (zone_family(&self.state, src), "source zone"),
                (zone_family(&self.state, dest), "destination zone"),
            ],
        ) {
            Ok(f) => f,
            Err(msg) => {
                self.warn_section(data, &format!("{msg}, skipping"));
                return;
            }
        };
        let (src, dest) = (src.unwrap(), dest.unwrap());
        let fam = family.unwrap_or(0);
        let name = name.filter(|s| !s.is_empty()).unwrap_or_else(|| {
            format!(
                "Accept {} to {} {}forwarding",
                if src.any {
                    "any".into()
                } else {
                    self.zone_name(Some(src))
                },
                if dest.any {
                    "any".into()
                } else {
                    self.zone_name(Some(dest))
                },
                if fam != 0 {
                    format!("{} ", emit::nfproto(fam, true))
                } else {
                    String::new()
                }
            )
        });
        let mut r = Rule {
            name,
            family: fam,
            proto: Proto {
                invert: false,
                any: true,
                name: None,
            },
            src: Some(src),
            dest: Some(dest),
            chain: if src.any {
                "forward".into()
            } else {
                format!("forward_{}", self.zone_name(Some(src)))
            },
            ..Default::default()
        };
        if dest.any {
            r.target = Some("accept".into());
        } else {
            r.jump_chain = Some(format!("accept_to_{}", self.zone_name(Some(dest))));
        }
        self.state.rules.push(r);
        if let Some(z) = self.zone_mut(Some(dest)) {
            z.dflags.set("accept");
        }
    }

    // ------------------------------------------------------------ rule

    pub fn parse_rule(&mut self, data: &Json) {
        let default_name = self
            .section_id(data.get(".name").and_then(Json::as_str))
            .map(Json::Str);
        let parsed = {
            let mut o = Opts::new(self, data);
            let r = (|| {
                let enabled = o
                    .opt("enabled", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let name = o.opt("name", default_name, 0, |f, v| f.parse_string(v))?;
                o.opt("_name", None, DEPRECATED, |f, v| f.parse_string(v))?;
                let family = o.opt("family", None, 0, |f, v| f.parse_family(v))?;
                let src = o.opt("src", None, 0, |f, v| f.parse_zone_ref(v))?;
                let dest = o.opt("dest", None, 0, |f, v| f.parse_zone_ref(v))?;
                let device = o.opt("device", None, NO_INVERT, |f, v| f.parse_device(v))?;
                let direction = o.opt("direction", None, 0, |f, v| f.parse_direction(v))?;
                let ipset = o.opt("ipset", None, 0, |f, v| f.parse_setmatch(v))?;
                let helper = o.opt("helper", None, 0, |f, v| f.parse_cthelper(v))?;
                let set_helper =
                    o.opt("set_helper", None, NO_INVERT, |f, v| f.parse_cthelper(v))?;
                let proto = o.list("proto", s("tcpudp"), PARSE_LIST | FLATTEN_LIST, |f, v| {
                    f.parse_protocol(v)
                })?;
                let src_ip = o.list("src_ip", None, PARSE_LIST, |f, v| {
                    f.parse_network(v).map(|d| vec![d])
                })?;
                let src_mac = o.list("src_mac", None, PARSE_LIST, |f, v| {
                    f.parse_mac(v).map(|d| vec![d])
                })?;
                let src_port = o.list("src_port", None, PARSE_LIST, |f, v| {
                    f.parse_port(v).map(|d| vec![d])
                })?;
                let dest_ip = o.list("dest_ip", None, PARSE_LIST, |f, v| {
                    f.parse_network(v).map(|d| vec![d])
                })?;
                let dest_port = o.list("dest_port", None, PARSE_LIST, |f, v| {
                    f.parse_port(v).map(|d| vec![d])
                })?;
                let icmp_type = o.list("icmp_type", None, PARSE_LIST, |f, v| {
                    f.parse_icmptype(v).map(|d| vec![d])
                })?;
                o.opt("extra", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                let limit = o.opt("limit", None, 0, |f, v| f.parse_limit(v))?;
                let limit_burst = o.opt("limit_burst", None, 0, |f, v| f.parse_int(v))?;
                o.opt("utc_time", None, 0, |f, v| f.parse_bool(v))?;
                let start_date = o.opt("start_date", None, 0, |f, v| f.parse_date(v))?;
                let stop_date = o.opt("stop_date", None, 0, |f, v| f.parse_date(v))?;
                let start_time = o.opt("start_time", None, 0, |f, v| f.parse_time(v))?;
                let stop_time = o.opt("stop_time", None, 0, |f, v| f.parse_time(v))?;
                let weekdays = o.opt("weekdays", None, 0, |f, v| f.parse_weekdays(v))?;
                o.opt("monthdays", None, UNSUPPORTED, |f, v| f.parse_monthdays(v))?;
                let mark = o.opt("mark", None, 0, |f, v| f.parse_mark(v))?;
                let set_mark = o.opt("set_mark", None, NO_INVERT, |f, v| f.parse_mark(v))?;
                let set_xmark = o.opt("set_xmark", None, NO_INVERT, |f, v| f.parse_mark(v))?;
                let dscp = o.opt("dscp", None, 0, |f, v| f.parse_dscp(v))?;
                let set_dscp = o.opt("set_dscp", None, NO_INVERT, |f, v| f.parse_dscp(v))?;
                let counter = o
                    .opt("counter", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let log = o.opt("log", None, 0, |f, v| f.parse_string(v))?;
                let log_limit = o.opt("log_limit", None, 0, |f, v| f.parse_limit(v))?;
                let target = o.opt("target", None, 0, |f, v| f.parse_target(v))?;
                Ok::<_, ()>(RuleOpts {
                    enabled,
                    name,
                    family,
                    src,
                    dest,
                    device,
                    direction,
                    ipset,
                    helper,
                    set_helper,
                    proto: proto.unwrap_or_default(),
                    src_ip,
                    src_mac,
                    src_port,
                    dest_ip,
                    dest_port,
                    icmp_type,
                    limit,
                    limit_burst,
                    start_date,
                    stop_date,
                    start_time,
                    stop_time,
                    weekdays,
                    mark,
                    set_mark,
                    set_xmark,
                    dscp,
                    set_dscp,
                    counter,
                    log,
                    log_limit,
                    target,
                })
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        let Ok(mut rule) = parsed else {
            self.warn_section(data, "skipped due to invalid options");
            return;
        };
        if !rule.enabled {
            self.warn_section(data, "is disabled, ignoring section");
            return;
        }
        let target = rule.target.clone().unwrap_or_default();
        let src_has_zone = rule.src.map(|r| r.zone.is_some()).unwrap_or(false);
        if (target == "helper" || target == "notrack") && !src_has_zone {
            self.warn_section(
                data,
                &format!("must specify a source zone for target '{target}'"),
            );
            return;
        } else if target == "dscp" && rule.set_dscp.is_none() {
            self.warn_section(data, "must specify option 'set_dscp' for target 'dscp'");
            return;
        } else if target == "mark" && rule.set_mark.is_none() && rule.set_xmark.is_none() {
            self.warn_section(
                data,
                "must specify option 'set_mark' or 'set_xmark' for target 'mark'",
            );
            return;
        } else if target == "helper" && rule.set_helper.is_none() {
            self.warn_section(data, "must specify option 'set_helper' for target 'helper'");
            return;
        } else if rule.device.as_ref().map(|d| d.any).unwrap_or(false) {
            self.warn_section(data, "must not specify '*' as device");
            return;
        }
        let rule_name = rule.name.clone().unwrap_or_else(|| "null".into());
        rule.log = match rule
            .log
            .as_deref()
            .map(|l| self.parse_bool(&Json::Str(l.to_owned())))
        {
            Some(Some(true)) => Some(format!("{rule_name}: ")),
            Some(Some(false)) => None,
            _ => rule.log,
        };
        let mut ipset: Option<Ipset> = None;
        if let Some(sm) = &rule.ipset {
            match self.state.ipsets.iter().find(|s| s.name == sm.name) {
                Some(set) => ipset = Some(set.clone()),
                None => {
                    self.warn_section(data, &format!("references unknown set '{}'", sm.name));
                    return;
                }
            }
            if ipset
                .as_ref()
                .unwrap()
                .types
                .iter()
                .any(|t| t == "inet_service")
                && !ensure_tcpudp(&mut rule.proto)
            {
                self.warn_section(
                    data,
                    "references named set with port match but no UDP/TCP protocol, ignoring section",
                );
                return;
            }
        }

        let protos = rule.proto.clone();
        for proto in &protos {
            let (mut sports, mut dports) = (None, None);
            let (mut itypes4, mut itypes6): (Option<Vec<IcmpType>>, Option<Vec<IcmpType>>) =
                (None, None);
            let mut family = rule.family;
            match proto.name() {
                "icmp" => {
                    let all = rule.icmp_type.clone().unwrap_or_default();
                    itypes4 = Some(
                        all.iter()
                            .filter(|i| i.family == 0 || i.family == 4)
                            .cloned()
                            .collect(),
                    );
                    itypes6 = Some(
                        all.iter()
                            .filter(|i| i.family == 0 || i.family == 6)
                            .cloned()
                            .collect(),
                    );
                }
                "ipv6-icmp" => {
                    family = Some(6);
                    let all = rule.icmp_type.clone().unwrap_or_default();
                    itypes6 = Some(
                        all.iter()
                            .filter(|i| i.family == 0 || i.family == 6)
                            .cloned()
                            .collect(),
                    );
                }
                "tcp" | "udp" => {
                    sports = rule.src_port.clone();
                    dports = rule.dest_port.clone();
                }
                _ => {}
            }
            let sip = subnets_split_af(rule.src_ip.as_deref().unwrap_or(&[]));
            let dip = subnets_split_af(rule.dest_ip.as_deref().unwrap_or(&[]));
            let family = match infer_family(
                family,
                &[
                    (fam_of(ipset.as_ref(), |s| s.family), "set match"),
                    (sip.family.map(|f| vec![f]).unwrap_or_default(), "source IP"),
                    (
                        dip.family.map(|f| vec![f]).unwrap_or_default(),
                        "destination IP",
                    ),
                    (zone_family(&self.state, rule.src), "source zone"),
                    (zone_family(&self.state, rule.dest), "destination zone"),
                    (helper_family(rule.helper.as_ref()), "helper match"),
                    (helper_family(rule.set_helper.as_ref()), "helper to set"),
                ],
            ) {
                Ok(f) => f,
                Err(msg) => {
                    self.warn_section(data, &format!("{msg}, skipping"));
                    continue;
                }
            };
            let n4 = itypes4.as_ref().map(|v| v.len()).unwrap_or(0);
            let n6 = itypes6.as_ref().map(|v| v.len()).unwrap_or(0);
            let has4 = sip.len(0) > 0 || dip.len(0) > 0 || n4 > 0 || rule.dscp.is_some();
            let has6 = sip.len(1) > 0 || dip.len(1) > 0 || n6 > 0 || rule.dscp.is_some();
            let family = match family {
                None => {
                    if has4 && !has6 {
                        4
                    } else if has6 && !has4 {
                        6
                    } else {
                        0
                    }
                }
                Some(f) => f,
            };
            #[allow(clippy::type_complexity)]
            let mut emitted: Vec<(
                i64,
                SubnetGroup,
                SubnetGroup,
                Option<Vec<IcmpType>>,
                Option<Vec<IcmpType>>,
            )> = Vec::new();
            if family == 0 && target != "dscp" && !has4 && !has6 {
                emitted.push((0, empty_group(), empty_group(), None, None));
            } else {
                for (fam, itypes, sipv, dipv) in [
                    (4, &itypes4, sip.v4.as_ref(), dip.v4.as_ref()),
                    (6, &itypes6, sip.v6.as_ref(), dip.v6.as_ref()),
                ] {
                    if family != 0 && family != fam {
                        continue;
                    }
                    let all = itypes.clone().unwrap_or_default();
                    let icmp_types: Vec<IcmpType> = all
                        .iter()
                        .filter(|i| i.code_min == Some(0) && i.code_max == Some(0xFF))
                        .cloned()
                        .collect();
                    let icmp_codes: Vec<IcmpType> = all
                        .iter()
                        .filter(|i| i.code_min != Some(0) || i.code_max != Some(0xFF))
                        .cloned()
                        .collect();
                    for saddrs in subnets_group_by_masking(sipv) {
                        for daddrs in subnets_group_by_masking(dipv) {
                            if !icmp_types.is_empty() || icmp_codes.is_empty() {
                                emitted.push((
                                    fam,
                                    saddrs.clone(),
                                    daddrs.clone(),
                                    Some(icmp_types.clone()),
                                    None,
                                ));
                            }
                            if !icmp_codes.is_empty() {
                                emitted.push((
                                    fam,
                                    saddrs.clone(),
                                    daddrs.clone(),
                                    None,
                                    Some(icmp_codes.clone()),
                                ));
                            }
                        }
                    }
                }
            }
            for (fam, saddrs, daddrs, icmptypes, icmpcodes) in emitted {
                self.add_rule(
                    data,
                    &rule_name,
                    &rule,
                    fam,
                    proto,
                    &saddrs,
                    &daddrs,
                    sports.as_ref(),
                    dports.as_ref(),
                    icmptypes,
                    icmpcodes,
                    ipset.as_ref(),
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_rule(
        &mut self,
        data: &Json,
        rule_name: &str,
        rule: &RuleOpts,
        family: i64,
        proto: &Proto,
        saddrs: &SubnetGroup,
        daddrs: &SubnetGroup,
        sports: Option<&Vec<Port>>,
        dports: Option<&Vec<Port>>,
        icmptypes: Option<Vec<IcmpType>>,
        icmpcodes: Option<Vec<IcmpType>>,
        ipset: Option<&Ipset>,
    ) {
        let src = rule.src;
        let dest = rule.dest;
        let mut r = Rule {
            name: rule_name.to_owned(),
            family,
            proto: proto.clone(),
            src,
            dest,
            has_addrs: saddrs.0.is_some()
                || saddrs.1.is_some()
                || saddrs.2.is_some()
                || daddrs.0.is_some()
                || daddrs.1.is_some()
                || daddrs.2.is_some(),
            has_ports: sports.map(|s| !s.is_empty()).unwrap_or(false)
                || dports.map(|s| !s.is_empty()).unwrap_or(false),
            saddrs_pos: cidrs(saddrs.0.as_ref()),
            saddrs_neg: cidrs(saddrs.1.as_ref()),
            saddrs_masked: saddrs.2.clone(),
            daddrs_pos: cidrs(daddrs.0.as_ref()),
            daddrs_neg: cidrs(daddrs.1.as_ref()),
            daddrs_masked: daddrs.2.clone(),
            sports_pos: filter_pos(sports),
            sports_neg: filter_neg(sports),
            dports_pos: filter_pos(dports),
            dports_neg: filter_neg(dports),
            smacs_pos: macs(rule.src_mac.as_ref(), false),
            smacs_neg: macs(rule.src_mac.as_ref(), true),
            icmp_types: icmptypes
                .map(|v| {
                    v.iter()
                        .map(|i| if family == 4 { i.ty } else { i.ty6 }.unwrap_or(0))
                        .collect::<Vec<i64>>()
                })
                .filter(|v| !v.is_empty()),
            icmp_codes: icmpcodes
                .map(|v| {
                    v.iter()
                        .map(|ic| {
                            let (t, c) = if family == 4 {
                                (ic.ty, ic.code_min)
                            } else {
                                (ic.ty6, ic.code6_min)
                            };
                            format!(
                                "{} . {}",
                                t.map(|x| x.to_string()).unwrap_or_else(|| "null".into()),
                                c.map(|x| x.to_string()).unwrap_or_else(|| "null".into())
                            )
                        })
                        .collect::<Vec<String>>()
                })
                .filter(|v| !v.is_empty()),
            helper: rule.helper.clone(),
            set_helper: rule.set_helper.clone(),
            limit: rule.limit.clone(),
            limit_burst: rule.limit_burst,
            start_date: rule.start_date.clone(),
            stop_date: rule.stop_date.clone(),
            start_time: rule.start_time.clone(),
            stop_time: rule.stop_time.clone(),
            weekdays: rule.weekdays.clone(),
            mark: rule.mark.clone(),
            set_xmark: rule.set_xmark.clone(),
            dscp: rule.dscp.clone(),
            set_dscp: rule.set_dscp.clone(),
            ipset: rule.ipset.clone(),
            log: rule.log.clone(),
            log_limit: rule.log_limit.clone(),
            counter: rule.counter,
            target: rule.target.clone(),
            ..Default::default()
        };
        if let Some(sm) = rule.set_mark.as_ref() {
            r.set_xmark = Some(Mark {
                invert: sm.invert,
                mark: sm.mark,
                mask: sm.mark | sm.mask,
            });
        }
        if let Some(sm) = &r.ipset {
            match map_setmatch(ipset, sm, proto.name()) {
                Err(()) => {
                    self.warn_section(data, "destination MAC address matching not supported");
                    return;
                }
                Ok(Some(fields)) => r.ipset.as_mut().unwrap().fields = Some(fields),
                Ok(None) => {}
            }
        }
        let target = r.target.clone().unwrap_or_default();
        let src_zone = src.and_then(|z| z.zone);
        let dest_zone = dest.and_then(|z| z.zone);
        let src_any = src.map(|z| z.any).unwrap_or(false);
        let dest_any = dest.map(|z| z.any).unwrap_or(false);
        match target.as_str() {
            "notrack" => {
                r.chain = format!("notrack_{}", self.zone_name(src));
                if let Some(z) = self.zone_mut(src) {
                    z.dflags.set("notrack");
                }
            }
            "helper" => {
                r.chain = format!("helper_{}", self.zone_name(src));
                if let Some(z) = self.zone_mut(src) {
                    z.dflags.set("helper");
                }
            }
            "mark" | "dscp" => {
                r.chain = if (src_any && dest_any) || (src_zone.is_some() && dest_zone.is_some()) {
                    "mangle_forward"
                } else if src_any && dest_zone.is_some() {
                    "mangle_postrouting"
                } else if src_zone.is_some() && dest_any {
                    "mangle_prerouting"
                } else if src.is_some() && dest.is_none() {
                    "mangle_input"
                } else {
                    "mangle_output"
                }
                .into();
                if let Some(i) = src_zone {
                    self.state.zones[i].dflags.set(&target);
                    r.iifnames = nie(&self.state.zones[i].match_devices);
                }
                if let Some(i) = dest_zone {
                    self.state.zones[i].dflags.set(&target);
                    r.oifnames = nie(&self.state.zones[i].match_devices);
                }
            }
            _ => {
                r.chain = "output".into();
                if let Some(sz) = src {
                    r.chain = if !sz.any {
                        format!(
                            "{}_{}",
                            if dest.is_some() { "forward" } else { "input" },
                            self.zone_name(src)
                        )
                    } else if dest.is_some() {
                        "forward".into()
                    } else {
                        "input".into()
                    };
                }
                if let Some(dz) = dest {
                    if src.is_none() {
                        r.chain = if !dz.any {
                            format!("output_{}", self.zone_name(dest))
                        } else {
                            "output".into()
                        };
                    }
                }
                let need_src_action_chain = src_zone
                    .map(|i| {
                        self.state.zones[i].log.is_some_and(|n| n.as_f64() != 0.0)
                            && target != "accept"
                    })
                    .unwrap_or(false);
                if !target.is_empty() && dest.is_some() && !dest_any {
                    r.jump_chain = Some(format!("{target}_to_{}", self.zone_name(dest)));
                    if let Some(z) = self.zone_mut(dest) {
                        z.dflags.set(&target);
                    }
                } else if !target.is_empty() && need_src_action_chain {
                    r.jump_chain = Some(format!("{target}_from_{}", self.zone_name(src)));
                    if let Some(z) = self.zone_mut(src) {
                        z.sflags.set(&target);
                    }
                } else if target == "reject" {
                    r.jump_chain = Some("handle_reject".into());
                }
            }
        }
        if let Some(dev) = rule.device.as_ref() {
            let names = Some(vec![dev.device.clone().unwrap_or_else(|| "null".into())]);
            if rule.direction == Some(true) {
                r.oifnames = names;
            } else {
                r.iifnames = names;
            }
        }
        self.state.rules.push(r);
    }
}

/// Fields shared by redirect/nat rule emission (`{ ...redir }` spread).
#[derive(Clone, Default)]
pub struct RedirBase {
    pub name: String,
    pub src: Option<ZoneRef>,
    pub dest: Option<ZoneRef>,
    pub device: Option<String>,
    pub helper: Option<CtHelper>,
    pub src_mac: Option<Vec<Mac>>,
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

fn ports_of(p: Option<&Port>, invert: bool) -> Option<Vec<String>> {
    match p {
        Some(p) if p.invert == invert => Some(vec![emit::port(p)]),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_redirect(
    base: &RedirBase,
    family: i64,
    proto: &Proto,
    saddrs: &SubnetGroup,
    daddrs: &SubnetGroup,
    raddrs: Option<&Vec<Addr>>,
    sport: Option<&Port>,
    dport: Option<&Port>,
    rport: Option<&Port>,
    has_ports: bool,
) -> Redirect {
    Redirect {
        name: base.name.clone(),
        chain: String::new(),
        family,
        proto: proto.clone(),
        src: base.src,
        dest: base.dest,
        device: base.device.clone(),
        has_addrs: saddrs.0.is_some()
            || saddrs.1.is_some()
            || saddrs.2.is_some()
            || daddrs.0.is_some()
            || daddrs.1.is_some()
            || daddrs.2.is_some(),
        has_ports,
        saddrs_pos: cidrs(saddrs.0.as_ref()),
        saddrs_neg: cidrs(saddrs.1.as_ref()),
        saddrs_masked: saddrs.2.clone(),
        daddrs_pos: cidrs(daddrs.0.as_ref()),
        daddrs_neg: cidrs(daddrs.1.as_ref()),
        daddrs_masked: daddrs.2.clone(),
        sports_pos: ports_of(sport, false),
        sports_neg: ports_of(sport, true),
        dports_pos: ports_of(dport, false),
        dports_neg: ports_of(dport, true),
        smacs_pos: macs(base.src_mac.as_ref(), false),
        smacs_neg: macs(base.src_mac.as_ref(), true),
        raddr: raddrs.and_then(|r| r.first().cloned()),
        rport: rport.cloned(),
        helper: base.helper.clone(),
        limit: base.limit.clone(),
        limit_burst: base.limit_burst,
        start_date: base.start_date.clone(),
        stop_date: base.stop_date.clone(),
        start_time: base.start_time.clone(),
        stop_time: base.stop_time.clone(),
        weekdays: base.weekdays.clone(),
        mark: base.mark.clone(),
        ipset: base.ipset.clone(),
        log: base.log.clone(),
        log_limit: base.log_limit.clone(),
        counter: base.counter,
        target: base.target.clone(),
    }
}

impl Fw4 {
    fn log_prefix(&self, log: Option<String>, name: &str) -> Option<String> {
        match log
            .as_deref()
            .map(|l| self.parse_bool(&Json::Str(l.to_owned())))
        {
            Some(Some(true)) => Some(format!("{name}: ")),
            Some(Some(false)) => None,
            _ => log,
        }
    }

    /// Lookup + tcp/udp check for `ipset` options of rules/redirects.
    fn resolve_setmatch(
        &self,
        data: &Json,
        sm: Option<&SetMatch>,
        proto: &mut Vec<Proto>,
    ) -> Result<Option<Ipset>, ()> {
        let Some(sm) = sm else { return Ok(None) };
        let Some(set) = self
            .state
            .ipsets
            .iter()
            .find(|s| s.name == sm.name)
            .cloned()
        else {
            self.warn_section(data, &format!("references unknown set '{}'", sm.name));
            return Err(());
        };
        if set.types.iter().any(|t| t == "inet_service") && !ensure_tcpudp(proto) {
            self.warn_section(
                data,
                "references named set with port match but no UDP/TCP protocol, ignoring section",
            );
            return Err(());
        }
        Ok(Some(set))
    }

    #[allow(clippy::too_many_arguments)]
    fn add_redirect(
        &mut self,
        data: &Json,
        base: &RedirBase,
        family: i64,
        proto: &Proto,
        saddrs: &SubnetGroup,
        daddrs: &SubnetGroup,
        raddrs: Option<&Vec<Addr>>,
        sport: Option<&Port>,
        dport: Option<&Port>,
        rport: Option<&Port>,
        ipset: Option<&Ipset>,
    ) {
        let has_ports = sport.is_some() || dport.is_some() || rport.is_some();
        let mut r = build_redirect(
            base, family, proto, saddrs, daddrs, raddrs, sport, dport, rport, has_ports,
        );
        if let Some(sm) = &r.ipset {
            match map_setmatch(ipset, sm, proto.name()) {
                Err(()) => {
                    self.warn_section(data, "destination MAC address matching not supported");
                    return;
                }
                Ok(Some(fields)) => r.ipset.as_mut().unwrap().fields = Some(fields),
                Ok(None) => {}
            }
        }
        match r.target.as_str() {
            "dnat" => {
                r.chain = format!("dstnat_{}", self.zone_name(r.src));
                if let Some(z) = self.zone_mut(r.src) {
                    z.dflags.set("dnat");
                }
                if r.raddr.is_none() {
                    r.target = "redirect".into();
                }
            }
            "snat" => {
                r.chain = format!("srcnat_{}", self.zone_name(r.dest));
                if let Some(z) = self.zone_mut(r.dest) {
                    z.dflags.set("snat");
                }
            }
            _ => {}
        }
        self.state.redirects.push(r);
    }

    // ------------------------------------------------------------ redirect

    pub fn parse_redirect(&mut self, data: &Json) {
        struct Rd {
            enabled: bool,
            name: Option<String>,
            family: Option<i64>,
            src: Option<ZoneRef>,
            dest: Option<ZoneRef>,
            ipset: Option<SetMatch>,
            helper: Option<CtHelper>,
            proto: Vec<Proto>,
            src_ip: Option<Network>,
            src_mac: Option<Vec<Mac>>,
            src_port: Option<Port>,
            src_dip: Option<Network>,
            src_dport: Option<Port>,
            dest_ip: Option<Network>,
            dest_port: Option<Port>,
            limit: Option<Limit>,
            limit_burst: Option<Num>,
            start_date: Option<DateTime>,
            stop_date: Option<DateTime>,
            start_time: Option<Time>,
            stop_time: Option<Time>,
            weekdays: Option<Weekdays>,
            mark: Option<Mark>,
            reflection: bool,
            reflection_src: Option<String>,
            reflection_zone: Option<Vec<ZoneRef>>,
            counter: bool,
            log: Option<String>,
            log_limit: Option<Limit>,
            target: String,
        }
        let default_name = self
            .section_id(data.get(".name").and_then(Json::as_str))
            .map(Json::Str);
        let parsed = {
            let mut o = Opts::new(self, data);
            let r = (|| {
                let enabled = o
                    .opt("enabled", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let name = o.opt("name", default_name, 0, |f, v| f.parse_string(v))?;
                o.opt("_name", None, DEPRECATED, |f, v| f.parse_string(v))?;
                let family = o.opt("family", None, 0, |f, v| f.parse_family(v))?;
                let src = o.opt("src", None, 0, |f, v| f.parse_zone_ref(v))?;
                let dest = o.opt("dest", None, 0, |f, v| f.parse_zone_ref(v))?;
                let ipset = o.opt("ipset", None, 0, |f, v| f.parse_setmatch(v))?;
                let helper = o.opt("helper", None, NO_INVERT, |f, v| f.parse_cthelper(v))?;
                let proto = o.list("proto", s("tcpudp"), PARSE_LIST | FLATTEN_LIST, |f, v| {
                    f.parse_protocol(v)
                })?;
                let src_ip = o.opt("src_ip", None, 0, |f, v| f.parse_network(v))?;
                let src_mac = o.list("src_mac", None, PARSE_LIST, |f, v| {
                    f.parse_mac(v).map(|d| vec![d])
                })?;
                let src_port = o.opt("src_port", None, 0, |f, v| f.parse_port(v))?;
                let src_dip = o.opt("src_dip", None, 0, |f, v| f.parse_network(v))?;
                let src_dport = o.opt("src_dport", None, 0, |f, v| f.parse_port(v))?;
                let dest_ip = o.opt("dest_ip", None, 0, |f, v| f.parse_network(v))?;
                let dest_port = o.opt("dest_port", None, 0, |f, v| f.parse_port(v))?;
                o.opt("extra", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                let limit = o.opt("limit", None, 0, |f, v| f.parse_limit(v))?;
                let limit_burst = o.opt("limit_burst", None, 0, |f, v| f.parse_int(v))?;
                o.opt("utc_time", None, 0, |f, v| f.parse_bool(v))?;
                let start_date = o.opt("start_date", None, 0, |f, v| f.parse_date(v))?;
                let stop_date = o.opt("stop_date", None, 0, |f, v| f.parse_date(v))?;
                let start_time = o.opt("start_time", None, 0, |f, v| f.parse_time(v))?;
                let stop_time = o.opt("stop_time", None, 0, |f, v| f.parse_time(v))?;
                let weekdays = o.opt("weekdays", None, 0, |f, v| f.parse_weekdays(v))?;
                o.opt("monthdays", None, UNSUPPORTED, |f, v| f.parse_monthdays(v))?;
                let mark = o.opt("mark", None, 0, |f, v| f.parse_mark(v))?;
                let reflection = o
                    .opt("reflection", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let reflection_src = o.opt("reflection_src", s("internal"), 0, |f, v| {
                    f.parse_reflection_source(v)
                })?;
                let reflection_zone = o.list("reflection_zone", None, PARSE_LIST, |f, v| {
                    f.parse_zone_ref(v).map(|d| vec![d])
                })?;
                let counter = o
                    .opt("counter", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let log = o.opt("log", None, 0, |f, v| f.parse_string(v))?;
                let log_limit = o.opt("log_limit", None, 0, |f, v| f.parse_limit(v))?;
                let target = o
                    .opt("target", s("dnat"), 0, |f, v| f.parse_target(v))?
                    .unwrap_or_default();
                Ok::<_, ()>(Rd {
                    enabled,
                    name,
                    family,
                    src,
                    dest,
                    ipset,
                    helper,
                    proto: proto.unwrap_or_default(),
                    src_ip,
                    src_mac,
                    src_port,
                    src_dip,
                    src_dport,
                    dest_ip,
                    dest_port,
                    limit,
                    limit_burst,
                    start_date,
                    stop_date,
                    start_time,
                    stop_time,
                    weekdays,
                    mark,
                    reflection,
                    reflection_src,
                    reflection_zone,
                    counter,
                    log,
                    log_limit,
                    target,
                })
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        let Ok(mut rd) = parsed else {
            self.warn_section(data, "skipped due to invalid options");
            return;
        };
        if !rd.enabled {
            self.warn_section(data, "is disabled, ignoring section");
            return;
        }
        if rd.target != "dnat" && rd.target != "snat" {
            self.warn_section(data, "has invalid target specified, defaulting to dnat");
            rd.target = "dnat".into();
        }
        let name = rd.name.clone().unwrap_or_else(|| "null".into());
        rd.log = self.log_prefix(rd.log.take(), &name);
        let Ok(ipset) = self.resolve_setmatch(data, rd.ipset.as_ref(), &mut rd.proto) else {
            return;
        };

        let masked = |n: Option<&Network>| {
            n.and_then(|n| n.addrs.as_ref())
                .map(|a| a.iter().any(|x| x.is_masked()))
                .unwrap_or(false)
        };
        if rd.target == "dnat" {
            let Some(src) = rd.src else {
                return self.warn_section(data, "has no source specified");
            };
            if src.any {
                return self.warn_section(data, "must not have source '*' for dnat target");
            } else if rd.dest_ip.as_ref().map(|d| d.invert).unwrap_or(false) {
                return self.warn_section(data, "must not specify a negated 'dest_ip' value");
            } else if masked(rd.dest_ip.as_ref()) {
                return self.warn_section(data, "must not use non-contiguous masks in 'dest_ip'");
            }
            if rd.dest.is_none() {
                if let Some(dest_ip) = &rd.dest_ip {
                    // resolve_dest
                    'outer: for (zi, zone) in self.state.zones.iter().enumerate() {
                        for zone_addr in &zone.related_subnets {
                            for dest_addr in dest_ip.addrs.iter().flatten() {
                                if dest_addr.family != zone_addr.family {
                                    continue;
                                }
                                let a = zone_addr.mask.as_deref().and_then(|m| {
                                    crate::ip::apply_mask(&dest_addr.addr, crate::ip::Mask::Addr(m))
                                });
                                let b = zone_addr.mask.as_deref().and_then(|m| {
                                    crate::ip::apply_mask(&zone_addr.addr, crate::ip::Mask::Addr(m))
                                });
                                if a != b {
                                    continue;
                                }
                                rd.dest = Some(ZoneRef {
                                    any: false,
                                    zone: Some(zi),
                                });
                                break 'outer;
                            }
                        }
                    }
                    if rd.dest.is_some() {
                        self.warn_section(
                            data,
                            &format!(
                                "does not specify a destination, assuming '{}'",
                                self.zone_name(rd.dest)
                            ),
                        );
                    }
                }
            }
            if rd.dest_port.is_none() {
                rd.dest_port = rd.src_dport.clone();
            }
            let src_masq = src.zone.map(|i| self.state.zones[i].masq).unwrap_or(false);
            if rd.reflection && rd.dest.and_then(|d| d.zone).is_some() && src_masq {
                if let Some(z) = self.zone_mut(rd.dest) {
                    z.dflags.set("accept");
                    z.dflags.set("dnat");
                    z.dflags.set("snat");
                }
            }
            if rd.helper.is_some() {
                if let Some(z) = self.zone_mut(Some(src)) {
                    z.dflags.set("helper");
                }
            }
            if let Some(z) = self.zone_mut(Some(src)) {
                z.dflags.set("dnat");
            }
        } else {
            let Some(dest) = rd.dest else {
                return self.warn_section(data, "has no destination specified");
            };
            if dest.any {
                return self.warn_section(data, "must not have destination '*' for snat target");
            } else if rd.src_dip.is_none() {
                return self.warn_section(data, "has no 'src_dip' option specified");
            } else if rd.src_dip.as_ref().map(|d| d.invert).unwrap_or(false) {
                return self.warn_section(data, "must not specify a negated 'src_dip' value");
            } else if masked(rd.src_dip.as_ref()) {
                return self.warn_section(data, "must not use non-contiguous masks in 'src_dip'");
            } else if rd.src_mac.is_some() {
                return self.warn_section(data, "must not use 'src_mac' option for snat target");
            } else if rd.helper.is_some() {
                return self.warn_section(data, "must not use 'helper' option for snat target");
            }
            if let Some(z) = self.zone_mut(Some(dest)) {
                z.dflags.set("snat");
            }
        }

        let base = RedirBase {
            name: name.clone(),
            src: rd.src,
            dest: rd.dest,
            device: None,
            helper: rd.helper.clone(),
            src_mac: rd.src_mac.clone(),
            limit: rd.limit.clone(),
            limit_burst: rd.limit_burst,
            start_date: rd.start_date.clone(),
            stop_date: rd.stop_date.clone(),
            start_time: rd.start_time.clone(),
            stop_time: rd.stop_time.clone(),
            weekdays: rd.weekdays.clone(),
            mark: rd.mark.clone(),
            ipset: rd.ipset.clone(),
            log: rd.log.clone(),
            log_limit: rd.log_limit.clone(),
            counter: rd.counter,
            target: rd.target.clone(),
        };
        let one = |n: Option<&Network>| -> Vec<Network> { n.cloned().into_iter().collect() };
        let protos = rd.proto.clone();
        for proto in &protos {
            let mut family = rd.family;
            if proto.name() == "ipv6-icmp" {
                family = Some(6);
            }
            let (sip, dip, rip);
            let (mut sport, mut dport, mut rport) = (None, None, None);
            if rd.target == "dnat" {
                sip = subnets_split_af(&one(rd.src_ip.as_ref()));
                dip = subnets_split_af(&one(rd.src_dip.as_ref()));
                rip = subnets_split_af(&one(rd.dest_ip.as_ref()));
                if matches!(proto.name(), "tcp" | "udp") {
                    sport = rd.src_port.as_ref();
                    dport = rd.src_dport.as_ref();
                    rport = rd.dest_port.as_ref();
                }
            } else {
                sip = subnets_split_af(&one(rd.src_ip.as_ref()));
                dip = subnets_split_af(&one(rd.dest_ip.as_ref()));
                rip = subnets_split_af(&one(rd.src_dip.as_ref()));
                if matches!(proto.name(), "tcp" | "udp") {
                    sport = rd.src_port.as_ref();
                    dport = rd.dest_port.as_ref();
                    rport = rd.src_dport.as_ref();
                }
            }
            let family = match infer_family(
                family,
                &[
                    (fam_of(ipset.as_ref(), |s| s.family), "set match"),
                    (sip.family.map(|f| vec![f]).unwrap_or_default(), "source IP"),
                    (
                        dip.family.map(|f| vec![f]).unwrap_or_default(),
                        "destination IP",
                    ),
                    (
                        rip.family.map(|f| vec![f]).unwrap_or_default(),
                        "rewrite IP",
                    ),
                    (zone_family(&self.state, rd.src), "source zone"),
                    (zone_family(&self.state, rd.dest), "destination zone"),
                    (helper_family(rd.helper.as_ref()), "helper match"),
                ],
            ) {
                Ok(f) => f,
                Err(msg) => {
                    self.warn_section(data, &format!("{msg}, skipping"));
                    continue;
                }
            };

            // reflection rules
            let src_zone = rd.src.and_then(|z| z.zone);
            let dest_zone = rd.dest.and_then(|z| z.zone);
            let reflect = rd.target == "dnat"
                && rd.reflection
                && (rip.len(0) > 0 || rip.len(1) > 0)
                && dest_zone.is_some();
            if let (true, Some(src_zone)) = (reflect, src_zone) {
                let refbase = RedirBase {
                    name: format!("{name} (reflection)"),
                    helper: rd.helper.clone(),
                    limit: rd.limit.clone(),
                    limit_burst: rd.limit_burst,
                    start_date: rd.start_date.clone(),
                    stop_date: rd.stop_date.clone(),
                    start_time: rd.start_time.clone(),
                    stop_time: rd.stop_time.clone(),
                    weekdays: rd.weekdays.clone(),
                    mark: rd.mark.clone(),
                    ..Default::default()
                };
                let eaddrs = if dip.non_empty() {
                    dip.clone()
                } else {
                    let hosts: Vec<Addr> = self.state.zones[src_zone]
                        .related_subnets
                        .iter()
                        .map(to_hostaddr)
                        .collect();
                    split_addrs(&hosts)
                };
                let rzones: Vec<ZoneRef> = match &rd.reflection_zone {
                    Some(z) if !z.is_empty() => z.clone(),
                    _ => vec![rd.dest.unwrap()],
                };
                for rzone in rzones {
                    // `rzone.zone.related_subnets` on the `'*'` pseudo-zone:
                    // ucode dies on the null member access.
                    let Some(rzi) = rzone.zone else {
                        self.aborted = true;
                        continue;
                    };
                    let related = self.state.zones[rzi].related_subnets.clone();
                    let iaddrs = split_addrs(&related);
                    let refaddrs = if rd.reflection_src.as_deref() == Some("internal") {
                        &iaddrs
                    } else {
                        &eaddrs
                    };
                    for i in 0..=1usize {
                        let masq = if i == 1 {
                            self.state.zones[src_zone].masq6
                        } else {
                            self.state.zones[src_zone].masq
                        };
                        if !(masq && rip.len(i) > 0) {
                            continue;
                        }
                        let ripi = rip.get(i).unwrap();
                        let mut snat_addr: Option<Addr> =
                            refaddrs.get(i).and_then(|v| v.first().cloned());
                        if rd.reflection_src.as_deref() == Some("internal") {
                            for zone_addr in &related {
                                if zone_addr.family != ripi[0].family {
                                    continue;
                                }
                                let r = zone_addr.mask.as_deref().and_then(|m| {
                                    crate::ip::apply_mask(&ripi[0].addr, crate::ip::Mask::Addr(m))
                                });
                                let a = zone_addr.mask.as_deref().and_then(|m| {
                                    crate::ip::apply_mask(&zone_addr.addr, crate::ip::Mask::Addr(m))
                                });
                                if r != a {
                                    continue;
                                }
                                snat_addr = Some(zone_addr.clone());
                                break;
                            }
                        }
                        let fam = if i == 1 { 6 } else { 4 };
                        let Some(snat_addr) = snat_addr.as_ref() else {
                            self.warn_section(
                                data,
                                &format!(
                                    "{} rewrite IP cannot be determined, disabling reflection",
                                    rd.reflection_src
                                        .clone()
                                        .unwrap_or_else(|| "external".into())
                                ),
                            );
                            continue;
                        };
                        if iaddrs.len(i) == 0 {
                            self.warn_section(
                                data,
                                "internal address range cannot be determined, disabling reflection",
                            );
                        } else if eaddrs.len(i) == 0 {
                            self.warn_section(
                                data,
                                "external address range cannot be determined, disabling reflection",
                            );
                        } else {
                            let mut rb = refbase.clone();
                            rb.src = Some(rzone);
                            rb.dest = None;
                            rb.target = "dnat".into();
                            for saddrs in subnets_group_by_masking(iaddrs.get(i)) {
                                for daddrs in subnets_group_by_masking(eaddrs.get(i)) {
                                    self.add_redirect(
                                        data,
                                        &rb,
                                        fam,
                                        proto,
                                        &saddrs,
                                        &daddrs,
                                        Some(ripi),
                                        sport,
                                        dport,
                                        rport,
                                        None,
                                    );
                                }
                            }
                            rb.src = None;
                            rb.dest = Some(rzone);
                            rb.target = "snat".into();
                            let snat = vec![to_hostaddr(snat_addr)];
                            for daddrs in subnets_group_by_masking(Some(ripi)) {
                                for saddrs in subnets_group_by_masking(iaddrs.get(i)) {
                                    self.add_redirect(
                                        data,
                                        &rb,
                                        fam,
                                        proto,
                                        &saddrs,
                                        &daddrs,
                                        Some(&snat),
                                        None,
                                        rport,
                                        None,
                                        None,
                                    );
                                }
                            }
                        }
                    }
                }
            }

            if rip.len(0) > 1 || rip.len(1) > 1 {
                self.warn_section(
                    data,
                    "specifies multiple rewrite addresses, using only first one",
                );
            }
            let has_ip4 = sip.len(0) > 0 || dip.len(0) > 0 || rip.len(0) > 0;
            let has_ip6 = sip.len(1) > 0 || dip.len(1) > 0 || rip.len(1) > 0;
            let has_any = has_ip4 || has_ip6;
            if family.unwrap_or(0) == 0 && !has_any {
                let fam = if family.is_none() { 4 } else { 0 };
                self.add_redirect(
                    data,
                    &base,
                    fam,
                    proto,
                    &empty_group(),
                    &empty_group(),
                    None,
                    sport,
                    dport,
                    rport,
                    ipset.as_ref(),
                );
            } else {
                for (fam, hasf, sipv, dipv, ripv) in [
                    (
                        4,
                        has_ip4,
                        sip.v4.as_ref(),
                        dip.v4.as_ref(),
                        rip.v4.as_ref(),
                    ),
                    (
                        6,
                        has_ip6,
                        sip.v6.as_ref(),
                        dip.v6.as_ref(),
                        rip.v6.as_ref(),
                    ),
                ] {
                    if (family.unwrap_or(0) == 0 || family == Some(fam)) && (!has_any || hasf) {
                        for saddrs in subnets_group_by_masking(sipv) {
                            for daddrs in subnets_group_by_masking(dipv) {
                                self.add_redirect(
                                    data,
                                    &base,
                                    fam,
                                    proto,
                                    &saddrs,
                                    &daddrs,
                                    ripv,
                                    sport,
                                    dport,
                                    rport,
                                    ipset.as_ref(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------ nat

    pub fn parse_nat(&mut self, data: &Json) {
        struct N {
            enabled: bool,
            name: Option<String>,
            family: Option<i64>,
            src: Option<ZoneRef>,
            device: Option<String>,
            proto: Vec<Proto>,
            src_ip: Option<Network>,
            src_port: Option<Port>,
            snat_ip: Option<Network>,
            snat_port: Option<Port>,
            dest_ip: Option<Network>,
            dest_port: Option<Port>,
            limit: Option<Limit>,
            limit_burst: Option<Num>,
            start_date: Option<DateTime>,
            stop_date: Option<DateTime>,
            start_time: Option<Time>,
            stop_time: Option<Time>,
            weekdays: Option<Weekdays>,
            mark: Option<Mark>,
            counter: bool,
            log: Option<String>,
            target: String,
        }
        let default_name = self
            .section_id(data.get(".name").and_then(Json::as_str))
            .map(Json::Str);
        let parsed = {
            let mut o = Opts::new(self, data);
            let r = (|| {
                let enabled = o
                    .opt("enabled", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let name = o.opt("name", default_name, 0, |f, v| f.parse_string(v))?;
                let family = o.opt("family", None, 0, |f, v| f.parse_family(v))?;
                let src = o.opt("src", None, 0, |f, v| f.parse_zone_ref(v))?;
                let device = o.opt("device", None, 0, |f, v| f.parse_string(v))?;
                o.opt("ipset", None, UNSUPPORTED, |f, v| f.parse_setmatch(v))?;
                let proto = o.list("proto", s("all"), PARSE_LIST | FLATTEN_LIST, |f, v| {
                    f.parse_protocol(v)
                })?;
                let src_ip = o.opt("src_ip", None, 0, |f, v| f.parse_network(v))?;
                let src_port = o.opt("src_port", None, 0, |f, v| f.parse_port(v))?;
                let snat_ip = o.opt("snat_ip", None, NO_INVERT, |f, v| f.parse_network(v))?;
                let snat_port = o.opt("snat_port", None, NO_INVERT, |f, v| f.parse_port(v))?;
                let dest_ip = o.opt("dest_ip", None, 0, |f, v| f.parse_network(v))?;
                let dest_port = o.opt("dest_port", None, 0, |f, v| f.parse_port(v))?;
                o.opt("extra", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                let limit = o.opt("limit", None, 0, |f, v| f.parse_limit(v))?;
                let limit_burst = o.opt("limit_burst", None, 0, |f, v| f.parse_int(v))?;
                o.opt("connlimit_ports", None, 0, |f, v| f.parse_bool(v))?;
                o.opt("utc_time", None, 0, |f, v| f.parse_bool(v))?;
                let start_date = o.opt("start_date", None, 0, |f, v| f.parse_date(v))?;
                let stop_date = o.opt("stop_date", None, 0, |f, v| f.parse_date(v))?;
                let start_time = o.opt("start_time", None, 0, |f, v| f.parse_time(v))?;
                let stop_time = o.opt("stop_time", None, 0, |f, v| f.parse_time(v))?;
                let weekdays = o.opt("weekdays", None, 0, |f, v| f.parse_weekdays(v))?;
                o.opt("monthdays", None, UNSUPPORTED, |f, v| f.parse_monthdays(v))?;
                let mark = o.opt("mark", None, 0, |f, v| f.parse_mark(v))?;
                let counter = o
                    .opt("counter", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let log = o.opt("log", None, 0, |f, v| f.parse_string(v))?;
                let target = o
                    .opt("target", s("masquerade"), 0, |f, v| f.parse_target(v))?
                    .unwrap_or_default();
                Ok::<_, ()>(N {
                    enabled,
                    name,
                    family,
                    src,
                    device,
                    proto: proto.unwrap_or_default(),
                    src_ip,
                    src_port,
                    snat_ip,
                    snat_port,
                    dest_ip,
                    dest_port,
                    limit,
                    limit_burst,
                    start_date,
                    stop_date,
                    start_time,
                    stop_time,
                    weekdays,
                    mark,
                    counter,
                    log,
                    target,
                })
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        let Ok(mut n) = parsed else {
            self.warn_section(data, "skipped due to invalid options");
            return;
        };
        if !n.enabled {
            self.warn_section(data, "is disabled, ignoring section");
            return;
        }
        if !matches!(n.target.as_str(), "accept" | "snat" | "masquerade") {
            self.warn_section(
                data,
                "has invalid target specified, defaulting to masquerade",
            );
            n.target = "masquerade".into();
        }
        if n.target == "snat" && n.snat_ip.is_none() && n.snat_port.is_none() {
            return self.warn_section(
                data,
                "needs either 'snat_ip' or 'snat_port' for target snat, ignoring section",
            );
        } else if n.target != "snat" && n.snat_ip.is_some() {
            return self.warn_section(
                data,
                "must not use 'snat_ip' for non-snat target, ignoring section",
            );
        } else if n.target != "snat" && n.snat_port.is_some() {
            return self.warn_section(
                data,
                "must not use 'snat_port' for non-snat target, ignoring section",
            );
        }
        if (n.snat_port.is_some() || n.src_port.is_some() || n.dest_port.is_some())
            && !ensure_tcpudp(&mut n.proto)
        {
            return self.warn_section(
                data,
                "specifies ports but no UDP/TCP protocol, ignoring section",
            );
        }
        if let Some(si) = &n.snat_ip {
            if si.addrs.iter().flatten().any(|a| a.is_masked() || a.invert) {
                return self.warn_section(
                    data,
                    "must not use inversion or non-contiguous masks in 'snat_ip', ignoring section",
                );
            }
        }
        let name = n.name.clone().unwrap_or_else(|| "null".into());
        n.log = self.log_prefix(n.log.take(), &name);
        let base = RedirBase {
            name: name.clone(),
            src: n.src,
            dest: None,
            device: n.device.clone(),
            helper: None,
            src_mac: None,
            limit: n.limit.clone(),
            limit_burst: n.limit_burst,
            start_date: n.start_date.clone(),
            stop_date: n.stop_date.clone(),
            start_time: n.start_time.clone(),
            stop_time: n.stop_time.clone(),
            weekdays: n.weekdays.clone(),
            mark: n.mark.clone(),
            ipset: None,
            log: n.log.clone(),
            log_limit: None,
            counter: n.counter,
            target: n.target.clone(),
        };
        let chain = match n.src.and_then(|z| z.zone) {
            Some(i) => format!("srcnat_{}", self.state.zones[i].name),
            None => "srcnat".into(),
        };
        let one = |x: Option<&Network>| -> Vec<Network> { x.cloned().into_iter().collect() };
        let protos = n.proto.clone();
        for proto in &protos {
            let sip = subnets_split_af(&one(n.src_ip.as_ref()));
            let dip = subnets_split_af(&one(n.dest_ip.as_ref()));
            let rip = subnets_split_af(&one(n.snat_ip.as_ref()));
            let (mut sport, mut dport, mut rport) = (None, None, None);
            if matches!(proto.name(), "tcp" | "udp") {
                sport = n.src_port.as_ref();
                dport = n.dest_port.as_ref();
                rport = n.snat_port.as_ref();
            }
            if rip.len(0) > 1 || rip.len(1) > 1 {
                self.warn_section(
                    data,
                    "specifies multiple rewrite addresses, using only first one",
                );
            }
            let family = match infer_family(
                n.family,
                &[
                    (sip.family.map(|f| vec![f]).unwrap_or_default(), "source IP"),
                    (
                        dip.family.map(|f| vec![f]).unwrap_or_default(),
                        "destination IP",
                    ),
                    (
                        rip.family.map(|f| vec![f]).unwrap_or_default(),
                        "rewrite IP",
                    ),
                    (zone_family(&self.state, n.src), "source zone"),
                ],
            ) {
                Ok(f) => f,
                Err(msg) => {
                    self.warn_section(data, &format!("{msg}, skipping"));
                    continue;
                }
            };
            if let Some(z) = self.zone_mut(n.src) {
                z.dflags.set("snat");
            }
            let family = match family {
                None => {
                    let any4 = sip.len(0) > 0 || dip.len(0) > 0 || rip.len(0) > 0;
                    let any6 = sip.len(1) > 0 || dip.len(1) > 0 || rip.len(1) > 0;
                    if any4 && !any6 {
                        4
                    } else if any6 && !any4 {
                        6
                    } else {
                        4
                    }
                }
                Some(f) => f,
            };
            let push = |this: &mut Fw4,
                        fam: i64,
                        saddrs: &SubnetGroup,
                        daddrs: &SubnetGroup,
                        raddrs: Option<&Vec<Addr>>| {
                let has_ports = sport.is_some() || dport.is_some();
                let mut r = build_redirect(
                    &base, fam, proto, saddrs, daddrs, raddrs, sport, dport, rport, has_ports,
                );
                r.chain = chain.clone();
                this.state.redirects.push(r);
            };
            if family == 0
                && sip.len(0) == 0
                && sip.len(1) == 0
                && dip.len(0) == 0
                && dip.len(1) == 0
                && rip.len(0) == 0
                && rip.len(1) == 0
            {
                push(self, 0, &empty_group(), &empty_group(), None);
            } else {
                if family == 0 || family == 4 {
                    for saddr in subnets_group_by_masking(sip.v4.as_ref()) {
                        for daddr in subnets_group_by_masking(dip.v4.as_ref()) {
                            push(self, 4, &saddr, &daddr, rip.v4.as_ref());
                        }
                    }
                }
                if family == 0 || family == 6 {
                    for saddr in subnets_group_by_masking(sip.v6.as_ref()) {
                        for daddr in subnets_group_by_masking(dip.v6.as_ref()) {
                            push(self, 6, &saddr, &daddr, rip.v6.as_ref());
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------ include

    /// `Err` is ucode aborting, exactly like `parse_defaults`: a failed
    /// `parse_options()` returns `false` and `fw4.uc:3220` dereferences it
    /// (`if (!inc.enabled)`), so the interpreter exits 254 without rendering
    /// anything.  Verified against the upstream ucode fw4, see
    /// `tools/r83_fw4_defaults.sh` / R83.
    pub fn parse_include(&mut self, data: &Json) -> Result<(), ()> {
        let compat_default = Json::Bool(!loose_eq_str(
            data.get("path").unwrap_or(&Json::Null),
            "/etc/firewall.user",
        ));
        let parsed = {
            let mut o = Opts::new(self, data);
            let r = (|| {
                let enabled = o
                    .opt("enabled", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                let path = o
                    .opt("path", None, REQUIRED, |f, v| f.parse_string(v))?
                    .unwrap_or_default();
                let ty = o
                    .opt("type", s("script"), 0, |f, v| f.parse_includetype(v))?
                    .unwrap_or_default();
                let fw4_compatible = o
                    .opt("fw4_compatible", Some(compat_default), 0, |f, v| {
                        f.parse_bool(v)
                    })?
                    .unwrap_or(false);
                o.opt("family", None, UNSUPPORTED, |f, v| f.parse_family(v))?;
                o.opt("reload", None, UNSUPPORTED, |f, v| f.parse_bool(v))?;
                let position = o.opt("position", None, 0, |f, v| f.parse_includeposition(v))?;
                let chain = o.opt("chain", None, 0, |f, v| f.parse_identifier(v))?;
                Ok::<_, ()>((enabled, path, ty, fw4_compatible, position, chain))
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        let (enabled, path, ty, fw4_compatible, position, mut chain) = parsed?;
        if !enabled {
            self.warn_section(data, "is disabled, ignoring section");
            return Ok(());
        }
        if ty == "script" && !fw4_compatible {
            self.warn_section(
                data,
                "is not marked as compatible with fw4, ignoring section",
            );
            self.warn_section(
                data,
                "requires 'option fw4_compatible 1' to be considered compatible",
            );
            return Ok(());
        }
        if ty != "nftables" {
            if chain.is_some() {
                self.warn_section(
                    data,
                    "must not specify 'chain' for non-nftables includes, ignoring section",
                );
                return Ok(());
            }
            if position.is_some() {
                self.warn_section(
                    data,
                    "must not specify 'position' for non-nftables includes, ignoring section",
                );
                return Ok(());
            }
        }
        let position = position.unwrap_or_else(|| "table-append".into());
        match position.as_str() {
            "ruleset-prepend" | "ruleset-append" | "table-prepend" | "table-append" => {
                if chain.is_some() {
                    self.warn_section(
                        data,
                        &format!("specifies 'chain' which has no effect for position {position}"),
                    );
                }
                chain = None;
            }
            "chain-prepend" | "chain-append" if chain.is_none() => {
                self.warn_section(
                    data,
                    &format!("must specify 'chain' for position {position}, ignoring section"),
                );
                return Ok(());
            }
            _ => {}
        }
        let real = self.inputs.readlink_or_self(&path);
        if !self.inputs.access(&real) {
            self.warn_section(
                data,
                &format!("specifies unreachable path '{real}', ignoring section"),
            );
            return Ok(());
        }
        if data.get(".name").map(truthy) != Some(true) {
            self.warn(&format!("Automatically including '{real}'"));
        }
        self.state.includes.push(Include {
            enabled,
            path: real,
            ty,
            fw4_compatible,
            position,
            chain,
        });
        Ok(())
    }

    // ------------------------------------------------------------ ipset

    pub fn parse_ipset(&mut self, data: &Json) {
        let parsed = {
            let mut o = Opts::new(self, data);
            let r = (|| {
                let enabled = o
                    .opt("enabled", s("1"), 0, |f, v| f.parse_bool(v))?
                    .unwrap_or(false);
                o.opt("reload_set", None, 0, |f, v| f.parse_bool(v))?;
                o.opt("counters", None, 0, |f, v| f.parse_bool(v))?;
                let comment = o.opt("comment", None, 0, |f, v| f.parse_string(v))?;
                let name = o
                    .opt("name", None, REQUIRED, |f, v| f.parse_identifier(v))?
                    .unwrap_or_default();
                let family = o
                    .opt("family", s("4"), 0, |f, v| f.parse_family(v))?
                    .unwrap_or(4);
                o.opt("storage", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                let matches = o.list("match", None, PARSE_LIST, |f, v| {
                    f.parse_ipsettype(v).map(|d| vec![d])
                })?;
                o.opt("iprange", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                o.opt("portrange", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                o.opt("netmask", None, UNSUPPORTED, |f, v| f.parse_int(v))?;
                let maxelem = o.opt("maxelem", None, 0, |f, v| f.parse_int(v))?;
                o.opt("hashsize", None, UNSUPPORTED, |f, v| f.parse_int(v))?;
                let timeout = o
                    .opt("timeout", s("-1"), 0, |f, v| f.parse_int(v))?
                    .unwrap_or(Num::Int(-1));
                o.opt("external", None, UNSUPPORTED, |f, v| f.parse_string(v))?;
                let entry = o.list("entry", None, PARSE_LIST, |f, v| {
                    f.parse_string(v).map(|d| vec![d])
                })?;
                let loadfile = o
                    .opt("loadfile", None, 0, |f, v| f.parse_string(v))?
                    .filter(|s: &String| !s.is_empty());
                Ok::<_, ()>((
                    enabled, comment, name, family, matches, maxelem, timeout, entry, loadfile,
                ))
            })();
            if r.is_ok() {
                o.finish();
            }
            r
        };
        let Ok((enabled, comment, name, family, matches, maxelem, timeout, entry, loadfile)) =
            parsed
        else {
            self.warn_section(data, "skipped due to invalid options");
            return;
        };
        if !enabled {
            self.warn_section(data, "is disabled, ignoring section");
            return;
        }
        let Some(matches) = matches else {
            self.warn_section(data, "has no datatypes assigned");
            return;
        };
        let dirs: Vec<String> = matches.iter().map(|m| m.0.clone()).collect();
        let types: Vec<String> = matches.iter().map(|m| m.1.clone()).collect();
        let has = |t: &str| types.iter().any(|x| x == t);
        if (has("ip") || has("net")) && family == 0 {
            self.warn_section(
                data,
                "must not specify family 'any' when matching type 'ip' or 'net'",
            );
            return;
        }
        if has("set") {
            self.warn_section(data, "match type 'set' is not supported");
            return;
        }
        let mut interval = false;
        if has("net") {
            if self.kernel < 0x05060000 {
                self.warn_section(data, "match type 'net' requires kernel 5.6 or later");
                return;
            }
            interval = true;
        }
        let nft_types: Vec<String> = types
            .iter()
            .map(|t| {
                match t.as_str() {
                    "ip" | "net" => {
                        if family == 4 {
                            "ipv4_addr"
                        } else {
                            "ipv6_addr"
                        }
                    }
                    "mac" => "ether_addr",
                    "port" => "inet_service",
                    _ => "null",
                }
                .to_owned()
            })
            .collect();
        let mut flags: Vec<String> = Vec::new();
        if interval {
            flags.push("interval".into());
        }
        if timeout.as_f64() >= 0.0 {
            flags.push("timeout".into());
        }
        let mut set = Ipset {
            name,
            family,
            comment,
            maxelem,
            timeout,
            entries: Vec::new(),
            loadfile,
            fw4types: types,
            types: nft_types,
            directions: dirs,
            interval,
            flags: if flags.is_empty() { None } else { Some(flags) },
        };
        let mut entries = Vec::new();
        for e in entry.unwrap_or_default() {
            match self.parse_ipsetentry(&e, &set) {
                Some(v) => entries.push(v),
                None => self.warn_section(data, &format!("ignoring invalid ipset entry '{e}'")),
            }
        }
        set.entries = entries;
        self.state.ipsets.push(set);
    }

    // ------------------------------------------------------------ ubus + load

    pub fn read_kernel_version(&self) -> i64 {
        let Some(text) = self.inputs.read_all("/proc/version") else {
            return 0;
        };
        let line = text.lines().next().unwrap_or("");
        let Some(rest) = line.strip_prefix("Linux version ") else {
            return 0;
        };
        let mut nums = Vec::new();
        let mut cur = String::new();
        for c in rest.chars() {
            if c.is_ascii_digit() {
                cur.push(c);
            } else if c == '.' && !cur.is_empty() && nums.len() < 2 {
                nums.push(cur.clone());
                cur.clear();
            } else {
                break;
            }
        }
        if !cur.is_empty() {
            nums.push(cur);
        }
        if nums.len() < 2 {
            return 0;
        }
        let n = |i: usize| nums.get(i).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
        (n(0) << 24) | (n(1) << 16) | n(2)
    }

    fn addr_from_ubus(family: i64, a: &Json) -> Addr {
        let mask = a.get("mask").map(|m| crate::val::to_num(m).as_i64());
        Addr {
            family,
            addr: a
                .get("address")
                .map(to_str)
                .unwrap_or_else(|| "null".into()),
            mask: mask.and_then(|m| crate::ip::to_mask(m, family == 6)),
            bits: mask,
            addr2: None,
            range: false,
            invert: false,
        }
    }

    fn ubus_rule(spec: &Json, name: Option<Json>, device: Option<Json>) -> Json {
        let mut obj: Vec<(String, Json)> = match spec {
            Json::Object(o) => o.clone(),
            _ => Vec::new(),
        };
        let set = |obj: &mut Vec<(String, Json)>, k: &str, v: Json| {
            if let Some(slot) = obj.iter_mut().find(|(key, _)| key == k) {
                slot.1 = v;
            } else {
                obj.push((k.to_owned(), v));
            }
        };
        if let Some(n) = name {
            set(&mut obj, "name", n);
        }
        if let Some(d) = device {
            set(&mut obj, "device", d);
        }
        Json::Object(obj)
    }

    pub fn read_ubus(&mut self) {
        let (ifaces, services) = self.inputs.ubus_state().unwrap_or_else(|_| {
            self.raw_warn("Unable to connect to ubus: Unable to connect to ubus socket\n");
            (None, None)
        });
        let mut rules = Vec::new();
        let mut networks = Vec::new();
        if let Some(Json::Array(list)) = ifaces.as_ref().and_then(|i| i.get("interface")) {
            for ifc in list {
                let l3 = ifc.get("l3_device").filter(|v| !matches!(v, Json::Null));
                let dev = ifc.get("device").filter(|v| !matches!(v, Json::Null));
                let mut net = Net {
                    up: ifc.get("up").map(truthy).unwrap_or(false),
                    device: l3.or(dev).map(to_str),
                    physdev: dev.map(to_str),
                    zone: ifc
                        .get("data")
                        .and_then(|d| d.get("zone"))
                        .filter(|v| !matches!(v, Json::Null))
                        .map(to_str),
                    ipaddrs: Vec::new(),
                };
                if let Some(Json::Array(a)) = ifc.get("ipv4-address") {
                    net.ipaddrs
                        .extend(a.iter().map(|x| Self::addr_from_ubus(4, x)));
                }
                if let Some(Json::Array(a)) = ifc.get("ipv6-address") {
                    net.ipaddrs
                        .extend(a.iter().map(|x| Self::addr_from_ubus(6, x)));
                }
                if let Some(Json::Array(a)) = ifc.get("ipv6-prefix-assignment") {
                    for p in a {
                        if let Some(la) = p.get("local-address").filter(|v| truthy(v)) {
                            net.ipaddrs.push(Self::addr_from_ubus(6, la));
                        }
                    }
                }
                if let Some(Json::Array(specs)) = ifc.get("data").and_then(|d| d.get("firewall")) {
                    for (n, spec) in specs.iter().enumerate() {
                        let ty = spec.get("type").cloned().unwrap_or(Json::Null);
                        let name = if !loose_eq_str(&ty, "ipset") {
                            Json::Str(format!(
                                "ubus:{}[{}] {} {}",
                                ifc.get("interface")
                                    .map(to_str)
                                    .unwrap_or_else(|| "null".into()),
                                ifc.get("proto")
                                    .map(to_str)
                                    .unwrap_or_else(|| "null".into()),
                                if truthy(&ty) {
                                    to_str(&ty)
                                } else {
                                    "rule".into()
                                },
                                n
                            ))
                        } else {
                            spec.get("name").cloned().unwrap_or(Json::Null)
                        };
                        let device = spec
                            .get("device")
                            .filter(|v| !matches!(v, Json::Null))
                            .or(l3)
                            .or(dev)
                            .cloned()
                            .unwrap_or(Json::Null);
                        rules.push(Self::ubus_rule(spec, Some(name), Some(device)));
                    }
                }
                networks.push((
                    ifc.get("interface")
                        .map(to_str)
                        .unwrap_or_else(|| "null".into()),
                    net,
                ));
            }
        }
        if let Some(Json::Object(svcs)) = &services {
            for (svcname, service) in svcs {
                if let Some(Json::Array(specs)) = service.get("firewall") {
                    for (n, spec) in specs.iter().enumerate() {
                        let ty = spec.get("type").cloned().unwrap_or(Json::Null);
                        let name = if !loose_eq_str(&ty, "ipset") {
                            Json::Str(format!(
                                "ubus:{svcname} {} {n}",
                                if truthy(&ty) {
                                    to_str(&ty)
                                } else {
                                    "rule".into()
                                }
                            ))
                        } else {
                            spec.get("name").cloned().unwrap_or(Json::Null)
                        };
                        rules.push(Self::ubus_rule(spec, Some(name), None));
                    }
                }
                if let Json::Object(insts) = service {
                    for (inst, instance) in insts {
                        if let Some(Json::Array(specs)) = instance.get("firewall") {
                            for (n, spec) in specs.iter().enumerate() {
                                let ty = spec.get("type").cloned().unwrap_or(Json::Null);
                                let name = if !loose_eq_str(&ty, "ipset") {
                                    Json::Str(format!(
                                        "ubus:{svcname}[{inst}] {} {n}",
                                        if truthy(&ty) {
                                            to_str(&ty)
                                        } else {
                                            "rule".into()
                                        }
                                    ))
                                } else {
                                    spec.get("name").cloned().unwrap_or(Json::Null)
                                };
                                rules.push(Self::ubus_rule(spec, Some(name), None));
                            }
                        }
                    }
                }
            }
        }
        self.state.networks = networks;
        self.state.ubus_rules = rules;
    }

    fn ubus_rules_of(&self, ty: &str) -> Vec<Json> {
        self.state
            .ubus_rules
            .iter()
            .filter(|r| r.get("type").map(|t| loose_eq_str(t, ty)).unwrap_or(false))
            .cloned()
            .collect()
    }

    /// fw4.uc `load()` without the statefile shortcut: always reads ubus.
    /// `Err` propagates ucode's abort out of `parse_defaults`; nothing is
    /// rendered and no state file is written.
    pub fn load(&mut self) -> Result<(), ()> {
        self.firewall = Rc::new(self.inputs.uci_load("firewall"));
        self.helpers_cfg = Rc::new(self.inputs.uci_load("/usr/share/firewall4/helpers"));
        self.read_ubus();
        self.kernel = self.read_kernel_version();

        // Rc handles let the section walk borrow the configs while each
        // parser borrows `self` mutably; nothing is cloned.
        let helpers_cfg = Rc::clone(&self.helpers_cfg);
        let firewall = Rc::clone(&self.firewall);
        for h in helpers_cfg.of_type("helper") {
            self.parse_helper(h);
        }
        for d in firewall.of_type("defaults") {
            self.parse_defaults(d)?;
        }
        if self.state.defaults.is_none() {
            self.parse_defaults(&Json::Object(vec![]))?;
        }
        for r in self.ubus_rules_of("ipset") {
            self.parse_ipset(&r);
        }
        for x in firewall.of_type("ipset") {
            self.parse_ipset(x);
        }
        for z in firewall.of_type("zone") {
            self.parse_zone(z);
        }
        for r in self.ubus_rules_of("rule") {
            self.parse_rule(&r);
        }
        for x in firewall.of_type("rule") {
            self.parse_rule(x);
        }
        for x in firewall.of_type("forwarding") {
            self.parse_forwarding(x);
        }
        for r in self.ubus_rules_of("redirect") {
            self.parse_redirect(&r);
        }
        for x in firewall.of_type("redirect") {
            self.parse_redirect(x);
        }
        for r in self.ubus_rules_of("nat") {
            self.parse_nat(&r);
        }
        for x in firewall.of_type("nat") {
            self.parse_nat(x);
        }
        for x in firewall.of_type("include") {
            self.parse_include(x)?;
        }
        if self.defaults().auto_includes.unwrap_or(false) {
            for position in [
                "ruleset-pre",
                "ruleset-post",
                "table-pre",
                "table-post",
                "chain-pre",
                "chain-post",
            ] {
                let chains: Vec<Option<String>> = if position.starts_with("chain-") {
                    self.inputs
                        .lsdir(&format!("/usr/share/nftables.d/{position}"))
                        .into_iter()
                        .map(Some)
                        .collect()
                } else {
                    vec![None]
                };
                for chain in chains {
                    let dir = match &chain {
                        Some(c) => format!("/usr/share/nftables.d/{position}/{c}"),
                        None => format!("/usr/share/nftables.d/{position}"),
                    };
                    for path in self.inputs.glob(&format!("{dir}/*.nft")) {
                        if self.inputs.access(&path) {
                            let obj = Json::Object(vec![
                                ("type".into(), Json::Str("nftables".into())),
                                ("position".into(), Json::Str(position.into())),
                                (
                                    "chain".into(),
                                    chain.clone().map(Json::Str).unwrap_or(Json::Null),
                                ),
                                ("path".into(), Json::Str(path)),
                            ]);
                            self.parse_include(&obj)?;
                        }
                    }
                }
            }
        }
        if self.aborted {
            return Err(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::Inputs;
    use crate::state::State;
    use crate::uci::Config;

    const ZONE: &str = r#""zone":[{"name":"lan","device":"br-lan","input":"ACCEPT","output":"ACCEPT","forward":"ACCEPT"}]"#;

    /// `load()` reads its config back through `Inputs`, so the fixture goes to
    /// a mock dir in the upstream test-suite layout.
    fn fw(tag: &str, cfg: &str) -> Fw4 {
        let dir = std::env::temp_dir().join(format!("fw4rs-defaults-{tag}"));
        std::fs::create_dir_all(dir.join("uci")).unwrap();
        std::fs::write(dir.join("uci/firewall.json"), cfg).unwrap();
        Fw4 {
            inputs: Inputs::mock(vec![dir.to_str().unwrap().to_owned()], false),
            firewall: Rc::new(Config::empty()),
            helpers_cfg: Rc::new(Config::empty()),
            state: State::default(),
            kernel: 0,
            quiet: true,
            aborted: false,
            tty: false,
        }
    }

    /// R83/F17: an invalid option in `config defaults` aborts the load, exactly
    /// like the ucode `parse_options()` -> `false` -> `fw4.uc:1978` reference
    /// error that makes utpl exit 254 with an empty ruleset.  It must never
    /// fall through to an all-`None` `Defaults`, which renders `policy null;`.
    #[test]
    fn defaults_invalid_option_aborts() {
        for (tag, bad) in [
            ("policy", r#""input":"ACEPT""#),
            ("bool", r#""drop_invalid":"notabool""#),
            ("list", r#""input":["ACCEPT","REJECT"]"#),
            ("limit", r#""synflood_rate":"25/fortnight""#),
        ] {
            let mut fw = fw(
                tag,
                &format!(r#"{{"defaults":{{{bad},"output":"ACCEPT"}},{ZONE}}}"#),
            );
            assert_eq!(fw.load(), Err(()), "expected an abort for {bad}");
            assert!(
                fw.state.defaults.is_none(),
                "{bad} stored a Defaults anyway"
            );
        }
    }

    /// R83: `config include` is the same failure class one section type over
    /// (`fw4.uc:3220`), and must abort too instead of degrading to the
    /// "is disabled, ignoring section" branch and rendering on.
    #[test]
    fn include_invalid_option_aborts() {
        let inc = |body: &str| format!(r#"{{{ZONE},"include":[{{{body}}}]}}"#);
        for (tag, bad) in [
            (
                "iposition",
                r#""path":"/etc/x.nft","type":"nftables","position":"BOGUS""#,
            ),
            ("itype", r#""path":"/etc/x.nft","type":"yes""#),
            (
                "ibool",
                r#""path":"/etc/x.nft","type":"nftables","enabled":"maybe""#,
            ),
            ("ipath", r#""type":"nftables""#), // REQUIRED but not set
        ] {
            let mut fw = fw(tag, &inc(bad));
            assert_eq!(fw.load(), Err(()), "expected an abort for {bad}");
            assert!(fw.state.includes.is_empty(), "{bad} kept an include anyway");
        }
        // `enabled 0` is one of ucode's own "ignoring section" paths, not an abort
        let mut fw = fw(
            "idisabled",
            &inc(r#""path":"/etc/x.nft","type":"nftables","enabled":"0""#),
        );
        assert_eq!(fw.load(), Ok(()));
        assert!(fw.state.includes.is_empty());
    }

    /// The other half: what fw4 accepts still loads, and neither a real
    /// `defaults` section nor a missing one renders the `null` policy the F17
    /// fall-through produced.
    #[test]
    fn defaults_valid_and_missing_render_real_policies() {
        for (tag, cfg) in [
            (
                "ok",
                format!(
                    r#"{{"defaults":{{"input":"REJECT","output":"ACCEPT","forward":"REJECT","syn_flood":"1"}},{ZONE}}}"#
                ),
            ),
            ("none", format!(r#"{{{ZONE}}}"#)), // no defaults section -> parse_defaults({})
        ] {
            let mut fw = fw(tag, &cfg);
            assert_eq!(fw.load(), Ok(()));
            assert!(fw.state.defaults.is_some());
            let out = fw.render_ruleset();
            assert!(
                !out.contains("policy null"),
                "rendered `policy null;`:\n{out}"
            );
            assert!(
                !out.contains("icmpx type  "),
                "rendered an empty reject code:\n{out}"
            );
            assert!(
                out.contains("type filter hook input priority filter; policy drop;"),
                "{out}"
            );
            assert!(
                out.contains("reject with icmpx type port-unreachable"),
                "{out}"
            );
        }
    }
}
