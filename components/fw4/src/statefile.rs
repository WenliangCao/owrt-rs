//! `/var/run/fw4.state`: written by `start`, read by the lookup actions,
//! `reload-sets` and `includes`. Same JSON shape as the ucode implementation
//! so either implementation can read what the other wrote.

use crate::state::*;
use crate::val::Num;
use owrt_ubus::json::Json;

pub const STATEFILE: &str = "/var/run/fw4.state";

fn s(v: &str) -> Json {
    Json::Str(v.to_owned())
}
fn os(v: &Option<String>) -> Json {
    v.as_ref().map(|x| s(x)).unwrap_or(Json::Null)
}
fn strs(v: &[String]) -> Json {
    Json::Array(v.iter().map(|x| s(x)).collect())
}
fn ostrs(v: &Option<Vec<String>>) -> Json {
    v.as_ref().map(|x| strs(x)).unwrap_or(Json::Null)
}
fn num(n: Num) -> Json {
    match n {
        Num::Int(i) => Json::Int(i),
        Num::Dbl(d) => Json::Float(d),
    }
}
fn onum(n: &Option<Num>) -> Json {
    n.map(num).unwrap_or(Json::Null)
}
fn obj(items: Vec<(&str, Json)>) -> Json {
    Json::Object(items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

fn addr(a: &Addr) -> Json {
    let mut o = vec![("family", Json::Int(a.family)), ("addr", s(&a.addr))];
    if a.range {
        o.push(("addr2", os(&a.addr2)));
        o.push(("range", Json::Bool(true)));
    } else {
        o.push(("mask", os(&a.mask)));
        o.push(("bits", a.bits.map(Json::Int).unwrap_or(Json::Null)));
    }
    if a.invert {
        o.push(("invert", Json::Bool(true)));
    }
    obj(o)
}
fn addrs(v: &[Addr]) -> Json {
    Json::Array(v.iter().map(addr).collect())
}
fn oaddrs(v: &Option<Vec<Addr>>) -> Json {
    v.as_ref().map(|x| addrs(x)).unwrap_or(Json::Null)
}
fn limit(l: &Option<Limit>) -> Json {
    match l {
        Some(l) => obj(vec![
            ("invert", Json::Bool(l.invert)),
            ("rate", num(l.rate)),
            ("unit", s(&l.unit)),
        ]),
        None => Json::Null,
    }
}
fn flags(f: &Flags) -> Json {
    Json::Object(f.0.iter().map(|k| (k.clone(), Json::Bool(true))).collect())
}
fn group(g: &SubnetGroup) -> Json {
    Json::Array(vec![oaddrs(&g.0), oaddrs(&g.1), oaddrs(&g.2)])
}
fn groups(v: &[SubnetGroup]) -> Json {
    Json::Array(v.iter().map(group).collect())
}

fn zone(z: &Zone) -> Json {
    obj(vec![
        ("name", s(&z.name)),
        (
            "family",
            if z.family == 0 {
                Json::Null
            } else {
                Json::Int(z.family)
            },
        ),
        ("input", s(&z.input)),
        ("output", s(&z.output)),
        ("forward", s(&z.forward)),
        ("masq", Json::Bool(z.masq)),
        ("masq_allow_invalid", Json::Bool(z.masq_allow_invalid)),
        ("masq6", Json::Bool(z.masq6)),
        ("mtu_fix", Json::Bool(z.mtu_fix)),
        ("log", onum(&z.log)),
        ("log_limit", limit(&z.log_limit)),
        ("auto_helper", Json::Bool(z.auto_helper)),
        ("counter", Json::Bool(z.counter)),
        (
            "network",
            Json::Array(
                z.network
                    .iter()
                    .map(|d| {
                        obj(vec![
                            ("invert", Json::Bool(d.invert)),
                            ("device", os(&d.device)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "match_rules",
            Json::Array(
                z.match_rules
                    .iter()
                    .map(|m| {
                        obj(vec![
                            ("family", Json::Int(m.family)),
                            ("devices_pos", ostrs(&m.devices_pos)),
                            ("devices_neg", ostrs(&m.devices_neg)),
                            ("devices_neg_wildcard", ostrs(&m.devices_neg_wildcard)),
                            ("subnets_pos", ostrs(&m.subnets_pos)),
                            ("subnets_neg", ostrs(&m.subnets_neg)),
                            ("subnets_masked", oaddrs(&m.subnets_masked)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("masq4_src_subnets", groups(&z.masq4_src_subnets)),
        ("masq4_dest_subnets", groups(&z.masq4_dest_subnets)),
        ("masq6_src_subnets", groups(&z.masq6_src_subnets)),
        ("masq6_dest_subnets", groups(&z.masq6_dest_subnets)),
        ("sflags", flags(&z.sflags)),
        ("dflags", flags(&z.dflags)),
        ("match_devices", strs(&z.match_devices)),
        ("match_subnets", strs(&z.match_subnets)),
        ("related_subnets", addrs(&z.related_subnets)),
        ("related_physdevs", strs(&z.related_physdevs)),
    ])
}

fn ipset(i: &Ipset) -> Json {
    obj(vec![
        ("enabled", Json::Bool(true)),
        ("comment", os(&i.comment)),
        ("name", s(&i.name)),
        ("family", Json::Int(i.family)),
        ("maxelem", onum(&i.maxelem)),
        ("timeout", num(i.timeout)),
        ("loadfile", os(&i.loadfile)),
        ("fw4types", strs(&i.fw4types)),
        ("types", strs(&i.types)),
        ("directions", strs(&i.directions)),
        ("interval", Json::Bool(i.interval)),
        ("flags", ostrs(&i.flags)),
        (
            "entries",
            Json::Array(i.entries.iter().map(|e| strs(e)).collect()),
        ),
    ])
}

fn include(i: &Include) -> Json {
    let mut o = vec![
        ("enabled", Json::Bool(i.enabled)),
        ("path", s(&i.path)),
        ("type", s(&i.ty)),
        ("fw4_compatible", Json::Bool(i.fw4_compatible)),
        ("position", s(&i.position)),
    ];
    if let Some(c) = &i.chain {
        o.push(("chain", s(c)));
    }
    obj(o)
}

fn net(n: &Net) -> Json {
    obj(vec![
        ("up", Json::Bool(n.up)),
        ("device", os(&n.device)),
        ("physdev", os(&n.physdev)),
        ("zone", os(&n.zone)),
        ("ipaddrs", addrs(&n.ipaddrs)),
    ])
}

pub fn to_json(st: &State) -> Json {
    obj(vec![
        ("zones", Json::Array(st.zones.iter().map(zone).collect())),
        ("ipsets", Json::Array(st.ipsets.iter().map(ipset).collect())),
        (
            "networks",
            Json::Object(
                st.networks
                    .iter()
                    .map(|(k, v)| (k.clone(), net(v)))
                    .collect(),
            ),
        ),
        ("ubus_rules", Json::Array(st.ubus_rules.clone())),
        (
            "includes",
            Json::Array(st.includes.iter().map(include).collect()),
        ),
    ])
}

/// What the lookup/reload-sets/includes actions need from a saved state.
pub struct Saved {
    pub zones: Vec<Json>,
    pub ipsets: Vec<Ipset>,
    pub includes: Vec<Include>,
}

fn jstrs(v: Option<&Json>) -> Vec<String> {
    match v {
        Some(Json::Array(a)) => a.iter().map(crate::val::to_str).collect(),
        _ => Vec::new(),
    }
}

pub fn parse(j: &Json) -> Saved {
    let arr = |k: &str| -> Vec<Json> {
        j.get(k)
            .and_then(Json::as_array)
            .map(|a| a.to_vec())
            .unwrap_or_default()
    };
    let ipsets = arr("ipsets")
        .iter()
        .map(|i| Ipset {
            name: i.get("name").map(crate::val::to_str).unwrap_or_default(),
            family: i
                .get("family")
                .map(|f| crate::val::to_num(f).as_i64())
                .unwrap_or(4),
            comment: i.get("comment").and_then(Json::as_str).map(str::to_owned),
            maxelem: i
                .get("maxelem")
                .filter(|v| !matches!(v, Json::Null))
                .map(crate::val::to_num),
            timeout: i
                .get("timeout")
                .map(crate::val::to_num)
                .unwrap_or(Num::Int(-1)),
            entries: match i.get("entries") {
                Some(Json::Array(a)) => a.iter().map(|e| jstrs(Some(e))).collect(),
                _ => Vec::new(),
            },
            loadfile: i.get("loadfile").and_then(Json::as_str).map(str::to_owned),
            fw4types: jstrs(i.get("fw4types")),
            types: jstrs(i.get("types")),
            directions: jstrs(i.get("directions")),
            interval: i.get("interval").map(crate::val::truthy).unwrap_or(false),
            flags: i
                .get("flags")
                .and_then(Json::as_array)
                .map(|_| jstrs(i.get("flags"))),
        })
        .collect();
    let includes = arr("includes")
        .iter()
        .map(|i| Include {
            enabled: i.get("enabled").map(crate::val::truthy).unwrap_or(true),
            path: i.get("path").map(crate::val::to_str).unwrap_or_default(),
            ty: i.get("type").map(crate::val::to_str).unwrap_or_default(),
            fw4_compatible: i
                .get("fw4_compatible")
                .map(crate::val::truthy)
                .unwrap_or(true),
            position: i
                .get("position")
                .map(crate::val::to_str)
                .unwrap_or_default(),
            chain: i.get("chain").and_then(Json::as_str).map(str::to_owned),
        })
        .collect();
    Saved {
        zones: arr("zones"),
        ipsets,
        includes,
    }
}
