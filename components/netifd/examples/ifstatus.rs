//! Build `network.interface dump` from the config alone, for a static-only
//! configuration, so it can be compared with what the C netifd reports.
//!
//! Usage: ifstatus <confdir> <c-dump.json>
//!
//! For `proto static` almost the whole status is a function of the config. The
//! parts that are not — the state machine's booleans, `uptime`, and which
//! device ended up being the L3 device — are taken from the C dump, and the
//! comparison is about everything else.

use owrt_netifd::{config, interface, ip};
use owrt_ubus::blob::BlobBuf;
use owrt_ubus::json::Json;


use interface::{Address, Interface, IpSettings, Route, State};

fn b_of(v: &Json, k: &str) -> bool {
    matches!(v.get(k), Some(Json::Bool(true)))
}

fn s_of(v: &Json, k: &str) -> Option<String> {
    match v.get(k) {
        Some(Json::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn u_of(v: &Json, k: &str) -> Option<u32> {
    match v.get(k) {
        Some(Json::Int(n)) => Some(*n as u32),
        _ => None,
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let confdir = args.next().expect("usage: ifstatus <confdir> <c-dump.json>");
    let cpath = args.next().expect("usage: ifstatus <confdir> <c-dump.json>");

    let cfg = config::load(&confdir).unwrap_or_else(|e| {
        eprintln!("config: {e}");
        std::process::exit(1);
    });
    for e in &cfg.errors {
        eprintln!("config error: {e}");
    }

    let ctext = std::fs::read_to_string(&cpath).expect("read c dump");
    let cdump = owrt_ubus::json::parse(&ctext).expect("parse c dump");
    let Some(Json::Array(cifaces)) = cdump.get("interface") else {
        eprintln!("no interface array in the C dump");
        std::process::exit(2);
    };

    // The global prefix list: the ULA from `globals`, plus anything an
    // uplink delegates (none, for a static-only config). netifd keeps it in
    // reverse insertion order, and the ULA is inserted at config load.
    let mut prefixes: Vec<ip::DevicePrefix> = Vec::new();
    if let Some((addr, len)) = cfg.globals.ula_prefix {
        // interface_ip_set_ula_prefix refuses a length outside 1..=64
        if (1..=64).contains(&len) {
            prefixes.push(ip::DevicePrefix::new(addr, len, "local", None));
        }
    }
    // requests are in netifd's interface order, which is by name
    let mut reqs: Vec<ip::AssignRequest> = cfg
        .interfaces
        .iter()
        .filter_map(|i| {
            i.ip6assign.map(|l| ip::AssignRequest {
                name: i.name.clone(),
                length: l,
                hint: i.ip6hint,
                weight: 0,
                classes: vec![],
            })
        })
        .collect();
    reqs.sort_by(|a, b| a.name.cmp(&b.name));
    let placed: Vec<(usize, ip::Assignment)> = prefixes
        .iter()
        .enumerate()
        .flat_map(|(pi, p)| ip::assign(p, &reqs).into_iter().map(move |a| (pi, a)))
        .collect();

    let mut b = BlobBuf::new();
    let arr = b.msg_open_array("interface");
    // the C dump's order is netifd's own interface list order; follow it so
    // the comparison is not about ordering we have not implemented yet
    for ci in cifaces {
        let Some(name) = s_of(ci, "interface") else { continue };
        let Some(ic) = cfg.interfaces.iter().find(|i| i.name == name) else { continue };

        let mut i = Interface::new(&name);
        i.state = if b_of(ci, "up") {
            State::Up
        } else if b_of(ci, "pending") {
            State::Setup
        } else {
            State::Down
        };
        i.available = b_of(ci, "available");
        i.autostart = b_of(ci, "autostart");
        i.dynamic = b_of(ci, "dynamic");
        let uptime = u_of(ci, "uptime").unwrap_or(0);
        i.l3_device = s_of(ci, "l3_device");
        i.proto = Some(ic.proto.clone());
        i.device = s_of(ci, "device");
        i.updated = u_of(ci, "updated").unwrap_or(0);
        // `updated` is an array of names in the dump, not a number
        if let Some(Json::Array(u)) = ci.get("updated") {
            i.updated = u.iter().fold(0, |acc, e| {
                acc | match e {
                    Json::Str(s) if s == "addresses" => interface::updated::ADDRESS,
                    Json::Str(s) if s == "routes" => interface::updated::ROUTE,
                    Json::Str(s) if s == "prefixes" => interface::updated::PREFIX,
                    Json::Str(s) if s == "data" => interface::updated::DATA,
                    _ => 0,
                }
            });
        }
        i.metric = ic.metric;
        i.dns_metric = ic.dns_metric;
        i.ip4table = ic.ip4table.unwrap_or(0);
        i.ip6table = ic.ip6table.unwrap_or(0);

        // proto static puts the configured addresses, routes and DNS into
        // proto_ip, not config_ip: proto_apply_static_ip_settings runs as the
        // protocol handler.
        let mut ip = IpSettings::default();
        for (a, m) in &ic.ipv4 {
            ip.addresses.push(Address::new(std::net::IpAddr::V4(*a), *m));
        }
        for (a, m) in &ic.ipv6 {
            ip.addresses.push(Address::new(std::net::IpAddr::V6(*a), *m));
        }
        // parse_gateway_option sets only the family flag: the metric it
        // stores is never printed, because DEVROUTE_METRIC stays clear.
        if let Some(gw) = ic.gateway {
            let mut r =
                Route::new("0.0.0.0".parse().unwrap(), 0, std::net::IpAddr::V4(gw));
            r.metric = ic.metric;
            if let Some(t) = ic.ip4table {
                r.table = t;
            }
            ip.routes.push(r);
        }
        if let Some(gw) = ic.ip6gw {
            let mut r = Route::new("::".parse().unwrap(), 0, std::net::IpAddr::V6(gw));
            r.metric = ic.metric;
            if let Some(t) = ic.ip6table {
                r.table = t;
            }
            ip.routes.push(r);
        }
        ip.dns_servers = ic.dns.clone();
        ip.dns_search = ic.dns_search.clone();
        ip.no_delegation = ic.delegate == Some(false);
        i.proto_ip = ip;
        i.proto_ip.routes.sort_by(interface::route_order);

        // errors are the state machine's; copy them so a device that is
        // missing in both runs does not read as a difference
        if let Some(Json::Array(errs)) = ci.get("errors") {
            for e in errs {
                i.errors.push(interface::IfaceError {
                    subsystem: s_of(e, "subsystem").unwrap_or_default(),
                    code: s_of(e, "code").unwrap_or_default(),
                    data: match e.get("data") {
                        Some(Json::Array(d)) => d
                            .iter()
                            .filter_map(|x| match x {
                                Json::Str(s) => Some(s.clone()),
                                _ => None,
                            })
                            .collect(),
                        _ => vec![],
                    },
                });
            }
        }

        // ipv6-prefix-assignment walks the global prefix list and picks the
        // entries naming this interface.
        for (pi, a) in placed.iter().filter(|(_, a)| a.name == name) {
            let p = &prefixes[*pi];
            let addr = ip::assignment_address(p, a.assigned);
            i.prefix_assignments.push(interface::PrefixAssignment {
                addr,
                length: a.length,
                preferred_until: p.preferred_until,
                valid_until: p.valid_until,
                local: if i.state == State::Up || i.state == State::Setup {
                    Some((ip::local_address(addr, "::1".parse().unwrap()), a.length))
                } else {
                    None
                },
                owner: Some((p.iface.clone(), p.addr, p.length)),
            });
        }

        let t = b.msg_open_table("");
        b.msg_string("interface", &name);
        i.dump_status_with(&mut b, uptime, &i.proto_ip.prefixes);
        b.msg_close(t);
    }
    b.msg_close(arr);
    println!("{}", owrt_ubus::convert::fields_to_json(b.payload()).to_compact());
}
