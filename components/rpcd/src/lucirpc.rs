//! luci-rpc.c port (rpcd-mod-luci 20240305): the `luci-rpc` ubus object.
//! Wireless replies combine network.wireless status with the `iwinfoobj`
//! serializer and its nl80211 backend.

use crate::session::{arg, Reply};
use crate::{rrdns, rtnl, Ctx, Deferrer};
use owrt_ubus::blob;
use owrt_ubus::blob::MsgType;
use owrt_ubus::json::Json;
use owrt_ubus::{status, BlobBuf, Connection, Request};
use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    vec![
        ("getNetworkDevices", vec![]),
        ("getWirelessDevices", vec![]),
        ("getHostHints", vec![]),
        ("getDUIDHints", vec![]),
        ("getBoardJSON", vec![]),
        ("getDHCPLeases", vec![("family", MsgType::Int32)]),
    ]
}

// ------------------------------------------------------------ small helpers

/// readstr(): first 127 bytes of the file, trailing whitespace trimmed; ""
/// when unreadable (a directory opens but fread fails -> "").
pub fn readstr(path: &str) -> String {
    let mut buf = [0u8; 127];
    let mut got = 0;
    if let Ok(mut f) = fs::File::open(path) {
        while got < buf.len() {
            match std::io::Read::read(&mut f, &mut buf[got..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
    }
    while got > 0 && buf[got - 1].is_ascii_whitespace() {
        got -= 1;
    }
    String::from_utf8_lossy(&buf[..got]).into_owned()
}

/// atoi()
pub fn atoi(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v * 10 + (b[i] - b'0') as i64;
        if v > i32::MAX as i64 + 1 {
            break;
        }
        i += 1;
    }
    (if neg { -v } else { v }) as i32
}

/// strtol(s, NULL, 10) truncated to int (lease timestamps).
fn strtol10(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((b[i] - b'0') as i64);
        i += 1;
    }
    let v = if neg { -v } else { v };
    v.clamp(i64::MIN, i64::MAX) as i32
}

/// strtoull(s, NULL, 10)
fn strtoull10(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < b.len() && b[i].is_ascii_digit() {
        match v
            .checked_mul(10)
            .and_then(|x| x.checked_add((b[i] - b'0') as u64))
        {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        return u64::MAX;
    }
    if neg {
        v.wrapping_neg()
    } else {
        v
    }
}

/// ether_aton(): six ':'-separated hex numbers (strtoul base 16), each <= 0xff.
pub fn ether_aton(s: &str) -> Option<[u8; 6]> {
    let b = s.as_bytes();
    let mut out = [0u8; 6];
    let mut i = 0;
    #[allow(clippy::needless_range_loop)] // index walk mirrors ether_aton's byte cursor
    for oct in 0..6 {
        if oct != 0 {
            if b.get(i) != Some(&b':') {
                return None;
            }
            i += 1;
        }
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        let mut v: u64 = 0;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            v = v
                .saturating_mul(16)
                .saturating_add((b[i] as char).to_digit(16).unwrap() as u64);
            i += 1;
        }
        if i == start || v > 0xff {
            return None;
        }
        out[oct] = v as u8;
    }
    if i != b.len() {
        return None;
    }
    Some(out)
}

/// duid2ea()
fn duid2ea(duid: &str) -> Option<[u8; 6]> {
    let b = duid.as_bytes();
    if !b.iter().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let p = match b.len() {
        28 if b.starts_with(b"00010001") => &b[16..],
        20 if b.starts_with(b"00030001") => &b[8..],
        12 => b,
        _ => return None,
    };
    let hex = |c: u8| (c as char).to_digit(16).unwrap() as u8;
    let mut ea = [0u8; 6];
    for i in 0..6 {
        ea[i] = hex(p[2 * i]) * 16 + hex(p[2 * i + 1]);
    }
    Some(ea)
}

fn ea_empty(ea: &[u8; 6]) -> bool {
    ea.iter().all(|&b| b == 0)
}

/// strtok(s, delims) as an iterator over tokens (delimiter runs skipped).
fn strtok<'a>(s: &'a str, delims: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    s.split(move |c| delims.contains(c))
        .filter(|t| !t.is_empty())
}

// ------------------------------------------------------------ leases

#[derive(Clone, Debug, Default)]
pub struct Lease {
    pub v6: bool,
    pub expire: i32,
    pub mac: [u8; 6],
    pub iface: Option<String>,
    pub hostname: Option<String>,
    pub duid: Option<String>,
    pub iaid: Option<String>,
    pub addrs: Vec<[u8; 16]>, // IPv4 in the first 4 bytes
    pub mask: u8,
}

fn parse_addr(v6: bool, s: &str) -> Option<[u8; 16]> {
    if v6 {
        s.parse::<Ipv6Addr>().ok().map(|a| a.octets())
    } else {
        s.parse::<Ipv4Addr>().ok().map(|a| {
            let mut o = [0u8; 16];
            o[..4].copy_from_slice(&a.octets());
            o
        })
    }
}

fn addr_str(v6: bool, a: &[u8; 16]) -> String {
    if v6 {
        Ipv6Addr::from(*a).to_string()
    } else {
        Ipv4Addr::new(a[0], a[1], a[2], a[3]).to_string()
    }
}

/// find_leasefiles(): `leasefile` of every dnsmasq (or odhcpd) section of
/// /etc/config/dhcp; falls back to the default path when none opened.
fn lease_files() -> Vec<(String, bool)> {
    let mut files = Vec::new();
    let mut ctx = owrt_uci::Context::new();
    let pkg = owrt_uci::file::load(&mut ctx, "dhcp").ok();
    for (ty, odhcpd, fallback) in [
        ("dnsmasq", false, "/tmp/dhcp.leases"),
        ("odhcpd", true, "/tmp/odhcpd.leases"),
    ] {
        let mut found = false;
        if let Some(pidx) = pkg {
            for s in ctx.root[pidx].sections.iter().filter(|s| s.ty == ty) {
                if let Some(i) = s.find_option("leasefile") {
                    if let owrt_uci::OptionValue::Str(path) = &s.options[i].value {
                        let path = String::from_utf8_lossy(path).into_owned();
                        if fs::File::open(&path).is_ok() {
                            files.push((path, odhcpd));
                            found = true;
                        }
                    }
                }
            }
        }
        if !found && fs::File::open(fallback).is_ok() {
            files.push((fallback.to_owned(), odhcpd));
        }
    }
    files
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// lease_open() + lease_next() until exhaustion.
pub fn leases() -> Vec<Lease> {
    let now = now();
    let mut out = Vec::new();
    for (path, odhcpd) in lease_files() {
        let Ok(data) = fs::read(&path) else { continue };
        // fgets(buf, 512): overlong lines split into chunks
        let mut lines: Vec<&[u8]> = Vec::new();
        for line in data.split_inclusive(|&c| c == b'\n') {
            let mut rest = line;
            while rest.len() > 511 {
                lines.push(&rest[..511]);
                rest = &rest[511..];
            }
            if !rest.is_empty() {
                lines.push(rest);
            }
        }
        for raw in lines {
            let line = String::from_utf8_lossy(raw).into_owned();
            let mut e = Lease::default();
            if odhcpd {
                let mut t = strtok(&line, " \t\n");
                if t.next() != Some("#") {
                    continue;
                }
                let Some(iface) = t.next() else { continue };
                let Some(duid) = t.next() else { continue };
                let Some(iaid) = t.next() else { continue };
                let mut ea = None;
                e.iface = Some(iface.to_owned());
                if iaid == "ipv4" {
                    e.v6 = false;
                    e.mask = 32;
                    ea = ether_aton(duid);
                } else {
                    e.v6 = true;
                    e.mask = 128;
                    e.duid = Some(duid.to_owned());
                    e.iaid = Some(iaid.to_owned());
                }
                let Some(hostname) = t.next() else { continue };
                let Some(ts) = t.next() else { continue };
                let n = strtol10(ts) as i64;
                e.expire = if n > now {
                    (n - now) as i32
                } else if n >= 0 {
                    0
                } else {
                    -1
                };
                t.next(); // id
                let Some(len) = t.next() else { continue };
                let n = atoi(len);
                if n != 0 {
                    e.mask = n as u8;
                }
                // the remaining tokens, additionally split at '/'
                let rest: Vec<&str> = t.collect();
                for tok in rest.iter().flat_map(|r| strtok(r, "/ \t\n")) {
                    if e.addrs.len() >= 10 {
                        break;
                    }
                    if let Some(a) = parse_addr(e.v6, tok) {
                        e.addrs.push(a);
                    }
                }
                if ea.is_none() {
                    if let Some(d) = &e.duid {
                        ea = duid2ea(d);
                    }
                }
                if let Some(ea) = ea {
                    e.mac = ea;
                }
                e.hostname = if hostname == "-" {
                    None
                } else {
                    Some(hostname.to_owned())
                };
                if e.duid.as_deref() == Some("-") {
                    e.duid = None;
                }
            } else {
                let mut t = strtok(&line, " \t\n");
                let Some(ts) = t.next() else { continue };
                let n = strtol10(ts) as i64;
                e.expire = if n > now {
                    (n - now) as i32
                } else if n > 0 {
                    0
                } else {
                    -1
                };
                let Some(mac) = t.next() else { continue };
                let mut ea = ether_aton(mac);
                let addr = t.next();
                match addr {
                    Some(p) if p.parse::<Ipv6Addr>().is_ok() => {
                        e.v6 = true;
                        e.mask = 128;
                        e.addrs.push(parse_addr(true, p).unwrap());
                    }
                    Some(p) if p.parse::<Ipv4Addr>().is_ok() => {
                        e.v6 = false;
                        e.mask = 32;
                        e.addrs.push(parse_addr(false, p).unwrap());
                    }
                    _ => continue,
                }
                if ea.is_none() && !e.v6 {
                    continue;
                }
                let (Some(hostname), Some(duid)) = (t.next(), t.next()) else {
                    continue;
                };
                e.hostname = if hostname == "*" {
                    None
                } else {
                    Some(hostname.to_owned())
                };
                let strip_colon = |s: &str| s.replace(':', "");
                if !e.v6 && duid.len() > 15 && duid.starts_with("ff:") {
                    // ff:<iaid-4-bytes>:<duid-x-bytes...>
                    // C splits bytes at fixed offsets. A malformed client ID
                    // can split a UTF-8 character; retain this module's lossy
                    // display policy without indexing inside a Rust string.
                    e.iaid = Some(strip_colon(&String::from_utf8_lossy(
                        &duid.as_bytes()[3..14],
                    )));
                    e.duid = Some(strip_colon(&String::from_utf8_lossy(
                        &duid.as_bytes()[15..],
                    )));
                } else if !e.v6 && duid.len() == 20 && duid.starts_with("01:") {
                    // 01:<mac-addr-6-bytes>
                    if ea.is_none() {
                        ea = ether_aton(&duid[3..]);
                    }
                    e.duid = None;
                } else if duid == "*" {
                    e.duid = None;
                } else {
                    e.duid = Some(strip_colon(duid));
                }
                if ea.is_none() {
                    if let Some(d) = &e.duid {
                        ea = duid2ea(d);
                    }
                }
                if let Some(ea) = ea {
                    e.mac = ea;
                }
            }
            out.push(e);
        }
    }
    out
}

// ------------------------------------------------------------ network devices

/// rpc_luci_parse_network_device_sys
fn network_device(b: &mut BlobBuf, name: &str, ifaddr: &[rtnl::IfAddr]) {
    let sys = |f: &str| format!("/sys/class/net/{name}/{f}");
    let o = b.msg_open_table(name);
    b.msg_string("name", name);
    if let Ok(rd) = fs::read_dir(sys("brif")) {
        b.msg_bool("bridge", true);
        let a = b.msg_open_array("ports");
        for e in rd.flatten() {
            b.msg_string("", &e.file_name().to_string_lossy());
        }
        b.msg_close(a);
        b.msg_string("id", &readstr(&sys("bridge/bridge_id")));
        b.msg_bool("stp", readstr(&sys("bridge/stp_state")) != "0");
    }
    if let Ok(link) = fs::read_link(sys("master")) {
        let base = link
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        b.msg_string("master", &base);
    }
    b.msg_bool("wireless", !readstr(&sys("phy80211/index")).is_empty());
    let op = readstr(&sys("operstate"));
    b.msg_bool("up", op == "up" || op == "unknown");
    let n = atoi(&readstr(&sys("mtu")));
    if n > 0 {
        b.msg_u32("mtu", n as u32);
    }
    let n = atoi(&readstr(&sys("tx_queue_len")));
    if n > 0 {
        b.msg_u32("qlen", n as u32);
    }
    // second "master" read via fopen() of the symlinked directory yields ""
    let uevent = readstr(&sys("uevent"));
    match uevent.find("DEVTYPE=") {
        Some(pos) => {
            let rest = &uevent[pos + 8..];
            let end = rest.find('\n').unwrap_or(rest.len());
            b.msg_string("devtype", &rest[..end]);
        }
        None => {
            b.msg_string("devtype", "ethernet");
        }
    }
    let mut ifa_flags: u32 = 0;
    for af in [rtnl::AF_INET, rtnl::AF_INET6] {
        let a = b.msg_open_array(if af == rtnl::AF_INET {
            "ipaddrs"
        } else {
            "ip6addrs"
        });
        for ifa in ifaddr.iter().filter(|i| i.family == af && i.name == name) {
            let t = b.msg_open_table("");
            b.msg_string("address", &rtnl::ntop(af, &ifa.addr));
            b.msg_string(
                "netmask",
                &ifa.netmask
                    .as_deref()
                    .map(|m| rtnl::ntop(af, m))
                    .unwrap_or_default(),
            );
            if let (Some(dst), true) = (&ifa.dst, ifa.flags & rtnl::IFF_POINTOPOINT != 0) {
                b.msg_string("remote", &rtnl::ntop(af, dst));
            } else if let (Some(bc), true) = (&ifa.broadcast, ifa.flags & rtnl::IFF_BROADCAST != 0)
            {
                b.msg_string("broadcast", &rtnl::ntop(af, bc));
            }
            b.msg_close(t);
            ifa_flags |= ifa.flags;
        }
        b.msg_close(a);
    }
    if let Some(ll) = ifaddr
        .iter()
        .find(|i| i.family == rtnl::AF_PACKET && i.name == name)
    {
        if ll.hatype == 1 {
            b.msg_string("mac", &rtnl::ea2str(&ll.addr));
        }
        b.msg_u32("type", ll.hatype as u32);
        b.msg_u32("ifindex", ll.ifindex as u32);
        ifa_flags |= ll.flags;
        let n = atoi(&readstr(&sys("iflink")));
        if n != ll.ifindex {
            if let Some(parent) = ifaddr
                .iter()
                .find(|i| i.family == rtnl::AF_PACKET && i.ifindex == n)
            {
                b.msg_string("parent", &parent.name);
            }
        }
    }
    let t = b.msg_open_table("stats");
    for st in [
        "rx_bytes",
        "tx_bytes",
        "tx_errors",
        "rx_errors",
        "tx_packets",
        "rx_packets",
        "multicast",
        "collisions",
        "rx_dropped",
        "tx_dropped",
    ] {
        b.msg_u64(st, strtoull10(&readstr(&sys(&format!("statistics/{st}")))));
    }
    b.msg_close(t);
    let t = b.msg_open_table("flags");
    b.msg_bool("up", ifa_flags & rtnl::IFF_UP != 0);
    b.msg_bool("broadcast", ifa_flags & rtnl::IFF_BROADCAST != 0);
    b.msg_bool("promisc", ifa_flags & rtnl::IFF_PROMISC != 0);
    b.msg_bool("loopback", ifa_flags & rtnl::IFF_LOOPBACK != 0);
    b.msg_bool("noarp", ifa_flags & rtnl::IFF_NOARP != 0);
    b.msg_bool("multicast", ifa_flags & rtnl::IFF_MULTICAST != 0);
    b.msg_bool("pointtopoint", ifa_flags & rtnl::IFF_POINTOPOINT != 0);
    b.msg_close(t);
    let t = b.msg_open_table("link");
    let p = readstr(&sys("speed"));
    if !p.is_empty() {
        b.msg_u32("speed", atoi(&p) as u32);
    }
    let p = readstr(&sys("duplex"));
    if !p.is_empty() {
        b.msg_string("duplex", &p);
    }
    b.msg_bool("carrier", atoi(&readstr(&sys("carrier"))) == 1);
    b.msg_u32("changes", atoi(&readstr(&sys("carrier_changes"))) as u32);
    b.msg_u32("up_count", atoi(&readstr(&sys("carrier_up_count"))) as u32);
    b.msg_u32(
        "down_count",
        atoi(&readstr(&sys("carrier_down_count"))) as u32,
    );
    b.msg_close(t);
    b.msg_close(o);
}

pub fn get_network_devices() -> Reply {
    let mut b = BlobBuf::new();
    if let Ok(rd) = fs::read_dir("/sys/class/net") {
        let ifaddr = rtnl::getifaddrs().unwrap_or_default();
        for e in rd.flatten() {
            let ft = e.file_type().ok();
            if ft.is_some_and(|t| t.is_dir() || t.is_file()) {
                continue;
            }
            network_device(&mut b, &e.file_name().to_string_lossy(), &ifaddr);
        }
    }
    Reply::one(0, b.into_payload())
}

// ------------------------------------------------------------ host hints

const PRIO_NL: i32 = 10;
const PRIO_ETHER: i32 = 50;
const PRIO_LEASEFILE: i32 = 100;
const PRIO_IFADDRS: i32 = 200;
#[allow(dead_code)]
const PRIO_STATIC_LEASE: i32 = 250;

#[derive(Default)]
struct Hint {
    hostname: Option<String>,
    /// (prio, addr) kept in avl order: higher prio first, then bytes
    ipaddrs: Vec<(i32, [u8; 4])>,
    ip6addrs: Vec<(i32, [u8; 16])>,
}

fn add_sorted<const N: usize>(list: &mut Vec<(i32, [u8; N])>, prio: i32, addr: [u8; N]) {
    if let Some(pos) = list.iter().position(|(_, a)| *a == addr) {
        if prio <= list[pos].0 {
            return;
        }
        list.remove(pos);
    }
    // host_hint_addr_avl_cmp: larger prio sorts first, then memcmp of the address
    let pos = list
        .iter()
        .position(|(p, a)| *p < prio || (*p == prio && *a > addr))
        .unwrap_or(list.len());
    list.insert(pos, (prio, addr));
}

type Hints = BTreeMap<String, Hint>;

fn hint_for<'a>(hints: &'a mut Hints, ea: &[u8; 6]) -> &'a mut Hint {
    hints.entry(rtnl::ea2str(ea)).or_default()
}

fn hints_nl(hints: &mut Hints) {
    let Ok(neigh) = rtnl::neighbours() else {
        return;
    };
    for n in neigh {
        if n.family != rtnl::AF_INET && n.family != rtnl::AF_INET6 {
            continue;
        }
        if n.state & (0xff & !rtnl::NUD_NOARP) == 0 {
            continue;
        }
        let (Some(mac), Some(dst)) = (n.lladdr, n.dst) else {
            continue;
        };
        let mut ea = [0u8; 6];
        for (i, v) in mac.iter().take(6).enumerate() {
            ea[i] = *v;
        }
        let h = hint_for(hints, &ea);
        if n.family == rtnl::AF_INET {
            if dst.len() >= 4 {
                add_sorted(&mut h.ipaddrs, PRIO_NL, dst[..4].try_into().unwrap());
            }
        } else if dst.len() >= 16 {
            add_sorted(&mut h.ip6addrs, PRIO_NL, dst[..16].try_into().unwrap());
        }
    }
}

fn hints_ether(hints: &mut Hints) {
    let Ok(text) = crate::util::read_lossy("/etc/ethers") else {
        return;
    };
    for line in text.split_inclusive('\n') {
        let mut t = strtok(line, " \t\n");
        let Some(ea) = t.next().and_then(ether_aton) else {
            continue;
        };
        let h = hint_for(hints, &ea);
        let Some(p) = t.next() else { continue };
        if let Ok(v4) = p.parse::<Ipv4Addr>() {
            add_sorted(&mut h.ipaddrs, PRIO_ETHER, v4.octets());
        } else if !p.is_empty() && h.hostname.is_none() {
            h.hostname = Some(p.to_owned());
        }
    }
}

fn hints_uci(hints: &mut Hints) {
    let mut ctx = owrt_uci::Context::new();
    if let Ok(pidx) = owrt_uci::file::load(&mut ctx, "dhcp") {
        for s in ctx.root[pidx].sections.iter().filter(|s| s.ty == "host") {
            // luci-rpc.c reads `ip` only when the option is NOT a string
            // (`ptr.o->type != UCI_TYPE_STRING`), so a static lease never
            // contributes its address; the name still does.
            let name = s
                .find_option("name")
                .and_then(|i| match &s.options[i].value {
                    owrt_uci::OptionValue::Str(v) => Some(String::from_utf8_lossy(v).into_owned()),
                    _ => None,
                });
            let Some(mi) = s.find_option("mac") else {
                continue;
            };
            let macs: Vec<String> = match &s.options[mi].value {
                owrt_uci::OptionValue::Str(v) => {
                    let text = String::from_utf8_lossy(v);
                    strtok(&text, " \t").map(str::to_owned).collect()
                }
                owrt_uci::OptionValue::List(items) => items
                    .iter()
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .collect(),
            };
            for m in macs {
                let Some(ea) = ether_aton(&m) else { continue };
                let h = hint_for(hints, &ea);
                if let Some(n) = &name {
                    if h.hostname.is_none() {
                        h.hostname = Some(n.clone());
                    }
                }
            }
        }
    }
    for lease in leases() {
        if ea_empty(&lease.mac) {
            continue;
        }
        let h = hint_for(hints, &lease.mac);
        for a in &lease.addrs {
            if lease.v6 {
                add_sorted(&mut h.ip6addrs, PRIO_LEASEFILE, *a);
            } else {
                add_sorted(&mut h.ipaddrs, PRIO_LEASEFILE, a[..4].try_into().unwrap());
            }
        }
        if let Some(n) = &lease.hostname {
            if h.hostname.is_none() {
                h.hostname = Some(n.clone());
            }
        }
    }
}

fn hints_ifaddrs(hints: &mut Hints) {
    let Ok(ifaddr) = rtnl::getifaddrs() else {
        return;
    };
    // per device name (avl strcmp order): mac, last IPv4, last IPv6 seen
    #[allow(clippy::type_complexity)]
    let mut devices: BTreeMap<String, ([u8; 6], [u8; 4], [u8; 16])> = BTreeMap::new();
    for ifa in &ifaddr {
        let d = devices
            .entry(ifa.name.clone())
            .or_insert(([0; 6], [0; 4], [0; 16]));
        match ifa.family {
            rtnl::AF_PACKET => {
                if ifa.addr.len() == 6 {
                    d.0.copy_from_slice(&ifa.addr);
                }
            }
            rtnl::AF_INET6 => {
                if ifa.addr.len() == 16 {
                    d.2.copy_from_slice(&ifa.addr);
                }
            }
            rtnl::AF_INET if ifa.addr.len() == 4 => {
                d.1.copy_from_slice(&ifa.addr);
            }
            _ => {}
        }
    }
    for (_, (ea, in4, in6)) in devices {
        if !ea_empty(&ea) && (in6 != [0; 16] || in4 != [0; 4]) {
            let h = hint_for(hints, &ea);
            if in4 != [0; 4] {
                add_sorted(&mut h.ipaddrs, PRIO_IFADDRS, in4);
            }
            if in6 != [0; 16] {
                add_sorted(&mut h.ip6addrs, PRIO_IFADDRS, in6);
            }
        }
    }
}

fn is_linklocal(a: &[u8; 16]) -> bool {
    a[0] == 0xfe && (a[1] & 0xc0) == 0x80
}
fn is_ula(a: &[u8; 16]) -> bool {
    (a[0] & 0xfe) == 0xfc
}

fn hints_rrdns(hints: &mut Hints) {
    let mut addrs = Vec::new();
    for h in hints.values() {
        for (_, a) in &h.ipaddrs {
            if *a != [0; 4] {
                addrs.push(Ipv4Addr::from(*a).to_string());
            }
        }
        for (_, a) in &h.ip6addrs {
            if *a != [0; 16] && !is_linklocal(a) && !is_ula(a) {
                addrs.push(Ipv6Addr::from(*a).to_string());
            }
        }
    }
    if addrs.is_empty() {
        return;
    }
    let n = addrs.len() as i32;
    let Some(pairs) = rrdns::resolve(&addrs, 250, n) else {
        return;
    };
    for (name, value) in pairs {
        if let Ok(v6) = name.parse::<Ipv6Addr>() {
            let o = v6.octets();
            for h in hints.values_mut() {
                if h.ip6addrs.iter().any(|(_, a)| *a == o) && h.hostname.is_none() {
                    h.hostname = Some(value.clone());
                }
            }
        } else if let Ok(v4) = name.parse::<Ipv4Addr>() {
            let o = v4.octets();
            for h in hints.values_mut() {
                if h.ipaddrs.iter().any(|(_, a)| *a == o) {
                    h.hostname = Some(value.clone());
                }
            }
        }
    }
}

pub fn get_host_hints() -> Reply {
    let mut hints: Hints = BTreeMap::new();
    hints_nl(&mut hints);
    hints_uci(&mut hints);
    hints_ether(&mut hints);
    hints_ifaddrs(&mut hints);
    hints_rrdns(&mut hints);
    let mut b = BlobBuf::new();
    for (mac, h) in &hints {
        let o = b.msg_open_table(mac);
        let a = b.msg_open_array("ipaddrs");
        for (_, addr) in &h.ipaddrs {
            if *addr != [0; 4] {
                b.msg_string("", &Ipv4Addr::from(*addr).to_string());
            }
        }
        b.msg_close(a);
        let a = b.msg_open_array("ip6addrs");
        for (_, addr) in &h.ip6addrs {
            if *addr != [0; 16] {
                b.msg_string("", &Ipv6Addr::from(*addr).to_string());
            }
        }
        b.msg_close(a);
        if let Some(n) = &h.hostname {
            b.msg_string("name", n);
        }
        b.msg_close(o);
    }
    Reply::one(0, b.into_payload())
}

// ------------------------------------------------------------ leases / duid / board

pub fn get_duid_hints() -> Reply {
    let mut seen = std::collections::BTreeSet::new();
    let mut b = BlobBuf::new();
    for lease in leases() {
        if !lease.v6 {
            continue;
        }
        let Some(duid) = &lease.duid else { continue };
        let key = match &lease.iaid {
            Some(iaid) => format!("{duid}%{iaid}"),
            None => duid.clone(),
        };
        if !seen.insert(key.clone()) {
            continue;
        }
        let o = b.msg_open_table(&key);
        if let Some(i) = &lease.iface {
            b.msg_string("interface", i);
        }
        b.msg_string("duid", duid);
        if let Some(i) = &lease.iaid {
            b.msg_string("iaid", i);
        }
        if let Some(h) = &lease.hostname {
            b.msg_string("hostname", h);
        }
        if !ea_empty(&lease.mac) {
            b.msg_string("macaddr", &rtnl::ea2str(&lease.mac));
        }
        let a = b.msg_open_array("ip6addrs");
        for addr in &lease.addrs {
            b.msg_string("", &addr_str(true, addr));
        }
        b.msg_close(a);
        b.msg_close(o);
    }
    Reply::one(0, b.into_payload())
}

pub fn get_board_json() -> Reply {
    let Ok(text) = crate::util::read_lossy("/etc/board.json") else {
        return Reply::empty(status::UNKNOWN_ERROR);
    };
    match owrt_ubus::json::parse(&text) {
        Ok(Json::Object(o)) => {
            Reply::one(0, owrt_ubus::convert::object_to_payload(&Json::Object(o)))
        }
        _ => Reply::empty(status::UNKNOWN_ERROR),
    }
}

pub fn get_dhcp_leases(raw: &[u8]) -> Reply {
    let family = arg(raw, "family", MsgType::Int32)
        .and_then(|f| f.as_u32())
        .unwrap_or(0);
    let fams: Vec<bool> = match family {
        0 => vec![false, true],
        4 => vec![false],
        6 => vec![true],
        _ => return Reply::empty(status::INVALID_ARGUMENT),
    };
    let mut b = BlobBuf::new();
    for v6 in fams {
        let a = b.msg_open_array(if v6 { "dhcp6_leases" } else { "dhcp_leases" });
        for lease in leases() {
            if lease.v6 != v6 {
                continue;
            }
            let o = b.msg_open_table("");
            if lease.expire == -1 {
                b.msg_bool("expires", false);
            } else {
                b.msg_u32("expires", lease.expire as u32);
            }
            if let Some(i) = &lease.iface {
                b.msg_string("interface", i);
            }
            if let Some(h) = &lease.hostname {
                b.msg_string("hostname", h);
            }
            if !ea_empty(&lease.mac) {
                b.msg_string("macaddr", &rtnl::ea2str(&lease.mac));
            }
            if let Some(d) = &lease.duid {
                b.msg_string("duid", d);
            }
            if let Some(i) = &lease.iaid {
                b.msg_string("iaid", i);
            }
            let first = lease.addrs.first().copied().unwrap_or([0; 16]);
            b.msg_string(if v6 { "ip6addr" } else { "ipaddr" }, &addr_str(v6, &first));
            if v6 {
                let a2 = b.msg_open_array("ip6addrs");
                for addr in &lease.addrs {
                    b.msg_string("", &format!("{}/{}", addr_str(true, addr), lease.mask));
                }
                b.msg_close(a2);
            }
            b.msg_close(o);
        }
        b.msg_close(a);
    }
    Reply::one(0, b.into_payload())
}

// ------------------------------------------------------------ wireless

/// rpc_luci_get_wireless_devices(_cb): `network.wireless status`, every radio
/// table forwarded field by field with an `iwinfo` table per interface and a
/// phy-only one per radio. Only the first DATA reply is processed (the C
/// invoke context clears its callback after one message); a failed lookup is
/// NOT_FOUND, a missing/late reply an empty table.
pub fn get_wireless_devices(socket: Option<&str>) -> Reply {
    let Ok(mut conn) = Connection::connect(socket) else {
        return Reply::empty(status::NOT_FOUND);
    };
    let Ok(id) = conn.lookup_id("network.wireless", 2000) else {
        return Reply::empty(status::NOT_FOUND);
    };
    let msg: Vec<u8> = match conn.invoke_status(id, "status", &[], 2000) {
        Ok(reply) => reply
            .data
            .first()
            .map(|payload| {
                blob::iter(payload)
                    .filter(|a| a.id == owrt_ubus::attr::DATA)
                    .map(|a| a.payload.to_vec())
                    .next()
                    .unwrap_or_default()
            })
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let mut b = BlobBuf::new();
    for wifi in blob::fields(&msg) {
        if wifi.ty != MsgType::Table as u32 || wifi.name.is_empty() {
            continue;
        }
        let o = b.msg_open_table(wifi.name);
        let mut first_ifname: Option<String> = None;
        for cur in wifi.children() {
            if cur.name == "iwinfo" {
                continue;
            } else if cur.name == "interfaces" {
                if cur.ty != MsgType::Array as u32 {
                    continue;
                }
                let a = b.msg_open_array("interfaces");
                for iface in cur.children() {
                    if iface.ty != MsgType::Table as u32 {
                        continue;
                    }
                    let o2 = b.msg_open_table("");
                    let mut name: Option<String> = None;
                    for cur2 in iface.children() {
                        if cur2.name == "ifname" {
                            name = cur2.as_str().map(str::to_owned);
                        } else if cur2.name == "iwinfo" {
                            continue;
                        }
                        b.msg_field(cur2.ty, cur2.name, cur2.data);
                    }
                    if let Some(n) = &name {
                        if crate::iwinfoobj::luci_iwinfo(&mut b, n, false) && first_ifname.is_none()
                        {
                            first_ifname = Some(n.clone());
                        }
                    }
                    b.msg_close(o2);
                }
                b.msg_close(a);
            } else {
                b.msg_field(cur.ty, cur.name, cur.data);
            }
        }
        crate::iwinfoobj::luci_iwinfo(&mut b, first_ifname.as_deref().unwrap_or(wifi.name), true);
        b.msg_close(o);
    }
    Reply::one(0, b.into_payload())
}

// ------------------------------------------------------------ dispatch

pub enum Outcome {
    Now(Request, Reply),
    Deferred,
}

/// getHostHints (rrdns round trip) and getWirelessDevices (ubus round trip)
/// are deferred in C; they run on worker threads here.
pub fn call(ctx: &Ctx, req: Request, deferrer: &Deferrer) -> Outcome {
    match req.method.as_str() {
        "getNetworkDevices" => Outcome::Now(req, get_network_devices()),
        "getHostHints" => match deferrer.defer(req, get_host_hints) {
            None => Outcome::Deferred,
            Some((req, reply)) => Outcome::Now(req, reply),
        },
        "getDUIDHints" => Outcome::Now(req, get_duid_hints()),
        "getBoardJSON" => Outcome::Now(req, get_board_json()),
        "getDHCPLeases" => {
            let r = get_dhcp_leases(&req.data);
            Outcome::Now(req, r)
        }
        "getWirelessDevices" => {
            let socket = ctx.socket.clone();
            match deferrer.defer(req, move || get_wireless_devices(socket.as_deref())) {
                None => Outcome::Deferred,
                Some((req, reply)) => Outcome::Now(req, reply),
            }
        }
        _ => Outcome::Now(req, Reply::empty(status::METHOD_NOT_FOUND)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readstr_preserves_limits_whitespace_and_lossy_bytes() {
        let root = std::env::temp_dir().join(format!("rpcd-readstr-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("value");
        let name = path.to_str().unwrap();
        assert_eq!(readstr(name), "");
        assert_eq!(readstr(root.to_str().unwrap()), "");
        for (bytes, expected) in [
            (b"".as_slice(), ""),
            (b" \t\r\n", ""),
            (
                b" leading and internal\nspace \t\r\n",
                " leading and internal\nspace",
            ),
            (b"raw-\xff\n", "raw-\u{fffd}"),
            (b"nul\0byte\n", "nul\0byte"),
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(readstr(name), expected);
        }
        let mut boundary = vec![b'x'; 126];
        boundary.extend_from_slice(b"\xe4\xb8\xad");
        fs::write(&path, boundary).unwrap();
        assert_eq!(readstr(name), format!("{}\u{fffd}", "x".repeat(126)));
        fs::write(&path, vec![b'y'; 256]).unwrap();
        assert_eq!(readstr(name), "y".repeat(127));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mac_and_duid() {
        assert_eq!(ether_aton("0:1:2:a:b:ff"), Some([0, 1, 2, 10, 11, 255]));
        assert_eq!(
            ether_aton("00:11:22:33:44:55"),
            Some([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert!(ether_aton("00:11:22:33:44").is_none());
        assert!(ether_aton("00:11:22:33:44:555").is_none());
        assert_eq!(
            duid2ea("000100011234567800112233aabb"),
            Some([0, 0x11, 0x22, 0x33, 0xaa, 0xbb])
        );
        assert_eq!(
            duid2ea("00030001aabbccddeeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            duid2ea("aabbccddeeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert!(duid2ea("zz").is_none());
    }

    #[test]
    fn prio_order() {
        let mut v: Vec<(i32, [u8; 4])> = Vec::new();
        add_sorted(&mut v, 10, [10, 0, 0, 2]);
        add_sorted(&mut v, 100, [10, 0, 0, 9]);
        add_sorted(&mut v, 10, [10, 0, 0, 1]);
        add_sorted(&mut v, 200, [10, 0, 0, 2]); // upgrade
        assert_eq!(
            v,
            vec![
                (200, [10, 0, 0, 2]),
                (100, [10, 0, 0, 9]),
                (10, [10, 0, 0, 1])
            ]
        );
    }
}
