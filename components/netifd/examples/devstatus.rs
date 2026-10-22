//! Reproduce `network.device status` from the kernel alone, so it can be
//! compared with what the C netifd reports for the same devices in the same
//! namespace.
//!
//! Usage: devstatus <c-status.json>
//!
//! `external`, `present`, `type`, `up`, `carrier` and `auth_status` are
//! netifd's own bookkeeping rather than kernel state, so they are taken from
//! the C output; everything else — the settings block, the ethtool block and
//! the statistics — is derived here and is what the comparison is about.

use owrt_netifd::{device, ethtool, netlink, sys};
use owrt_ubus::blob::BlobBuf;
use owrt_ubus::json::Json;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: devstatus <c-status.json>");
    let text = std::fs::read_to_string(&path).expect("read");
    let Ok(Json::Object(devs)) = owrt_ubus::json::parse(&text) else {
        eprintln!("not a status object");
        std::process::exit(2);
    };

    let e = ethtool::Ethtool::open().expect("ioctl socket");
    let ifc = sys::IfIoctl::open().expect("ioctl socket");

    let mut b = BlobBuf::new();
    for (name, val) in &devs {
        let get_bool = |k: &str| matches!(val.get(k), Some(Json::Bool(true)));
        let mut d = device::Device::new(
            name,
            match val.get("type") {
                Some(Json::Str(s)) => s,
                _ => "Network device",
            },
        );
        d.external = get_bool("external");
        d.present = get_bool("present");
        d.active = get_bool("up");
        d.link_active = get_bool("carrier");
        d.auth_status = get_bool("auth_status");
        if d.present {
            d.orig_settings = device::read_settings(name, &e, &ifc);
            // the DSA conduit is netlink state, read the same way the C does
            if let Some(idx) = dsa_conduit(name) {
                d.orig_settings.master_ifindex = idx;
                d.orig_settings.flags |= device::opt::MASTER;
            }
        }
        if let Some(Json::Array(ms)) = val.get("bridge-members") {
            d.bridge = Some(device::BridgeState {
                members: ms
                    .iter()
                    .filter_map(|m| match m {
                        Json::Str(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                config: sys::BridgeConfig::default(),
                stp_proto: None,
            });
        }
        let t = b.msg_open_table(name);
        d.dump_status(&mut b, Some(&e), None);
        b.msg_close(t);
    }
    println!(
        "{}",
        owrt_ubus::convert::fields_to_json(b.payload())
            .unwrap()
            .to_compact()
    );
}

/// `system_if_get_master_ifindex`: `IFLA_LINKINFO/IFLA_INFO_KIND == "dsa"` then
/// `IFLA_INFO_DATA/IFLA_DSA_MASTER`. Only DSA user ports have it.
fn dsa_conduit(ifname: &str) -> Option<u32> {
    const IFLA_DSA_MASTER: u16 = 1;
    let mut nl = netlink::Netlink::open(0).ok()?;
    let hdr = sys::ifinfomsg(sys::AF_UNSPEC, 0, 0, 0);
    let mut a = netlink::Attrs::new();
    a.str0(sys::IFLA_IFNAME, ifname);
    let msg = nl.dump_one(sys::RTM_GETLINK, &hdr, a.as_bytes()).ok()??;
    let attrs = msg.attrs(16);
    let li = netlink::attr(&attrs, sys::IFLA_LINKINFO)
        .or_else(|| netlink::attr(&attrs, sys::IFLA_LINKINFO | netlink::NLA_F_NESTED))?;
    let inner = netlink::parse_attrs(li);
    if netlink::attr_str(&inner, sys::IFLA_INFO_KIND)? != "dsa" {
        return None;
    }
    let data = netlink::attr(&inner, sys::IFLA_INFO_DATA)
        .or_else(|| netlink::attr(&inner, sys::IFLA_INFO_DATA | netlink::NLA_F_NESTED))?;
    netlink::attr_u32(&netlink::parse_attrs(data), IFLA_DSA_MASTER)
}
