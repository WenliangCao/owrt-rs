//! Drive the sys layer against a live kernel, so the encodings can be compared
//! with the same operations performed by iproute2 in an identical namespace.
//!
//! Usage: sysprobe <step> [args...]
//!
//! Each step is one operation, so the harness can interleave them with reads.

use owrt_netifd::{ethtool, sys};
use std::net::IpAddr;

fn arg(n: usize) -> String {
    std::env::args().nth(n).unwrap_or_else(|| {
        eprintln!("missing argument {n}");
        std::process::exit(2);
    })
}

fn main() {
    let step = arg(1);
    let mut s = sys::System::open().expect("netlink");
    let r = match step.as_str() {
        // addbr <name>
        "addbr" => s.bridge_addbr(&arg(2), &sys::BridgeConfig::default()),
        // delbr <name>
        "delbr" => s.bridge_delbr(&arg(2)),
        // setmaster <dev> <bridge|->
        "setmaster" => {
            let dev = s.if_index(&arg(2)).expect("index");
            let m = arg(3);
            let master = if m == "-" {
                0
            } else {
                s.if_index(&m).expect("index")
            };
            s.bridge_setmaster(dev, master)
        }
        // up <dev> / down <dev>
        "up" | "down" => {
            let dev = s.if_index(&arg(2)).expect("index");
            s.set_link_up(dev, step == "up")
        }
        // mtu <dev> <n>
        "mtu" => {
            let dev = s.if_index(&arg(2)).expect("index");
            s.set_mtu(dev, arg(3).parse().expect("mtu"))
        }
        // mac <dev> <aa:bb:...>
        "mac" => {
            let dev = s.if_index(&arg(2)).expect("index");
            let mut mac = [0u8; 6];
            for (i, p) in arg(3).split(':').enumerate().take(6) {
                mac[i] = u8::from_str_radix(p, 16).expect("mac byte");
            }
            s.set_mac(dev, &mac)
        }
        // txqlen <dev> <n>
        "txqlen" => {
            let dev = s.if_index(&arg(2)).expect("index");
            s.set_txqueuelen(dev, arg(3).parse().expect("txqlen"))
        }
        // addr <dev> <ip/mask> [pref] [valid] [offlink]
        "addr" | "deladdr" => {
            let dev = s.if_index(&arg(2)).expect("index");
            let spec = arg(3);
            let (ip, mask) = spec.split_once('/').expect("ip/mask");
            let mut a = sys::Address::new(
                ip.parse::<IpAddr>().expect("ip"),
                mask.parse().expect("mask"),
            );
            a.preferred = std::env::args().nth(4).and_then(|v| v.parse().ok());
            a.valid = std::env::args().nth(5).and_then(|v| v.parse().ok());
            a.offlink = std::env::args().nth(6).as_deref() == Some("offlink");
            if step == "addr" {
                s.add_address(dev, &a)
            } else {
                s.del_address(dev, &a)
            }
        }
        // route <dev> <target/mask> <gw|-> [metric] [table]
        "route" | "delroute" => {
            let dev = s.if_index(&arg(2)).expect("index");
            let spec = arg(3);
            let (t, m) = spec.split_once('/').expect("target/mask");
            let target: IpAddr = t.parse().expect("target");
            let gws = arg(4);
            let nexthop: IpAddr = if gws == "-" {
                if target.is_ipv4() {
                    "0.0.0.0".parse().unwrap()
                } else {
                    "::".parse().unwrap()
                }
            } else {
                gws.parse().expect("gw")
            };
            let mut r = sys::Route {
                target,
                mask: m.parse().expect("mask"),
                source: None,
                sourcemask: 0,
                nexthop,
                metric: std::env::args()
                    .nth(5)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                table: std::env::args()
                    .nth(6)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(sys::RT_TABLE_MAIN),
                mtu: None,
                onlink: false,
                proto: None,
                ty: None,
                nodev: false,
            };
            // iproute2 defaults to proto boot (3) for a manually added route;
            // netifd always writes RTPROT_STATIC, so the harness compares with
            // `ip route add ... proto static`.
            r.proto = Some(sys::RTPROT_STATIC);
            if step == "route" {
                s.add_route(dev, &r)
            } else {
                s.del_route(dev, &r)
            }
        }
        // index <dev>: 0 when absent
        "index" => {
            println!("{}", s.if_index(&arg(2)).expect("index"));
            Ok(())
        }
        // linkinfo <dev>: the ethtool half of `network.device status`
        "linkinfo" => {
            let e = ethtool::Ethtool::open().expect("ioctl socket");
            match e.link_info(&arg(2)) {
                Ok(i) => {
                    println!(
                        "speed={:?} autoneg={} pause_autoneg={}",
                        i.speed, i.autoneg, i.pause_autoneg
                    );
                    println!("supported={}", i.link_supported.join(","));
                    println!("advertising={}", i.link_advertising.join(","));
                    println!("partner={}", i.link_partner_advertising.join(","));
                    println!("pause_supported={}", i.pause_supported.join(","));
                    println!("pause_selected={:?}", i.pause_selected);
                }
                Err(e) => println!("linkinfo error: {e}"),
            }
            println!("devtype={:?}", ethtool::devtype(&arg(2)));
            println!(
                "hw-tc-offload={}",
                e.feature_value(&arg(2), "hw-tc-offload")
            );
            for (k, v) in ethtool::statistics(&arg(2)) {
                println!("stat {k}={v}");
            }
            Ok(())
        }
        other => {
            eprintln!("unknown step: {other}");
            std::process::exit(2);
        }
    };
    match r {
        Ok(()) => println!("ok"),
        Err(e) => {
            println!("error: {e}");
            std::process::exit(1);
        }
    }
}
