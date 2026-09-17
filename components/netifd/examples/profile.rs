//! Costs of the actual status projection and kernel counter readers.
//! No event loop or ubus transport is included. The interface-list fixture
//! compares explicit clones with borrowing, but excludes global PD reconstruction.
#![allow(dead_code)]
#[path = "../src/clock.rs"]
mod clock;
#[path = "../src/config.rs"]
mod config;
#[path = "../src/device.rs"]
mod device;
#[path = "../src/ethtool.rs"]
mod ethtool;
#[path = "../src/ethtool_modes.rs"]
mod ethtool_modes;
#[path = "../src/interface.rs"]
mod interface;
#[path = "../src/ip.rs"]
mod ip;
#[path = "../src/logging.rs"]
mod logging;
#[path = "../src/netdev_types.rs"]
mod netdev_types;
#[path = "../src/netlink.rs"]
mod netlink;
#[path = "../src/rt.rs"]
mod rt;
#[path = "../src/sys.rs"]
mod sys;
#[path = "../src/ubus.rs"]
mod ubus;
#[path = "../../rpcd/examples/profile_support/mod.rs"]
mod profile_support;

use owrt_ubus::blob::{self, BlobBuf};
use std::hint::black_box;

fn interface(index: usize) -> interface::Interface {
    let mut i = interface::Interface::new(&format!("interface{index:03}"));
    i.state = interface::State::Up;
    i.available = true;
    i.autostart = true;
    i.proto = Some("static".into());
    i.device = Some("br-profile".into());
    i.l3_device = i.device.clone();
    i.uptime = 60;
    i.started_at = Some(60);
    i.proto_ip.addresses.push(interface::Address::new("192.0.2.1".parse().unwrap(), 24));
    i.proto_ip.addresses.push(interface::Address::new("2001:db8::1".parse().unwrap(), 64));
    i
}

fn main() {
    let n = std::env::args().nth(1).unwrap_or_else(|| "1000".into()).parse().unwrap();
    let filter = std::env::args().nth(2).unwrap_or_default();
    println!("stage,iterations,ns_per_op,allocations,reallocations,allocated_bytes");
    for count in [2, 32, 128] {
        let interfaces: Vec<_> = (0..count).map(interface).collect();
        let times: Vec<_> = interfaces.iter().map(|i| (i.name.clone(), 60u64)).collect();
        let objects = ubus::Objects {
            per_interface: interfaces.iter().enumerate().map(|(n, i)| (i.name.clone(), 100 + n as u32)).collect(),
            ..Default::default()
        };
        let name = interfaces.last().unwrap().name.as_str();
        profile_support::measure(&format!("lookup_object_{count}"), n, &filter, || {
            black_box(objects.route(black_box(100 + count as u32 - 1)));
        });
        profile_support::measure(&format!("lookup_interface_linear_{count}"), n, &filter, || {
            black_box(black_box(&interfaces).iter().find(|i| i.name == black_box(name)));
        });
        profile_support::measure(&format!("lookup_interface_partition_{count}"), n, &filter, || {
            let at = black_box(&interfaces).partition_point(|i| i.name.as_str() < black_box(name));
            black_box(interfaces.get(at).filter(|i| i.name == name));
        });
        profile_support::measure(&format!("lookup_uptime_linear_{count}"), n, &filter, || {
            black_box(black_box(&times).iter().find(|(key, _)| key == black_box(name))
                .map(|(_, time)| clock::now().saturating_sub(*time) as u32).unwrap_or(0));
        });
        profile_support::measure(&format!("lookup_interface_current_{count}"), n, &filter, || {
            black_box(interface::find_by_name(black_box(&interfaces), black_box(name)));
        });
        profile_support::measure(&format!("lookup_uptime_current_{count}"), n, &filter, || {
            black_box(black_box(interfaces.last().unwrap()).current_uptime());
        });
    }
    let iface = interface(0);
    profile_support::measure("interface_clone", n, &filter, || {
        black_box(black_box(&iface).clone());
    });
    profile_support::measure("interface_status_static", n, &filter, || {
        let mut b = BlobBuf::with_capacity(1024);
        iface.dump_status(&mut b);
        black_box(b.payload());
    });
    for count in [2, 32, 128] {
        let interfaces: Vec<_> = (0..count).map(interface).collect();
        profile_support::measure(&format!("interface_dump_snapshots_{count}"), n, &filter, || {
            let mut b = BlobBuf::with_capacity(1024);
            let arr = b.msg_open_array("interface");
            for i in &interfaces {
                let snapshot = i.clone();
                let table = b.msg_open_table("");
                b.msg_string("interface", &snapshot.name);
                snapshot.dump_status(&mut b);
                b.msg_close(table);
            }
            b.msg_close(arr);
            black_box(b.payload());
        });
        profile_support::measure(&format!("interface_dump_borrowed_{count}"), n, &filter, || {
            let mut b = BlobBuf::with_capacity(1024);
            let arr = b.msg_open_array("interface");
            for i in &interfaces {
                let table = b.msg_open_table("");
                b.msg_string("interface", &i.name);
                i.dump_status_with(&mut b, i.uptime, &i.proto_ip.prefixes);
                b.msg_close(table);
            }
            b.msg_close(arr);
            black_box(b.payload());
        });
    }
    let ethtool = ethtool::Ethtool::open().unwrap();
    let ioctl = sys::IfIoctl::open().unwrap();
    for present in [false, true] {
        let mut d = device::Device::new("lo", "Network device");
        d.present = present;
        d.active = present;
        d.link_active = present;
        if present {
            d.orig_settings = device::read_settings("lo", &ethtool, &ioctl);
            assert_eq!(ethtool::statistics("lo").len(), ethtool::STAT_COUNTERS.len());
        }
        let label = if present { "device_status_lo" } else { "device_status_absent" };
        profile_support::measure(label, n, &filter, || {
            let mut b = BlobBuf::with_capacity(1024);
            d.dump_status(&mut b, Some(&ethtool), None);
            black_box(b.payload());
        });
        let mut b = BlobBuf::with_capacity(1024);
        d.dump_status(&mut b, Some(&ethtool), None);
        assert!(blob::fields(b.payload()).any(|f| f.name == "present"));
    }
    profile_support::measure("statistics_lo", n, &filter, || {
        black_box(ethtool::statistics(black_box("lo")));
    });
    profile_support::measure("one_sysfs_counter", n, &filter, || {
        black_box(ethtool::dev_sysfs("lo", "statistics/rx_bytes").unwrap());
    });
}
