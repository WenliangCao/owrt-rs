//! Phase costs of the actual service projection and system.info builder.
//! Does not supervise processes or estimate full daemon latency.
#![allow(dead_code)]
macro_rules! log {
    ($priority:expr, $($arg:tt)*) => { crate::sys::ulog($priority, &format!($($arg)*)) };
}
macro_rules! debug {
    ($level:expr, $($arg:tt)*) => {
        if crate::sys::debug_level() >= $level {
            crate::sys::ulog(crate::sys::LOG_NOTICE, &format!($($arg)*));
        }
    };
}
#[path = "../src/instance.rs"]
mod instance;
#[path = "../src/dispatch.rs"]
mod dispatch;
#[path = "../src/proc.rs"]
mod proc;
#[path = "../src/service.rs"]
mod service;
#[path = "../src/sys.rs"]
mod sys;
#[path = "../src/sysobj.rs"]
mod sysobj;
#[path = "../../rpcd/examples/profile_support/mod.rs"]
mod profile_support;

use owrt_ubus::{BlobBuf, MsgType};
use std::collections::BTreeMap;
use std::hint::black_box;

fn main() {
    let n = std::env::args().nth(1).unwrap_or_else(|| "20000".into()).parse().unwrap();
    let filter = std::env::args().nth(2).unwrap_or_default();
    println!("stage,iterations,ns_per_op,allocations,reallocations,allocated_bytes");
    for count in [1, 32, 128] {
        let mut services = BTreeMap::new();
        for i in 0..count {
            let name = format!("r84fixture{i}");
            let mut service = service::Service::new(&name);
            service.data.insert("index".into(), (MsgType::Int32 as u32, (i as u32).to_be_bytes().to_vec()));
            services.insert(name, service);
        }
        let mut check = BlobBuf::new();
        for service in services.values() { service.dump(&mut check, false); }
        assert_eq!(owrt_ubus::blob::fields(check.payload()).count(), count);
        let mut b = BlobBuf::new();
        profile_support::measure(&format!("service_list_{count}"), n, &filter, || {
            service::dump_list(&services, &[], &mut b);
            black_box(b.payload());
            b.reset_bounded(16 * 1024);
        });
    }
    let mut b = BlobBuf::new();
    profile_support::measure("system_info", n, &filter, || {
        assert!(sysobj::build_info(&mut b, &mut sysobj::Meminfo::open()));
        black_box(b.payload());
        b.reset_bounded(16 * 1024);
    });
    // Cost of the unchanged dynamic-object scan that fixed service/system
    // targets used to traverse. This is an avoided substep, not total routing.
    for count in [8, 32, 128] {
        let mut d = dispatch::Dispatch::default();
        for i in 0..count { d.objects.insert(format!("subsystem-{i}"), i); }
        profile_support::measure(&format!("hotplug_object_miss_{count}"), n, &filter, || {
            black_box(black_box(&d).subsystem_of(black_box(u32::MAX)));
        });
    }
}
