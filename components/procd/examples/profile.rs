//! Phase costs of the actual service projection and system.info builder.
//! Does not supervise processes or estimate full daemon latency.
// Production modules are tested through the daemon root, where the dispatch
// recovery tests can access its supervisor. Do not compile those tests again
// under this benchmark-only root.
#![cfg(not(test))]
#![allow(dead_code)]
macro_rules! log {
    ($priority:expr, $($arg:tt)*) => { crate::sys::ulog($priority, &format!($($arg)*)) };
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

/// Encoding-only fixture: the process state is synthetic; no child is spawned.
/// The daemon benchmark uses actual supervised instances separately.
fn fielded_services(count: usize) -> BTreeMap<String, service::Service> {
    let mut services = BTreeMap::new();
    for i in 0..count {
        let name = format!("r84fixture{i}");
        let mut service = service::Service::new(&name);
        service.data.insert("index".into(), (MsgType::Int32 as u32, (i as u32).to_be_bytes().to_vec()));
        let mut inst = instance::Instance::new("main");
        inst.valid = true;
        inst.state = instance::Run::Running;
        inst.pid = 1000 + i as i32;
        inst.command = vec!["/bin/sh".into(), "-c".into(), "exec sleep 600".into()];
        inst.env.insert("MODE".into(), "fixture".into());
        inst.env.insert("CONTROL_SOCKET".into(), "/run/fixture/control.sock".into());
        inst.data.insert("enabled".into(), (MsgType::Int8 as u32, vec![1]));
        inst.data.insert("label".into(), (MsgType::String as u32, b"supervised fixture\0".to_vec()));
        inst.limits.insert("core".into(), "0".into());
        inst.limits.insert("nofile".into(), "1024 1024".into());
        inst.netdev.push(("lo".into(), 1));
        inst.reload_signal = 1;
        inst.respawn = Some(instance::Respawn { threshold: 3600, timeout: 5, retry: 5 });
        inst.respawn_active = true;
        inst.no_new_privs = true;
        inst.user = Some("nobody".into());
        inst.group = Some("nogroup".into());
        inst.pidfile = Some(format!("/run/{name}.pid"));
        inst.watchdog_mode = 1;
        inst.watchdog_freq = 30;
        let mut trigger = BlobBuf::new();
        let rule = trigger.msg_open_array("");
        trigger.msg_string("", "fixture.*");
        let action = trigger.msg_open_array("");
        trigger.msg_string("", "run_script");
        trigger.msg_string("", "/bin/true");
        trigger.msg_close(action);
        trigger.msg_u32("", 1000);
        trigger.msg_close(rule);
        inst.triggers = Some(trigger.payload().to_vec());
        service.trigger = Some(trigger.into_payload());
        for kind in ["first", "second"] {
            service.validate.push(service::Validator {
                package: "fixture".into(), kind: kind.into(), seq: 0,
                rules: BTreeMap::from([("enabled".into(), "bool".into()), ("port".into(), "port".into())]),
            });
        }
        service.instances.insert(inst.name.clone(), inst);
        services.insert(name, service);
    }
    services
}

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
        eprintln!("fixture=service_list_{count} payload_bytes={}", check.payload().len());
        let mut b = BlobBuf::new();
        profile_support::measure(&format!("service_list_{count}"), n, &filter, || {
            service::dump_list(&services, &[], &mut b);
            black_box(b.payload());
            b.reset_bounded(16 * 1024);
        });
    }
    for count in [32, 128] {
        let services = fielded_services(count);
        for (suffix, named, verbose) in [("", false, false), ("_named", true, false), ("_verbose", false, true)] {
            let stage = format!("service_list_fielded_{count}{suffix}");
            let mut request = BlobBuf::new();
            if named { request.msg_string("name", "r84fixture0"); }
            if verbose { request.msg_bool("verbose", true); }
            let mut b = BlobBuf::new();
            service::dump_list(&services, request.payload(), &mut b);
            assert_eq!(owrt_ubus::blob::fields(b.payload()).count(), if named { 1 } else { count });
            eprintln!("fixture={stage} payload_bytes={}", b.payload().len());
            b.reset_bounded(16 * 1024);
            profile_support::measure(&stage, n, &filter, || {
                service::dump_list(&services, request.payload(), &mut b);
                black_box(b.payload());
                b.reset_bounded(16 * 1024);
            });
        }
    }
    let mut b = BlobBuf::new();
    // Match the daemon: one descriptor and buffer live across requests.
    let mut meminfo = sysobj::Meminfo::open();
    profile_support::measure("system_info", n, &filter, || {
        assert!(sysobj::build_info(&mut b, &mut meminfo));
        black_box(b.payload());
        b.reset_bounded(16 * 1024);
    });
    // Parsing-only diagnostic snapshot; the daemon still reads current bytes.
    let meminfo_text = std::fs::read("/proc/meminfo").expect("meminfo profile input");
    profile_support::measure("system_info_parse_meminfo", n, &filter, || {
        black_box(sysobj::scan_meminfo(black_box(&meminfo_text)));
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
