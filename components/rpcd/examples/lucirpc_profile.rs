//! Profile the real luci-rpc sysfs reader and network-device reply handler.
//! Run in the exact image namespace: lucirpc_profile [iterations] [filter].
//! Host hints are opt-in, include the real DNS work, and exclude defer/reply
//! delivery. No daemon, ubus, ACL or wireless work is measured.
// These profiling adapters deliberately replace daemon state. Production
// unit tests run against the real binary, never against these stubs.
#![cfg(not(test))]
#![allow(dead_code)]

#[path = "../src/lucirpc.rs"]
mod lucirpc;
#[path = "../src/rtnl.rs"]
mod rtnl;
#[path = "../src/rrdns.rs"]
mod rrdns;
#[path = "../src/session.rs"]
mod session;
#[path = "../src/util.rs"]
#[allow(unused_imports)]
mod util;
#[path = "../src/glob.rs"]
mod glob;
#[path = "../src/reply.rs"]
mod reply;
mod profile_support;

use owrt_ubus::Request;
use profile_support::{measure, measure_with_warmup};
use std::hint::black_box;

pub struct Ctx { pub socket: Option<String> }
#[derive(Clone)]
pub struct Deferrer;
impl Deferrer {
    pub fn defer<F>(&self, _: Request, _: F) -> Option<(Request, session::Reply)>
    where F: FnOnce() -> session::Reply + Send + 'static,
    {
        panic!("deferred delivery is outside this profiler's scope");
    }
}
mod uciobj {
    pub fn purge_dir(_: &str) { panic!("session destruction is outside this profiler's scope"); }
}
mod iwinfoobj {
    pub fn luci_iwinfo(_: &mut owrt_ubus::BlobBuf, _: &str, _: bool) -> bool {
        panic!("wireless is outside this profiler's scope");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n = args.get(1).map(|s| s.parse().expect("iterations")).unwrap_or(1000);
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    assert!(n > 0);
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes");
    measure("lucirpc_readstr", n, filter, || {
        black_box(lucirpc::readstr("/sys/class/net/lo/mtu"));
    });
    measure("lucirpc_getNetworkDevices", n, filter, || {
        black_box(lucirpc::get_network_devices());
    });
    if filter.contains("getHostHints") {
        measure_with_warmup("lucirpc_getHostHints", n, 1, filter, || {
            black_box(lucirpc::get_host_hints());
        });
    }
}
