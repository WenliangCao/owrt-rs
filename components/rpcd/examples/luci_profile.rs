//! Profile actual LuCI read-only handlers and their JSON-to-Blob reply bridge.
//! Run in the exact image namespace: luci_profile [iterations] [stage filter].
//! getFeatures forks real helpers and is opt-in with a getFeatures filter;
//! use a small iteration count for it. No ubus or ACL time is measured.
// These profiling adapters deliberately replace daemon state. Production
// unit tests run against the real binary, never against these stubs.
#![cfg(not(test))]
#![allow(dead_code)]

#[path = "../src/luci.rs"]
mod luci;
#[path = "../src/util.rs"]
#[allow(unused_imports)]
mod util;
#[path = "../src/glob.rs"]
mod glob;
#[path = "../src/ip.rs"]
mod ip;
mod profile_support;

use owrt_ubus::convert::object_to_payload;
use owrt_ubus::json::Json;
use profile_support::measure_with_warmup;
use std::hint::black_box;

pub struct Ctx;
impl Ctx {
    pub fn ubus_call(&self, _: &str, _: &str, _: Option<&Json>) -> Option<Json> {
        panic!("nested ubus calls are outside this profiler's scope");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n = args.get(1).map(|s| s.parse().expect("iterations")).unwrap_or(20000);
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    assert!(n > 0);
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes");
    for method in ["getUnixtime", "getVersion", "getFeatures"] {
        if method == "getFeatures" && !filter.contains("getFeatures") {
            continue;
        }
        let stage = format!("luci_{method}");
        if !["handler", "encode", "reply"].iter().any(|part| format!("{stage}_{part}").contains(filter)) {
            continue;
        }
        let call = || luci::call(&Ctx, method, &[]).expect("successful handler").expect("reply");
        let result = call();
        assert!(matches!(result, Json::Object(_)));
        let warmup = if method == "getFeatures" { 1 } else { 100 };
        measure_with_warmup(&format!("{stage}_handler"), n, warmup, filter, || {
            black_box(call());
        });
        measure_with_warmup(&format!("{stage}_encode"), n, warmup, filter, || {
            black_box(object_to_payload(&result));
        });
        measure_with_warmup(&format!("{stage}_reply"), n, warmup, filter, || {
            black_box(object_to_payload(&call()));
        });
    }
}
