#!/usr/bin/env python3
"""Measure frozen Rust type layouts without changing the product source.

Creates an ignored diagnostic source copy, appends sizeof-only globals, and
cross-compiles the library to LLVM IR. No measured daemon is instrumented.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


TYPES = {
    "dns/cache.rs": ["Slot", "Entry", "Record", "Cache", "CnameTarget", "LocalTarget"],
    "dns/wire.rs": ["Name"],
    "dhcp/lease.rs": ["Lease", "ClientIdentity", "LeaseId", "LeaseStore", "ScriptQueue"],
    "dns/lease_names.rs": ["LeaseInput", "LeaseName", "LeaseNames"],
    "logging.rs": ["Logger", "Record", "TcpLogContext"],
    "helper.rs": ["ExtraData", "LeaseEvent", "LeaseEventContext", "LeaseDelivery"],
    "helper/process.rs": ["Helper"],
    "listeners.rs": ["DnsSocket"],
    "net.rs": ["DatagramSocket"],
}


def run(argv, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True)


def definition(text, kind, name):
    start = re.search(r"\b" + kind + r"\s+" + name + r"\s*\{", text).start()
    opening = text.index("{", start)
    depth = 1
    position = opening + 1
    while depth:
        depth += (text[position] == "{") - (text[position] == "}")
        position += 1
    return text[start:position] + ";\n"


def c_layout(reference, out):
    header = (reference / "src/dnsmasq.h").read_text()
    shim = """
typedef long time_t; typedef long off_t; typedef int pid_t;
struct in_addr { unsigned int s_addr; };
struct in6_addr { union { unsigned char bytes[16]; unsigned int words[4]; } u; };
struct sockaddr { unsigned short family; char data[14]; };
struct sockaddr_in { unsigned short family, port; struct in_addr addr; char zero[8]; };
struct sockaddr_in6 { unsigned short family, port; unsigned int flowinfo; struct in6_addr addr; unsigned int scope; };
#define SMALLDNAME 75
#define MAXDNAMESTR 503
#define KEYBLOCK_LEN 40
#define DHCP_CHADDR_MAX 16
#define IF_NAMESIZE 16
#define MAX_MESSAGE 1024
#define HAVE_TFTP 1
"""
    types = [("union", "all_addr"), ("union", "bigname"), ("struct", "blockdata"),
             ("struct", "crec"), ("union", "mysockaddr"), ("struct", "listener"),
             ("struct", "dhcp_lease"), ("struct", "log_entry"), ("struct", "script_data")]
    inputs = {"log_entry": reference / "src/log.c", "script_data": reference / "src/helper.c"}
    for kind, name in types:
        value = inputs[name].read_text() if name in inputs else header
        shim += definition(value, kind, name)
        shim += f"const unsigned long M6_C_SIZE_{name} = sizeof({kind} {name});\n"
    source = out / "c-layout.c"
    source.write_text(shim)
    llvm = out / "c-layout.ll"
    argv = ["clang", "--target=aarch64-linux-musl", "-S", "-emit-llvm", "-o", str(llvm), str(source)]
    subprocess.run(argv, check=True)
    ir = llvm.read_text()
    result = []
    for kind, name in types:
        size = re.findall(r"@M6_C_SIZE_" + name + r" = .*?constant i64 (\d+)", ir)
        if len(size) != 1:
            raise RuntimeError(f"missing C layout: {name}")
        result.append({"type": f"{kind} {name}", "bytes": int(size[0])})
    return {"types": result, "command": argv,
            "method": "exact upstream record declarations with Linux AArch64 ABI primitive/network shims; no DHCP6/broken-RTC, TFTP enabled",
            "inputs": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in [reference / "src/dnsmasq.h", reference / "src/config.h",
                                    reference / "src/dns-protocol.h", reference / "src/dhcp-protocol.h",
                                    *inputs.values()]},
            "llvm_sha256": hashlib.sha256(llvm.read_bytes()).hexdigest()}


CAPACITY_DIAGNOSTIC = r'''
pub fn m6_diagnostic_cache() -> String {
    let mut cache = Cache::new(4096, Policy::default());
    for index in 0..4096u32 {
        let name = Name::from_ascii(&format!("c{index:04x}.cache.test")).unwrap();
        cache.start_insert();
        cache.insert(Record { name: name.clone(), kind: Kind::Ipv4, negative: false,
                              data: vec![198, 18, (index >> 8) as u8, index as u8] }, 0, 3600).unwrap();
        assert!(cache.commit());
    }
    let name_bytes: usize = cache.slots.iter().filter_map(|s| s.entry.as_ref()).map(|e| e.record.name.m6_diagnostic_capacity()).sum();
    let data_capacity: usize = cache.slots.iter().filter_map(|s| s.entry.as_ref()).map(|e| e.record.data.capacity()).sum();
    let key_capacity: usize = cache.names.keys().map(Vec::capacity).sum();
    let index_capacity: usize = cache.names.values().map(Vec::capacity).sum();
    let snapshot = cache.snapshot();
    let snapshot_index_capacity: usize = snapshot.names.values().map(Vec::capacity).sum();
    format!("{{\"slots\":{},\"slot_capacity\":{},\"names\":{},\"hashmap_capacity\":{},\"name_capacity\":{},\"data_capacity\":{},\"key_capacity\":{},\"index_capacity\":{},\"pending_capacity\":{},\"reverse_capacity\":{},\"snapshot_slot_capacity\":{},\"snapshot_hashmap_capacity\":{},\"snapshot_index_capacity\":{}}}",
            cache.slots.len(), cache.slots.capacity(), cache.names.len(), cache.names.capacity(),
            name_bytes, data_capacity, key_capacity, index_capacity, cache.pending.capacity(), cache.reverse_chain.capacity(),
            snapshot.slots.capacity(), snapshot.names.capacity(), snapshot_index_capacity)
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--source", default="dc1b740d7973838e2ae7f098d0726b0484e55074")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target", default="aarch64-unknown-linux-musl")
    parser.add_argument("--c-reference", type=Path)
    args = parser.parse_args()
    repository, out = args.repository.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = run(["git", "rev-parse", args.source], repository).strip()
    records = {}
    for component in ["dnsmasq", "ubus"]:
        prefix = f"components/{component}/"
        paths = run(["git", "ls-tree", "-r", "--name-only", source, prefix], repository).splitlines()
        for name in paths:
            value = subprocess.check_output(["git", "show", f"{source}:{name}"], cwd=repository)
            path = out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
    for name, types in TYPES.items():
        path = out / "components/dnsmasq/src" / name
        value = path.read_text()
        for kind in types:
            marker = "M6_LAYOUT_" + (name + "_" + kind).replace("/", "_").replace(".", "_")
            records[marker] = {"module": name, "type": kind}
            value += (f"\n#[used]\n#[no_mangle]\npub static {marker}: "
                      f"[u8; std::mem::size_of::<{kind}>()] = "
                      f"[0; std::mem::size_of::<{kind}>()];\n")
        path.write_text(value)
    manifest = out / "components/dnsmasq/Cargo.toml"
    argv = ["cargo", "rustc", "--release", "--manifest-path", str(manifest), "--lib", "--target",
            args.target, "--target-dir", str(out / "target"), "--", "--emit=llvm-ir"]
    with (out / "build.log").open("w") as log:
        subprocess.run(argv, cwd=out, stdout=log, stderr=log, check=True)
    irs = list((out / "target" / args.target / "release/deps").glob("dnsmasq_rs-*.ll"))
    if len(irs) != 1:
        raise RuntimeError(f"expected one diagnostic LLVM IR, got {irs}")
    ir = irs[0].read_text()
    for marker, record in records.items():
        matches = re.findall(r"^@" + re.escape(marker) + r" = .*?\[(\d+) x i8\]", ir, re.MULTILINE)
        if len(matches) != 1:
            raise RuntimeError(f"missing or ambiguous layout: {marker}")
        record["bytes"] = int(matches[0])
    result = {"source": source, "target": args.target, "rustc": run(["rustc", "-Vv"]),
              "command": argv, "method": "sizeof globals in a diagnostic source copy; no product changes",
              "llvm_sha256": hashlib.sha256(irs[0].read_bytes()).hexdigest(),
              "types": list(records.values())}
    if args.c_reference:
        result["c_reference"] = c_layout(args.c_reference.resolve(), out)
    cache = out / "components/dnsmasq/src/dns/cache.rs"
    cache.write_text(cache.read_text() + CAPACITY_DIAGNOSTIC)
    wire = out / "components/dnsmasq/src/dns/wire.rs"
    wire.write_text(wire.read_text() + "\nimpl Name { pub fn m6_diagnostic_capacity(&self) -> usize { self.0.capacity() } }\n")
    example = out / "components/dnsmasq/examples/m6_capacities.rs"
    example.parent.mkdir(exist_ok=True)
    example.write_text(r'''
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
struct DiagnosticAllocator;
static RECORD: AtomicBool = AtomicBool::new(false);
static TABLE_BYTES: AtomicUsize = AtomicUsize::new(0);
// SAFETY: allocation/deallocation ownership remains entirely with System;
// telemetry touches only atomics and cannot allocate or recurse.
unsafe impl GlobalAlloc for DiagnosticAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if RECORD.load(Ordering::Relaxed) && (100_000..450_000).contains(&layout.size()) {
            TABLE_BYTES.fetch_max(layout.size(), Ordering::Relaxed);
        }
        // SAFETY: forward the caller's valid allocation layout unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forward the allocation owner and original layout unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: DiagnosticAllocator = DiagnosticAllocator;
fn main() {
    RECORD.store(true, Ordering::Relaxed);
    let capacities = dnsmasq_rs::dns::cache::m6_diagnostic_cache();
    RECORD.store(false, Ordering::Relaxed);
    println!("{{\"capacities\":{capacities},\"hashmap_requested_bytes\":{}}}", TABLE_BYTES.load(Ordering::Relaxed));
}
''')
    capacity_command = ["cargo", "run", "--release", "--manifest-path", str(manifest),
                        "--target-dir", str(out / "target"), "--example", "m6_capacities"]
    with (out / "native-build.log").open("w") as log:
        native = subprocess.run(capacity_command, cwd=out, stdout=subprocess.PIPE, stderr=log, text=True, check=True)
    diagnostic = json.loads(native.stdout)
    result["cache_capacities"] = diagnostic["capacities"]
    result["hashmap_requested_bytes"] = diagnostic["hashmap_requested_bytes"]
    result["cache_capacity_method"] = "native diagnostic copy, same 64-bit compiler; capacity behavior only, not measured target CPU/RSS"
    result["capacity_command"] = capacity_command
    (out / "layout.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
