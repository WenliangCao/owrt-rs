#!/usr/bin/env python3
"""Exact read_opts enable-ubus acceptance and byte state; opens no listeners."""
import argparse
import json
from pathlib import Path
import subprocess

import dhcp_config_diff as base

C_DRIVER = r'''
#include "dnsmasq.h"
int main(int argc, char **argv) {
  rand_init();read_opts(argc,argv,"ubus-config-state");
  printf("enabled=%d name=",!!option_bool(OPT_UBUS));
  if(!daemon->ubus_name)printf("-");
  else for(unsigned char *p=(unsigned char *)daemon->ubus_name;*p;p++)printf("%02x",*p);
  puts("");return 0;
}
'''
RUST_DRIVER = r'''
#[path="CONFIG"] mod config;
#[path="HOSTS"] mod hosts;
use config::{loader,ubus::UbusConfig};
fn main() {
 let mut ubus=UbusConfig::default();
 let args:Vec<_>=std::env::args_os().skip(1).collect();
 let action=loader::load(&args,std::path::Path::new("/etc/dnsmasq.conf"),|d,_| {
  if ubus.apply(d)? {Ok(())} else {Err(config::Error("unhandled probe option"))}
 });
 match action {
  Err(error)=>{eprintln!("{error}");std::process::exit(error.exit_code);}
  Ok(loader::Action::Test)=>return,
  _=>{}
 }
 let (enabled,name)=match &ubus {UbusConfig::Disabled=>(false,None),UbusConfig::Enabled{name}=>(true,name.as_deref())};
 print!("enabled={} name=",u8::from(enabled));
 if let Some(name)=name {for byte in name {print!("{byte:02x}");}} else {print!("-");}
 println!();
 // Test the safety boundary separately from C parser acceptance.
 assert_eq!(ubus.object_name().is_err(),enabled && name.is_none());
}
'''


def cases():
    yield "disabled", b"", []
    for index, body in enumerate([
        b"enable-ubus", b"enable-ubus=", b'enable-ubus=""',
        b"enable-ubus=custom.name", b"enable-ubus=dnsmasq.dns",
        b"enable-ubus= opaque name ", b'enable-ubus=" opaque name "',
        b"enable-ubus=raw\xff\xfe", b"enable-ubus=a,b:c/path*?[]",
        b'enable-ubus="a,b:c"', b'enable-ubus="a\\tb\\nc\\ed"',
        b"enable-ubus=before\0after", b"enable-ubus=abc # comment",
        b"enable-ubus=abc#suffix", b'enable-ubus="unterminated',
        b"enable-ubus\nenable-ubus", b"enable-ubus=a\nenable-ubus=b",
        b"enable-ubus=a\nenable-ubus=", b"enable-ubus=\nenable-ubus=a",
        b"enable-ubus=" + b"a" * 1024,
    ]):
        yield f"file-{index:02}", body + b"\n", []
    for index, args in enumerate([
        [b"--enable-ubus"], [b"--enable-ubus="], [b"--enable-ubus=custom"],
        [b"--enable-ubus", b"custom"], [b"--enable-ubus=opaque\xff"],
        [b"--enable-ubus=a,b:c/path"], [b"--enable-ubus=a", b"--enable-ubus=b"],
        [b"--enable-ubus", b"--enable-ubus"], [b"--enable-ubu=abbreviated"],
    ]):
        yield f"cli-{index:02}", b"", args
    yield "file-overrides-cli", b"enable-ubus=file\n", [b"--enable-ubus=cli"]
    yield "empty-file-overrides-cli", b"enable-ubus=\n", [b"--enable-ubus=cli"]
    yield "default-file-overrides-cli", b"enable-ubus\n", [b"--enable-ubus=cli"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-only", action="store_true")
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(base.ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    base.C_DRIVER, base.RUST_DRIVER = C_DRIVER, RUST_DRIVER
    base.build(args, out)
    checks, raw = [], []
    # Observe all C state and --test outcomes before invoking the Rust probe.
    corpus = list(cases())
    assert len(corpus) == 33, "frozen enable-ubus corpus changed"
    observations = []
    for index, (label, body, argv) in enumerate(corpus):
        conf = out / f"{index:03}.conf"
        conf.write_bytes(body)
        arguments = [b"-C", bytes(conf), *argv]
        pair = [subprocess.run([bytes(out / "c-state"), *arguments, *tail], capture_output=True)
                for tail in ([], [b"--test"])]
        observations.append((label, arguments, pair))
    for index, (label, arguments, pair) in enumerate(observations):
        for mode, (reference, tail) in enumerate(zip(pair, ([], [b"--test"]))):
            expected = reference.stdout
            if args.inject_error and index == 0 and mode == 0:
                expected = b"enabled=1 name=646e736d617371\n"
            row = {"case": label, "mode": ["state", "test"][mode], "c_exit": reference.returncode,
                   "c_stdout": reference.stdout.hex(), "c_stderr": reference.stderr.hex()}
            if not args.c_only:
                rust = subprocess.run([bytes(out / "rust-state"), *arguments, *tail], capture_output=True)
                passed = reference.returncode == rust.returncode and (reference.returncode != 0 or expected == rust.stdout)
                row.update(rust_exit=rust.returncode, rust_stdout=rust.stdout.hex(), rust_stderr=rust.stderr.hex())
                checks.append({"case": f"{label}-{row['mode']}", "pass": passed})
            raw.append(row)
    report = {"scope": "enable-ubus parser state/acceptance only; empty name activation explicitly rejected",
              "cases": len(corpus), "passed": sum(c["pass"] for c in checks),
              "failed": sum(not c["pass"] for c in checks), "checks": checks, "raw": raw,
              "option_sha256": base.OPTION_SHA, "oracle_sha256": base.sha(out / "c-state"),
              "rustc": subprocess.check_output([args.rustc, "--version"], text=True).strip()}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("checks", "raw")}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
