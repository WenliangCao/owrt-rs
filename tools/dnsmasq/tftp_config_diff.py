#!/usr/bin/env python3
"""Compare TFTP option state with the exact patched dnsmasq option parser.

The C side links the existing read_opts object from a caller-supplied
reference build and never starts a listener. The Rust side uses the real
``config::tftp::TftpConfig`` parser. Generated binaries, fixtures and reports
must remain under ignored ``private/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src"
OPTION_SHA256 = "bdcd4c532b66560fb2b197470fe7ebbfe387d4ab3cd5372932591ce260e30bed"

C_DRIVER = r'''
#include "dnsmasq.h"
#include <stdio.h>
#include <string.h>

static void hex(const unsigned char *value, size_t length) {
  if (!value) { putchar('-'); return; }
  if (length == 0) { putchar('_'); return; }
  for (size_t i = 0; i < length; i++) printf("%02x", value[i]);
}
static void text(const char *value) {
  if (!value) { putchar('-'); return; }
  hex((const unsigned char *)value, strlen(value));
}
static void bit(unsigned option) { putchar(option_bool(option) ? '1' : '0'); }

int main(int argc, char **argv) {
  rand_init();
  read_opts(argc, argv, "tftp-config-state");
  printf("enabled="); bit(OPT_TFTP);
  printf(" secure="); bit(OPT_TFTP_SECURE);
  printf(" no_blocksize="); bit(OPT_TFTP_NOBLOCK);
  printf(" lowercase="); bit(OPT_TFTP_LC);
  printf(" no_fail="); bit(OPT_TFTP_NO_FAIL);
  printf(" single_port="); bit(OPT_SINGLE_PORT);
  printf(" unique_ip="); bit(OPT_TFTP_APREF_IP);
  printf(" unique_mac="); bit(OPT_TFTP_APREF_MAC);
  printf(" max=%d mtu=%d start=%d end=%d root=", daemon->tftp_max,
         daemon->tftp_mtu, daemon->start_tftp_port, daemon->end_tftp_port);
  text(daemon->tftp_prefix);
  putchar('\n');
  for (struct iname *entry = daemon->tftp_interfaces; entry; entry = entry->next) {
    printf("interface="); text(entry->name); putchar('\n');
  }
  for (struct tftp_prefix *entry = daemon->if_prefix; entry; entry = entry->next) {
    printf("prefix="); text(entry->prefix); putchar(' ');
    text(entry->interface); putchar('\n');
  }
  return 0;
}
'''

RUST_DRIVER = r'''
#[path = "CONFIG"] mod config;
#[path = "HOSTS"] mod hosts;
use config::{loader, tftp::TftpConfig};
use std::path::Path;

fn hex(value: Option<&[u8]>) -> String {
    value.map_or_else(|| "-".to_string(), |bytes| {
        if bytes.is_empty() { "_".to_string() }
        else { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
    })
}
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut tftp = TftpConfig::default();
    let result = loader::load(&args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        if tftp.apply(directive)? { Ok(()) }
        else { Err(config::Error("unimplemented probe option")) }
    });
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(error.exit_code);
    }
    println!("enabled={} secure={} no_blocksize={} lowercase={} no_fail={} single_port={} unique_ip={} unique_mac={} max={} mtu={} start={} end={} root={}",
        u8::from(tftp.enabled), u8::from(tftp.secure), u8::from(tftp.no_block_size),
        u8::from(tftp.lowercase), u8::from(tftp.no_fail), u8::from(tftp.single_port),
        u8::from(tftp.unique_root_ip), u8::from(tftp.unique_root_mac), tftp.max_transfers,
        tftp.mtu.map_or_else(|| "0".to_string(), |value| value.to_string()),
        tftp.port_range.map_or(0, |range| range.0),
        tftp.port_range.map_or(0, |range| range.1), hex(tftp.root.as_deref()));
    for value in &tftp.interfaces { println!("interface={}", hex(value.as_deref())); }
    for value in &tftp.interface_roots {
        println!("prefix={} {}", hex(value.path.as_deref()), hex(value.interface.as_deref()));
    }
}
'''


def build(reference_build: Path, out: Path, rustc: str) -> None:
    if hashlib.sha256((SOURCE / "option.c").read_bytes()).hexdigest() != OPTION_SHA256:
        raise SystemExit("option.c identity mismatch")
    reference_root = reference_build.resolve()
    build_dir = reference_root / "dnsmasq"
    if not (build_dir / "dnsmasq.o").exists():
        # Also accept a directly supplied object directory for ad-hoc probes.
        build_dir = reference_root
    deps = reference_root / "deps"
    if not deps.exists():
        deps = build_dir / "deps"
    (out / "state_probe.c").write_text(C_DRIVER)
    renamed = out / "dnsmasq-without-main.o"
    subprocess.run([
        "objcopy", "--redefine-sym", "main=reference_main",
        str(build_dir / "dnsmasq.o"), str(renamed),
    ], check=True)
    objects = [str(path) for path in sorted(build_dir.glob("*.o")) if path.name != "dnsmasq.o"]
    flags = ["-DHAVE_UBUS", "-DHAVE_POLL_H", "-DNO_DHCP6", "-DNO_AUTH", "-DNO_IPSET", "-DNO_ID"]
    subprocess.run([
        "cc", "-O2", "-Werror=format", *flags,
        "-I" + str(build_dir), "-I" + str(deps / "include"),
        str(out / "state_probe.c"), str(renamed), *objects,
        "-L" + str(deps / "lib"), "-Wl,-rpath," + str(deps / "lib"),
        "-lubus", "-lubox", "-o", str(out / "c-state"),
    ], check=True)
    (out / "driver.rs").write_text(
        RUST_DRIVER.replace("CONFIG", str(ROOT / "components/dnsmasq/src/config/mod.rs"))
        .replace("HOSTS", str(ROOT / "components/dnsmasq/src/hosts.rs"))
    )
    subprocess.run([rustc, "--edition=2021", "-A", "dead_code", "-A", "unused_imports",
                    str(out / "driver.rs"), "-o", str(out / "rust-state")], check=True)


def cases() -> list[bytes]:
    return [
        b"enable-tftp",
        b"enable-tftp=eth0,eth1",
        b"enable-tftp=",
        b"tftp-root=/srv/tftp",
        b"tftp-root=/a\ntftp-root=/b",
        b"tftp-root=/srv/eth0,eth0",
        b"tftp-root=/srv/eth0,eth0,tail",
        b"tftp-root=",
        b"tftp-root=,eth0",
        b"tftp-max=0",
        b"tftp-max=2147483647",
        b"tftp-mtu=0",
        b"tftp-mtu=511",
        b"tftp-port-range=40010,40000",
        b"tftp-port-range=,",
        b"tftp-port-range=65535,0",
        b"tftp-unique-root",
        b"tftp-unique-root=ip\ntftp-unique-root=mac",
        b"tftp-unique-root=",
        b"tftp-lowercase\ntftp-no-blocksize\ntftp-secure\ntftp-no-fail\ntftp-single-port",
        b"tftp-max=x",
        b"tftp-port-range=1,65536",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--rustc", default=shutil.which("rustc") or
                        str(next(iter(sorted((Path.home() / ".rustup/toolchains").glob("1.98.1-*/bin/rustc"))), "rustc")))
    parser.add_argument("--out", type=Path, default=ROOT / "private/dnsmasq-rs/tftp-config-diff")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "private"):
        parser.error("--out must remain under private/")
    out.mkdir(parents=True, exist_ok=True)
    build(args.reference_build, out, args.rustc)
    rows = []
    for index, body in enumerate(cases()):
        config = out / f"{index:03}.conf"
        config.write_bytes(body)
        argv = ["-C", str(config)]
        observed = []
        for binary in ["c-state", "rust-state"]:
            run = subprocess.run([str(out / binary), *argv], capture_output=True)
            (out / f"{index:03}.{binary}.stdout").write_bytes(run.stdout)
            (out / f"{index:03}.{binary}.stderr").write_bytes(run.stderr)
            observed.append(run)
        c, rust = observed
        equal = (c.returncode == 0) == (rust.returncode == 0)
        if equal and c.returncode == 0:
            equal = c.stdout.splitlines() == rust.stdout.splitlines()
        rows.append({"case": index, "input": body.decode("ascii"),
                     "c_status": c.returncode, "rust_status": rust.returncode,
                     "match": equal})
    report = {
        "scope": "TFTP option acceptance and parser state; no listener or filesystem",
        "cases": len(rows),
        "failures": [row for row in rows if not row["match"]],
        "option_c_sha256": OPTION_SHA256,
        "rows": rows,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "rows"}, indent=2))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
