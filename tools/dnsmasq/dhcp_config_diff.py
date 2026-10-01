#!/usr/bin/env python3
"""Compare DHCPv4 range/leasefile/boolean state with exact option.c; never open listeners.

Selector/static/proxy/deprecated gaps are reported separately, not counted as
functional equivalence. Integer-overflow inputs are outside the defined C
arithmetic contract and are never used as differential expected values.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OPTION_SHA = "bdcd4c532b66560fb2b197470fe7ebbfe387d4ab3cd5372932591ce260e30bed"
C_DRIVER = r'''
#include "dnsmasq.h"
int main(int argc, char **argv) {
  rand_init();
  read_opts(argc, argv, "dhcp-config-state");
  int bootp_global=0;
  for(struct dhcp_netid_list *node=daemon->bootp_dynamic;node;node=node->next)if(!node->list)bootp_global=1;
  printf("max=%d ro=%d bootp=%d auth=%d clid=%d sequential=%d noping=%d file=", daemon->dhcp_max, !!option_bool(OPT_LEASE_RO),bootp_global,
         !!option_bool(OPT_AUTHORITATIVE),!!option_bool(OPT_IGNORE_CLID),!!option_bool(OPT_CONSEC_ADDR),!!option_bool(OPT_NO_PING));
  if (!daemon->lease_file) printf("-");
  else for (unsigned char *p=(unsigned char *)daemon->lease_file; *p; p++) printf("%02x",*p);
  puts("");
  for (struct dhcp_context *c = daemon->dhcp; c; c = c->next) {
    char start[INET_ADDRSTRLEN], end[INET_ADDRSTRLEN];
    char mask[INET_ADDRSTRLEN], broadcast[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c->start, start, sizeof(start));
    inet_ntop(AF_INET, &c->end, end, sizeof(end));
    inet_ntop(AF_INET, &c->netmask, mask, sizeof(mask));
    inet_ntop(AF_INET, &c->broadcast, broadcast, sizeof(broadcast));
    printf("%s %s %s %s %u %d\n", start, end,
           (c->flags & CONTEXT_NETMASK) ? mask : "-",
           (c->flags & CONTEXT_BRDCAST) ? broadcast : "-",
           c->lease_time, !!(c->flags & CONTEXT_SETLEASE));
  }
  return 0;
}
'''
RUST_DRIVER = r'''
#[path = "CONFIG"] mod config;
#[path = "HOSTS"] mod hosts;
use config::{dhcp::DhcpConfig, loader};
use std::path::Path;
fn main() {
    let mut dhcp = DhcpConfig::default();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let Err(error) = loader::load(&args, Path::new("/etc/dnsmasq.conf"), |d, _| {
        if dhcp.apply(d)? { Ok(()) } else { Err(config::Error("unhandled probe option")) }
    }) {
        eprintln!("{error}"); std::process::exit(error.exit_code);
    }
    print!("max={} ro={} bootp={} auth={} clid={} sequential={} noping={} file=",dhcp.lease_max,u8::from(dhcp.lease_read_only),
           u8::from(dhcp.bootp_dynamic),u8::from(dhcp.authoritative),u8::from(dhcp.ignore_client_id),u8::from(dhcp.sequential),u8::from(dhcp.no_ping));
    if let Some(path)=&dhcp.lease_file {for byte in path {print!("{byte:02x}");}}else{print!("-");}
    println!();
    for c in dhcp.ranges {
        println!("{} {} {} {} {} {}", c.start, c.end,
            c.netmask.map_or_else(|| "-".into(), |v| v.to_string()),
            c.broadcast.map_or_else(|| "-".into(), |v| v.to_string()),
            c.lease_time, u8::from(c.lease_time_explicit));
    }
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def corpus():
    base = "192.0.2.10,192.0.2.20"
    values = [base, "192.0.2.20,192.0.2.10", "192.0.2.10,192.0.2.10",
              base + ",255.255.255.0", base + ",255.255.255.0,192.0.2.255",
              base + ",255.255.255.0,192.0.2.255,12h", base + ",0.0.0.0",
              base + ",255.0.255.0", "192.0.2.10,198.51.100.20",
              "192.0.2.10,198.51.100.20,255.255.255.0",
              base + ",255.255.255.0,203.0.113.255",
              base + ",255.255.255.255", base + ",", base + ",255.255.255.0,",
              base + ",255.255.255.0,192.0.2.255,", base + ",1h,2h",
              base + ",,1h", base + ",255.255.255.0,1h,extra",
              "192.0.2.10", "192.0.2.10,", "192.0.2.10,bad", "bad,192.0.2.20",
              "192.0.2.010,192.0.2.20", base + ",255.255.999.0",
              base + ",255.255.255.0,255.255.999.0", '"192.0.2.10",192.0.2.20',
              base + ',"12h"', "192.0.2.10 , 192.0.2.20 , 255.255.255.0 , 1h"]
    values += [base + "," + value for value in
               ("0", "1", "119", "120", "121", "3600", "2147483647", "infinite",
                "000120", "-1", "+1", "1.5h", "12x", "INFINITE")]
    values += [base + "," + value + suffix
               for suffix in "sSmMhHdDwW" for value in ("", "0", "1", "2")]
    rows = [("contract", "dhcp-range=" + value) for value in values]
    rows.append(("contract", "dhcp-range=" + base + "\ndhcp-range=198.51.100.20,198.51.100.10,1d"))
    rows += [("unsupported", "dhcp-range=" + value) for value in
             ("tag:known," + base, "set:known," + base, "known," + base,
              "192.0.2.10,static", "192.0.2.10,proxy", base + ",deprecated")]
    rows.append(("contract", "dhcp-range=2001:db8::10,2001:db8::20"))
    rows += [("contract", value) for value in [
        "", "leasefile-ro", "dhcp-leasefile=/private/fixture.leases", "dhcp-lease=/private/fixture.leases",
        "dhcp-leasefile=", 'dhcp-leasefile="/private/comma,name"',
        "dhcp-leasefile=/private/fixture.leases\nleasefile-ro",
        "dhcp-lease-max=", "dhcp-lease-max=0", "dhcp-lease-max=1000", "dhcp-lease-max=2147483647",
        "dhcp-lease-max=-1"]]
    rows.append(("contract","bootp-dynamic"))
    rows += [("unsupported","bootp-dynamic="+value) for value in ["tag:known","known","tag:!blocked"]]
    rows += [("contract",option+suffix) for option in ["dhcp-authoritative","dhcp-ignore-clid","dhcp-sequential-ip","no-ping"] for suffix in ["","=tag:known"]]
    return rows


def build(args, out):
    source = args.source.resolve()
    if sha(source / "src/option.c") != OPTION_SHA:
        raise SystemExit("exact option.c identity mismatch")
    objects = args.reference_build.resolve() / "dnsmasq"
    if sha(objects / "option.c") != OPTION_SHA:
        raise SystemExit("reference-build option.c identity mismatch")
    deps = args.reference_build.resolve() / "deps"
    (out / "state.c").write_text(C_DRIVER)
    renamed = out / "dnsmasq-without-main.o"
    subprocess.run(["objcopy", "--redefine-sym", "main=reference_main",
                    str(objects / "dnsmasq.o"), str(renamed)], check=True)
    flags = ["-DHAVE_UBUS", "-DHAVE_POLL_H", "-DNO_DHCP6", "-DNO_AUTH", "-DNO_IPSET", "-DNO_ID"]
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", *flags,
                    "-I" + str(objects), "-I" + str(deps / "include"), str(out / "state.c"),
                    str(renamed), *(str(p) for p in sorted(objects.glob("*.o")) if p.name != "dnsmasq.o"),
                    "-L" + str(deps / "lib"), "-Wl,-rpath," + str(deps / "lib"),
                    "-lubus", "-lubox", "-o", str(out / "c-state")], check=True)
    if not args.c_only:
        (out / "state.rs").write_text(RUST_DRIVER
            .replace("CONFIG", str(ROOT / "components/dnsmasq/src/config/mod.rs"))
            .replace("HOSTS", str(ROOT / "components/dnsmasq/src/hosts.rs")))
        subprocess.run([args.rustc, "--edition=2021", "-A", "dead_code", "-A", "unused_imports",
                        str(out / "state.rs"), "-o", str(out / "rust-state")], check=True)


def matches(c, rust):
    return c.returncode == rust.returncode and (c.returncode != 0 or c.stdout == rust.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--rustc", default=shutil.which("rustc") or "rustc")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-only", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "private") or out.exists():
        parser.error("--out must be a new directory below private/")
    out.mkdir(parents=True)
    build(args, out)
    rows = []
    for index, (scope, body) in enumerate(corpus()):
        conf = out / f"{index:03}.conf"
        conf.write_text(body + "\n")
        observations = []
        for binary in (["c-state"] if args.c_only else ["c-state", "rust-state"]):
            run = subprocess.run([str(out / binary), "-C", str(conf)], capture_output=True)
            (out / f"{index:03}.{binary}.stdout").write_bytes(run.stdout)
            (out / f"{index:03}.{binary}.stderr").write_bytes(run.stderr)
            observations.append(run)
        c = observations[0]
        row = {"case": index, "scope": scope, "input": body, "c_exit": c.returncode,
               "c_state": c.stdout.decode()}
        if not args.c_only:
            rust = observations[1]
            row.update(rust_exit=rust.returncode, rust_state=rust.stdout.decode(), match=matches(c, rust))
            row["boundary_checked"] = scope == "unsupported" and c.returncode == 0 and rust.returncode != 0
        rows.append(row)
    accepted = sum(row["c_exit"] == 0 for row in rows)
    rejected = len(rows) - accepted
    # Frozen after the C-only baseline, independently of the Rust parser.
    if not args.c_only:
        assert (len(rows), accepted, rejected) == (114, 89, 25)
    # Independent deliberate failures calibrate acceptance and state comparison.
    ok = subprocess.CompletedProcess([], 0, b"3600\n")
    assert matches(ok, ok)
    assert not matches(ok, subprocess.CompletedProcess([], 1, b""))
    assert not matches(ok, subprocess.CompletedProcess([], 0, b"43200\n"))
    assert not matches(subprocess.CompletedProcess([],1,b""),subprocess.CompletedProcess([],2,b""))
    failures = [] if args.c_only else [r for r in rows
        if not (r["boundary_checked"] if r["scope"] == "unsupported" else r["match"])]
    report = {"scope": "DHCPv4 range/leasefile/readonly/capacity/boolean option acceptance/state only; no runtime/interface inference",
              "cases": len(rows), "c_accepted": accepted, "c_rejected": rejected,
              "contract_matches": None if args.c_only else sum(r["scope"] == "contract" and r["match"] for r in rows),
              "unsupported_boundary_checks": None if args.c_only else sum(r["boundary_checked"] for r in rows),
              "failures": failures, "known_unsupported": [r for r in rows if r["scope"] == "unsupported"],
              "full_functional_equivalence": False, "calibration": "accept/reject/state mismatch checked",
              "option_c_sha256": OPTION_SHA, "c_oracle_sha256": sha(out / "c-state"),
              "rust_parser_sha256": sha(ROOT / "components/dnsmasq/src/config/dhcp.rs"), "rows": rows}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("rows", "known_unsupported")}, indent=2))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
