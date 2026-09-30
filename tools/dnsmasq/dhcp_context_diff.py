#!/usr/bin/env python3
"""Differential dynamic context completion using verbatim hash-pinned C bodies.

The same ordered config/interface snapshots and persistent state feed both
programs. No listener, interface mutation, router or production access. C warning
logging is suppressed; warning text is outside this state-comparison boundary.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DHCP_SHA = "600dc068b0516d7edebcde9b02ae2091a278fc154551106823ddc388170d7001"
C_DRIVER = r'''
#include "dnsmasq.h"
#define my_syslog(...) ((void)0)
struct iface_param { struct dhcp_context *current; int ind; };
/* EXACT_BODIES */
static struct in_addr address(const char *value) {
  struct in_addr addr = {0};
  if (strcmp(value, "-") && inet_pton(AF_INET, value, &addr) != 1) exit(2);
  return addr;
}
static void print_address(struct in_addr addr) {
  char text[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr, text, sizeof(text)); printf(" %s", text);
}
int main(void) {
  unsigned count, steps;
  if (scanf("%u %u", &count, &steps) != 2 || count > 32 || steps > 32) return 2;
  struct dhcp_context *contexts = calloc(count ? count : 1, sizeof(*contexts));
  daemon = calloc(1, sizeof(*daemon));
  if (!contexts || !daemon) return 2;
  daemon->dhcp_buff = calloc(1, DHCP_BUFF_SZ);
  daemon->dhcp_buff2 = calloc(1, DHCP_BUFF_SZ);
  daemon->addrbuff = calloc(1, ADDRSTRLEN);
  if (!daemon->dhcp_buff || !daemon->dhcp_buff2 || !daemon->addrbuff) return 2;
  daemon->dhcp = count ? contexts : NULL;
  for (unsigned i = 0; i < count; i++) {
    char start[64], end[64], mask[64], broadcast[64];
    unsigned lease, explicit_lease, epoch;
    if (scanf("%63s %63s %63s %63s %u %u %u", start, end, mask, broadcast,
              &lease, &explicit_lease, &epoch) != 7) return 2;
    struct dhcp_context *c = &contexts[i];
    c->next = i + 1 < count ? &contexts[i+1] : NULL;
    c->start = address(start); c->end = address(end);
    c->netmask = address(mask); c->broadcast = address(broadcast);
    if (strcmp(mask, "-")) c->flags |= CONTEXT_NETMASK;
    if (strcmp(broadcast, "-")) c->flags |= CONTEXT_BRDCAST;
    if (explicit_lease) c->flags |= CONTEXT_SETLEASE;
    c->lease_time = lease; c->addr_epoch = epoch;
  }
  for (unsigned step = 0; step < steps; step++) {
    unsigned incoming, interfaces;
    if (scanf("%u %u", &incoming, &interfaces) != 2 || interfaces > 32) return 2;
    struct iface_param parm = {NULL, (int)incoming};
    for (unsigned i = 0; i < count; i++) contexts[i].current = &contexts[i];
    for (unsigned i = 0; i < interfaces; i++) {
      unsigned index, loopback;
      char local[64], mask[64], broadcast[64];
      if (scanf("%u %63s %63s %63s %u", &index, local, mask, broadcast, &loopback) != 5) return 2;
      complete_context(address(local), (int)index, NULL, address(mask), address(broadcast), &parm);
    }
    for (struct dhcp_context *c = parm.current; c; c = c->current) {
      printf("selected %u %td", step, c - contexts);
      print_address(c->start); print_address(c->end); print_address(c->netmask);
      print_address(c->broadcast); print_address(c->router); print_address(c->local);
      printf(" %u %u\n", c->lease_time, c->addr_epoch);
    }
    for (unsigned i = 0; i < count; i++) {
      struct dhcp_context *c = &contexts[i];
      printf("state %u %u", step, i); print_address(c->netmask);
      print_address(c->broadcast); print_address(c->router); print_address(c->local);
      printf(" %u\n", c->addr_epoch);
    }
  }
  free(daemon->dhcp_buff); free(daemon->dhcp_buff2); free(daemon->addrbuff);
  free(contexts); free(daemon);
  return 0;
}
'''
RUST_DRIVER = r'''
#[path = "CONFIG"] mod config;
#[path = "HOSTS"] mod hosts;
#[path = "INTERFACES"] mod interfaces;
mod dhcp {
    #[path = "LEASE_FILE"] pub mod lease_file;
    #[path = "LEASE"] pub mod lease;
    #[path = "ALLOCATION"] pub mod allocation;
    #[path = "CONTEXT"] pub mod context;
}
use config::dhcp::RangeConfig;
use dhcp::context::{ContextState, select_contexts};
use interfaces::Ipv4Interface;
use std::io::Read;
fn main() {
    let mut input = String::new(); std::io::stdin().read_to_string(&mut input).unwrap();
    let mut words = input.split_whitespace();
    let count: usize = words.next().unwrap().parse().unwrap();
    let steps: usize = words.next().unwrap().parse().unwrap();
    let mut configs = Vec::new(); let mut states = Vec::new();
    for _ in 0..count {
        let start = words.next().unwrap().parse().unwrap();
        let end = words.next().unwrap().parse().unwrap();
        let netmask = words.next().unwrap().parse().ok();
        let broadcast = words.next().unwrap().parse().ok();
        let lease_time = words.next().unwrap().parse().unwrap();
        let lease_time_explicit = words.next().unwrap() == "1";
        let epoch = words.next().unwrap().parse().unwrap();
        let config = RangeConfig {start,end,netmask,broadcast,lease_time,lease_time_explicit};
        let mut state = ContextState::new(&config); state.epoch = epoch;
        configs.push(config); states.push(state);
    }
    for step in 0..steps {
        let incoming = words.next().unwrap().parse().unwrap();
        let count: usize = words.next().unwrap().parse().unwrap();
        let mut interfaces = Vec::new();
        for _ in 0..count {
            interfaces.push(Ipv4Interface {
                index: words.next().unwrap().parse().unwrap(),
                address: words.next().unwrap().parse().unwrap(),
                netmask: words.next().unwrap().parse().unwrap(),
                broadcast: words.next().unwrap().parse().unwrap(),
                loopback: words.next().unwrap() == "1",
            });
        }
        for c in select_contexts(&configs, &mut states, &interfaces, incoming) {
            println!("selected {} {} {} {} {} {} {} {} {} {}", step, c.source_index,
                c.range.start,c.range.end,c.range.netmask,c.broadcast,c.range.router,
                c.range.local,c.range.lease_time,c.range.epoch);
        }
        for (i, state) in states.iter().enumerate() {
            println!("state {} {} {} {} {} {} {}", step,i,state.netmask,state.broadcast,
                state.router,state.local,state.epoch);
        }
    }
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(args, out):
    source = args.source.resolve() / "src/dhcp.c"
    if sha(source) != DHCP_SHA:
        raise SystemExit("exact dhcp.c identity mismatch")
    text = source.read_text()
    begin = text.index("static void guess_range_netmask(")
    end = text.index("struct dhcp_context *address_available(", begin)
    bodies = text[begin:end]
    (out / "state.c").write_text(C_DRIVER.replace("/* EXACT_BODIES */", bodies))
    reference = args.reference_build.resolve()
    objects, deps = reference / "dnsmasq", reference / "deps"
    if sha(objects / "dhcp.c") != DHCP_SHA:
        raise SystemExit("reference build dhcp.c identity mismatch")
    renamed = out / "dnsmasq-without-main.o"
    subprocess.run(["objcopy", "--redefine-sym", "main=reference_main", str(objects / "dnsmasq.o"), str(renamed)], check=True)
    flags = ["-DHAVE_UBUS", "-DHAVE_POLL_H", "-DNO_DHCP6", "-DNO_AUTH", "-DNO_IPSET", "-DNO_ID"]
    subprocess.run(["cc", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", *flags,
                    "-I" + str(objects), "-I" + str(deps / "include"), str(out / "state.c"), str(renamed),
                    *(str(p) for p in sorted(objects.glob("*.o")) if p.name != "dnsmasq.o"),
                    "-L" + str(deps / "lib"), "-Wl,-rpath," + str(deps / "lib"), "-lubus", "-lubox",
                    "-o", str(out / "c-state")], check=True)
    if not args.c_only:
        driver = RUST_DRIVER
        for marker, path in {"CONFIG":"config/mod.rs", "HOSTS":"hosts.rs", "INTERFACES":"interfaces.rs",
                             "LEASE_FILE":"dhcp/lease_file.rs", "LEASE":"dhcp/lease.rs", "ALLOCATION":"dhcp/allocation.rs", "CONTEXT":"dhcp/context.rs"}.items():
            driver = driver.replace(marker, str(ROOT / "components/dnsmasq/src" / path))
        (out / "state.rs").write_text(driver)
        subprocess.run([args.rustc, "--edition=2021", "-A", "dead_code", "-A", "unused_imports",
                        str(out / "state.rs"), "-o", str(out / "rust-state")], check=True)
    return hashlib.sha256(bodies.encode()).hexdigest()


def corpus():
    def pool(start="192.0.2.10", end="192.0.2.20", mask="-", broadcast="-", epoch=9):
        return (start, end, mask, broadcast, 3600, 0, epoch)
    def iface(index=2, address="192.0.2.1", mask="255.255.255.0", broadcast="192.0.2.255"):
        return (index, address, mask, broadcast, 0)
    rows = [
        ("implicit", [pool()], [(2, [iface()])]),
        ("explicit-mask-zero", [pool(mask="0.0.0.0")], [(2, [iface()])]),
        ("explicit-broadcast-zero", [pool(broadcast="0.0.0.0")], [(2, [iface()])]),
        ("explicit-broadcast", [pool(broadcast="203.0.113.255")], [(2, [iface()])]),
        ("fallback-broadcast", [pool()], [(2, [iface(broadcast="203.0.113.255")])]),
        ("alias-order", [pool()], [(2, [iface(), iface(address="192.0.2.2")])]),
        ("preferred-alias-prepass", [pool()], [(2, [iface(address="192.0.2.2"), iface(), iface(address="192.0.2.2")])]),
        ("wrong-incoming-interface", [pool()], [(7, [iface()])]),
        ("other-interface-guesses-mask", [pool()], [(2, [iface(index=7), iface(mask="255.255.255.255")])]),
        ("later-interface-updates-linked-mask", [pool()], [(2, [iface(), iface(index=7, mask="255.255.0.0", broadcast="192.0.255.255")])]),
        ("context-head-order", [pool(epoch=8), pool("192.0.2.30", "192.0.2.40", epoch=17)], [(2, [iface()])]),
        ("subnet-interface-order", [pool(), pool("198.51.100.10", "198.51.100.20")], [(2, [iface(), iface(address="198.51.100.1", broadcast="198.51.100.255")])]),
        ("persistent-mask-after-interface-change", [pool()], [(2, [iface()]), (2, [iface(address="192.0.2.5", mask="255.255.255.252", broadcast="192.0.2.7")])]),
        ("interface-disappear-reappear", [pool()], [(2, [iface()]), (2, []), (2, [iface(address="192.0.2.2")])]),
        ("partial-guess", [pool("192.0.2.10", "198.51.100.20")], [(2, [iface()])]),
        ("single-address-mask", [pool("192.0.2.1", "192.0.2.1", "255.255.255.255")], [(2, [iface()])]),
        ("empty", [], [(2, [iface()])]),
    ]
    rng = random.Random(0x293C)
    addresses = ["192.0.2.1", "192.0.2.5", "192.0.2.10", "192.0.2.20", "198.51.100.1"]
    masks = ["0.0.0.0", "255.255.0.0", "255.255.255.0", "255.255.255.252", "255.255.255.255"]
    for case in range(128):
        pools = []
        for _ in range(rng.randint(1, 4)):
            start, end = sorted(rng.sample(addresses, 2), key=ipaddress.IPv4Address)
            pools.append(pool(start, end, rng.choice(["-", *masks]), rng.choice(["-", "0.0.0.0", "192.0.2.255"]), rng.randrange(100)))
        steps = []
        for _ in range(rng.randint(1, 5)):
            interfaces = [iface(rng.choice([2, 7]), rng.choice(addresses), rng.choice(masks), rng.choice(["0.0.0.0", "192.0.2.255", "198.51.100.255"])) for _ in range(rng.randint(0, 5))]
            steps.append((rng.choice([2, 7]), interfaces))
        rows.append((f"seeded-{case}", pools, steps))
    return rows


def serialize(pools, steps):
    lines = [f"{len(pools)} {len(steps)}"] + [" ".join(map(str, pool)) for pool in pools]
    for incoming, interfaces in steps:
        lines.append(f"{incoming} {len(interfaces)}")
        lines += [" ".join(map(str, interface)) for interface in interfaces]
    return ("\n".join(lines) + "\n").encode()


def matches(c, rust):
    return c.returncode == 0 and not c.stderr and rust.returncode == 0 and not rust.stderr and c.stdout == rust.stdout


def summarize(rows):
    failures = [row for row in rows if not row["match"]]
    return {"success": len(rows) - len(failures), "error_count": len(failures), "failures": failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rustc", default=shutil.which("rustc") or "rustc")
    parser.add_argument("--c-only", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "private") or out.exists():
        parser.error("--out must be a new directory below private/")
    out.mkdir(parents=True)
    # Exercise the exact comparator and counter path with independent deliberate
    # output and process-status failures before running either implementation.
    fixture = subprocess.CompletedProcess([], 0, b"state 0 0 255.255.255.0\n", b"")
    calibration = summarize([
        {"match": matches(fixture, fixture)},
        {"match": matches(fixture, subprocess.CompletedProcess([], 0, b"wrong\n", b""))},
        {"match": matches(fixture, subprocess.CompletedProcess([], 1, fixture.stdout, b""))},
    ])
    assert (calibration["success"], calibration["error_count"]) == (1, 2)
    extracted_sha = build(args, out)
    rows = []
    selected, steps_count, selected_steps = 0, 0, 0
    for index, (label, pools, steps) in enumerate(corpus()):
        wire = serialize(pools, steps)
        (out / f"{index:03}.input").write_bytes(wire)
        observations = []
        for binary in (["c-state"] if args.c_only else ["c-state", "rust-state"]):
            run = subprocess.run([str(out / binary)], input=wire, capture_output=True)
            (out / f"{index:03}.{binary}.stdout").write_bytes(run.stdout)
            (out / f"{index:03}.{binary}.stderr").write_bytes(run.stderr)
            observations.append(run)
        c = observations[0]
        selected += sum(line.startswith(b"selected ") for line in c.stdout.splitlines())
        selected_steps += len({line.split()[1] for line in c.stdout.splitlines() if line.startswith(b"selected ")})
        steps_count += len(steps)
        good = c.returncode == 0 and not c.stderr
        if not args.c_only:
            rust = observations[1]
            good = matches(c, rust)
        rows.append({"case": index, "label": label, "steps": len(steps), "c_exit": c.returncode, "match": good})
    # Frozen from the C-only baseline, not generated by Rust.
    assert (len(rows), steps_count, selected, selected_steps) == (145, 402, 162, 120)
    report = {"cases": len(rows), "steps": steps_count, "selected_contexts": selected,
              "steps_with_context": selected_steps, "steps_without_context": steps_count - selected_steps,
              **summarize(rows), "calibration": calibration,
              "dhcp_c_sha256": DHCP_SHA, "extracted_bodies_sha256": extracted_sha,
              "c_oracle_sha256": sha(out / "c-state"), "rows": rows,
              "rust_probe_sha256": None if args.c_only else sha(out / "rust-state"),
              "tool_sha256": sha(Path(__file__)),
              "rust_sources": {} if args.c_only else {name: sha(ROOT / "components/dnsmasq/src" / name) for name in
                  ("config/dhcp.rs", "interfaces.rs", "dhcp/context.rs", "dhcp/allocation.rs", "dhcp/lease.rs", "dhcp/lease_file.rs")},
              "scope": "Dynamic unrelayed context selection/state; excludes admission and warning logs"}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "rows"}, indent=2))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
