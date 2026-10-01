#!/usr/bin/env python3
"""C-only review of whether real cache callers create the collider state.

Uses actual extract_addresses, cache_add_dhcp_entry, cache_unhash_dhcp and
cache_reload; it never injects a local record through the H fixture operation.
"""
import argparse
import json
from pathlib import Path
import subprocess

from cache_answer_diff import name, packet
import lease_cache_diff

FORWARD, DHCP, HOSTS, CONFIG, IPV4, CNAME = 8, 16, 64, 8192, 128, 2048


def states(line):
    assert line.startswith("E")
    return [tuple(map(int, record.split(":"))) for record in line.split()[1:]]


def coexist(entries):
    live = [entry for entry in entries if not entry[2] and not entry[3]]
    local = any(flags & DHCP and flags & IPV4 for _, flags, _, _ in live)
    dynamic = any(flags & (IPV4 | CNAME) and not flags & (DHCP | HOSTS | CONFIG) for _, flags, _, _ in live)
    return local and dynamic


def corpus():
    a = ("lease.test", 1, 90, bytes([192, 0, 2, 99]))
    cn = ("lease.test", 5, 90, name("target.test"))
    target = ("target.test", 1, 90, bytes([192, 0, 2, 100]))
    packets = [("a", packet("lease.test", 1, 0x8180, [a])),
               ("cname", packet("lease.test", 1, 0x8180, [cn, target])),
               ("a-before-cname", packet("lease.test", 1, 0x8180, [a, cn, target])),
               ("aaaa", packet("lease.test", 28, 0x8180, [("lease.test", 28, 90, bytes.fromhex("20010db8000000000000000000000009"))])),
               ("nxdomain", packet("lease.test", 1, 0x8183))]
    configs = [("plain", ""), ("static-a", "host-record=lease.test,192.0.2.9\n"),
               ("static-aaaa", "host-record=lease.test,2001:db8::9\n"),
               ("static-cname", "cname=lease.test,target.test\nhost-record=target.test,192.0.2.9\n"),
               ("lease-nonreverse", "host-record=address-owner.test,192.0.2.7\n")]
    for conf_label, config in configs:
        for packet_label, response in packets:
            for order in ["response-first", "lease-first", "duplicate-and-reload"]:
                yield f"{conf_label}/{packet_label}/{order}", config, response, order


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reference-build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(); out = args.output.resolve()
    assert out.is_relative_to(lease_cache_diff.ROOT / "private") and not out.exists()
    args.reference_build = args.reference_build.resolve(); out.mkdir(parents=True)
    c = lease_cache_diff.build_c(args, out)
    assert coexist([(1, FORWARD | DHCP | IPV4, 0, 0), (1, FORWARD | IPV4, 0, 0)])
    assert not coexist([(1, FORWARD | DHCP | IPV4, 0, 0), (5, FORWARD | CNAME, 1, 0)])
    rows, failures, commands_total = [], [], 0
    for no_round in [False, True]:
        for same in [False, True]:
            for index, (label, extra, response, order) in enumerate(corpus()):
                base = out / f"{int(no_round)}-{int(same)}-{index:02}"
                config = base.with_suffix(".conf")
                config.write_text("no-hosts\nno-resolv\ncache-size=16\nneg-ttl=60\n" + extra + ("no-round-robin\n" if no_round else ""))
                with base.with_suffix(".stderr").open("w") as log:
                    oracle = subprocess.Popen([str(c), "-C", str(config)], stdin=subprocess.PIPE,
                                              stdout=subprocess.PIPE, stderr=log, text=True)
                    selection = f"X lease.test {int(same)}\n"
                    oracle.stdin.write(selection); oracle.stdin.flush()
                    chosen = oracle.stdout.readline().strip(); assert chosen.startswith("X collision")
                    other = chosen.split()[1]
                    verification = f"V lease.test {other}\n"
                    oracle.stdin.write(verification); oracle.stdin.flush()
                    verified = oracle.stdout.readline().strip(); assert verified == f"V {int(same)}"
                    incoming = f"P 100 {response.hex()}"
                    collision = f"P 100 {packet(other, 1, 0x8180, [(other, 1, 90, bytes([192, 0, 2, 88]))]).hex()}"
                    prefix = ["R", "D lease.test", "E lease.test", incoming] if order == "lease-first" else [incoming]
                    commands = prefix + ["E lease.test", collision, "R", "D lease.test", "E lease.test"]
                    if order == "duplicate-and-reload":
                        commands += ["D lease.test", "E lease.test", "S", "E lease.test", "R", "D lease.test", "E lease.test"]
                    commands += [f"W 100 {packet('lease.test', kind).hex()}" for kind in [1, 28, 5]]
                    commands += ["E lease.test"]
                    wire = "\n".join(commands) + "\n"
                    output, _ = oracle.communicate(wire, timeout=10); assert oracle.returncode == 0
                results = output.splitlines(); assert len(results) == len(commands)
                base.with_suffix(".input").write_text(selection + verification + wire)
                base.with_suffix(".stdout").write_text(chosen + "\n" + verified + "\n" + output)
                violations = [i for i, (command, result) in enumerate(zip(commands, results)) if command.startswith("E ") and coexist(states(result))]
                row = {"label": label, "no_round_robin": no_round, "same_c_bucket": same,
                       "commands": len(commands), "coexistence_lines": violations}
                rows.append(row); commands_total += len(commands)
                if violations: failures.append(row)
                if index == 0:
                    after = commands.index("D lease.test") + 1
                    assert any(flags & DHCP for _, flags, _, _ in states(results[after])), "real DHCP publication missing"
    report = {"c_sha256": lease_cache_diff.digest(c), "scope": "C-only real-caller reachability review; finite corpus does not prove all initial states unreachable",
              "calibration": {"coexistence_detected": 1, "outdated_cname_excluded": 1, "real_dhcp_entry": 4},
              "cases": len(rows), "commands": commands_total, "rows": rows, "failures": failures}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "rows"}))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
