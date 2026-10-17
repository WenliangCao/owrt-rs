#!/usr/bin/env python3
"""Derive address-free timing/counts from one private boot capture directory.

Kernel log receive timestamps provide an approximate pre-NTP clock anchor.
Neither these intervals nor protocol setup envelopes are pure script CPU time.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    base = args.directory
    raw = (base / "logread-ms-resumed.txt").read_bytes()
    rows = []
    for number, line in enumerate(raw.decode().splitlines(), 1):
        match = re.search(r"\[(\d+)\.(\d{3})\]", line)
        if match:
            rows.append(dict(line=number, ms=int(match[1]) * 1000 + int(match[2]), text=line))
    jumps = [(a, b) for a, b in zip(rows, rows[1:]) if abs(b["ms"] - a["ms"]) > 300_000]
    assert len(jumps) == 1, "this capture requires exactly two clock segments"
    split = jumps[0][1]["line"]
    offsets = []
    for row in rows:
        match = re.search(r"kernel: \[\s*(\d+\.\d+)\]", row["text"])
        if row["line"] < split and match and float(match[1]) >= 15:
            offsets.append(row["ms"] / 1000 - float(match[1]))
    assert offsets, "missing live kernel anchor after buffered early boot messages"
    old_offset = statistics.median(offsets)
    anchor = json.loads((base / "boot-anchor-refined.json").read_text())
    new_offset = statistics.mean([anchor["boot_zero_unix_lower"], anchor["boot_zero_unix_upper"]])

    def boot_seconds(row):
        return row["ms"] / 1000 - (old_offset if row["line"] < split else new_offset)

    def selected(pattern):
        return [r for r in rows if re.search(pattern, r["text"])]

    def event(row):
        return dict(line=row["line"], epoch_ms=row["ms"], boot_seconds_estimate=round(boot_seconds(row), 3))

    def same_clock_intervals(records):
        return [b["ms"] - a["ms"] for a, b in zip(records, records[1:])
                if (a["line"] < split) == (b["line"] < split)]

    def stats(values):
        return dict(count=len(values), min=min(values), mean=statistics.mean(values), median=statistics.median(values),
                    max=max(values), values=values) if values else None

    leases = selected(r"netifd: wan \(\d+\): udhcpc: lease of ")
    wan_up = selected(r"Interface 'wan' is now up")
    wan6_up = selected(r"Interface 'wan6' is now up")
    fw = selected(r"firewall: Reloading firewall")
    updates = [r for r in fw if "due to ifupdate " in r["text"]]
    starts = selected(r"dnsmasq.*started, version")
    exits = selected(r"dnsmasq.*exiting on receipt of SIGTERM")
    setup = {name: selected(r"Interface '" + name + r"' is setting up now")[0] for name in ("wan", "wan6")}
    assert len(wan_up) == len(wan6_up) == 1
    result = dict(
        raw_sha256=hashlib.sha256(raw).hexdigest(), raw_bytes=len(raw), log_lines=len(rows),
        clock=dict(jump_before_line=split, adjacent_jump_ms=jumps[0][1]["ms"]-jumps[0][0]["ms"],
                   old_anchor_samples=len(offsets), old_anchor_spread_ms=round((max(offsets)-min(offsets))*1000, 3),
                   post_clock_boot_zero_interval=[anchor["boot_zero_unix_lower"], anchor["boot_zero_unix_upper"]]),
        wan=dict(lease_events=[event(r) for r in leases], initial_up=event(wan_up[0]),
                 initial_lease_to_up_ms=wan_up[0]["ms"]-leases[0]["ms"],
                 renewals_without_new_up=len(leases)-1, same_clock_lease_intervals_ms=stats(same_clock_intervals(leases))),
        wan6=dict(initial_up=event(wan6_up[0])),
        firewall=dict(trigger_count=len(fw), ifup_count=len(fw)-len(updates), ifupdate_count=len(updates),
                      events=[event(r) for r in fw], same_clock_all_intervals_ms=stats(same_clock_intervals(fw)),
                      wan6_ifupdate_intervals_ms=stats(same_clock_intervals(updates)), completion_durations_ms=None),
        dnsmasq=dict(starts=[event(r) for r in starts], terminations=[event(r) for r in exits],
                     observed_restarts=len(exits), hosts_read_batches=[event(r) for r in selected(r"dnsmasq.*read /etc/hosts -")],
                     reported_lost_messages=sum(int(re.search(r"overflow: (\d+)", r["text"])[1])
                                                for r in selected(r"dnsmasq.*overflow: \d+"))),
        script_timing=dict(pure_total_ms=None, reason="No complete DHCP script/hotplug entry and exit markers",
                           protocol_setup_sum_ms=wan_up[0]["ms"]-setup["wan"]["ms"]+wan6_up[0]["ms"]-setup["wan6"]["ms"],
                           protocol_setup_union_ms=wan6_up[0]["ms"]-setup["wan"]["ms"],
                           qualification="Protocol setup envelopes include network waits and netifd; not a total-script-time bound"))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
