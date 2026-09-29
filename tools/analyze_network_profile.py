#!/usr/bin/env python3
"""Derive address-free summaries from complete LAN and software/hardware trials."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics


def read(path):
    return json.loads(path.read_text())


def distribution(values):
    return {"min": min(values), "median": statistics.median(values), "max": max(values)}


def latency(records):
    values = sorted(r["ms"] for r in records if "ms" in r)
    assert values, "no successful TCP probes"
    return {"samples": len(records), "failures": len(records)-len(values),
            "p50_ms": statistics.median(values),
            "p95_ms": values[math.ceil(len(values)*0.95)-1], "max_ms": max(values)}


def window(root, kind):
    rows = read(root / "summary.json")
    expected = {(i, d) for i in range(1, 4) for d in ("upload", "download")} if kind == "lan" else set(range(1, 4))
    actual = [(r["trial"], r["direction"]) if kind == "lan" else r["trial"] for r in rows]
    assert len(actual) == len(expected) and set(actual) == expected, f"incomplete or duplicate window: {root.name}"
    result = {"rounds": rows, "idle_tcp": latency(read(root / "idle-probes.json"))}
    for direction in (("upload", "download") if kind == "lan" else ("simultaneous",)):
        selected = [r for r in rows if kind != "lan" or r["direction"] == direction]
        records = []
        for row in selected:
            name = f"{row['trial']:02}-{direction}-probes.json" if kind == "lan" else f"{row['trial']:02}.probes.json"
            records.extend(read(root / name))
        item = {"router_cpu_pct": distribution([r["router_cpu"]["cpu"]["busy_pct"] for r in selected]),
                "loaded_tcp": latency(records)}
        if kind == "lan":
            item["receiver_mbps"] = distribution([r["receiver_mbps"] for r in selected])
            item["sender_retransmits"] = [r["sender_retransmits"] for r in selected]
        else:
            for key in ("download_mbps", "upload_mbps", "base_rtt_ms", "responsiveness_rpm"):
                item[key] = distribution([r[key] for r in selected])
        result[direction] = item
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    roots = {"lan": "lan-terminal-baseline", "software_before": "wan-final-software-before",
             "hardware": "wan-final-hardware", "software_after": "wan-final-software-after"}
    result = {"date": "2026-09-29", "firmware": "ax3000t-rust9-v0.1.0", "iperf": "3.21",
              "tcp_p95_method": "nearest rank, successful probes only; failed probes counted separately",
              "network_path": "LAN: Mac Wi-Fi to Windows gigabit LAN; WAN: Mac Wi-Fi to Apple HTTPS endpoints",
              "pure_wired_WAN_measured": False,
              "windows_sender_TCP_retransmit_count": "unavailable, not zero",
              "windows": {k: window(args.raw / name, "lan" if k == "lan" else "wan") for k, name in roots.items()}}
    before = result["windows"]["software_before"]
    hardware = result["windows"]["hardware"]
    after = result["windows"]["software_after"]
    refs = before["rounds"] + after["rounds"]
    cpu_ref = statistics.median(r["router_cpu"]["cpu"]["busy_pct"] for r in refs)
    candidate = hardware["simultaneous"]
    delta = {"cpu_pct": (candidate["router_cpu_pct"]["median"]/cpu_ref-1)*100}
    for key in ("download_mbps", "upload_mbps"):
        reference = statistics.median(r[key] for r in refs)
        delta[key] = (candidate[key]["median"]/reference-1)*100
    reference_probes = [w["simultaneous"]["loaded_tcp"] for w in (before, after)]
    hardware_counts = []
    snapshots = [args.raw / roots["hardware"] / f"{trial:02}.{phase}.txt"
                 for trial in range(1, 4) for phase in ("before", "after")]
    for path in snapshots:
        text = path.read_text()
        if "@@flow_counts\n" in text:
            fields = text.split("@@flow_counts\n", 1)[1].split()
            if len(fields) == 3:
                hardware_counts.append(int(fields[2]))
    gates = {"hardware_connections_observed_on_router": any(hardware_counts),
             "cpu_reduction_at_least_15pct": delta["cpu_pct"] <= -15,
             "download_not_down_over_10pct": delta["download_mbps"] >= -10,
             "upload_not_down_over_10pct": delta["upload_mbps"] >= -10,
             "tcp_failures_not_above_either_software_window": candidate["loaded_tcp"]["failures"] <= min(p["failures"] for p in reference_probes),
             "tcp_p95_not_up_over_20pct_against_either_software_window": candidate["loaded_tcp"]["p95_ms"] <= min(p["p95_ms"] for p in reference_probes)*1.2}
    result["hardware_candidate"] = {"delta_vs_six_software_round_medians_pct": delta,
                                    "whole_router_hardware_connection_samples": hardware_counts,
                                    "hardware_sample_order": "trial 1 before/after, trial 2 before/after, trial 3 before/after",
                                    "hardware_sample_scope": "all clients, not proof every measured flow used hardware",
                                    "gates": gates, "accepted": all(gates.values())}
    result["raw_sha256"] = {str(p.relative_to(args.raw)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for name in roots.values() for p in sorted((args.raw / name).iterdir()) if p.is_file()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["hardware_candidate"], indent=2))


if __name__ == "__main__":
    main()
