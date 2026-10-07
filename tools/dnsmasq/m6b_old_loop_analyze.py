#!/usr/bin/env python3
"""Attribute frozen M5 loop behavior using bounded, retrospective diagnostics."""

import argparse
import hashlib
import json
import math
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def delta(last, first, key):
    value = last[key] - first[key]
    if value < 0:
        raise ValueError(f"counter went backwards: {key}")
    return value


def percentile_bounds(upper, counts, fraction):
    rank = math.ceil(sum(counts) * fraction)
    if rank == 0:
        return None
    lower = 0
    for high, count in zip(upper, counts):
        rank -= count
        if rank <= 0:
            return [lower, high]
        lower = high + 1
    raise ValueError("invalid histogram")


def analyze(window, history):
    load = json.loads((window / "load.json").read_text())
    telemetry = json.loads((window / "wake-counters.json").read_text())
    raw = [json.loads(line) for line in history.read_text().splitlines() if line.strip()]
    by_time = {row["monotonic_ns"]: row for row in raw}
    if len(by_time) != len(raw) or not all(row["schema"] == "m5-old-loop-v1" for row in raw):
        raise ValueError("duplicate or unknown raw snapshot")
    # A two-second margin exceeds the one-second snapshot publication period.
    # Match raw histogram rows by their exact product monotonic ID, rather than
    # treating repeated controller observations as additional poll samples.
    selected = {}
    for sample in telemetry["samples"]:
        elapsed = sample["measurement_elapsed_seconds"]
        if 2 <= elapsed <= load["measurement_seconds"] - 2:
            timestamp = sample["counters"]["monotonic_ns"]
            if timestamp not in by_time:
                raise ValueError("controller snapshot has no preserved raw histogram")
            selected[timestamp] = by_time[timestamp]
    if len(selected) < 4:
        raise ValueError("insufficient distinct interior snapshots")
    first, last = (selected[key] for key in (min(selected), max(selected)))
    elapsed = (last["monotonic_ns"] - first["monotonic_ns"]) / 1e9
    loops, polls, waits = (delta(last, first, key) for key in
                          ("loop_rounds", "poll_calls", "poll_wait_ns"))
    hist = [after - before for before, after in
            zip(first["wait_histogram_counts"], last["wait_histogram_counts"])]
    if len(hist) != len(last["wait_histogram_upper_ns"]) or any(value < 0 for value in hist):
        raise ValueError("invalid histogram delta")
    if sum(hist) != polls or not polls or elapsed <= 0:
        raise ValueError("histogram does not account for every ordinary poll")
    if len(first["udp_listeners"]) != len(last["udp_listeners"]):
        raise ValueError("listener topology changed")
    listeners = [{key: delta(after, before, key) for key in after}
                 for before, after in zip(first["udp_listeners"], last["udp_listeners"])]
    packets = sum(row["udp_packets"] for row in listeners)
    source = {key: delta(last, first, key) for key in
              ("probe_poll_calls", "probe_poll_wait_ns", "arp_poll_calls", "arp_poll_wait_ns")}
    if source["probe_poll_calls"] or source["arp_poll_calls"]:
        raise ValueError("DNS-only attribution mixed in probe or ARP polls")
    if last["ordinary_poll_fd_max"]["dns_udp"] or last["ordinary_poll_fd_max"]["dns_tcp"]:
        raise ValueError("ordinary file poll unexpectedly contained DNS listeners")
    for listener in listeners:
        if listener["udp_packets"] > listener["step_udp_calls"]:
            raise ValueError("more than one UDP packet per listener step")
        if listener["alloc_count"] != listener["receive_attempts"]:
            raise ValueError("allocation/receive count mismatch")
        if listener["alloc_bytes"] != listener["alloc_count"] * 65_535:
            raise ValueError("unexpected receive allocation size")
    correct = load["measurement"]["correct"]
    errors = {key: load["measurement"][key] for key in ("wrong", "timeout", "transport_error")}
    return {
        "scope": "retrospective diagnostics of M5 dc1b740d; no formal performance qualification",
        "inputs": {str(path): digest(path) for path in
                   (window / "load.json", window / "wake-counters.json", history)},
        "distinct_interior_snapshots": len(selected), "interval_seconds": elapsed,
        "first_product_monotonic_ns": first["monotonic_ns"],
        "last_product_monotonic_ns": last["monotonic_ns"],
        "loops": loops, "polls": polls, "udp_packets": packets,
        "loops_per_second": loops / elapsed, "polls_per_second": polls / elapsed,
        "udp_packets_per_second": packets / elapsed,
        "udp_packets_per_loop": packets / loops if loops else None,
        "ordinary_poll_wait_mean_ns": waits / polls,
        "ordinary_poll_wait_p50_bounds_ns": percentile_bounds(last["wait_histogram_upper_ns"], hist, .5),
        "ordinary_poll_wait_p95_bounds_ns": percentile_bounds(last["wait_histogram_upper_ns"], hist, .95),
        "ordinary_poll_fd_max": last["ordinary_poll_fd_max"],
        "nested_poll_delta": source, "listener_deltas": listeners,
        "measurement_correct": correct, "measurement_errors": errors,
        "correct_answers_per_second": correct / load["measurement_seconds"],
        "answer_denominator_note": "load measurement correct is a full phase; counter rates use the shorter interior interval",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--window", type=Path, required=True)
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("fresh output required")
    args.output.write_text(json.dumps(analyze(args.window, args.history), indent=2) + "\n")


if __name__ == "__main__":
    main()
