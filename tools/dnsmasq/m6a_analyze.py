#!/usr/bin/env python3
"""Offline M6a analysis, using the frozen protocol and explicit valid attempts.

No network access or product changes. --output PREFIX creates PREFIX.json,
PREFIX.windows.csv and PREFIX.comparisons.csv. Missing state.json permits
diagnostic window analysis only; it never selects a replacement attempt.
"""
from __future__ import annotations

import argparse
from array import array
from bisect import bisect_right
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct

from dns_service_probe import read_name, semantics

LATENCY = struct.Struct("<QQQHHBBBB")
LAG = struct.Struct("<QQ")
PROFILES = ("udp-hit", "udp-miss", "dns-mixed", "upstream-fault", "tcp-local",
            "tcp-cache", "tcp-miss", "dhcp-lease", "reload-concurrent")
GROUPS = ("C", "R3", "Rs")
STATUS = ("correct", "timeout", "wrong", "transport_error")
RESOURCE_KEYS = ("rss_kib", "pss_kib", "fd_count", "thread_count", "child_processes")


class EvidenceError(ValueError):
    pass


def read_json(path):
    return json.loads(Path(path).read_text())


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def percentile(values, fraction):
    """Nearest rank, without interpolation or exclusion of slow successes."""
    if not values:
        return None
    return values[max(0, math.ceil(len(values) * fraction) - 1)]


def quantiles(values, p99=True):
    ordered = sorted(values)
    return {"sample_count": len(ordered), "p50": percentile(ordered, .50),
            "p95": percentile(ordered, .95),
            "p99": percentile(ordered, .99) if p99 and len(ordered) >= 10000 else None,
            "p99_reason": "not requested" if not p99 else None if len(ordered) >= 10000 else "fewer than 10000 correct samples",
            "max": ordered[-1] if ordered else None}


def profile_for(identity):
    scenario = identity["scenario"]
    if scenario == "tcp":
        return {"local": "tcp-local", "hit": "tcp-cache", "miss": "tcp-miss"}[identity["tcp_profile"]]
    return {"hit": "udp-hit", "miss": "udp-miss", "mixed": "dns-mixed",
            "fault": "upstream-fault", "dhcp": "dhcp-lease", "reload": "reload-concurrent"}[scenario]


def group_for(identity):
    return {"c": "C", "r3": "R3", "rs": "Rs"}[identity["implementation"]]


def phase_intervals(identity, epoch, points):
    start, end = epoch["measurement_start_ns"], epoch["measurement_end_ns"]
    if end <= start:
        raise EvidenceError("measurement end does not follow start")
    if identity["scenario"] == "fault":
        fault_start = points["fault-start"]["scheduled_monotonic_ns"]
        fault_end = points["fault-end"]["scheduled_monotonic_ns"]
        bounds = [("before-fault", start, fault_start, "measurement-start", "fault-start"),
                  ("fault", fault_start, fault_end, "fault-start", "fault-end"),
                  ("recovery", fault_end, end, "fault-end", "measurement-end")]
    elif identity.get("saturation_seconds", 0):
        middle = epoch["saturation_start_ns"]
        bounds = [("steady", start, middle, "measurement-start", "saturation-start"),
                  ("saturation", middle, end, "saturation-start", "measurement-end")]
    else:
        bounds = [("steady", start, end, "measurement-start", "measurement-end")]
    if any(right <= left for _, left, right, _, _ in bounds):
        raise EvidenceError("phase boundaries are not ordered")
    return bounds


def empty_phase(label, start, end, cpu_left=None, cpu_right=None):
    return {"phase": label, "start_ns": start, "end_ns": end,
            "seconds": (end - start) / 1e9, "cpu_left": cpu_left, "cpu_right": cpu_right,
            "origin_counts": dict.fromkeys(STATUS, 0),
            "completion_counts": dict.fromkeys(STATUS, 0),
            "cross_phase_completions": dict.fromkeys(STATUS, 0),
            "qtype_origin_counts": {}, "kind_origin_counts": {},
            "correct_origin_late": 0, "correct_origin_cross_phase": 0,
            "latencies": array("Q"), "origin_latencies": array("Q"), "send_lags": array("Q"),
            "success_completion_ns": array("Q")}


def binary_records(path, definition):
    """Read bounded chunks; reject truncation instead of ignoring a tail."""
    with path.open("rb") as stream:
        while block := stream.read(definition.size * 32768):
            if len(block) % definition.size:
                raise EvidenceError(f"truncated {path.name}: {len(block)} byte chunk")
            yield from definition.iter_unpack(block)


def worker_cpu(samples, label):
    rows = [(row["monotonic_ns"], row[label]) for row in samples
            if label in row and "user_ticks" in row[label] and "system_ticks" in row[label]]
    if len(rows) < 2:
        return {"cpu_seconds": None, "single_core_fraction": None, "sample_span_seconds": None}
    first_ns, first = rows[0]
    last_ns, last = rows[-1]
    if first.get("starttime_ticks") != last.get("starttime_ticks") or first.get("pid") != last.get("pid"):
        raise EvidenceError(f"{label} process identity changed during a phase")
    ticks = last["user_ticks"] + last["system_ticks"] - first["user_ticks"] - first["system_ticks"]
    hz = samples[0]["clock_ticks_per_second"]
    span = (last_ns - first_ns) / 1e9
    if ticks < 0 or span <= 0:
        raise EvidenceError(f"invalid sampled {label} CPU delta")
    cpu = ticks / hz
    return {"cpu_seconds": cpu, "single_core_fraction": cpu / span,
            "sample_span_seconds": span, "resolution_seconds": 1 / hz,
            "method": "sampled process self user+system ticks; excludes boundary gaps"}


def resource_summary(samples, phase):
    rows = [row for row in samples if phase["start_ns"] <= row["monotonic_ns"] < phase["end_ns"]]
    peaks = {key: max((row["tree"][key] for row in rows), default=None) for key in RESOURCE_KEYS}
    quarters = []
    for index in range(4):
        left = phase["start_ns"] + (phase["end_ns"] - phase["start_ns"]) * index // 4
        right = phase["start_ns"] + (phase["end_ns"] - phase["start_ns"]) * (index + 1) // 4
        quarter = [row for row in rows if left <= row["monotonic_ns"] < right]
        quarters.append({"quarter": index + 1, "sample_count": len(quarter),
                         **{key: max((row["tree"][key] for row in quarter), default=None)
                            for key in RESOURCE_KEYS}})
    return {"sample_count": len(rows), "sampled_tree_peaks": peaks, "quarters": quarters,
            "parent_hwm_kib": max((row["parent"].get("hwm_kib", 0) for row in rows), default=None),
            "loadgen_cpu": worker_cpu(rows, "loadgen"), "upstream_cpu": worker_cpu(rows, "upstream"),
            "tftp_cpu": worker_cpu(rows, "tftp"),
            "rss_note": "tree RSS sums shared pages repeatedly; tree PSS is the total-memory comparison"}


def maximum_gap(values, left, right):
    ordered = sorted(values)
    maximum, previous = 0, left
    for value in ordered:
        maximum = max(maximum, value - previous)
        previous = value
    return max(maximum, right - previous)


def sample_dns_correct(query, reply):
    try:
        q, r = semantics(query), semantics(reply)
        if r["id"] != q["id"] or r["flags"] & 0x820f != 0x8000 or r["questions"] != q["questions"] or len(q["questions"]) != 1:
            return False
        host, kind, klass = q["questions"][0]
        if klass != 1:
            return False
        cname = host.startswith("cname-")
        if cname and kind != 1:
            return False
        records = r["records"]
        answers = [record for record in records if record["section"] == "answer"]
        if len(answers) != (2 if cname else 1) or any(record["section"] != "answer" for record in records):
            return False
        expected = [{"section": "answer", "name": host, "type": 5, "class": 1, "data": "m6a.target"}] if cname else []
        expected.append({"section": "answer", "name": "m6a.target" if cname else host,
                         "type": kind, "class": 1,
                         "data": {1: "192.0.2.1", 28: "2001:db8::1", 16: "036d3661"}[kind]})
        if any(not 0 < record["ttl"] <= 3600 for record in answers):
            return False
        stripped = [{key: value for key, value in record.items() if key != "ttl"} for record in answers]
        if sorted(stripped, key=lambda x: x["type"]) != sorted(expected, key=lambda x: x["type"]):
            return False
        position = 12
        qd, an, ns, ar = struct.unpack_from("!4H", reply, 4)
        for _ in range(qd):
            _, position = read_name(reply, position)
            position += 4
        for _ in range(an + ns + ar):
            _, position = read_name(reply, position)
            size = struct.unpack_from("!H", reply, position + 8)[0]
            position += 10 + size
        return position == len(reply)
    except (ValueError, KeyError, IndexError, struct.error):
        return False


def sample_dhcp_correct(query, reply, stage):
    if len(reply) < 241 or len(query) < 240 or reply[:3] != b"\x02\x01\x06" or reply[4:8] != query[4:8] or reply[28:34] != query[28:34] or reply[236:240] != b"\x63\x82\x53\x63":
        return False
    expected_address = bytes((127, 0, 0, 10 + query[33]))
    if reply[16:20] != expected_address:
        return False
    options, offset, ended = {}, 240, False
    while offset < len(reply):
        code = reply[offset]
        offset += 1
        if code == 255:
            ended = True
            break
        if code == 0:
            continue
        if offset >= len(reply) or code in options:
            return False
        size = reply[offset]
        offset += 1
        if offset + size > len(reply):
            return False
        options[code] = reply[offset:offset + size]
        offset += size
    if not ended or options.get(53) != bytes((2 if stage == 0 else 5,)) or options.get(54) != b"\x7f\0\0\1":
        return False
    if any(len(options.get(code, b"")) != 4 for code in (51, 58, 59)):
        return False
    lease, t1, t2 = (int.from_bytes(options[code], "big") for code in (51, 58, 59))
    return lease >= 120 and 0 < t1 < t2 < lease


def verify_raw_samples(directory, dhcp):
    path = directory / "load.wire-samples.jsonl"
    if not path.exists():
        raise EvidenceError("missing independent raw wire samples")
    counts = {"warmup": 0, "measurement": 0, "declared_correct": 0, "declared_wrong": 0}
    with path.open() as stream:
        for line in stream:
            row = json.loads(line)
            query, reply = bytes.fromhex(row["query_hex"]), bytes.fromhex(row["reply_hex"])
            correct = sample_dhcp_correct(query, reply, row["dhcp_stage"]) if dhcp else sample_dns_correct(query, reply)
            if correct != row["correct"]:
                raise EvidenceError("independent raw sample disagrees with loadgen correctness")
            counts["measurement" if row["phase"] else "warmup"] += 1
            counts["declared_correct" if correct else "declared_wrong"] += 1
    return counts


def auxiliary_summary(directory, start, end):
    result = {}
    reload_path = directory / "reloads.json"
    if reload_path.exists():
        reloads = read_json(reload_path)
        successes = [row for row in reloads if row.get("publication_correct")]
        result["reload"] = {"offered": len(reloads), "correct": len(successes),
                            "errors": len(reloads) - len(successes),
                            "publication_ns": quantiles([round(row["publication_seconds"] * 1e9) for row in successes]),
                            "probe_resolution_ns": 10_000_000,
                            "note": "upper bound from 10ms probe interval plus controller scheduling gaps"}
    tftp_path = directory / "tftp-transfers.jsonl"
    if tftp_path.exists():
        rows = [json.loads(line) for line in tftp_path.read_text().splitlines()]
        measured = [row for row in rows if start <= row["send_monotonic_ns"] < end]
        correct = [row for row in measured if row["correct"]]
        completed = [row for row in correct if row["completion_monotonic_ns"] < end]
        verified = 0
        for row in correct:
            if not row.get("wire"):
                continue
            payload = bytearray()
            if len(row["wire"]) != 3:
                raise EvidenceError("sampled correct TFTP transfer missing terminal DATA block")
            for block, packet in enumerate(row["wire"], 1):
                data, ack = bytes.fromhex(packet["data"]), bytes.fromhex(packet["ack"])
                if data[:4] != struct.pack("!HH", 3, block) or ack != struct.pack("!HH", 4, block):
                    raise EvidenceError("sampled correct TFTP DATA/ACK block invalid")
                if len(data) != (4 if block == 3 else 516):
                    raise EvidenceError("sampled correct TFTP block length invalid")
                payload.extend(data[4:])
            if payload != bytes(range(256)) * 4:
                raise EvidenceError("sampled correct TFTP content invalid")
            verified += 1
        if correct and not verified:
            raise EvidenceError("measured correct TFTP has no retained wire evidence")
        result["tftp"] = {"offered": len(measured), "correct": len(correct), "errors": len(measured) - len(correct),
                          "correct_in_window": len(completed), "late_correct": len(correct) - len(completed),
                          "qps": len(completed) / ((end - start) / 1e9),
                          "latency_ns": quantiles([row["latency_ns"] for row in correct]),
                          "missed_scheduled_opportunities": sum(row["missed_scheduled_opportunities"] for row in measured),
                          "independently_verified_wire_transfers": verified,
                          "max_success_gap_ns": maximum_gap([row["completion_monotonic_ns"] for row in completed], start, end)}
    return result


def analyze_window(directory):
    directory = Path(directory)
    result = read_json(directory / "result.json")
    identity = result["identity"]
    row = {"directory": str(directory), "profile": profile_for(identity), "group": group_for(identity),
           "round": identity["round"], "pilot": bool(identity.get("excluded_preflight")),
           "methodology_valid": bool(result.get("measurement_valid", result.get("accepted", False))),
           "behavior_checks": result.get("behavior_checks"), "runner_error": result.get("error"),
           "identity": identity, "analysis_errors": []}
    if "measurement" not in result:
        row["analysis_errors"].append("runner produced no measurement")
        row["methodology_valid"] = False
        return row
    measured = result["measurement"]
    load = read_json(directory / "load.json")
    epoch = read_json(directory / "epoch.json")
    if load != measured["load"] or epoch != measured["epoch"]:
        raise EvidenceError("standalone load/epoch do not match runner result")
    points = measured["cpu_points"]
    bounds = phase_intervals(identity, epoch, points)
    phases = [empty_phase(*bound) for bound in bounds]
    full = empty_phase("measurement", epoch["measurement_start_ns"], epoch["measurement_end_ns"],
                       "measurement-start", "measurement-end")
    ends = [phase["end_ns"] for phase in phases]
    def phase_index(timestamp):
        index = bisect_right(ends, timestamp)
        if index == len(phases) or timestamp < phases[0]["start_ns"]:
            return None
        return index
    binary_counts = dict.fromkeys(STATUS, 0)
    flags = {1: dict.fromkeys(STATUS, 0), 2: dict.fromkeys(STATUS, 0)}
    outside_origin = dict.fromkeys(STATUS, 0)
    late = dict.fromkeys(STATUS, 0)
    records, flag_crossings = 0, 0
    sequence_base = (identity["seed"] << 32) & ((1 << 64) - 1)
    # DNS advances once per started request. DHCP additionally advances once
    # after DORA and once after renewal; this exactly bounds its sequence span.
    span = sum(load[label]["sent"] + load[label].get("dora_correct", 0) +
               load[label].get("renew_correct", 0) for label in ("warmup", "measurement"))
    seen_sequences = bytearray((span + 8) // 8)
    raw_lag_sum, raw_lag_max = 0, 0
    lag_records = iter(binary_records(directory / "load.send-lag.bin", LAG))
    for sequence, latency, sent, client, qtype, status, phase_flag, kind, padding in binary_records(
            directory / "load.latencies.bin", LATENCY):
        if status >= len(STATUS) or phase_flag not in (1, 2) or padding or client >= identity["clients"]:
            raise EvidenceError("invalid latency record fields")
        try:
            lag_sequence, lag = next(lag_records)
        except StopIteration as error:
            raise EvidenceError("send lag has fewer records than latency") from error
        if lag_sequence != sequence:
            raise EvidenceError("latency and send-lag sequence do not match")
        offset = sequence - sequence_base
        if offset < 1 or offset > span:
            raise EvidenceError("completion sequence outside the recorded request span")
        byte, bit = offset // 8, 1 << (offset % 8)
        if seen_sequences[byte] & bit:
            raise EvidenceError("duplicate completion sequence")
        seen_sequences[byte] |= bit
        raw_lag_sum += lag
        raw_lag_max = max(raw_lag_max, lag)
        completed = sent + latency
        origin, destination = phase_index(sent), phase_index(completed)
        status_name = STATUS[status]
        records += 1
        binary_counts[status_name] += 1
        flags[phase_flag][status_name] += 1
        if origin is None:
            if sent < epoch["measurement_start_ns"]:
                raise EvidenceError("warmup request present in measured latency records")
            outside_origin[status_name] += 1
        else:
            for phase in (phases[origin], full):
                phase["origin_counts"][status_name] += 1
                key = "cycle" if row["profile"] == "dhcp-lease" else (
                    "cname" if row["profile"] == "dns-mixed" and 15 <= sequence % 256 % 20 < 18
                    else {1: "a", 28: "aaaa", 16: "txt"}.get(qtype, str(qtype)))
                phase["qtype_origin_counts"][key] = phase["qtype_origin_counts"].get(key, 0) + 1
                phase["kind_origin_counts"][str(kind)] = phase["kind_origin_counts"].get(str(kind), 0) + 1
                phase["send_lags"].append(lag)
                if status == 0:
                    phase["origin_latencies"].append(latency)
            expected_flag = 2 if identity.get("saturation_seconds", 0) and sent >= epoch["saturation_start_ns"] else 1
            if phase_flag != expected_flag:
                flag_crossings += 1
            if status == 0:
                if destination is None:
                    phases[origin]["correct_origin_late"] += 1
                    full["correct_origin_late"] += 1
                elif destination != origin:
                    phases[origin]["correct_origin_cross_phase"] += 1
                    full["correct_origin_cross_phase"] += 1
        if destination is None:
            late[status_name] += 1
        else:
            for phase in (phases[destination], full):
                phase["completion_counts"][status_name] += 1
                if origin != destination:
                    phase["cross_phase_completions"][status_name] += 1
                if status == 0:
                    phase["latencies"].append(latency)
                    phase["success_completion_ns"].append(completed)
    if next(lag_records, None) is not None:
        raise EvidenceError("send lag has more records than latency")
    expected = load["measurement"]
    if any(binary_counts[key] != expected[key] for key in STATUS):
        raise EvidenceError(f"binary completions disagree with load counters: {binary_counts}")
    if raw_lag_sum != expected.get("send_lag_sum_ns", raw_lag_sum) or raw_lag_max != expected.get("send_lag_max_ns", raw_lag_max):
        raise EvidenceError("raw send-lag sum/maximum disagree with load counters")
    for flag, label in ((1, "steady"), (2, "saturation")):
        if label in load and any(flags[flag][key] != load[label][key] for key in STATUS):
            raise EvidenceError(f"binary {label} flag counters disagree with load counters")
    if load.get("interrupted") or load.get("output_failed"):
        row["analysis_errors"].append("interrupted or output_failed load evidence")
        row["methodology_valid"] = False
    samples_path = directory / "resources.json"
    samples = read_json(samples_path)
    if any(a["monotonic_ns"] >= b["monotonic_ns"] for a, b in zip(samples, samples[1:])):
        raise EvidenceError("resource samples are not in strict timestamp order")
    for phase in [*phases, full]:
        left, right = points[phase["cpu_left"]], points[phase["cpu_right"]]
        before, after = left.get("cgroup_cpu"), right.get("cgroup_cpu")
        if not before or not after:
            raise EvidenceError("missing primary cgroup CPU boundary")
        usage = after["usage_usec"] - before["usage_usec"]
        if usage < 0:
            raise EvidenceError("cgroup CPU counter decreased")
        segment_name = phase["cpu_left"] + ".." + phase["cpu_right"]
        if phase["phase"] != "measurement":
            segment = measured.get("cpu_segments", {}).get(segment_name)
            if segment is None or abs(segment["cpu_seconds"] * 1e6 - usage) > 1:
                raise EvidenceError("runner CPU segment disagrees with cgroup boundary delta")
        elif abs(measured.get("measurement_cpu_seconds", usage / 1e6) * 1e6 - usage) > 1:
            raise EvidenceError("runner measurement CPU disagrees with cgroup boundary delta")
        captures = (left["capture_lag_ns"], right["capture_lag_ns"])
        if any(lag < 0 or lag > 250_000_000 for lag in captures):
            row["analysis_errors"].append(f"{phase['phase']} CPU boundary capture lag invalid")
            row["methodology_valid"] = False
        correct = phase["completion_counts"]["correct"]
        phase["qps"] = correct / phase["seconds"]
        phase["origin_sent"] = sum(phase["origin_counts"].values())
        phase["origin_success_fraction"] = (phase["origin_counts"]["correct"] / phase["origin_sent"]
                                            if phase["origin_sent"] else None)
        phase["cpu_microseconds"] = usage
        phase["cpu_us_per_correct"] = usage / correct if correct else None
        phase["cpu_seconds"] = usage / 1e6
        phase["cpu_capture_seconds"] = (after["monotonic_ns"] - before["monotonic_ns"]) / 1e9
        phase["cpu_capture_lag_ns"] = list(captures)
        phase["latency_ns"] = quantiles(phase.pop("origin_latencies"))
        phase["latency_note"] = "all correct requests sent in this interval, including cross-phase and late completion"
        phase["completion_latency_ns"] = quantiles(phase.pop("latencies"))
        phase["send_lag_ns"] = quantiles(phase.pop("send_lags"), p99=False)
        phase["max_success_gap_ns"] = maximum_gap(phase.pop("success_completion_ns"), phase["start_ns"], phase["end_ns"])
        phase["resources"] = resource_summary(samples, phase)
        cpu_fraction = phase["resources"]["loadgen_cpu"]["single_core_fraction"]
        lag_p95 = phase["send_lag_ns"]["p95"]
        reasons = []
        if cpu_fraction is None:
            reasons.append("native generator CPU samples unavailable")
        elif cpu_fraction >= .9:
            reasons.append("native generator CPU >=90% of one core")
        if phase["phase"] != "saturation" and lag_p95 is not None and lag_p95 > 1_000_000:
            reasons.append("steady p95 scheduled-to-send lag >1ms")
        phase["generator_limited"] = bool(reasons)
        phase["generator_limit_reasons"] = reasons
        phase["unit"] = "cycle" if row["profile"] == "dhcp-lease" else "DNS query"
        counter_label = "saturation" if phase["phase"] == "saturation" else "steady"
        if identity["scenario"] != "fault" and phase["phase"] != "measurement":
            phase["load_phase_counters"] = load[counter_label]
            phase["offered"] = load[counter_label].get("scheduled")
            phase["scheduled_skipped"] = load[counter_label].get("scheduled_skipped")
        else:
            phase["offered"] = None
            phase["nominal_opportunities"] = round(identity.get("rate", load.get("rate", 0)) * phase["seconds"])
            phase["offered_note"] = "exact whole-window counters retained in load_counters; no timestamped skipped opportunities"
    full["generator_limited"] = any(phase["generator_limited"] for phase in phases)
    full["generator_limit_reasons"] = sorted({reason for phase in phases for reason in phase["generator_limit_reasons"]})
    if full["resources"]["sample_count"] < max(1, math.floor(identity["duration_seconds"]) - 2):
        row["analysis_errors"].append("independent measured resource sample count insufficient")
        row["methodology_valid"] = False
    raw_samples = verify_raw_samples(directory, row["profile"] == "dhcp-lease")
    if full["origin_counts"]["correct"] and not raw_samples["measurement"]:
        row["analysis_errors"].append("measured correct requests have no retained raw sample")
        row["methodology_valid"] = False
    auxiliary_files = ["load.wire-samples.jsonl"]
    if (directory / "reloads.json").exists():
        auxiliary_files.append("reloads.json")
    if (directory / "tftp.json").exists():
        auxiliary_files.append("tftp.json")
    if (directory / "tftp-transfers.jsonl").exists():
        auxiliary_files.append("tftp-transfers.jsonl")
    row.update({"phases": phases, "measurement": full, "record_count": records,
                "binary_counts": binary_counts, "load_counters": load,
                "late_completion_counts": late, "outside_origin_counts": outside_origin,
                "send_phase_flag_boundary_crossings": flag_crossings,
                "load_aggregate_in_window_difference": full["completion_counts"]["correct"] - load["measurement"].get("correct_in_window", full["completion_counts"]["correct"]),
                "raw_sample_verification": raw_samples,
                "auxiliary": auxiliary_summary(directory, full["start_ns"], full["end_ns"]),
                "warmup_excluded": True, "upstream": result.get("upstream"),
                "reloads": read_json(directory / "reloads.json") if (directory / "reloads.json").exists() else [],
                "tftp": read_json(directory / "tftp.json") if (directory / "tftp.json").exists() else None,
                "input_sha256": {name: sha256(directory / name) for name in
                                  ("result.json", "load.json", "epoch.json", "resources.json",
                                   "load.latencies.bin", "load.send-lag.bin", *auxiliary_files)}})
    return row


def variability(values):
    middle = statistics.median(values)
    return (max(values) - min(values)) / middle if middle else (0 if max(values) == min(values) else None)


def classify(reference, candidate, metric, limited=False):
    """Frozen W, direction and magnitude gates, evaluated per metric."""
    if len(reference) != 5 or len(candidate) != 5 or any(x is None for x in [*reference, *candidate]):
        return {"classification": "受限", "reason": "five paired valid rounds required"}
    if any(not math.isfinite(x) or x < 0 for x in [*reference, *candidate]):
        return {"classification": "受限", "reason": "missing or invalid metric"}
    a, b = statistics.median(reference), statistics.median(candidate)
    wa, wb = variability(reference), variability(candidate)
    delta = b - a
    relative = delta / a if a else (0 if not delta else math.inf)
    higher_good = metric == "qps"
    good_count = sum(y > x if higher_good else y < x for x, y in zip(reference, candidate))
    bad_count = sum(y < x if higher_good else y > x for x, y in zip(reference, candidate))
    noise = max(wa, wb) if wa is not None and wb is not None else None
    benefit = relative >= .10 if higher_good else relative <= -.10
    worse = relative <= -.05 if higher_good else relative >= .10
    if metric in ("rss_kib", "pss_kib"):
        benefit = benefit and abs(delta) >= 64
        worse = worse and abs(delta) >= 64
    direction = "有收益" if noise is not None and benefit and good_count >= 4 and abs(relative) > noise else (
        "变差" if noise is not None and worse and bad_count >= 4 and abs(relative) > noise else "无显著差异")
    if limited or noise is None:
        direction = "受限"
    return {"classification": direction, "reason": "generator-limited" if limited else "W undefined at zero median" if noise is None else None,
            "reference": {"rounds": reference, "median": a, "min": min(reference), "max": max(reference), "W": wa},
            "candidate": {"rounds": candidate, "median": b, "min": min(candidate), "max": max(candidate), "W": wb},
            "absolute_delta": delta, "relative_delta": relative if math.isfinite(relative) else None,
            "benefit_direction_rounds": good_count, "worse_direction_rounds": bad_count,
            "required_relative_delta_exceeds_W": noise}


def select_windows(root):
    state_path = root / "state.json"
    if not state_path.exists():
        return [(path.parent, None) for path in sorted(root.rglob("result.json"))], [], False
    state = read_json(state_path)
    selected, excluded = [], []
    for job_id, window in state.get("windows", {}).items():
        valid = window.get("valid_attempt")
        excluded.append({"job_id": job_id, "valid_attempt": valid, "attempts": window.get("attempts", [])})
        if valid is None:
            continue
        number = str(valid).removeprefix("attempt-")
        paths = [root / "archives" / job_id / f"attempt-{number}" / "plain/formal",
                 root / "runs" / job_id / f"attempt-{number}" / "formal"]
        found = [path for path in paths if (path / "result.json").exists()]
        if not found:
            excluded[-1]["analysis_error"] = "state-selected formal evidence unavailable"
            continue
        if len(found) == 2 and sha256(found[0] / "result.json") != sha256(found[1] / "result.json"):
            raise EvidenceError(f"archive and run result disagree for {job_id}")
        state_group = window.get("group")
        state_group = {"c": "C", "r3": "R3", "rs": "Rs"}.get(state_group, state_group)
        selected.append((found[0], {"job_id": job_id, "attempt": int(number),
                                    "state_round": int(window["round"]) if window.get("round") is not None else None,
                                    "state_profile": window.get("profile"), "state_group": state_group,
                                    "suite_methodology_valid": window.get("methodology_valid")}))
    return selected, excluded, True


def comparison_tables(windows, authoritative):
    rows = []
    if not authoritative:
        return rows
    index = {}
    for window in windows:
        if not window.get("methodology_valid") or window.get("pilot") or window.get("analysis_errors"):
            continue
        for phase in window["phases"]:
            key = window["profile"], phase["phase"], window["group"], window["round"]
            if key in index:
                raise EvidenceError(f"duplicate authoritative round: {key}")
            index[key] = phase
    profiles_phases = sorted({(key[0], key[1]) for key in index})
    for profile, phase in profiles_phases:
        for reference, candidate in (("C", "R3"), ("C", "Rs"), ("R3", "Rs")):
            a = [index.get((profile, phase, reference, n)) for n in range(1, 6)]
            b = [index.get((profile, phase, candidate, n)) for n in range(1, 6)]
            for metric in ("qps", "cpu_us_per_correct", "p50_ns", "p95_ns", "p99_ns",
                           "rss_kib", "pss_kib", "fd_count", "thread_count", "child_processes",
                           "wrong_count", "transport_error_count", "timeout_count"):
                def value(row):
                    if row is None:
                        return None
                    if metric.startswith("p") and metric.endswith("_ns"):
                        return row["latency_ns"][metric[:-3]]
                    if metric in RESOURCE_KEYS:
                        return row["resources"]["sampled_tree_peaks"][metric]
                    if metric.endswith("_count"):
                        return row["origin_counts"][metric.removesuffix("_count")]
                    return row[metric]
                # A saturated native generator limits only the offered-capacity
                # throughput conclusion. CPU and latency are still measured at
                # the fixed offered rate and retain their ordinary gates, with
                # the limitation carried as an annotation in each window.
                restricted = any(row and row["generator_limited"] for row in [*a, *b]) and metric == "qps"
                verdict = classify([value(row) for row in a], [value(row) for row in b], metric, restricted)
                if metric in ("p50_ns", "p99_ns", "fd_count", "thread_count", "child_processes"):
                    verdict["classification"] = "受限"
                    verdict["reason"] = "descriptive metric; frozen protocol has no independent benefit gate"
                if metric.endswith("_count") and len([row for row in [*a, *b] if row]) == 10:
                    av, bv = [value(row) for row in a], [value(row) for row in b]
                    if profile == "upstream-fault" and phase == "fault" and metric == "timeout_count":
                        verdict["classification"] = "受限"
                        verdict["reason"] = "fault-origin timeout is an expected outcome; compare availability and recovery separately"
                    else:
                        added = sum(bv) - sum(av)
                        verdict["classification"] = "变差" if added > 0 else "无显著差异"
                        verdict["added_errors_across_five_rounds"] = added
                        verdict["reason"] = "additional ordinary failures are a direct regression" if added > 0 else None
                rows.append({"profile": profile, "phase": phase, "comparison": f"{candidate}/{reference}",
                             "metric": metric, **verdict})
    return rows


def write_csv(path, rows):
    fields = sorted({key for row in rows for key in row})
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def analyze(root):
    root = Path(root).resolve()
    selected, history, authoritative = select_windows(root)
    windows = []
    for directory, selector in selected:
        try:
            row = analyze_window(directory)
            if selector:
                if any(selector["state_" + key] is not None and selector["state_" + key] != row[key]
                       for key in ("round", "profile", "group")):
                    raise EvidenceError("state identity disagrees with selected formal evidence")
                row.update(selector)
                if row["pilot"]:
                    raise EvidenceError("state selected a pilot as formal")
                if selector["suite_methodology_valid"] is False:
                    row["methodology_valid"] = False
                    row["analysis_errors"].append("suite methodology gate rejected selected attempt")
            windows.append(row)
        except (EvidenceError, KeyError, ValueError, OSError) as error:
            windows.append({"directory": str(directory), "selector": selector,
                            "methodology_valid": False, "analysis_errors": [str(error)]})
    comparisons = comparison_tables(windows, authoritative)
    counts = {profile: {group: sum(1 for row in windows if row.get("profile") == profile and
                                  row.get("group") == group and row.get("methodology_valid") and
                                  not row.get("pilot") and not row.get("analysis_errors"))
                        for group in GROUPS} for profile in PROFILES}
    complete = authoritative and all(count == 5 for values in counts.values() for count in values.values())
    return {"schema": 1, "evidence_root": str(root), "authoritative_state": authoritative,
            "formal_complete": complete, "valid_counts": counts, "windows": windows,
            "attempt_history": history, "comparisons": comparisons,
            "manifest_sha256": sha256(root / "manifest.json") if (root / "manifest.json").exists() else None,
            "state_sha256": sha256(root / "state.json") if (root / "state.json").exists() else None,
            "method": "frozen M6A_PROTOCOL v1; nearest-rank; no mean or fastest-attempt selection",
            "scope": "Oracle build machine only; no router performance claim"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.evidence_root)
    prefix = args.output.with_suffix("") if args.output.suffix == ".json" else args.output
    prefix.parent.mkdir(parents=True, exist_ok=True)
    Path(str(prefix) + ".json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    windows = []
    for row in report["windows"]:
        for phase in row.get("phases", []):
            windows.append({**{key: row.get(key) for key in ("profile", "group", "round", "attempt", "pilot", "methodology_valid")},
                            "phase": phase["phase"], "seconds": phase["seconds"], "qps": phase["qps"],
                            "cpu_us_per_correct": phase["cpu_us_per_correct"],
                            "offered": phase["offered"], "scheduled_skipped": phase.get("scheduled_skipped"),
                            "generator_limited": phase["generator_limited"],
                            "latency_samples": phase["latency_ns"]["sample_count"],
                            "origin_sent": phase["origin_sent"], "correct_origin_late": phase["correct_origin_late"],
                            "correct_origin_cross_phase": phase["correct_origin_cross_phase"],
                            "send_lag_p95_ns": phase["send_lag_ns"]["p95"],
                            **{"completed_" + key: value for key, value in phase["completion_counts"].items()},
                            **{"origin_" + key: value for key, value in phase["origin_counts"].items()},
                            **{key + "_ns": phase["latency_ns"][key] for key in ("p50", "p95", "p99")},
                            **phase["resources"]["sampled_tree_peaks"]})
    write_csv(Path(str(prefix) + ".windows.csv"), windows)
    comparisons = []
    for row in report["comparisons"]:
        comparisons.append({**{key: row.get(key) for key in ("profile", "phase", "comparison", "metric", "classification", "reason", "absolute_delta", "relative_delta")},
                            **{group + "_" + key: row.get(group, {}).get(key)
                               for group in ("reference", "candidate") for key in ("median", "min", "max", "W")}})
    write_csv(Path(str(prefix) + ".comparisons.csv"), comparisons)
    print(json.dumps({"output": str(prefix), "formal_complete": report["formal_complete"],
                      "windows": len(report["windows"]), "valid_counts": report["valid_counts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
