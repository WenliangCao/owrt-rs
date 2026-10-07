#!/usr/bin/env python3
"""One CPU-separated M6a window; this tool never builds or changes a product.

Invoke under run_isolated.sh. Each invocation starts an exact-image overlay,
an upstream on CPU1, a service on CPU0 and the native client on CPU2. The
controller and /proc sampling use CPU3. Raw evidence remains under private/.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import name, query, read_name, rr, semantics
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256

R3_SHA = "37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b"
PORT, UPSTREAM_PORT = 15353, 15354
TTL, CAPACITY = 3600, 4096
PREFIX = "m6a.test"
CGROUP_PATH = None

# The post-load barrier is deliberately stricter than the old child-only check.
# Rust owns TCP clients and cache views in the daemon itself, so it has no child
# process whose exit can stand in for release.  A confirmed idle FD count held
# for several samples is the portable external drain contract.  M6b formal
# windows use the fixed 0/1/5/60 second snapshots below.
DEFAULT_DRAIN_SAMPLE_SECONDS = (0.0, 1.0, 5.0, 60.0)
DRAIN_STABLE_SAMPLES = 3
DRAIN_SAMPLE_INTERVAL_SECONDS = 0.02


def save(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def answer(packet: bytes) -> bytes:
    host, end = read_name(packet, 12)
    kind, cls = struct.unpack_from("!HH", packet, end)
    if cls != 1 or not (host.endswith("." + PREFIX) or host == "m6a.target"):
        raise ValueError("query outside the frozen workload")
    question = packet[12:end + 4]
    count = 1
    if host.startswith("cname-") and kind == 1:
        count = 2
        body = rr(5, name("m6a.target"), TTL)
        body += rr(1, socket.inet_aton("192.0.2.1"), TTL, name("m6a.target"))
    elif kind == 1:
        body = rr(1, socket.inet_aton("192.0.2.1"), TTL)
    elif kind == 28:
        body = rr(28, socket.inet_pton(socket.AF_INET6, "2001:db8::1"), TTL)
    elif kind == 16:
        body = rr(16, b"\x03m6a", TTL)
    else:
        raise ValueError("qtype outside the frozen workload")
    return packet[:2] + struct.pack("!5H", 0x8180, 1, count, 0, 0) + question + body


def proc_row(pid: int):
    """Own + waited-child CPU is cumulative; live descendants are separate."""
    proc = Path("/proc") / str(pid)
    text = (proc / "stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    status = {}
    for line in (proc / "status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("VmRSS", "VmHWM", "RssAnon", "RssFile", "Threads"):
            status[key] = int(value.split()[0])
    rollup = {}
    # A zombie retains CPU counters until wait, but no address space remains.
    rollup_text = "" if fields[0] == "Z" else (proc / "smaps_rollup").read_text()
    for line in rollup_text.splitlines():
        key, _, value = line.partition(":")
        if key in ("Pss", "Private_Clean", "Private_Dirty", "Shared_Clean", "Shared_Dirty"):
            rollup[key] = int(value.split()[0])
    cpu = {"user_ticks": int(fields[11]), "system_ticks": int(fields[12]),
           "waited_child_user_ticks": int(fields[13]),
           "waited_child_system_ticks": int(fields[14])}
    return {"pid": pid, "state": fields[0], "starttime_ticks": int(fields[19]),
            **cpu, "cpu_ticks": sum(cpu.values()),
            "rss_kib": status.get("VmRSS", 0), "hwm_kib": status.get("VmHWM", 0),
            "rss_anon_kib": status.get("RssAnon", 0), "rss_file_kib": status.get("RssFile", 0),
            "pss_kib": rollup.get("Pss", 0), "smaps": rollup,
            "thread_count": status.get("Threads", 0),
            "fd_count": len(list((proc / "fd").iterdir())),
            "affinity": sorted(os.sched_getaffinity(pid)),
            "children": [int(x) for x in (proc / "task" / str(pid) / "children").read_text().split()]}


def cgroup_cpu():
    if CGROUP_PATH is None:
        return None
    values = {key: int(value) for key, value in
              (line.split() for line in (CGROUP_PATH / "cpu.stat").read_text().splitlines())}
    for key in ("usage_usec", "user_usec", "system_usec"):
        if key not in values:
            raise RuntimeError(f"cgroup CPU accounting missing {key}")
    return {"monotonic_ns": time.monotonic_ns(), "path": str(CGROUP_PATH), **values}


def process_tree(pid: int):
    cg = cgroup_cpu()
    parent = proc_row(pid)
    pending, children, lost = list(parent["children"]), [], []
    while pending:
        child = pending.pop()
        try:
            row = proc_row(child)
        except (FileNotFoundError, ProcessLookupError):
            lost.append(child)
            continue
        children.append(row)
        pending.extend(row["children"])
    rows = [parent, *children]
    keys = ("cpu_ticks", "rss_kib", "pss_kib", "fd_count", "thread_count", "rss_anon_kib", "rss_file_kib")
    return {"monotonic_ns": time.monotonic_ns(), "parent": parent,
            "children": children, "children_disappeared_during_sample": lost,
            "cgroup_cpu": cg,
            "tree": {**{key: sum(row[key] for row in rows) for key in keys},
                     "child_processes": len(children)}, "clock_ticks_per_second": os.sysconf("SC_CLK_TCK")}


def snapshot(pid: int, out: Path, label: str):
    directory = out / "proc-snapshots"
    directory.mkdir(exist_ok=True)
    tree = process_tree(pid)
    for row in [tree["parent"], *tree["children"]]:
        for filename in ("status", "smaps", "smaps_rollup", "stat", "maps"):
            try:
                (directory / f"{label}.{row['pid']}.{filename}").write_bytes(
                    (Path("/proc") / str(row["pid"]) / filename).read_bytes())
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ESRCH):
                    raise
    save(directory / f"{label}.json", tree)
    return tree


def parse_drain_sample_seconds(value: str | None):
    """Parse and validate the fixed post-drain sample offsets."""
    if value is None:
        return DEFAULT_DRAIN_SAMPLE_SECONDS
    try:
        offsets = tuple(float(part.strip()) for part in value.split(",") if part.strip())
    except ValueError as error:
        raise ValueError("drain sample offsets must be comma-separated seconds") from error
    if not offsets or offsets[0] != 0.0 or any(offset < 0 for offset in offsets):
        raise ValueError("drain samples must start at 0 and be non-negative")
    if tuple(sorted(set(offsets))) != offsets:
        raise ValueError("drain samples must be strictly increasing")
    return offsets


def wait_for_drain(pid: int, idle_fd_count: int, timeout: float = 5.0,
                   stable_samples: int = DRAIN_STABLE_SAMPLES,
                   interval: float = DRAIN_SAMPLE_INTERVAL_SECONDS):
    """Wait for children and daemon-owned work to return to a stable idle shape.

    The FD criterion is intentionally observable for both C and Rust.  It is
    only accepted after ``stable_samples`` consecutive process snapshots with
    no live descendants and the exact pre-load FD count.  The snapshots are
    retained as evidence so a later report can show why the barrier passed.
    """
    if idle_fd_count < 0 or stable_samples < 1:
        raise ValueError("invalid drain barrier parameters")
    started_ns = time.monotonic_ns()
    deadline = time.monotonic() + timeout
    stable = 0
    observations = []
    while True:
        now_ns = time.monotonic_ns()
        row = process_tree(pid)
        children = row["tree"]["child_processes"]
        fd_count = row["tree"]["fd_count"]
        ready = children == 0 and fd_count == idle_fd_count
        stable = stable + 1 if ready else 0
        observations.append({"monotonic_ns": now_ns, "elapsed_ns": now_ns - started_ns,
                             "fd_count": fd_count, "child_processes": children,
                             "stable_samples": stable, "ready": ready})
        if stable >= stable_samples:
            return {"started_monotonic_ns": started_ns,
                    "completed_monotonic_ns": now_ns,
                    "elapsed_seconds": (now_ns - started_ns) / 1e9,
                    "idle_fd_count": idle_fd_count,
                    "stable_samples_required": stable_samples,
                    "observations": observations,
                    "criterion": "no live descendants and daemon FD count equals pre-load idle count"}
        if time.monotonic() >= deadline:
            raise TimeoutError(f"daemon did not drain to stable FD count {idle_fd_count}")
        time.sleep(interval)


def capture_drain_samples(pid: int, out: Path, barrier: dict, offsets):
    """Capture fixed samples relative to the completed drain barrier.

    ``after-drain`` remains an alias for the zero-second sample for compatibility
    with M6a readers; the explicit map is the authoritative new evidence.
    """
    offsets = tuple(offsets)
    completed_ns = barrier["completed_monotonic_ns"]
    samples = {}
    for offset in offsets:
        target_ns = completed_ns + int(offset * 1e9)
        while True:
            remaining_ns = target_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                break
            time.sleep(min(0.05, remaining_ns / 1e9))
        stem = str(int(offset)) if offset.is_integer() else str(offset).replace(".", "p")
        label = "after-drain" if offset == 0 else "drain-plus-" + stem
        snapshot_row = snapshot(pid, out, label)
        if offset == 0:
            # Keep an explicit drain-plus-0 copy for fixed-offset consumers.
            directory = out / "proc-snapshots"
            for path in directory.glob("after-drain.*"):
                path.with_name(path.name.replace("after-drain", "drain-plus-0")).write_bytes(path.read_bytes())
        samples[str(int(offset) if offset.is_integer() else offset)] = {
            "scheduled_offset_seconds": offset,
            "scheduled_monotonic_ns": target_ns,
            "captured_monotonic_ns": time.monotonic_ns(),
            "snapshot": snapshot_row,
        }
    zero = samples.get("0")
    if zero is not None:
        samples["after-drain"] = zero
    save(out / "drain-samples.json", {"barrier": barrier, "samples": samples})
    return samples


def measure_idle_cpu(pid: int, out: Path, seconds: float):
    """Measure daemon CPU with no load, using cgroup and /proc cross-checks."""
    if seconds < 0:
        raise ValueError("idle CPU duration must be non-negative")
    if seconds == 0:
        result = {"enabled": False, "duration_seconds": 0.0}
        save(out / "idle-cpu.json", result)
        return result
    started_ns = time.monotonic_ns()
    before = process_tree(pid)
    before_cgroup = cgroup_cpu()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not alive(pid):
            raise RuntimeError("daemon exited during idle CPU measurement")
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    ended_ns = time.monotonic_ns()
    after = process_tree(pid)
    after_cgroup = cgroup_cpu()
    elapsed = (ended_ns - started_ns) / 1e9
    ticks = after["tree"]["cpu_ticks"] - before["tree"]["cpu_ticks"]
    ticks_per_second = os.sysconf("SC_CLK_TCK")
    cpu_seconds = (after_cgroup["usage_usec"] - before_cgroup["usage_usec"]) / 1e6
    result = {"enabled": True, "started_monotonic_ns": started_ns,
              "ended_monotonic_ns": ended_ns, "elapsed_seconds": elapsed,
              "requested_seconds": seconds, "cgroup_before": before_cgroup,
              "cgroup_after": after_cgroup, "proc_before": before,
              "proc_after": after, "cpu_seconds": cpu_seconds,
              "proc_cpu_seconds": ticks / ticks_per_second,
              "cpu_percent": 100.0 * cpu_seconds / elapsed if elapsed else 0.0,
              "proc_cpu_percent": 100.0 * ticks / ticks_per_second / elapsed if elapsed else 0.0,
              "clock_ticks_per_second": ticks_per_second,
              "criterion": "daemon cgroup CPU over a no-load interval"}
    save(out / "idle-cpu.json", result)
    return result


def _wake_value(values, names):
    for name in names:
        if name in values:
            return values[name]
    return None


def read_wake_telemetry(path: Path):
    """Read one cumulative wake snapshot from a JSON or JSONL sidecar.

    Product instrumentation may atomically replace JSON or append JSONL.  The
    canonical fields are ``loop_rounds``, ``poll_calls`` and
    ``poll_wait_ns``; optional ``wait_durations_ns`` preserves each actual
    poll wait for attribution without requiring a tracer in the hot path.
    """
    try:
        text = path.read_text()
    except (FileNotFoundError, OSError):
        return None
    values = None
    for line in reversed(text.splitlines()):
        if not line.strip():
            continue
        try:
            values = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    if not isinstance(values, dict):
        return None
    values = values.get("counters", values)
    loops = _wake_value(values, ("loop_rounds", "loops", "main_loop_rounds"))
    polls = _wake_value(values, ("poll_calls", "polls", "poll_count"))
    waits = _wake_value(values, ("poll_wait_ns", "wait_ns", "wait_duration_ns"))
    if not all(isinstance(value, int) and value >= 0 for value in (loops, polls, waits)):
        return None
    durations = values.get("wait_durations_ns", values.get("poll_wait_durations_ns", []))
    if not isinstance(durations, list) or not all(isinstance(value, int) and value >= 0 for value in durations):
        durations = []
    reasons = values.get("wait_reasons", {})
    if not isinstance(reasons, dict):
        reasons = {}
    listeners = values.get("udp_listeners", values.get("udp", {}))
    if not isinstance(listeners, (dict, list)):
        listeners = {}
    return {"monotonic_ns": values.get("monotonic_ns", time.monotonic_ns()),
            "loop_rounds": loops, "poll_calls": polls, "poll_wait_ns": waits,
            "wait_durations_ns": durations, "wait_reasons": reasons,
            "udp_listeners": listeners}


def _mapping_delta(current, previous):
    if not isinstance(current, dict) or not isinstance(previous, dict):
        return current
    result = {}
    for key in set(current) | set(previous):
        now, before = current.get(key), previous.get(key, 0)
        if isinstance(now, int) and isinstance(before, int):
            result[key] = now - before
        else:
            result[key] = now
    return result


def _wait_duration_stats(values):
    values = sorted(value for value in values if isinstance(value, int) and value >= 0)
    if not values:
        return {"count": 0, "min_ns": None, "p50_ns": None, "p95_ns": None,
                "p99_ns": None, "max_ns": None}
    def nearest_rank(fraction):
        index = max(0, min(len(values) - 1, int((len(values) * fraction + 0.999999999) - 1)))
        return values[index]
    return {"count": len(values), "min_ns": values[0],
            "p50_ns": nearest_rank(0.50), "p95_ns": nearest_rank(0.95),
            "p99_ns": nearest_rank(0.99), "max_ns": values[-1]}


def summarize_wake_telemetry(samples):
    intervals = []
    for previous, current in zip(samples, samples[1:]):
        elapsed = (current["observed_monotonic_ns"] - previous["observed_monotonic_ns"]) / 1e9
        if elapsed <= 0:
            continue
        loops = current["counters"]["loop_rounds"] - previous["counters"]["loop_rounds"]
        polls = current["counters"]["poll_calls"] - previous["counters"]["poll_calls"]
        waits = current["counters"]["poll_wait_ns"] - previous["counters"]["poll_wait_ns"]
        durations = current["counters"].get("wait_durations_ns", [])
        intervals.append({"started_monotonic_ns": previous["observed_monotonic_ns"],
                          "ended_monotonic_ns": current["observed_monotonic_ns"],
                          "elapsed_seconds": elapsed, "loop_rounds": loops,
                          "poll_calls": polls, "poll_wait_ns": waits,
                          "loop_rounds_per_second": loops / elapsed,
                          "poll_calls_per_second": polls / elapsed,
                          "poll_wait_seconds": waits / 1e9,
                          "poll_wait_average_ns": waits / polls if polls > 0 else None,
                          "poll_wait_stats_ns": _wait_duration_stats(durations),
                          "wait_durations_ns": durations,
                          "wait_reasons": _mapping_delta(current["counters"].get("wait_reasons", {}),
                                                         previous["counters"].get("wait_reasons", {})),
                          "udp_listeners": current["counters"].get("udp_listeners", {})})
    return {"available": bool(samples), "samples": samples, "intervals": intervals,
            "totals": (samples[-1]["counters"] if samples else None)}


def correct_answer(host: str, kind: int, ident: int, packet: bytes):
    result = semantics(packet)
    expected = semantics(answer(query(host, kind, ident)))
    def records_without_ttl(value):
        return [{k: v for k, v in record.items() if k != "ttl"} for record in value["records"]]
    return (result["id"] == ident and result["flags"] & 0x820f == 0x8000
            and result["questions"] == [[host, kind, 1]]
            and records_without_ttl(result) == records_without_ttl(expected)
            and all(0 < row["ttl"] <= TTL for row in result["records"])
            and complete_dns_wire(packet))


def complete_dns_wire(packet):
    counts = struct.unpack_from("!6H", packet)[2:]
    position = 12
    for _ in range(counts[0]):
        _, position = read_name(packet, position)
        position += 4
    for _ in range(sum(counts[1:])):
        _, position = read_name(packet, position)
        size = struct.unpack_from("!H", packet, position + 8)[0]
        position += 10 + size
    return position == len(packet)


def correct_reload_reply(packet, ident, address):
    parsed = semantics(packet)
    host = f"reload-proof.{PREFIX}"
    return (parsed["id"] == ident and parsed["questions"] == [[host, 1, 1]]
            and parsed["flags"] & 0x820f == 0x8000 and len(parsed["records"]) == 1
            and parsed["records"][0]["section"] == "answer"
            and parsed["records"][0]["name"] == host
            and parsed["records"][0]["class"] == 1
            and parsed["records"][0]["type"] == 1
            and parsed["records"][0]["data"] == address
            and 0 < parsed["records"][0]["ttl"] <= TTL
            and complete_dns_wire(packet))


def bank_question(index, mixed):
    slot = index % 20
    kind = 1 if not mixed or slot < 10 or 15 <= slot < 18 else 28 if slot < 15 else 16
    prefix = "cname-" if mixed and 15 <= slot < 18 else ""
    return f"{prefix}q{index:04x}.{PREFIX}", kind


def fill_and_prove(out: Path, count: int, disable: bool, upstream_pid: int, daemon_pid: int, mixed=False):
    endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    endpoint.connect(("127.0.0.1", PORT))
    endpoint.settimeout(2)
    rows = []
    try:
        for i in range(count):
            host, kind = bank_question(i, mixed)
            endpoint.send(query(host, kind, i))
            reply = endpoint.recv(65535)
            if not correct_answer(host, kind, i, reply):
                raise AssertionError(f"incorrect cache fill at {i}")
        snapshot(daemon_pid, out, "filled")
        if disable:
            os.kill(upstream_pid, signal.SIGUSR1)
            time.sleep(.1)
            for i in range(count):
                host, kind = bank_question(i, mixed)
                endpoint.send(query(host, kind, i))
                reply = endpoint.recv(65535)
                valid = correct_answer(host, kind, i, reply)
                rows.append({"name": host, "correct": valid, "reply": reply.hex()})
                if not valid:
                    raise AssertionError(f"cache occupancy missing {host}")
            snapshot(daemon_pid, out, "verified")
        save(out / "cache-proof.json", {"capacity": CAPACITY, "filled_names": count,
                                        "validated_names": len(rows), "ttl": TTL,
                                        "upstream_disabled": disable, "rows": rows})
    finally:
        endpoint.close()


def config_for(scenario: str, tcp_profile="hit"):
    common = ("no-resolv\nno-hosts\nno-poll\nno-0x20-encode\nuser=root\ngroup=root\nbind-interfaces\ninterface=lo\n"
              "listen-address=127.0.0.1\n"
              f"port={PORT}\ncache-size={CAPACITY}\nlocal-ttl={TTL}\n"
              "dns-forward-max=1024\ncache-rr=TXT\n"
              f"server=127.0.0.1#{UPSTREAM_PORT}\n"
              "log-facility=-\npid-file=/m6a/pid\n")
    if scenario == "dhcp":
        common += ("no-ping\ndhcp-authoritative\n"
                   "dhcp-range=127.0.0.10,127.0.0.29,255.0.0.0,127.255.255.255,3600s\n"
                   "dhcp-lease-max=150\ndhcp-leasefile=/m6a/leases\n")
        common += "".join(f"dhcp-host=02:00:00:6a:00:{i:02x},127.0.0.{i + 10}\n" for i in range(20))
    if scenario == "reload":
        common += "addn-hosts=/m6a/hosts\nenable-tftp\ntftp-root=/m6a/tftp\n"
    if scenario == "tcp" and tcp_profile == "local":
        common += f"address=/localbank.{PREFIX}/192.0.2.1\n"
    return common


def alive(pid: int):
    try:
        text = (Path("/proc") / str(pid) / "stat").read_text()
        return text[text.rfind(")") + 2:].split()[0] != "Z"
    except FileNotFoundError:
        return False


def wait_file(path: Path, timeout: float, process=None):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"process exited before {path.name}")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"waiting for {path.name}")
        time.sleep(.02)


def read_json_ready(path: Path, timeout: float, process=None):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            if process is not None and process.poll() is not None:
                raise RuntimeError(f"process exited before complete {path.name}")
            if time.monotonic() >= deadline:
                raise TimeoutError(f"waiting for complete {path.name}")
            time.sleep(.01)


def tftp_worker(args):
    """Fixed 10/s background, sharing CPU2 with the native DNS generator."""
    os.sched_setaffinity(0, {args.cpu_load})
    epoch = read_json_ready(args.output / "epoch.json", 10)
    expected = bytes(range(256)) * 4
    next_ns = epoch["warmup_start_ns"]
    end_ns = epoch["measurement_end_ns"]
    rows = []
    raw_counts = {"warmup": 0, "measurement": 0}
    stream = (args.output / "tftp-transfers.jsonl").open("w")
    try:
        while next_ns < end_ns:
            now = time.monotonic_ns()
            if now < next_ns:
                time.sleep(min(.01, (next_ns - now) / 1e9))
                continue
            # Fixed scheduled opportunities; a stalled transfer creates missed
            # opportunities rather than a catch-up burst or hidden offered work.
            missed = max(0, (now - next_ns) // 100_000_000)
            next_ns += missed * 100_000_000
            if next_ns >= end_ns:
                break
            scheduled = next_ns
            next_ns += 100_000_000
            endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            endpoint.settimeout(args.timeout_ms / 1000)
            started = time.monotonic_ns()
            row = {"scheduled_monotonic_ns": scheduled, "send_monotonic_ns": started,
                   "phase": "measurement" if started >= epoch["measurement_start_ns"] else "warmup",
                   "schedule_lag_ns": started - scheduled, "missed_scheduled_opportunities": int(missed),
                   "correct": False, "wire": []}
            try:
                rrq = b"\x00\x01payload\x00octet\x00"
                endpoint.sendto(rrq, ("127.0.0.1", 69))
                received, peer, block = bytearray(), None, 1
                while True:
                    packet, sender = endpoint.recvfrom(2048)
                    if peer is None:
                        peer = sender
                    if sender != peer or len(packet) < 4:
                        raise ValueError("unexpected TFTP peer or short packet")
                    opcode, number = struct.unpack_from("!HH", packet)
                    if opcode != 3 or number != block or len(packet) > 516:
                        raise ValueError("unexpected TFTP opcode, block or payload length")
                    received.extend(packet[4:])
                    if received != expected[:len(received)] or len(received) > len(expected):
                        raise ValueError("incorrect TFTP payload")
                    ack = struct.pack("!HH", 4, block)
                    endpoint.sendto(ack, peer)
                    row["wire"].append({"data": packet.hex(), "ack": ack.hex()})
                    if len(packet) < 516:
                        if bytes(received) != expected:
                            raise ValueError("incomplete TFTP payload")
                        row["correct"] = True
                        break
                    block += 1
            except (OSError, ValueError, struct.error) as error:
                row["error"] = {"type": type(error).__name__, "message": str(error)}
            finally:
                endpoint.close()
            row["completion_monotonic_ns"] = time.monotonic_ns()
            row["latency_ns"] = row["completion_monotonic_ns"] - started
            row["completed_within_window"] = row["completion_monotonic_ns"] <= end_ns
            if row["correct"] and raw_counts[row["phase"]] >= 10:
                row["wire"] = []
            else:
                raw_counts[row["phase"]] += 1
            rows.append(row)
            stream.write(json.dumps(row) + "\n")
            stream.flush()
        measured = [r for r in rows if r["phase"] == "measurement"]
        save(args.output / "tftp.json", {"rate": 10, "payload_bytes": 1024,
                                         "offers": len(measured),
                                         "correct": sum(r["correct"] for r in measured),
                                         "correct_in_window": sum(r["correct"] and r["completed_within_window"] for r in measured),
                                         "errors": sum(not r["correct"] for r in measured),
                                         "missed_scheduled_opportunities": sum(r["missed_scheduled_opportunities"] for r in measured),
                                         "latencies_ns": [r["latency_ns"] for r in measured if r["correct"]]})
    finally:
        stream.close()
    return 0


def stop_daemon(process):
    forced = False
    if alive(process.pid):
        os.kill(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + 10
    while alive(process.pid) and time.monotonic() < deadline:
        time.sleep(.02)
    if alive(process.pid):
        forced = True
        os.kill(process.pid, signal.SIGKILL)
    waited, status, usage = os.wait4(process.pid, 0)
    process.returncode = os.waitstatus_to_exitcode(status)
    return {"pid": waited, "returncode": process.returncode, "forced_kill": forced,
            "wait4_user_seconds": usage.ru_utime, "wait4_system_seconds": usage.ru_stime,
            "wait4_maxrss_kib": usage.ru_maxrss,
            "accounting": "Linux wait4 rusage includes terminated child and its waited descendants"}


def load_command(args):
    mode = "tcp" if args.scenario == "tcp" else "dhcp" if args.scenario == "dhcp" else "udp"
    profile = ("hit" if mode == "tcp" and args.tcp_profile == "local" else args.tcp_profile if mode == "tcp" else "hit" if args.scenario in ("hit", "reload") else
               "mixed" if args.scenario == "mixed" else "miss")
    result = ["taskset", "-c", str(args.cpu_load), str(args.loadgen),
              "--mode", mode, "--host", "127.0.0.1", "--port", str(67 if mode == "dhcp" else PORT),
              "--clients", str(args.clients), "--duration-seconds", str(args.duration),
              "--rate", str(args.rate), "--seed", str(args.seed),
              "--name-prefix", f"localbank.{PREFIX}" if args.scenario == "tcp" and args.tcp_profile == "local" else PREFIX,
              "--profile", profile,
              "--cache-names", str(args.cache_names),
              "--qtype", "mix" if args.scenario == "mixed" else "a",
              "--warmup-seconds", str(args.warmup), "--timeout-ms", str(args.timeout_ms),
              "--saturation-seconds", str(args.saturation_seconds),
              "--epoch-output", str(args.output / "epoch.json"),
              "--epoch-file", str(args.output / "measurement-start-ns"),
              "--output", str(args.output / "load")]
    if mode == "dhcp":
        result += ["--dhcp-first-address", "127.0.0.10", "--interface", "lo"]
    return result


def boundaries_for(args, epoch):
    start, end = epoch["measurement_start_ns"], epoch["measurement_end_ns"]
    boundaries = [("measurement-start", start)]
    if args.scenario == "fault":
        boundaries += [("fault-start", start + int(args.fault_start * 1e9)),
                       ("fault-end", start + int(args.fault_end * 1e9))]
    elif args.saturation_seconds:
        boundaries += [("saturation-start", end - int(args.saturation_seconds * 1e9))]
    boundaries.append(("measurement-end", end))
    return boundaries


def run_load(args, daemon, root, upstream):
    command_line = load_command(args)
    save(args.output / "load-command.json", command_line)
    log = (args.output / "loadgen.log").open("wb")
    resource_stream = (args.output / "resources.jsonl").open("w")
    initial = snapshot(daemon.pid, args.output, "before-warmup")
    idle_fd_count = initial["tree"]["fd_count"]
    idle_cpu = measure_idle_cpu(daemon.pid, args.output, args.idle_seconds)
    process = subprocess.Popen(command_line, stdout=log, stderr=log)
    resources, points, reloads, wake_samples = [], {}, [], []
    wake_path = root / "m6a/wake-metrics.json" if args.wake_metrics else None
    peak_pss, next_sample = 0, 0
    next_reload = args.reload_period
    reload_socket = None
    pending_reload = None
    if args.scenario == "reload":
        reload_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        reload_socket.connect(("127.0.0.1", PORT))
        reload_socket.setblocking(False)
    started = time.monotonic()
    tftp = tftp_log = None
    measurement_peak_pss = 0
    last_loop_ns = time.monotonic_ns()
    max_controller_gap_ns = 0
    try:
        epoch = read_json_ready(args.output / "epoch.json", 5, process)
        if args.scenario == "reload":
            tftp_log = (args.output / "tftp-worker.log").open("wb")
            tftp_command = ["taskset", "-c", str(args.cpu_load), sys.executable, __file__,
                            "--tftp-worker", "--scenario", "reload", "--output", str(args.output),
                            "--cpu-load", str(args.cpu_load), "--timeout-ms", str(args.timeout_ms)]
            save(args.output / "tftp-command.json", tftp_command)
            tftp = subprocess.Popen(tftp_command, stdout=tftp_log, stderr=tftp_log)
        boundaries = boundaries_for(args, epoch)
        while process.poll() is None:
            now_ns = time.monotonic_ns()
            max_controller_gap_ns = max(max_controller_gap_ns, now_ns - last_loop_ns)
            last_loop_ns = now_ns
            if not alive(daemon.pid):
                raise RuntimeError("daemon exited during load")
            if upstream.poll() is not None:
                raise RuntimeError("upstream exited during the measurement window")
            for label, scheduled in boundaries:
                if label not in points and now_ns >= scheduled:
                    points[label] = snapshot(daemon.pid, args.output, label)
                    points[label]["scheduled_monotonic_ns"] = scheduled
                    points[label]["capture_lag_ns"] = points[label]["cgroup_cpu"]["monotonic_ns"] - scheduled
                    save(args.output / "cpu-points.json", points)
            if now_ns >= next_sample:
                row = process_tree(daemon.pid)
                for label, worker in [("loadgen", process), ("upstream", upstream), *([("tftp", tftp)] if tftp else [])]:
                    try:
                        row[label] = proc_row(worker.pid)
                    except (FileNotFoundError, ProcessLookupError):
                        row[label] = {"exited_during_sample": True}
                row["measurement_elapsed_seconds"] = (now_ns - epoch["measurement_start_ns"]) / 1e9
                resources.append(row)
                if wake_path is not None:
                    counters = read_wake_telemetry(wake_path)
                    if counters is not None:
                        wake_samples.append({"observed_monotonic_ns": now_ns,
                                             "measurement_elapsed_seconds": row["measurement_elapsed_seconds"],
                                             "counters": counters})
                resource_stream.write(json.dumps(row) + "\n")
                resource_stream.flush()
                next_sample = now_ns + 1_000_000_000
                if row["tree"]["pss_kib"] > peak_pss:
                    peak_pss = row["tree"]["pss_kib"]
                    snapshot(daemon.pid, args.output, "all-phases-peak-pss")
                if 0 <= row["measurement_elapsed_seconds"] < args.duration and row["tree"]["pss_kib"] > measurement_peak_pss:
                    measurement_peak_pss = row["tree"]["pss_kib"]
                    snapshot(daemon.pid, args.output, "measurement-peak-pss")
            elapsed = (now_ns - epoch["measurement_start_ns"]) / 1e9
            if args.scenario == "reload" and next_reload <= elapsed and next_reload < args.duration:
                version = int(next_reload / args.reload_period)
                address = f"192.0.2.{10 + version}"
                temporary = root / "m6a/hosts.new"
                temporary.write_text(f"{address} reload-proof.{PREFIX}\n")
                temporary.replace(root / "m6a/hosts")
                sent_ns = time.monotonic_ns()
                os.kill(daemon.pid, signal.SIGHUP)
                reloads.append({"scheduled_seconds": next_reload, "signal_monotonic_ns": sent_ns,
                                "host_address": address, "publish_lag_ns":
                                sent_ns - epoch["measurement_start_ns"] - int(next_reload * 1e9)})
                save(args.output / "reloads.json", reloads)
                pending_reload = {"row": reloads[-1], "next_query_ns": sent_ns,
                                  "deadline_ns": sent_ns + 2_000_000_000,
                                  "ident": 0x6000 + len(reloads)}
                next_reload += args.reload_period
            if pending_reload is not None:
                if now_ns >= pending_reload["next_query_ns"]:
                    request = query(f"reload-proof.{PREFIX}", ident=pending_reload["ident"])
                    reload_socket.send(request)
                    pending_reload["row"]["probe_request"] = request.hex()
                    pending_reload["next_query_ns"] = now_ns + 10_000_000
                while True:
                    try:
                        packet = reload_socket.recv(65535)
                    except BlockingIOError:
                        break
                    row = pending_reload["row"]
                    row.setdefault("observed_replies", []).append(packet.hex())
                    try:
                        valid = correct_reload_reply(packet, pending_reload["ident"], row["host_address"])
                    except (ValueError, IndexError, struct.error) as error:
                        row.setdefault("malformed_probes", []).append(repr(error))
                        valid = False
                    if valid:
                        received = time.monotonic_ns()
                        row.update({"published_monotonic_ns": received,
                                    "publication_seconds": (received - row["signal_monotonic_ns"]) / 1e9,
                                    "probe_reply": packet.hex(), "publication_correct": True})
                        save(args.output / "reloads.json", reloads)
                        pending_reload = None
                        break
                if pending_reload is not None and now_ns >= pending_reload["deadline_ns"]:
                    pending_reload["row"]["publication_correct"] = False
                    pending_reload["row"]["publication_error"] = "new A record not observed within 2 seconds"
                    pending_reload = None
            if time.monotonic() - started > args.warmup + args.duration + args.timeout_ms / 1000 + 15:
                raise TimeoutError("load generator did not finish")
            time.sleep(.005)
        if process.returncode != 0:
            raise RuntimeError(f"load generator exited {process.returncode}")
        for label, scheduled in boundaries:
            if label not in points:
                points[label] = snapshot(daemon.pid, args.output, label)
                points[label]["scheduled_monotonic_ns"] = scheduled
                points[label]["capture_lag_ns"] = points[label]["cgroup_cpu"]["monotonic_ns"] - scheduled
        if tftp is not None:
            tftp.wait(args.timeout_ms / 1000 + 3)
            if tftp.returncode != 0:
                raise RuntimeError(f"TFTP measurement worker exited {tftp.returncode}")
            if not (args.output / "tftp.json").exists():
                raise RuntimeError("TFTP worker did not produce complete counters")
        load_finished = snapshot(daemon.pid, args.output, "load-finished")
        if wake_path is not None:
            counters = read_wake_telemetry(wake_path)
            if counters is not None:
                wake_samples.append({"observed_monotonic_ns": time.monotonic_ns(),
                                     "measurement_elapsed_seconds": args.duration,
                                     "counters": counters})
        if pending_reload is not None:
            pending_reload["row"]["publication_correct"] = False
            pending_reload["row"]["publication_error"] = "window ended before publication"
        # Linux accumulates a child's CPU into cutime/cstime only when reaped.
        # Rust has no child to reap, so require the daemon's own FDs to return to
        # the confirmed pre-load idle value and remain stable before sampling.
        barrier = wait_for_drain(daemon.pid, idle_fd_count,
                                 timeout=args.drain_timeout_seconds)
        drain_samples = capture_drain_samples(
            daemon.pid, args.output, barrier, args.drain_sample_seconds)
        final = drain_samples["0"]["snapshot"]
        save(args.output / "resources.json", resources)
        wake_summary = summarize_wake_telemetry(wake_samples)
        save(args.output / "wake-counters.json", wake_summary)
        save(args.output / "reloads.json", reloads)
        load = json.loads((args.output / "load.json").read_text())
        if load.get("interrupted") or load.get("output_failed"):
            raise RuntimeError("load generator reports interrupted or incomplete evidence")
        segments = {}
        ordered = [(label, points[label]) for label, _ in boundaries]
        ticks_per_second = os.sysconf("SC_CLK_TCK")
        for (left, before), (right, after) in zip(ordered, ordered[1:]):
            ticks = after["tree"]["cpu_ticks"] - before["tree"]["cpu_ticks"]
            cg_seconds = (after["cgroup_cpu"]["usage_usec"] - before["cgroup_cpu"]["usage_usec"]) / 1e6
            if cg_seconds < 0:
                raise RuntimeError("primary cgroup CPU accounting decreased")
            segments[left + ".." + right] = {
                "cpu_ticks": ticks, "proc_cpu_seconds": ticks / ticks_per_second,
                "cpu_seconds": cg_seconds,
                "proc_snapshot_churn": ticks < 0 or bool(before["children_disappeared_during_sample"]
                                                           or after["children_disappeared_during_sample"]),
                "start_capture_lag_ns": before["capture_lag_ns"],
                "end_capture_lag_ns": after["capture_lag_ns"]}
        measured = [r for r in resources if 0 <= r["measurement_elapsed_seconds"] < args.duration]
        return {"epoch": epoch, "load": load, "cpu_before_warmup": initial,
                "cpu_points": points, "cpu_segments": segments,
                "cpu_load_finished": load_finished, "cpu_after_drain": final,
                "drain_barrier": barrier, "drain_samples": drain_samples,
                "idle_cpu": idle_cpu, "wake_counters": wake_summary,
                "cpu_resolution_seconds": 1 / ticks_per_second,
                "measurement_cpu_seconds": (points["measurement-end"]["cgroup_cpu"]["usage_usec"] -
                                            points["measurement-start"]["cgroup_cpu"]["usage_usec"]) / 1e6,
                "proc_measurement_cpu_seconds": (points["measurement-end"]["tree"]["cpu_ticks"] -
                                                 points["measurement-start"]["tree"]["cpu_ticks"]) / ticks_per_second,
                "postwindow_cpu_seconds": (final["tree"]["cpu_ticks"] -
                                          points["measurement-end"]["tree"]["cpu_ticks"]) / ticks_per_second,
                "drain_seconds": barrier["elapsed_seconds"],
                "drain_sample_window_seconds": max(args.drain_sample_seconds, default=0.0),
                "idle_fd_count": idle_fd_count,
                "max_controller_loop_gap_ns": max_controller_gap_ns,
                "reload_publication_observation": "upper bound; 10ms probe interval plus recorded controller scheduling gaps",
                "sample_count": len(measured), "all_sample_count": len(resources),
                "quality": {"capture_lag_passed": all(0 <= p["capture_lag_ns"] <= 250_000_000 for p in points.values()),
                            "sample_count_passed": len(measured) >= max(1, int(args.duration) - 2),
                            "reload_schedule_complete": args.scenario != "reload" or len(reloads) == int(
                                (args.duration - 1e-9) // args.reload_period),
                            "service_cpu_affinity_passed": all(
                                node["affinity"] == [args.cpu_daemon] for row in measured
                                for node in [row["parent"], *row["children"]]),
                            "worker_cpu_affinity_passed": all(
                                row[label].get("affinity") == [cpu] for row in measured
                                for label, cpu in (("loadgen", args.cpu_load), ("upstream", args.cpu_upstream), ("tftp", args.cpu_load))
                                if label in row and not row[label].get("exited_during_sample")),
                            "drain_barrier_passed": barrier["observations"][-1]["stable_samples"] >= barrier["stable_samples_required"],
                            "wake_metrics_passed": not args.wake_metrics or wake_summary["available"]},
                "peaks": {key: max((row["tree"][key] for row in measured), default=0)
                          for key in ("rss_kib", "pss_kib", "fd_count", "thread_count", "child_processes")},
                "parent_peaks": {key: max((row["parent"][key] for row in measured), default=0)
                                 for key in ("rss_kib", "pss_kib", "hwm_kib", "fd_count", "thread_count")}}
    finally:
        if tftp is not None and tftp.poll() is None:
            tftp.terminate()
            try:
                tftp.wait(3)
            except subprocess.TimeoutExpired:
                tftp.kill()
                tftp.wait(3)
        if tftp_log is not None:
            tftp_log.close()
        save(args.output / "resources.json", resources)
        save(args.output / "reloads.json", reloads)
        save(args.output / "cpu-points.json", points)
        resource_stream.close()
        if reload_socket is not None:
            reload_socket.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(3)
        log.close()


def run_window(args):
    global CGROUP_PATH
    if os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        raise RuntimeError("root in run_isolated.sh required")
    if len({args.cpu_daemon, args.cpu_upstream, args.cpu_load, args.cpu_control}) != 4:
        raise ValueError("service, upstream, clients and sampling require disjoint CPUs")
    os.sched_setaffinity(0, {args.cpu_control})
    args.output = args.output.resolve()
    if "private" not in args.output.parts:
        raise ValueError("evidence must remain under private/")
    args.output.mkdir(parents=True, exist_ok=False)
    expected = STOCK_SHA256 if args.implementation == "c" else args.expected_rust_sha
    if args.implementation == "r3" and expected != R3_SHA:
        raise ValueError("M5 opt3 identity mismatch")
    if args.implementation != "c" and sha256(args.rust) != expected:
        raise ValueError("Rust artifact identity mismatch")
    identity = {"argv": sys.argv, "implementation": args.implementation,
                "scenario": args.scenario, "round": args.round, "expected_elf_sha256": expected,
                "protocol_sha256": sha256(args.protocol) if args.protocol else None,
                "loadgen_sha256": sha256(args.loadgen), "runner_sha256": sha256(__file__),
                "upstream_sha256": sha256(args.upstream), "tcp_profile": args.tcp_profile,
                "saturation_seconds": args.saturation_seconds, "excluded_preflight": args.preflight,
                "seed": args.seed, "cpus": {"daemon": args.cpu_daemon, "upstream": args.cpu_upstream,
                                             "loadgen": args.cpu_load, "control": args.cpu_control},
                "warmup_seconds": args.warmup, "duration_seconds": args.duration,
                "rate": args.rate, "clients": args.clients, "kernel": os.uname().release,
                "idle_cpu_seconds": args.idle_seconds,
                "drain_sample_seconds": args.drain_sample_seconds,
                "wake_metrics": args.wake_metrics}
    save(args.output / "identity.json", identity)
    daemon = upstream = None
    daemon_log = upstream_log = None
    result = {"accepted": False, "identity": identity}
    try:
        root = prepare(args.image_root, None, args.output / "filesystem", args.rust)
        directory = root / "m6a"
        directory.mkdir()
        config = config_for(args.scenario, args.tcp_profile)
        (directory / "config").write_text(config)
        (args.output / "config").write_text(config)
        (directory / "leases").write_text("")
        if args.scenario == "dhcp":
            for i in range(20):
                subprocess.run(["ip", "addr", "add", f"127.0.0.{i + 10}/8", "dev", "lo"], check=True)
            save(args.output / "network.json", json.loads(subprocess.run(
                ["ip", "-j", "addr"], check=True, capture_output=True, text=True).stdout))
        if args.scenario == "reload":
            (directory / "hosts").write_text(f"192.0.2.10 reload-proof.{PREFIX}\n")
            (directory / "tftp").mkdir()
            (directory / "tftp/payload").write_bytes(bytes(range(256)) * 4)
        upstream_log = (args.output / "upstream.log").open("wb")
        upstream_command = ["taskset", "-c", str(args.cpu_upstream), str(args.upstream),
                            "--port", str(UPSTREAM_PORT),
                            "--epoch-file", str(args.output / "measurement-start-ns"),
                            "--output", str(args.output / "upstream.json"),
                            "--ready-file", str(args.output / "upstream-ready.json"),
                            "--steady-seconds", str(args.duration - args.saturation_seconds)]
        if args.scenario == "fault":
            upstream_command += ["--fault-start", str(args.fault_start), "--fault-end", str(args.fault_end)]
        save(args.output / "upstream-command.json", upstream_command)
        upstream = subprocess.Popen(upstream_command,
                                    stdout=upstream_log, stderr=upstream_log)
        wait_file(args.output / "upstream-ready.json", 5, upstream)
        daemon_log = (args.output / "daemon.log").open("wb")
        cg_name = "dnsmasq-m6a-" + hashlib.sha256(
            (str(args.output) + str(time.monotonic_ns())).encode()).hexdigest()[:16]
        CGROUP_PATH = args.cgroup_parent / cg_name
        CGROUP_PATH.mkdir()
        daemon_environment = os.environ.copy()
        if args.wake_metrics:
            # The daemon is chrooted into ``root``; this path resolves to the
            # host-side ``root/m6a/wake-metrics.json`` read by run_load.
            daemon_environment["DNSMASQ_M6B_WAKE_METRICS"] = "/m6a/wake-metrics.json"
        daemon = subprocess.Popen(["taskset", "-c", str(args.cpu_daemon),
                                  *command(root, "c" if args.implementation == "c" else "rust", "-k", "-C", "/m6a/config")],
                                 stdout=daemon_log, stderr=daemon_log, env=daemon_environment)
        (CGROUP_PATH / "cgroup.procs").write_text(str(daemon.pid))
        save(args.output / "cgroup.json", {"path": str(CGROUP_PATH), "daemon_pid": daemon.pid,
                                           "cpu_initial": cgroup_cpu(),
                                           "controller": "cpu.stat usage_usec includes service descendants"})
        deadline = time.monotonic() + 10
        while True:
            udp = Path("/proc") / str(daemon.pid) / "net/udp"
            if (directory / "pid").exists() and udp.exists() and any(
                    row.split()[1] == f"0100007F:{PORT:04X}" for row in udp.read_text().splitlines()[1:]):
                break
            if not alive(daemon.pid) or time.monotonic() > deadline:
                raise RuntimeError("service did not become ready")
            time.sleep(.02)
        actual = process_identity(root, daemon.pid)
        save(args.output / "process-identity.json", actual)
        if actual["sha256"] != expected or os.sched_getaffinity(daemon.pid) != {args.cpu_daemon}:
            raise AssertionError("service SHA or CPU affinity mismatch")
        snapshot(daemon.pid, args.output, "empty")
        if args.scenario == "hit" or (args.scenario == "tcp" and args.tcp_profile == "hit"):
            fill_and_prove(args.output, CAPACITY, True, upstream.pid, daemon.pid)
            snapshot(daemon.pid, args.output, "cache-full")
        elif args.scenario == "mixed":
            fill_and_prove(args.output, args.cache_names, False, upstream.pid, daemon.pid, mixed=True)
        elif args.scenario == "reload":
            fill_and_prove(args.output, args.cache_names, False, upstream.pid, daemon.pid)
        result["measurement"] = run_load(args, daemon, root, upstream)
        result["accepted"] = all(result["measurement"]["quality"].values())
        counters = result["measurement"]["load"]["measurement"]
        result["behavior_checks"] = {
            "wrong_answers": counters["wrong"], "transport_errors": counters["transport_error"],
            "timeouts": counters["timeout"],
            "errors_excluded_from_correct_throughput": True,
            "definition": "Actual service errors remain valid observations; accepted is the measurement-method gate."}
        if args.scenario == "reload":
            published = json.loads((args.output / "reloads.json").read_text())
            result["behavior_checks"]["reload_publications"] = published
            result["behavior_checks"]["tftp"] = json.loads((args.output / "tftp.json").read_text())
        if args.scenario == "dhcp":
            release_deadline = time.monotonic() + 2
            while (directory / "leases").read_text().strip() and time.monotonic() < release_deadline:
                time.sleep(.01)
            leases = (directory / "leases").read_text()
            (args.output / "final-leases").write_text(leases)
            result["dhcp_release_endstate"] = {"leasefile_empty": not leases.strip(),
                                               "remaining_rows": leases.splitlines()}
            result["behavior_checks"]["dhcp_release_endstate"] = result["dhcp_release_endstate"]
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if daemon is not None:
            try:
                result["cpu_before_termination"] = cgroup_cpu()
                result["cleanup"] = stop_daemon(daemon)
                result["cpu_after_termination"] = cgroup_cpu()
                if "measurement" in result:
                    last = result["measurement"]["cpu_after_drain"]["tree"]["cpu_ticks"] / os.sysconf("SC_CLK_TCK")
                    wait4_total = result["cleanup"]["wait4_user_seconds"] + result["cleanup"]["wait4_system_seconds"]
                    result["proc_wait4_cpu_crosscheck"] = {
                        "last_proc_tree_cpu_seconds": last, "wait4_total_seconds": wait4_total,
                        "difference_seconds": wait4_total - last,
                        "note": "secondary quantized CPU crosscheck; includes termination work after last proc sample"}
                if result["cleanup"]["forced_kill"] or result["cleanup"]["returncode"] != 0:
                    result["accepted"] = False
            except Exception as error:
                result["cleanup_error"] = repr(error)
                result["accepted"] = False
        if CGROUP_PATH is not None:
            try:
                occupants = (CGROUP_PATH / "cgroup.procs").read_text().split()
                result["cgroup_cleanup"] = {"remaining_pids": occupants}
                if occupants:
                    raise RuntimeError("service cgroup still has processes after termination")
                CGROUP_PATH.rmdir()
                result["cgroup_cleanup"]["removed"] = True
            except Exception as error:
                result["cgroup_cleanup_error"] = repr(error)
                result["accepted"] = False
            CGROUP_PATH = None
        if upstream is not None:
            upstream.terminate()
            try:
                upstream.wait(5)
            except subprocess.TimeoutExpired:
                upstream.kill()
                upstream.wait(3)
                result["accepted"] = False
                result["upstream_forced_kill"] = True
            result["upstream_returncode"] = upstream.returncode
            if upstream.returncode != 0:
                result["accepted"] = False
        for stream in (daemon_log, upstream_log):
            if stream is not None:
                stream.close()
        if (args.output / "upstream.json").exists():
            stats = json.loads((args.output / "upstream.json").read_text())
            result["upstream"] = stats
            if stats.get("invalid_queries", 0):
                result["accepted"] = False
            if (args.scenario == "hit" or (args.scenario == "tcp" and args.tcp_profile == "hit")) and stats.get("disabled_requests", 0):
                result["accepted"] = False
                result["unexpected_upstream_requests"] = True
        else:
            result["accepted"] = False
            result["upstream_evidence_missing"] = True
        result["measurement_valid"] = result["accepted"]
        save(args.output / "result.json", result)
    return 0 if result["accepted"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tftp-worker", action="store_true")
    parser.add_argument("--implementation", choices=("c", "r3", "rs"))
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--expected-rust-sha", default=R3_SHA)
    parser.add_argument("--image-root", type=Path)
    parser.add_argument("--protocol", type=Path)
    parser.add_argument("--loadgen", type=Path)
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--cgroup-parent", type=Path, default=Path("/sys/fs/cgroup"))
    parser.add_argument("--scenario", choices=("hit", "miss", "mixed", "fault", "tcp", "dhcp", "reload"), required=True)
    parser.add_argument("--round", type=int, default=0)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu-daemon", type=int, default=0)
    parser.add_argument("--cpu-upstream", type=int, default=1)
    parser.add_argument("--cpu-load", type=int, default=2)
    parser.add_argument("--cpu-control", type=int, default=3)
    parser.add_argument("--warmup", type=float, default=30)
    parser.add_argument("--duration", type=float, default=120)
    parser.add_argument("--clients", type=int, default=20)
    parser.add_argument("--rate", type=float, default=10000)
    parser.add_argument("--saturation-seconds", type=float, default=30)
    parser.add_argument("--cache-names", type=int, default=4096)
    parser.add_argument("--tcp-profile", choices=("hit", "miss", "local"), default="hit")
    parser.add_argument("--fault-start", type=float, default=30)
    parser.add_argument("--fault-end", type=float, default=60)
    parser.add_argument("--reload-period", type=float, default=10)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--timeout-ms", type=int, default=1000)
    parser.add_argument("--idle-seconds", type=float, default=0.0,
                        help="no-load daemon CPU interval (M6b formal uses 60)")
    parser.add_argument("--drain-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--drain-sample-seconds", default="0,1,5,60")
    parser.add_argument("--wake-metrics", action="store_true",
                        help="require/read DNSMASQ_M6B_WAKE_METRICS sidecar telemetry")
    args = parser.parse_args()
    args.drain_sample_seconds = parse_drain_sample_seconds(args.drain_sample_seconds)
    if args.tftp_worker:
        return tftp_worker(args)
    if args.seed is None:
        args.seed = 0x4d364100 + args.round
    if any(getattr(args, key) is None for key in ("implementation", "rust", "image_root", "loadgen", "upstream")):
        parser.error("implementation, rust, image-root, loadgen and upstream are required")
    if not args.preflight and (args.warmup != 30 or args.duration != 120 or args.round < 1 or args.protocol is None):
        parser.error("formal windows require protocol, round>=1, warmup30 and duration120")
    return run_window(args)


if __name__ == "__main__":
    raise SystemExit(main())
