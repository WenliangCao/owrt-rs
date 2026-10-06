#!/usr/bin/env python3
"""One CPU-separated M6a window; this tool never builds or changes a product.

Invoke under run_isolated.sh. Each invocation starts an exact-image overlay,
an upstream on CPU1, a service on CPU0 and the native client on CPU2. The
controller and /proc sampling use CPU3. Raw evidence remains under private/.
"""
from __future__ import annotations

import argparse
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
            except FileNotFoundError:
                pass
    save(directory / f"{label}.json", tree)
    return tree


def correct_answer(host: str, kind: int, ident: int, packet: bytes):
    result = semantics(packet)
    expected = semantics(answer(query(host, kind, ident)))
    def records_without_ttl(value):
        return [{k: v for k, v in record.items() if k != "ttl"} for record in value["records"]]
    return (result["id"] == ident and result["flags"] & 0x800f == 0x8000
            and result["questions"] == [[host, kind, 1]]
            and records_without_ttl(result) == records_without_ttl(expected)
            and all(0 < row["ttl"] <= TTL for row in result["records"]))


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
                    if len(rows) < 10:
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
              "--mode", mode, "--host", "127.0.0.1", "--port", str(PORT),
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
    process = subprocess.Popen(command_line, stdout=log, stderr=log)
    resources, points, reloads = [], {}, []
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
                    parsed = semantics(packet)
                    row = pending_reload["row"]
                    if (parsed["id"] == pending_reload["ident"]
                            and parsed["questions"] == [[f"reload-proof.{PREFIX}", 1, 1]]
                            and parsed["flags"] & 0x800f == 0x8000
                            and len(parsed["records"]) == 1
                            and parsed["records"][0]["type"] == 1
                            and parsed["records"][0]["data"] == row["host_address"]
                            and 0 < parsed["records"][0]["ttl"] <= TTL):
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
        if tftp is not None:
            tftp.wait(args.timeout_ms / 1000 + 3)
            if tftp.returncode != 0:
                raise RuntimeError(f"TFTP measurement worker exited {tftp.returncode}")
            if not (args.output / "tftp.json").exists():
                raise RuntimeError("TFTP worker did not produce complete counters")
        for label, scheduled in boundaries:
            if label not in points:
                points[label] = snapshot(daemon.pid, args.output, label)
                points[label]["scheduled_monotonic_ns"] = scheduled
                points[label]["capture_lag_ns"] = points[label]["cgroup_cpu"]["monotonic_ns"] - scheduled
        load_finished = snapshot(daemon.pid, args.output, "load-finished")
        if pending_reload is not None:
            pending_reload["row"]["publication_correct"] = False
            pending_reload["row"]["publication_error"] = "window ended before publication"
        # Linux accumulates a child's CPU into cutime/cstime only when reaped.
        # Sum live child CPU during sampling, then require connection-close drain.
        drain_started = time.monotonic()
        while process_tree(daemon.pid)["tree"]["child_processes"]:
            if time.monotonic() - drain_started > 5:
                raise RuntimeError("TCP daemon child did not drain")
            time.sleep(.01)
        final = snapshot(daemon.pid, args.output, "after-drain")
        save(args.output / "resources.json", resources)
        save(args.output / "reloads.json", reloads)
        load = json.loads((args.output / "load.json").read_text())
        if load.get("interrupted") or load.get("output_failed"):
            raise RuntimeError("load generator reports interrupted or incomplete evidence")
        segments = {}
        ordered = [(label, points[label]) for label, _ in boundaries]
        ticks_per_second = os.sysconf("SC_CLK_TCK")
        for (left, before), (right, after) in zip(ordered, ordered[1:]):
            ticks = after["tree"]["cpu_ticks"] - before["tree"]["cpu_ticks"]
            if ticks < 0:
                raise RuntimeError("CPU accounting decreased across a measured segment")
            segments[left + ".." + right] = {
                "cpu_ticks": ticks, "proc_cpu_seconds": ticks / ticks_per_second,
                "cpu_seconds": (after["cgroup_cpu"]["usage_usec"] - before["cgroup_cpu"]["usage_usec"]) / 1e6,
                "start_capture_lag_ns": before["capture_lag_ns"],
                "end_capture_lag_ns": after["capture_lag_ns"]}
        measured = [r for r in resources if 0 <= r["measurement_elapsed_seconds"] < args.duration]
        return {"epoch": epoch, "load": load, "cpu_before_warmup": initial,
                "cpu_points": points, "cpu_segments": segments,
                "cpu_load_finished": load_finished, "cpu_after_drain": final,
                "cpu_resolution_seconds": 1 / ticks_per_second,
                "measurement_cpu_seconds": (points["measurement-end"]["cgroup_cpu"]["usage_usec"] -
                                            points["measurement-start"]["cgroup_cpu"]["usage_usec"]) / 1e6,
                "proc_measurement_cpu_seconds": (points["measurement-end"]["tree"]["cpu_ticks"] -
                                                 points["measurement-start"]["tree"]["cpu_ticks"]) / ticks_per_second,
                "postwindow_cpu_seconds": (final["tree"]["cpu_ticks"] -
                                          points["measurement-end"]["tree"]["cpu_ticks"]) / ticks_per_second,
                "drain_seconds": time.monotonic() - drain_started,
                "max_controller_loop_gap_ns": max_controller_gap_ns,
                "reload_publication_observation": "upper bound; 10ms probe interval plus recorded controller scheduling gaps",
                "sample_count": len(measured), "all_sample_count": len(resources),
                "quality": {"capture_lag_passed": all(0 <= p["capture_lag_ns"] <= 250_000_000 for p in points.values()),
                            "sample_count_passed": len(measured) >= max(1, int(args.duration) - 2),
                            "service_cpu_affinity_passed": all(
                                node["affinity"] == [args.cpu_daemon] for row in measured
                                for node in [row["parent"], *row["children"]])},
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
                "rate": args.rate, "clients": args.clients, "kernel": os.uname().release}
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
        daemon = subprocess.Popen(["taskset", "-c", str(args.cpu_daemon),
                                  *command(root, "c" if args.implementation == "c" else "rust", "-k", "-C", "/m6a/config")],
                                 stdout=daemon_log, stderr=daemon_log)
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
    args = parser.parse_args()
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
