#!/usr/bin/env python3
"""Compare exact-image daemon resources with 4096 proven live dynamic A records.

Run a 300-second pair as preflight, then a fresh 600-second pair. Both sides
use identical short names and one A record per name. After filling, the
upstream stops answering. Every name must still answer correctly without an
upstream request; insertion counters are never used as occupancy evidence.
Each side first runs a separate 4095-record negative control. All listeners
require run_isolated.sh; raw packets and image files stay below private/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

from dns_service_probe import query, read_name, rr, semantics
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256
from m3_soak import proc_resources, run_parallel

PRIVATE = Path(__file__).resolve().parents[2] / "private"
CAPACITY = 4096
TTL = 3600
PORT = 15353
UPSTREAM_PORT = 15354
NAMES = [f"c{index:04x}.cache.test" for index in range(CAPACITY)]
RESOURCE_KEYS = ("rss_kib", "pss_kib", "rss_anon_kib", "rss_file_kib",
                 "fd_count", "thread_count", "child_processes")


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def address(host):
    index = int(host.split(".")[0][1:], 16)
    if host != NAMES[index]:
        raise ValueError("name outside frozen input set")
    return f"198.18.{index >> 8}.{index & 255}"


def upstream_answer(packet):
    host, end = read_name(packet, 12)
    if struct.unpack_from("!HH", packet, end) != (1, 1):
        raise ValueError("fixture accepts only IN A")
    question = packet[12:end + 4]
    return (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
            + question + rr(1, socket.inet_aton(address(host)), TTL))


def valid_reply(host, ident, packet):
    value = semantics(packet)
    records = value["records"]
    return (value["id"] == ident and value["flags"] & 0x800f == 0x8000
            and value["questions"] == [[host, 1, 1]] and len(records) == 1
            and records[0] == {"section": "answer", "name": host,
                               "type": 1, "class": 1,
                               "ttl": records[0]["ttl"], "data": address(host)}
            and 0 < records[0]["ttl"] <= TTL)


def occupancy_proof(rows, upstream_requests):
    """Require every distinct expected name, not a count of insert attempts."""
    hits = {row["name"] for row in rows if row.get("hit") is True}
    failures = [row for row in rows if row.get("hit") is not True]
    accepted = (len(rows) == CAPACITY and hits == set(NAMES)
                and not failures and upstream_requests == 0)
    return {"accepted": accepted, "expected_dynamic_a_entries": CAPACITY,
            "unique_correct_hits": len(hits), "upstream_requests": upstream_requests,
            "failures": failures,
            "live_dynamic_a_entries": CAPACITY if accepted else None,
            "method": "All fixed names answer with positive TTL after upstream answers are disabled; no upstream request is observed. One A record per name, configured capacity 4096."}


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", UPSTREAM_PORT))
        self.socket.settimeout(.05)
        self.lock = threading.Lock()
        self.enabled = True
        self.trace = []
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            try:
                packet, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                row = {"packet": packet.hex(), "answered": self.enabled}
                self.trace.append(row)
                if self.enabled:
                    try:
                        reply = upstream_answer(packet)
                        self.socket.sendto(reply, peer)
                        row["reply"] = reply.hex()
                    except (ValueError, IndexError, OSError, struct.error) as error:
                        row["error"] = repr(error)

    def disable(self):
        with self.lock:
            self.enabled = False
            return len(self.trace)

    def count(self):
        with self.lock:
            return len(self.trace)

    def close(self):
        self.stop_event.set()
        self.thread.join(2)
        self.socket.close()
        if self.thread.is_alive():
            raise RuntimeError("upstream audit thread did not stop")


def resources(pid):
    row = proc_resources(pid)
    if not row.get("alive"):
        raise RuntimeError("daemon exited during sampling")
    for line in (Path("/proc") / str(pid) / "status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("RssAnon", "RssFile"):
            row[{"RssAnon": "rss_anon_kib", "RssFile": "rss_file_kib"}[key]] = int(value.split()[0])
    if any(type(row.get(key)) is not int for key in RESOURCE_KEYS):
        raise RuntimeError("missing required resource measurement")
    return row


def snapshot(fixture, label):
    directory = fixture.out / "proc-snapshots"
    directory.mkdir(exist_ok=True)
    pid = fixture.process.pid
    for name in ("status", "smaps_rollup"):
        (directory / f"{label}.{name}").write_bytes((Path("/proc") / str(pid) / name).read_bytes())
    return resources(pid)


def require_binary_identity(identity, expected_sha):
    if identity["sha256"] != expected_sha:
        raise AssertionError("running ELF differs from expected binary")


class Fixture:
    def __init__(self, root, implementation, out, expected_sha):
        self.root, self.implementation, self.out = root, implementation, out
        self.expected_sha = expected_sha
        out.mkdir()
        directory = root / "cache-full"
        directory.mkdir(exist_ok=True)
        self.pidfile = directory / "pid"
        config = ("no-resolv\nno-hosts\nuser=root\nbind-interfaces\n"
                  "interface=lo\nlisten-address=127.0.0.1\n"
                  f"port={PORT}\ncache-size={CAPACITY}\nserver=127.0.0.1#{UPSTREAM_PORT}\n")
        (directory / "config").write_text(config)
        (out / "config").write_text(config)
        self.process = self.upstream = self.client = None
        self.log = self.wire = None
        self.requests = 0

    def start(self):
        self.upstream = Upstream()
        self.log = (self.out / "daemon.log").open("wb")
        self.wire = (self.out / "wire.jsonl").open("w")
        self.process = subprocess.Popen(
            command(self.root, self.implementation, "-k", "-C", "/cache-full/config", "-x", "/cache-full/pid"),
            stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("daemon exited before readiness")
            # No readiness DNS query may add an unplanned cache entry.
            udp = Path("/proc") / str(self.process.pid) / "net/udp"
            if self.pidfile.exists() and udp.exists() and any(
                    row.split()[1] == f"0100007F:{PORT:04X}"
                    for row in udp.read_text().splitlines()[1:] if len(row.split()) > 1):
                break
            time.sleep(.02)
        else:
            raise TimeoutError("daemon readiness")
        identity = process_identity(self.root, self.process.pid)
        save(self.out / "process-identity.json", identity)
        require_binary_identity(identity, self.expected_sha)
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.connect(("127.0.0.1", PORT))
        self.client.settimeout(1)

    def ask(self, host):
        ident = self.requests & 0xffff
        self.requests += 1
        packet = query(host, ident=ident)
        row = {"name": host, "hit": False, "request": packet.hex()}
        try:
            self.client.send(packet)
            reply = self.client.recv(4096)
            row["response"] = reply.hex()
            row["hit"] = valid_reply(host, ident, reply)
        except (OSError, ValueError, IndexError, struct.error) as error:
            row["error"] = repr(error)
        self.wire.write(json.dumps(row) + "\n")
        return {key: value for key, value in row.items() if key not in ("request", "response")}

    def fill(self, count):
        for host in NAMES[:count]:
            row = self.ask(host)
            if not row["hit"]:
                raise AssertionError({"stage": "fill", "row": row})

    def prove(self, before):
        rows = [self.ask(host) for host in NAMES]
        return occupancy_proof(rows, self.upstream.count() - before)

    def close(self):
        result = {"forced_kill": False}
        if self.process is not None:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGTERM)
                try:
                    self.process.wait(5)
                except subprocess.TimeoutExpired:
                    result["forced_kill"] = True
                    self.process.kill()
                    self.process.wait(5)
            result["process_returncode"] = self.process.returncode
            result["daemon_alive_after_stop"] = proc_resources(self.process.pid).get("alive", False)
        result["pid_file_before_runner_cleanup"] = self.pidfile.exists()
        if self.pidfile.exists():
            self.pidfile.unlink()
        result["pid_file_after_stop"] = self.pidfile.exists()
        if self.client is not None:
            self.client.close()
        if self.upstream is not None:
            self.upstream.close()
            save(self.out / "upstream.json", self.upstream.trace)
        for stream in (self.log, self.wire):
            if stream is not None:
                stream.close()
        return result


def clean(result):
    return (result.get("process_returncode") == 0
            and result.get("daemon_alive_after_stop") is False
            and result.get("pid_file_before_runner_cleanup") is False
            and result.get("pid_file_after_stop") is False
            and result.get("forced_kill") is False)


def summary(rows):
    report = {}
    for key in RESOURCE_KEYS:
        values = [row[key] for row in rows]
        report[key] = {"first": values[0], "last": values[-1], "peak": max(values),
                       "third_quarter_median": statistics.median(values[len(values)//2:3*len(values)//4]),
                       "fourth_quarter_median": statistics.median(values[3*len(values)//4:])}
        report[key]["q4_minus_q3"] = (report[key]["fourth_quarter_median"]
                                      - report[key]["third_quarter_median"])
    return report


def run_side(args):
    if os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        raise SystemExit("run requires root through run_isolated.sh")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {"scope": "4096 live short-name dynamic A entries; no complex RR or long-name claim",
              "source_commit": args.source_commit, "implementation": args.implementation,
              "failures": [], "accepted": False, "duration_seconds": args.duration_seconds,
              "resource_review_required": True,
              "accepted_scope": "Collection, full-cache proofs and cleanup only; RSS growth requires review.",
              "cpu_affinity": sorted(os.sched_getaffinity(0)),
              "network_namespace": os.readlink("/proc/self/ns/net")}
    fixture = None
    try:
        if sha256(args.rust_binary) != args.expected_rust_sha:
            raise AssertionError("Rust ELF identity changed")
        root = prepare(args.image_root, None, out / "rootfs-stage", args.rust_binary)
        result["binary_sha256"] = sha256(root / ("usr/sbin/dnsmasq" if args.implementation == "c" else "usr/sbin/dnsmasq-rs"))
        expected_sha = STOCK_SHA256 if args.implementation == "c" else args.expected_rust_sha
        require_binary_identity({"sha256": result["binary_sha256"]}, expected_sha)
        fixture = Fixture(root, args.implementation, out / "negative-missing-one", expected_sha)
        fixture.start()
        fixture.fill(CAPACITY - 1)
        proof = fixture.prove(fixture.upstream.disable())
        result["negative_control"] = proof
        result["negative_cleanup"] = fixture.close()
        fixture = None
        if (proof["accepted"] or proof["unique_correct_hits"] != CAPACITY - 1
                or proof["upstream_requests"] < 1
                or [row["name"] for row in proof["failures"]] != [NAMES[-1]]
                or not clean(result["negative_cleanup"])):
            raise AssertionError("missing-one negative control did not reject exactly the absent name")
        fixture = Fixture(root, args.implementation, out / "full", expected_sha)
        fixture.start()
        result["empty_resources"] = snapshot(fixture, "empty")
        fixture.fill(CAPACITY)
        result["filled_resources"] = snapshot(fixture, "filled")
        disabled_at = fixture.upstream.disable()
        result["initial_occupancy_proof"] = fixture.prove(disabled_at)
        if not result["initial_occupancy_proof"]["accepted"]:
            raise AssertionError("initial full-cache proof failed")
        result["verified_resources"] = snapshot(fixture, "verified")
        result["fill_upstream_requests"] = disabled_at
        samples = []
        started = time.monotonic()
        queries = 0
        with (out / "metrics.jsonl").open("w") as stream:
            for tick in range(args.duration_seconds):
                row = {"tick": tick, "elapsed_seconds": time.monotonic() - started,
                       **resources(fixture.process.pid)}
                samples.append(row)
                stream.write(json.dumps(row) + "\n")
                stream.flush()
                for _ in range(64):
                    observed = fixture.ask(NAMES[queries % CAPACITY])
                    queries += 1
                    if not observed["hit"]:
                        raise AssertionError({"stage": "full-cache-window", "row": observed})
                time.sleep(max(0, started + tick + 1 - time.monotonic()))
        result["observed_duration_seconds"] = time.monotonic() - started
        result["sample_count"] = len(samples)
        result["window_queries"] = queries
        result["maximum_sample_lag_seconds"] = max(row["elapsed_seconds"] - row["tick"] for row in samples)
        result["resource_summary"] = summary(samples)
        result["rss_changes_kib"] = {
            "empty_to_filled": result["filled_resources"]["rss_kib"] - result["empty_resources"]["rss_kib"],
            "filled_to_full_hit_scan": result["verified_resources"]["rss_kib"] - result["filled_resources"]["rss_kib"],
            "full_hit_scan_to_window_q4": result["resource_summary"]["rss_kib"]["fourth_quarter_median"] - result["verified_resources"]["rss_kib"],
        }
        result["observed_fill_rss_bytes_per_entry"] = result["rss_changes_kib"]["empty_to_filled"] * 1024 / CAPACITY
        result["after_window_resources"] = snapshot(fixture, "after-window")
        result["final_occupancy_proof"] = fixture.prove(disabled_at)
        if not result["final_occupancy_proof"]["accepted"]:
            raise AssertionError("final full-cache proof failed")
        if any(row["thread_count"] != 1 or row["child_processes"] != 0 for row in samples):
            raise AssertionError("daemon did not stay single-threaded without children")
    except Exception as error:
        result["failures"].append(repr(error))
    finally:
        if fixture is not None:
            try:
                result["cleanup"] = fixture.close()
            except Exception as error:
                result["failures"].append(f"cleanup failed: {error!r}")
    result["accepted"] = (not result["failures"] and clean(result.get("cleanup", {}))
                          and result.get("sample_count") == args.duration_seconds
                          and result.get("observed_duration_seconds", 0) >= args.duration_seconds)
    save(out / "run.json", result)
    print(json.dumps({"accepted": result["accepted"], "failures": result["failures"]}))
    return 0 if result["accepted"] else 1


def pair(args):
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cpus = args.cpus or sorted(os.sched_getaffinity(0))[:2]
    if len(cpus) != 2 or cpus[0] == cpus[1] or not set(cpus) <= os.sched_getaffinity(0):
        raise SystemExit("pair needs two distinct available CPUs")
    scripts = Path(__file__).resolve().parent
    records = []
    for side, cpu in zip(("c", "rust"), cpus):
        argv = ["taskset", "-c", str(cpu), "sh", str(scripts / "run_isolated.sh"), sys.executable,
                str(Path(__file__).resolve()), "run", "--image-root", str(args.image_root),
                "--rust-binary", str(args.rust_binary), "--source-commit", args.source_commit,
                "--expected-rust-sha", args.expected_rust_sha, "--implementation", side,
                "--duration-seconds", str(args.duration_seconds), "--out", str(out / side)]
        records.append({"implementation": side, "cpu": cpu, "argv": argv})
    failures = []
    try:
        run_parallel(records, out, args.duration_seconds + 240)
    except Exception as error:
        failures.append(f"pair runner failed: {error!r}")
    save(out / "commands.json", records)
    runs = {}
    for row in records:
        side = row["implementation"]
        path = out / side / "run.json"
        if path.exists():
            runs[side] = json.loads(path.read_text())
        if (row.get("returncode") != 0 or row.get("timed_out")
                or not runs.get(side, {}).get("accepted")):
            failures.append(f"{side} failed; retained side result and log")
    differences = {}
    if set(runs) == {"c", "rust"} and not failures:
        c, rust = runs["c"], runs["rust"]
        if c["network_namespace"] == rust["network_namespace"]:
            failures.append("C and Rust share a network namespace")
        if [c["cpu_affinity"], rust["cpu_affinity"]] != [[cpus[0]], [cpus[1]]]:
            failures.append("CPU assignment not observed")
        if c["window_queries"] != rust["window_queries"]:
            failures.append("workload counts differ")
        for stage in ("empty_resources", "filled_resources", "verified_resources"):
            differences[stage] = {"c_rss_kib": c[stage]["rss_kib"], "rust_rss_kib": rust[stage]["rss_kib"],
                                  "rust_minus_c_kib": rust[stage]["rss_kib"] - c[stage]["rss_kib"]}
        a = c["resource_summary"]["rss_kib"]["fourth_quarter_median"]
        b = rust["resource_summary"]["rss_kib"]["fourth_quarter_median"]
        differences["full_window_rss_q4"] = {"c_kib": a, "rust_kib": b, "rust_minus_c_kib": b - a,
                                              "rust_over_c": b / a}
    report = {"accepted": not failures and len(runs) == 2, "failures": failures, "runs": runs,
              "resource_review_required": True,
              "accepted_scope": "Collection, full-cache proofs and cleanup only; RSS growth requires review.",
              "differences": differences, "commands": records, "tool_sha256": sha256(Path(__file__)),
              "names_sha256": hashlib.sha256(("\n".join(NAMES) + "\n").encode()).hexdigest(),
              "name_length_bytes": len(NAMES[0]), "ttl_seconds": TTL,
              "scope_limit": "Dynamic single-A entries with fixed short names. Long-name allocations, CNAME chains, negative and complex RRs require separate measurements."}
    save(out / "result.json", report)
    print(json.dumps({"accepted": report["accepted"], "failures": failures}))
    return 0 if report["accepted"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "pair"))
    for name in ("image-root", "rust-binary", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-rust-sha", required=True)
    parser.add_argument("--implementation", choices=("c", "rust"))
    parser.add_argument("--cpus", type=int, nargs=2)
    parser.add_argument("--duration-seconds", type=int, choices=(300, 600), required=True)
    args = parser.parse_args()
    if not args.out.resolve().is_relative_to(PRIVATE):
        parser.error("evidence must be under private/")
    if args.mode == "run" and args.implementation is None:
        parser.error("run needs --implementation")
    return run_side(args) if args.mode == "run" else pair(args)


if __name__ == "__main__":
    raise SystemExit(main())
