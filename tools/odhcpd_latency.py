#!/usr/bin/env python3
"""One frozen odhcpd latency/RSS batch; Linux root and private namespaces only."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import time
import traceback
from types import SimpleNamespace

from odhcpd_baseline import C_SHA, Fixture, GUA, ULA, opt, run

METRICS = ("first_active_ra_ns", "first_rs_ns", "first_solicit_ns", "first_request_ns")
PHASES = ("zero_leases", "three_na_one_pd", "prefix_changed", "ubus_reconnected")
FLOOR_PORT = 15467
FIXTURE_TIMEOUT = 120


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def schedule():
    pairs = []
    for i in range(1, 4):
        pairs.append({"kind": "calibration", "index": i,
                      "members": [{"name": f"cal-{i}-C{j}", "side": "C"} for j in (1, 2)]})
    for i, order in enumerate(("CR", "RC", "CR"), 1):
        pairs.append({"kind": "formal", "index": i,
                      "members": [{"name": f"formal-{i}-{side}", "side": side} for side in order]})
    return pairs


def analyze(batch):
    """Read the fixed samples once. Never discard, replace or average away a pair."""
    fixtures = batch["fixtures"]
    expected = {member["name"] for pair in schedule() for member in pair["members"]}
    if batch.get("schedule") != schedule() or set(fixtures) != expected:
        return {"decision": "invalid_incomplete_batch"}
    if any(not value.get("complete") for value in fixtures.values()):
        return {"decision": "invalid_incomplete_fixture"}
    quantization = 2 * max(value["clock_resolution_ns"] for value in fixtures.values())
    report = {"clock_pair_quantization_ns": quantization, "latency": {}, "memory": [],
              "latency_pass": True, "memory_pass": True}
    for metric in METRICS:
        calibration = []
        for i in range(1, 4):
            first = fixtures[f"cal-{i}-C1"]["latencies_ns"][metric]
            second = fixtures[f"cal-{i}-C2"]["latencies_ns"][metric]
            calibration.append({"pair": i, "first_C_ns": first, "second_C_ns": second,
                                "second_minus_first_ns": second - first})
        noise = max(quantization, *(abs(x["second_minus_first_ns"]) for x in calibration))
        formal = []
        for i, order in enumerate(("CR", "RC", "CR"), 1):
            c = fixtures[f"formal-{i}-C"]["latencies_ns"][metric]
            rust = fixtures[f"formal-{i}-R"]["latencies_ns"][metric]
            difference = rust - c
            classification = ("slower_beyond_noise" if difference > noise else
                              "faster_beyond_noise" if difference < -noise else "within_noise")
            formal.append({"pair": i, "order": order, "C_ns": c, "R_ns": rust,
                           "R_minus_C_ns": difference, "classification": classification})
            report["latency_pass"] &= difference <= noise
        report["latency"][metric] = {
            "calibration": calibration, "noise_ns": noise, "formal": formal,
            "C_median_ns": statistics.median(x["C_ns"] for x in formal),
            "R_median_ns": statistics.median(x["R_ns"] for x in formal),
            "largest_R_minus_C_ns": max(x["R_minus_C_ns"] for x in formal)}
    for i in range(1, 4):
        for phase in PHASES:
            c = fixtures[f"formal-{i}-C"]["memory_kib"][phase]
            rust = fixtures[f"formal-{i}-R"]["memory_kib"][phase]
            passed = c["VmRSS"] > 0 and rust["VmRSS"] <= 2 * c["VmRSS"]
            report["memory_pass"] &= passed
            report["memory"].append({"pair": i, "phase": phase, "C": c, "R": rust,
                                     "rss_ratio": rust["VmRSS"] / c["VmRSS"] if c["VmRSS"] else None,
                                     "pass": passed})
    report["decision"] = "pass" if report["latency_pass"] and report["memory_pass"] else "stop_and_report"
    report["floor_subtracted"] = False
    report["limits"] = "Oracle isolated cold process starts; not router boot or device acceptance"
    return report


def floor_client(device, destination, count):
    idx = socket.if_nametoindex(device)
    records = []
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode() + b"\0")
        udp.settimeout(2)
        for sequence in range(count):
            packet = b"odhcpd-floor" + struct.pack("!I", sequence) + bytes(48)
            sent = time.monotonic_ns()
            udp.sendto(packet, (destination, FLOOR_PORT, 0, idx))
            reply, source = udp.recvfrom(4096)
            received = time.monotonic_ns()
            if reply != packet or source[1] != FLOOR_PORT:
                raise RuntimeError("UDP floor payload/source mismatch")
            records.append({"sequence": sequence, "sent_ns": sent, "received_ns": received,
                            "elapsed_ns": received - sent, "request_hex": packet.hex(),
                            "reply_hex": reply.hex(), "source": source[0]})
    return {"clock": vars(time.get_clock_info("monotonic")), "samples": records}


def wait_ready(process, timeout=3):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise RuntimeError("UDP floor helper readiness timeout")
    if not json.loads(process.stdout.readline()).get("ready"):
        raise RuntimeError("UDP floor helper bad readiness")


class LatencyFixture(Fixture):
    def __init__(self, args):
        super().__init__(SimpleNamespace(rootfs=args.rootfs, daemon=args.daemon,
                                         out=args.out, case="baseline"))
        self.helper = args.floor_helper
        self.expected_sha = args.expected_sha
        self.side = args.subject

    def start_daemon(self):
        marker = self.out / "exec.monotonic_ns"
        self.daemon = self.spawn("odhcpd", [self.helper, "launch", str(self.root), str(marker),
                                            "/usr/sbin/odhcpd", "-f"])
        limit = time.monotonic() + 3
        while time.monotonic() < limit:
            if marker.exists() and marker.read_text().strip():
                self.started = int(marker.read_text())
                self.record("daemon_start_ns", self.started)
                return
            if self.daemon.poll() is not None:
                raise RuntimeError("daemon launch failed")
            time.sleep(.001)
        raise RuntimeError("daemon exec marker absent")

    def memory(self, phase, require_leases):
        state = self.snapshot("memory_" + phase)
        self.expect(phase + "_rss_present", state["memory_kib"].get("VmRSS", 0) > 0)
        if require_leases:
            leases = json.loads(state["leases"]["stdout"])["device"]["br-lan"]["leases"]
            na = [lease for lease in leases if "bound" in lease["flags"] and "ipv6-addr" in lease]
            pd = [lease for lease in leases if "bound" in lease["flags"] and "ipv6-prefix" in lease]
            self.expect(phase + "_lease_count", (len(na), len(pd)) == (3, 1))
        return state["memory_kib"]

    def udp_floor(self):
        log = open(self.out / "floor.log", "w")
        server = subprocess.Popen([self.helper, "echo", "br-lan", str(FLOOR_PORT), "3"],
                                  stdout=subprocess.PIPE, stderr=log, text=True)
        self.children.append(server)
        wait_ready(server)
        result = run(*self.ns, sys.executable, str(Path(__file__).resolve()), "--floor-client")
        server.wait(3)
        if server.returncode:
            raise RuntimeError("UDP floor server failed")
        return self.record("udp_floor", json.loads(result.stdout))

    def measure(self):
        self.setup()
        self.expect("exact_elf", self.results["events"]["identity"]["sha256"] == self.expected_sha)
        clock = json.loads(run(self.helper, "clock").stdout)
        resolution = max(clock["resolution_ns"], math.ceil(time.get_clock_info("monotonic").resolution * 1e9))
        self.record("instrument_clock", {"helper": clock, "resolution_ns": resolution})
        # Same fixed quiet interval after all fixture construction, on both sides.
        time.sleep(1)
        self.start_daemon()
        first = self.request("first_active_ra", "ra")
        self.expect("first_active_ra", not first.get("timeout") and first["decoded"]["flags"] == 0xc0)
        first["from_exec_ns"] = first["received_ns"] - self.started
        self.record("first_active_ra", first)
        rs = self.request("first_rs", "rs")
        self.expect("first_rs", not rs.get("timeout"))
        memory = {"zero_leases": self.memory("zero_leases", False)}
        zero = json.loads(self.results["events"]["memory_zero_leases"]["leases"]["stdout"])
        self.expect("zero_leases_count", zero["device"]["br-lan"]["leases"] == [])
        fqdn = opt(39, b"\x00\x08fixture1\x00")
        offer = self.dhcp("first_solicit", 1, [(3, struct.pack("!III", 1, 0, 0))], extra=fqdn)
        self.expect("first_solicit", not offer.get("timeout") and offer["decoded"]["type"] == 2)
        self.server = self.raw_option(offer, 2)
        self.na = self.raw_option(offer, 3)
        reply = self.dhcp("first_request", 3, [(3, self.na)], server=self.server, extra=fqdn)
        self.expect("first_request", not reply.get("timeout") and reply["decoded"]["type"] == 7)
        self.expect("first_na_resources", len(self.ia_items(reply, 3)) == 2)
        pd_offer = self.dhcp("pd_offer", 1, [(25, struct.pack("!III", 2, 0, 0))])
        self.expect("pd_offer", not pd_offer.get("timeout"))
        self.pd = self.raw_option(pd_offer, 25)
        pd_reply = self.dhcp("pd_request", 3, [(25, self.pd)], server=self.server)
        self.expect("pd_bound", len(self.ia_items(pd_reply, 25)) == 1)
        self.dhcp("two_more_na", 1, [(3, struct.pack("!III", 3, 0, 0)),
                                     (3, struct.pack("!III", 4, 0, 0))], extra=opt(14, b""))
        time.sleep(.1)
        memory["three_na_one_pd"] = self.memory("three_na_one_pd", True)

        for address in ("2001:db8:2::1/64", "fd12:3456:789b::1/60"):
            run("ip", "-6", "addr", "add", address, "dev", "br-lan", "nodad")
        for address in (GUA, ULA):
            run("ip", "-6", "addr", "del", address, "dev", "br-lan")
        run("ip", "-6", "route", "del", "unreachable", "fd12:3456:789a::/60", "dev", "lo", "metric", "2147483647")
        run("ip", "-6", "route", "add", "unreachable", "fd12:3456:789b::/60", "dev", "lo", "metric", "2147483647")
        time.sleep(1.2)
        self.request("prefix_rs", "rs")
        self.dhcp("prefix_na_renew", 5, [(3, self.na)], server=self.server)
        self.dhcp("prefix_pd_renew", 5, [(25, self.pd)], server=self.server)
        memory["prefix_changed"] = self.memory("prefix_changed", True)

        self.provider.terminate()
        self.provider.wait(3)
        self.ubusd.terminate()
        self.ubusd.wait(3)
        self.start_bus()
        self.start_provider()
        time.sleep(1.2)
        alive = self.request("reconnected_rs", "rs")
        self.expect("protocol_survives_ubus_restart", not alive.get("timeout"))
        restored = self.record("ubus_object_after_restart", self.bus("dhcp", "ipv6leases", check=False))
        if self.side == "R":
            self.expect("rust_ubus_restored", restored["status"] == 0)
        memory["ubus_reconnected"] = self.memory("ubus_reconnected", restored["status"] == 0)
        floor = self.udp_floor()
        self.record("measurement", {"complete": True, "subject": self.side,
                     "elf_sha256": self.expected_sha, "clock_resolution_ns": resolution,
                     "latencies_ns": dict(zip(METRICS, (first["from_exec_ns"], rs["elapsed_ns"], offer["elapsed_ns"], reply["elapsed_ns"]))),
                     "memory_kib": memory, "udp_floor": floor,
                     "ubus_restored": restored["status"] == 0})


def bounded_child(command, out, timeout=FIXTURE_TIMEOUT):
    with open(Path(out) / "driver.log", "w") as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return child.wait(timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            save(Path(out) / "timeout.json", {"timeout_seconds": timeout, "command": command})
            return 124


def namespace_command(script):
    return ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc",
            sys.executable, str(script)]


def selftest_inside(args):
    run("ip", "link", "set", "lo", "up")
    marker = Path(args.out) / "selftest.exec.monotonic_ns"
    before = time.monotonic_ns()
    run(args.floor_helper, "launch", "/", str(marker), "/bin/true")
    after = time.monotonic_ns()
    stamp = int(marker.read_text())
    assert before <= stamp <= after
    duplicate = run(args.floor_helper, "launch", "/", str(marker), "/bin/true", check=False)
    assert duplicate.returncode != 0 and int(marker.read_text()) == stamp
    with open(Path(args.out) / "floor.log", "w") as log:
        server = subprocess.Popen([args.floor_helper, "echo", "lo", str(FLOOR_PORT), "3"],
                                  stdout=subprocess.PIPE, stderr=log, text=True)
        try:
            wait_ready(server)
            floor = floor_client("lo", "::1", 3)
            server.wait(3)
            if server.returncode:
                raise RuntimeError("echo helper failed")
        finally:
            if server.poll() is None:
                server.kill()
                server.wait()
    # Exercise sign, alternating order, strict >noise, quantization and RSS gates.
    synthetic = {"schedule": schedule(), "fixtures": {}}
    for pair in schedule():
        for j, member in enumerate(pair["members"]):
            value = 100 + (10 * j if pair["kind"] == "calibration" else 0)
            synthetic["fixtures"][member["name"]] = {"complete": True, "clock_resolution_ns": 1,
                "latencies_ns": {key: value for key in METRICS},
                "memory_kib": {phase: {"VmRSS": 100, "RssAnon": 20} for phase in PHASES}}
    assert analyze(synthetic)["decision"] == "pass"
    sample = synthetic["fixtures"]["formal-2-R"]
    sample["latencies_ns"][METRICS[0]] = 110
    assert analyze(synthetic)["decision"] == "pass"
    sample["latencies_ns"][METRICS[0]] = 111
    assert not analyze(synthetic)["latency_pass"]
    sample["latencies_ns"][METRICS[0]] = 89
    assert analyze(synthetic)["latency_pass"]
    sample["memory_kib"][PHASES[0]]["VmRSS"] = 201
    assert not analyze(synthetic)["memory_pass"]
    sample["memory_kib"][PHASES[0]]["VmRSS"] = 200
    assert analyze(synthetic)["memory_pass"]
    sample["clock_resolution_ns"] = 20
    assert analyze(synthetic)["latency"][METRICS[0]]["noise_ns"] == 40
    save(Path(args.out) / "selftest.json", {"complete": True, "analysis_checks": 7,
         "exec_marker_check": {"before_ns": before, "marker_ns": stamp, "after_ns": after,
                               "overwrite_rejected": True},
         "floor": floor, "helper_clock": json.loads(run(args.floor_helper, "clock").stdout),
         "note": "instrument validation only; no C or Rust daemon was started"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs")
    parser.add_argument("--candidate")
    parser.add_argument("--candidate-sha")
    parser.add_argument("--floor-helper")
    parser.add_argument("--out")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--summarize")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--selftest-inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--floor-client", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--subject", choices=("C", "R"), help=argparse.SUPPRESS)
    parser.add_argument("--daemon", help=argparse.SUPPRESS)
    parser.add_argument("--expected-sha", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.floor_client:
        print(json.dumps(floor_client("client0", "fe80::1", 3)))
        return
    if args.summarize:
        print(json.dumps(analyze(json.loads(Path(args.summarize).read_text())), indent=2))
        return
    if os.geteuid() or not args.out or not args.floor_helper:
        parser.error("Linux root, --out and --floor-helper are required")
    args.out = str(Path(args.out).resolve())
    args.floor_helper = str(Path(args.floor_helper).resolve())
    if args.selftest_inside:
        selftest_inside(args)
        return
    if args.inside:
        fixture = LatencyFixture(args)
        try:
            fixture.measure()
            fixture.record("complete", True)
        except Exception:
            fixture.record("error", traceback.format_exc())
            raise
        finally:
            fixture.close()
        return
    out = Path(args.out)
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    instrument = out / "instrument"
    instrument.mkdir()
    for name in (Path(__file__).name, "odhcpd_baseline.py", "odhcpd_latency_floor.c"):
        shutil.copy2(Path(__file__).with_name(name), instrument / name)
    helper = instrument / "floor-helper"
    shutil.copy2(args.floor_helper, helper)
    script = instrument / Path(__file__).name
    if args.selftest:
        command = namespace_command(script) + ["--selftest-inside", "--floor-helper", str(helper), "--out", args.out]
        sys.exit(bounded_child(command, out, 20))
    if not args.rootfs or not args.candidate or not args.candidate_sha:
        parser.error("batch requires --rootfs, --candidate and --candidate-sha")
    rootfs = Path(args.rootfs).resolve()
    if digest(rootfs / "usr/sbin/odhcpd") != C_SHA or digest(args.candidate) != args.candidate_sha:
        raise RuntimeError("exact ELF hash gate failed; no samples run")
    subjects = out / "subjects"
    subjects.mkdir()
    shutil.copy2(rootfs / "usr/sbin/odhcpd", subjects / "C")
    shutil.copy2(args.candidate, subjects / "R")
    batch = {"schedule": schedule(), "fixtures": {}, "fixture_timeout_seconds": FIXTURE_TIMEOUT,
             "C_sha256": C_SHA, "R_sha256": args.candidate_sha, "rootfs": str(rootfs),
             "instrument_sha256": {path.name: digest(path) for path in instrument.iterdir()},
             "predictive_plan": "docs/reviews/ODHCPD_LATENCY_PLAN_20261018.md",
             "clock": vars(time.get_clock_info("monotonic")), "host": run("uname", "-a").stdout.strip()}
    save(out / "batch.json", batch)
    for pair in batch["schedule"]:
        for member in pair["members"]:
            sample = out / member["name"]
            sample.mkdir(mode=0o700)
            side = member["side"]
            expected = C_SHA if side == "C" else args.candidate_sha
            command = namespace_command(script) + ["--inside", "--rootfs", str(rootfs), "--out", str(sample),
                       "--subject", side, "--daemon", str(subjects / side), "--expected-sha", expected,
                       "--floor-helper", str(helper)]
            status = bounded_child(command, sample)
            raw = json.loads((sample / "results.json").read_text()) if (sample / "results.json").exists() else {}
            value = raw.get("events", {}).get("measurement", {"complete": False})
            value["exit_status"] = status
            value["complete"] = bool(value["complete"] and status == 0 and raw.get("events", {}).get("complete"))
            batch["fixtures"][member["name"]] = value
            save(out / "batch.json", batch)
            if not value["complete"]:
                save(out / "analysis.json", analyze(batch))
                raise RuntimeError("invalid fixture; fixed batch stopped without replacement samples")
    report = analyze(batch)
    save(out / "analysis.json", report)
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["decision"] == "pass" else 1)


if __name__ == "__main__":
    main()
