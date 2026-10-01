#!/usr/bin/env python3
"""One frozen real-daemon UDP deadline window against the exact C reference.

No timing/performance claim: a reply after 11 seconds must still complete;
a reply after 41 seconds must not. A fresh request at 42 seconds observes
continued service and C's lazy expired-frec reclamation. Raw times, packets,
resource samples and process shutdown remain in private storage.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import name, read_name, semantics
from dns_udp_refusal_diff import verify_reference

DELAYS = {"delayed.test": 11.0, "expired.test": 41.0, "probe.test": 0.0}
PROBE_AT = 42.0
IDS = {"delayed.test": 0x6110, "expired.test": 0x6111, "probe.test": 0x6112}


def valid_completions(replies):
    return ([row["id"] for row in replies] == [IDS["delayed.test"], IDS["probe.test"]]
            and 10 < replies[0]["elapsed_s"] < 40)


def query(host, ident):
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + name(host) + struct.pack("!HH", 1, 1)


class Upstream:
    def __init__(self, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", port)); self.socket.settimeout(.02)
        self.events, self.sent, self.errors = [], [], []
        self.stop = threading.Event(); self.thread = threading.Thread(target=self.run); self.thread.start()

    def run(self):
        pending = []
        while not self.stop.is_set():
            try: packet, peer = self.socket.recvfrom(65535)
            except socket.timeout: packet = None
            except OSError as error:
                self.errors.append(repr(error)); break
            if packet is not None:
                try:
                    host, end = read_name(packet, 12)
                    value = semantics(packet); value["id"] = 0
                    self.events.append(value)
                    response = packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:end+4]
                    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 7])
                    pending.append((time.monotonic() + DELAYS[host], host, response, peer))
                except Exception as error: self.errors.append(repr(error))
            retained = []
            for deadline, host, response, peer in pending:
                if time.monotonic() >= deadline:
                    try: self.socket.sendto(response, peer); self.sent.append(host)
                    except OSError as error: self.errors.append(repr(error))
                else: retained.append((deadline, host, response, peer))
            pending = retained

    def close(self):
        self.stop.set(); self.thread.join(2); self.socket.close()
        assert not self.thread.is_alive(), "upstream thread leaked"


def resources(pid, label, started):
    base = Path(f"/proc/{pid}")
    return {"label": label, "elapsed_s": time.monotonic() - started,
            "fds": len(list((base / "fd").iterdir())), "threads": len(list((base / "task").iterdir())),
            "children": len((base / f"task/{pid}/children").read_text().split())}


def run(binary, side, config, listen_port, upstream_port, output):
    output.mkdir(); server = Upstream(upstream_port)
    replies, samples = [], []; started = time.monotonic(); issued = 0
    report = {"side": side, "replies": replies, "resources": samples, "failures": []}
    with (output / "daemon.log").open("wb") as log:
        process = subprocess.Popen([str(binary.resolve()), "-d", "-C", str(config)], stdout=log, stderr=log)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.connect(("127.0.0.1", listen_port)); client.settimeout(.1)
                for _ in range(100):
                    assert process.poll() is None, "daemon exited during readiness"
                    try:
                        client.send(query("ready.test", 1))
                        marker = client.recv(65535)
                        assert marker[:2] == b"\0\1" and marker[6:8] == b"\0\1", "unexpected readiness marker"
                        break
                    except OSError: time.sleep(.01)
                else: raise AssertionError("readiness failed")
                client.settimeout(.02)
                while True:
                    try:
                        marker = client.recv(65535)
                        assert marker[:2] == b"\0\1", "unexpected warmup packet"
                    except socket.timeout: break
                client.settimeout(.1)
                started = time.monotonic(); samples.append(resources(process.pid, "ready", started))
                for host in ["delayed.test", "expired.test"]:
                    client.send(query(host, IDS[host])); issued += 1
                sampled, probe_sent = set(), False
                while time.monotonic() - started < PROBE_AT + 2:
                    elapsed = time.monotonic() - started
                    for point, label in [(1, "pending"), (12, "after-delayed"), (40.5, "after-deadline")]:
                        if elapsed >= point and label not in sampled:
                            sampled.add(label); samples.append(resources(process.pid, label, started))
                    if elapsed >= PROBE_AT and not probe_sent:
                        client.send(query("probe.test", IDS["probe.test"])); probe_sent = True; issued += 1
                    try: response = client.recv(65535)
                    except socket.timeout: continue
                    ident = struct.unpack_from("!H", response)[0]
                    replies.append({"id": ident, "elapsed_s": time.monotonic() - started, "wire": response.hex()})
                    if ident == IDS["probe.test"]: break
                samples.append(resources(process.pid, "after-probe", started))
                assert valid_completions(replies), "completion count/order/deadline window differs"
                until = time.monotonic() + .2
                while len(server.sent) < 3 and time.monotonic() < until: time.sleep(.005)
                assert server.sent == ["delayed.test", "expired.test", "probe.test"], "upstream send count/order"
                assert len(server.events) == 3 and not server.errors, "upstream event count/error"
        except Exception as error:
            report["failures"].append(repr(error))
        finally:
            if process.poll() is None: process.send_signal(signal.SIGTERM)
            try: process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(); report["failures"].append("shutdown timeout")
            server.close()
    report.update(exit=process.returncode, closed=not Path(f"/proc/{process.pid}").exists(),
                  upstream=server.events, upstream_sent=server.sent, upstream_errors=server.errors,
                  completed=len(replies), expected_unanswered=1, issued_queries=issued, unexecuted_queries=3-issued)
    if process.returncode != 0 or not report["closed"]: report["failures"].append("unclean process release")
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ["side", "completed", "expected_unanswered", "closed", "failures"]}), flush=True)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--c", type=Path, required=True); p.add_argument("--c-identity", type=Path)
    p.add_argument("--rust", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    reference = verify_reference(args.c, args.c_identity)
    output = args.output.resolve(); assert "private" in output.parts and not output.exists(); output.mkdir(parents=True)
    with socket.socket() as a, socket.socket() as b:
        a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0)); listen_port, upstream_port = a.getsockname()[1], b.getsockname()[1]
    config = output / "dnsmasq.conf"
    config.write_text(f"no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport={listen_port}\ncache-size=0\nedns-packet-max=1232\nserver=127.0.0.1#{upstream_port}\nhost-record=ready.test,192.0.2.254\n")
    plan = {"rounds_per_side": 1, "send_delays_s": DELAYS, "fresh_probe_at_s": PROBE_AT,
            "expected_completed_per_side": 2, "expected_unanswered_per_side": 1,
            "comparison": "exact client reply bytes and upstream semantics/order/counts; random upstream ID normalized; elapsed time checked against frozen window, not a performance comparison",
            "reference": reference, "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest(),
            "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest()}
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    # Calibrate rejection of a lost valid completion and of an extra late one.
    sample = [{"id": IDS["delayed.test"], "elapsed_s": 11}, {"id": IDS["probe.test"], "elapsed_s": 42}]
    assert valid_completions(sample)
    assert not valid_completions(sample[1:])
    assert not valid_completions([*sample, {"id": IDS["expired.test"], "elapsed_s": 41}])
    expected = run(args.c, "c", config, listen_port, upstream_port, output / "c")
    actual = run(args.rust, "rust", config, listen_port, upstream_port, output / "rust")
    differences = []
    if [row["wire"] for row in expected["replies"]] != [row["wire"] for row in actual["replies"]]: differences.append("client replies")
    if expected["upstream"] != actual["upstream"]: differences.append("upstream semantics/count/order")
    report = {"plan": plan, "c_failures": expected["failures"], "rust_failures": actual["failures"], "differences": differences,
              "calibration": {"missing_completion_rejected": 1, "late_extra_completion_rejected": 1}}
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(bool(expected["failures"] or actual["failures"] or differences))


if __name__ == "__main__":
    raise SystemExit(main())
