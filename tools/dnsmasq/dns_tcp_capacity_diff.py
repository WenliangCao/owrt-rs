#!/usr/bin/env python3
"""Actual -k TCP slot admission, queued-client recovery and UBus metrics.

Run only through run_isolated.sh. At capacity the exact C daemon leaves the
excess connection in the kernel accept queue until a child and its pipe close.
No upstream traffic, DHCP, router state or performance claim is involved.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

from dns_service_probe import exact_read, query, semantics
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
PORT = 15353
PROFILES = [("one-slot", 1), ("shared-two-slots", 2)]


class Product(Fixture):
    def start_product(self, binary, config):
        command = [str(binary.resolve()), "-k", "-C", str(config)]
        if binary.resolve() == (self.args.reference_build / "dnsmasq/dnsmasq").resolve():
            command += ["--user=root", "--group=root", "--log-facility=-",
                        "--pid-file=" + str(self.out / "pid")]
        self.daemon, _ = self.spawn(command, "daemon")
        self.wait_registered()

    def wait_connections(self, count):
        deadline = time.monotonic() + 3
        while True:
            values = self.metrics()
            if values["tcp_connections"] == count:
                return values
            assert self.daemon.poll() is None and time.monotonic() < deadline, (count, values)
            time.sleep(.005)


def run(args, binary, out, config, limit):
    out.mkdir()
    fixture = Product(args, out)
    clients, rows, wire = [], [], []
    resources = {}
    try:
        fixture.start_bus()
        fixture.start_product(binary, config)

        def record(label, value):
            rows.append({"label": label, "value": value})
            return value

        def connect(address):
            client = socket.create_connection((address, PORT), timeout=2)
            client.settimeout(2)
            clients.append(client)
            return client

        def send(client, ident):
            packet = query("capacity.test", 1, ident)
            wire.append({"direction": "query", "wire": packet.hex()})
            client.sendall(struct.pack("!H", len(packet)) + packet)

        def receive(client, ident):
            try:
                packet = exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
            except socket.timeout:
                return {"status": "timeout"}
            except (ConnectionError, OSError) as error:
                wire.append({"direction": "receive-error", "error": repr(error)})
                return {"status": "closed"}
            wire.append({"direction": "reply", "wire": packet.hex()})
            value = semantics(packet)
            assert value["id"] == ident, "transaction ID changed"
            return {"status": "reply", "packet": value}

        def ask(label, client, ident):
            try:
                send(client, ident)
            except (ConnectionError, OSError) as error:
                wire.append({"direction": "send-error", "error": repr(error)})
                return record(label, {"status": "closed"})
            return record(label, receive(client, ident))

        record("initial-metrics", fixture.wait_connections(0))
        active = []
        for index in range(limit):
            active.append(connect(f"127.0.0.{index + 1}"))
            ask(f"active-{index}", active[-1], 0x6000 + index)
            fixture.wait_connections(index + 1)
        record("saturated-metrics", fixture.metrics())

        # The second address exercises one shared limit across Rust listeners.
        queued = connect("127.0.0.2")
        send(queued, 0x6010)
        queued.settimeout(.2)
        try:
            first = queued.recv(1, socket.MSG_PEEK)
            pending = {"status": "readable" if first else "closed"}
        except socket.timeout:
            pending = {"status": "pending"}
        except (ConnectionError, OSError) as error:
            wire.append({"direction": "pending-error", "error": repr(error)})
            pending = {"status": "closed"}
        queued.settimeout(2)
        record("queued-before-release", pending)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(2)
            packet = query("capacity.test", 1, 0x6011)
            wire.append({"direction": "udp-query", "wire": packet.hex()})
            udp.sendto(packet, ("127.0.0.2", PORT))
            response = udp.recv(65535)
            wire.append({"direction": "udp-reply", "wire": response.hex()})
            record("parent-while-full", {"status": "reply", "packet": semantics(response)})
        ask("active-still-live", active[0], 0x6012)
        record("full-metrics", fixture.metrics())

        active.pop(0).close()
        answered = record("queued-after-release", receive(queued, 0x6010))
        ask("queued-reuse", queued, 0x6013)
        expected_connections = limit if answered["status"] == "reply" else limit - 1
        record("released-metrics", fixture.wait_connections(expected_connections))
        for client in clients:
            client.close()
        clients.clear()
        record("all-closed-metrics", fixture.wait_connections(0))
        recovered = connect("127.0.0.2")
        ask("recovery", recovered, 0x6014)
        record("recovery-open-metrics", fixture.wait_connections(1))
        recovered.close()
        clients.clear()
        record("recovery-closed-metrics", fixture.wait_connections(0))

        proc = Path(f"/proc/{fixture.daemon.pid}")
        resources = {"parent_fds_after_close": len(list((proc / "fd").iterdir())),
                     "children_after_close": (proc / "task" / str(fixture.daemon.pid) / "children").read_text().split()}
        assert not resources["children_after_close"], "unreaped TCP child after gauge reached zero"
        fixture.stop(fixture.daemon)
        record("shutdown-exit", fixture.daemon.returncode)
        assert not fixture.upstream.requests, "unexpected upstream traffic"
        return rows, resources
    finally:
        for client in clients:
            client.close()
        fixture.close()
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wire": wire,
            "ubus": fixture.raw, "checks": fixture.checks, "resources": resources}, indent=2) + "\n")
        assert all(check["pass"] for check in fixture.checks), "fixture/lifecycle check failed"


def compare(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("observation count differs")
    return [{"label": a["label"], "c": a["value"], "rust": b["value"]}
            for a, b in zip(expected, actual) if a != b]


def calibrate(rows, limit):
    assert len(rows) == 14 + limit, "planned observation count differs"
    by_label = {row["label"]: row["value"] for row in rows}
    assert by_label["queued-before-release"] == {"status": "pending"}
    for row in rows:
        value = row["value"]
        if isinstance(value, dict) and "status" in value and row["label"] != "queued-before-release":
            assert value["status"] == "reply", row
            packet = value["packet"]
            assert packet["flags"] == 0x8580 and len(packet["records"]) == 1, row
            assert packet["records"][0]["data"] == "192.0.2.41" and packet["records"][0]["ttl"] == 37, row
    for label, count in [("initial-metrics", 0), ("saturated-metrics", limit),
                         ("full-metrics", limit), ("released-metrics", limit),
                         ("all-closed-metrics", 0), ("recovery-open-metrics", 1),
                         ("recovery-closed-metrics", 0)]:
        metrics = by_label[label]
        assert metrics["tcp_connections"] == count, (label, metrics)
        assert metrics["dns_local_answered"] == int(label not in ("initial-metrics", "saturated-metrics")), (label, metrics)
        assert all(value == 0 for key, value in metrics.items()
                   if key not in ("tcp_connections", "dns_local_answered")), (label, metrics)
    assert by_label["shutdown-exit"] == 0
    assert not compare(rows, copy.deepcopy(rows))
    for label, field, value in [("queued-before-release", "status", "closed"),
                                ("saturated-metrics", "tcp_connections", limit + 1)]:
        bad = copy.deepcopy(rows)
        next(row for row in bad if row["label"] == label)["value"][field] = value
        assert len(compare(rows, bad)) == 1, "mutation escaped comparison"
    bad = copy.deepcopy(rows)
    next(row for row in bad if row["label"] == "queued-after-release")["value"]["packet"]["flags"] ^= 1
    assert len(compare(rows, bad)) == 1, "reply mutation escaped comparison"
    try:
        compare(rows, rows[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("missing observation escaped comparison")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-failure", action="store_true")
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    out = args.out.resolve()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and [name for _, name in socket.if_nameindex()] == ["lo"]
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    assert not args.inject_failure or args.rust, "negative differential requires Rust"
    out.mkdir(parents=True)
    reference = args.reference_build / "dnsmasq/dnsmasq"
    report = {"planned": 31, "c_observations": 0, "matched": 0, "failures": [],
              "reference": verify_reference(reference, None), "tool_sha256": digest(Path(__file__)),
              "rust_sha256": digest(args.rust) if args.rust else None,
              "profiles": {}, "scope": "actual -k TCP capacity/queued recovery, all UBus metrics, clean shutdown; native contract only"}
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=0755", "tmpfs", "/run"], check=True)
    Path(BUS).parent.mkdir(parents=True)
    try:
        for profile, limit in PROFILES:
            work = out / profile
            work.mkdir()
            hosts = work / "hosts"
            hosts.write_text("192.0.2.41 capacity.test\n")
            config = work / "dnsmasq.conf"
            config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1,127.0.0.2\nport=15353\n"
                              "cache-size=16\nlocal-ttl=37\n"
                              f"addn-hosts={hosts}\nenable-ubus={OBJECT}\nmax-tcp-connections={limit}\n")
            expected, resources = run(args, reference, work / "c", config, limit)
            calibrate(expected, limit)
            report["c_observations"] += len(expected)
            detail = {"limit": limit, "config_sha256": digest(config), "hosts_sha256": digest(hosts),
                      "c_resources": resources, "calibration": {"equal": 1, "mutations_detected": 3, "missing_row_detected": 1}}
            report["profiles"][profile] = detail
            if args.rust:
                actual, resources = run(args, args.rust, work / "rust", config, limit)
                if args.inject_failure and profile == PROFILES[0][0]:
                    next(row for row in actual if row["label"] == "queued-before-release")["value"]["status"] = "injected-closed"
                failures = compare(expected, actual)
                report["matched"] += len(expected) - len(failures)
                report["failures"].extend({"profile": profile, **failure} for failure in failures)
                detail["rust_resources"] = resources
    except Exception as error:
        report["failures"].append({"infrastructure_or_protocol": repr(error)})
    finally:
        subprocess.run(["umount", "/run"], check=True)
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
