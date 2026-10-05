#!/usr/bin/env python3
"""Actual C/Rust daemon UBus metrics, DNS doctor and DHCP event integration.

Runs the entire C schedule first. No fixture counters or test-only daemon CLI.
Raw packets/configuration/identities remain in a new private directory.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import query, semantics, exact_read
from dhcp_lease_lifecycle import packet as dhcp_packet
from ubus_contract_diff import BUS, OBJECT, Fixture, digest, fields, read_json_lines
from dns_udp_refusal_diff import verify_reference


class Product(Fixture):
    def stop(self, child):
        super().stop(child)
        if child is not None and child is self.daemon:
            self.check(self.side + "-daemon-normal-exit", child.returncode, 0)

    def start_product(self, side, extra="", port=15353, bus=True, restored=False,
                      cache_size=20, upstream=True, wait_bus=True):
        self.side = side
        self.hosts = self.out / f"hosts-{self.index}"
        self.hosts.write_text("192.0.2.42 local.invalid\n")
        lease = self.out / f"lease-{self.index}"
        if restored:
            lease.write_text("4102444800 02:00:00:00:00:08 127.0.0.18 restored *\n")
        config = self.out / f"config-{self.index}"
        config.write_text(f"no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport={port}\n"
                          + ("server=127.0.0.1#15354\n" if upstream else "")
                          + f"cache-size={cache_size}\nlocal-ttl=120\n"
                          "no-ping\ndhcp-authoritative\ndhcp-lease-max=150\n"
                          "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
                          f"dhcp-leasefile={lease}\naddn-hosts={self.hosts}\n"
                          + (f"enable-ubus={OBJECT}\n" if bus else "") + extra)
        binary = (self.args.c_binary or self.args.reference_build / "dnsmasq/dnsmasq") if side == "C" else self.args.rust_binary
        # Both products must reconnect with the same credentials and sink.
        # C-only root overrides hide the private ubusd socket's access policy.
        command = [str(binary), "--keep-in-foreground", "--conf-file=" + str(config),
                   "--user=root", "--group=root", "--log-facility=-",
                   "--pid-file=" + str(self.out / "pid")]
        self.daemon, self.daemon_log = self.spawn(command, side)
        if bus and wait_bus:
            self.wait_registered()
        else:
            time.sleep(.1)
        assert self.daemon.poll() is None

    def exchange(self, host, kind=1, tcp=None):
        packet = query(host, kind)
        if tcp is None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(packet, ("127.0.0.1", 15353))
                response = client.recv(65535)
        else:
            tcp.sendall(struct.pack("!H", len(packet)) + packet)
            response = exact_read(tcp, struct.unpack("!H", exact_read(tcp, 2))[0])
        self.raw.append({"side": self.side, "query": packet.hex(), "answer": response.hex(), "tcp": tcp is not None})
        return semantics(response)

    def wait_metric(self, field, value):
        deadline = time.monotonic() + 3
        while True:
            metrics = self.metrics()
            if metrics[field] == value:
                return metrics
            assert self.daemon.poll() is None and time.monotonic() < deadline, (field, value, metrics)
            time.sleep(.005)

    def reload(self):
        self.daemon.send_signal(signal.SIGHUP)
        return self.wait_metric("dns_cache_inserted", 0)

    def notices(self, log, expected=None):
        deadline = time.monotonic() + 2
        while True:
            rows = [row for row in read_json_lines(log) if row.get("event") == "notify"]
            if expected is None or len(rows) >= expected:
                return [{"method": row["method"], "fields": fields(row["wire"])} for row in rows]
            assert time.monotonic() < deadline, (log, expected, rows)
            time.sleep(.002)


def run_side(f, side):
    observed = {}
    def record(label, value):
        assert label not in observed
        observed[label] = value
    def snapshot(label):
        record(label, f.metrics())

    f.start_product(side, "alias=192.0.2.9,198.51.100.9\n")
    for path in (OBJECT, OBJECT + ".dns"):
        row = next(row for row in f.client_call("lookup", path) if row["event"] == "lookup")
        record("signature-" + path, {"signature": fields(row["wire"]), "has_type": row["type"] != 0})
    snapshot("initial")
    record("local-answer", f.exchange("local.invalid"))
    snapshot("after-local")
    record("forward-answer", f.exchange("forward.invalid"))
    snapshot("after-forward")
    record("cache-answer", f.exchange("forward.invalid"))
    snapshot("after-cache")
    record("reload-window", f.reload())
    snapshot("after-reload")
    for label, response, kind in [
        ("rewrite", "192.0.2.9", 1), ("rewrite6", "2001:db8::9", 28),
        ("same", "192.0.2.1", 1), ("invalid", "invalid", 1),
        ("wrong-family", "2001:db8::9", 1), ("silent", "silent", 1),
    ]:
        watcher, log = f.watch(response)
        record(label + "-answer", f.exchange(label + ".invalid", kind))
        record(label + "-notice", f.notices(log, 1))
        snapshot(label + "-metrics")
        if label == "rewrite":
            record("rewritten-cache-answer", f.exchange(label + ".invalid", kind))
            snapshot("rewritten-cache-metrics")
            record("rewritten-cache-notices", f.notices(log))
        f.stop(watcher)
    # The subscriber invokes metrics before finishing its dns_result callback.
    watcher, log = f.watch("metrics")
    record("queued-before", f.metrics())
    record("queued-answer", f.exchange("queued.invalid"))
    deadline = time.monotonic() + 2
    while True:
        data = [row for row in read_json_lines(log) if row.get("event") == "data"]
        if data:
            break
        assert time.monotonic() < deadline
        time.sleep(.002)
    record("queued-during", {row["name"]: row["value"] for row in fields(data[0]["wire"])})
    snapshot("queued-after")
    f.stop(watcher)
    # Gauge and TCP no-doctor behavior use real accepted/closed sessions.
    watcher, log = f.watch("192.0.2.9")
    with socket.create_connection(("127.0.0.1", 15353), 2) as tcp:
        record("tcp-active", f.wait_metric("tcp_connections", 1))
        record("tcp-local", f.exchange("local.invalid", tcp=tcp))
        snapshot("tcp-local-metrics")
        record("tcp-forward", f.exchange("tcp-forward.invalid", tcp=tcp))
    record("tcp-closed", f.wait_metric("tcp_connections", 0))
    record("tcp-notices", f.notices(log))
    f.stop(watcher)
    current = f.metrics()
    f.stop(f.bus)
    f.start_bus()
    f.wait_registered()
    f.check(side + "-reconnect-preserves-metrics", f.metrics(), current)
    rows = f.client_call("lookup", OBJECT + ".dns")
    if side == "C":
        f.check("C-known-restart-DNS-type-defect", rows, [{"event": "status", "status": 0}])
    else:
        f.check("Rust-reconnect-DNS-type", sum(row["event"] == "lookup" for row in rows), 1)
        watcher, log = f.watch("192.0.2.9")
        answer = f.exchange("reconnected.invalid")
        f.check("Rust-reconnected-doctor", answer["records"][0]["data"], "198.51.100.9")
        f.stop(watcher)
    f.stop(f.daemon)

    for label, extra, expected in [("normal", "", 2), ("quiet", "quiet-dhcp\n", 0),
                                   ("quiet-options", "quiet-dhcp\nlog-dhcp\n", 2)]:
        f.start_product(side, extra)
        watcher, log = f.watch(dns=False)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("0.0.0.0", 68))
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo\0")
            client.settimeout(2)
            for index, kind in enumerate((1, 3, 7)):
                packet = dhcp_packet(kind, index + 1, address="127.0.0.10", selecting=kind == 3)
                client.sendto(packet, ("255.255.255.255", 67))
                if kind != 7:
                    reply = client.recv(4096)
                    f.check(side + label + "-reply-id", reply[4:8], packet[4:8])
                    f.raw.append({"side": side, "dhcp": packet.hex(), "reply": reply.hex()})
                else:
                    f.wait_metric("dhcp_release", 1)
                snapshot(label + "-after-" + str(kind))
        record(label + "-dhcp-notices", f.notices(log, expected))
        f.stop(watcher)
        f.stop(f.daemon)
    f.start_product(side, port=0, restored=True)
    snapshot("port-zero-restored")
    f.daemon.send_signal(signal.SIGHUP)
    time.sleep(.05)
    snapshot("port-zero-after-hup")
    f.stop(f.daemon)
    f.start_product(side, "use-stale-cache=10\n")
    record("stale-seed", f.exchange("stale.invalid"))
    snapshot("stale-seeded-metrics")
    time.sleep(3.1)
    record("stale-answer", f.exchange("stale.invalid"))
    record("stale-refresh-metrics", f.wait_metric("dns_cache_inserted", 2))
    f.stop(f.daemon)
    f.start_product(side, cache_size=2)
    for index in range(4):
        record(f"pressure-answer-{index}", f.exchange(f"pressure-{index}.invalid"))
    snapshot("pressure-metrics")
    f.stop(f.daemon)
    f.start_product(side, upstream=False)
    record("no-server-answer", f.exchange("unowned.invalid"))
    snapshot("no-server-metrics")
    f.stop(f.daemon)
    f.stop(f.bus)
    f.start_product(side, wait_bus=False)
    record("absent-bus-local-answer", f.exchange("local.invalid"))
    f.start_bus()
    f.wait_registered()
    snapshot("delayed-bus-metrics")
    f.stop(f.daemon)
    return observed


def compare(f, expected, actual, inject_error):
    f.check("paired-observation-keys", list(actual), list(expected))
    for key, reference in expected.items():
        value = actual.get(key)
        left, right = copy.deepcopy(reference), copy.deepcopy(value)
        if key in ("cache-answer", "rewritten-cache-answer") and right is not None:
            for c, r in zip(left["records"], right["records"]):
                if c["type"] != 41 and abs(c["ttl"] - r["ttl"]) <= 1:
                    r["ttl"] = c["ttl"]
        if key == "wrong-family-answer":
            # Exact image musl inet_pton(AF_INET, "2001:db8::9", p) returns
            # zero after writing 200 to p[0]. rfc1035.c passes the live RDATA
            # destination, so its rejected subscriber response still mutates A.
            c_records = left.get("records", [])
            r_records = right.get("records", [])
            guarded = (len(c_records) == len(r_records) == 1
                       and c_records[0].get("type") == r_records[0].get("type") == 1
                       and c_records[0].get("data") == "200.0.2.1"
                       and r_records[0].get("data") == "192.0.2.1")
            f.check("C-partial-inet-pton-rejection-and-Rust-original-A-guard", guarded, True)
            if guarded:
                left["records"][0]["data"] = right["records"][0]["data"]
        if inject_error and key == "initial":
            left["dns_cache_inserted"] += 1
        f.check("paired-" + key, right, left)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--c-binary", type=Path, help="optional exact image runner; native build still supplies ubusd/client")
    parser.add_argument("--c-identity", type=Path, help="strict image ELF/library/runner identity for --c-binary")
    parser.add_argument("--rust-binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    assert {row["ifname"] for row in json.loads(subprocess.check_output(["ip", "-j", "link"]))} == {"lo"}
    args.reference_build, args.rust_binary = args.reference_build.resolve(), args.rust_binary.resolve()
    assert digest(args.reference_build / "dnsmasq/dnsmasq") == args.c_sha256
    reference = {"kind": "native-glibc", "elf_sha256": args.c_sha256}
    if args.c_binary is not None:
        args.c_binary = args.c_binary.resolve()
        reference = verify_reference(args.c_binary, args.c_identity)
    else:
        assert args.c_identity is None, "--c-identity requires --c-binary"
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "ubus-product", "/run"], check=True)
    Path(BUS).parent.mkdir()
    f = Product(args, out)
    upstream_answer = f.upstream.answer
    def timed_answer(packet, transport):
        response = bytearray(upstream_answer(packet, transport))
        if packet[12:].startswith(b"\x05stale\x07invalid\0"):
            response[-10:-6] = struct.pack("!I", 2)
        return bytes(response)
    f.upstream.answer = timed_answer
    error, expected, actual = None, {}, {}
    try:
        f.start_bus()
        expected = run_side(f, "C")
        assert len(expected) == 69, "frozen paired service schedule changed"
        (out / "c-observations.json").write_text(json.dumps(expected, indent=2) + "\n")
        actual = run_side(f, "Rust")
        compare(f, expected, actual, args.inject_error)
    except Exception as exception:
        error = repr(exception)
        f.check("uncaught-exception", error, None)
    finally:
        f.close()
    report = {"scope": __doc__, "error": error, "checks": f.checks, "raw": f.raw,
              "c": expected, "rust": actual,
              "passed": sum(row["pass"] for row in f.checks), "failed": sum(not row["pass"] for row in f.checks),
              "paired_observations": len(expected),
              "paired_matches": sum(row["pass"] for row in f.checks if row["case"].startswith("paired-") and row["case"] != "paired-observation-keys"),
              "reference_defects": ["C DNS object's type survives bus restart and cannot be resolved",
                                    "Exact image inet_pton rejection writes a partial A destination; Rust retains the original address"],
              "reference": reference,
              "identities": {"c": reference["elf_sha256"], "native_client_build_c": args.c_sha256, "rust": digest(args.rust_binary),
                             "ubusd": digest(args.reference_build / "deps/sbin/ubusd"),
                             "client": digest(f.client), "tool": digest(__file__)}}
    (out / "result.json").write_text(json.dumps(report, indent=2, default=lambda value: value.hex()) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "failed", "error")}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
