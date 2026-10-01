#!/usr/bin/env python3
"""Frozen C-first DO lookup/LRU pressure gate; see DO_LOOKUP_PRESSURE_PLAN.md."""
import argparse
import copy
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

from dns_do_cache_diff import answer, compare, request
from dns_service_probe import read_name, semantics
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)


def profiles():
    return [{"label": f"k{kind}-{shape}-{touch}", "kind": kind, "shape": shape, "touch": touch}
            for kind in (1, 28) for shape in ("direct", "cname")
            for touch in ("untouched", "plain", "do")]


def schedule(profile):
    owner = "owner.pressure.test"
    target = "target." + owner
    rows = [("seed-owner", owner, False, profile["shape"], False),
            ("seed-b", "b.pressure.test", False, "address", False)]
    if profile["shape"] == "cname":
        rows.append(("prime-target", target, False, "failure", True))
    rows.append(("seed-c", "c.pressure.test", False, "address", False))
    rows.append(("touch", "missing.pressure.test" if profile["touch"] == "untouched" else owner,
                 profile["touch"] == "do", "failure", profile["touch"] == "plain"))
    rows.append(("insert-d", "d.pressure.test", False, "address", False))
    for label, host, cached in [
        ("probe-b", "b.pressure.test", profile["touch"] == "untouched"),
        ("probe-owner", owner, profile["touch"] != "untouched"),
        ("probe-c", "c.pressure.test", True),
        ("probe-d", "d.pressure.test", True),
    ]:
        rows.append((label, host, False, "failure", cached))
    if profile["shape"] == "cname":
        rows.append(("probe-target", target, False, "failure", True))
    return rows


def response(packet, shape):
    if shape != "failure":
        return answer(packet, False, False, "address" if shape == "direct" else shape)
    end = read_name(packet, 12)[1] + 4
    opt = next((rr for rr in semantics(packet)["records"] if rr["type"] == 41), None)
    wire = packet[:2] + struct.pack("!5H", 0x8182, 1, 0, 0, int(opt is not None)) + packet[12:end]
    if opt is not None:
        wire += b"\0" + struct.pack("!HHIH", 41, 1232, opt["ttl"] & 0x8000, 0)
    return wire


def run(args, binary, side, profile, out):
    out.mkdir()
    fixture = Fixture(args, out)
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(2)
    rows, wires = [], []
    try:
        fixture.start_bus()
        config = out / "dnsmasq.conf"
        capacity = 4 if profile["shape"] == "cname" else 3
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "no-0x20-encode\nno-round-robin\nhost-record=ready.test,192.0.2.41\n"
                          f"cache-size={capacity}\nserver=127.0.0.1#{upstream.getsockname()[1]}\n"
                          f"enable-ubus={OBJECT}\n")
        command = [str(binary), "-k", "-C", str(config)]
        if side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        client.sendto(request("ready.test", 1, 0x3000, opt=False), LISTEN)
        assert semantics(client.recv(65535))["records"][0]["type"] == 1
        before = fixture.metrics()
        for index, (label, host, do, shape, _) in enumerate(schedule(profile)):
            packet = request(host, profile["kind"], 0x4000 + index, do=do)
            observed, raw_upstream = [], []
            client.sendto(packet, LISTEN)
            deadline = time.monotonic() + 2
            while True:
                ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
                assert ready, ("DNS response timeout", label)
                if upstream in ready:
                    sent, peer = upstream.recvfrom(65535)
                    decoded = semantics(sent)
                    decoded["id"] = 0
                    observed.append(decoded)
                    reply = response(sent, shape)
                    raw_upstream.append({"request": sent.hex(), "response": reply.hex(), "peer": peer})
                    upstream.sendto(reply, peer)
                if client in ready:
                    reply = client.recv(65535)
                    break
            wires.append({"label": label, "request": packet.hex(), "response": reply.hex(),
                          "upstream": raw_upstream})
            assert reply[:2] == packet[:2], "recipient ID changed"
            assert not select.select([client, upstream], [], [], .02)[0], "extra datagram"
            rows.append({"label": label, "cached": not observed, "response": semantics(reply),
                         "question": reply[12:read_name(reply, 12)[1] + 4].hex(),
                         "upstream": observed, "metrics": fixture.metrics(), "before": before})
            before = rows[-1]["metrics"]
        fixture.daemon.send_signal(signal.SIGTERM)
        fixture.daemon.wait(3)
        assert fixture.daemon.returncode == 0
        return rows
    finally:
        client.close()
        upstream.close()
        fixture.close()
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wires": wires,
                                                   "raw": fixture.raw, "checks": fixture.checks}, indent=2) + "\n")
        assert all(check["pass"] for check in fixture.checks)


def calibrate(rows, profile):
    expected = schedule(profile)
    assert len(rows) == len(expected)
    for row, (label, _, _, shape, cached) in zip(rows, expected):
        assert row["label"] == label and row["cached"] == cached, (profile, label, row["cached"], cached)
        delta = row["metrics"]["dns_cache_inserted"] - row["before"]["dns_cache_inserted"]
        assert delta == (2 if shape == "cname" else int(shape != "failure")), (profile, label, delta)
        assert len(row["upstream"]) == (0 if cached else 2 if shape == "failure" else 1), (profile, label)
        if not cached and shape == "failure":
            assert row["response"]["flags"] & 15 == 2, "SERVFAIL was not preserved"
    assert rows[-1]["metrics"]["dns_cache_live_freed"] == 1, profile
    assert rows[-1]["metrics"]["dns_cache_inserted"] == (5 if profile["shape"] == "cname" else 4), profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", required=True, type=Path)
    parser.add_argument("--c-binary", type=Path)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    if args.inject_error and args.rust is None:
        parser.error("negative control requires Rust")
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(profiles(), indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-do-pressure", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native, "tool_sha256": digest(__file__),
              "rust_sha256": None if args.rust is None else digest(args.rust), "c_only": args.rust is None,
              "profiles": [], "failures": [], "injected_error": args.inject_error}
    expected_profiles = []
    # Calibrate the complete C workload before starting any Rust process.
    for profile in profiles():
        work = out / profile["label"]
        work.mkdir()
        try:
            expected = run(args, c, "C", profile, work / "c")
            calibrate(expected, profile)
            assert not compare(expected, copy.deepcopy(expected))
            changed = copy.deepcopy(expected)
            changed[0]["cached"] = not changed[0]["cached"]
            assert len(compare(expected, changed)) == 1
            try:
                compare(expected, expected[:-1])
            except ValueError:
                pass
            else:
                raise AssertionError("missing row calibration")
            expected_profiles.append((profile, expected, work))
        except Exception as error:
            report["failures"].append({"profile": profile, "stage": "C", "error": repr(error)})
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if not report["failures"]:
        for index, (profile, expected, work) in enumerate(expected_profiles):
            try:
                differences = []
                if args.rust is not None:
                    actual = run(args, args.rust.resolve(), "Rust", profile, work / "rust")
                    if args.inject_error and index == 0:
                        actual[0]["cached"] = not actual[0]["cached"]
                    differences = compare(expected, actual)
                report["profiles"].append({"profile": profile, "observations": len(expected),
                                           "differences": differences})
            except Exception as error:
                report["failures"].append({"profile": profile, "stage": "Rust", "error": repr(error)})
            (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    report["c_calibrated"] = sum(len(rows) for _, rows, _ in expected_profiles)
    report["compared"] = 0 if args.rust is None else sum(row["observations"] for row in report["profiles"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "profiles"}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
