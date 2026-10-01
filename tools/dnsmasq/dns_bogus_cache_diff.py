#!/usr/bin/env python3
"""C-first bogus-wildcard cache transactions versus ordinary CD suppression."""
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

from dns_do_cache_diff import request
from dns_service_probe import read_name, rr, semantics
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)


def matrix():
    for kind in (1, 28):
        for do, ad in ((False, False), (False, True), (True, False), (True, True)):
            for cd in (False, True):
                for reply_cd in (False, True):
                    for bogus in (False, True):
                        label = f"k{kind}-d{int(do)}-a{int(ad)}-c{int(cd)}-rc{int(reply_cd)}-b{int(bogus)}"
                        yield {"label": label, "host": label + ".bogus.test", "kind": kind,
                               "do": do, "ad": ad, "cd": cd, "reply_cd": reply_cd, "bogus": bogus}


def answer(packet, case):
    decoded = semantics(packet)
    _, end = read_name(packet, 12)
    opt = next((record for record in decoded["records"] if record["type"] == 41), None)
    if case["kind"] == 1:
        data = bytes([8, 8, 4, 4 if case["bogus"] else 5])
    else:
        data = bytes.fromhex("20014860486000000000000000008888" if case["bogus"]
                             else "20014860486000000000000000008889")
    flags = 0x81a0 | (0x10 if case["reply_cd"] else 0)
    response = (packet[:2] + struct.pack("!5H", flags, 1, 1, 0, int(opt is not None))
                + packet[12:end + 4] + rr(case["kind"], data, 120))
    if opt is not None:
        response += b"\0" + struct.pack("!HHIH", 41, 1232, opt["ttl"] & 0x8000, 0)
    return response


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("observation count or labels differ")
    return [{"label": c["label"], "c": c, "rust": rust}
            for c, rust in zip(expected, actual) if c != rust]


def run(args, binary, side, no_negcache, out):
    out.mkdir()
    fixture = Fixture(args, out)
    rows, wires, upstream_wires = [], [], []
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))

    def exchange(label, packet, case):
        observed = []
        before = fixture.metrics()
        client.sendto(packet, LISTEN)
        deadline = time.monotonic() + 2
        while True:
            ready = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))[0]
            assert ready, (label, "reply timeout")
            if upstream in ready:
                sent, peer = upstream.recvfrom(65535)
                response = answer(sent, case)
                upstream_wires.append({"label": label, "request": sent.hex(), "response": response.hex()})
                decoded = semantics(sent)
                decoded["id"] = 0  # Random forwarding IDs are not a protocol difference.
                observed.append(decoded)
                upstream.sendto(response, peer)
            if client in ready:
                response = client.recv(65535)
                break
        assert response[:2] == packet[:2] and len(observed) <= 1
        question = response[12:read_name(response, 12)[1] + 4]
        assert question == packet[12:read_name(packet, 12)[1] + 4]
        wires.append({"label": label, "request": packet.hex(), "response": response.hex()})
        return {"label": label, "response": semantics(response), "question": question.hex(),
                "upstream": observed, "cached": not observed, "before": before,
                "metrics": fixture.metrics(), "case": case}

    try:
        fixture.start_bus()
        config = out / "dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "no-0x20-encode\nno-round-robin\ncache-size=512\nneg-ttl=30\n"
                          "host-record=ready.test,192.0.2.41\nbogus-nxdomain=8.8.4.4\n"
                          "bogus-nxdomain=2001:4860:4860::8888\n"
                          f"server=127.0.0.1#{upstream.getsockname()[1]}\nenable-ubus={OBJECT}\n"
                          + ("no-negcache\n" if no_negcache else ""))
        command = [str(binary), "-k", "-C", str(config)]
        if side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        assert exchange("ready", request("ready.test", 1, 0x3000, opt=False), {})["cached"]
        for index, case in enumerate(matrix()):
            fraction = time.time() % 1
            if fraction > .70:
                time.sleep(1.02 - fraction)
            begin = int(time.time())
            for step, packet in [
                ("seed", request(case["host"], case["kind"], 0x4000 + index * 2,
                                 case["ad"], case["cd"], case["do"])),
                ("plain", request(case["host"], case["kind"], 0x4001 + index * 2, opt=False)),
            ]:
                rows.append({**exchange(case["label"] + "/" + step, packet, case), "step": step})
            assert int(time.time()) == begin, (case["label"], "pair crossed a wall-clock second")
        fixture.daemon.send_signal(signal.SIGTERM)
        fixture.daemon.wait(3)
        assert fixture.daemon.returncode == 0
        return rows
    finally:
        client.close()
        upstream.close()
        fixture.close()
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wires": wires,
            "upstream_wires": upstream_wires, "raw": fixture.raw, "checks": fixture.checks}, indent=2) + "\n")
        assert all(row["pass"] for row in fixture.checks)


def calibrate(rows):
    assert len(rows) == len(list(matrix())) * 2
    for row in rows:
        case = row["case"]
        cached = row["step"] == "plain" and (case["bogus"] or not (case["cd"] or case["reply_cd"]))
        assert row["cached"] == cached, row["label"]
        inserted = not cached and (case["bogus"] or not (case["reply_cd"] or
                                  (row["step"] == "seed" and case["cd"])))
        delta = row["metrics"]["dns_cache_inserted"] - row["before"]["dns_cache_inserted"]
        assert delta == int(inserted), (row["label"], delta)
        assert row["response"]["flags"] & 15 == (3 if case["bogus"] else 0)
        assert not row["response"]["flags"] & 0x20
        assert bool(row["response"]["flags"] & 0x10) == (row["step"] == "seed" and case["cd"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-binary", type=Path)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    if args.inject_error and args.rust is None:
        parser.error("negative control requires Rust")
    args.reference_build = args.reference_build.resolve()
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-bogus-cache", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native, "tool_sha256": digest(__file__),
              "rust_sha256": None if args.rust is None else digest(args.rust), "profiles": [],
              "failures": [], "injected_error": args.inject_error, "compared": 0, "mismatches": 0}
    expected = {}
    for no_negcache in (False, True):
        work = out / ("no-negcache" if no_negcache else "ordinary")
        work.mkdir()
        try:
            rows = run(args, c, "C", no_negcache, work / "c")
            calibrate(rows)
            assert not compare(rows, copy.deepcopy(rows))
            changed = copy.deepcopy(rows)
            changed[0]["metrics"]["dns_cache_inserted"] += 1
            assert len(compare(rows, changed)) == 1
            try:
                compare(rows, rows[:-1])
            except ValueError:
                pass
            else:
                raise AssertionError("missing row calibration")
            expected[no_negcache] = rows
        except Exception as error:
            report["failures"].append({"no_negcache": no_negcache, "stage": "C", "error": repr(error)})
    if not report["failures"]:
        for no_negcache, rows in expected.items():
            differences = []
            try:
                if args.rust is not None:
                    work = out / ("no-negcache" if no_negcache else "ordinary")
                    actual = run(args, args.rust.resolve(), "Rust", no_negcache, work / "rust")
                    if args.inject_error and not no_negcache:
                        actual[0]["metrics"]["dns_cache_inserted"] += 1
                    differences = compare(rows, actual)
                    report["compared"] += len(rows)
                report["profiles"].append({"no_negcache": no_negcache, "observations": len(rows),
                                           "differences": differences})
            except Exception as error:
                report["failures"].append({"no_negcache": no_negcache, "stage": "Rust", "error": repr(error)})
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "profiles"}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
