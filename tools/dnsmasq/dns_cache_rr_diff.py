#!/usr/bin/env python3
"""C-first cache-rr configuration and forward-generic cache service contract."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

from dns_do_cache_diff import compare, request
from dns_service_probe import name, read_name, rr
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)
# Matching rrfilter.c::rrfilter_desc, not a Rust implementation reference.
NAME_LAYOUTS = {
    2: [0], 3: [0], 4: [0], 5: [0], 6: [0, 0], 7: [0], 8: [0], 9: [0],
    12: [0], 14: [0, 0], 15: [2, 0], 17: [0, 0], 18: [2, 0], 21: [2, 0],
    24: [18, 0], 26: [2, 0, 0], 30: [0], 36: [2, 0], 33: [6, 0], 39: [0],
}


def decode(packet):
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    pos, questions, records = 12, [], []
    for _ in range(qd):
        host, pos = read_name(packet, pos)
        kind, cls = struct.unpack_from("!HH", packet, pos)
        pos += 4
        questions.append([host, kind, cls])
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            host, pos = read_name(packet, pos)
            kind, cls, ttl, size = struct.unpack_from("!HHIH", packet, pos)
            pos += 10
            end = pos + size
            assert end <= len(packet), "truncated RDATA"
            value = bytearray()
            for field in NAME_LAYOUTS.get(kind, []):
                if field:
                    assert pos + field <= end, "truncated RDATA prefix"
                    value.extend(packet[pos:pos + field])
                    pos += field
                else:
                    target, pos = read_name(packet, pos)
                    assert pos <= end, "name exceeds RDATA"
                    value.extend(name(target))
            value.extend(packet[pos:end])
            records.append({"section": section, "name": host, "type": kind,
                            "class": cls, "ttl": ttl, "data": value.hex()})
            pos = end
    assert pos == len(packet), "trailing packet bytes"
    return {"id": ident, "flags": flags, "questions": questions, "records": records}


def config_cases():
    valid = [
        ("txt", "TXT"), ("lowercase", "txt"), ("numeric-txt", "16"),
        ("numeric-unknown", "65280"), ("any", "ANY"), ("numeric-any", "255"),
        ("comma-repeat", "TXT,65280\ncache-rr=MX"), ("duplicate", "TXT,TXT"),
        ("zero", "0"), ("wrap-zero", "65536"), ("wrap-txt", "65552"),
        ("max-u16", "65535"), ("max-int", "2147483647"), ("empty", ""),
        ("trailing-empty", "TXT,"), ("leading-empty", ",TXT"),
    ]
    invalid = [("unknown-name", "NOT_A_TYPE"), ("type-prefix", "TYPE16"),
               ("negative", "-1"), ("positive-sign", "+16"), ("decimal", "1.6"), ("hex", "0x10")]
    return [{"label": label, "argument": value, "accepted": expected}
            for expected, items in ((True, valid), (False, invalid)) for label, value in items]


def profiles():
    rows = [
        ("disabled-txt", "", 16, "txt", 0),
        ("disabled-unknown", "", 65280, "opaque", 0),
        ("txt-small", "TXT", 16, "txt", 1),
        ("txt-large", "TXT", 16, "large", 1),
        ("unknown-pointer", "65280", 65280, "opaque", 1),
        ("wrap-txt", "65552", 16, "txt", 1),
        ("any-txt", "ANY", 16, "txt", 1),
        ("any-unknown", "ANY", 65281, "opaque", 1),
        ("mx-repeat", "TXT,65280\ncache-rr=MX", 15, "mx", 1),
        ("default-srv", "", 33, "srv", 1),
        ("default-ptr", "", 12, "ptr", 1),
        ("soa-two-names", "SOA", 6, "soa", 1),
        ("disabled-mx", "TXT", 15, "mx", 0),
        ("cname-query", "ANY", 5, "cname-only", 0),
        ("any-query", "ANY", 255, "any", 0),
        ("txt-round-robin", "TXT", 16, "multi", 3),
        ("cname-txt", "TXT", 16, "cname-txt", 2),
        ("txt-nodata", "TXT", 16, "nodata", 2),
        ("srv-nodata", "", 33, "nodata", 2),
        ("disabled-txt-nx", "", 16, "nx", 1),
    ]
    result = [{"label": label, "option": option, "kind": kind, "shape": shape,
               "inserts": inserts, "group": "forward"}
              for label, option, kind, shape, inserts in rows]
    for mode in ("commit", "request-cd", "reply-cd"):
        result.append({"label": "replace-" + mode, "option": "TXT", "kind": 16,
                       "shape": "replace", "mode": mode, "group": "forward"})
    for version in (4, 6):
        address = "192.0.2.7" if version == 4 else "2001:db8::7"
        result.append({"label": f"reverse-v{version}", "option": "", "kind": 12,
                       "shape": "reverse", "inserts": 1, "group": "reverse-c-only",
                       "host": ipaddress.ip_address(address).reverse_pointer})
    result.append({"label": "reverse-alias", "option": "", "kind": 12,
                   "shape": "cname-ptr", "inserts": 2, "group": "reverse-c-only",
                   "host": "7.2.0.192.in-addr.arpa"})
    return result


def step(label, host, kind, shape, cached, inserts=0, request_cd=False, reply_cd=False):
    return {"label": label, "host": host, "kind": kind, "shape": shape,
            "cached": cached, "inserts": inserts, "request_cd": request_cd, "reply_cd": reply_cd}


def schedule(profile):
    if profile["shape"] == "replace":
        commit = profile["mode"] == "commit"
        return [
            step("seed-owner", "owner.rr.test", 16, "old", False, 1),
            step("seed-sentinel", "sentinel.rr.test", 16, "txt", False, 1),
            step("replace", "alias.rr.test", 16, "replace", False, 2 if commit else 0,
                 profile["mode"] == "request-cd", profile["mode"] == "reply-cd"),
            step("probe-owner", "owner.rr.test", 16, "failure", commit),
            step("probe-alias", "alias.rr.test", 16, "failure", commit),
            step("probe-sentinel", "sentinel.rr.test", 16, "failure", True),
        ]
    return [step(label, profile.get("host", profile["label"] + ".rr.test"), profile["kind"],
                 profile["shape"], index > 0 and profile["inserts"] > 0,
                 profile["inserts"] if index == 0 else 0)
            for index, label in enumerate(("seed", "replay-1", "replay-2"))]


def response(packet, shape, reply_cd):
    host, end = read_name(packet, 12)
    kind = struct.unpack_from("!H", packet, end)[0]
    question = packet[12:end + 4]
    # Every service query has an empty OPT, including the no-DO CD profiles.
    assert struct.unpack_from("!H", packet, 10)[0] == 1
    answers, authority = [], []
    flags = 0x8180 | (0x10 if reply_cd else 0)
    target_compressed = b"\x06Target\xc0\x0c"
    soa_data = b"\x02NS\xc0\x0c\x0aHostmaster\xc0\x0c" + struct.pack("!5I", 1, 2, 3, 4, 120)
    if shape == "failure":
        flags |= 2
    elif shape == "nx":
        flags |= 3
    elif shape == "nodata":
        data = name("ns.rr.test") + name("hostmaster.rr.test") + struct.pack("!5I", 1, 2, 3, 4, 120)
        authority.append(rr(6, data, 120, name("rr.test")))
    elif shape in ("cname-only", "cname-txt", "cname-ptr", "replace"):
        target = "owner.rr.test" if shape == "replace" else "target." + host
        target_data = name(target) if shape == "replace" else target_compressed
        answers.append(rr(5, target_data, 90))
        if shape != "cname-only":
            offset = 12 + len(question) + 12
            owner = struct.pack("!H", 0xc000 | offset)
            data = name("host.reverse.test") if shape == "cname-ptr" else b"\x03new"
            answers.append(rr(kind, data, 120, owner))
    elif shape == "any":
        answers = [rr(16, b"\x03one"), rr(65280, b"\x00\xff\xc0\x0c")]
    elif shape == "multi":
        answers = [rr(16, value) for value in (b"\x03one", b"\x03two", b"\x05three")]
    else:
        data = {
            "txt": b"\x08pressure", "old": b"\x03old", "large": b"\xff" + b"x" * 255 + b"\x01z",
            "opaque": b"\x00\xff\xc0\x0c\x80\x41", "mx": struct.pack("!H", 10) + target_compressed,
            "srv": struct.pack("!3H", 10, 20, 5353) + target_compressed,
            "ptr": target_compressed, "soa": soa_data, "reverse": name("host.reverse.test"),
        }[shape]
        answers.append(rr(kind, data))
    opt = b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return (packet[:2] + struct.pack("!5H", flags, 1, len(answers), len(authority), 1)
            + question + b"".join(answers + authority) + opt)


def run_config(binary, case, out):
    out.mkdir()
    config = out / "dnsmasq.conf"
    config.write_text("no-hosts\nno-resolv\ncache-rr=" + case["argument"] + "\n")
    result = subprocess.run([str(binary), "--test", "-C", str(config)], capture_output=True, text=True, timeout=3)
    raw = {"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    (out / "result.json").write_text(json.dumps(raw, indent=2) + "\n")
    return {"label": case["label"], "accepted": result.returncode == 0}


def run_service(args, binary, side, profile, out):
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
        capacity = 3 if profile["shape"] == "replace" else 64
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "no-0x20-encode\nneg-ttl=120\nhost-record=ready.test,192.0.2.41\n"
                          + ("" if profile["shape"] == "multi" else "no-round-robin\n")
                          + ("cache-rr=" + profile["option"] + "\n" if profile["option"] else "")
                          + f"cache-size={capacity}\nserver=127.0.0.1#{upstream.getsockname()[1]}\n"
                          + f"enable-ubus={OBJECT}\n")
        command = [str(binary), "-k", "-C", str(config)]
        if side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        client.sendto(request("ready.test", 1, 0x3000, opt=False), LISTEN)
        assert decode(client.recv(65535))["records"][0]["type"] == 1
        before = fixture.metrics()
        for index, action in enumerate(schedule(profile)):
            packet = request(action["host"], action["kind"], 0x4000 + index, cd=action["request_cd"])
            observed, raw_upstream = [], []
            client.sendto(packet, LISTEN)
            deadline = time.monotonic() + 2
            while True:
                ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
                assert ready, ("DNS response timeout", action["label"])
                if upstream in ready:
                    sent, peer = upstream.recvfrom(65535)
                    decoded = decode(sent)
                    decoded["id"] = 0
                    observed.append(decoded)
                    reply = response(sent, action["shape"], action["reply_cd"])
                    raw_upstream.append({"request": sent.hex(), "response": reply.hex(), "peer": peer})
                    upstream.sendto(reply, peer)
                if client in ready:
                    reply = client.recv(65535)
                    break
            wires.append({"label": action["label"], "request": packet.hex(), "response": reply.hex(),
                          "upstream": raw_upstream})
            assert reply[:2] == packet[:2], "recipient ID changed"
            assert not select.select([client, upstream], [], [], .02)[0], "extra datagram"
            rows.append({"label": action["label"], "cached": not observed, "response": decode(reply),
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
    for row, action in zip(rows, expected):
        assert row["label"] == action["label"] and row["cached"] == action["cached"], (profile["label"], action["label"], row["cached"])
        delta = row["metrics"]["dns_cache_inserted"] - row["before"]["dns_cache_inserted"]
        assert delta == action["inserts"], (profile["label"], action["label"], "insert", delta, action["inserts"])
        sends = 0 if action["cached"] else 2 if action["shape"] == "failure" else 1
        assert len(row["upstream"]) == sends, (profile["label"], action["label"], "send")
        assert bool(row["response"]["flags"] & 0x10) == action["request_cd"], "client CD not restored"
        if action["shape"] == "failure" and not action["cached"]:
            assert row["response"]["flags"] & 15 == 2, "SERVFAIL not preserved"
    assert rows[-1]["metrics"]["dns_cache_live_freed"] == 0, "unexpected capacity eviction"
    assert not compare(rows, copy.deepcopy(rows))
    changed = copy.deepcopy(rows)
    changed[0]["cached"] = not changed[0]["cached"]
    assert len(compare(rows, changed)) == 1
    try:
        compare(rows, rows[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("missing row calibration")


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
    (out / "matrix.json").write_text(json.dumps({"configuration": config_cases(), "services": profiles()}, indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-cache-rr", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native, "tool_sha256": digest(__file__),
              "rust_sha256": None if args.rust is None else digest(args.rust), "c_only": args.rust is None,
              "configuration": [], "profiles": [], "failures": [], "injected_error": args.inject_error}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    config_expected, service_expected = [], []
    for case in config_cases():
        work = out / ("config-" + case["label"])
        work.mkdir()
        try:
            row = run_config(c, case, work / "c")
            assert row["accepted"] == case["accepted"], (case, row)
            config_expected.append((case, row, work))
        except Exception as error:
            report["failures"].append({"profile": case["label"], "stage": "C-config", "error": repr(error)})
        save()
    for profile in profiles():
        work = out / profile["label"]
        work.mkdir()
        try:
            expected = run_service(args, c, "C", profile, work / "c")
            calibrate(expected, profile)
            service_expected.append((profile, expected, work))
        except Exception as error:
            report["failures"].append({"profile": profile, "stage": "C-service", "error": repr(error)})
        save()
    if not report["failures"]:
        for case, expected, work in config_expected:
            actual = None if args.rust is None else run_config(args.rust.resolve(), case, work / "rust")
            report["configuration"].append({"expected": expected, "actual": actual,
                                             "mismatch": actual is not None and actual != expected})
        for index, (profile, expected, work) in enumerate(service_expected):
            try:
                differences = []
                paired = args.rust is not None and profile["group"] == "forward"
                if paired:
                    actual = run_service(args, args.rust.resolve(), "Rust", profile, work / "rust")
                    if args.inject_error and index == 0:
                        actual[0]["cached"] = not actual[0]["cached"]
                    differences = compare(expected, actual)
                report["profiles"].append({"profile": profile, "observations": len(expected),
                                           "paired": paired, "differences": differences})
            except Exception as error:
                report["failures"].append({"profile": profile, "stage": "Rust-service", "error": repr(error)})
            save()
    report["c_config_calibrated"] = len(config_expected)
    report["c_service_calibrated"] = sum(len(rows) for _, rows, _ in service_expected)
    report["compared"] = sum(row["observations"] for row in report["profiles"] if row["paired"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    report["config_mismatches"] = sum(row["mismatch"] for row in report["configuration"])
    report["reverse_c_only"] = sum(row["observations"] for row in report["profiles"] if row["profile"]["group"] == "reverse-c-only")
    save()
    print(json.dumps({key: value for key, value in report.items() if key not in ("profiles", "configuration")}))
    return int(bool(report["failures"] or report["mismatches"] or report["config_mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
