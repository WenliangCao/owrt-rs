#!/usr/bin/env python3
"""C-first malformed generic RDATA replies and ordered cache-prefix effects."""
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

from dns_cache_rr_diff import NAME_LAYOUTS
from dns_do_cache_diff import compare, request
from dns_service_probe import name, read_name, rr
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)


def decode(packet):
    """Keep malformed RDATA observable; reject malformed outer DNS framing."""
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
            start, end = pos, pos + size
            assert end <= len(packet), "truncated outer RDATA"
            value, malformed = bytearray(), False
            try:
                for field in NAME_LAYOUTS.get(kind, []):
                    if field:
                        following = min(pos + field, end)
                        value.extend(packet[pos:following])
                        pos = following
                    else:
                        assert pos < end, "missing name"
                        target, pos = read_name(packet, pos)
                        assert pos <= end, "name crosses RDLEN"
                        value.extend(name(target) if target else b"\0")
                value.extend(packet[pos:end])
            except (AssertionError, ValueError, UnicodeError):
                malformed = True
                value = packet[start:end]
            records.append({"section": section, "name": host, "type": kind,
                            "class": cls, "ttl": ttl, "data": bytes(value).hex(),
                            "malformed_rdata": malformed})
            pos = end
    assert pos == len(packet), "trailing packet bytes"
    return {"id": ident, "flags": flags, "questions": questions, "records": records}


def profiles():
    return [
        {"label": "srv-missing-target", "kind": 33, "option": "", "shape": "srv-short"},
        {"label": "mx-missing-exchange", "kind": 15, "option": "MX", "shape": "mx-short"},
        {"label": "soa-missing-second", "kind": 6, "option": "SOA", "shape": "soa-short"},
        {"label": "mx-name-crosses-rdlen", "kind": 15, "option": "MX", "shape": "mx-cross"},
        {"label": "disabled-mx", "kind": 15, "option": "TXT", "shape": "mx-short", "disabled": True},
        {"label": "unknown-opaque", "kind": 65280, "option": "65280", "shape": "opaque"},
        {"label": "replacement-prefix", "kind": 33, "option": "", "shape": "prefix"},
        {"label": "pressure-prefix", "kind": 33, "option": "", "shape": "prefix", "pressure": True},
    ]


def step(label, host, shape, cached=False, inserts=0, freed=0, malformed=False):
    return {"label": label, "host": host, "shape": shape, "cached": cached,
            "inserts": inserts, "freed": freed, "malformed": malformed}


def schedule(profile):
    if profile["shape"] != "prefix":
        opaque = profile["shape"] == "opaque"
        return [step(label, profile["label"] + ".badrr.test", profile["shape"],
                     opaque and index > 0, int(opaque and index == 0),
                     malformed=not opaque and not profile.get("disabled"))
                for index, label in enumerate(("seed", "replay-1", "replay-2"))]
    pressure = profile.get("pressure", False)
    result = [step("seed-owner", "owner.badrr.test", "old", inserts=1),
              step("seed-sentinel", "sentinel.badrr.test", "valid", inserts=1)]
    if pressure:
        result.append(step("seed-victim", "victim.badrr.test", "valid", inserts=1))
    result.append(step("failed-prefix", "alias.badrr.test", "prefix",
                       freed=2 if pressure else 0, malformed=True))
    result.append(step("probe-owner", "owner.badrr.test", "failure"))
    if pressure:
        result += [step("probe-sentinel", "sentinel.badrr.test", "failure"),
                   step("probe-victim", "victim.badrr.test", "failure", cached=True)]
    else:
        result += [step("probe-alias", "alias.badrr.test", "failure"),
                   step("probe-sentinel", "sentinel.badrr.test", "failure", cached=True)]
    result += [step("recover-owner", "owner.badrr.test", "valid", inserts=1),
               step("replay-owner", "owner.badrr.test", "failure", cached=True)]
    return result


def response(packet, shape):
    _, end = read_name(packet, 12)
    kind = struct.unpack_from("!H", packet, end)[0]
    question = packet[12:end + 4]
    flags, answers = 0x8180, []
    valid = struct.pack("!3H", 10, 20, 5353) + name("new.target.test")
    if shape == "failure":
        flags |= 2
    elif shape == "prefix":
        owner = name("owner.badrr.test")
        answers = [rr(5, owner, 90), rr(33, valid, owner=owner),
                   rr(33, struct.pack("!3H", 10, 20, 5353), owner=owner)]
    elif shape == "mx-cross":
        # The next RR starts with label length 12, completing c0 0c across
        # the preceding RDLEN. Both outer RR frames and the target are valid.
        answers = [rr(15, b"\0\x0a\xc0"),
                   rr(65280, b"opaque", owner=name("abcdefghijkl.other.test"))]
    else:
        data = {"srv-short": struct.pack("!3H", 10, 20, 5353),
                "mx-short": b"\0\x0a", "soa-short": b"\xc0\x0c",
                "opaque": b"\xc0\xff\x80\x41\0\xff", "valid": valid,
                "old": struct.pack("!3H", 10, 20, 5353) + name("old.target.test")}[shape]
        answers = [rr(kind, data)]
    opt = b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return packet[:2] + struct.pack("!5H", flags, 1, len(answers), 0, 1) + question + b"".join(answers) + opt


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
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "no-0x20-encode\nno-round-robin\ncache-size=3\n"
                          "host-record=ready.test,192.0.2.41\n"
                          + ("cache-rr=" + profile["option"] + "\n" if profile["option"] else "")
                          + f"server=127.0.0.1#{upstream.getsockname()[1]}\nenable-ubus={OBJECT}\n")
        command = [str(binary), "-k", "-C", str(config)]
        if side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        client.sendto(request("ready.test", 1, 0x3000, opt=False), LISTEN)
        assert decode(client.recv(65535))["records"][0]["type"] == 1
        before = fixture.metrics()
        for index, action in enumerate(schedule(profile)):
            packet = request(action["host"], profile["kind"], 0x4000 + index)
            observed, raw = [], []
            client.sendto(packet, LISTEN)
            deadline = time.monotonic() + 2
            while True:
                ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
                assert ready, (action["label"], "DNS response timeout")
                if upstream in ready:
                    sent, peer = upstream.recvfrom(65535)
                    decoded = decode(sent)
                    decoded["id"] = 0
                    observed.append(decoded)
                    answer = response(sent, action["shape"])
                    raw.append({"request": sent.hex(), "response": answer.hex(), "peer": peer})
                    upstream.sendto(answer, peer)
                if client in ready:
                    reply = client.recv(65535)
                    break
            wires.append({"label": action["label"], "request": packet.hex(), "response": reply.hex(), "upstream": raw})
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


def ede_codes(decoded):
    codes = []
    for record in decoded["records"]:
        if record["type"] != 41:
            continue
        data = bytes.fromhex(record["data"])
        while data:
            code, length = struct.unpack_from("!HH", data)
            assert length <= len(data) - 4
            if code == 15:
                assert length >= 2
                codes.append(struct.unpack_from("!H", data, 4)[0])
            data = data[4 + length:]
    return codes


def calibrate(rows, profile):
    actions = schedule(profile)
    assert len(rows) == len(actions)
    for row, action in zip(rows, actions):
        assert row["label"] == action["label"] and row["cached"] == action["cached"], (profile["label"], action["label"], "cache")
        for metric, field in (("dns_cache_inserted", "inserts"), ("dns_cache_live_freed", "freed")):
            delta = row["metrics"][metric] - row["before"][metric]
            assert delta == action[field], (profile["label"], action["label"], metric, delta, action[field])
        sends = 0 if action["cached"] else 2 if action["shape"] == "failure" else 1
        assert len(row["upstream"]) == sends, (action["label"], "send", len(row["upstream"]), sends)
        packet = row["response"]
        expected_rcode = 2 if action["malformed"] or (action["shape"] == "failure" and not action["cached"]) else 0
        assert packet["flags"] & 15 == expected_rcode, (action["label"], "rcode", packet["flags"])
        if action["malformed"]:
            assert all(record["section"] == "additional" and record["type"] == 41 for record in packet["records"])
            assert ede_codes(packet) == [0], (action["label"], "EDE", ede_codes(packet))
        if profile.get("disabled"):
            assert any(record["malformed_rdata"] for record in packet["records"])
        if profile["shape"] == "opaque":
            assert packet["records"][0]["data"] == "c0ff804100ff"
    assert not compare(rows, copy.deepcopy(rows))
    changed = copy.deepcopy(rows)
    changed[0]["response"]["flags"] ^= 0x20
    assert len(compare(rows, changed)) == 1
    try:
        compare(rows, rows[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("missing row accepted")


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
    assert sorted(label for _, label in socket.if_nameindex()) == ["lo"]
    assert args.rust is not None or not args.inject_error
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps([{**profile, "schedule": schedule(profile)} for profile in profiles()], indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-generic-malformed", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native, "tool_sha256": digest(__file__),
              "rust_sha256": None if args.rust is None else digest(args.rust), "c_only": args.rust is None,
              "profiles": [], "failures": [], "injected_error": args.inject_error}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    expected_rows = []
    for profile in profiles():
        work = out / profile["label"]
        work.mkdir()
        try:
            expected = run(args, c, "C", profile, work / "c")
            calibrate(expected, profile)
            expected_rows.append((profile, expected, work))
        except Exception as error:
            report["failures"].append({"profile": profile["label"], "stage": "C", "error": repr(error)})
        save()
    if not report["failures"]:
        for index, (profile, expected, work) in enumerate(expected_rows):
            try:
                differences = []
                if args.rust is not None:
                    actual = run(args, args.rust.resolve(), "Rust", profile, work / "rust")
                    if args.inject_error and index == 0:
                        actual[0]["response"]["flags"] ^= 0x20
                    differences = compare(expected, actual)
                report["profiles"].append({"profile": profile, "observations": len(expected), "differences": differences})
            except Exception as error:
                report["failures"].append({"profile": profile["label"], "stage": "Rust", "error": repr(error)})
            save()
    report["c_calibrated"] = sum(len(rows) for _, rows, _ in expected_rows)
    report["compared"] = sum(row["observations"] for row in report["profiles"]) if args.rust is not None else 0
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    save()
    print(json.dumps({key: value for key, value in report.items() if key != "profiles"}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
