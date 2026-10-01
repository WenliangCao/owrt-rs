#!/usr/bin/env python3
"""Frozen C-first reverse-cache UDP gate: 19 profiles, 124 observations."""
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
from dns_generic_malformed_diff import decode as decode_records, ede_codes
from dns_service_probe import name, read_name, rr
from dns_udp_refusal_diff import verify_reference
from reverse_cache_c_gate import ptr_case
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)
V4 = "0.2.0.192.in-addr.arpa"
PARTIAL4 = "2.0.192.in-addr.arpa"
R1 = "1.2.0.192.in-addr.arpa"
R2 = "2.2.0.192.in-addr.arpa"
A = "a.reverse.test"
B = "b.reverse.test"
C = "c.reverse.test"


def decode(packet):
    try:
        result = decode_records(packet)
    except (AssertionError, ValueError, UnicodeError, struct.error):
        return {"malformed_outer": True, "wire": packet.hex()}
    try:
        result["ptr_case"] = ptr_case(packet)
    except (AssertionError, ValueError, UnicodeError, struct.error):
        result["ptr_case"] = {"malformed_name": True}
    return result


def action(label, host, shape="failure", kind=12, cached=False, inserts=0, freed=0,
           target="new.target.test", do=False, ad=False, cd=False, reply_cd=False,
           reply_ad=False, ra=True, rd=True, opt=True, rcode=None, malformed=False,
           ede=None, terminal=None, ptr_targets=None):
    return {"label": label, "host": host, "shape": shape, "kind": kind, "cached": cached,
            "inserts": inserts, "freed": freed, "target": target, "do": do, "ad": ad,
            "cd": cd, "reply_cd": reply_cd, "reply_ad": reply_ad, "ra": ra, "rd": rd,
            "opt": opt, "rcode": (2 if shape == "failure" and not cached else 3 if shape == "nx" else 0) if rcode is None else rcode,
            "malformed": malformed, "ede": ede, "terminal": terminal, "ptr_targets": ptr_targets}


def profiles():
    result = []
    def add(label, rows, capacity=8):
        result.append({"label": label, "capacity": capacity, "actions": rows})
    for version, partial, full in [
        (4, PARTIAL4, V4),
        (6, "8.b.d.0.1.0.0.2.ip6.arpa", ipaddress.ip_address("2001:db8::").reverse_pointer),
    ]:
        target = f"MiXeD.v{version}.Test"
        alternative = partial.upper() if version == 4 else full[:-4] + "int"
        add(f"equivalent-v{version}", [
            action("seed-partial", partial, "positive", inserts=1, target=target, ptr_targets=[target]),
            action("full-hit", full, cached=True, ptr_targets=[target]),
            action("alternative-hit", alternative, cached=True, ptr_targets=[target]),
            action("target-address-miss", target, kind=1 if version == 4 else 28),
        ])
    for reverse_insert in (False, True):
        rows = [action("seed-forward-a", A, "positive", kind=1, inserts=1),
                action("seed-reverse-one", R1, "positive", inserts=1, target="one.reverse.test")]
        if reverse_insert:
            rows += [action("seed-forward-b", B, "positive", kind=1, inserts=1),
                     action("promote-reverse-one", R1, cached=True),
                     action("insert-reverse-two", R2, "positive", inserts=1, freed=1, target="two.reverse.test")]
        else:
            rows += [action("seed-reverse-two", R2, "positive", inserts=1, target="two.reverse.test"),
                     action("promote-forward-a", A, kind=1, cached=True),
                     action("insert-forward-b", B, "positive", kind=1, inserts=1, freed=1)]
        rows += [action("probe-forward-a", A, kind=1, cached=not reverse_insert),
                 action("probe-reverse-one", R1, cached=reverse_insert),
                 action("probe-reverse-two", R2, cached=True),
                 action("probe-forward-b", B, kind=1, cached=True)]
        add("capacity-" + ("reverse-insert" if reverse_insert else "forward-insert"), rows, 3)
    for nx in (False, True):
        add("negative-" + ("nx" if nx else "nodata"), [
            action("seed-negative", V4, "nx" if nx else "nodata", inserts=1 if nx else 2),
            action("partial-negative-miss", PARTIAL4),
            action("original-negative-hit", V4, cached=True, rcode=3 if nx else 0),
            action("partial-positive", PARTIAL4, "positive", inserts=1),
            action("original-positive-hit", V4, cached=True),
        ])
    for literal in (True, False):
        terminal = V4 if literal else "1.0/24.2.0.192.in-addr.arpa"
        add("fallback-" + ("literal" if literal else "rfc2317"), [
            action("seed-cname-terminal", R2, "cname", inserts=2, terminal=terminal),
            action("alias-hit", R2, cached=True),
            action("terminal-hit", terminal, cached=True),
            action("different-forward-key-miss", PARTIAL4 if literal else R1),
            action("terminal-hit-again", terminal, cached=True),
        ])
    for touch in ("rd0", "any"):
        rows = [action("seed-reverse-one", R1, "positive", inserts=1, target="one.reverse.test"),
                action("seed-forward-a", A, "positive", kind=1, inserts=1),
                action("seed-reverse-two", R2, "positive", inserts=1, target="two.reverse.test"),
                action("touch-without-cache-answer", R1, kind=12 if touch == "rd0" else 255, rd=touch != "rd0"),
                action("insert-forward-b", B, "positive", kind=1, inserts=1, freed=1),
                action("probe-forward-a", A, kind=1),
                action("probe-reverse-one", R1, cached=True),
                action("probe-reverse-two", R2, cached=True),
                action("probe-forward-b", B, kind=1, cached=True)]
        for row in rows:
            row["opt"] = False
        add("plain-pressure-" + touch, rows, 3)
    for beyond in (False, True):
        add("malformed-" + ("endrr" if beyond else "replacement-prefix"), [
            action("seed-old", V4, "positive", inserts=1, target="old.target.test"),
            action("seed-sentinel", A, "positive", kind=1, inserts=1),
            action("malformed-replacement", V4, "beyond" if beyond else "prefix", do=True, rcode=2, malformed=True, ede=[] if beyond else [0]),
            action("removed-owner-miss", V4),
            action("sentinel-hit", A, kind=1, cached=True),
            action("recover-owner", V4, "positive", inserts=1),
            action("recovered-hit", V4, cached=True),
        ], 3)
    add("malformed-pressure-prefix", [
        action("seed-a", A, "positive", kind=1, inserts=1),
        action("seed-b", B, "positive", kind=1, inserts=1),
        action("seed-c", C, "positive", kind=1, inserts=1),
        action("malformed-new-ptr", V4, "prefix", freed=1, rcode=2, malformed=True, ede=[0]),
        action("evicted-a-miss", A, kind=1),
        action("b-hit", B, kind=1, cached=True),
        action("c-hit", C, kind=1, cached=True),
        action("recover-owner", V4, "positive", inserts=1),
        action("recovered-hit", V4, cached=True),
    ], 3)
    add("ptr-crosses-rdlen", [
        action("seed-cross-rdlen", V4, "cross", inserts=1, ptr_targets=[V4]),
        action("cached-valid-full", V4, cached=True, ptr_targets=[V4]),
        action("cached-valid-partial", PARTIAL4, cached=True, ptr_targets=[V4]),
    ])
    add("empty-opt-do-ad", [
        action("do-ad-seed", V4, "positive", inserts=1, do=True, ad=True, reply_ad=True),
        action("plain-hit", V4, cached=True),
        action("ad-hit", V4, cached=True, ad=True),
        action("do-miss", V4, do=True),
        action("do-ad-miss", V4, do=True, ad=True),
        action("plain-hit-after-do", V4, cached=True),
    ])
    for mode in ("commit", "request-cd", "reply-cd", "ra0"):
        commit = mode in ("commit", "ra0")
        add("do-replace-" + mode, [
            action("seed-old", V4, "positive", inserts=1, target="old.target.test"),
            action("seed-sentinel", A, "positive", kind=1, inserts=1),
            action("replace", V4, "positive", do=True, cd=mode == "request-cd", reply_cd=mode == "reply-cd", ra=mode != "ra0", inserts=int(commit)),
            action("probe-owner", V4, cached=commit),
            action("probe-sentinel", A, kind=1, cached=True),
            action("recover-or-hit-owner", V4, "positive", cached=commit, inserts=int(not commit)),
            action("final-owner-hit", V4, cached=True),
        ], 3)
    assert len(result) == 19 and sum(len(profile["actions"]) for profile in result) == 124
    return result


def response(packet, action_row):
    _, end = read_name(packet, 12)
    question = packet[12:end + 4]
    shape = action_row["shape"]
    flags = 0x8000 | (struct.unpack_from("!H", packet, 2)[0] & 0x100)
    flags |= (0x80 if action_row["ra"] else 0) | (0x10 if action_row["reply_cd"] else 0) | (0x20 if action_row["reply_ad"] else 0)
    answers, authority = [], []
    if shape == "failure":
        flags |= 2
    elif shape == "nx":
        flags |= 3
    elif shape == "nodata":
        soa = name("ns.reverse.test") + name("hostmaster.reverse.test") + struct.pack("!5I", 1, 2, 3, 4, 120)
        authority.append(rr(6, soa, 120, name(PARTIAL4)))
    elif shape == "cname":
        terminal = action_row["terminal"]
        answers = [rr(5, name(terminal), 90), rr(12, name(action_row["target"]), owner=name(terminal))]
    elif shape == "cross":
        answers = [rr(12, b"\xc0"), rr(65280, b"opaque", owner=name("abcdefghijkl.other.test"))]
    elif shape in ("prefix", "beyond"):
        answers = [rr(12, name(action_row["target"]))]
        if shape == "prefix":
            answers.append(rr(12, b"\x40"))
    else:
        assert shape == "positive"
        kind = action_row["kind"]
        data = name(action_row["target"]) if kind == 12 else ipaddress.ip_address("192.0.2.99" if kind == 1 else "2001:db8::99").packed
        answers = [rr(kind, data)]
    upstream_opt = next((record for record in decode_records(packet)["records"] if record["type"] == 41), None)
    opt = b"" if upstream_opt is None else b"\0" + struct.pack("!HHIH", 41, 1232, upstream_opt["ttl"] & 0x8000, 0)
    result = bytearray(packet[:2] + struct.pack("!5H", flags, 1, len(answers), len(authority), int(upstream_opt is not None)) + question + b"".join(answers + authority) + opt)
    if shape == "beyond":
        first_fixed = 12 + len(question) + 2
        rdata_start = first_fixed + 10
        struct.pack_into("!H", result, first_fixed + 8, len(result) - rdata_start + 1)
    return bytes(result)


def wait_udp_bound(process):
    deadline = time.monotonic() + 3
    table = Path(f"/proc/{process.pid}/net/udp")
    while time.monotonic() < deadline:
        assert process.poll() is None, "daemon exited before UDP bind"
        if table.exists():
            for line in table.read_text().splitlines()[1:]:
                fields = line.split()
                if int(fields[1].split(":")[1], 16) == LISTEN[1]:
                    return
        time.sleep(.002)
    raise TimeoutError("UDP listener did not bind")


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
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "no-0x20-encode\nno-round-robin\nneg-ttl=120\nhost-record=ready.test,192.0.2.41\n"
                          + f"cache-size={profile['capacity']}\nserver=127.0.0.1#{upstream.getsockname()[1]}\nenable-ubus={OBJECT}\n")
        command = [str(binary), "-k", "-C", str(config)]
        if side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        wait_udp_bound(fixture.daemon)
        client.sendto(request("ready.test", 1, 0x3000, opt=False), LISTEN)
        assert decode(client.recv(65535))["records"][0]["type"] == 1
        before = fixture.metrics()
        for index, item in enumerate(profile["actions"]):
            packet = bytearray(request(item["host"], item["kind"], 0x4000 + index, ad=item["ad"], cd=item["cd"], do=item["do"], opt=item["opt"]))
            if not item["rd"]:
                packet[2] &= ~1
            packet = bytes(packet)
            observed, raw = [], []
            client.sendto(packet, LISTEN)
            deadline = time.monotonic() + 2
            while True:
                ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
                assert ready, (item["label"], "DNS response timeout")
                if upstream in ready:
                    sent, peer = upstream.recvfrom(65535)
                    decoded = decode(sent)
                    decoded["id"] = 0
                    observed.append(decoded)
                    answer = response(sent, item)
                    raw.append({"request": sent.hex(), "response": answer.hex(), "peer": peer})
                    upstream.sendto(answer, peer)
                if client in ready:
                    reply = client.recv(65535)
                    break
            wires.append({"label": item["label"], "request": packet.hex(), "response": reply.hex(), "upstream": raw})
            assert reply[:2] == packet[:2], "recipient ID changed"
            assert not select.select([client, upstream], [], [], .02)[0], "extra datagram"
            rows.append({"label": item["label"], "cached": not observed, "response": decode(reply),
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
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wires": wires, "raw": fixture.raw, "checks": fixture.checks}, indent=2) + "\n")
        assert all(check["pass"] for check in fixture.checks)


def calibrate(rows, profile):
    assert len(rows) == len(profile["actions"])
    for row, item in zip(rows, profile["actions"]):
        assert row["label"] == item["label"] and row["cached"] == item["cached"], (item["label"], "cache", row["cached"], item["cached"])
        for metric, field in (("dns_cache_inserted", "inserts"), ("dns_cache_live_freed", "freed")):
            delta = row["metrics"][metric] - row["before"][metric]
            assert delta == item[field], (item["label"], metric, delta, item[field])
        sends = 0 if item["cached"] else 2 if item["shape"] == "failure" else 1
        assert len(row["upstream"]) == sends, (item["label"], "upstream", len(row["upstream"]), sends)
        message = row["response"]
        assert not message.get("malformed_outer"), (item["label"], "malformed outer reply")
        assert message["flags"] & 15 == item["rcode"], (item["label"], "rcode", message["flags"] & 15, item["rcode"])
        assert bool(message["flags"] & 0x10) == item["cd"], "client CD restoration"
        assert message["flags"] & 0x20 == 0, "unsigned AD was asserted"
        if item["ptr_targets"] is not None:
            assert message["ptr_case"] == item["ptr_targets"], (item["label"], "PTR case", message["ptr_case"])
        if item["malformed"]:
            assert all(record["section"] == "additional" and record["type"] == 41 for record in message["records"])
            assert ede_codes(message) == item["ede"], (item["label"], "EDE", ede_codes(message), item["ede"])
        if item["shape"] == "cross":
            assert message["records"][0]["malformed_rdata"] and message["records"][0]["data"] == "c0"
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
        parser.error("paired negative requires Rust")
    args.reference_build = args.reference_build.resolve()
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(profiles(), indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-reverse-cache", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native, "tool_sha256": digest(__file__),
              "rust_sha256": None if args.rust is None else digest(args.rust), "profiles": [], "failures": [], "injected_error": args.inject_error}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    expected_profiles = []
    for profile in profiles():
        work = out / profile["label"]
        work.mkdir()
        try:
            expected = run_service(args, c, "C", profile, work / "c")
            calibrate(expected, profile)
            expected_profiles.append((profile, expected, work))
        except Exception as error:
            report["failures"].append({"profile": profile["label"], "stage": "C", "error": repr(error)})
        save()
    if not report["failures"]:
        for index, (profile, expected, work) in enumerate(expected_profiles):
            try:
                differences = []
                if args.rust is not None:
                    actual = run_service(args, args.rust.resolve(), "Rust", profile, work / "rust")
                    if args.inject_error and index == 0:
                        actual[0]["response"]["flags"] ^= 0x20
                    differences = compare(expected, actual)
                report["profiles"].append({"profile": profile["label"], "observations": len(expected), "differences": differences})
            except Exception as error:
                report["failures"].append({"profile": profile["label"], "stage": "Rust", "error": repr(error)})
            save()
    report["c_calibrated"] = sum(len(rows) for _, rows, _ in expected_profiles)
    report["compared"] = 0 if args.rust is None else sum(row["observations"] for row in report["profiles"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    save()
    print(json.dumps({key: value for key, value in report.items() if key != "profiles"}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
