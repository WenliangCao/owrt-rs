#!/usr/bin/env python3
"""Ordinary static DHCP hosts against the exact native C daemon in isolation.

Compare wire semantics and committed lease rows after every event. C runs first;
Rust is never used to generate expected responses. Random renewal timers retain
their range/difference checks, and expiry is normalized only to the send time.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import time

from dhcp_lease_lifecycle import Daemon, rows
from dhcp_daemon_smoke import decode

# Event/response counts frozen from lifecycle-c-baseline-01, before the paired
# run. Missing packets, omitted scenarios or a shortened result must fail.
C_COUNTS = {
    "names": (14, 13), "client-id": (5, 4), "handover": (4, 4),
    "ignore-id": (4, 3), "reserved-ignore": (4, 2), "decline": (3, 2),
    "occupied": (2, 2), "restore": (1, 1), "bootp": (1, 1),
    "dynamic-names": (4, 4),
}


def packet(event, xid):
    kind = event.get("kind", 1)
    value = bytearray(240)
    value[:3] = bytes([1, 1, 6])
    value[4:8] = struct.pack("!I", xid)
    value[10:12] = b"\x80\0"
    value[28:34] = bytes([2, 0, 0, 0, 0, event.get("client", 1)])
    value[236:240] = bytes([99, 130, 83, 99])
    options = bytearray()
    if kind:
        options += bytes([53, 1, kind])
    if event.get("prl", "default") != "none":
        requested = event.get("prl", [1, 3, 6, 12, 15, 51, 58, 59])
        options += bytes([55, len(requested), *requested])
    if "address" in event:
        address = socket.inet_aton(event["address"])
        if kind in (1, 4) or event.get("selecting"):
            options += bytes([50, 4]) + address
        else:
            value[12:16] = address
    if event.get("selecting") or kind in (4, 7):
        options += bytes([54, 4]) + socket.inet_aton("127.0.0.1")
    for key, code in [("name", 12), ("clid", 61), ("fqdn", 81)]:
        if key in event:
            data = bytes.fromhex(event[key])
            options += bytes([code, len(data)]) + data
    return bytes(value + options + b"\xff")


def event(label, kind=1, **kwargs):
    return {"label": label, "kind": kind, **kwargs}


def fixtures():
    mac = "02:00:00:00:00:"
    host = lambda client, tail: f"dhcp-host={mac}{client:02x},{tail}\n"
    text = lambda value: value.encode().hex()
    fixed = host(1, "127.0.0.40,FiXeD.config.invalid,900")
    request = lambda label, **kw: event(label, 3, address="127.0.0.40", selecting=True, **kw)
    yield "names", fixed, b"", [
        event("offer-conflicting-name", name=text("client")), request("ack-configured", name=text("client")),
        event("offer-matching-case", name=text("fIxEd")),
        event("offer-full-client-name", name=text("fixed.client.invalid")),
        event("offer-no-client-name"),
        request("ack-no-prl", prl="none"),
        request("ack-excluded-name", prl=[1, 51, 58, 59]),
        request("ack-broken-string", name=text("client\0")),
        request("ack-fqdn-ascii", fqdn=(b"\0\0\0guest.client.invalid").hex()),
        event("offer-fqdn-ascii", fqdn=(b"\x09\0\0guest").hex()),
        request("ack-fqdn-encoded", fqdn=(b"\x04\0\0\x05guest\x06client\0").hex()),
        request("ack-fqdn-broken", fqdn=(b"\0\0\0guest\0").hex()),
        request("ack-fqdn-not-in-prl", prl=[], fqdn=(b"\x05\0\0\x05guest\0").hex()),
        event("release", 7, address="127.0.0.40"),
    ]
    yield "client-id", host(2, "127.0.0.42,mac,1800") + "dhcp-host=id:client,127.0.0.41,clid,1200\n", b"", [
        event("id-before-mac", client=2, clid=text("client")),
        event("id-ack", 3, client=2, clid=text("client"), address="127.0.0.41", selecting=True),
        event("id-reuse-when-absent", client=2),
        event("id-release", 7, client=2, clid=text("client"), address="127.0.0.41"),
        event("zero-prefixed-id", client=2, clid=text("\0client")),
    ]
    yield "handover", host(4, f"{mac}05,127.0.0.44,shared,infinite"), b"", [
        event("first-offer", client=4), event("first-ack", 3, client=4, address="127.0.0.44", selecting=True),
        event("second-offer", client=5), event("second-ack", 3, client=5, address="127.0.0.44", selecting=True),
    ]
    yield "ignore-id", host(6, "id:*,127.0.0.45,noclid,600"), b"", [
        event("first-ack", 3, client=6, clid=text("first"), address="127.0.0.45", selecting=True),
        event("new-id-offer", client=6, clid=text("second")),
        event("new-id-ack", 3, client=6, clid=text("second"), address="127.0.0.45", selecting=True),
        event("new-id-release", 7, client=6, clid=text("second"), address="127.0.0.45"),
    ]
    yield "reserved-ignore", host(7, "127.0.0.14,reserved") + host(3, "127.0.0.43,ignore"), b"", [
        event("reserved-offer", client=9, address="127.0.0.14"),
        event("reserved-nak", 3, client=9, address="127.0.0.14", selecting=True),
        event("ignored-discover", client=3), event("ignored-request", 3, client=3, address="127.0.0.43", selecting=True),
    ]
    yield "decline", fixed, b"", [request("static-ack"), event("decline", 4, address="127.0.0.40"), event("backoff-offer")]
    yield "occupied", fixed, b"0 02:00:00:00:00:08 127.0.0.40 occupant *\n", [
        event("occupied-offer"), request("occupied-nak"),
    ]
    yield "restore", fixed, b"0 02:00:00:00:00:01 127.0.0.40 stale *\n", [event("restored-offer")]
    yield "bootp", fixed, b"", [event("static-bootp", 0)]
    yield "dynamic-names", "", b"", [
        event("offer-client-name", address="127.0.0.10", name=text("dynamic")),
        event("ack-client-name", 3, address="127.0.0.10", selecting=True, name=text("dynamic")),
        event("renew-no-name", 3, address="127.0.0.10"),
        event("inform-by-address", 8, client=9, address="127.0.0.10"),
    ]


def normalized_rows(path, sent):
    result = rows(path)
    for row in result:
        if row["expiry"]:
            row["remaining"] = row.pop("expiry") - int(sent)
    return result


def exchange(daemon, item):
    daemon.xid += 1
    sent = time.time()
    request = packet(item, daemon.xid)
    daemon.socket.sendto(request, ("255.255.255.255", 67))
    daemon.socket.settimeout(.5)
    try:
        response = daemon.socket.recv(4096)
    except socket.timeout:
        response = None
    folder = daemon.folder
    (folder / f"{daemon.xid:03}-{item['label']}.request").write_bytes(request)
    if response:
        (folder / f"{daemon.xid:03}-{item['label']}.response").write_bytes(response)
        options = decode(response, daemon.xid)
        daemon.check(item["label"] + "-transaction", response[4:8].hex(), request[4:8].hex())
        semantic = {"header": (response[:4] + response[8:44]).hex(),
                    "boot_fields": response[44:236].hex(),
                    "options": {str(code): value.hex() for code, value in options.items()}}
        if item["kind"] == 3 and not item.get("selecting") and 58 in options and 59 in options:
            lifetime = struct.unpack("!I", options[51])[0]
            t1 = struct.unpack("!I", options[58])[0]
            t2 = struct.unpack("!I", options[59])[0]
            daemon.check(item["label"] + "-renewal-fuzz", 0 <= lifetime // 2 - t1 <= lifetime // 16, True)
            daemon.check(item["label"] + "-renewal-difference", t2 - t1, lifetime * 7 // 8 - lifetime // 2)
            semantic["options"].pop("58"); semantic["options"].pop("59")
    else:
        semantic = None
    database = normalized_rows(daemon.leasefile, sent)
    (folder / f"{daemon.xid:03}-{item['label']}.leases").write_bytes(daemon.leasefile.read_bytes())
    return {"label": item["label"], "response": semantic, "leases": database}


def equivalent(actual, expected):
    if actual["label"] != expected["label"] or actual["response"] != expected["response"]:
        return False
    if len(actual["leases"]) != len(expected["leases"]):
        return False
    for a, b in zip(actual["leases"], expected["leases"]):
        a = dict(a); b = dict(b)
        ar = a.pop("remaining", None); br = b.pop("remaining", None)
        if a != b or (ar is None) != (br is None) or (ar is not None and abs(ar - br) > 1):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-reference", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--scenario", action="append", choices=C_COUNTS)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    if args.inject_error and args.scenario and "names" not in args.scenario:
        parser.error("--inject-error requires the names scenario")
    assert os.uname().sysname == "Linux" and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert not Path("/etc/openwrt_release").exists(), "build host only"
    assert hashlib.sha256(args.c_reference.read_bytes()).hexdigest() == args.c_sha256
    out = args.out.resolve(); assert "private" in out.parts; out.mkdir(parents=True, exist_ok=False)
    checks = []; runs = []
    sample = {"label": "calibration", "response": {"options": {"12": "6669786564"}}, "leases": []}
    assert equivalent(sample, sample)
    assert not equivalent({**sample, "response": None}, sample)
    assert not equivalent({**sample, "leases": [{"expiry": 0}]}, sample)
    assert not equivalent({**sample, "response": {"options": {"12": "77726f6e67"}}}, sample)
    failure = None
    try:
        for scenario, hosts, initial, events in fixtures():
            if args.scenario and scenario not in args.scenario: continue
            folder = out / scenario; folder.mkdir()
            leasefile = folder / "leases"; config = folder / "dnsmasq.conf"
            config.write_text("no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport=15353\nno-ping\ndhcp-authoritative\n"
                "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
                "domain=global.test\ndomain=pool.test,127.0.0.40,127.0.0.45\n"
                f"dhcp-leasefile={leasefile}\n" + hosts)
            observed = {}
            binaries = [("c", args.c_reference)] + ([("rust", args.rust)] if args.rust else [])
            for implementation, binary in binaries:
                child = folder / implementation; child.mkdir(); leasefile.write_bytes(initial)
                (child / "initial.leases").write_bytes(initial)
                daemon = Daemon(binary.resolve(), config, leasefile, child, checks, implementation + "-" + scenario)
                try:
                    daemon.start()
                    values = [{"label": "startup", "response": None, "leases": normalized_rows(leasefile, time.time())}]
                    for item in events: values.append(exchange(daemon, item))
                    observed[implementation] = values
                    expected_events, expected_responses = C_COUNTS[scenario]
                    daemon.check("event-count", len(values) - 1, expected_events)
                    daemon.check("response-count", sum(value["response"] is not None for value in values), expected_responses)
                finally:
                    daemon.stop()
            if args.rust:
                if args.inject_error and scenario == "names":
                    observed["rust"][2]["response"]["options"]["12"] = b"wrong".hex()
                for c, rust in zip(observed["c"], observed["rust"]):
                    checks.append({"case": scenario + "-" + c["label"], "pass": equivalent(rust, c), "c": c, "rust": rust})
            runs.append({"scenario": scenario, "observed": observed})
    except Exception as error:
        failure = repr(error)
    failures = [check for check in checks if not check["pass"]]
    result = {"passed": sum(check["pass"] for check in checks), "failed": len(failures), "error": failure,
              "checks": checks, "runs": runs, "failures": failures, "full_functional_equivalence": False,
              "scope": "ordinary static selectors, address reservation/occupancy/handover, configured/client name wire and leasefile semantics",
              "c_sha256": args.c_sha256, "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest() if args.rust else None}
    result["scenarios_expected"] = len(set(args.scenario or C_COUNTS))
    result["scenarios_completed"] = len(runs)
    if result["scenarios_completed"] != result["scenarios_expected"] and failure is None:
        result["error"] = "incomplete scenario coverage"
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("checks", "runs")}, indent=2))
    return int(bool(failures) or result["error"] is not None)


if __name__ == "__main__":
    raise SystemExit(main())
