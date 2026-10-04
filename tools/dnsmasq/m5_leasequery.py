#!/usr/bin/env python3
"""Daemon-level DHCPLEASEQUERY differential against the exact image C.

The driver runs inside ``run_isolated.sh``.  A private bridge/veth gives the
relay a real source address and port 67, so the candidate and image C exercise
the same UDP listener, relay route, ACL and reply serializer.  C is the only
oracle; the Rust side is compared to the recorded C packets and normalized
only for wall-clock lease timers.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256
from test_single_poll_service import Network, stop

SERVER = "10.77.0.1"
CLIENT = "10.77.0.2"
RANGE_START = "10.77.0.10"
ACTIVE_MAC = bytes.fromhex("02004d350101")
ACTIVE_CLIENT_ID = bytes(range(1, 201))
ACTIVE_AGENT_ID = bytes([1, 7]) + b"circuit" + bytes([2, 6]) + b"remote" + bytes([6, 10]) + b"subscriber" + bytes([128, 169]) + bytes(range(169))


def save(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def lease_file(expiry: int, vendor: bytes | None = None) -> bytes:
    client_id = ":".join(f"{value:02x}" for value in ACTIVE_CLIENT_ID)
    agent_id = ":".join(f"{value:02x}" for value in ACTIVE_AGENT_ID)
    data = (
        f"{expiry} 01-02:00:4d:35:01:01 {RANGE_START} active {client_id}\n"
        f"agent-info {RANGE_START} {agent_id}\n"
    ).encode()
    if vendor is not None:
        data += f"vendorclass {RANGE_START} ".encode() + b":".join(f"{byte:02x}".encode() for byte in vendor) + b"\n"
    return data


def option(code: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError("DHCP option too long")
    return bytes([code, len(value)]) + value


def request(xid: int, ciaddr: str = "0.0.0.0", giaddr: str = CLIENT,
           prl: bytes | None = None, client_id: bytes | None = None,
           max_size: int | None = None, all_ones_giaddr: bool = False,
           extra: bytes = b"", dirty_header: bool = False) -> bytes:
    packet = bytearray(240)
    packet[:4] = bytes([1, 1, 6, 0])
    packet[4:8] = struct.pack("!I", xid)
    packet[12:16] = socket.inet_aton(ciaddr)
    packet[24:28] = socket.inet_aton("255.255.255.255" if all_ones_giaddr else giaddr)
    packet[28:34] = ACTIVE_MAC
    if dirty_header:
        packet[20:24] = socket.inet_aton("10.77.0.222")
        packet[34:44] = b"QUERY-TAIL"
    packet[236:240] = bytes([99, 130, 83, 99])
    options = option(53, bytes([10]))
    if client_id is not None:
        options += option(61, client_id)
    if prl is not None:
        options += option(55, prl)
    if max_size is not None:
        options += option(57, struct.pack("!H", max_size))
    return bytes(packet) + options + extra + b"\xff"


def decode_options(packet: bytes) -> list[tuple[int, bytes]]:
    """Decode primary/file/sname options, following option 52 overload."""
    if len(packet) < 240 or packet[0] != 2:
        raise AssertionError("not a DHCP reply")
    regions = [packet[240:]]
    overload = None
    position = 0
    while position + 1 < len(regions[0]):
        code = regions[0][position]
        if code == 255:
            break
        if code == 0:
            position += 1
            continue
        length = regions[0][position + 1]
        end = position + 2 + length
        if end > len(regions[0]):
            break
        if code == 52 and length == 1:
            overload = regions[0][position + 2]
        position = end
    if overload is not None:
        if overload & 1:
            regions.append(packet[108:236])
        if overload & 2:
            regions.append(packet[44:108])
    decoded: list[tuple[int, bytes]] = []
    for region in regions:
        position = 0
        while position < len(region):
            code = region[position]
            position += 1
            if code == 255:
                break
            if code == 0:
                continue
            if position >= len(region):
                raise AssertionError("truncated DHCP option")
            length = region[position]
            position += 1
            end = position + length
            if end > len(region):
                raise AssertionError("truncated DHCP option value")
            decoded.append((code, region[position:end]))
            position = end
    return decoded


def semantic(packet: bytes, peer: tuple[str, int] | None = None) -> dict:
    options = decode_options(packet)
    return {
        "len": len(packet),
        "fixed": packet[:240].hex(),
        "status": next((value[0] for code, value in options if code == 53), None),
        "ciaddr": socket.inet_ntoa(packet[12:16]),
        "htype": packet[1],
        "hlen": packet[2],
        "chaddr": packet[28:44].hex(),
        "giaddr": socket.inet_ntoa(packet[24:28]),
        "overload": next((value[0] for code, value in options if code == 52), 0),
        "options": [[code, value.hex()] for code, value in options],
        "peer": list(peer) if peer else None,
    }


def client_mode(args: argparse.Namespace) -> int:
    packet = bytes.fromhex(args.packet)
    result = {"request": args.packet, "reply": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            endpoint.bind((CLIENT, args.source_port))
            endpoint.settimeout(args.timeout)
            endpoint.sendto(packet, (SERVER, 67))
            reply, peer = endpoint.recvfrom(65535)
        result["reply"] = reply.hex()
        result["semantic"] = semantic(reply, peer)
    except socket.timeout:
        result["timeout"] = True
    except Exception as error:  # retain the raw failure in evidence
        result["error"] = repr(error)
    save(args.out, result)
    return 0 if "error" not in result else 1


def run_client(network: Network, packet: bytes, out: Path, timeout: float = 1.0, source_port: int = 67) -> dict:
    save_path = out.with_suffix(".json")
    command_line = network.argv(sys.executable, Path(__file__).resolve(), "--client",
                                "--packet", packet.hex(), "--out", save_path,
                                "--timeout", str(timeout), "--source-port", str(source_port))
    completed = subprocess.run(command_line, capture_output=True, text=True, timeout=4)
    if completed.returncode:
        raise AssertionError(f"relay client failed: {completed.stdout}{completed.stderr}")
    return json.loads(save_path.read_text())


def config(profile: dict) -> str:
    lease_query = profile["acl"]
    lines = [
        "port=0", "no-resolv", "no-hosts", "interface=br-lan",
        "bind-interfaces", "user=root", "group=root", "no-ping",
        "dhcp-range=10.77.0.10,10.77.0.30,255.255.255.0,600s",
        "dhcp-leasefile=/m2/leases", "pid-file=/m2/dnsmasq.pid",
        "log-facility=-",
    ]
    if lease_query is not None:
        lines.append("leasequery" if lease_query == "" else f"leasequery={lease_query}")
    lines.extend(profile.get("config", []))
    if "range" in profile:
        lines = [line for line in lines if not line.startswith("dhcp-range=")]
        lines.extend(profile["range"])
    lines = [f"port={profile.get('dns_port', 0)}" if line.startswith("port=") else line for line in lines]
    if profile.get("ipv4_listener"):
        # Exercise option 6 with an explicit IPv4 listener. Tentative IPv6
        # address admission belongs to the separate listener family.
        lines = [line for line in lines if not line.startswith("interface=")]
        lines.append(f"listen-address={SERVER}")
    return "\n".join(lines) + "\n"


def scenarios() -> list[dict]:
    all_prl = bytes([61, 51, 58, 59, 91, 82])
    network_prl = bytes([1, 3, 6, 12, 15, 28, 43, 60, 66, 67, 121, 122, 123, 124, 125, 126, 127])
    xid = 0
    def query(name, status=13, **kwargs):
        nonlocal xid
        xid += 1
        source_port = kwargs.pop("source_port", 67)
        delay = kwargs.pop("delay", 0)
        kwargs.setdefault("ciaddr", RANGE_START)
        kwargs.setdefault("prl", all_prl)
        return {"name": name, "packet": request(xid, **kwargs), "status": status,
                "source_port": source_port, "delay": delay}
    def profile(name, queries, **kwargs):
        return {"name": name, "acl": "", "queries": queries, **kwargs}
    return [
        profile("disabled", [query("active-disabled", None)], acl=None),
        profile("denied", [query("active-denied", None)], acl="10.77.0.99/32"),
        profile("ipv6-acl", [query("active-ipv6-acl", None)], acl="2001:db8::/64"),
        profile("allowed", [
            query("unknown", 12, ciaddr="10.77.0.99"),
            query("unassigned", 11, ciaddr="10.77.0.20"),
            query("active-address"),
            query("active-identity", ciaddr="0.0.0.0", client_id=ACTIVE_CLIENT_ID),
            query("empty-prl", prl=b""),
            query("timers-only", prl=bytes([51, 58, 59, 91])),
            query("all-options-without-prl", prl=None),
            query("relay-source", all_ones_giaddr=True),
            query("relay-source-port", all_ones_giaddr=True, source_port=1067),
            query("no-relay", None, giaddr="0.0.0.0"),
            query("fixed-header", dirty_header=True),
            query("overload", max_size=300),
        ]),
        profile("acl-prefix", [query("prefix-active")], acl="10.77.0.0/24"),
        profile("acl-route", [query("acl-checks-giaddr", None, giaddr="10.77.0.99"),
                              query("acl-checks-source-sentinel", all_ones_giaddr=True, source_port=1067)], acl=CLIENT),
        profile("defaults", [query("network-and-name", prl=network_prl, max_size=1200)],
                config=["domain=lease.test"]),
        profile("implicit-mask", [query("guessed-mask", prl=network_prl, max_size=1200)],
                range=["dhcp-range=10.77.0.10,10.77.0.30,600s"]),
        profile("remote-context", [query("remote-no-context", 12, prl=network_prl)],
                range=["dhcp-range=192.0.2.10,192.0.2.30,255.255.255.0,600s"]),
        profile("stored-tags", [query("relay-host-context-tags", prl=network_prl + all_prl, max_size=1600),
                                  query("query-agent-not-lease-agent", prl=network_prl, max_size=1200,
                                        extra=option(82, option(1, b"wrong")))],
                vendor=b"stored-vendor",
                range=["dhcp-range=tag:circuit,set:range,10.77.0.10,10.77.0.30,255.255.255.0,600s"],
                config=["dhcp-circuitid=set:circuit,circuit", "dhcp-remoteid=set:remote,remote",
                        "dhcp-subscrid=set:subscriber,subscriber", "tag-if=set:derived,tag:circuit,tag:remote,tag:subscriber",
                        "dhcp-host=02:00:4d:35:01:01,set:host,1200s", "domain=lease.test",
                        "dhcp-option=tag:circuit,121,01:02", "dhcp-option=tag:remote,122,03:04",
                        "dhcp-option=tag:subscriber,123,05:06", "dhcp-option=tag:derived,124,07:08",
                        "dhcp-option=tag:host,126,09:0a", "dhcp-option=tag:range,127,0b:0c"]),
        profile("request-tags", [query("query-class-match-tags", prl=network_prl, max_size=1200,
                                      extra=option(60, b"query-vendor") + option(77, b"\x04user"))],
                config=["dhcp-mac=set:mac,02:00:4d:35:01:01", "dhcp-vendorclass=set:vendor,query-vendor",
                        "dhcp-userclass=set:user,user", "dhcp-match=set:match,option:vendor-class,query-vendor",
                        "dhcp-option=tag:mac,121,01:02", "dhcp-option=tag:vendor,122,03:04",
                        "dhcp-option=tag:user,123,05:06", "dhcp-option=tag:match,124,07:08"]),
        profile("configured", [query("requested-options", prl=network_prl, max_size=1200),
                               query("force-still-needs-prl", prl=b""),
                               query("no-prl-boot-as-options", prl=None, max_size=1200)],
                vendor=b"stored-vendor",
                config=["dhcp-option=1", "dhcp-option=28", "dhcp-option=3,10.77.0.254",
                        "dhcp-option-force=121,01:02", "dhcp-option=66,server", "dhcp-option=67,boot.img",
                        "dhcp-option=vendor:stored-vendor,1,05:06", "dhcp-option=encap:122,1,07:08",
                        "dhcp-option=vi-encap:1234,1,09:0a", "dhcp-option=58,123", "dhcp-option=59,456"]),
        profile("remote-active", [query("remote-active-context", ciaddr="192.0.2.10", all_ones_giaddr=True, prl=network_prl)],
                lease_address="192.0.2.10",
                range=["dhcp-range=192.0.2.10,192.0.2.30,600s"]),
        profile("dns-default", [query("dns-server-default", prl=network_prl)], dns_port=53, ipv4_listener=True),
        profile("packet-expiry", [query("before-expiry"), query("after-expiry", 11, delay=4)], expiry=3),
        profile("capacity", [query("option-overload", prl=all_prl + bytes([244, 245, 246]))],
                config=["dhcp-option=244," + "x" * 120, "dhcp-option=245," + "y" * 120,
                        "dhcp-option=246," + "z" * 30]),
        profile("capacity-no-override", [query("blocked-option-overload", prl=all_prl + bytes([244, 245, 246]))],
                config=["dhcp-no-override", "dhcp-option=244," + "x" * 120,
                        "dhcp-option=245," + "y" * 120, "dhcp-option=246," + "z" * 30]),
        profile("infinite", [query("infinite-lease")], expiry=0),
        profile("expired", [query("expired-unassigned", 11)], expiry=-1),
        profile("older", [query("old-lease-last-transaction")], expiry=60),
        profile("no-dhcp-interface", [query("blocked-interface", None)], config=["no-dhcp-interface=br-lan"]),
        profile("no-override", [query("no-overload", max_size=300)], config=["dhcp-no-override"]),
    ]


def start_side(root: Path, side: str, text: str, leases: bytes, out: Path):
    (root / "m2/config").write_text(text)
    (root / "m2/leases").write_bytes(leases)
    log = (out / "daemon.log").open("wb")
    process = subprocess.Popen(command(root, side, "-k", "-C", "/m2/config"),
                                stdout=log, stderr=log, start_new_session=True)
    time.sleep(.25)
    if process.poll() is not None:
        log.close()
        raise AssertionError(f"{side} exited at startup: {process.returncode}")
    return process, log


def stop_side(process, log):
    row = stop(process)
    log.close()
    return row


def run_profile(root: Path, network: Network, side: str, profile: dict,
                leases: bytes, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    text = config(profile)
    (out / "dnsmasq.conf").write_text(text)
    process = log = None
    row = {"side": side, "profile": profile["name"], "queries": [], "started": False}
    try:
        process, log = start_side(root, side, text, leases, out)
        row["started"] = True
        row["identity"] = process_identity(root, process.pid)
        for index, item in enumerate(profile["queries"]):
            if item["delay"]:
                time.sleep(item["delay"])
            query_out = out / f"query-{index:02d}"
            observed = run_client(network, item["packet"], query_out,
                                   0.6 if item["status"] is None else 1.5, item["source_port"])
            if observed.get("reply"):
                reply = bytes.fromhex(observed["reply"])
                observed["packet"] = reply.hex()
            actual_status = observed.get("semantic", {}).get("status")
            if actual_status != item["status"]:
                observed["status_error"] = f"expected {item['status']}, got {actual_status}"
            row["queries"].append({"name": item["name"], "request": item["packet"].hex(),
                                    "observed": observed})
    except Exception as error:
        row["error"] = repr(error)
    finally:
        if process is not None:
            try:
                row["cleanup"] = stop_side(process, log)
            except Exception as error:
                row["cleanup"] = {"error": repr(error)}
    save(out / "result.json", row)
    return row


def timer_value(rows: list[list], code: int) -> int | None:
    values = [bytes.fromhex(value) for option_code, value in rows if option_code == code]
    if not values:
        return None
    if len(values[0]) != 4:
        raise AssertionError(f"timer {code} has invalid length")
    return struct.unpack("!I", values[0])[0]


def normalized_wire(encoded: str) -> bytes:
    packet = bytearray.fromhex(encoded)
    overload = next((value[0] for code, value in decode_options(packet) if code == 52), 0)
    regions = [(240, len(packet))]
    if overload & 1:
        regions.append((108, 236))
    if overload & 2:
        regions.append((44, 108))
    for position, end in regions:
        while position < end:
            code = packet[position]
            if code == 255:
                break
            if code == 0:
                position += 1
                continue
            length = packet[position + 1]
            if code in (51, 58, 59, 91) and length == 4:
                packet[position + 2:position + 6] = bytes(4)
            position += length + 2
    return bytes(packet)


def compare(c: dict, rust: dict) -> list[str]:
    errors = []
    if c.get("error") or rust.get("error"):
        return ["profile execution failure"]
    c_by_name = {row["name"]: row["observed"] for row in c["queries"]}
    r_by_name = {row["name"]: row["observed"] for row in rust["queries"]}
    if set(c_by_name) != set(r_by_name):
        return ["query set differs"]
    for name in sorted(c_by_name):
        left, right = c_by_name[name], r_by_name[name]
        if left.get("status_error") or right.get("status_error"):
            errors.append(f"{name}: fixture status guard: C={left.get('status_error')}, Rust={right.get('status_error')}")
        if bool(left.get("reply")) != bool(right.get("reply")):
            errors.append(f"{name}: reply presence differs")
            continue
        if not left.get("reply"):
            continue
        if normalized_wire(left["reply"]) != normalized_wire(right["reply"]):
            errors.append(f"{name}: wire bytes differ after timer-only normalization")
        c_sem, r_sem = left["semantic"], right["semantic"]
        for field in ("len", "fixed", "ciaddr", "htype", "hlen", "chaddr", "giaddr", "overload", "peer"):
            if c_sem[field] != r_sem[field]:
                errors.append(f"{name}: {field} differs ({c_sem[field]!r} != {r_sem[field]!r})")
        c_opts, r_opts = c_sem["options"], r_sem["options"]
        if [(code, value) for code, value in c_opts if code not in (51, 58, 59, 91)] != \
                [(code, value) for code, value in r_opts if code not in (51, 58, 59, 91)]:
            errors.append(f"{name}: non-timer options differ")
        for code in (51, 58, 59, 91):
            c_value, r_value = timer_value(c_opts, code), timer_value(r_opts, code)
            if (c_value is None) != (r_value is None) or (c_value is not None and abs(c_value - r_value) > 2):
                errors.append(f"{name}: timer {code} differs ({c_value!r} != {r_value!r})")
        if c_sem["peer"] and r_sem["peer"] and c_sem["peer"][0] != r_sem["peer"][0]:
            errors.append(f"{name}: relay peer differs")
    return errors


def cleanup_errors(cleanup, label: str, returncodes: tuple[int, ...]) -> list[str]:
    if not isinstance(cleanup, dict):
        return [f"{label}: cleanup evidence missing"]
    if cleanup.get("error") or cleanup.get("forced") is not False or cleanup.get("returncode") not in returncodes:
        return [f"{label}: cleanup failed"]
    return []


def evaluate(rows: list[dict], profiles: list[dict], network_cleanup) -> list[str]:
    """Validate coverage and execution before comparing any C/Rust packets."""
    failures = cleanup_errors(network_cleanup, "network", (0, -15))
    expected = {(profile["name"], side) for profile in profiles for side in ("c", "rust")}
    actual = [(row.get("profile"), row.get("side")) for row in rows]
    if not profiles:
        failures.append("no selected profiles")
    if len(actual) != len(set(actual)) or set(actual) != expected:
        failures.append("profile/side coverage differs from selected fixtures")
    by_key = {(row.get("profile"), row.get("side")): row for row in rows}
    for profile in profiles:
        expected_queries = {item["name"]: item for item in profile["queries"]}
        valid_sides = True
        for side in ("c", "rust"):
            label = f"{profile['name']}/{side}"
            row = by_key.get((profile["name"], side))
            if row is None:
                valid_sides = False
                continue
            if row.get("error") or row.get("started") is not True or not row.get("identity"):
                failures.append(f"{label}: side execution failed or identity missing")
                valid_sides = False
            failures.extend(cleanup_errors(row.get("cleanup"), label, (0,)))
            queries = row.get("queries", [])
            names = [query.get("name") for query in queries]
            if len(names) != len(set(names)) or set(names) != set(expected_queries):
                failures.append(f"{label}: query coverage differs from selected fixtures")
                valid_sides = False
            for query in queries:
                name = query.get("name")
                if name not in expected_queries:
                    continue
                item = expected_queries[name]
                observed = query.get("observed", {})
                if observed.get("error") or not observed:
                    failures.append(f"{label}/{name}: query execution failed")
                    valid_sides = False
                    continue
                expected_request = item["packet"].hex()
                if query.get("request") != expected_request or observed.get("request") != expected_request:
                    failures.append(f"{label}/{name}: request differs from fixture")
                try:
                    if observed.get("reply"):
                        encoded = bytes.fromhex(observed["reply"])
                        peer = observed.get("semantic", {}).get("peer")
                        if not isinstance(peer, list) or len(peer) != 2:
                            raise ValueError("missing UDP peer")
                        actual_semantic = semantic(encoded, tuple(peer))
                        if actual_semantic != observed.get("semantic"):
                            failures.append(f"{label}/{name}: decoded observation differs from raw reply")
                        if actual_semantic["status"] != item["status"]:
                            failures.append(f"{label}/{name}: raw response status differs from fixture")
                        if observed.get("timeout"):
                            failures.append(f"{label}/{name}: contradictory reply and timeout")
                    elif item["status"] is not None or observed.get("timeout") is not True:
                        failures.append(f"{label}/{name}: missing expected response or timeout evidence")
                except (ValueError, KeyError, TypeError, IndexError, AssertionError) as error:
                    failures.append(f"{label}/{name}: malformed response evidence: {error}")
                    valid_sides = False
        if valid_sides:
            try:
                errors = compare(by_key[(profile["name"], "c")], by_key[(profile["name"], "rust")])
                failures.extend(f"{profile['name']}: {error}" for error in errors)
            except (ValueError, KeyError, TypeError, IndexError, AssertionError) as error:
                failures.append(f"{profile['name']}: malformed paired evidence: {error}")
    return failures


def negative_controls(rows: list[dict], profiles: list[dict], network_cleanup) -> dict:
    """Reject deliberately corrupted copies through the real result evaluator."""
    baseline_errors = evaluate(rows, profiles, network_cleanup)
    if baseline_errors:
        return {"passed": False, "baseline_accepted": False,
                "baseline_errors": baseline_errors, "controls": []}
    active = next(((index, query_index) for index, row in enumerate(rows)
                   if row["side"] == "rust"
                   for query_index, query in enumerate(row["queries"])
                   if query["observed"].get("semantic", {}).get("status") == 13
                   and {51, 61}.issubset({code for code, _ in query["observed"]["semantic"]["options"]})), None)
    if active is None:
        return {"passed": False, "baseline_accepted": True,
                "error": "negative controls require an observed ACTIVE reply with client ID and lease timer", "controls": []}
    active_index, active_query = active
    controls = []

    def check(name, mutate):
        altered, cleanup = copy.deepcopy(rows), copy.deepcopy(network_cleanup)
        mutate(altered, cleanup)
        errors = evaluate(altered, profiles, cleanup)
        controls.append({"name": name, "detected": bool(errors), "failures": errors})

    def set_value(mapping, key, value):
        mapping[key] = value

    def observation(altered):
        return altered[active_index]["queries"][active_query]["observed"]

    def flip_option(altered, code):
        observed = observation(altered)
        packet = bytearray.fromhex(observed["reply"])
        position = 240
        while position + 2 < len(packet) and packet[position] != 255:
            if packet[position] == 0:
                position += 1
                continue
            length = packet[position + 1]
            if packet[position] == code and length:
                packet[position + 2] ^= 1
                observed["reply"] = packet.hex()
                observed["semantic"] = semantic(packet, tuple(observed["semantic"]["peer"]))
                return
            position += length + 2
        raise AssertionError(f"negative control option {code} missing in ACTIVE fixture")

    check("response-status", lambda altered, _: flip_option(altered, 53))
    check("response-client-id-option", lambda altered, _: flip_option(altered, 61))
    check("response-timer", lambda altered, _: flip_option(altered, 51))
    check("response-peer-port", lambda altered, _: set_value(observation(altered)["semantic"]["peer"], 1, 9999))
    check("missing-query", lambda altered, _: altered[active_index]["queries"].pop(active_query))
    check("failed-side", lambda altered, _: set_value(altered[active_index], "error", "injected failure"))
    check("side-not-started", lambda altered, _: set_value(altered[active_index], "started", False))
    check("missing-side", lambda altered, _: altered.pop(active_index))
    check("duplicate-side", lambda altered, _: altered.append(copy.deepcopy(altered[active_index])))
    profile_name = rows[active_index]["profile"]
    query_name = rows[active_index]["queries"][active_query]["name"]

    def omit_profile(altered, _):
        altered[:] = [row for row in altered if row["profile"] != profile_name]

    def omit_query_both(altered, _):
        for row in altered:
            if row["profile"] == profile_name:
                row["queries"] = [query for query in row["queries"] if query["name"] != query_name]

    check("missing-entire-profile", omit_profile)
    check("missing-query-both-sides", omit_query_both)
    check("daemon-cleanup-forced", lambda altered, _: set_value(altered[active_index]["cleanup"], "forced", True))
    check("daemon-cleanup-bad-exit", lambda altered, _: set_value(altered[active_index]["cleanup"], "returncode", 2))
    check("daemon-cleanup-missing", lambda altered, _: altered[active_index].pop("cleanup"))
    check("network-cleanup-forced", lambda _, cleanup: set_value(cleanup, "forced", True))
    check("network-cleanup-bad-exit", lambda _, cleanup: set_value(cleanup, "returncode", 2))
    check("network-cleanup-error", lambda _, cleanup: set_value(cleanup, "error", "injected cleanup failure"))
    check("network-cleanup-missing", lambda _, cleanup: cleanup.clear())
    return {"passed": all(control["detected"] for control in controls),
            "baseline_accepted": True, "count": len(controls), "controls": controls}


def close_network(network: Network) -> dict:
    result = stop(network.client)
    for link in reversed(network.links):
        deleted = subprocess.run(["ip", "link", "delete", link], capture_output=True, timeout=3)
        if deleted.returncode:
            # Namespace teardown may delete the veth between presence and
            # deletion checks. Verify absence instead of masking other errors.
            present = subprocess.run(["ip", "link", "show", link], capture_output=True, timeout=3)
            if present.returncode == 0:
                raise AssertionError(f"network cleanup failed: {deleted.stderr!r}")
    return result


def main(args: argparse.Namespace) -> int:
    if os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        raise SystemExit("run through tools/dnsmasq/run_isolated.sh as root")
    if sorted(name for _, name in socket.if_nameindex()) != ["lo"]:
        raise SystemExit("outer isolated namespace must contain only lo")
    out = args.out.resolve()
    if out.exists() or "private" not in out.parts:
        raise SystemExit("--out must be a fresh path below private/")
    out.mkdir(parents=True)
    root = prepare(args.image_root, None, out, args.rust)
    network = Network()
    expiry = int(time.time()) + 600
    leases = lease_file(expiry)
    (out / "lease-input").write_bytes(leases)
    rows = []
    profiles = [profile for profile in scenarios() if not args.profile or profile["name"] in args.profile]
    run_errors = []
    try:
        network.start()
        for profile in profiles:
            for side in (("c", "rust") if args.side == "both" else (args.side,)):
                duration = profile.get("expiry", 540)
                profile_leases = lease_file(0 if duration == 0 else int(time.time()) + duration, profile.get("vendor"))
                profile_leases = profile_leases.replace(RANGE_START.encode(), profile.get("lease_address", RANGE_START).encode())
                rows.append(run_profile(root, network, side, profile, profile_leases,
                                        out / f"{profile['name']}-{side}"))
    except Exception as error:
        run_errors.append(f"run execution failure: {error!r}")
    finally:
        try:
            network_cleanup = close_network(network)
        except Exception as error:
            network_cleanup = {"error": repr(error)}
    failures = run_errors + evaluate(rows, profiles, network_cleanup)
    controls = negative_controls(rows, profiles, network_cleanup)
    if not controls["passed"]:
        failures.append("comparator negative controls did not all pass")
    result = {
        "passed": not failures,
        "network_cleanup": network_cleanup,
        "negative_controls": controls,
        "comparison_executed": args.side == "both",
        "failures": failures,
        "profiles": rows,
        "c_sha256": STOCK_SHA256,
        "rust_sha256": sha256(args.rust),
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "query_count": sum(len(profile["queries"]) for profile in profiles),
        "profile_count": len(profiles),
        "scope": "DHCPLEASEQUERY daemon image-C differential: admission/ACL/source route and port, unknown/unassigned/active, expired/infinite leases, host/range and stored relay tags, configured/default options, stored vendor-class, PRL timers, agent-id and overload",
    }
    save(out / "summary.json", result)
    print(json.dumps({key: result[key] for key in ("passed", "failures", "comparison_executed")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-root", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--side", choices=("both", "c", "rust"), default="both")
    parser.add_argument("--client", action="store_true")
    parser.add_argument("--packet")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--source-port", type=int, default=67)
    parser.add_argument("--profile", action="append")
    parser.add_argument("--out-file", dest="client_out", type=Path)
    parser_args = parser.parse_args()
    if parser_args.client:
        # Network.argv uses --out for the per-query JSON.  Keep this path
        # separate from the top-level evidence argument.
        if parser_args.packet is None or parser_args.out is None:
            parser.error("--client requires --packet and --out")
        raise SystemExit(client_mode(parser_args))
    if parser_args.image_root is None or parser_args.rust is None:
        parser.error("daemon mode requires --image-root and --rust")
    raise SystemExit(main(parser_args))
