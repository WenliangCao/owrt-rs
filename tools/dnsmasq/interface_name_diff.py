#!/usr/bin/env python3
"""C-first interface-name syntax and namespace UDP/TCP snapshot contract."""
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

from dns_do_cache_diff import request
from dns_reverse_cache_diff import decode
from dns_service_probe import read_name
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest, receive_exact

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)
ADDED = "192.0.2.77"
FIRST = "first.interface.test"
SNAPSHOT = "snapshot.interface.test"


def config_cases():
    return [{"label": label, "argument": argument, "accepted": accepted} for label, argument, accepted in [
        ("plain", "node.interface.test,lo", True),
        ("ipv4", "node.interface.test,lo/4", True),
        ("ipv6", "node.interface.test,lo/6", True),
        ("mixed-name", "MiXeD.Interface.Test,lo", True),
        ("repeat-name", "node.interface.test,lo/4\ninterface-name=node.interface.test,lo/6", True),
        ("missing-interface", "node.interface.test,missing0", True),
        ("no-interface", "node.interface.test", False),
        ("empty-name", ",lo", True),
        ("empty-interface", "node.interface.test,", False),
        ("bad-family", "node.interface.test,lo/5", False),
        ("bad-name", "bad..interface.test,lo", False),
        ("prototype", "node.interface.test,192.0.2.1,lo", False),
    ]]


def query(label, host, kind=1, values=None, local=True, tcp=None):
    return {"op": "query", "label": label, "host": host, "kind": kind,
            "values": values or [], "local": local, "tcp": tcp}


def reverse(address):
    return ipaddress.ip_address(address).reverse_pointer


def profiles():
    static = [query("first-a", FIRST, values=["127.0.0.1"]),
              query("first-aaaa", FIRST, 28, ["::1"]), query("first-any", FIRST, 255, ["127.0.0.1", "::1"]),
              query("second-a", "second.interface.test", values=["127.0.0.1"]),
              query("v4-a", "v4.interface.test", values=["127.0.0.1"]),
              query("v4-aaaa", "v4.interface.test", 28, local=False),
              query("v6-a", "v6.interface.test", local=False),
              query("v6-aaaa", "v6.interface.test", 28, ["::1"]),
              query("joined-any", "joined.interface.test", 255, ["127.0.0.1", "::1"]),
              query("v4-first-ptr", reverse("127.0.0.1"), 12, [FIRST]),
              query("v6-first-ptr", reverse("::1"), 12, [FIRST]),
              query("missing-a", "absent.interface.test", local=False),
              query("missing-child-txt", "child.absent.interface.test", 16, local=False),
              query("cname-terminal", "alias.interface.test", values=["127.0.0.1"])]
    snapshot = [query("initial-udp", SNAPSHOT, values=["127.0.0.1"]),
                query("initial-tcp0", SNAPSHOT, values=["127.0.0.1"], tcp="tcp0"),
                {"op": "address", "label": "add-loopback-alias", "present": True},
                query("added-udp-a", SNAPSHOT, values=["127.0.0.1", ADDED]),
                query("added-udp-ptr", reverse(ADDED), 12, [SNAPSHOT]),
                query("added-old-tcp0", SNAPSHOT, values=["127.0.0.1"], tcp="tcp0"),
                query("added-new-tcp1", SNAPSHOT, values=["127.0.0.1", ADDED], tcp="tcp1"),
                {"op": "address", "label": "delete-loopback-alias", "present": False},
                query("deleted-udp-a", SNAPSHOT, values=["127.0.0.1"]),
                query("deleted-udp-ptr", reverse(ADDED), 12, local=False),
                query("deleted-old-tcp0", SNAPSHOT, values=["127.0.0.1"], tcp="tcp0"),
                query("deleted-held-tcp1", SNAPSHOT, values=["127.0.0.1", ADDED], tcp="tcp1"),
                query("deleted-new-tcp2", SNAPSHOT, values=["127.0.0.1"], tcp="tcp2")]
    result = [{"label": "families-and-priority", "actions": static}, {"label": "accepted-tcp-snapshot", "actions": snapshot}]
    assert sum(item["op"] == "query" for case in result for item in case["actions"]) == 25
    return result


def stamp():
    return {"monotonic": time.monotonic(), "wall": time.time()}


def interface_state(out, label):
    command = ["ip", "-j", "address", "show", "dev", "lo"]
    result = subprocess.run(command, capture_output=True, text=True)
    (out / (label + "-interface.json")).write_text(json.dumps({"command": command, "exit": result.returncode,
                                                              "stdout": result.stdout, "stderr": result.stderr,
                                                              "when": stamp()}, indent=2) + "\n")
    result.check_returncode()
    state = json.loads(result.stdout)
    assert len(state) == 1 and state[0]["ifname"] == "lo"
    addresses = [address["local"] for address in state[0]["addr_info"]]
    assert "127.0.0.1" in addresses and "::1" in addresses, "loopback address precondition"
    ipv6 = next(address for address in state[0]["addr_info"] if address["local"] == "::1")
    assert ipv6.get("valid_life_time") == 4294967295 and ipv6.get("preferred_life_time") == 4294967295
    assert not any(flag in ipv6.get("flags", []) for flag in ("temporary", "tentative", "deprecated"))
    return state, addresses


def nx_reply(packet):
    _, end = read_name(packet, 12)
    opt = any(record["type"] == 41 for record in decode(packet)["records"])
    answer = packet[:2] + struct.pack("!5H", 0x8183, 1, 0, 0, int(opt)) + packet[12:end + 4]
    if opt:
        answer += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return answer


def run_config(binary, case, out):
    out.mkdir()
    config = out / "dnsmasq.conf"
    config.write_text("no-hosts\nno-resolv\ninterface-name=" + case["argument"] + "\n")
    result = subprocess.run([str(binary), "--test", "-C", str(config)], capture_output=True, text=True, timeout=3)
    (out / "result.json").write_text(json.dumps({"exit": result.returncode, "stdout": result.stdout,
                                                "stderr": result.stderr}, indent=2) + "\n")
    return {"label": case["label"], "accepted": result.returncode == 0}


def run_service(args, binary, side, profile, out):
    out.mkdir()
    initial, addresses = interface_state(out, "initial")
    assert ADDED not in addresses
    fixture = Fixture(args, out)
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    rows, wires, events, connections, accepted = [], [], [], {}, {}
    alias_present = False
    config = out / "dnsmasq.conf"
    extra = (f"interface-name={FIRST},lo\ninterface-name=second.interface.test,lo\n"
             "interface-name=v4.interface.test,lo/4\ninterface-name=v6.interface.test,lo/6\n"
             "interface-name=joined.interface.test,lo/4\ninterface-name=joined.interface.test,lo/6\n"
             "interface-name=absent.interface.test,missing0\n"
             f"ptr-record={reverse('127.0.0.1')},explicit.interface.test\ncname=alias.interface.test,{FIRST}\n"
             if profile["label"] == "families-and-priority" else f"interface-name={SNAPSHOT},lo\n")
    config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                      "local-ttl=17\nno-negcache\nno-0x20-encode\nno-round-robin\n"
                      "host-record=ready.test,192.0.2.41\n"
                      + f"server=127.0.0.1#{upstream.getsockname()[1]}\nenable-ubus={OBJECT}\n" + extra)

    def wait_connections(expected):
        deadline = time.monotonic() + 3
        while True:
            metrics = fixture.metrics()
            if metrics["tcp_connections"] == expected:
                return metrics
            assert fixture.daemon.poll() is None and time.monotonic() < deadline, ("tcp_connections", expected, metrics)
            time.sleep(.005)

    def exchange(label, packet, tcp=None):
        observed, raw = [], []
        if tcp is not None and tcp not in connections:
            lower = stamp()
            connection = socket.create_connection(LISTEN, 3)
            connection.settimeout(3)
            connections[tcp] = connection
            connected = stamp()
            metrics = wait_connections(len(connections))
            accepted[tcp] = {"connect_start": lower, "connect_complete": connected,
                             "accepted_metric_observed": stamp(), "metrics": metrics}
        sent_at = stamp()
        if tcp is None:
            client.sendto(packet, LISTEN)
            deadline = time.monotonic() + 3
            while True:
                ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
                assert ready, (label, "UDP timeout")
                if upstream in ready:
                    query_packet, peer = upstream.recvfrom(65535)
                    decoded = decode(query_packet)
                    decoded["id"] = 0
                    observed.append(decoded)
                    answer = nx_reply(query_packet)
                    raw.append({"request": query_packet.hex(), "response": answer.hex(), "peer": peer})
                    upstream.sendto(answer, peer)
                if client in ready:
                    reply = client.recv(65535)
                    break
        else:
            connection = connections[tcp]
            connection.sendall(struct.pack("!H", len(packet)) + packet)
            reply = receive_exact(connection, struct.unpack("!H", receive_exact(connection, 2))[0])
        received_at = stamp()
        assert reply[:2] == packet[:2], "recipient ID changed"
        assert not select.select([client, upstream], [], [], .01)[0], "extra UDP datagram"
        if tcp is not None and "first_query_sent" not in accepted[tcp]:
            accepted[tcp].update(first_query_sent=sent_at, first_reply_received=received_at)
        wires.append({"label": label, "tcp": tcp, "request": packet.hex(), "response": reply.hex(),
                      "upstream": raw, "sent": sent_at, "received": received_at})
        return {"response": decode(reply), "question": reply[12:read_name(reply, 12)[1] + 4].hex(),
                "upstream": observed, "local": not observed, "transport": "tcp" if tcp else "udp"}

    try:
        fixture.start_bus()
        command = [str(binary), "-k", "-C", str(config)]
        if side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        ready = exchange("ready", request("ready.test", 1, 0x3000, opt=False))
        assert ready["local"] and ready["response"]["records"][0]["data"] == ipaddress.ip_address("192.0.2.41").packed.hex()
        assert fixture.metrics()["tcp_connections"] == 0
        for action in profile["actions"]:
            if action["op"] == "address":
                before = stamp()
                command = ["ip", "address", "add" if action["present"] else "del", ADDED + "/32", "dev", "lo"]
                result = subprocess.run(command, capture_output=True, text=True)
                assert result.returncode == 0, (command, result.stdout, result.stderr)
                alias_present = action["present"]
                state, addresses = interface_state(out, action["label"])
                assert (ADDED in addresses) == action["present"]
                barrier = exchange(action["label"] + "-parent-barrier", request("ready.test", 1, 0x3100 + len(events), opt=False))
                assert barrier["local"]
                metrics = fixture.metrics()
                events.append({**action, "command": command, "exit": result.returncode,
                               "stdout": result.stdout, "stderr": result.stderr, "before": before,
                               "verified_and_barrier_complete": stamp(), "state": state, "barrier": barrier, "metrics": metrics})
                continue
            packet = request(action["host"], action["kind"], 0x4100 + len(rows), opt=False)
            row = {"label": action["label"], **exchange(action["label"], packet, action["tcp"]), "metrics": fixture.metrics()}
            rows.append(row)
        for connection in connections.values():
            connection.close()
        connections.clear()
        final_metrics = wait_connections(0)
        events.append({"op": "drained", "when": stamp(), "metrics": final_metrics})
        fixture.daemon.send_signal(signal.SIGTERM)
        fixture.daemon.wait(3)
        assert fixture.daemon.returncode == 0
        return rows
    finally:
        for connection in connections.values():
            connection.close()
        client.close()
        upstream.close()
        fixture.close()
        cleanup_error = False
        if alias_present:
            cleanup = subprocess.run(["ip", "address", "del", ADDED + "/32", "dev", "lo"], capture_output=True, text=True)
            events.append({"op": "cleanup-address", "exit": cleanup.returncode, "stdout": cleanup.stdout, "stderr": cleanup.stderr})
            cleanup_error = cleanup.returncode != 0
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wires": wires, "events": events,
                                                   "connections": accepted, "initial_interface_state": initial,
                                                   "ubus": fixture.raw, "checks": fixture.checks}, indent=2) + "\n")
        assert all(check["pass"] for check in fixture.checks)
        assert not cleanup_error, "namespace alias cleanup failed; raw trace retained"


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("missing, extra or reordered rows")
    return [{"label": left["label"], "c": left, "rust": right}
            for left, right in zip(expected, actual) if left != right]


def calibrate(rows, profile):
    actions = [item for item in profile["actions"] if item["op"] == "query"]
    assert len(rows) == len(actions)
    for row, action in zip(rows, actions):
        assert row["label"] == action["label"] and row["local"] == action["local"], (action["label"], "local")
        assert len(row["upstream"]) == int(not action["local"])
        expected_rcode = 3 if action["label"] == "deleted-udp-ptr" else 0
        assert row["response"]["flags"] & 15 == expected_rcode, (action["label"], "rcode", row["response"]["flags"])
        answers = [record for record in row["response"]["records"] if record["section"] == "answer"]
        if action["kind"] == 12:
            actual = row["response"]["ptr_case"]
        else:
            actual = [str(ipaddress.ip_address(bytes.fromhex(record["data"]))) for record in answers if record["type"] in (1, 28)]
        # Membership calibration only. Preserve original C ordering in rows;
        # the cross-language comparator below compares lists exactly as saved.
        assert len(actual) == len(action["values"]) and all(actual.count(value) == action["values"].count(value) for value in actual), (action["label"], actual)
        assert all(record["ttl"] == 17 for record in answers)
        if action["label"] == "cname-terminal":
            assert [record["type"] for record in answers] == [5, 1]
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
    parser.add_argument("phase", choices=("c", "rust"))
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-binary", type=Path)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--c-baseline", type=Path, action="append", default=[])
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(label for _, label in socket.if_nameindex()) == ["lo"]
    args.reference_build = args.reference_build.resolve()
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    matrix = {"configuration": config_cases(), "services": profiles()}
    if args.phase == "c":
        binary = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
        reference = verify_reference(binary, args.c_identity)
        baselines = []
    else:
        assert args.rust is not None and len(args.c_baseline) == 2
        binary, reference = args.rust.resolve(), None
        baselines = []
        for path in args.c_baseline:
            result = json.loads((path / "result.json").read_text())
            assert not result["failures"] and result["observed"] == 25 and result["config_calibrated"] == 12
            assert result["phase"] == "c" and result["tool_sha256"] == digest(__file__)
            assert json.loads((path / "matrix.json").read_text()) == matrix
            baselines.append((path, result))
        assert {result["reference"]["kind"] for _, result in baselines} == {"native-glibc", "image-aarch64-musl"}
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(matrix, indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "interface-name-gate", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"phase": args.phase, "reference": reference, "native_client_build": native,
              "rust_sha256": digest(binary) if args.phase == "rust" else None, "tool_sha256": digest(__file__),
              "configuration": [], "profiles": [], "failures": [], "baselines": [
                  {"reference": result["reference"], "result_sha256": digest(path / "result.json"), "matrix_sha256": digest(path / "matrix.json")}
                  for path, result in baselines]}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    for case in config_cases():
        try:
            row = run_config(binary, case, out / ("config-" + case["label"]))
            if args.phase == "c":
                assert row["accepted"] == case["accepted"], (case, row)
            report["configuration"].append(row)
        except Exception as error:
            report["failures"].append({"case": case["label"], "stage": "config", "error": repr(error)})
        save()
    for profile in profiles():
        work = out / profile["label"]
        rows, failures, comparisons = [], [], []
        try:
            rows = run_service(args, binary, "C" if args.phase == "c" else "Rust", profile, work)
            if args.phase == "c":
                calibrate(rows, profile)
            else:
                for baseline, result in baselines:
                    expected = json.loads((baseline / profile["label"] / "trace.json").read_text())["rows"]
                    calibrate(expected, profile)
                    comparisons.append({"reference": result["reference"]["kind"], "differences": compare(expected, rows)})
        except Exception as error:
            failures.append(repr(error))
            if not rows and (work / "trace.json").exists():
                rows = json.loads((work / "trace.json").read_text())["rows"]
        report["profiles"].append({"label": profile["label"], "observed": len(rows), "failures": failures, "comparisons": comparisons})
        report["failures"].extend({"case": profile["label"], "stage": "service", "error": error} for error in failures)
        save()
    report["observed"] = sum(profile["observed"] for profile in report["profiles"])
    report["config_calibrated"] = len(report["configuration"]) if args.phase == "c" and not any(row["stage"] == "config" for row in report["failures"]) else 0
    report["config_differences"] = [{"reference": result["reference"]["kind"], "differences": compare(result["configuration"], report["configuration"])} for _, result in baselines]
    report["mismatches"] = sum(len(case["differences"]) for profile in report["profiles"] for case in profile["comparisons"])
    save()
    print(json.dumps({key: value for key, value in report.items() if key not in ("configuration", "profiles")}))
    return int(bool(report["failures"] or report["mismatches"] or any(row["differences"] for row in report["config_differences"])))


if __name__ == "__main__":
    raise SystemExit(main())
