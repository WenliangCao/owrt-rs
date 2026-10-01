#!/usr/bin/env python3
"""Exact C startup/HUP hosts-derived DHCP reservations, packets and metrics.

Freeze a C-only run before passing --rust and --baseline. All listeners and
private ubusd run inside run_isolated.sh; /run is private. No router access.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess

from dhcp_host_lifecycle import packet
from dhcp_boot_service_diff import options
from dhcp_lease_lifecycle import rows as lease_rows
from dhcp_reverse_lifecycle_diff import watch_reads, read_closed, wait_until
from dns_service_probe import query, semantics
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]


def fixtures():
    host = lambda client, tail: f"dhcp-host=02:00:00:00:00:{client:02x},{tail},infinite\n"
    offer = lambda address, client=1: {"kind": 1, "address": "127.0.0.20", "client": client, "expected": address}
    step = lambda hosts, expected, **kw: {"hosts": hosts, "requests": [offer(expected)], **kw}
    named = host(1, "derived")
    base = lambda label, steps, extra=named, **kw: {"label": label, "extra": extra, "steps": steps, **kw}
    yield base("reload-address", [step("127.0.0.40 derived\n", "127.0.0.40"),
        step("127.0.0.41 derived\n", "127.0.0.41"), step("", "127.0.0.20"),
        {"hosts": "127.0.0.42 derived\n", "requests": [{"kind": 3, "address": "127.0.0.42", "selecting": True, "expected": "127.0.0.42"}]}])
    yield base("explicit-wins", [step("127.0.0.40 derived\n", "127.0.0.45"), step("127.0.0.41 derived\n", "127.0.0.45")], host(1, "127.0.0.45,derived"))
    yield base("explicit-conflict", [{"hosts": "127.0.0.40 derived\n", "requests": [offer("127.0.0.20"), offer("127.0.0.40", 2)]}], named + host(2, "127.0.0.40,other"))
    yield base("derived-conflict", [{"hosts": "127.0.0.40 derived\n", "requests": [offer("127.0.0.20"), offer("127.0.0.40", 2)]}], named + host(2, "derived"))
    yield base("file-precedence", [{"hosts": "127.0.0.40 derived\n", "bank": "02:00:00:00:00:02,derived,infinite\n", "requests": [offer("127.0.0.20"), offer("127.0.0.40", 2)]},
        step("127.0.0.40 derived\n", "127.0.0.40", bank="")])
    yield base("old-derived-blocks-new-file-explicit", [step("127.0.0.40 derived\n", "127.0.0.40"),
        {"hosts": "127.0.0.41 derived\n", "bank": "02:00:00:00:00:02,127.0.0.40,file,infinite\n", "requests": [offer("127.0.0.41"), offer("127.0.0.20", 2)]},
        {"hosts": "127.0.0.41 derived\n", "bank": "02:00:00:00:00:02,127.0.0.40,file,infinite\n", "requests": [offer("127.0.0.41"), offer("127.0.0.40", 2)]}])
    yield base("alias-primary", [step("127.0.0.40 canonical derived\n", "127.0.0.40"),
        step("127.0.0.40 canonical derived\n127.0.0.41 another derived\n", "127.0.0.20"),
        step("127.0.0.40 canonical derived\n127.0.0.41 derived\n", "127.0.0.41")])
    for label, extra in [("multiple-addresses", ""), ("multiple-no-round-robin", "no-round-robin\n")]:
        yield base(label, [step("127.0.0.40 derived\n127.0.0.41 derived\n127.0.0.42 derived\n", ["127.0.0.40", "127.0.0.41", "127.0.0.42"])], named + extra)
    yield base("host-record", [step("", "127.0.0.46")], named + "host-record=derived,127.0.0.46\n")
    yield base("short-configured-name", [step("127.0.0.40 derived.pool.test\n", "127.0.0.20"),
        step("127.0.0.43 derived\n", "127.0.0.43")], host(1, "derived.pool.test"))
    yield base("port-zero", [step("FIFO", "127.0.0.20"), step("FIFO", "127.0.0.20")], port=0)
    yield base("restored-address-mismatch", [step("127.0.0.40 derived\n", "127.0.0.40"), step("", "127.0.0.20")],
               initial="0 02:00:00:00:00:01 127.0.0.20 oldname *\n")
    yield base("cname-not-followed", [step("", "127.0.0.20")], named + "host-record=target,127.0.0.40\ncname=derived,target\n")
    yield base("expanded-aliases", [step("127.0.0.40 derived\n127.0.0.41 derived\n", "127.0.0.20")], named + "expand-hosts\n")


def run_case(fixture, binary, case, out):
    out.mkdir()
    hosts, bank, leases = [out / name for name in ("hosts", "dhcp-hosts", "leases")]
    bank.write_text("")
    leases.write_text(case.get("initial", ""))
    marker = watch_reads(bank)
    port = case.get("port", 15353)
    config = out / "dnsmasq.conf"
    config.write_text("no-hosts\nno-resolv\nno-ping\nlisten-address=127.0.0.1\n"
        f"port={port}\naddn-hosts={hosts}\ndhcp-hostsfile={bank}\ndhcp-leasefile={leases}\n"
        f"enable-ubus={OBJECT}\nlocal-ttl=37\ndhcp-ttl=37\ndomain=pool.test\n"
        "dhcp-authoritative\ndhcp-range=127.0.0.10,127.0.0.50,255.0.0.0,infinite\n" + case["extra"])
    observations, wire = [], []
    raw_start = len(fixture.raw)
    process = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("0.0.0.0", 68))
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            client.setsockopt(socket.SOL_SOCKET, 25, b"lo\0")
            client.settimeout(1)
            for index, stage in enumerate(case["steps"]):
                if stage["hosts"] == "FIFO":
                    if not hosts.exists(): os.mkfifo(hosts)
                else:
                    hosts.write_text(stage["hosts"])
                bank.write_text(stage.get("bank", ""))
                if process is None:
                    command = [str(binary.resolve()), "-k", "-C", str(config)]
                    if binary.resolve() == (fixture.args.reference_build / "dnsmasq/dnsmasq").resolve():
                        command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
                    process, _ = fixture.spawn(command, case["label"])
                    fixture.daemon = process
                else:
                    process.send_signal(signal.SIGHUP)
                wait_until(process, lambda: read_closed(marker), "DHCP hosts-source close")
                fixture.wait_registered()
                before = {"metrics": fixture.metrics(), "leases": lease_rows(leases)}
                responses = []
                for request_index, item in enumerate(stage["requests"]):
                    request = packet(item, 0x7000 + index * 16 + request_index)
                    client.sendto(request, ("255.255.255.255", 67))
                    try:
                        response, peer = client.recvfrom(65535)
                        assert response[:3] == b"\x02\x01\x06" and response[4:8] == request[4:8]
                        options(response)
                        observed = {"wire": response.hex(), "peer": list(peer), "address": socket.inet_ntoa(response[16:20])}
                    except socket.timeout:
                        observed = None
                    wire.append({"stage": index, "request": request.hex(), "response": observed})
                    responses.append(observed)
                after = {"metrics": fixture.metrics(), "leases": lease_rows(leases)}
                dns = None
                if port:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(1)
                        request = query("derived", 1, 0x7100 + index)
                        udp.sendto(request, ("127.0.0.1", port))
                        response = udp.recv(65535)
                        dns = semantics(response)
                        wire.append({"stage": index, "dns_query": request.hex(), "dns_reply": response.hex()})
                observations.append({"scenario": case["label"], "stage": index, "before": before,
                                     "responses": responses, "after": after, "dns": dns})
                (out / f"{index}.leases").write_bytes(leases.read_bytes())
        fixture.stop(process)
        assert process.returncode == 0, "daemon did not shut down normally"
        return observations
    finally:
        os.close(marker)
        fixture.stop(process)
        fixture.daemon = None
        (out / "trace.json").write_text(json.dumps({"observations": observations, "wire": wire,
            "ubus": fixture.raw[raw_start:], "shutdown_exit": process.returncode if process else None}, indent=2) + "\n")


def calibrate(cases, observations):
    assert len(observations) == sum(len(case["steps"]) for case in cases)
    offset = 0
    for case in cases:
        for stage in case["steps"]:
            row = observations[offset]
            offset += 1
            assert len(row["responses"]) == len(stage["requests"])
            for item, response in zip(stage["requests"], row["responses"]):
                expected = item["expected"]
                assert response and response["address"] in (expected if isinstance(expected, list) else [expected]), (case["label"], row["stage"], response, expected)
                reply_options = options(bytes.fromhex(response["wire"]))
                assert next(value for code, value in reply_options if code == 53) == ("05" if item["kind"] == 3 else "02")
            initial_count = int(bool(case.get("initial")))
            assert row["before"]["metrics"]["leases_allocated_4"] == initial_count
            assert row["after"]["metrics"]["leases_allocated_4"] == initial_count + sum(item["kind"] == 3 for item in stage["requests"])
    assert observations[0]["before"]["leases"] == []
    assert observations[3]["after"]["leases"][0]["address"] == "127.0.0.42"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-failure", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    args.reference_build = args.reference_build.resolve()
    reference = args.reference_build / "dnsmasq/dnsmasq"
    identity = verify_reference(reference, None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    cases = list(fixtures())
    (out / "plan.json").write_text(json.dumps(cases, indent=2) + "\n")
    expected = None
    if args.rust:
        assert args.baseline, "freeze independent C observations first"
        baseline = json.loads((args.baseline / "result.json").read_text())
        assert baseline["failures"] == [] and baseline["rust_sha256"] is None
        assert baseline["tool_sha256"] == digest(Path(__file__))
        assert baseline["plan_sha256"] == digest(out / "plan.json")
        assert baseline["observations_sha256"] == digest(args.baseline / "observations.json")
        expected = json.loads((args.baseline / "observations.json").read_text())
        if args.inject_failure:
            expected[0]["responses"][0]["address"] = "192.0.2.99"
    report = {"reference": identity, "rust_sha256": digest(args.rust) if args.rust else None,
              "tool_sha256": digest(Path(__file__)), "plan_sha256": digest(out / "plan.json"),
              "scenarios": len(cases), "planned": sum(len(case["steps"]) for case in cases),
              "completed": 0, "matched": None, "failures": []}
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=0755", "tmpfs", "/run"], check=True)
    Path(BUS).parent.mkdir(parents=True)
    fixture = None
    observations = []
    try:
        fixture = Fixture(args, out)
        fixture.start_bus()
        for case in cases:
            try:
                observations.extend(run_case(fixture, args.rust or reference, case, out / case["label"]))
            except Exception as error:
                report["failures"].append({"scenario": case["label"], "error": repr(error)})
        report["completed"] = len(observations)
        if expected is None:
            calibrate(cases, observations)
        else:
            assert len(observations) == len(expected), "missing observations"
            mismatches = [{"scenario": c["scenario"], "stage": c["stage"], "c": c, "rust": r}
                          for c, r in zip(expected, observations) if c != r]
            report["matched"] = len(expected) - len(mismatches)
            report["failures"].extend(mismatches)
        negative = copy.deepcopy(observations)
        negative[0]["responses"][0]["address"] = "192.0.2.99"
        assert sum(a != b for a, b in zip(observations, negative)) == 1
        report["calibration"] = {"one_mutation_detected": 1}
    except Exception as error:
        report["failures"].append({"infrastructure_or_calibration": repr(error)})
    finally:
        if fixture:
            fixture.close()
            (out / "fixture-checks.json").write_text(json.dumps(fixture.checks, indent=2) + "\n")
            report["failures"].extend(check for check in fixture.checks if not check["pass"])
        subprocess.run(["umount", "/run"], check=True)
        (out / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
        report["observations_sha256"] = digest(out / "observations.json")
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "failures"} | {"failures": len(report["failures"])}))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
