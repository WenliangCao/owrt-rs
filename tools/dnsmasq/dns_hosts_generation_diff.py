#!/usr/bin/env python3
"""Exact-C/Rust static host generation, address order, PTR and reload gate."""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_local_udp_diff import exchange
from dns_service_probe import semantics
from dns_service_probe import read_name
from dns_udp_refusal_diff import C_HASH, ROOT, digest, query
from dns_hosts_generation_oracle import Rotation, build, inventory


FILES = [
    "192.0.2.1 file.test cfg.test\n192.0.2.4 mixed.test fileonly.test\n"
    "192.0.2.5 mixed.test\n192.0.2.4 mixed.test\n2001:db8::4 mixed.test v6file.test\n"
    "192.0.2.9 dup.test\n192.0.2.6 FIRST.File.test second.file.test\n",
    "192.0.2.1 fresh.file.test cfg.test\n192.0.2.7 mixed.test\n"
    "192.0.2.8 new.file.test\n2001:db8::8 mixed.test\n",
]


def config(port, hosts_file, no_round):
    return (f"port={port}\nno-resolv\nno-hosts\ncache-size=0\nlocal-ttl=37\n"
            f"listen-address=127.0.0.1,::1\naddn-hosts={hosts_file}\n" +
            ("no-round-robin\n" if no_round else "") +
            "host-record=CfG.test,alias.test,192.0.2.1,2001:db8::1,90\n"
            "host-record=mixed.test,192.0.2.1,11\n"
            "host-record=mixed.test,192.0.2.2,2001:db8::2,22\n"
            "host-record=mixed.test,192.0.2.3,2001:db8::3,33\n"
            "host-record=mixed.test,192.0.2.2,999\n"
            "host-record=zero.test,192.0.2.0,50\n"
            "host-record=v6prefix.test,2001:db8::,51\n"
            "host-record=dup.test,192.0.2.9,54\nhost-record=dup.test,192.0.2.9,999\n"
            "host-record=no-address.test,unused.test,81\n"
            "host-record=one.two.test,192.0.2.12,44\n"
            "address=/route.test/192.0.2.13\nlocal=/local.test/\n"
            "ptr-record=2.2.0.192.in-addr.arpa,override.test\n")


def schedule():
    rows = [(f"a-cycle-{i}", "mixed.test", 1, "127.0.0.1" if i != 1 else "::1", False) for i in range(3)]
    rows += [("aaaa", "mixed.test", 28, "127.0.0.1", False),
             ("unowned-type", "mixed.test", 16, "127.0.0.1", False),
             ("a-after-other-type", "mixed.test", 1, "127.0.0.1", False),
             ("any-families", "mixed.test", 255, "::1", False),
             ("tcp-snapshot-1", "mixed.test", 1, "127.0.0.1", True),
             ("tcp-snapshot-2", "mixed.test", 1, "::1", True),
             ("udp-after-tcp", "mixed.test", 1, "127.0.0.1", False)]
    for address in ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.6", "192.0.2.9",
                    "2001:db8::1", "2001:db8::4", "2001:db8::8"]:
        rows.append((f"ptr-{address}", ipaddress.ip_address(address).reverse_pointer, 12, "127.0.0.1", False))
    for host in ["2.0.192.in-addr.arpa", "8.b.d.0.1.0.0.2.ip6.arpa", "257.2.0.192.in-addr.arpa",
                 "1.0/24.2.0.192.in-addr.arpa", ipaddress.ip_address("2001:db8::1").reverse_pointer.replace("arpa", "int")]:
        rows.append((f"reverse-form-{host}", host, 12, "::1", False))
    for host in ["cfg.test", "alias.test", "dup.test", "fileonly.test", "no-address.test"]:
        rows.append((f"forward-{host}", host, 1, "127.0.0.1", False))
    rows.append(("disturb-before-reload", "mixed.test", 1, "127.0.0.1", False))
    rows += [("literal-dot-forward", b"\x07one.two\x04test\0", 1, "127.0.0.1", False),
             ("literal-dot-reverse", b"\x031.2\x010\x03192\x07in-addr\x04arpa\0", 12, "::1", False),
             ("literal-dot-address-suffix", b"\x07one.two\x05route\x04test\0", 1, "::1", False),
             ("literal-dot-local-suffix", b"\x07one.two\x05local\x04test\0", 1, "127.0.0.1", False)]
    return rows


def run(binary, side, out, no_round, port):
    label = f"{'fixed' if no_round else 'rotating'}-{side}"
    hosts_file = out / "data.hosts"
    hosts_file.write_text(FILES[0])
    conf = out / "dnsmasq.conf"
    conf.write_text(config(port, hosts_file, no_round))
    (out / f"{label}.conf").write_text(conf.read_text())
    rows = []
    with (out / f"{label}.log").open("wb") as log:
        process = subprocess.Popen([str(binary), "-k", "-C", str(conf)], stdout=log, stderr=log,
                                   start_new_session=True)
        try:
            for stage, generation in enumerate([0, 1, 1]):
                if stage:
                    hosts_file.write_text(FILES[generation])
                    process.send_signal(signal.SIGHUP)
                    # Identical input has no changed DNS marker. Settle this
                    # small fixture, then require the original seed below;
                    # the prior stage deliberately leaves its cursor rotated.
                    if stage == 2:
                        time.sleep(.25)
                for _ in range(100):
                    assert process.poll() is None
                    try:
                        marker = "new.file.test" if stage else "cfg.test"
                        answer = exchange("127.0.0.1", port, query(marker, 1, 1, 0x100, 1), False)
                        if answer[6:8] == b"\0\1":
                            break
                    except OSError:
                        pass
                    time.sleep(.025)
                else:
                    raise AssertionError("startup/reload marker failed")
                for case, host, kind, ip, tcp in schedule():
                    packet = (struct.pack("!6H", 0x3000 + len(rows), 0x100, 1, 0, 0, 0) + host + struct.pack("!HH", kind, 1)
                              if isinstance(host, bytes) else query(host, kind, 1, 0x100, 0x3000 + len(rows)))
                    reply = exchange(ip, port, packet, tcp)
                    rows.append({"stage": stage, "generation": generation, "case": case,
                                 "tcp": tcp, "request": packet.hex(), "reply": reply.hex()})
        finally:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            (out / f"{label}.json").write_text(json.dumps(rows, indent=2) + "\n")
    assert process.returncode == 0
    return rows


def validate_transitions(rows, inventories, rotation, no_round):
    seeds, models, current_stage = {}, {}, None
    errors, transitions = [], []
    try:
        for row in rows:
            if row["stage"] != current_stage:
                for model in models.values():
                    model.close()
                models = {}
                current_stage = row["stage"]
            parsed = semantics(bytes.fromhex(row["reply"]))
            host, kind, cls = parsed["questions"][0]
            if host != "mixed.test" or kind not in [1, 28, 255] or cls != 1:
                continue
            inventory = inventories[row["generation"]]
            observed_types = [record["type"] for record in parsed["records"]]
            assert all(record["type"] in ([1, 28] if kind == 255 else [kind]) and
                       record["section"] == "answer" for record in parsed["records"]), "unexpected address section/type"
            if observed_types != sorted(observed_types):
                errors.append({"case": row["case"], "error": "ANY family order changed"})
            for family in ([1, 28] if kind == 255 else [kind]):
                records = [record for record in parsed["records"] if record["type"] == family]
                values = [record["data"] for record in records]
                expected = {address: item for (name, address), item in inventory.items()
                            if name == host and ((":" in address) == (family == 28))}
                assert len(values) == len(set(values)) == len(expected) and set(values) == set(expected), "address set differs from C inventory"
                assert all(record["name"] == host and record["class"] == 1 and
                           record["ttl"] == expected[record["data"]]["ttl"] for record in records), "address TTL/class differs from C inventory"
                reverse = [bool(expected[address]["flags"] & 4) for address in values]
                assert reverse == sorted(reverse, reverse=True), "reverse-owner group lost precedence"
                key = (row["generation"], family)
                if key not in seeds:
                    seeds[key] = values
                if family not in models:
                    models[family] = Rotation(rotation, [expected[address]["flags"] for address in seeds[key]], no_round, family == 28)
                indices = models[family].next(row["tcp"])
                wanted = [seeds[key][index] for index in indices]
                transitions.append({"stage": row["stage"], "case": row["case"], "family": family,
                                    "tcp_snapshot": row["tcp"], "expected": wanted, "actual": values})
                if values != wanted:
                    errors.append({"stage": row["stage"], "case": row["case"], "family": family,
                                   "expected": wanted, "actual": values})
    finally:
        for model in models.values():
            model.close()
    return errors, transitions, [{"generation": key[0], "family": key[1], "order": value} for key, value in seeds.items()]


def compare_envelopes(c, rust):
    mismatches, permitted_seeds = [], []
    for left, right in zip(c, rust):
        if left == right:
            continue
        a = semantics(bytes.fromhex(left["reply"]))
        b = semantics(bytes.fromhex(right["reply"]))
        host, kind, _ = a["questions"][0]
        if host == "mixed.test" and kind in [1, 28, 255]:
            # Only the initial address ordering is a process/generation seed.
            # Full inventory and each later transition are checked above by C.
            aa, bb = {k: v for k, v in a.items() if k != "records"}, {k: v for k, v in b.items() if k != "records"}
            if aa == bb and len(left["reply"]) == len(right["reply"]):
                permitted_seeds.append({"stage": left["stage"], "case": left["case"]})
                continue
        mismatches.append({"stage": left["stage"], "case": left["case"]})
    return mismatches, permitted_seeds


def calibrate(c, inventories, rotation, no_round):
    errors, _, _ = validate_transitions(c, inventories, rotation, no_round)
    assert not errors, "C daemon disagrees with extracted C rotation model"
    mutation = copy.deepcopy(c)
    changed = next(row for row in mutation if row["stage"] == 0 and row["case"] == "a-cycle-1")
    packet = bytearray.fromhex(changed["reply"])
    _, end = read_name(packet, 12)
    start = end + 4
    assert packet[start:start + 2] == b"\xc0\x0c" and packet[start + 16:start + 18] == b"\xc0\x0c"
    packet[start:start + 32] = packet[start + 16:start + 32] + packet[start:start + 16]
    changed["reply"] = packet.hex()
    errors, _, _ = validate_transitions(mutation, inventories, rotation, no_round)
    assert errors, "second-response address reordering was normalized away"
    mutation = copy.deepcopy(c)
    changed = next(row for row in mutation if row["stage"] == 0 and row["case"] == "a-cycle-1")
    packet = bytearray.fromhex(changed["reply"])
    packet[start + 9] ^= 1  # First RR TTL, preserving address inventory.
    changed["reply"] = packet.hex()
    try:
        validate_transitions(mutation, inventories, rotation, no_round)
    except AssertionError:
        pass
    else:
        raise AssertionError("TTL mutation was normalized away")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reference-build", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    assert digest(args.c) == C_HASH
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    inventory_binary, rotation = build(args.reference_build.resolve(), out / "models")
    # Same normal -k behavior, isolated default C pid location and readable
    # input paths. No real /run, privilege or logging parity claim is made.
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=0755", "tmpfs", "/run"], check=True)
    assert Path("/var/run").resolve() == Path("/run")
    fixture = Path("/run/private")
    fixture.mkdir()
    subprocess.run(["mount", "--bind", str(out), str(fixture)], check=True)
    report = {"c_sha256": digest(args.c), "rust_sha256": digest(args.rust),
              "inventory_sha256": digest(inventory_binary), "rotation_sha256": digest(rotation),
              "scope": "same normal -k argv/config; private /run/net/pid; static DNS generation/cursors, not privilege/logging/procd parity",
              "normalization": "C-inventory-validated initial RRset permutation is one seed per process and identical generation input; exact C transition model thereafter; no per-reply sorting",
              "rounds": [], "failures": []}
    try:
        for no_round in [True, False]:
            inventories = []
            for generation, contents in enumerate(FILES):
                hostfile = fixture / f"inventory-{no_round}-{generation}.hosts"
                hostfile.write_text(contents)
                conf = fixture / f"inventory-{no_round}-{generation}.conf"
                conf.write_text(config(0, hostfile, no_round))
                inventories.append(inventory(inventory_binary, conf, fixture / f"inventory-{no_round}-{generation}.txt"))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
            c = run(args.c, "c", fixture, no_round, port)
            rust = run(args.rust, "rust", fixture, no_round, port)
            assert len(c) == len(rust) == 3 * len(schedule()), "count calibration"
            calibrate(c, inventories, rotation, no_round)
            c_errors, c_trace, c_seeds = validate_transitions(c, inventories, rotation, no_round)
            r_errors, r_trace, r_seeds = validate_transitions(rust, inventories, rotation, no_round)
            (out / f"transitions-{no_round}.json").write_text(json.dumps({"c": c_trace, "rust": r_trace}, indent=2) + "\n")
            mismatch, seed_differences = compare_envelopes(c, rust)
            report["rounds"].append({"no_round_robin": no_round, "queries_per_side": len(c),
                                     "mismatches": mismatch, "c_transition_errors": c_errors,
                                     "rust_transition_errors": r_errors, "initial_c_seeds": c_seeds,
                                     "initial_rust_seeds": r_seeds, "raw_order_differences": seed_differences,
                                     "calibration": {"equal": 1, "negative_order_and_ttl": 2}})
        assert not any(row["mismatches"] or row["c_transition_errors"] or row["rust_transition_errors"] for row in report["rounds"]), "generation mismatch"
    except Exception as error:
        report["failures"].append(repr(error))
        raise
    finally:
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        subprocess.run(["umount", str(fixture)], check=True)
        subprocess.run(["umount", "/run"], check=True)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
