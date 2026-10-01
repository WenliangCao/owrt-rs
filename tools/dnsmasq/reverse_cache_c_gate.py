#!/usr/bin/env python3
"""Frozen exact-C reverse-cache primitive gate; no Rust implementation oracle."""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess

import local_answer_diff
from cache_answer_diff import HASHES, name, packet
from dns_cache_rr_diff import decode

ROOT = Path(__file__).resolve().parents[2]
DRIVER = Path(__file__).with_name("reverse_cache_driver.c")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def reverse(address):
    return ipaddress.ip_address(address).reverse_pointer


class Case:
    def __init__(self, label, capacity=8, extra="", cohort=False):
        self.label, self.capacity, self.extra, self.cohort = label, capacity, extra, cohort
        self.actions = []

    def emit(self, label, command, expected):
        self.actions.append({"label": label, "command": command, "expected": expected})

    def positive(self, label, owner, kind, data, now=100, ttl=120):
        self.emit(label, f"P {now} " + packet(owner, kind, 0x8180, [(owner, kind, ttl, data)]).hex(), {"status": 0})

    def ptr(self, label, owner, target, now=100, ttl=120):
        self.positive(label, owner, 12, name(target), now, ttl)

    def address(self, label, owner, address, now=100, ttl=120):
        value = ipaddress.ip_address(address)
        self.positive(label, owner, 1 if value.version == 4 else 28, value.packed, now, ttl)

    def query(self, label, owner, kind=12, data=None, now=100, flags=0x100, rcode=0, authority=None, unordered_data=None):
        expected = {"hit": data is not None or authority is not None or rcode == 3 or unordered_data is not None}
        if expected["hit"]:
            expected.update(flags=0x8080 | (flags & 0x0110) | rcode, answers=[] if data is None else [(kind, data.hex())])
            if authority is not None:
                expected["authority"] = authority
            if unordered_data is not None:
                expected.pop("answers")
                expected["cohort_members"] = [value.hex() for value in unordered_data]
        self.emit(label, f"Q {now} " + packet(owner, kind, flags).hex(), expected)

    def exists(self, label, owner, exists, now=100):
        self.emit(label, f"N {now} {owner}", {"exists": int(exists)})

    def state(self, label, entries):
        self.emit(label, "S", {"entries": entries})

    def metrics(self, inserted, live_freed=0):
        self.emit("metrics", "M", {"inserted": inserted, "live_freed": live_freed})


def entry(owner, address="", kind=None, negative=False, expires=220, reverse_only=False):
    return {"name": owner, "address": address, "kind": kind or (28 if ":" in address else 1),
            "negative": int(negative), "expires": expires,
            "forward": int(not reverse_only), "reverse": int(reverse_only)}


def rentry(owner, address, expires=220):
    return entry(owner, address, expires=expires, reverse_only=True)


def corpus():
    cases = []
    v4, partial4 = "192.0.2.0", "2.0.192.in-addr.arpa"
    v6, partial6 = "2001:db8::", "8.b.d.0.1.0.0.2.ip6.arpa"
    for version, address, partial, forward_ip in [(4, v4, partial4, "192.0.2.99"), (6, v6, partial6, "2001:db8::99")]:
        owner, target, kind = reverse(address), f"target-v{version}.test", 1 if version == 4 else 28
        c = Case(f"direction-v{version}")
        c.ptr("seed-partial", partial, target)
        c.query("full-hit", owner, data=name(target))
        if version == 6:
            c.query("ip6-int-hit", owner[:-4] + "int", data=name(target))
        c.query("partial-hit", partial, data=name(target))
        c.exists("target-not-forward", target, False)
        c.query("target-address-miss", target, kind)
        c.address("seed-forward-target", target, forward_ip)
        c.query("target-address-hit", target, kind, ipaddress.ip_address(forward_ip).packed)
        c.query("reverse-still-hit", owner, data=name(target))
        c.state("independent-directions", [rentry(target, address), entry(target, forward_ip)])
        c.metrics(2)
        cases.append(c)
    for version, address, partial in [(4, v4, partial4), (6, v6, partial6)]:
        c = Case(f"replace-v{version}")
        c.ptr("seed-old", reverse(address), "old-target.test")
        c.ptr("replace-via-partial", partial, "new-target.test", now=101)
        c.query("full-new", reverse(address), data=name("new-target.test"), now=101)
        c.query("partial-new", partial, data=name("new-target.test"), now=101)
        c.query("old-forward-miss", "old-target.test", 1 if version == 4 else 28, now=101)
        c.state("one-reverse", [rentry("new-target.test", address, 221)])
        c.metrics(2)
        cases.append(c)
    c = Case("same-target-two-addresses")
    for suffix in [1, 2]:
        c.ptr(f"seed-{suffix}", reverse(f"192.0.2.{suffix}"), "shared-target.test")
    for suffix in [1, 2]:
        c.query(f"hit-{suffix}", reverse(f"192.0.2.{suffix}"), data=name("shared-target.test"))
    c.ptr("replace-only-one", reverse("192.0.2.1"), "new-target.test", now=101)
    c.query("one-replaced", reverse("192.0.2.1"), data=name("new-target.test"), now=101)
    c.query("two-retained", reverse("192.0.2.2"), data=name("shared-target.test"), now=101)
    c.state("two-addresses", [rentry("new-target.test", "192.0.2.1", 221), rentry("shared-target.test", "192.0.2.2")])
    c.metrics(3)
    cases.append(c)
    soa_owner = partial4
    soa_data = name("ns.reverse.test") + name("hostmaster.reverse.test") + struct.pack("!5I", 1, 2, 3, 4, 120)
    for label, nx, disabled in [("nodata-owner-scope", False, False), ("nxdomain-owner-scope", True, False), ("no-negcache", False, True)]:
        c = Case(label, extra="no-negcache\n" if disabled else "")
        authority = [] if nx else [(soa_owner, 6, 120, soa_data)]
        c.emit("seed-negative", "P 100 " + packet(reverse(v4), 12, 0x8183 if nx else 0x8180, authority=authority).hex(), {"status": 0})
        c.query("full-negative", reverse(v4), rcode=3 if nx else 0, authority=soa_owner if not nx and not disabled else None)
        c.query("partial-negative-miss", partial4)
        if disabled:
            c.state("nothing-committed", [])
            c.metrics(0)
        else:
            c.exists("negative-forward-existence", reverse(v4), not nx)
            c.ptr("positive-via-partial", partial4, "positive-target.test", now=101)
            c.query("full-positive", reverse(v4), data=name("positive-target.test"), now=101)
            c.query("partial-positive", partial4, data=name("positive-target.test"), now=101)
            entries = [rentry("positive-target.test", v4, 221), entry(reverse(v4), kind=65536 if nx else 12, negative=True)]
            if not nx:
                entries.append(entry(soa_owner, kind=6))
            c.state("separate-negative-and-reverse", entries)
            c.metrics(2 if nx else 3)
        cases.append(c)
    for label, reverse_insert in [("pressure-forward-insert", False), ("pressure-reverse-insert", True)]:
        c = Case(label, capacity=3)
        c.address("seed-forward-a", "a.forward.test", "192.0.2.21")
        c.ptr("seed-reverse-one", reverse("192.0.2.1"), "reverse-one.test")
        if reverse_insert:
            c.address("seed-forward-b", "b.forward.test", "192.0.2.22")
            c.query("promote-reverse-one", reverse("192.0.2.1"), data=name("reverse-one.test"))
            c.ptr("pressure-new-reverse", reverse("192.0.2.2"), "reverse-two.test")
        else:
            c.ptr("seed-reverse-two", reverse("192.0.2.2"), "reverse-two.test")
            c.query("promote-forward-a", "a.forward.test", 1, ipaddress.ip_address("192.0.2.21").packed)
            c.address("pressure-new-forward", "b.forward.test", "192.0.2.22")
        c.query("probe-forward-a", "a.forward.test", 1, None if reverse_insert else ipaddress.ip_address("192.0.2.21").packed)
        c.query("probe-reverse-one", reverse("192.0.2.1"), data=name("reverse-one.test") if reverse_insert else None)
        c.query("probe-reverse-two", reverse("192.0.2.2"), data=name("reverse-two.test"))
        c.query("probe-forward-b", "b.forward.test", 1, ipaddress.ip_address("192.0.2.22").packed)
        entries = [entry("b.forward.test", "192.0.2.22"), rentry("reverse-two.test", "192.0.2.2")]
        entries.append(rentry("reverse-one.test", "192.0.2.1") if reverse_insert else entry("a.forward.test", "192.0.2.21"))
        c.state("surviving-directions", entries)
        c.metrics(4, 1)
        cases.append(c)
    c = Case("reverse-lookup-expiry")
    for suffix in [1, 2]:
        c.ptr(f"seed-expiring-reverse-{suffix}", reverse(f"192.0.2.{suffix}"), f"expired-{suffix}.test", ttl=10)
    c.address("seed-expiring-forward", "expired-forward.test", "192.0.2.21", ttl=10)
    c.ptr("seed-live-reverse", reverse("192.0.2.3"), "live-reverse.test")
    c.emit("address-lookup-at-expiry", "A 110 192.0.2.3", {"entries": [rentry("live-reverse.test", "192.0.2.3")]})
    c.state("forward-not-globally-pruned", [rentry("live-reverse.test", "192.0.2.3"), entry("expired-forward.test", "192.0.2.21", expires=110)])
    for suffix in [1, 2]:
        c.query(f"backward-reverse-miss-{suffix}", reverse(f"192.0.2.{suffix}"))
    c.query("backward-forward-hit", "expired-forward.test", 1, ipaddress.ip_address("192.0.2.21").packed)
    c.metrics(4)
    cases.append(c)
    c = Case("reverse-insert-expiry")
    c.ptr("seed-expiring-reverse", reverse("192.0.2.1"), "expired-reverse.test", ttl=10)
    c.address("seed-expiring-forward", "expired-forward.test", "192.0.2.21", ttl=10)
    c.ptr("seed-live-reverse", reverse("192.0.2.2"), "live-reverse.test")
    c.ptr("new-reverse-at-expiry", reverse("192.0.2.3"), "new-reverse.test", now=110)
    c.state("global-expired-directions-removed", [rentry("new-reverse.test", "192.0.2.3", 230), rentry("live-reverse.test", "192.0.2.2")])
    c.query("backward-reverse-miss", reverse("192.0.2.1"))
    c.query("backward-forward-miss", "expired-forward.test", 1)
    c.metrics(4)
    cases.append(c)
    c = Case("rd0-pressure", capacity=3)
    c.ptr("seed-reverse-one", reverse("192.0.2.1"), "reverse-one.test")
    c.address("seed-forward-a", "a.forward.test", "192.0.2.21")
    c.ptr("seed-reverse-two", reverse("192.0.2.2"), "reverse-two.test")
    c.query("rd0-miss-still-promotes", reverse("192.0.2.1"), flags=0)
    c.address("pressure-forward-b", "b.forward.test", "192.0.2.22")
    c.query("probe-forward-a", "a.forward.test", 1)
    for suffix, word in [(1, "one"), (2, "two")]:
        c.query(f"probe-reverse-{word}", reverse(f"192.0.2.{suffix}"), data=name(f"reverse-{word}.test"))
    c.query("probe-forward-b", "b.forward.test", 1, ipaddress.ip_address("192.0.2.22").packed)
    c.state("rd0-pressure-survivors", [entry("b.forward.test", "192.0.2.22"), rentry("reverse-one.test", "192.0.2.1"), rentry("reverse-two.test", "192.0.2.2")])
    c.metrics(4, 1)
    cases.append(c)
    c = Case("mixed-case-target")
    target = "MiXeD.Ptr.Test"
    c.ptr("seed-mixed-case", reverse(v4).upper(), target)
    c.query("lower-owner-hit", reverse(v4), data=name(target.lower()))
    c.actions[-1]["expected"]["ptr_case"] = [target]
    c.query("upper-partial-hit", partial4.upper(), data=name(target.lower()))
    c.actions[-1]["expected"]["ptr_case"] = [target]
    c.exists("mixed-target-not-forward", target, False)
    c.exists("lower-target-not-forward", target.lower(), False)
    c.state("stored-case", [rentry(target, v4)])
    c.metrics(1)
    cases.append(c)
    assert len(cases) == 14
    for index in range(4):
        c = Case(f"multi-target-cohort-{index + 1}", capacity=3, cohort=True)
        owner, targets = reverse("192.0.2.1"), ["zeta.reverse.test", "alpha.reverse.test"]
        c.emit("seed-two-targets", "P 100 " + packet(owner, 12, 0x8180, [(owner, 12, 120, name(target)) for target in targets]).hex(), {"status": 0})
        c.address("seed-forward-sentinel", "sentinel.forward.test", "192.0.2.21")
        c.query("multi-ptr-order", owner, unordered_data=[name(target) for target in targets])
        c.query("promote-sentinel", "sentinel.forward.test", 1, ipaddress.ip_address("192.0.2.21").packed)
        c.state("before-pressure-order", [entry("sentinel.forward.test", "192.0.2.21"), *[rentry(target, "192.0.2.1") for target in targets]])
        c.address("pressure-new-forward", "new.forward.test", "192.0.2.22")
        c.state("both-reverse-removed", [entry("new.forward.test", "192.0.2.22"), entry("sentinel.forward.test", "192.0.2.21")])
        c.metrics(4, 1)
        c.query("reverse-miss", owner)
        c.query("sentinel-hit", "sentinel.forward.test", 1, ipaddress.ip_address("192.0.2.21").packed)
        c.query("new-forward-hit", "new.forward.test", 1, ipaddress.ip_address("192.0.2.22").packed)
        cases.append(c)
    return cases


def read_case_name(packet_bytes, position):
    labels, visited, resume = [], set(), None
    while True:
        assert position < len(packet_bytes) and position not in visited
        visited.add(position)
        size = packet_bytes[position]
        position += 1
        if size == 0:
            return b".".join(labels).decode("ascii"), position if resume is None else resume
        if size & 0xc0 == 0xc0:
            assert position < len(packet_bytes)
            if resume is None:
                resume = position + 1
            position = ((size & 63) << 8) | packet_bytes[position]
        else:
            assert size <= 63 and position + size <= len(packet_bytes)
            labels.append(packet_bytes[position:position + size])
            position += size


def ptr_case(packet_bytes):
    _, _, qd, an, ns, ar = struct.unpack_from("!6H", packet_bytes)
    position, targets = 12, []
    for _ in range(qd):
        _, position = read_case_name(packet_bytes, position)
        position += 4
    for _ in range(an + ns + ar):
        _, position = read_case_name(packet_bytes, position)
        kind, _, _, size = struct.unpack_from("!HHIH", packet_bytes, position)
        position += 10
        if kind == 12:
            target, _ = read_case_name(packet_bytes, position)
            targets.append(target)
        position += size
    assert position == len(packet_bytes)
    return targets


def check_row(row, expected):
    errors = []
    for key, value in expected.items():
        if key == "entries":
            actual = [{k: v for k, v in record.items() if k != "bucket"} for record in row["entries"]]
            # C-only membership calibration, not response/state normalization.
            # Keep the untouched actual order and bucket in the saved rows.
            if len(actual) != len(value) or any(actual.count(record) != value.count(record) for record in value):
                errors.append({"field": key, "expected": value, "actual": actual})
        elif key == "hit":
            if (row["packet"] is not None) != value:
                errors.append({"field": key, "expected": value, "actual": row["packet"] is not None})
        elif key in ("flags", "answers", "authority", "cohort_members"):
            message = row.get("decoded")
            if message is None:
                errors.append({"field": key, "error": "missing packet"})
                continue
            records = message["records"]
            if key == "flags":
                actual = message["flags"]
            elif key == "answers":
                actual = [(record["type"], record["data"]) for record in records if record["section"] == "answer"]
            elif key == "authority":
                actual = next((record["name"] for record in records if record["section"] == "authority" and record["type"] == 6), None)
            else:
                actual = [record["data"] for record in records if record["section"] == "answer"]
                if len(actual) != len(value) or any(actual.count(record) != value.count(record) for record in value):
                    errors.append({"field": key, "expected": value, "actual": actual})
                continue
            if actual != value:
                errors.append({"field": key, "expected": value, "actual": actual})
        elif row.get(key) != value:
            errors.append({"field": key, "expected": value, "actual": row.get(key)})
    return errors


def compare(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("missing or extra rows")
    return [index for index, (left, right) in enumerate(zip(expected, actual)) if left != right]


def build(args, out):
    obj = args.reference_build / "dnsmasq"
    local_answer_diff.validate_reference_variant(obj)
    actual = {file: digest(obj / file) for file in HASHES}
    assert actual == HASHES, actual
    renamed = local_answer_diff.rename_main(obj, out)
    objects = sorted(p for p in obj.glob("*.o") if p.name not in {"cache.o", "dnsmasq.o", "dnsmasq-renamed.o"})
    objects.append(renamed)
    deps = args.reference_build / "deps/lib"
    binary = out / "oracle"
    command = ["cc", *local_answer_diff.REFERENCE_COPTS, "-O2", "-Wall", "-Wextra", "-Werror",
               f"-I{obj}", f"-I{args.reference_build / 'deps/include'}", str(DRIVER),
               *map(str, objects), f"-L{deps}", f"-Wl,-rpath,{deps}", "-lubus", "-lubox", "-o", str(binary)]
    with (out / "build.log").open("w") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    compiler = subprocess.run(["cc", "--version"], capture_output=True, text=True, check=True)
    identity = {"kind": "exact-native-source-primitive-not-stock-image", "sources": actual,
                "config_sha256": digest(obj / "config.h"), "objects": {p.name: digest(p) for p in objects},
                "driver_sha256": digest(DRIVER), "tool_sha256": digest(__file__),
                "binary_sha256": digest(binary), "compiler": compiler.stdout,
                "build_command": command, "copts": local_answer_diff.REFERENCE_COPTS}
    save(out / "identity.json", identity)
    return binary, identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    args.reference_build = args.reference_build.resolve()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    shutil.copy2(DRIVER, out / DRIVER.name)
    shutil.copy2(__file__, out / Path(__file__).name)
    cases = corpus()
    save(out / "matrix.json", [vars(case) for case in cases])
    report = {"profiles": [], "failures": [], "main_profiles": 14, "cohort_processes": 4,
              "main_rows": sum(len(c.actions) for c in cases if not c.cohort),
              "cohort_rows": sum(len(c.actions) for c in cases if c.cohort)}
    binary, identity = build(args, out)
    report["identity"] = identity
    for case in cases:
        work = out / case.label
        work.mkdir()
        config = work / "dnsmasq.conf"
        config.write_text(f"no-hosts\nno-resolv\ncache-size={case.capacity}\nneg-ttl=120\nno-round-robin\n" + case.extra)
        commands = "\n".join(row["command"] for row in case.actions) + "\n"
        (work / "commands.txt").write_text(commands)
        result = subprocess.run([str(binary), "-C", str(config)], input=commands, capture_output=True, text=True, timeout=15)
        (work / "stdout.txt").write_text(result.stdout)
        (work / "stderr.txt").write_text(result.stderr)
        rows, errors = [], []
        try:
            assert result.returncode == 0, f"driver exit {result.returncode}"
            raw = [json.loads(line) for line in result.stdout.splitlines()]
            assert len(raw) == len(case.actions), "missing or extra command rows"
            for action, row in zip(case.actions, raw):
                row["label"] = action["label"]
                if row.get("packet") is not None:
                    row["decoded"] = decode(bytes.fromhex(row["packet"]))
                    row["ptr_case"] = ptr_case(bytes.fromhex(row["packet"]))
                errors.extend({"label": action["label"], **error} for error in check_row(row, action["expected"]))
                rows.append(row)
            assert not compare(rows, copy.deepcopy(rows))
            changed = copy.deepcopy(rows)
            negative_at = next((i for i, row in enumerate(changed) if row["op"] == "N"), None)
            if negative_at is not None:
                changed[negative_at]["exists"] ^= 1
            else:
                negative_at = next(i for i, row in enumerate(changed) if row.get("decoded", {}).get("records"))
                changed[negative_at]["decoded"]["records"][0]["ttl"] += 1
            assert compare(rows, changed) == [negative_at]
            try:
                compare(rows, rows[:-1])
            except ValueError:
                pass
            else:
                raise AssertionError("missing-row negative control failed")
        except Exception as error:
            errors.append({"error": repr(error)})
        save(work / "observations.json", rows)
        profile = {"label": case.label, "cohort": case.cohort, "expected_rows": len(case.actions),
                   "observed_rows": len(rows), "checks_failed": errors, "driver_exit": result.returncode}
        report["profiles"].append(profile)
        if errors:
            report["failures"].append(profile)
        save(out / "result.json", report)
    report["main_complete"] = sum(p["observed_rows"] for p in report["profiles"] if not p["cohort"])
    report["cohort_complete"] = sum(p["observed_rows"] for p in report["profiles"] if p["cohort"])
    save(out / "result.json", report)
    print(json.dumps({k: v for k, v in report.items() if k not in ("profiles", "identity")}))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
