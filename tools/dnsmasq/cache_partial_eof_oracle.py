#!/usr/bin/env python3
"""Native exact-cache primitive oracle for deterministic partial pipe EOF.

Requires run_isolated.sh even though this primitive fixture has no listener.
No Rust-generated expectations or cache/read_write replacements are used.
"""
import argparse
import json
import os
from pathlib import Path
import socket

import local_answer_diff as reference
import c_primitive_receipt
from cache_transfer_diff import CACHE_SHA, IDENTITY_SHA, NATIVE_SHA, command, save, sha

ROOT = Path(__file__).resolve().parents[2]
CASES = ["no-op-eof", "op-only-eof", "partial-length", "partial-name", "partial-address",
         "complete-record-eof", "pressure-partial-second", "partial-marker", "complete-control"]


def plan(label):
    pressure = label == "pressure-partial-second"
    prior = label in ("no-op-eof", "op-only-eof")
    address = lambda host, suffix: {"name": host, "type": "A", "class": 1,
                                    "address": f"192.0.2.{suffix}", "expiry": 220}
    seed = [{"operation": "start"},
            {"operation": "insert", "record": {"name": "alias.test", "type": "CNAME", "class": 1, "expiry": 220}},
            {"operation": "insert", "record": address("owner.test", 11)},
            {"operation": "link", "alias": "alias.test", "target": "owner.test"}, {"operation": "commit"}]
    if pressure:
        seed += [{"operation": "start"}, {"operation": "insert", "record": address("filler.test", 55)}, {"operation": "commit"}]
    if prior:
        seed += [{"operation": "start"}, {"operation": "insert", "record": address("owner.test", 31)}]
    records = [address("extra.test" if pressure else "owner.test", 21)]
    if pressure or label == "complete-record-eof":
        records += [address("second.test", 22)]
    return {"case": label, "capacity": 3 if pressure else 8, "seed_now": 100, "receive_now": 103,
            "seed": seed, "preexisting_pending": int(prior), "intended_records": records,
            "completed_wire_records": 1 if label in ("complete-record-eof", "pressure-partial-second", "partial-marker", "complete-control") else 0,
            "cut_stage": {"no-op-eof": "before-operation", "op-only-eof": "after-operation-before-record-length",
                          "partial-length": "partial-first-record-length", "partial-name": "partial-first-record-name",
                          "partial-address": "partial-first-record-address", "complete-record-eof": "after-first-record-before-second-record",
                          "pressure-partial-second": "partial-second-record-address", "partial-marker": "partial-end-sentinel",
                          "complete-control": "complete-transaction"}[label],
            "typed_correspondence": "not-representable-no-typed-sentinel" if label == "partial-marker" else "semantic-cutpoint-only-native-byte-offsets-differ",
            "observation_stages": ["before", "after-receive", "after-next-start"],
            "lookup_order": [{"name": name, "type": kind} for name, kind in [
                ("owner.test", "A"), ("alias.test", "CNAME"), ("filler.test", "A"), ("extra.test", "A"), ("second.test", "A")]],
            "cleanup": "cache_start_insert before after-next-start lookups"}


def build(args, out):
    objects = args.reference_build / "dnsmasq"
    reference.validate_reference_variant(objects)
    assert sha(objects / "dnsmasq") == NATIVE_SHA
    assert sha(objects / "cache.c") == CACHE_SHA
    assert sha(args.source_identity) == IDENTITY_SHA
    identity = json.loads(args.source_identity.read_text())
    linked = sorted(path for path in objects.glob("*.o") if path.name not in {"cache.o", "dnsmasq.o", "dnsmasq-renamed.o"})
    assert any(path.name == "util.o" for path in linked)
    sources = ([objects / (path.stem + ".c") for path in linked]
               + [objects / "dnsmasq.c", objects / "cache.c", objects / "dnsmasq.h", objects / "config.h"])
    for source in sources:
        assert sha(source) == identity["patched_files"]["src/" + source.name], source
    driver = Path(__file__).with_name("cache_partial_eof_driver.c")
    renamed = reference.rename_main(objects, out)
    deps = args.reference_build / "deps/lib"
    native = out / "native-oracle"
    flags = [*reference.REFERENCE_COPTS, '-DVERSION="2.93"', "-O2", "-Wall", "-Wextra", "-Werror",
             f"-I{objects}", f"-I{args.reference_build / 'deps/include'}"]
    command(args, out, "build", ["cc", *flags, driver, *linked, renamed, f"-L{deps}", f"-Wl,-rpath,{deps}",
                                 "-lubus", "-lubox", "-o", native])
    command(args, out, "compiler", ["cc", "--version"])
    manifest = {"scope": "unchanged exact cache.c plus full native audited object build including util.o",
                "native_reference_sha256": NATIVE_SHA, "source_identity_sha256": IDENTITY_SHA,
                "cache_source_sha256": CACHE_SHA, "sources": {path.name: sha(path) for path in sources},
                "objects": {path.name: sha(path) for path in [*linked, renamed]},
                "driver_sha256": sha(driver), "tool_sha256": sha(Path(__file__)), "oracle_sha256": sha(native),
                "libraries": {name: sha(deps / name) for name in ("libubus.so", "libubox.so")}}
    save(out / "identity.json", manifest)
    return native, manifest


def calibrate(label, trace, inject_error):
    metadata, *rows = trace
    stages = {row["stage"]: row for row in rows}
    checks = []

    def check(case, actual, expected):
        checks.append({"case": label + "/" + case, "actual": actual, "expected": expected, "pass": actual == expected})

    before, after, clean = [stages[key] for key in ("before", "after-receive", "after-next-start")]
    complete = label == "complete-control"
    prior = label in ("no-op-eof", "op-only-eof")
    prefix = label in ("complete-record-eof", "partial-marker", "pressure-partial-second")
    pressure = label == "pressure-partial-second"
    expected_pending = int(prefix or label == "no-op-eof")
    expected_inserted = 3 if pressure or complete else 2
    value = lambda suffix: [{"expiry": 220, "value": f"192.0.2.{suffix}"}]
    alias = [{"expiry": 220, "value": "owner.test"}]
    check("three-state-observations", len(rows), 3)
    check("receive-return", after["received"], int(complete))
    check("before-pending", before["pending_before_lookup"], int(prior))
    check("after-pending", after["pending_before_lookup"], expected_pending)
    check("lookup-does-not-clear-pending", after["pending_after_lookup"], expected_pending)
    check("after-inserted", after["inserted"], expected_inserted + int(inject_error))
    check("after-live-freed", after["live_freed"], int(pressure))
    expected_owner = value(21) if complete else [] if prior or prefix else value(11)
    check("after-owner", after["lookups"]["owner.test"], expected_owner)
    check("after-alias", after["lookups"]["alias.test"], [] if label == "op-only-eof" or pressure else alias)
    check("new-record-unhashed", after["lookups"]["extra.test"], [])
    check("second-record-absent", after["lookups"]["second.test"], [])
    check("after-filler", after["lookups"]["filler.test"], value(55) if pressure else [])
    check("cleanup-pending", clean["pending_after_lookup"], 0)
    check("cleanup-inserted", clean["inserted"], expected_inserted)
    check("cleanup-live-freed", clean["live_freed"], int(pressure))
    check("cleanup-owner", clean["lookups"]["owner.test"], expected_owner)
    check("cleanup-alias", clean["lookups"]["alias.test"], [] if prior or prefix else alias)
    check("no-insert-error", [row["insert_error"] for row in rows], [0, 0, 0])
    check("bounded-cut", 0 <= metadata["cut"] <= metadata["total"], True)
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--source-identity", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    out = args.out.resolve()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and [name for _, name in socket.if_nameindex()] == ["lo"]
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    save(out / "plan.json", [plan(label) for label in CASES])
    input_paths = [args.source_identity, args.reference_build / 'dnsmasq',
                   args.reference_build / 'deps/include', args.reference_build / 'deps/lib',
                   Path(__file__).with_name('cache_partial_eof_driver.c')]
    frozen_inputs = c_primitive_receipt.snapshot(input_paths)
    save(out / 'source-inputs-before.json', frozen_inputs)
    report = {"scope": "C-only native exact-cache partial anonymous-pipe EOF", "checks": [], "failures": [], "cases": []}
    try:
        binary, identity = build(args, out)
        compilers = [c_primitive_receipt.compiler_probe(out, 'native', 'cc')]
        report["identity"] = identity
        for label in CASES:
            folder = out / label
            folder.mkdir()
            config = folder / "config"
            config.write_text(f"no-hosts\nno-resolv\ncache-size={3 if label == 'pressure-partial-second' else 8}\n")
            lines = command(args, folder, "oracle", [binary, config, label, folder / "complete-wire.bin"])
            trace = [json.loads(line) for line in lines]
            save(folder / "trace.json", trace)
            report["checks"] += calibrate(label, trace, args.inject_error and label == "complete-record-eof")
            report["cases"].append({"case": label, "metadata": trace[0], "observations": len(trace) - 1,
                                     "trace_sha256": sha(folder / "trace.json"), "raw_sha256": sha(folder / "complete-wire.bin")})
    except Exception as error:
        report["failures"].append(repr(error))
    report["passed"] = sum(check["pass"] for check in report["checks"])
    report["failed"] = sum(not check["pass"] for check in report["checks"]) + len(report["failures"])
    save(out / "result.json", report)
    if report['failed'] == 0:
        c_primitive_receipt.freeze(out, 'cache-partial-eof', args.source_identity, frozen_inputs,
                                   compilers, [out / 'native-oracle'], True)
    print(json.dumps(report))
    return int(bool(report["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
