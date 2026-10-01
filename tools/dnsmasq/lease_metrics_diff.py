#!/usr/bin/env python3
"""Compare ordered lease counter snapshots with exact C lease.c and objects.

No sockets are opened. Configurations, leases, inputs, logs and executables
stay in private/. This checks the store, not ubus publication or all DHCP
message counters. C read_leases and lease_prune supply restoration expectations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess

import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]
LEASE_SHA256 = "4260039af27b40084cbe6dbbae2bb9417fa3a91806ea53f3f6bdd20234cad763"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command, folder, name, input=None):
    result = subprocess.run(list(map(str, command)), input=input, text=True, capture_output=True)
    (folder / f"{name}.json").write_text(json.dumps({
        "command": list(map(str, command)), "exit": result.returncode,
        "stdout": result.stdout, "stderr": result.stderr,
    }, indent=2) + "\n")
    result.check_returncode()
    return result.stdout.splitlines()


def build(reference, out):
    obj = reference / "dnsmasq"
    local_answer_diff.validate_reference_variant(obj)
    assert digest(obj / "lease.c") == LEASE_SHA256
    renamed = local_answer_diff.rename_main(obj, out)
    objects = sorted(p for p in obj.glob("*.o") if p.name not in ("lease.o", "dnsmasq.o", "dnsmasq-renamed.o"))
    deps = reference / "deps/lib"
    c = out / "c-oracle"
    execute(["cc", *local_answer_diff.REFERENCE_COPTS, "-O2", "-Wall", "-Wextra", "-Werror",
             f"-I{obj}", f"-I{reference / 'deps/include'}",
             ROOT / "tools/dnsmasq/lease_metrics_driver.c", *objects, renamed,
             f"-L{deps}", f"-Wl,-rpath,{deps}", "-lubus", "-lubox", "-o", c], out, "build-c")
    execute(["cargo", "+1.98.1", "build", "--manifest-path", ROOT / "components/dnsmasq/Cargo.toml", "--lib"], out, "build-lib")
    target = ROOT / "components/dnsmasq/target/debug"
    rust = out / "rust-probe"
    execute(["rustc", "+1.98.1", "--edition=2021", "-O", ROOT / "tools/dnsmasq/lease_metrics_probe.rs",
             "--extern", f"dnsmasq_rs={target / 'libdnsmasq_rs.rlib'}", "-L", f"dependency={target / 'deps'}",
             "-o", rust], out, "build-rust")
    identity = {"reference_source": {name: digest(obj / name) for name in ("lease.c", "dnsmasq.h", "config.h")},
                "reference_objects": {path.name: digest(path) for path in [*objects, renamed]},
                "c_oracle": digest(c), "rust_probe": digest(rust),
                "product_lease_source": digest(ROOT / "components/dnsmasq/src/dhcp/lease.rs"),
                "tools": {name: digest(ROOT / "tools/dnsmasq" / name) for name in (
                    "lease_metrics_diff.py", "lease_metrics_driver.c", "lease_metrics_probe.rs")}}
    (out / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    return c, rust


def corpus(out):
    yield "calibration", ["S 1", "A 1", "E 1 120 100", "A 2", "P - 219", "P - 220", "P - 221", "H", "Q"]
    yield "zero-address-and-unknown-target", ["S 2", "A 0", "E 0 4294967295 100", "A 1",
        "E 1 120 100", "P 999 100", "P 0 100", "P 0 100", "H", "P - 220", "Q"]
    yield "renewal-infinite-rollback", ["S 3", "A 1", "E 1 120 100", "E 1 400 120", "H",
        "P - 220", "E 1 4294967295 220", "P - 100000", "E 1 120 100", "P - 99", "P - 220", "Q"]
    for label, records, now in [
        ("restore-live-expired-infinite", [(219, "192.0.2.1"), (220, "192.0.2.2"), (221, "192.0.2.3"), (0, "192.0.2.4")], 220),
        ("restore-zero-expired", [(220, "0.0.0.0"), (221, "192.0.2.1")], 220),
        ("restore-zero-live", [(221, "0.0.0.0"), (220, "192.0.2.1")], 220),
        ("restore-zero-infinite", [(0, "0.0.0.0")], 220),
    ]:
        lease = out / f"{label}.leases"
        lease.write_text("".join(f"{expiry} 02:00:00:00:00:{i+1:02x} {address} host{i} *\n"
                                 for i, (expiry, address) in enumerate(records)))
        yield label, [f"S {len(records)}", f"R {now} {lease}", "H", "P - 221", "P 0 221", "Q"]
    rng = random.Random(20261001)
    for index in range(40):
        commands = [f"S {rng.choice([0, 1, 2, 5, 16])}"]
        for address in range(36):
            commands += [f"A {address}", f"E {address} {rng.choice([0, 1, 120, 300, 4294967295])} {rng.randrange(90, 400)}"]
            if rng.randrange(3) == 0:
                commands.append(f"P {rng.choice(['-', str(rng.randrange(address + 2))])} {rng.randrange(80, 800)}")
            if rng.randrange(7) == 0:
                commands.append("H")
        commands += ["P - 1000000", "H", "Q"]
        yield f"seeded-{index:02}", commands


def differences(expected, actual):
    assert len(expected) == len(actual), "missing observations"
    return [{"index": i, "c": c, "rust": r} for i, (c, r) in enumerate(zip(expected, actual)) if c != r]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-counter-mismatch", action="store_true")
    args = parser.parse_args()
    assert os.name == "posix"
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private")
    out.mkdir(parents=True, exist_ok=False)
    # Calibrate the same comparator before compiling/running either product.
    assert differences(["Q 1 1 0 0 1"], ["Q 1 1 0 0 1"]) == []
    assert len(differences(["Q 1 1 0 0 1"], ["Q 1 0 0 0 1"])) == 1
    c, rust = build(args.reference_build.resolve(), out)
    config = out / "oracle.conf"
    config.write_text("no-resolv\nno-hosts\ncache-size=0\n")
    report = {"status": "failed", "scope": "ordered lease-store operations and counters; not daemon/ubus integration",
              "cases": 0, "observations": 0, "matched": 0, "mismatches": 0, "rows": [],
              "calibration": {"equal": 1, "wrong_counter_rejected": 1}, "injected": args.inject_counter_mismatch}
    for index, (label, commands) in enumerate(corpus(out)):
        folder = out / label
        folder.mkdir()
        wire = "\n".join(commands) + "\n"
        (folder / "input.txt").write_text(wire)
        expected = execute([c, "-C", config], folder, "c", wire)
        actual = execute([rust], folder, "rust", wire)
        assert len(expected) == len(actual) == len(commands)
        if index == 0:
            assert expected == ["S 1 0 0 0 0", "A 1 1 0 0 1", "E 1 1 0 0 1", "A 0 1 0 0 1",
                "P 0 1 0 0 1", "P 1 1 1 0 0", "P 0 1 1 0 0", "H 1 1 1 0 0", "Q 1 1 1 0 0"]
            if args.inject_counter_mismatch:
                fields = actual[-1].split(); fields[2] = str(int(fields[2]) + 1)
                actual[-1] = " ".join(fields)
                (folder / "injected-output.txt").write_text("\n".join(actual) + "\n")
        mismatch = differences(expected, actual)
        row = {"case": label, "observations": len(commands), "differences": mismatch}
        (folder / "comparison.json").write_text(json.dumps(row, indent=2) + "\n")
        report["rows"].append(row)
        report["cases"] += 1
        report["observations"] += len(commands)
        report["matched"] += len(commands) - len(mismatch)
        report["mismatches"] += len(mismatch)
    report["status"] = "passed" if report["mismatches"] == 0 else "failed"
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "rows"}))
    return int(report["mismatches"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
