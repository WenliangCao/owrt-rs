#!/usr/bin/env python3
"""C-first five-case dhcp-fqdn default-domain --test contract."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess

from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import digest

ROOT = Path(__file__).resolve().parents[2]
CASES = [
    ("plain", "", True),
    ("fqdn-no-domain", "dhcp-fqdn\n", False),
    ("conditional-control", "domain=range.test,127.0.0.0/8\n", True),
    ("fqdn-conditional-only", "domain=range.test,127.0.0.0/8\ndhcp-fqdn\n", False),
    ("fqdn-default-domain", "domain=leases.test\ndhcp-fqdn\n", True),
]


def run(binary, out, directives):
    out.mkdir()
    config = out / "dnsmasq.conf"
    config.write_text("no-hosts\nno-resolv\n" + directives)
    result = subprocess.run([str(binary), "--test", "-C", str(config)], capture_output=True, text=True, timeout=3)
    raw = {"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    (out / "result.json").write_text(json.dumps(raw, indent=2) + "\n")
    return result.returncode == 0


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("missing or reordered cases")
    return [left["label"] for left, right in zip(expected, actual) if left != right]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-binary", type=Path)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(CASES, indent=2) + "\n")
    report = {"reference": reference, "tool_sha256": digest(__file__),
              "rust_sha256": None if args.rust is None else digest(args.rust), "c": [], "rust": [], "failures": []}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    for label, directives, accepted in CASES:
        work = out / label
        work.mkdir()
        try:
            result = run(c, work / "c", directives)
            report["c"].append({"label": label, "accepted": result})
            assert result == accepted, (label, result, accepted)
        except Exception as error:
            report["failures"].append({"case": label, "stage": "C", "error": repr(error)})
        save()
    if not report["failures"]:
        expected = report["c"]
        assert not compare(expected, copy.deepcopy(expected))
        changed = copy.deepcopy(expected)
        changed[0]["accepted"] = not changed[0]["accepted"]
        assert compare(expected, changed) == [CASES[0][0]]
        try:
            compare(expected, expected[:-1])
        except ValueError:
            pass
        else:
            raise AssertionError("missing case accepted")
        if args.rust is not None:
            for label, directives, _ in CASES:
                accepted = run(args.rust.resolve(), out / label / "rust", directives)
                report["rust"].append({"label": label, "accepted": accepted})
        report["differences"] = [] if args.rust is None else compare(expected, report["rust"])
    report["c_calibrated"] = len(report["c"]) if not report["failures"] else 0
    report["compared"] = len(report["rust"])
    save()
    print(json.dumps(report))
    return int(bool(report["failures"] or report.get("differences")))


if __name__ == "__main__":
    raise SystemExit(main())
