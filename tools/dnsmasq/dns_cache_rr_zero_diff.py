#!/usr/bin/env python3
"""Independent QTYPE-zero cache-rr C anchor, separate from the forward gate."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess

from dns_cache_rr_diff import ROOT, calibrate, compare, run_service
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, digest


def profiles():
    # A newline keeps the base fixture's truthy-option branch while writing
    # an explicit empty cache-rr value, not omitting the directive.
    return [{"label": label, "option": option, "kind": 0, "shape": "opaque",
             "inserts": inserts, "group": "forward"}
            for label, option, inserts in (("zero", "0", 0), ("empty", "\n", 0),
                                           ("any", "ANY", 1))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", required=True, type=Path)
    parser.add_argument("--c-binary", type=Path)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    if args.inject_error and args.rust is None:
        parser.error("negative control requires Rust")
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(profiles(), indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-cache-rr-zero", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native,
              "tool_sha256": digest(__file__),
              "base_tool_sha256": digest(Path(__file__).with_name("dns_cache_rr_diff.py")),
              "rust_sha256": None if args.rust is None else digest(args.rust),
              "c_only": args.rust is None, "injected_error": args.inject_error,
              "profiles": [], "failures": []}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    expected_rows = []
    for profile in profiles():
        work = out / profile["label"]
        work.mkdir()
        try:
            rows = run_service(args, c, "C", profile, work / "c")
            calibrate(rows, profile)
            expected_rows.append((profile, rows, work))
        except Exception as error:
            report["failures"].append({"profile": profile, "stage": "C-service", "error": repr(error)})
        save()
    if not report["failures"]:
        for index, (profile, expected, work) in enumerate(expected_rows):
            try:
                differences = []
                if args.rust is not None:
                    actual = run_service(args, args.rust.resolve(), "Rust", profile, work / "rust")
                    if args.inject_error and index == 0:
                        actual = copy.deepcopy(actual)
                        actual[0]["cached"] = not actual[0]["cached"]
                    differences = compare(expected, actual)
                report["profiles"].append({"profile": profile, "observations": len(expected),
                                           "paired": args.rust is not None, "differences": differences})
            except Exception as error:
                report["failures"].append({"profile": profile, "stage": "Rust-service", "error": repr(error)})
            save()
    report["c_service_calibrated"] = sum(len(rows) for _, rows, _ in expected_rows)
    report["compared"] = sum(row["observations"] for row in report["profiles"] if row["paired"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    save()
    print(json.dumps(report))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
