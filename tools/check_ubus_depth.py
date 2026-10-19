#!/usr/bin/env python3
"""Check bounded blob conversion against exact C, using prebuilt Linux probes.

Build the Rust probe against the release owrt-ubus rlib and ubus_depth_check.c
against the matching libubox blob.c/blobmsg.c/blobmsg_json.c and libjson-c.
This runner changes only its output report and does not contact a router.
"""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_STACK, (8 * 1024 * 1024, 8 * 1024 * 1024))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--c", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    rows = []
    for depth in (63, 64, 65, 100_000):
        for repeat in range(1, 5):
            control = subprocess.run([str(args.c), str(depth)], capture_output=True,
                                     timeout=30, preexec_fn=limits)
            rows.append(dict(mode="c", depth=depth, repeat=repeat,
                             returncode=control.returncode,
                             stdout_sha256=hashlib.sha256(control.stdout).hexdigest(),
                             stderr=control.stderr.decode(errors="replace")))
            for mode in ("tree", "direct"):
                result = subprocess.run([str(args.rust), mode, str(depth)], capture_output=True,
                                        timeout=30, preexec_fn=limits)
                passed = (result.returncode == control.returncode == 0 and result.stdout == control.stdout
                          if depth <= 64 else
                          result.returncode == 2 and not result.stdout
                          and result.stderr == b"blobmsg nesting exceeds 64 containers\n")
                rows.append(dict(mode=mode, depth=depth, repeat=repeat,
                                 returncode=result.returncode, passed=passed,
                                 stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                                 stderr=result.stderr.decode(errors="replace")))
    # The deep C crash is an intentional documented divergence, not the green
    # criterion. All Rust conversions must complete with output or a normal error.
    passed = all(row.get("passed", True) for row in rows)
    args.output.write_text(json.dumps(dict(passed=passed, stack_bytes=8 * 1024 * 1024,
                                          results=rows), indent=2) + "\n")
    print(json.dumps(dict(passed=passed, rust_cases=sum("passed" in row for row in rows))))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
