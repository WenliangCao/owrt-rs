#!/usr/bin/env python3
"""Real raw-ICMP C/Rust checks in a fresh build-host network namespace only."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import time


def fd_count(pid: int) -> int:
    return len(list(Path(f"/proc/{pid}/fd").iterdir()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.uname().sysname == "Linux"
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert not Path("/etc/openwrt_release").exists(), "build host only"
    # /sys may still be a sysfs mount from the caller's namespace. rtnetlink
    # queried by ip reads the current network namespace rather than that mount.
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"], text=True))
    assert {entry["ifname"] for entry in links} == {"lo"}, "fresh namespace required"
    args.out.mkdir(parents=True, exist_ok=False)
    for command in [["ip", "link", "add", "probe0", "type", "dummy"],
                    ["ip", "addr", "add", "192.0.2.1/24", "dev", "probe0"],
                    ["ip", "link", "set", "probe0", "up"]]:
        subprocess.run(command, check=True)
    records = []
    checks = []

    def check(name, actual, expected):
        checks.append({"case": name, "actual": actual, "expected": expected, "pass": actual == expected})

    # Calibrate both counter outcomes before interpreting live observations.
    check("calibration-pass", "A 7", "A 7")
    check("calibration-fail", "I", "A 7")
    assert sum(row["pass"] for row in checks) == 1
    assert sum(not row["pass"] for row in checks) == 1
    checks.clear()
    try:
        for implementation, binary in [("c", args.c), ("rust", args.rust)]:
            process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=(args.out / f"{implementation}.stderr").open("wb"), text=True, bufsize=1)
            windows = []

            def request(command):
                start = time.monotonic()
                process.stdin.write(command + "\n"); process.stdin.flush()
                peak = 0
                while True:
                    peak = max(peak, fd_count(process.pid))
                    if select.select([process.stdout], [], [], 0.02)[0]: break
                    if time.monotonic() - start > 8: raise RuntimeError("probe exceeded bounded wait")
                output = process.stdout.readline().strip()
                if not output: raise RuntimeError("missing probe output")
                row = {"command": command, "output": output, "seconds": time.monotonic() - start,
                       "fd_after": fd_count(process.pid), "fd_peak": peak}
                windows.append(row)
                return row

            try:
                for address in ["127.0.0.1", "192.0.2.1"]:
                    row = request(f"N {address}")
                    check(f"{implementation}-occupied-{address}", row["output"], "I")
                baseline = windows[-1]["fd_after"]
                if implementation == "rust":
                    row = request("S 192.0.2.2")
                    check("rust-cancellation", row["output"], "E Interrupted")
                    check("rust-cancellation-bound", row["seconds"] < 0.75, True)
                row = request("N 192.0.2.2")
                check(f"{implementation}-unused", row["output"], "A 7")
                check(f"{implementation}-full-timeout", 2.5 <= row["seconds"] <= 5.0, True)
                row = request("N 192.0.2.2")
                check(f"{implementation}-cached", row["output"], "A 7")
                check(f"{implementation}-cache-no-wait", row["seconds"] < 0.5, True)
                for _ in range(32):
                    row = request("N 192.0.2.1")
                    check(f"{implementation}-repeat-{len(windows)}", row["output"], "I")
                check(f"{implementation}-no-fd-growth", all(row["fd_after"] == baseline for row in windows[1:]), True)
            finally:
                process.stdin.close()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                    check(f"{implementation}-forced-kill", True, False)
                (args.out / f"{implementation}.windows.json").write_text(json.dumps(windows, indent=2) + "\n")
            check(f"{implementation}-exit", process.returncode, 0)
            check(f"{implementation}-exit-resources", Path(f"/proc/{process.pid}").exists(), False)
            records.append({"implementation": implementation, "pid": process.pid,
                            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                            "windows": windows, "exit": process.returncode})

            denied = subprocess.run(["setpriv", "--bounding-set=-net_raw", "--inh-caps=-all", "--ambient-caps=-all", "--", str(binary)],
                input="N 192.0.2.1\nN 192.0.2.1\n", text=True, capture_output=True, timeout=5)
            (args.out / f"{implementation}.denied.stdout").write_text(denied.stdout)
            (args.out / f"{implementation}.denied.stderr").write_text(denied.stderr)
            check(f"{implementation}-permission-exit", denied.returncode, 0)
            # Record the explicit safety-policy difference; it is not a C/Rust
            # equality success. C treats raw-socket failure as an unused IP.
            expected = ["A 7", "A 7"] if implementation == "c" else ["E PermissionDenied", "E PermissionDenied"]
            check(f"{implementation}-permission-policy", denied.stdout.splitlines(), expected)

            failed = subprocess.run([str(binary)], input="N 203.0.113.1\n", text=True,
                                    capture_output=True, timeout=5)
            (args.out / f"{implementation}.no-route.stdout").write_text(failed.stdout)
            (args.out / f"{implementation}.no-route.stderr").write_text(failed.stderr)
            check(f"{implementation}-send-error-exit", failed.returncode, 0)
            check(f"{implementation}-send-error-policy", failed.stdout.strip(),
                  "A 7" if implementation == "c" else "E NetworkUnreachable")
    except Exception as error:
        checks.append({"case": "runner-exception", "actual": repr(error), "expected": "no exception", "pass": False})
        raise
    finally:
        result = {"checks": checks, "success_count": sum(row["pass"] for row in checks),
                  "error_count": sum(not row["pass"] for row in checks), "runs": records,
                  "intentional_difference": "C caches raw-socket/send errors as available; Rust reports error and does not cache",
                  "scope": "isolated dummy/loopback ICMP dependency; no full DHCP service or physical router claim"}
        (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key:value for key,value in result.items() if key not in ("checks", "runs")}))
    return int(result["error_count"] != 0)


if __name__ == "__main__": raise SystemExit(main())
