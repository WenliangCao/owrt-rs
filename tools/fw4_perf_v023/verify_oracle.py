#!/usr/bin/env python3
"""Oracle-only fixture/ABI checks: one functional command per side/scenario.

Recorded timings are not compared and never screen production candidates.
This verifies the driver that the parent will schedule once on the router.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.uname().sysname == "Linux"
    args.bundle = args.bundle.resolve()
    args.output = args.output.resolve()
    log = args.output.with_suffix(".driver.log")
    with log.open("xb") as output:
        process = subprocess.Popen(["/bin/sh", str(args.bundle / "driver.sh"), str(args.rootfs.resolve()),
                                    str(args.bundle), str(args.output)], stdout=output, stderr=output)
        rows = []
        try:
            def wait(path):
                deadline = time.monotonic() + 20
                while not path.exists():
                    assert process.poll() is None, log.read_text()
                    assert time.monotonic() < deadline, str(path)
                    time.sleep(0.01)

            wait(args.output / "READY")
            parent = (args.output / "parent-netns.txt").read_text()
            child = (args.output / "netns.txt").read_text()
            assert parent != child
            for scene in ("unchanged", "changed", "start", "check", "print"):
                for side in ("A", "B"):
                    label = f"functional-{scene}-{side}"
                    with (args.output / "control").open("w") as control:
                        control.write(f"{scene} {side} {label}\n")
                    wait(args.output / label / "COMPLETE")
                    result = json.loads((args.output / label / "measurement.json").read_text())
                    assert result["exit"] == 0 and result["wall_ns"] > 0 and result["cpu_us"] > 0
                    assert result["cpu_us"] == result["user_us"] + result["system_us"]
                    rows.append({"scene": scene, "side": side, "passed": True})
            with (args.output / "control").open("w") as control:
                control.write("stop\n")
            assert process.wait(timeout=5) == 0, log.read_text()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        (args.output / "functional-results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(json.dumps({"functional_commands": len(rows), "passed": all(r["passed"] for r in rows)}))


if __name__ == "__main__":
    main()
