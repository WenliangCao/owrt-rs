#!/usr/bin/env python3
"""Verify failed passwd requests reap their direct child in private namespaces.

Run on Linux as root with an exact-image rootfs and the candidate rpcd binary.
The nonexistent synthetic account makes passwd close its input early; no real
password is changed. All processes and files belong to disposable namespaces.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from r92_compat_probe import Fixture, string

def inner(root, side):
    fixture = Fixture(root, side, "rpcd")
    try:
        fixture.start_bus()
        fixture.start_subject(obj="rpc-sys")
        client = fixture.connect()
        obj = client.lookup("rpc-sys")
        # Positive control: changing the synthetic sandbox root password must
        # still complete normally; the physical device is never contacted.
        success_code, _ = client.invoke(obj, "password_set", string("user", "root")
                                        + string("password", "Synthetic-Review-7-Only"))
        observations = []
        for _ in range(5):
            code, _ = client.invoke(obj, "password_set", string("user", "v030-no-such-account")
                                    + string("password", "synthetic-test-value"))
            time.sleep(0.1)
            children = Path(f"/proc/{fixture.subject.pid}/task/{fixture.subject.pid}/children").read_text().split()
            states = [Path(f"/proc/{pid}/stat").read_text().split()[2] for pid in children]
            observations.append({"code": code, "children": states})
        observed = {"side": side, "identity": fixture.checks["identity"],
                    "alive": fixture.subject.poll() is None, "success_code": success_code, "requests": observations}
        (fixture.output / "result.json").write_text(json.dumps(observed, indent=2) + "\n")
        print(json.dumps(observed), flush=True)
        assert observed["identity"]["passed"] and observed["alive"] and success_code == 0
        assert all(item == {"code": 9, "children": []} for item in observations), observations
    finally:
        fixture.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        return inner(Path(sys.argv[2]), sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--sides", nargs="+", choices=["original", "candidate"], default=["original", "candidate"])
    args = parser.parse_args()
    assert os.geteuid() == 0 and sys.platform == "linux"
    args.output.mkdir(parents=True, exist_ok=False)
    failures = 0
    for side in args.sides:
        for repeat in range(4):
            with tempfile.TemporaryDirectory(prefix="rpcd-passwd-") as temporary:
                root = Path(temporary) / "root"
                shutil.copytree(args.rootfs, root, symlinks=True)
                for directory in ["proc", "sys", "dev", "tmp/out", "tmp/run/ubus", "tmp/lock", "tmp/state"]:
                    (root / directory).mkdir(parents=True, exist_ok=True)
                shutil.copy2(args.binary, root / "tmp/rpcd-rs")
                result = subprocess.run([
                    "timeout", "-k", "3", "40", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                    sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side,
                ], capture_output=True)
                destination = args.output / f"{side}-{repeat}"
                shutil.copytree(root / "tmp/out", destination)
                (destination / "driver.log").write_bytes(result.stdout + result.stderr)
                print(side, repeat, result.returncode, result.stdout.decode(), flush=True)
                failures += result.returncode != 0
    assert failures == 0, f"{failures} failed child-reaping comparisons; raw results retained"


if __name__ == "__main__":
    main()
