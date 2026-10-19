#!/usr/bin/env python3
"""Compare file.md5 in private exact-image namespaces under a memory limit.

Run on Linux as root. Only disposable rootfs copies and their child processes
are changed. Both the original C rpcd and candidate must return the known digest
and answer a subsequent request under the same 128 MiB address-space limit.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import time

from r92_compat_probe import Fixture, integer, message, response_data, string

EXPECTED = {
    "small": "7265f4d211b56873a381d321f586e4a9",  # 1024 x 'x'
    "large": "7f614da9329cd3aebf59b91aadc30bf0",  # 64 MiB zeroes
}


def inner(root, side):
    fixture = Fixture(root, side, "rpcd")
    try:
        with (root / "tmp/md5-large").open("wb") as output:
            output.truncate(64 * 1024 * 1024)
        (root / "tmp/md5-small").write_bytes(b"x" * 1024)
        fixture.start_bus()
        fixture.start_subject(obj="file")
        resource.prlimit(fixture.subject.pid, resource.RLIMIT_AS,
                         (128 * 1024 * 1024, 128 * 1024 * 1024))
        client = fixture.connect()
        session, file_object = client.lookup("session"), client.lookup("file")
        code, replies = client.invoke(session, "create", integer("timeout", 30))
        assert code == 0
        sid = response_data(replies)[0][b"ubus_rpc_session"]
        session_arg = string("ubus_rpc_session", sid)
        assert client.invoke(file_object, "md5", session_arg + string("path", "/tmp/md5-small"))[0] == 6
        pair = message("", 1, string("", "/tmp/md5-*") + string("", "read"))
        assert client.invoke(session, "grant", session_arg + string("scope", "file")
                             + message("objects", 1, pair))[0] == 0
        observed = {"side": side, "identity": fixture.checks["identity"]}
        for name in EXPECTED:
            try:
                code, replies = client.invoke(file_object, "md5", session_arg + string("path", "/tmp/md5-" + name))
                data = response_data(replies)
                observed[name] = {"code": code, "md5": data[0].get(b"md5", b"").decode() if data else None}
            except Exception as error:
                observed[name] = {"error": str(error)}
        time.sleep(0.05)
        observed["alive"] = fixture.subject.poll() is None
        observed["exit"] = fixture.subject.poll()
        if observed["alive"]:
            observed["followup"] = client.invoke(file_object, "md5", session_arg + string("path", "/tmp/md5-small"))[0]
            status = Path(f"/proc/{fixture.subject.pid}/status").read_text()
            observed["vmhwm_kib"] = int(next(line.split()[1] for line in status.splitlines() if line.startswith("VmHWM:")))
        (fixture.output / "result.json").write_text(json.dumps(observed, indent=2) + "\n")
        print(json.dumps(observed), flush=True)
        assert observed["identity"]["passed"]
        assert observed["alive"] and observed.get("followup") == 0, "rpcd stopped serving"
        for name, digest in EXPECTED.items():
            assert observed[name] == {"code": 0, "md5": digest}, observed[name]
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
            with tempfile.TemporaryDirectory(prefix="rpcd-md5-") as temporary:
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
    assert failures == 0, f"{failures} failed memory-limit comparisons; raw results retained"


if __name__ == "__main__":
    main()
