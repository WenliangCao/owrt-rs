#!/usr/bin/env python3
"""Compare hotplug include, recursion and caching in private Linux namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile

from check_procd_static import wait_for


def run(rootfs, candidate, side, repeat, output):
    with tempfile.TemporaryDirectory(prefix="procd-include-") as temporary:
        root = Path(temporary) / "root"
        shutil.copytree(rootfs, root, symlinks=True)
        (root / "tmp").mkdir(exist_ok=True)
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        if side == "rust":
            shutil.copy2(candidate, root / "sbin/procd")
        def command(tag):
            return ["exec", "/bin/sh", "-c", f"echo {tag} >> /tmp/actions"]
        (root / "tmp/rules.json").write_text(json.dumps([
            ["include", "/tmp/missing.json"], ["include", "/tmp/child.json"],
            ["include", "/tmp/child.json"], command("main")]))
        child_rules = root / "tmp/child.json"
        child_rules.write_text(json.dumps([command("child"),
            ["include", "/tmp/rules.json"], command("child-after"),
            ["return"], command("unreachable")]))
        with (output / f"{side}-{repeat}.log").open("w") as log:
            child = subprocess.Popen(["chroot", str(root), "/sbin/procd", "-h", "/tmp/rules.json"],
                                     stdout=log, stderr=log)
            try:
                with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 15) as sender:
                    sender.bind((0, 0))
                    def send():
                        assert child.poll() is None, "hotplug daemon exited"
                        try:
                            sender.sendto(b"ACTION=add\0SUBSYSTEM=test\0", (child.pid, 0))
                            return True
                        except ConnectionRefusedError:
                            return False
                    actions = root / "tmp/actions"
                    wait_for(send)
                    wait_for(lambda: actions.exists() and "main" in actions.read_text())
                    first = actions.read_text().splitlines()
                    child_rules.write_text(json.dumps([command("changed")]))
                    assert send()
                    wait_for(lambda: actions.read_text().splitlines().count("main") == 2)
                    return {"first": first, "all": actions.read_text().splitlines(),
                            "alive": child.poll() is None}
            finally:
                child.kill()
                child.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("PROCD_INCLUDE_PRIVATE_NAMESPACE") != "1":
        return subprocess.call(["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
            "python3", str(Path(__file__).resolve()), *os.sys.argv[1:]],
            env={**os.environ, "PROCD_INCLUDE_PRIVATE_NAMESPACE": "1"})
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    args.output.mkdir(parents=True)
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = {"artifacts": {"c": sha(args.rootfs / "sbin/procd"), "rust": sha(args.candidate)}, "runs": []}
    for repeat in range(1, 5):
        sides = {side: run(args.rootfs, args.candidate, side, repeat, args.output) for side in ("c", "rust")}
        assert sides["c"]["first"] == ["child", "child-after", "main"], sides
        assert sides["c"]["all"] == sides["c"]["first"] * 2, sides
        report["runs"].append({"repeat": repeat, "sides": sides, "passed": sides["c"] == sides["rust"]})
    report["passed"] = all(row["passed"] for row in report["runs"])
    (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
