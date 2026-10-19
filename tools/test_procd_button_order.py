#!/usr/bin/env python3
"""Compare button queue ordering in disposable mount/net/PID namespaces.

Send parsed-shape uevents over a private netlink socket to the exact image's
procd and the candidate; no physical button, router, or host sysfs is used.
"""
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
import time


def wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("button fixture precondition timed out")
        time.sleep(0.02)


def run_case(rootfs, candidate, side, release, output, repeat):
    with tempfile.TemporaryDirectory(prefix="procd-button-") as temporary:
        root = Path(temporary) / "root"
        shutil.copytree(rootfs, root, symlinks=True)
        (root / "tmp").mkdir(exist_ok=True)
        (root / "dev").mkdir(exist_ok=True)
        null = root / "dev/null"
        null.unlink(missing_ok=True)
        os.mknod(null, stat.S_IFCHR | 0o666, os.makedev(1, 3))
        if side == "rust":
            shutil.copy2(candidate, root / "sbin/procd")
        (root / "tmp/rules.json").write_text('[["button", "/bin/sh", "/tmp/button.sh"]]\n')
        (root / "tmp/button.sh").write_text('''#!/bin/sh
echo "$ACTION" >> /tmp/actions
if [ "$ACTION" = pressed ]; then
    touch /tmp/started
    while [ ! -e /tmp/finish ]; do sleep 0.02; done
    exit 1
fi
exit 0
''')
        with (output / f"{side}-{release}-{repeat}.log").open("w") as log:
            child = subprocess.Popen(["chroot", str(root), "/sbin/procd", "-h", "/tmp/rules.json"],
                                     stdout=log, stderr=log)
            with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 15) as sender:
                sender.bind((0, 0))
                def send(action):
                    sender.sendto(f"ACTION={action}\0BUTTON=reset\0SUBSYSTEM=button\0".encode(),
                                  (child.pid, 0))
                try:
                    # A successful send proves the daemon bound its private socket.
                    def start():
                        if child.poll() is not None:
                            raise AssertionError("hotplug daemon exited before listening")
                        try:
                            send("pressed")
                            return True
                        except ConnectionRefusedError:
                            return False
                    wait_for(start)
                    wait_for(lambda: (root / "tmp/started").exists())
                    if release:
                        send("released")
                        # Both event loops get time to queue release before press exits.
                        time.sleep(0.2)
                    (root / "tmp/finish").touch()
                    if release:
                        wait_for(lambda: "released" in (root / "tmp/actions").read_text())
                    time.sleep(1.5)
                    actions = (root / "tmp/actions").read_text().splitlines()
                    return {"side": side, "release": release, "repeat": repeat,
                            "alive": child.poll() is None, "actions": actions}
                finally:
                    child.kill()
                    child.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Always isolate ourselves before starting a daemon or sending uevents.
    if os.environ.get("PROCD_BUTTON_PRIVATE_NAMESPACE") != "1":
        subprocess.run(["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                        "python3", str(Path(__file__).resolve()), *os.sys.argv[1:]],
                       env={**os.environ, "PROCD_BUTTON_PRIVATE_NAMESPACE": "1"}, check=True)
        return
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    args.output.mkdir(parents=True, exist_ok=True)
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in
              [("stock", args.rootfs / "sbin/procd"), ("candidate", args.candidate)]}
    (args.output / "artifacts.json").write_text(json.dumps(hashes, indent=2) + "\n")
    rows = [run_case(args.rootfs, args.candidate, side, release, args.output, repeat)
            for release in (False, True) for side in ("c", "rust") for repeat in range(4)]
    (args.output / "result.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(json.dumps(rows, indent=2))
    for row in rows:
        expected = ["pressed", "released"] if row["release"] else ["pressed", "timeout"]
        assert row["alive"] and row["actions"] == expected, row


if __name__ == "__main__":
    main()
