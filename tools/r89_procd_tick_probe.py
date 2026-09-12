#!/usr/bin/env python3
"""Prove the supervisor's timers keep running under a pure read-only bus flood.

R88 procd F1: after the R87 idle-sleep change, procd-rs noticed an elapsed
timer tick only when poll() returned 0, so clients that kept the bus socket
readable starved every time-based action (stop deadlines, respawns, the
hardware watchdog feed). The probe starts an instance that ignores SIGTERM
with term_timeout 1 s, floods `service list` from eight loaders, deletes the
service in the middle of the flood and checks 5 s later that the child was
SIGKILLed. Original procd and the candidate must both report the child gone.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

DRIVER = r'''set -eu
side=$1
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out /tmp/initd /tmp/rcd
/sbin/ubusd >/tmp/out/bus.log 2>&1 &
for i in $(seq 1 10); do ubus list >/dev/null 2>&1 && break; sleep 1; done
bin=/sbin/procd
[ "$side" = original ] || bin=/tmp/procd-rs
"$bin" -S -I /tmp/initd -R /tmp/rcd >/tmp/out/procd.log 2>&1 &
core=$!
for i in $(seq 1 10); do ubus list service >/dev/null 2>&1 && break; sleep 1; done
ubus -S call service set "$(cat /tmp/stubborn.json)" >/dev/null
sleep 1
ubus -S call service list '{"name":"stubborn"}' >/tmp/out/before.json
pid=$(jsonfilter -i /tmp/out/before.json -e '@.stubborn.instances.i.pid')
[ -n "$pid" ]
kill -0 "$pid"
touch /tmp/busy-run
loads=
for i in 1 2 3 4 5 6 7 8; do
    (
        count=0
        while [ -e /tmp/busy-run ]; do
            ubus -S -t 15 call service list '{"name":"absent"}' >/dev/null
            count=$((count + 1))
        done
        echo "$count" >/tmp/out/load-$i.count
    ) &
    loads="$loads $!"
done
trap 'rm -f /tmp/busy-run; kill $loads 2>/dev/null || true' EXIT
sleep 1
ubus -S call service delete '{"name":"stubborn"}' >/dev/null
sleep 5
alive=0
kill -0 "$pid" 2>/dev/null && alive=1
rm -f /tmp/busy-run
wait $loads || true
core_alive=0
kill -0 "$core" 2>/dev/null && core_alive=1
ubus -S call service list >/tmp/out/after.json
total=0
for f in /tmp/out/load-*.count; do total=$((total + $(cat "$f"))); done
printf '{"pid":%s,"alive_after_5s":%s,"core_alive":%s,"load_requests":%s}\n' \
    "$pid" "$alive" "$core_alive" "$total" >/tmp/out/result.json
kill "$pid" 2>/dev/null || true
kill "$core" 2>/dev/null || true
'''

SETUP = r'''set -eu
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
mount -t sysfs sysfs "$root/sys"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
mount --bind "$root/dev/null" "$root/proc/kmsg"
exec chroot "$root" /bin/sh /tmp/driver.sh "$2"
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--sides", nargs="+", choices=("original", "candidate"),
                        default=("original", "candidate"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root on the Linux build host")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    service = {"name": "stubborn", "instances": {"i": {
        "command": ["/bin/sh", "-c", "trap '' TERM; while :; do sleep 1; done"],
        "term_timeout": 1}}}
    summary = []
    for side in args.sides:
        destination = args.output / side
        destination.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="r89-procd-tick-") as work:
            root = Path(work) / "root"
            shutil.copytree(args.rootfs, root, symlinks=True)
            (root / "tmp/out").mkdir(parents=True, exist_ok=True)
            shutil.copy2(args.candidate, root / "tmp/procd-rs")
            (root / "tmp/procd-rs").chmod(0o755)
            (root / "tmp/driver.sh").write_text(DRIVER)
            (root / "tmp/stubborn.json").write_text(json.dumps(service))
            try:
                with (destination / "driver.log").open("wb") as log:
                    run = subprocess.run(["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                                          "sh", "-c", SETUP, "sh", str(root), side],
                                         stdout=log, stderr=subprocess.STDOUT, timeout=120)
            finally:
                shutil.copytree(root / "tmp/out", destination / "raw")
            (destination / "exit").write_text(str(run.returncode) + "\n")
            run.check_returncode()
        row = {"side": side, **json.loads((destination / "raw/result.json").read_text())}
        summary.append(row)
        print(json.dumps(row), flush=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    failed = [r["side"] for r in summary if r["alive_after_5s"] or not r["core_alive"] or r["load_requests"] == 0]
    if failed:
        raise SystemExit("timers starved or supervisor died on: " + ", ".join(failed))
    (args.output / "COMPLETE").touch()


if __name__ == "__main__":
    main()
