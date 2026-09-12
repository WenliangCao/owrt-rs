#!/usr/bin/env python3
"""Exercise procd maintenance under continuous requests in disposable namespaces.

SIGSTOP holds the supervisor while 32 children exit, forcing coalesced SIGCHLD
delivery on resume. Both exact-image procd and the candidate must drain all
statuses and final log lines, expire a watchdog, update hotplug objects and
release descriptors. Request counts prove activity; they are not a benchmark.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def check_final_logs(before, messages):
    """Each child must keep its own last line and its original pid tag."""
    instances = before["burst"]["instances"]
    expected = sorted((int(instances[f"i{i}"]["pid"]), i) for i in range(32))
    observed = []
    for line in messages.splitlines():
        match = re.search(r"\bsh\[(\d+)\]: r85-tail-(\d+)$", line)
        if match:
            observed.append(tuple(map(int, match.groups())))
    assert sorted(observed) == expected, "missing, duplicate or wrongly attributed final log line"


DRIVER = r'''set -eu
side=$1
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out /tmp/initd /tmp/rcd
/sbin/ubusd >/tmp/out/bus.log 2>&1 &
for i in $(seq 1 10); do ubus list >/dev/null 2>&1 && break; sleep 1; done
/sbin/logd -S 128 >/tmp/out/logd.log 2>&1 &
bin=/sbin/procd
[ "$side" = original ] || bin=/tmp/procd-rs
"$bin" -S -I /tmp/initd -R /tmp/rcd >/tmp/out/procd.log 2>&1 &
core=$!
for i in $(seq 1 10); do ubus list service >/dev/null 2>&1 && break; sleep 1; done
ubus list service >/dev/null
before=$(ls /proc/$core/fd | wc -l)
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
trap 'rm -f /tmp/busy-run; kill -CONT "$core" 2>/dev/null || true; kill $loads 2>/dev/null || true' EXIT
ubus -S -t 15 call service set "$(cat /tmp/burst.json)" >/dev/null
ubus -S call service list '{"name":"burst"}' >/tmp/out/before.json
[ "$(jsonfilter -i /tmp/out/before.json -e '@.burst.instances.*.running' | grep -c '^true$')" = 32 ]
ubus -S call service set '{"name":"busywatch","instances":{"one":{"command":["/bin/sleep","60"]}}}' >/dev/null
ubus -S call service list '{"name":"busywatch"}' >/tmp/out/watchdog-before.json
watchdog_pid=$(jsonfilter -i /tmp/out/watchdog-before.json -e '@.busywatch.instances.one.pid')
[ -n "$watchdog_pid" ]
kill -0 "$watchdog_pid"
ubus -S call service watchdog '{"name":"busywatch","instance":"one","mode":2,"timeout":1}' >/dev/null
kill -STOP "$core"
touch /tmp/release
sleep 2
kill -CONT "$core"
for i in $(seq 1 10); do
    ubus -S call service list '{"name":"burst"}' >/tmp/out/after.json
    stopped=$(jsonfilter -i /tmp/out/after.json -e '@.burst.instances.*.running' | grep -c '^false$' || true)
    [ "$stopped" = 32 ] && break
    sleep 1
done
[ "$stopped" = 32 ]
[ "$(jsonfilter -i /tmp/out/after.json -e '@.burst.instances.*.exit_code' | grep -c '^19$')" = 32 ]
for i in $(seq 1 10); do
    ubus -S call service list '{"name":"busywatch"}' >/tmp/out/watchdog.json
    [ "$(cat /tmp/out/watchdog.json)" = '{"busywatch":{}}' ] && ! kill -0 "$watchdog_pid" 2>/dev/null && break
    sleep 1
done
[ "$(cat /tmp/out/watchdog.json)" = '{"busywatch":{}}' ]
! kill -0 "$watchdog_pid" 2>/dev/null
for i in $(seq 1 10); do
    logread >/tmp/out/messages.txt
    [ "$(grep -c 'r85-tail-' /tmp/out/messages.txt || true)" = 32 ] && break
    sleep 1
done
[ "$(grep -c 'r85-tail-' /tmp/out/messages.txt)" = 32 ]
mkdir /etc/hotplug.d/r85busy
for i in $(seq 1 10); do
    [ "$(ubus list hotplug.r85busy 2>/dev/null)" = hotplug.r85busy ] && break
    sleep 1
done
[ "$(ubus list hotplug.r85busy)" = hotplug.r85busy ]
rmdir /etc/hotplug.d/r85busy
for i in $(seq 1 10); do
    [ -z "$(ubus list hotplug.r85busy 2>/dev/null)" ] && break
    sleep 1
done
[ -z "$(ubus list hotplug.r85busy 2>/dev/null)" ]
for pid in $loads; do kill -0 "$pid"; done
rm /tmp/busy-run
for pid in $loads; do wait "$pid"; done
total=0
for i in 1 2 3 4 5 6 7 8; do
    count=$(cat /tmp/out/load-$i.count)
    [ "$count" -gt 0 ]
    total=$((total + count))
done
ubus -S call service delete '{"name":"burst"}' >/dev/null
ubus -S call service delete '{"name":"busywatch"}' >/dev/null
sleep 1
after=$(ls /proc/$core/fd | wc -l)
[ "$before" = "$after" ]
printf '{"children_reaped":32,"exit_code":19,"final_log_lines":32,"watchdog_stopped":true,"hotplug_added_removed":true,"load_requests":%s,"fds_before":%s,"fds_after":%s}\n' "$total" "$before" "$after" >/tmp/out/result.json
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
                        default=("original", "candidate"),
                        help="explicit subjects, for completing an unrun side after a recorded failure")
    args = parser.parse_args()
    if len(set(args.sides)) != len(args.sides):
        parser.error("duplicate subjects")
    if os.geteuid() != 0:
        parser.error("run as root on the Linux build host")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    instances = {
        f"i{i}": {"command": ["/bin/sh", "-c", f"while [ ! -e /tmp/release ]; do sleep 1; done; echo r85-tail-{i}; exit 19"],
                  "stdout": True}
        for i in range(32)
    }
    summary = []
    for side in args.sides:
        destination = args.output / side
        destination.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="r85-procd-busy-") as work:
            root = Path(work) / "root"
            shutil.copytree(args.rootfs, root, symlinks=True)
            (root / "tmp/out").mkdir(parents=True, exist_ok=True)
            shutil.copy2(args.candidate, root / "tmp/procd-rs")
            (root / "tmp/procd-rs").chmod(0o755)
            (root / "tmp/driver.sh").write_text(DRIVER)
            (root / "tmp/burst.json").write_text(json.dumps({"name": "burst", "instances": instances}))
            try:
                with (destination / "driver.log").open("wb") as log:
                    run = subprocess.run(["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                                          "sh", "-c", SETUP, "sh", str(root), side],
                                         stdout=log, stderr=subprocess.STDOUT, timeout=180)
            finally:
                shutil.copytree(root / "tmp/out", destination / "raw")
            (destination / "exit").write_text(str(run.returncode) + "\n")
            run.check_returncode()
        row = {"side": side, **json.loads((destination / "raw/result.json").read_text())}
        check_final_logs(json.loads((destination / "raw/before.json").read_text()),
                         (destination / "raw/messages.txt").read_text())
        assert row["children_reaped"] == row["final_log_lines"] == 32
        assert row["fds_before"] == row["fds_after"] and row["load_requests"] > 0
        summary.append(row)
        print(json.dumps(row), flush=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.output / "COMPLETE").touch()


if __name__ == "__main__":
    main()
