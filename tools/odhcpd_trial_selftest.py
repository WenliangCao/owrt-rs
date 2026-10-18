#!/usr/bin/env python3
"""Exercise finite odhcpd trial guards with real mounts and stock init.

Linux aarch64 root only; a fresh mount/net/PID namespace owns every daemon.
The source rootfs is copied, no physical devices or host sockets are exposed.
Client-health confirmation is synthetic and is not protocol qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import time

import odhcpd_trial_prepare as prepare


DRIVE = r'''#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
OUT=/test-out
INPUT=/root/odhcpd-trial-test-inputs
done_test=0
finish() {
    result=$?
    for base in /tmp/owrt-odhcpd-trial-*; do
        [ -d "$base" ] || continue
        cp -a "$base" "$OUT/" 2>/dev/null || true
    done
    [ "$done_test" = 1 ] || printf 'FAILED %s\n' "$result" > "$OUT/verdict"
}
trap finish EXIT
test ! -e "$OUT/started"
touch "$OUT/started"
for i in $(seq 1 40); do
    if ubus -S -t 1 call service list > /dev/null 2>&1; then break; fi
    sleep 1
done
/etc/init.d/odhcpd start

select_case() {
    current_case=$1
    cp -a "$INPUT/bundles/$current_case" /tmp/
    token=$(cat "$INPUT/tokens/$current_case")
    base=/tmp/owrt-odhcpd-trial-$token
    mv "/tmp/$current_case" "$base"
    boot=$(cat /proc/sys/kernel/random/boot_id)
    manifest=$(sha256sum "$base/bundle.sha256" | cut -d' ' -f1)
}
trial() { /bin/sh "$base/trial.sh" "$1" "$token" "$boot" "$manifest" "${2:-}"; }
wait_state() {
    wanted=$1
    for i in $(seq 1 70); do
        state=$(cat "$base/state" 2>/dev/null || true)
        [ "$state" != "$wanted" ] || return 0
        [ "$state" != restore-failed ] || return 1
        sleep 1
    done
    return 1
}
restored() {
    test ! -e /tmp/owrt-odhcpd-trial.lock
    test "$(sha256sum /usr/sbin/odhcpd | cut -d' ' -f1)" = "$C_SHA"
    test "$(awk '$5=="/usr/sbin/odhcpd" {n++} END{print n+0}' /proc/self/mountinfo)" = 0
    trial restore
    printf '%s\n' "$current_case" >> "$OUT/passed"
}
C_SHA=53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82

select_case gate
for i in $(seq 1 25); do if trial preflight; then break; fi; sleep 1; done
trial preflight
before=$(cat "$base/original.id")
if /bin/sh "$base/trial.sh" preflight "$token" 11111111-1111-1111-1111-111111111111 "$manifest"; then exit 1; fi
mkdir "$base/foreign-source"
mount -o bind "$base/foreign-source" "$base/foreign-source"
if trial activate; then exit 1; fi
umount "$base/foreign-source"
rmdir "$base/foreign-source"
chmod 700 "$base/candidate.elf"
printf bad >> "$base/candidate.elf"
if trial activate; then exit 1; fi
test ! -e "$base/state"
test ! -e /tmp/owrt-odhcpd-trial.lock
test "$(cat "$base/original.id")" = "$before"
printf 'gate\n' >> "$OUT/passed"

select_case detached_timeout
# A session-owning launcher stands in for SSH. The guard must live in a
# different session and survive this launcher being killed.
setsid /bin/sh -c '/bin/sh "$1/trial.sh" activate "$2" "$3" "$4"; sleep 60' \
    sh "$base" "$token" "$boot" "$manifest" </dev/null > "$base/launcher.log" 2>&1 &
launcher=$!
wait_state active
read -r guard guard_start guard_token < /tmp/owrt-odhcpd-trial.lock/identity
guard_session=$(awk '{sub(/^.*\) /, ""); print $4}' "/proc/$guard/stat")
launcher_session=$(awk '{sub(/^.*\) /, ""); print $4}' "/proc/$launcher/stat")
test "$guard_session" != "$launcher_session"
kill -KILL "$launcher"
kill -0 "$guard"
wait_state restored-timeout
restored

select_case confirmed
trial activate
candidate=$(sha256sum "$base/candidate.elf" | cut -d' ' -f1)
printf '{"passed":true,"trial_token":"wrong","boot_id":"%s","candidate_sha256":"%s","external_health_token":"%064d"}\n' \
    "$boot" "$candidate" 0 > "$base/client-health.json"
health=$(sha256sum "$base/client-health.json" | cut -d' ' -f1)
if trial confirm "$health"; then exit 1; fi
test "$(cat "$base/state")" = active
printf '{"passed":true,"trial_token":"%s","boot_id":"%s","candidate_sha256":"%s","external_health_token":"%064d"}\n' \
    "$token" "$boot" "$candidate" 0 > "$base/client-health.json"
health=$(sha256sum "$base/client-health.json" | cut -d' ' -f1)
trial confirm "$health"
wait_state restored-confirmed
test -s "$base/accepted"
restored

select_case manual
trial activate
trial restore
wait_state restored-manual
restored

select_case candidate_failure
trial activate
read -r candidate_pid candidate_start < "$base/active.id"
kill -KILL "$candidate_pid"
wait_state restored-failure
restored

select_case guard_term
trial activate
read -r guard guard_start guard_token < /tmp/owrt-odhcpd-trial.lock/identity
kill -TERM "$guard"
wait_state restored-failure
restored

sha256sum -c "$INPUT/config.sha256"
test "$(wc -l < "$OUT/passed")" = 6
done_test=1
printf 'PASS\n' > "$OUT/verdict"
while :; do sleep 60; done
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("rootfs", "candidate", "helper", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--helper-sha256", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "aarch64" or Path("/etc/openwrt_release").exists():
        raise SystemExit("requires isolated Linux aarch64 build host root")
    os.umask(0o022)
    out = args.output.resolve()
    if not out.is_relative_to((prepare.REPO / "private").resolve()):
        raise SystemExit("selftest output must be a fresh ignored private/ directory")
    out.mkdir(parents=True, exist_ok=False)
    source = args.rootfs.resolve()
    root = out / "rootfs"
    subprocess.run(["cp", "-a", str(source), str(root)], check=True)
    for relative in ("etc/rc.d", "tmp"):
        shutil.rmtree(root / relative)
        (root / relative).mkdir(mode=0o755)
    for relative in ("etc/config", "rom", "test-out", "root/odhcpd-trial-test-inputs/tokens"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "etc/config/dhcp").write_text("config odhcpd 'odhcpd'\n option maindhcp '0'\n option leasefile '/tmp/odhcpd.leases'\n option hostsdir '/tmp/hosts'\n option piodir '/tmp/odhcpd-piodir'\n option loglevel '4'\n")
    (root / "etc/config/network").write_text("config interface 'loopback'\n option device 'lo'\n option proto 'static'\n option ipaddr '127.0.0.1'\n option netmask '255.0.0.0'\n")
    (root / "etc/config/system").write_text("config system\n option hostname 'odhcpd-guard-fixture'\n")
    (root / "etc/rc.d/S35odhcpd").symlink_to("../init.d/odhcpd")
    (root / "etc/rc.d/K85odhcpd").symlink_to("../init.d/odhcpd")
    (root / "etc/inittab").write_text("::respawn:/bin/sh /root/odhcpd-trial-test-inputs/drive.sh\n")
    inputs = root / "root/odhcpd-trial-test-inputs"
    (inputs / "drive.sh").write_text(DRIVE)
    (inputs / "drive.sh").chmod(0o755)
    backup = out / "synthetic-backup.tar.gz"
    with tarfile.open(backup, "w:gz") as archive:
        for name in ("dhcp", "network", "system"):
            archive.add(root / "etc/config" / name, arcname="etc/config/" + name)
    configs = prepare.config_hashes(backup)
    (inputs / "config.sha256").write_text("".join(f"{value}  {key}\n" for key, value in configs.items()))
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    for name in ("gate", "detached_timeout", "confirmed", "manual", "candidate_failure", "guard_term"):
        bundle = inputs / "bundles" / name
        receipt = prepare.prepare(args.candidate, args.candidate_sha256, source, backup, prepare.sha(backup),
                                  args.helper, args.helper_sha256, boot, bundle, 8 if name == "detached_timeout" else 45)
        (inputs / "tokens" / name).write_text(receipt["token"] + "\n")
    evidence = out / "evidence"
    evidence.mkdir()
    command = r'''set -eu
root=$1
source=$2
evidence=$3
mount --make-rprivate /
mount --bind "$root" "$root"
mount -t proc proc "$root/proc"
mount -t sysfs -o ro sysfs "$root/sys"
mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
mount -t tmpfs -o mode=1777 tmpfs "$root/tmp"
mount --bind "$source" "$root/rom"
mount -o remount,bind,ro "$root/rom"
mount --bind "$evidence" "$root/test-out"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
ip link set lo up
chroot "$root" /bin/mkdir -p /var/lock /var/run /var/log /var/state
exec chroot "$root" /sbin/procd
'''
    with (out / "pid1.log").open("wb") as log:
        process = subprocess.Popen(["unshare", "--mount", "--net", "--pid", "--uts", "--ipc", "--fork", "--kill-child",
                                    "/bin/sh", "-c", command, "sh", str(root), str(source), str(evidence)],
                                   stdout=log, stderr=log, env=dict(os.environ, container="1"), start_new_session=True)
        try:
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline and process.poll() is None:
                if (evidence / "verdict").exists():
                    break
                time.sleep(0.2)
            verdict = (evidence / "verdict").read_text().strip() if (evidence / "verdict").exists() else "missing verdict"
            if verdict != "PASS":
                raise RuntimeError(f"trial selftest failed: {verdict}; inspect {out / 'pid1.log'}")
            # Copy tmpfs evidence before namespace teardown. The successful
            # driver remains asleep; no additional service mutation is made.
            ns_child = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
            if len(ns_child) != 1:
                raise RuntimeError("cannot identify the owned namespace init")
            namespace_root = Path("/proc") / ns_child[0] / "root"
            for bundle in (namespace_root / "tmp").glob("owrt-odhcpd-trial-*"):
                if bundle.is_dir():
                    shutil.copytree(bundle, evidence / bundle.name, dirs_exist_ok=True)
            result = {"passed": True, "cases": (evidence / "passed").read_text().splitlines(),
                      "candidate_sha256": args.candidate_sha256,
                      "source_procd_sha256": prepare.sha(source / "sbin/procd"),
                      "source_ubusd_sha256": prepare.sha(source / "sbin/ubusd"),
                      "original_init_sha256": prepare.INIT_SHA, "physical_router_accessed": False,
                      "real_bind_mounts_and_original_init": True,
                      "client_health_confirmation": "synthetic; no client qualification claimed"}
            (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))
        finally:
            # unshare --kill-child terminates only this fixture's PID namespace.
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)


if __name__ == "__main__":
    main()
