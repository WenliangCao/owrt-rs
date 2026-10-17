#!/usr/bin/env python3
"""Exercise the real native-image sysupgrade handoff, never physical flashing.

Run only on an aarch64 Linux build host as root. Each case has a copied image,
private mount/network/PID namespaces, and a minimal /dev without flash or
watchdog devices. The image's PID1, ubusd, sysupgrade, validation and upgrade
libraries remain unchanged. Only /sbin/upgraded becomes an inert static
recorder: it records PID1's actual argv/configuration, then ends the namespace.

Two cases use the real trial guard: ordinary handoff, and a real procd service
with term_timeout=70, exceeding the guard's 60-second outer client deadline
(the stock ubus client may return on its own earlier deadline). This
checks that an uncertain client result does not cause a C bridge or reboot
while PID1 is still preparing the already accepted handoff. It does not run
stage2, write flash, test boot recovery, or qualify physical hardware.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import time


TOOLS = Path(__file__).resolve().parent
BASE = "root/owrt-native-trial"
RECEIPT = "root/owrt-v0.2.1-rollback-receipt"
RECORDER_SOURCE = r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int copy_file(const char *from, const char *to) {
    int input = open(from, O_RDONLY), output;
    if (input < 0) return 1;
    output = open(to, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (output < 0) { close(input); return 1; }
    char buffer[8192];
    ssize_t count;
    while ((count = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t done = 0;
        while (done < count) {
            ssize_t written = write(output, buffer + done, count - done);
            if (written <= 0) return 1;
            done += written;
        }
    }
    int failed = count < 0 || fsync(output) != 0;
    close(output); close(input);
    return failed;
}

int main(int argc, char **argv) {
    /* install_bin's ldd fallback may execute a static program. */
    if (getpid() != 1) return 0;
    /* Exact upgraded starts by escaping its prefix with its retained cwd.
       Stay inside the fixture's old root; never execute stage2 or reboot. */
    if (chroot(".") || chdir("/")) return 21;
    int fd = open("/tmp/handoff-out/upgraded.txt", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 22;
    FILE *out = fdopen(fd, "w");
    if (!out) return 23;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    fprintf(out, "pid=%ld\nargc=%d\nmonotonic=%.9f\n", (long)getpid(), argc,
            now.tv_sec + now.tv_nsec / 1e9);
    for (int i = 0; i < argc; i++) fprintf(out, "argv%d=%s\n", i, argv[i]);
    const char *names[] = {"UPGRADE_BACKUP", "UPGRADE_OPT_SAVE_PARTITIONS",
                          "UPGRADE_OPT_ADD_PROVISIONING", "WDTFD", NULL};
    for (int i = 0; names[i]; i++) {
        const char *value = getenv(names[i]);
        if (value) fprintf(out, "%s=%s\n", names[i], value);
    }
    fflush(out); fsync(fd); fclose(out);
    const char *backup = getenv("UPGRADE_BACKUP");
    if (!backup || copy_file(backup, "/tmp/handoff-out/actual-backup.tar.gz")) return 24;
    sync();
    return 0;
}
'''

NAMESPACE = r'''
set -eu
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t sysfs -o ro sysfs "$root/sys"
mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
ip link set lo up
exec chroot "$root" /sbin/procd
'''

DRIVER = r'''#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
out=/tmp/handoff-out
for attempt in $(seq 1 40); do
    if ubus -S -t 1 call system board > "$out/board.json" 2>/dev/null; then break; fi
    sleep 1
done
[ "$(jsonfilter -i "$out/board.json" -e '@.board_name')" = xiaomi,mi-router-ax3000t ]
sha256sum /proc/1/exe > "$out/pid1.sha256"
pid=$(pidof ubusd)
case "$pid" in ''|*[!0-9]*) exit 3;; esac
sha256sum "/proc/$pid/exe" > "$out/ubusd.sha256"
ubus -S -t 3 call service set '{"name":"handoff-delay","instances":{"main":{"command":["/bin/sleep","3600"],"term_timeout":__DELAY__}}}'
ubus -S -t 3 call service list '{"name":"handoff-delay"}' > "$out/service.json"
/usr/libexec/validate_firmware_image /root/owrt-native-trial/rollback-v0.2.0.bin > "$out/validation.json"
[ "$(jsonfilter -i "$out/validation.json" -e '@.valid')" = true ]
# This separate session is not an inittab child or a supervised service.
# service_stop_all kills the launcher but must leave the guard to observe its
# client's timeout while PID1 waits the actual registered term_timeout.
setsid /bin/sh /tmp/handoff-guard.sh < /dev/null > "$out/guard-stdio.log" 2>&1 &
echo "$!" > "$out/guard.pid"
exit 0
'''

GUARD_LAUNCHER = r'''#!/bin/sh
set +e
cut -d' ' -f1 /proc/uptime > /tmp/handoff-out/guard-start-uptime
/bin/sh /root/owrt-native-trial/native_trial_guard.sh restore
result=$?
printf '%s\n' "$result" > /tmp/handoff-out/guard-returned
cut -d' ' -f1 /proc/uptime > /tmp/handoff-out/guard-return-uptime
sync
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
    path.chmod(mode)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify_identity(root, manifest):
    for item in manifest["components"].values():
        require(sha(root / item["path"].lstrip("/")) == item["rust_sha256"], item["path"])
        require(sha(root / item["recovery_path"].lstrip("/")) == item["stock_sha256"], item["recovery_path"])
    for item in manifest["integration_files"].values():
        require(sha(root / item["path"].lstrip("/")) == item["replacement_sha256"], item["path"])
        require(sha(root / item["recovery_path"].lstrip("/")) == item["stock_sha256"], item["recovery_path"])


def check_case(source, image, bounded, recorder, output, manifest, delay):
    root = output / "root"
    output.mkdir()
    subprocess.run(["cp", "-a", str(source), str(root)], check=True)
    protected = [root / "sbin/sysupgrade", root / "usr/libexec/validate_firmware_image"]
    protected += [p for p in (root / "lib/upgrade").rglob("*") if p.is_file()]
    protected_hashes = {str(p.relative_to(root)): sha(p) for p in protected}
    shutil.copy2(recorder, root / "sbin/upgraded")
    (root / "sbin/upgraded").chmod(0o755)
    for entry in (root / "etc/rc.d").iterdir():
        require(not entry.is_dir(), "unexpected rc.d subdirectory")
        entry.unlink()
    write(root / "etc/inittab", "::sysinit:/etc/init.d/rcS S boot\n::respawn:/bin/sh /tmp/handoff-drive.sh\n", 0o644)
    write(root / "etc/config/system", "config system\n option compat_version '1.0'\n", 0o600)
    for directory in ("tmp/handoff-out", "tmp/sysinfo", "tmp/run", "tmp/lock", "proc", "sys", "dev", BASE):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / BASE).chmod(0o700)
    write(root / "tmp/sysinfo/board_name", "xiaomi,mi-router-ax3000t\n")
    write(root / "tmp/handoff-drive.sh", DRIVER.replace("__DELAY__", str(delay)), 0o700)
    write(root / "tmp/handoff-guard.sh", GUARD_LAUNCHER, 0o700)
    shutil.copy2(TOOLS / "native_trial_guard.sh", root / BASE / "native_trial_guard.sh")
    shutil.copy2(bounded, root / BASE / "bounded")
    (root / BASE / "bounded").chmod(0o700)
    shutil.copy2(image, root / BASE / "rollback-v0.2.0.bin")
    original = b"config interface 'fixture'\n option proto 'none'\n"
    with tarfile.open(root / BASE / "rollback-config.tar.gz", "w:gz") as archive:
        member = tarfile.TarInfo("etc/config/network")
        member.size, member.mode, member.uid, member.gid = len(original), 0o600, 0, 0
        archive.addfile(member, io.BytesIO(original))
    write(root / BASE / "rollback-members.txt", "etc/config/network\n")
    inputs = ("rollback-v0.2.0.bin", "rollback-config.tar.gz", "rollback-members.txt")
    write(root / BASE / "rollback.sha256", "".join(
        f"{sha(root / BASE / name)}  /{BASE}/{name}\n" for name in inputs))
    stock = root / "usr/share/owrt-control-plane/stock.sha256"
    recovery = stock.read_text() + f"{sha(stock)}  /usr/share/owrt-control-plane/stock.sha256\n"
    recovery += f"{sha(root / 'usr/sbin/owrt-recover-c')}  /usr/sbin/owrt-recover-c\n"
    write(root / BASE / "recovery.sha256", recovery)
    started = time.monotonic()
    with (output / "namespace.log").open("wb") as log:
        run = subprocess.run(["timeout", "-s", "KILL", "150", "unshare", "--mount", "--net", "--pid", "--uts", "--ipc",
                              "--fork", "--kill-child", "/bin/sh", "-c", NAMESPACE, "sh", str(root)],
                             env=dict(os.environ, container="1"), stdout=log, stderr=subprocess.STDOUT, timeout=160)
    elapsed = time.monotonic() - started
    require(run.returncode == 0, f"namespace did not end successfully after handoff: {run.returncode}")
    evidence = root / "tmp/handoff-out"
    require((evidence / "upgraded.txt").is_file(), "real PID1 did not reach the inert upgraded recorder")
    values = dict(line.split("=", 1) for line in (evidence / "upgraded.txt").read_text().splitlines())
    expected = {"pid": "1", "argc": "3", "argv0": "/sbin/upgraded",
                "argv1": "/tmp/owrt-native-rollback/image.bin", "argv2": "/lib/upgrade/do_stage2",
                "UPGRADE_BACKUP": "/tmp/sysupgrade.tgz", "UPGRADE_OPT_SAVE_PARTITIONS": "1",
                "UPGRADE_OPT_ADD_PROVISIONING": "0"}
    require(all(values.get(k) == v for k, v in expected.items()), f"unexpected handoff: {values}")
    require("WDTFD" not in values, "fixture must not expose a watchdog")
    require((evidence / "pid1.sha256").read_text().split()[0] == manifest["components"]["procd"]["rust_sha256"], "wrong actual PID1")
    require((evidence / "ubusd.sha256").read_text().split()[0] == manifest["components"]["ubusd"]["rust_sha256"], "wrong actual ubusd")
    service = json.loads((evidence / "service.json").read_text())["handoff-delay"]["instances"]["main"]
    require(service["running"] and service["term_timeout"] == delay, "delay was not an actual live procd service")
    with tarfile.open(evidence / "actual-backup.tar.gz") as archive:
        members = archive.getmembers()
        names = [m.name.rstrip("/") for m in members]
        require(len(set(names)) == len(names), "duplicate backup members")
        require(all(n == "etc/config/network" or n == RECEIPT or n.startswith(RECEIPT + "/") for n in names), "unexpected backup additions")
        member = archive.getmember("etc/config/network")
        require((member.mode, member.uid, member.gid) == (0o600, 0, 0), "original config metadata changed")
        require(archive.extractfile(member).read() == original, "original config bytes changed")
        require(RECEIPT + "/guard.log" in names, "rollback reason did not reach actual PID1 backup")
    guard_log = (root / BASE / "guard.log").read_text()
    require(guard_log.count("v0.2.0 rollback requested with original configuration") == 1, "handoff was not submitted exactly once")
    require(not list((root / BASE).glob("c-bridge-*")), "C bridge must not occur after handoff submission")
    require(sha(root / "tmp/owrt-native-rollback/image.bin") == sha(image), "PID1 image differs from verified input")
    if delay > 60:
        require("sysupgrade handoff uncertain" in guard_log, "delayed acceptance did not exercise the uncertain-client boundary")
        require((evidence / "guard-returned").read_text().strip() == "0", "guard did not stop after uncertain handoff")
        start = float((evidence / "guard-start-uptime").read_text())
        returned = float((evidence / "guard-return-uptime").read_text())
        # Stock ubus has its own timeout inside the guard's outer timeout.
        # Assert observed order, not an invented exact 60-second duration.
        require(0 < returned - start < delay, "guard did not return before delayed PID1 exec")
        require(elapsed >= delay, "actual service_stop_all delay was not exercised")
    verify_identity(root, manifest)
    require(all(sha(root / name) == value for name, value in protected_hashes.items()), "exact sysupgrade/validation inputs changed")
    result = {"passed": True, "term_timeout_s": delay, "elapsed_s": elapsed, "namespace_exit": run.returncode,
              "actual_PID1_and_ubusd_verified": True, "actual_sysupgrade_and_validation_unchanged": True,
              "actual_PID1_argv_backup_verified": True, "only_one_submission": True,
              "no_C_bridge_or_forced_reboot": True, "original_configuration_preserved": True,
              "uncertain_client_before_delayed_exec": delay > 60, "protected_inputs": protected_hashes}
    write(output / "result.json", json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("rollback_image", type=Path)
    parser.add_argument("bounded", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--image-sha256", required=True)
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() == "aarch64" and os.geteuid() == 0,
            "requires root on an aarch64 Linux build host")
    require(not Path("/etc/openwrt_release").exists(), "never run this tool on an OpenWrt device")
    root, image, bounded, output = (p.resolve() for p in (args.rootfs, args.rollback_image, args.bounded, args.output))
    require(root.is_dir() and image.is_file() and bounded.is_file(), "missing fixture input")
    require(root != output and root not in output.parents, "output must not be inside the source rootfs")
    require(sha(image) == args.image_sha256, "rollback image differs from independently verified Release SHA")
    manifest_path = root / "usr/share/owrt-control-plane/release.json"
    manifest = json.loads(manifest_path.read_text())
    require(manifest["layout"] == "native-ten" and len(manifest["components"]) == 10 and len(manifest["integration_files"]) == 2,
            "expected exact final native-ten image")
    verify_identity(root, manifest)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    write(output / "upgraded-recorder.c", RECORDER_SOURCE)
    recorder = output / "upgraded-recorder"
    with (output / "recorder-build.log").open("wb") as log:
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-static",
                        str(output / "upgraded-recorder.c"), "-o", str(recorder)], check=True, stdout=log, stderr=subprocess.STDOUT)
    program = subprocess.check_output(["readelf", "-W", "-l", str(recorder)], text=True)
    require("INTERP" not in program, "inert recorder must not need a loader inside sysupgrade prefix")
    identity = {"image_sha256": sha(image), "image_bytes": image.stat().st_size,
                "image_source_commit": manifest["source_commit"], "rootfs_release_manifest_sha256": sha(manifest_path),
                "guard_sha256": sha(TOOLS / "native_trial_guard.sh"), "bounded_sha256": sha(bounded),
                "driver_sha256": sha(Path(__file__)), "recorder_sha256": sha(recorder),
                "boundary": "real sysupgrade validation and PID1 handoff; upgraded recorder replaces all flash/reboot execution"}
    write(output / "identity.json", json.dumps(identity, indent=2) + "\n")
    cases = {}
    for name, delay in (("normal", 1), ("delayed-service-stop", 70)):
        cases[name] = check_case(root, image, bounded, recorder, output / name, manifest, delay)
        print("PASS:", name, flush=True)
    verify_identity(root, manifest)
    write(output / "result.json", json.dumps({"passed": True, "cases": cases,
          "physical_flash_tested": False, "physical_reboot_tested": False, "stage2_executed": False}, indent=2) + "\n")


if __name__ == "__main__":
    main()
