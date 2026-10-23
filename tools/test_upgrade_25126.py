#!/usr/bin/env python3
"""Check exact 25.12.6 AX3000T UBI routing in disposable, device-free chroots.

All NAND, volume, mount, and backup-move operations are recording functions.
This validates script decisions only; it never executes flash, stage2 or reboot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


INPUTS = ("lib/upgrade/platform.sh", "lib/upgrade/nand.sh", "lib/functions.sh", "lib/config/uci.sh",
          "bin/busybox", "etc/openwrt_release")
SCRIPT = r'''#!/bin/sh
PATH=/tmp/no-external-commands
export PATH
. /lib/upgrade/nand.sh
. /lib/upgrade/platform.sh
record() { printf '%s\n' "$*" >> /tmp/trace; }
board_name() { printf '%s\n' xiaomi,mi-router-ax3000t; }
nand_do_upgrade() {
    record "selection:${CI_KERN_UBIPART:-}:${CI_ROOT_UBIPART:-}:${CI_DATA_UBIPART:-}"
}
# Deliberately different from the target partition: the AX3000T branch must
# supply all three overrides instead of silently using this generic fallback.
CI_UBIPART=wrong-default
platform_do_upgrade /tmp/synthetic-image
partition() {
    case "$1" in ubi_kernel) echo ubi7;; ubi) echo ubi9;; *) echo wrong-device;; esac
}
nand_attach_ubi() { record "attach:$1"; partition "$1"; }
nand_find_ubi() { record "find-ubi:$1"; partition "$1"; }
nand_find_volume() {
    record "find-volume:$1:$2"
    if [ "$SCENARIO" = restore-missing ]; then return 0; fi
    if [ "$SCENARIO" = restore-fallback ] && [ "$2" = rootfs_data ]; then return 0; fi
    case "$2" in kernel) echo "${1}_0";; rootfs) echo "${1}_1";; rootfs_data) echo "${1}_2";; esac
}
nand_remove_ubiblock() { record "remove-block:$1"; }
ubirmvol() { record "ubirmvol:$*"; }
ubimkvol() { record "ubimkvol:$*"; }
fw_printenv() { :; }
mkdir() { record "mkdir:$*"; }
rmdir() { record "rmdir:$*"; }
mount() {
    record "mount:$*"
    [ "$SCENARIO" != restore-mount-failure ]
}
umount() { record "umount:$*"; }
mv() { record "mv:$*"; }
BACKUP_FILE=sysupgrade.tgz
if [ "$SCENARIO" = prepare ]; then
    nand_upgrade_prepare_ubi 4096 squashfs 1024
else
    nand_restore_config /tmp/config-backup.tar.gz
fi
status=$?
record "status:$status"
exit 0
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected(scenario):
    lines = ["selection:ubi_kernel:ubi:ubi"]
    if scenario == "prepare":
        return lines + [
            "attach:ubi_kernel", "attach:ubi", "attach:ubi",
            "find-volume:ubi7:kernel", "find-volume:ubi9:rootfs",
            "find-volume:ubi9:rootfs_data", "remove-block:ubi7_0",
            "remove-block:ubi9_1", "remove-block:ubi9_2",
            "ubirmvol:/dev/ubi7 -N kernel", "ubirmvol:/dev/ubi9 -N rootfs",
            "ubirmvol:/dev/ubi9 -N rootfs_data", "ubimkvol:/dev/ubi7 -N kernel -s 1024",
            "ubimkvol:/dev/ubi9 -N rootfs -s 4096", "ubimkvol:/dev/ubi9 -N rootfs_data -m",
            "status:0",
        ]
    lines += ["find-ubi:ubi", "find-volume:ubi9:rootfs_data"]
    if scenario in ("restore-fallback", "restore-missing"):
        lines += ["find-ubi:ubi", "find-volume:ubi9:rootfs"]
    if scenario == "restore-missing":
        return lines + ["status:1"]
    volume = "ubi9_1" if scenario == "restore-fallback" else "ubi9_2"
    lines += ["mkdir:/tmp/new_root", f"mount:-t ubifs /dev/{volume} /tmp/new_root"]
    if scenario == "restore-mount-failure":
        return lines + ["rmdir:/tmp/new_root", "status:1"]
    return lines + ["mv:/tmp/config-backup.tar.gz /tmp/new_root/sysupgrade.tgz",
                    "umount:/tmp/new_root", "rmdir:/tmp/new_root", "status:0"]


def run_case(source, output, scenario, mutant=False):
    output.mkdir()
    root = output / "root"
    subprocess.run(["cp", "-a", str(source), str(root)], check=True)
    # Never bind host devices, procfs or sysfs into this fixture.
    for name in ("dev", "proc", "sys", "tmp"):
        path = root / name
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)
        path.mkdir()
    (root / "dev/null").touch()  # redirection sink, deliberately not a device
    (root / "tmp/check.sh").write_text(SCRIPT)
    (root / "tmp/trace").touch()
    if mutant:
        path = root / "lib/upgrade/platform.sh"
        text = path.read_text()
        needle = "\t\tCI_DATA_UBIPART=ubi\n"
        assert text.count(needle) == 1, "negative control must remove exactly the new AX3000T override"
        path.write_text(text.replace(needle, "", 1))
    command = ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
               "chroot", str(root), "/bin/sh", "/tmp/check.sh"]
    run = subprocess.run(command, env={"SCENARIO": scenario, "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                       "LANG": "C"},
                         text=True, capture_output=True, timeout=20)
    (output / "stdout").write_text(run.stdout)
    (output / "stderr").write_text(run.stderr)
    observed = (root / "tmp/trace").read_text().splitlines()
    matched = run.returncode == 0 and observed == expected(scenario)
    rejected = (run.returncode == 0 and not matched
                and observed[0:1] == ["selection:ubi_kernel:ubi:"]
                and "attach:wrong-default" in observed
                and "ubimkvol:/dev/wrong-device -N rootfs_data -m" in observed)
    result = {"scenario": scenario, "mutant": mutant, "command": command,
              "exit": run.returncode, "observed": observed, "expected": expected(scenario),
              "matched": matched, "passed": rejected if mutant else matched}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    assert result["passed"], result
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == "Linux"
    assert platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists()
    source, output = args.rootfs.resolve(), args.output.resolve()
    assert "DISTRIB_RELEASE='25.12.6'" in (source / "etc/openwrt_release").read_text()
    output.mkdir(parents=True, exist_ok=False)
    identities = {name: sha(source / name) for name in INPUTS}
    result = {"passed": False, "scope": "exact-script UBI routing and restoration decisions only",
              "physical_flash_tested": False, "stage2_executed": False,
              "host_devices_exposed": False, "script_sha256": sha(Path(__file__)),
              "inputs": identities, "cases": []}
    try:
        for scenario in ("prepare", "restore-data", "restore-fallback", "restore-missing",
                         "restore-mount-failure"):
            result["cases"].append(run_case(source, output / scenario, scenario))
        result["cases"].append(run_case(source, output / "missing-data-override", "prepare", True))
        assert identities == {name: sha(source / name) for name in INPUTS}
        result.update(passed=True, source_unchanged=True)
    finally:
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("AX3000T UBI decisions: 5 positive cases and 1 rejected missing-override control passed")


if __name__ == "__main__":
    main()
