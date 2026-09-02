#!/usr/bin/env python3
"""Validate the V1 OpenWrt package in disposable exact-image rootfs copies.

This tool never contacts a router.  It checks package metadata and ABI, runs
the R1 differential suite against the binary extracted by an actual package
install, exercises package lifecycle and reboot-volatile activation in mount
namespaces, and adds V1 I/O, disk-full, dependency-recovery and long-loop
checks.  Only a derived JSON manifest is retained.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import r1_candidate_check as candidate_check
import r1_reference_oracle as oracle


ORIGINAL_RELOAD_CONFIG_SHA256 = (
    "f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15"
)
EXPECTED_ROOTFS = oracle.EXPECTED_ARTIFACTS
EXPECTED_DEPENDENCIES = {"libc", "procd", "ubus", "uci"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def checked_output(command: list[str], *, timeout: int = 120) -> str:
    result = run(command, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {command!r}\n{result.stderr}"
        )
    return result.stdout


def assert_rootfs_identity(rootfs: Path) -> dict[str, str]:
    observed: dict[str, str] = {}
    for relative, expected in EXPECTED_ROOTFS.items():
        path = rootfs / relative
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(
                f"rootfs identity mismatch for {relative}: {actual} != {expected}"
            )
        observed[relative] = actual
    return observed


def apk_dump(apk_tool: Path, package: Path) -> str:
    return checked_output([str(apk_tool), "adbdump", str(package)])


def parse_apk_metadata(text: str) -> dict[str, Any]:
    scalar: dict[str, str] = {}
    for field in ("name", "version", "arch", "license", "origin", "installed-size"):
        match = re.search(rf"^  {re.escape(field)}: (.+)$", text, re.MULTILINE)
        if not match:
            raise ValueError(f"missing APK metadata field: {field}")
        scalar[field.replace("-", "_")] = match.group(1)

    dependency_block = re.search(
        r"^  depends:.*?\n(?P<body>(?:    - .+\n)+)", text, re.MULTILINE
    )
    if not dependency_block:
        raise ValueError("missing APK dependency block")
    dependencies = {
        line.removeprefix("    - ")
        for line in dependency_block.group("body").splitlines()
    }

    expected_file_fragments = [
        "- name: owrt-reload-config-switch\n"
        "        acl:\n"
        "          mode: 0755\n"
        "          user: root\n"
        "          group: root",
        "- name: reload_config_rs\n"
        "        acl:\n"
        "          mode: 0755\n"
        "          user: root\n"
        "          group: root",
        "- name: owrt-reload-config\n"
        "        acl:\n"
        "          mode: 0755\n"
        "          user: root\n"
        "          group: root",
    ]
    files_root_0755 = all(fragment in text for fragment in expected_file_fragments)
    script_names = set(re.findall(r"^  (post-install|post-upgrade|pre-deinstall):", text, re.MULTILINE))
    script_blocks = {
        name: match.group("body")
        for name in script_names
        if (
            match := re.search(
                rf"^  {re.escape(name)}: \|\n(?P<body>(?:    .*(?:\n|$))+)"
                rf"(?=^  (?:post-install|post-upgrade|pre-deinstall):|^# data block)",
                text,
                re.MULTILINE,
            )
        )
    }
    disable_in_all_scripts = script_names == {
        "post-install",
        "post-upgrade",
        "pre-deinstall",
    } and all(
        "/usr/sbin/owrt-reload-config-switch disable" in script_blocks.get(name, "")
        for name in script_names
    )
    return {
        **scalar,
        "dependencies": sorted(dependencies),
        "files_root_0755": files_root_0755,
        "lifecycle_scripts": sorted(script_names),
        "disable_in_all_lifecycle_scripts": disable_in_all_scripts,
    }


def inspect_binary(candidate: Path) -> dict[str, Any]:
    file_output = checked_output(["file", str(candidate)]).strip()
    file_description = file_output.split(": ", 1)[-1]
    header = checked_output(["readelf", "-hW", str(candidate)])
    program = checked_output(["readelf", "-lW", str(candidate)])
    dynamic = checked_output(["readelf", "-dW", str(candidate)])
    needed = sorted(re.findall(r"Shared library: \[([^]]+)\]", dynamic))
    load_alignments = [
        fields[-1]
        for line in program.splitlines()
        if line.lstrip().startswith("LOAD")
        and len(fields := line.split()) >= 2
    ]
    stack_line = next(
        (line for line in program.splitlines() if "GNU_STACK" in line), ""
    )
    checks = {
        "aarch64": "Machine:                           AArch64" in header,
        "pie": "Type:                              DYN" in header
        and "Flags: NOW PIE" in dynamic,
        "musl_interpreter": "[Requesting program interpreter: /lib/ld-musl-aarch64.so.1]"
        in program,
        "needed_exact": needed == ["libc.so", "libgcc_s.so.1"],
        "load_alignment_4k": bool(load_alignments)
        and all(value == "0x1000" for value in load_alignments),
        "bind_now": "(BIND_NOW)" in dynamic,
        "relro": "GNU_RELRO" in program,
        "non_executable_stack": "GNU_STACK" in stack_line and " RWE " not in stack_line,
        "no_rpath_or_runpath": "(RPATH)" not in dynamic and "(RUNPATH)" not in dynamic,
        "relr": "(RELR)" in dynamic,
    }
    return {
        "sha256": sha256_file(candidate),
        "size_bytes": candidate.stat().st_size,
        "file": file_description,
        "needed": needed,
        "load_alignments": load_alignments,
        "checks": checks,
        "passed": all(checks.values()),
    }


def run_namespace(root: Path, script: str, *, timeout: int = 120) -> str:
    result = run(
        [
            "sudo",
            "-n",
            "unshare",
            "--mount",
            "--fork",
            "/bin/bash",
            "-s",
            "--",
            str(root),
        ],
        input_text=script,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"namespace check failed ({result.returncode})\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout


def copy_rootfs(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True)
    (destination / "tmp").mkdir(parents=True, exist_ok=True)


@contextlib.contextmanager
def package_rootfs(source: Path, prefix: str):
    """Yield a disposable rootfs and remove root-owned APK files safely."""
    temp = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    temporary_parent = Path(tempfile.gettempdir()).resolve()
    if temp.parent != temporary_parent or not temp.name.startswith(prefix):
        raise RuntimeError(f"unsafe temporary path: {temp}")
    root = temp / "rootfs"
    try:
        copy_rootfs(source, root)
        yield root
    finally:
        cleanup = run(["sudo", "-n", "rm", "-rf", "--", str(temp)])
        if cleanup.returncode != 0:
            raise RuntimeError(f"cannot remove disposable rootfs {temp}: {cleanup.stderr}")


LIFECYCLE_SCRIPT = r"""
set -euo pipefail
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
trap 'umount "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh -s <<'CHROOT_TEST'
set -eu
apk=/usr/bin/apk
expected=f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15
installed_version() {
  $apk --no-network query --from installed --fields name,version owrt-reload-config |
    awk '/^Version:/ { print $2 }'
}
expect_disabled() {
  if /usr/sbin/owrt-reload-config-switch status >/dev/null; then
    echo 'status unexpectedly enabled' >&2
    exit 1
  else
    [ "$?" -eq 3 ]
  fi
  test "$(sha256sum /sbin/reload_config | awk '{print $1}')" = "$expected"
}
config_before=$(find /etc/config -type f -exec sha256sum {} \; | sort | sha256sum | awk '{print $1}')
test "$(sha256sum /sbin/reload_config | awk '{print $1}')" = "$expected"
$apk --no-network add --allow-untrusted /tmp/r1.apk >/tmp/v1-install.log 2>&1
[ "$(installed_version)" = '__VERSION__-r1' ]
test -x /usr/sbin/reload_config_rs
test -x /usr/sbin/owrt-reload-config-switch
test -x /etc/init.d/owrt-reload-config
test -L /etc/rc.d/S11owrt-reload-config
candidate_sha256=$(sha256sum /usr/sbin/reload_config_rs | awk '{print $1}')
expect_disabled
if /usr/sbin/owrt-reload-config-switch boot-enable status >/dev/null; then
  echo 'boot-enable unexpectedly on after install' >&2
  exit 1
fi
/etc/init.d/owrt-reload-config start
expect_disabled
/usr/sbin/owrt-reload-config-switch boot-enable on >/dev/null
test -e /etc/owrt-reload-config.boot-enable
/etc/init.d/owrt-reload-config start
/usr/sbin/owrt-reload-config-switch status >/dev/null
cmp -s /usr/sbin/reload_config_rs /sbin/reload_config
/etc/init.d/owrt-reload-config stop
expect_disabled
/usr/sbin/owrt-reload-config-switch boot-enable off >/dev/null
test ! -e /etc/owrt-reload-config.boot-enable
/usr/sbin/reload_config_rs --help >/dev/null
/usr/sbin/owrt-reload-config-switch enable >/dev/null
/usr/sbin/owrt-reload-config-switch status >/dev/null
cmp -s /usr/sbin/reload_config_rs /sbin/reload_config
/sbin/reload_config --help >/dev/null
$apk --no-network add --allow-untrusted /tmp/r2.apk >/tmp/v1-upgrade.log 2>&1
[ "$(installed_version)" = '__VERSION__-r2' ]
expect_disabled
/usr/sbin/owrt-reload-config-switch enable >/dev/null
$apk --no-network add --allow-untrusted /tmp/r1.apk >/tmp/v1-downgrade.log 2>&1
[ "$(installed_version)" = '__VERSION__-r1' ]
expect_disabled
/usr/sbin/owrt-reload-config-switch enable >/dev/null
/usr/sbin/owrt-reload-config-switch boot-enable on >/dev/null
$apk --no-network del owrt-reload-config >/tmp/v1-remove.log 2>&1
test ! -e /usr/sbin/reload_config_rs
test ! -e /usr/sbin/owrt-reload-config-switch
test ! -e /etc/init.d/owrt-reload-config
test ! -e /etc/rc.d/S11owrt-reload-config
test ! -e /etc/owrt-reload-config.boot-enable
test "$(sha256sum /sbin/reload_config | awk '{print $1}')" = "$expected"
config_after=$(find /etc/config -type f -exec sha256sum {} \; | sort | sha256sum | awk '{print $1}')
[ "$config_before" = "$config_after" ]
printf 'lifecycle=PASS\nconfig_tree_sha256=%s\ncandidate_sha256=%s\n' \
  "$config_after" "$candidate_sha256"
CHROOT_TEST
"""


ACTIVATE_AND_EXIT_SCRIPT = r"""
set -euo pipefail
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
trap 'umount "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh -s <<'CHROOT_TEST'
set -eu
/usr/bin/apk --no-network add --allow-untrusted /tmp/r1.apk >/tmp/v1-install.log 2>&1
/usr/sbin/owrt-reload-config-switch enable >/dev/null
/usr/sbin/owrt-reload-config-switch status >/dev/null
cmp -s /usr/sbin/reload_config_rs /sbin/reload_config
printf 'activation_namespace=enabled\n'
CHROOT_TEST
"""


VERIFY_NEW_NAMESPACE_SCRIPT = r"""
set -euo pipefail
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
trap 'umount "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh -s <<'CHROOT_TEST'
set -eu
expected=f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15
if /usr/sbin/owrt-reload-config-switch status >/dev/null; then
  echo 'activation survived namespace restart' >&2
  exit 1
else
  [ "$?" -eq 3 ]
fi
[ "$(sha256sum /sbin/reload_config | awk '{print $1}')" = "$expected" ]
/usr/bin/apk --no-network del owrt-reload-config >/tmp/v1-remove.log 2>&1
printf 'new_namespace=disabled\nreboot_volatile=PASS\n'
CHROOT_TEST
"""


SWITCH_FAULT_SCRIPT = r"""
set -euo pipefail
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
trap 'umount "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh -s <<'CHROOT_TEST'
set -eu
expected=f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15
/usr/bin/apk --no-network add --allow-untrusted /tmp/r1.apk >/tmp/v1-install.log 2>&1
mv /usr/sbin/reload_config_rs /usr/sbin/reload_config_rs.saved
if /usr/sbin/owrt-reload-config-switch enable >/tmp/v1-missing.out 2>&1; then
  echo 'enable accepted a missing candidate' >&2
  exit 1
fi
[ "$(sha256sum /sbin/reload_config | awk '{print $1}')" = "$expected" ]
mv /usr/sbin/reload_config_rs.saved /usr/sbin/reload_config_rs
cp /sbin/reload_config /tmp/reload_config.original
printf '\n# synthetic identity fault\n' >>/sbin/reload_config
if /usr/sbin/owrt-reload-config-switch enable >/tmp/v1-identity.out 2>&1; then
  echo 'enable accepted the wrong original identity' >&2
  exit 1
fi
cp /tmp/reload_config.original /sbin/reload_config
[ "$(sha256sum /sbin/reload_config | awk '{print $1}')" = "$expected" ]
/usr/bin/apk --no-network del owrt-reload-config >/tmp/v1-remove.log 2>&1
printf 'missing_candidate_fail_closed=PASS\noriginal_identity_fail_closed=PASS\n'
CHROOT_TEST
"""


DISK_FULL_SCRIPT = r"""
set -euo pipefail
root=$1
mount --make-rprivate /
mount -t tmpfs -o size=64k tmpfs "$root/var/run"
trap 'umount "$root/var/run" 2>/dev/null || true' EXIT
cp "$root/tmp/v1-baseline.seed" "$root/var/run/config.md5"
touch "$root/var/run/reload-config-rs.lock"
set +e
dd if=/dev/zero of="$root/var/run/v1-fill" bs=4096 status=none 2>/dev/null
set -e
before=$(sha256sum "$root/var/run/config.md5" | awk '{print $1}')
set +e
chroot "$root" /bin/sh -c 'PATH=/usr/sbin:/usr/bin:/sbin:/bin /sbin/reload_config_rs --trace-stderr' \
  2>"$root/tmp/v1-disk-full.stderr"
rc=$?
set -e
after=$(sha256sum "$root/var/run/config.md5" | awk '{print $1}')
[ "$rc" -eq 70 ]
[ "$before" = "$after" ]
grep -q '"kind":"fatal","class":"dependency"' "$root/tmp/v1-disk-full.stderr"
printf 'disk_full=PASS\nexit_status=%s\nbaseline_sha256=%s\n' "$rc" "$after"
"""


READ_ONLY_SCRIPT = r"""
set -euo pipefail
root=$1
mount --make-rprivate /
mount --bind "$root/var/run" "$root/var/run"
mount -o remount,bind,ro "$root/var/run"
trap 'umount "$root/var/run" 2>/dev/null || true' EXIT
before=$(sha256sum "$root/var/run/config.md5" | awk '{print $1}')
set +e
chroot "$root" /bin/sh -c 'PATH=/usr/sbin:/usr/bin:/sbin:/bin /sbin/reload_config_rs --trace-stderr' \
  2>"$root/tmp/v1-read-only.stderr"
rc=$?
set -e
after=$(sha256sum "$root/var/run/config.md5" | awk '{print $1}')
[ "$rc" -eq 70 ]
[ "$before" = "$after" ]
grep -q '"kind":"fatal","class":"dependency"' "$root/tmp/v1-read-only.stderr"
printf 'read_only_io=PASS\nexit_status=%s\nbaseline_sha256=%s\n' "$rc" "$after"
"""


def package_lifecycle(
    rootfs: Path,
    r1_apk: Path,
    r2_apk: Path,
    candidate_sha256: str,
    expect_version: str,
) -> dict[str, Any]:
    with package_rootfs(rootfs, "owrt-v1-lifecycle-") as root:
        shutil.copy2(r1_apk, root / "tmp/r1.apk")
        shutil.copy2(r2_apk, root / "tmp/r2.apk")
        lifecycle = run_namespace(
            root, LIFECYCLE_SCRIPT.replace("__VERSION__", expect_version)
        )

    with package_rootfs(rootfs, "owrt-v1-reboot-") as root:
        shutil.copy2(r1_apk, root / "tmp/r1.apk")
        activation = run_namespace(root, ACTIVATE_AND_EXIT_SCRIPT)
        new_namespace = run_namespace(root, VERIFY_NEW_NAMESPACE_SCRIPT)

    with package_rootfs(rootfs, "owrt-v1-switch-fault-") as root:
        shutil.copy2(r1_apk, root / "tmp/r1.apk")
        switch_faults = run_namespace(root, SWITCH_FAULT_SCRIPT)

    return {
        "install_default_disabled": "lifecycle=PASS" in lifecycle,
        "installed_candidate_matches_tested_binary": f"candidate_sha256={candidate_sha256}"
        in lifecycle,
        "enable_disable_upgrade_downgrade_uninstall": "lifecycle=PASS" in lifecycle,
        "config_tree_unchanged": "config_tree_sha256=" in lifecycle,
        "reboot_volatile": "reboot_volatile=PASS" in new_namespace,
        "activation_was_observed": "activation_namespace=enabled" in activation,
        "missing_candidate_fail_closed": "missing_candidate_fail_closed=PASS"
        in switch_faults,
        "original_identity_fail_closed": "original_identity_fail_closed=PASS"
        in switch_faults,
    }


def persistent_snapshot(root: Path) -> list[dict[str, Any]]:
    snapshot: list[dict[str, Any]] = []
    run_dir = root / "var/run"
    for path in sorted(run_dir.rglob("*")):
        relative = str(path.relative_to(run_dir))
        if path.is_symlink():
            snapshot.append({"path": relative, "type": "symlink", "target": os.readlink(path)})
        elif path.is_dir():
            snapshot.append({"path": relative, "type": "directory"})
        elif path.is_file():
            snapshot.append(
                {
                    "path": relative,
                    "type": "file",
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return snapshot


def additional_isolation_checks(root: Path) -> dict[str, Any]:
    initial = oracle.establish_baseline(root, {"alpha": "A"})
    expanded = {"alpha": "A2"}
    expanded.update({f"package{number:03d}": "NEW" for number in range(100)})
    oracle.write_config_set(root, expanded, {})
    baseline_seed = root / "tmp/v1-baseline.seed"
    shutil.copy2(root / "var/run/config.md5", baseline_seed)
    disk_full = run_namespace(root, DISK_FULL_SCRIPT)
    read_only = run_namespace(root, READ_ONLY_SCRIPT)

    initial = candidate_check.prepare_simple_change(root, {"alpha": ("A", "A2")})
    ubus = root / "bin/ubus"
    hidden_ubus = root / "bin/ubus.v1-hidden"
    ubus.rename(hidden_ubus)
    try:
        missing = candidate_check.run_candidate(root, [])
    finally:
        hidden_ubus.rename(ubus)
    oracle.write_config_set(root, {"alpha": "A3"}, {})
    recovered = candidate_check.run_candidate(root, [0])
    missing_deliveries = candidate_check.trace_of_kind(missing, "delivery")
    recovery_ok = (
        missing["exit_status"] == 2
        and [item["outcome"] for item in missing_deliveries] == ["spawn_error"]
        and missing["baseline"].get("alpha") is not None
        and recovered["exit_status"] == 0
        and [item["package"] for item in recovered["deliveries"]] == ["alpha"]
    )

    oracle.establish_baseline(root, {"alpha": "A"})
    oracle.write_config_set(root, {"alpha": "A"}, {})
    warm = candidate_check.run_candidate(root, [])
    before = persistent_snapshot(root)
    loop_ok = warm["exit_status"] == 0 and not warm["deliveries"]
    for _ in range(100):
        result = candidate_check.run_candidate(root, [])
        loop_ok = loop_ok and result["exit_status"] == 0 and not result["deliveries"]
        loop_ok = loop_ok and not (root / "var/run/config.check").exists()
    after = persistent_snapshot(root)
    loop_ok = loop_ok and before == after

    return {
        "disk_full": {
            "passed": "disk_full=PASS" in disk_full,
            "baseline_preserved": "baseline_sha256=" in disk_full,
            "exit_status": 70,
        },
        "read_only_io": {
            "passed": "read_only_io=PASS" in read_only,
            "baseline_preserved": "baseline_sha256=" in read_only,
            "exit_status": 70,
        },
        "dependency_restart": {
            "passed": recovery_ok,
            "failure_exit_status": missing["exit_status"],
            "failure_outcomes": [item["outcome"] for item in missing_deliveries],
            "recovery_events": [item["package"] for item in recovered["deliveries"]],
        },
        "long_loop": {
            "passed": loop_ok,
            "iterations": 100,
            "persistent_state_byte_equivalent": before == after,
            "process_model": "one-shot; no resident daemon heap exists",
        },
        "initial_entry_count": len(initial),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--r1-apk", required=True, type=Path)
    parser.add_argument("--r1-repeat-apk", required=True, type=Path)
    parser.add_argument("--r2-apk", required=True, type=Path)
    parser.add_argument("--apk-tool", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    parser.add_argument("--expect-version", default="0.2.0")
    args = parser.parse_args()

    paths = [
        args.rootfs,
        args.candidate,
        args.cases,
        args.r1_apk,
        args.r1_repeat_apk,
        args.r2_apk,
        args.apk_tool,
    ]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise SystemExit(f"missing input(s): {', '.join(missing)}")

    source_artifacts = assert_rootfs_identity(args.rootfs.resolve())
    r1_dump = apk_dump(args.apk_tool.resolve(), args.r1_apk.resolve())
    r2_dump = apk_dump(args.apk_tool.resolve(), args.r2_apk.resolve())
    r1_meta = parse_apk_metadata(r1_dump)
    r2_meta = parse_apk_metadata(r2_dump)
    binary = inspect_binary(args.candidate.resolve())

    package_checks = {
        "r1_repeat_byte_identical": args.r1_apk.read_bytes()
        == args.r1_repeat_apk.read_bytes(),
        "r1_version": r1_meta["version"] == f"{args.expect_version}-r1",
        "r2_version": r2_meta["version"] == f"{args.expect_version}-r2",
        "name": r1_meta["name"] == r2_meta["name"] == "owrt-reload-config",
        "arch": r1_meta["arch"] == r2_meta["arch"] == "aarch64_cortex-a53",
        "dependencies": set(r1_meta["dependencies"])
        == set(r2_meta["dependencies"])
        == EXPECTED_DEPENDENCIES,
        "license": r1_meta["license"]
        == r2_meta["license"]
        == "MIT OR Apache-2.0",
        "origin": r1_meta["origin"]
        == r2_meta["origin"]
        == "feeds/base/owrt-reload-config",
        "files_root_0755": r1_meta["files_root_0755"]
        and r2_meta["files_root_0755"],
        "lifecycle_scripts_fail_closed": r1_meta[
            "disable_in_all_lifecycle_scripts"
        ]
        and r2_meta["disable_in_all_lifecycle_scripts"],
    }

    lifecycle = package_lifecycle(
        args.rootfs.resolve(),
        args.r1_apk.resolve(),
        args.r2_apk.resolve(),
        binary["sha256"],
        args.expect_version,
    )

    with tempfile.TemporaryDirectory(prefix="owrt-v1-candidate-") as temp:
        root = Path(temp) / "rootfs"
        observed, candidate_info = candidate_check.prepare_rootfs(
            args.rootfs.resolve(), root, args.candidate.resolve()
        )
        reference_cases, case_problems = candidate_check.run_reference_cases(
            root, args.cases.resolve()
        )
        fault_cases, fault_problems = candidate_check.run_fault_cases(root)
        additional = additional_isolation_checks(root)

    all_additional = all(
        value["passed"]
        for key, value in additional.items()
        if key != "initial_entry_count"
    )
    limitations = [
        "Mount namespaces use the Ubuntu host kernel, not the target OpenWrt kernel.",
        "No hardware, driver, flash, bootloader, radio, timing, or physical recovery path was exercised.",
        "The component is one-shot; the 100-cycle check proves stable persistent state, not resident-heap behaviour.",
        "No physical router was contacted or modified.",
    ]
    passed = (
        all(package_checks.values())
        and binary["passed"]
        and all(lifecycle.values())
        and not case_problems
        and not fault_problems
        and all_additional
        and candidate_info["within_size_budget"]
        and observed == source_artifacts
    )
    payload = {
        "schema_version": 1,
        "stage": "V1",
        "status": "complete" if passed else "failed",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "scope": {
            "release": "OpenWrt 25.12.5 r33051-f5dae5ece4",
            "target": "mediatek/filogic",
            "package_arch": "aarch64_cortex-a53",
            "libc": "musl",
            "device_access": False,
            "device_writes": False,
            "rootfs_copies_disposable": True,
        },
        "source_artifacts": source_artifacts,
        "packages": {
            "r1": {
                "path_basename": args.r1_apk.name,
                "sha256": sha256_file(args.r1_apk),
                "size_bytes": args.r1_apk.stat().st_size,
                "metadata": r1_meta,
            },
            "r1_repeat": {
                "path_basename": args.r1_repeat_apk.name,
                "sha256": sha256_file(args.r1_repeat_apk),
                "size_bytes": args.r1_repeat_apk.stat().st_size,
            },
            "r2": {
                "path_basename": args.r2_apk.name,
                "sha256": sha256_file(args.r2_apk),
                "size_bytes": args.r2_apk.stat().st_size,
                "metadata": r2_meta,
            },
            "checks": package_checks,
        },
        "installed_binary": binary,
        "lifecycle": lifecycle,
        "differential": {
            "reference_cases": reference_cases,
            "fault_cases": fault_cases,
            "reference_case_count": len(reference_cases),
            "fault_case_count": len(fault_cases),
            "event_sets_equivalent": all(
                item["candidate_events"] == item["reference_events"]
                for item in reference_cases
            ),
            "baseline_bytes_equivalent": all(
                item["baseline_byte_equivalent"] for item in reference_cases
            ),
        },
        "additional_isolation": additional,
        "limitations": limitations,
        "gate": {
            "package_identity_and_reproducibility": all(package_checks.values()),
            "abi_and_hardening": binary["passed"],
            "default_install_has_no_control": lifecycle["install_default_disabled"],
            "rollback_paths": all(lifecycle.values()),
            "reference_and_fault_suites": not case_problems and not fault_problems,
            "v1_faults_and_long_loop": all_additional,
            "within_size_budget": candidate_info["within_size_budget"],
            "passed": passed,
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "gate_passed": passed,
                "reference_cases": len(reference_cases),
                "fault_cases": len(fault_cases),
                "additional_checks": 4,
                "output_sha256": sha256_file(args.output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    if not passed:
        raise SystemExit("V1 gate failed; inspect the emitted manifest")


if __name__ == "__main__":
    main()
