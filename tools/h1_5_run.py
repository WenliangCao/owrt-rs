#!/usr/bin/env python3
"""Install the frozen H1.5 APK disabled on the approved OpenWrt device."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
APK_SHA256 = "02d0c977d68192c28d0ef537a704435d9814fb8e04763cd67d73e00e41e5d9b1"
APK_SIZE = 184_099
DISPATCHER_SHA256 = "f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15"
BASELINE_SHA256 = "b77e0e99672ee504d1ee1183f14b8ba8cfe92f6c546aa585f7efc784d2b0c163"
CONFIG_TREE_SHA256 = "c571059487c486dc8f255228f49ab558092a50ee22c0845c91ed4839a0ded44a"
PACKAGE_DB_SHA256 = "6149a91ae1efa348b3e56d08ef13f844ecee6288a78448749519682a9e8cb5fc"
WORLD_SHA256 = "906eb5cf1013afd8e8ff97b486175fa77a97a2a2437d640a1c4fdc4dd9eab69b"
SCRIPTS_SHA256 = "4a5fd6b59a9eadd3b27dd31fd4d79b622083b0a11d966a8c2dd5916c1b945bfc"
TRIGGERS_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
CANDIDATE_SHA256 = "b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75"
SWITCH_SHA256 = "ce7ef65892c69d1900ee0f626183bcae5a42b3ccd1f18f706ab496703b990bdf"
REMOTE_APK = "/tmp/owrt-h1-5-r1.apk"
REMOTE_HARNESS = "/tmp/owrt-h1-5-disabled-install.sh"
REMOTE_RUN_ROOT = "/tmp/owrt-h1-5-install-20260902"
REMOTE_RESTORE = "/lib/apk/db/.scripts.tar.gz.h1-5-restore"
SSH_OPTIONS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=2",
    "-o",
    "StrictHostKeyChecking=yes",
]
IDENTITY_COMMAND = (
    "set -eu; "
    "cat /etc/openwrt_release /tmp/sysinfo/board_name /proc/sys/kernel/osrelease; "
    "sha256sum /sbin/reload_config /var/run/config.md5 /lib/apk/db/installed "
    "/etc/apk/world /lib/apk/db/scripts.tar.gz /lib/apk/db/triggers; "
    "(cd /etc/config; find . -type f -exec sha256sum '{}' ';' | sort | sha256sum); "
    "test ! -e /usr/sbin/reload_config_rs; "
    "test ! -e /usr/sbin/owrt-reload-config-switch; "
    f"test ! -e {REMOTE_RESTORE}; "
    "if /usr/bin/apk info -e owrt-reload-config >/dev/null 2>&1; then exit 1; fi; "
    "awk '$5 == \"/sbin/reload_config\" { found=1 } "
    "END { exit found ? 1 : 0 }' /proc/self/mountinfo"
)
CLEANUP_COMMAND = (
    "set -u; status=0; "
    f"if [ -d {REMOTE_RUN_ROOT} ]; then busybox rm -r {REMOTE_RUN_ROOT} || status=1; fi; "
    f"if [ -e {REMOTE_APK} ]; then busybox rm {REMOTE_APK} || status=1; fi; "
    f"if [ -e {REMOTE_HARNESS} ]; then busybox rm {REMOTE_HARNESS} || status=1; fi; "
    "exit $status"
)
ROLLBACK_COMMAND = (
    "set -u; status=0; "
    "if /usr/bin/apk info -e owrt-reload-config >/dev/null 2>&1; then "
    "if [ -x /usr/sbin/owrt-reload-config-switch ]; then "
    "/usr/sbin/owrt-reload-config-switch disable >/tmp/h1-5-emergency-disable.log 2>&1 "
    "|| status=1; fi; "
    "/usr/bin/apk --no-network del owrt-reload-config "
    ">/tmp/h1-5-emergency-delete.log 2>&1 || status=1; fi; "
    f"if [ \"$(sha256sum /lib/apk/db/scripts.tar.gz | awk '{{print $1}}')\" != {SCRIPTS_SHA256} ]; then "
    f"if [ \"$(sha256sum /rom/lib/apk/db/scripts.tar.gz | awk '{{print $1}}')\" != {SCRIPTS_SHA256} ]; then status=1; "
    f"elif [ -e {REMOTE_RESTORE} ]; then status=1; "
    f"else cp /rom/lib/apk/db/scripts.tar.gz {REMOTE_RESTORE} || status=1; "
    f"if [ \"$(sha256sum {REMOTE_RESTORE} | awk '{{print $1}}')\" != {SCRIPTS_SHA256} ]; then status=1; "
    f"else chmod 0644 {REMOTE_RESTORE} || status=1; "
    f"mv -f {REMOTE_RESTORE} /lib/apk/db/scripts.tar.gz || status=1; fi; fi; fi; "
    f"if [ -e {REMOTE_RESTORE} ]; then busybox rm {REMOTE_RESTORE} || status=1; fi; "
    "busybox rm /tmp/h1-5-emergency-disable.log /tmp/h1-5-emergency-delete.log "
    "2>/dev/null || true; "
    "exit $status"
)
VERIFY_SUCCESS_COMMAND = (
    "set -eu; "
    f"test ! -e {REMOTE_APK}; test ! -e {REMOTE_HARNESS}; test ! -e {REMOTE_RUN_ROOT}; "
    "/usr/bin/apk info -e owrt-reload-config >/dev/null; "
    "test -x /usr/sbin/reload_config_rs; "
    "test -x /usr/sbin/owrt-reload-config-switch; "
    f"test \"$(sha256sum /usr/sbin/reload_config_rs | awk '{{print $1}}')\" = {CANDIDATE_SHA256}; "
    f"test \"$(sha256sum /usr/sbin/owrt-reload-config-switch | awk '{{print $1}}')\" = {SWITCH_SHA256}; "
    "set +e; output=$(/usr/sbin/owrt-reload-config-switch status 2>&1); rc=$?; set -e; "
    "test \"$rc\" -eq 3; test \"$output\" = disabled; "
    f"test \"$(sha256sum /sbin/reload_config | awk '{{print $1}}')\" = {DISPATCHER_SHA256}; "
    f"test \"$(sha256sum /var/run/config.md5 | awk '{{print $1}}')\" = {BASELINE_SHA256}; "
    f"test \"$(cd /etc/config; find . -type f -exec sha256sum '{{}}' ';' | sort | sha256sum | awk '{{print $1}}')\" = {CONFIG_TREE_SHA256}; "
    f"test \"$(sha256sum /lib/apk/db/installed | awk '{{print $1}}')\" != {PACKAGE_DB_SHA256}; "
    f"test \"$(sha256sum /etc/apk/world | awk '{{print $1}}')\" != {WORLD_SHA256}; "
    f"test \"$(sha256sum /lib/apk/db/scripts.tar.gz | awk '{{print $1}}')\" != {SCRIPTS_SHA256}; "
    f"test \"$(sha256sum /lib/apk/db/triggers | awk '{{print $1}}')\" = {TRIGGERS_SHA256}; "
    f"test ! -e {REMOTE_RESTORE}; "
    "awk '$5 == \"/sbin/reload_config\" { found=1 } "
    "END { exit found ? 1 : 0 }' /proc/self/mountinfo; "
    "printf 'post_install_verify=PASS\\n'"
)
VERIFY_ROLLBACK_COMMAND = (
    "set -eu; "
    f"test ! -e {REMOTE_APK}; test ! -e {REMOTE_HARNESS}; test ! -e {REMOTE_RUN_ROOT}; "
    "if /usr/bin/apk info -e owrt-reload-config >/dev/null 2>&1; then exit 1; fi; "
    "test ! -e /usr/sbin/reload_config_rs; "
    "test ! -e /usr/sbin/owrt-reload-config-switch; "
    f"test \"$(sha256sum /sbin/reload_config | awk '{{print $1}}')\" = {DISPATCHER_SHA256}; "
    f"test \"$(sha256sum /var/run/config.md5 | awk '{{print $1}}')\" = {BASELINE_SHA256}; "
    f"test \"$(cd /etc/config; find . -type f -exec sha256sum '{{}}' ';' | sort | sha256sum | awk '{{print $1}}')\" = {CONFIG_TREE_SHA256}; "
    f"test \"$(sha256sum /lib/apk/db/installed | awk '{{print $1}}')\" = {PACKAGE_DB_SHA256}; "
    f"test \"$(sha256sum /etc/apk/world | awk '{{print $1}}')\" = {WORLD_SHA256}; "
    f"test \"$(sha256sum /lib/apk/db/scripts.tar.gz | awk '{{print $1}}')\" = {SCRIPTS_SHA256}; "
    f"test \"$(sha256sum /lib/apk/db/triggers | awk '{{print $1}}')\" = {TRIGGERS_SHA256}; "
    f"test ! -e {REMOTE_RESTORE}; "
    "awk '$5 == \"/sbin/reload_config\" { found=1 } "
    "END { exit found ? 1 : 0 }' /proc/self/mountinfo; "
    "printf 'post_rollback_verify=PASS\\n'"
)


class RunError(RuntimeError):
    """Raised when the bounded H1.5 install cannot be proven safe."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(command, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RunError(f"command timed out after {timeout}s: {command[0]}") from error


def record(
    evidence_dir: Path,
    name: str,
    result: subprocess.CompletedProcess[bytes],
) -> dict[str, object]:
    stdout_path = evidence_dir / f"{name}.stdout"
    stderr_path = evidence_dir / f"{name}.stderr"
    stdout_path.write_bytes(result.stdout)
    stderr_path.write_bytes(result.stderr)
    return {
        "name": name,
        "exit_status": result.returncode,
        "stdout_sha256": sha256_file(stdout_path),
        "stderr_sha256": sha256_file(stderr_path),
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
    }


def require_success(result: subprocess.CompletedProcess[bytes], stage: str) -> None:
    if result.returncode != 0:
        raise RunError(f"{stage} exited {result.returncode}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--ssh-target", default="openwrt")
    args = parser.parse_args()

    apk = args.apk.resolve()
    harness = args.harness.resolve()
    evidence_dir = args.evidence_dir.resolve()
    if args.ssh_target != "openwrt":
        raise SystemExit("H1.5 only permits the reviewed SSH alias 'openwrt'")
    if sha256_file(apk) != APK_SHA256 or apk.stat().st_size != APK_SIZE:
        raise SystemExit("APK identity mismatch")
    if evidence_dir.exists():
        raise SystemExit(f"refusing to overwrite evidence directory: {evidence_dir}")
    evidence_dir.mkdir(parents=True, mode=0o700)

    started_at = now()
    records: list[dict[str, object]] = []
    transferred = False
    installed_success = False
    run_error: str | None = None
    try:
        identity = run(["ssh", *SSH_OPTIONS, args.ssh_target, IDENTITY_COMMAND], 30)
        records.append(record(evidence_dir, "identity", identity))
        require_success(identity, "identity gate")
        identity_text = identity.stdout.decode("utf-8", errors="strict")
        for marker in (
            "DISTRIB_RELEASE='25.12.5'",
            "DISTRIB_REVISION='r33051-f5dae5ece4'",
            "DISTRIB_TARGET='mediatek/filogic'",
            "xiaomi,mi-router-ax3000t",
            "6.12.94",
            DISPATCHER_SHA256,
            BASELINE_SHA256,
            CONFIG_TREE_SHA256,
            PACKAGE_DB_SHA256,
            WORLD_SHA256,
            SCRIPTS_SHA256,
            TRIGGERS_SHA256,
        ):
            if marker not in identity_text:
                raise RunError(f"identity marker missing: {marker}")

        for source, destination, label in (
            (apk, REMOTE_APK, "transfer_apk"),
            (harness, REMOTE_HARNESS, "transfer_harness"),
        ):
            transferred = True
            result = run(
                ["scp", "-O", *SSH_OPTIONS, str(source), f"{args.ssh_target}:{destination}"],
                60,
            )
            records.append(record(evidence_dir, label, result))
            require_success(result, label)

        harness_sha256 = sha256_file(harness)
        execute_command = (
            "set -eu; "
            f"test \"$(sha256sum {REMOTE_APK} | awk '{{print $1}}')\" = {APK_SHA256}; "
            f"test \"$(sha256sum {REMOTE_HARNESS} | awk '{{print $1}}')\" = {harness_sha256}; "
            f"chmod 0400 {REMOTE_APK}; chmod 0500 {REMOTE_HARNESS}; "
            f"exec {REMOTE_HARNESS}"
        )
        install = run(["ssh", *SSH_OPTIONS, args.ssh_target, execute_command], 180)
        records.append(record(evidence_dir, "install", install))
        require_success(install, "disabled install harness")
        install_text = install.stdout.decode("utf-8", errors="strict")
        for marker in (
            "h1_5_disabled_install=PASS",
            "version=0.1.0-r1",
            "switch_status=disabled",
            "switch_status_rc=3",
            "candidate_activation=false",
            "real_ubus_calls=0",
            "persistent_writes=package-only",
            "runtime_mount_changes=0",
            "cleanup=PASS",
        ):
            if marker not in install_text:
                raise RunError(f"install marker missing: {marker}")
        installed_success = True
    except (RunError, OSError, UnicodeError) as error:
        run_error = str(error)
    finally:
        if transferred:
            if not installed_success:
                rollback = run(["ssh", *SSH_OPTIONS, args.ssh_target, ROLLBACK_COMMAND], 60)
                records.append(record(evidence_dir, "emergency_rollback", rollback))
                if rollback.returncode != 0 and run_error is None:
                    run_error = f"emergency rollback exited {rollback.returncode}"
            cleanup = run(["ssh", *SSH_OPTIONS, args.ssh_target, CLEANUP_COMMAND], 30)
            records.append(record(evidence_dir, "cleanup", cleanup))
            if cleanup.returncode != 0 and run_error is None:
                run_error = f"temporary cleanup exited {cleanup.returncode}"

    verify_command = VERIFY_SUCCESS_COMMAND if installed_success else VERIFY_ROLLBACK_COMMAND
    verify = run(["ssh", *SSH_OPTIONS, args.ssh_target, verify_command], 30)
    records.append(record(evidence_dir, "verify", verify))
    if verify.returncode != 0 and run_error is None:
        run_error = f"final verification exited {verify.returncode}"

    completed_at = now()
    manifest = {
        "schema_version": 1,
        "evidence_id": IMAGE_ID,
        "stage": "H1.5-disabled-install-private",
        "started_at": started_at,
        "completed_at": completed_at,
        "status": "passed" if run_error is None else "failed",
        "error": run_error,
        "apk_sha256": APK_SHA256,
        "apk_size_bytes": APK_SIZE,
        "harness_sha256": sha256_file(harness),
        "ssh_target_alias": args.ssh_target,
        "installed_success": installed_success,
        "records": records,
        "scope": {
            "device_contact": True,
            "device_transfer": True,
            "device_execution": True,
            "tmpfs_writes": True,
            "overlay_writes": True,
            "package_database_writes": True,
            "persistent_writes": True,
            "candidate_activation": False,
            "real_ubus_calls": False,
            "runtime_mount_changes": False,
            "router_reboot": False,
            "firmware_flash": False,
        },
    }
    manifest_path = evidence_dir / "run.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    if run_error is not None:
        raise SystemExit(f"h1_5_disabled_install=false: {run_error}")
    print("h1_5_disabled_install=true")
    print("switch_status=disabled")
    print("candidate_activation=false")
    print("real_ubus_calls=0")
    print("runtime_mount_changes=0")
    print("cleanup_verified=true")


if __name__ == "__main__":
    main()
