#!/usr/bin/env python3
"""Run the approved H1.4 tmpfs shadow harness over the existing SSH path."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
CANDIDATE_SHA256 = "b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75"
CANDIDATE_SIZE = 346_531
DISPATCHER_SHA256 = "f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15"
REMOTE_CANDIDATE = "/tmp/owrt-h1-4-reload-config-rs"
REMOTE_HARNESS = "/tmp/owrt-h1-4-shadow.sh"
REMOTE_RUN_ROOT = "/tmp/owrt-r05-shadow-20260901"
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
    "sha256sum /sbin/reload_config /var/run/config.md5; "
    "test ! -e /usr/sbin/reload_config_rs; "
    "test ! -e /usr/sbin/owrt-reload-config-switch; "
    "awk '$5 == \"/sbin/reload_config\" { found=1 } "
    "END { exit found ? 1 : 0 }' /proc/self/mountinfo"
)
VERIFY_COMMAND = (
    "set -eu; "
    f"test ! -e {REMOTE_CANDIDATE}; "
    f"test ! -e {REMOTE_HARNESS}; "
    f"test ! -e {REMOTE_RUN_ROOT}; "
    "sha256sum /sbin/reload_config /var/run/config.md5; "
    "test ! -e /usr/sbin/reload_config_rs; "
    "test ! -e /usr/sbin/owrt-reload-config-switch; "
    "awk '$5 == \"/sbin/reload_config\" { found=1 } "
    "END { exit found ? 1 : 0 }' /proc/self/mountinfo; "
    "printf 'post_cleanup=PASS\\n'"
)
CLEANUP_COMMAND = (
    "set -u; status=0; "
    f"if [ -d {REMOTE_RUN_ROOT} ]; then busybox rm -r {REMOTE_RUN_ROOT} || status=1; fi; "
    f"if [ -e {REMOTE_CANDIDATE} ]; then busybox rm {REMOTE_CANDIDATE} || status=1; fi; "
    f"if [ -e {REMOTE_HARNESS} ]; then busybox rm {REMOTE_HARNESS} || status=1; fi; "
    "exit $status"
)


class RunError(RuntimeError):
    """Raised when a frozen H1.4 operation fails."""


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


def write_result(
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
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--ssh-target", default="openwrt")
    args = parser.parse_args()

    candidate = args.candidate.resolve()
    harness = args.harness.resolve()
    evidence_dir = args.evidence_dir.resolve()
    if args.ssh_target != "openwrt":
        raise SystemExit("H1.4 only permits the reviewed SSH alias 'openwrt'")
    if sha256_file(candidate) != CANDIDATE_SHA256 or candidate.stat().st_size != CANDIDATE_SIZE:
        raise SystemExit("candidate identity mismatch")
    if evidence_dir.exists():
        raise SystemExit(f"refusing to overwrite evidence directory: {evidence_dir}")
    evidence_dir.mkdir(parents=True, mode=0o700)

    started_at = now()
    records: list[dict[str, object]] = []
    transferred = False
    run_error: str | None = None
    try:
        identity = run(["ssh", *SSH_OPTIONS, args.ssh_target, IDENTITY_COMMAND], 30)
        records.append(write_result(evidence_dir, "identity", identity))
        require_success(identity, "identity gate")
        identity_text = identity.stdout.decode("utf-8", errors="strict")
        for marker in (
            "DISTRIB_RELEASE='25.12.5'",
            "DISTRIB_REVISION='r33051-f5dae5ece4'",
            "DISTRIB_TARGET='mediatek/filogic'",
            "xiaomi,mi-router-ax3000t",
            "6.12.94",
            DISPATCHER_SHA256,
        ):
            if marker not in identity_text:
                raise RunError(f"identity marker missing: {marker}")

        for source, destination, label in (
            (candidate, REMOTE_CANDIDATE, "transfer_candidate"),
            (harness, REMOTE_HARNESS, "transfer_harness"),
        ):
            # A failed scp can still leave a partial file at the fixed target.
            transferred = True
            result = run(
                ["scp", *SSH_OPTIONS, str(source), f"{args.ssh_target}:{destination}"],
                60,
            )
            records.append(write_result(evidence_dir, label, result))
            require_success(result, label)

        harness_sha256 = sha256_file(harness)
        execute_command = (
            "set -eu; "
            f"test \"$(sha256sum {REMOTE_CANDIDATE} | awk '{{print $1}}')\" = "
            f"{CANDIDATE_SHA256}; "
            f"test \"$(sha256sum {REMOTE_HARNESS} | awk '{{print $1}}')\" = "
            f"{harness_sha256}; "
            f"chmod 0500 {REMOTE_CANDIDATE} {REMOTE_HARNESS}; "
            f"exec {REMOTE_HARNESS}"
        )
        shadow = run(["ssh", *SSH_OPTIONS, args.ssh_target, execute_command], 120)
        records.append(write_result(evidence_dir, "shadow", shadow))
        require_success(shadow, "shadow harness")
        shadow_text = shadow.stdout.decode("utf-8", errors="strict")
        for marker in (
            "h1_4_shadow=PASS",
            "run1_shared_baseline=PASS",
            "run2_creation_silent=PASS",
            "run3_modification_event=PASS",
            "real_ubus_calls=0",
            "persistent_writes=0",
            "runtime_mount_changes=0",
            "cleanup=PASS",
        ):
            if marker not in shadow_text:
                raise RunError(f"shadow marker missing: {marker}")
    except (RunError, OSError, UnicodeError) as error:
        run_error = str(error)
    finally:
        if transferred:
            cleanup = run(["ssh", *SSH_OPTIONS, args.ssh_target, CLEANUP_COMMAND], 30)
            records.append(write_result(evidence_dir, "cleanup", cleanup))
            if cleanup.returncode != 0 and run_error is None:
                run_error = f"emergency cleanup exited {cleanup.returncode}"

    verify = run(["ssh", *SSH_OPTIONS, args.ssh_target, VERIFY_COMMAND], 30)
    records.append(write_result(evidence_dir, "verify", verify))
    if verify.returncode != 0 and run_error is None:
        run_error = f"post-cleanup verification exited {verify.returncode}"

    completed_at = now()
    manifest = {
        "schema_version": 1,
        "evidence_id": IMAGE_ID,
        "stage": "H1.4-device-run-private",
        "started_at": started_at,
        "completed_at": completed_at,
        "status": "passed" if run_error is None else "failed",
        "error": run_error,
        "candidate_sha256": CANDIDATE_SHA256,
        "candidate_size_bytes": CANDIDATE_SIZE,
        "harness_sha256": sha256_file(harness),
        "ssh_target_alias": args.ssh_target,
        "records": records,
        "scope": {
            "device_contact": True,
            "device_transfer": True,
            "device_execution": True,
            "tmpfs_writes": True,
            "persistent_writes": False,
            "real_ubus_calls": False,
            "runtime_mount_changes": False,
            "package_install": False,
            "router_reboot": False,
            "firmware_flash": False,
        },
    }
    manifest_path = evidence_dir / "run.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    if run_error is not None:
        raise SystemExit(f"h1_4_device_run=false: {run_error}")
    print("h1_4_device_run=true")
    print("tmpfs_only=true")
    print("real_ubus_calls=0")
    print("persistent_writes=0")
    print("cleanup_verified=true")


if __name__ == "__main__":
    main()
