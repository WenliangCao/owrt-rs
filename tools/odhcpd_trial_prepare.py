#!/usr/bin/env python3
"""Prepare a finite odhcpd bind-mount trial; never contacts a router.

The bundle remains private. Activation is a separate, explicitly authorized
operation after the exact candidate's functional/SDK/performance gates pass.
Confirmation records external client health and immediately restores C.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tarfile
import uuid

REPO = Path(__file__).resolve().parent.parent
C_SHA = "53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82"
INIT_SHA = "4d59c3687e7cacee9e7b82ba9433fa815aafeb8f94af4c6926993653009e0fa4"
TRIGGER_SHA = "1a29b066be81007cbc354b311fd30f30d625eb82754a2abcd3b207115da450d5"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_file(path, expected):
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or path.is_symlink() or not path.is_file() or sha(path) != expected:
        raise ValueError(f"input identity mismatch: {path.name}")


def static_aarch64(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError(f"not a little-endian ELF64 AArch64 executable: {path.name}")
    kind, = struct.unpack_from("<H", data, 16)
    offset, = struct.unpack_from("<Q", data, 32)
    size, count = struct.unpack_from("<HH", data, 54)
    if kind not in (2, 3) or size < 56 or not count or offset + size * count > len(data):
        raise ValueError(f"invalid executable program headers: {path.name}")
    if any(struct.unpack_from("<I", data, offset + i * size)[0] == 3 for i in range(count)):
        raise ValueError(f"trial helpers/candidate must not depend on a dynamic loader: {path.name}")


def config_hashes(backup):
    result = {}
    seen = set()
    with tarfile.open(backup) as archive:
        for member in archive:
            name = member.name.lstrip("/")
            if name.startswith("./"):
                name = name[2:]
            if not name or ".." in Path(name).parts or any(ord(c) < 32 or ord(c) == 127 for c in name) or name in seen:
                raise ValueError("ambiguous or unsafe backup member")
            seen.add(name)
            if not name.startswith("etc/config/"):
                continue
            if not member.isfile():
                raise ValueError("configuration backup must contain regular UCI files")
            result["/" + name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    if not {"/etc/config/dhcp", "/etc/config/network", "/etc/config/system"} <= set(result):
        raise ValueError("backup lacks dhcp/network/system configuration")
    return result


def prepare(candidate, candidate_sha, rootfs, backup, backup_sha, helper, helper_sha, boot, output, timeout=300):
    output = output.resolve()
    if not output.is_relative_to((REPO / "private").resolve()) or output.exists():
        raise ValueError("output must be a new directory below the ignored private/ directory")
    if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot):
        raise ValueError("expected boot ID is required")
    if not 5 <= timeout <= 900:
        raise ValueError("trial timeout must be 5..900 seconds")
    for path, expected in ((candidate, candidate_sha), (backup, backup_sha), (helper, helper_sha),
                           (rootfs / "usr/sbin/odhcpd", C_SHA),
                           (rootfs / "etc/init.d/odhcpd", INIT_SHA),
                           (rootfs / "usr/sbin/odhcpd-update", TRIGGER_SHA)):
        checked_file(path, expected)
    static_aarch64(candidate)
    static_aarch64(helper)
    if candidate_sha == C_SHA:
        raise ValueError("candidate must be distinct from the reference C ELF")
    configs = config_hashes(backup)
    token = str(uuid.uuid4())
    remote = "/tmp/owrt-odhcpd-trial-" + token
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    copies = {
        "candidate.elf": candidate, "stock.elf": rootfs / "usr/sbin/odhcpd",
        "original-init": rootfs / "etc/init.d/odhcpd",
        "original-trigger": rootfs / "usr/sbin/odhcpd-update",
        "config-backup.tar.gz": backup, "bounded": helper,
        "trial.sh": REPO / "tools/odhcpd_trial.sh",
    }
    for name, source in copies.items():
        shutil.copyfile(source, output / name)
        (output / name).chmod(0o500 if name in ("candidate.elf", "stock.elf", "bounded", "trial.sh") else 0o400)
    inputs = {"TOKEN": token, "BOOT": boot, "CANDIDATE_SHA": candidate_sha,
              "C_SHA": C_SHA, "INIT_SHA": INIT_SHA, "TRIGGER_SHA": TRIGGER_SHA,
              "HELPER_SHA": helper_sha, "BACKUP_SHA": backup_sha, "LIMIT": str(timeout)}
    # Every value is a validated digest, UUID or integer. No user text becomes
    # shell code; the manifest authenticates this file before it is sourced.
    (output / "inputs.env").write_text("".join(f"{key}='{value}'\n" for key, value in inputs.items()))
    (output / "config.sha256").write_text("".join(f"{digest}  {path}\n" for path, digest in sorted(configs.items())))
    (output / "inputs.env").chmod(0o400)
    (output / "config.sha256").chmod(0o400)
    names = sorted([*copies, "inputs.env", "config.sha256"])
    (output / "bundle.sha256").write_text("".join(f"{sha(output / name)}  {name}\n" for name in names))
    (output / "bundle.sha256").chmod(0o400)
    bundle_sha = sha(output / "bundle.sha256")
    command = f"/bin/sh {remote}/trial.sh"
    args = f"{token} {boot} {bundle_sha}"
    receipt = {"status": "prepared_not_deployed", "remote_directory": remote,
               "token": token, "expected_boot_id": boot, "candidate_sha256": candidate_sha,
               "stock_sha256": C_SHA, "backup_sha256": backup_sha,
               "bundle_manifest_sha256": bundle_sha, "timeout_s": timeout,
               "config_files": len(configs), "confirmation_restores_C": True,
               "mutations": ["one tmpfs file bind at /usr/sbin/odhcpd", "original odhcpd init stop/restart only"],
               "commands": {"preflight": f"{command} preflight {args}", "activate": f"{command} activate {args}",
                            "restore": f"{command} restore {args}",
                            "confirm": f"{command} confirm {args} CLIENT_HEALTH_RECEIPT_SHA256"}}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (output / "receipt.json").chmod(0o600)
    (output / "REVIEW.txt").write_text(f"""Prepared only. No device was contacted or changed by this tool.

Activation requires functional and exact SDK ELF qualification, an accepted
performance decision, and user authorization covering this trial. Existing
authorization remains valid; this tool does not create an approval step. Preserve the
local private bundle and receipt. Transfer the immutable bundle files into:
  {remote}
Verify the transferred bundle.sha256 against {bundle_sha}, then its contents.
The directory must be on the router's existing /tmp tmpfs. The commands below
do not create a boot service, change UCI, restart other services or reboot.

Read-only gate: {receipt['commands']['preflight']}
Approved activation: {receipt['commands']['activate']}
Manual early restore: {receipt['commands']['restore']}
Confirmation: {receipt['commands']['confirm']}

The detached setsid guard performs the bind and original-init restart itself,
then restores C on timeout ({timeout} s), candidate process loss, TERM, early
restore, or successful confirmation. No persistent promotion mode exists.
SSH may disappear: guard input is /dev/null and output is private guard.log.

For confirmation, first save client-health.json in the remote trial directory:
{{"passed":true,"trial_token":"{token}","boot_id":"{boot}",
 "candidate_sha256":"{candidate_sha}","external_health_token":"SHA256_OF_EXTERNAL_CLIENT_HEALTH_EVIDENCE"}}
Only a passed external client health assessment may produce this receipt.
Pass its actual SHA256 to confirm; a stale token/boot/candidate is rejected.
Confirmation immediately restores C and verifies its supervised PID, dhcp
object and original UCI hashes. State 'restored-confirmed' is successful trial
completion; any restore failure retains the lock/evidence and is not success.
Do not remove the bundle or lock while active. Copy logs and the final state
back to the private archive before deleting owned files after restoration.
""")
    (output / "REVIEW.txt").chmod(0o600)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "rootfs", "backup", "helper", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("candidate-sha256", "backup-sha256", "helper-sha256", "expected-boot-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    receipt = prepare(args.candidate, args.candidate_sha256, args.rootfs, args.backup,
                      args.backup_sha256, args.helper, args.helper_sha256, args.expected_boot_id,
                      args.output, args.timeout_seconds)
    print(json.dumps({key: receipt[key] for key in ("status", "remote_directory", "bundle_manifest_sha256", "timeout_s")}, indent=2))


if __name__ == "__main__":
    main()
