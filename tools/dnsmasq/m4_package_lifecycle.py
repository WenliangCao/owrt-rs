#!/usr/bin/env python3
"""Exercise dnsmasq APK replacement and rollback in a disposable exact rootfs.

The rootfs contains the stock image package database.  This checker never
contacts a router and never writes the supplied rootfs; it copies that tree,
then runs the image's own ``apk`` through ``chroot``.  A stock APK is required
for the final rollback, so an absent fixture is a hard setup failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / "private"
STOCK_DNSMASQ_SHA256 = "097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87"
CONTRACT_FILES = (
    "etc/config/dhcp",
    "etc/dnsmasq.conf",
    "etc/hotplug.d/ntp/25-dnsmasqsec",
    "etc/init.d/dnsmasq",
    "etc/uci-defaults/50-dnsmasq-migrate-ipset.sh",
    "etc/uci-defaults/50-dnsmasq-migrate-resolv-conf-auto.sh",
    "lib/apk/packages/dnsmasq.rusers",
    "lib/apk/packages/dnsmasq.conffiles",
    "lib/apk/packages/dnsmasq.conffiles_static",
    "lib/upgrade/keep.d/dnsmasq",
    "usr/lib/dnsmasq/dhcp-script.sh",
    "usr/sbin/dnsmasq",
    "usr/share/acl.d/dnsmasq_acl.json",
    "usr/share/dnsmasq/dhcpbogushostname.conf",
    "usr/share/dnsmasq/rfc6761.conf",
)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(root: Path, args: list[str], log: Path) -> subprocess.CompletedProcess[str]:
    command = ["chroot", str(root), "/usr/bin/apk", "--root", "/", *args]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    log.write_text(json.dumps({"command": command, "returncode": result.returncode,
                               "stdout": result.stdout, "stderr": result.stderr}, indent=2) + "\n")
    if result.returncode:
        raise RuntimeError(f"apk command failed ({result.returncode}): {' '.join(args)}")
    return result


def package_version(root: Path, log: Path) -> str:
    result = run(root, ["--no-network", "query", "--from", "installed",
                        "--fields", "name,version", "dnsmasq"], log)
    return result.stdout.strip()


def hashes(root: Path) -> dict[str, str | None]:
    return {relative: sha(root / relative) if (root / relative).is_file() else None
            for relative in CONTRACT_FILES}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--stock-apk", type=Path, required=True)
    parser.add_argument("--candidate-apk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--candidate-elf-sha256")
    args = parser.parse_args()

    if os.name != "posix" or os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        parser.error("exact rootfs lifecycle requires root inside DNSMASQ_TEST_ISOLATED")
    rootfs, stock, candidate, out = (path.resolve() for path in
                                     (args.rootfs, args.stock_apk, args.candidate_apk, args.out))
    if not out.is_relative_to(PRIVATE) or out.exists():
        parser.error("--out must be a new path below private/")
    if any(not path.is_file() for path in (stock, candidate)):
        parser.error("stock and candidate APKs must be files")
    if not rootfs.is_dir() or not (rootfs / "usr/bin/apk").is_file():
        parser.error("rootfs must contain the image apk executable")
    if sha(rootfs / "usr/sbin/dnsmasq") != STOCK_DNSMASQ_SHA256:
        parser.error("rootfs stock dnsmasq identity mismatch")
    out.mkdir(parents=True)
    work = out / "rootfs"
    shutil.copytree(rootfs, work, symlinks=True)
    (work / "m4").mkdir()
    shutil.copy2(stock, work / "m4/stock.apk")
    shutil.copy2(candidate, work / "m4/candidate.apk")
    report: dict[str, object] = {
        "status": "failed", "rootfs_stock_sha256": STOCK_DNSMASQ_SHA256,
        "stock_apk_sha256": sha(stock), "candidate_apk_sha256": sha(candidate),
        "candidate_elf_sha256": args.candidate_elf_sha256,
        "contract_files": list(CONTRACT_FILES), "stages": [],
        "scope": "exact-image APK install/upgrade/uninstall/rollback; no router or daemon traffic",
    }
    try:
        before = hashes(work)
        package_version(work, out / "01-query-stock.json")
        report["stock_version"] = "present-before-install"
        run(work, ["--no-network", "--no-scripts", "--allow-untrusted", "add", "--force-overwrite",
                   "/m4/candidate.apk"], out / "02-install-candidate.json")
        report["stages"].append("install")
        candidate_version = package_version(work, out / "03-query-candidate.json")
        after_install = hashes(work)
        if after_install["usr/sbin/dnsmasq"] == before["usr/sbin/dnsmasq"]:
            raise RuntimeError("candidate install did not replace /usr/sbin/dnsmasq")
        if args.candidate_elf_sha256 and after_install["usr/sbin/dnsmasq"] != args.candidate_elf_sha256:
            raise RuntimeError("installed candidate ELF hash differs from supplied identity")
        report["candidate_version"] = candidate_version
        report["candidate_hashes"] = after_install
        run(work, ["--no-network", "--no-scripts", "--allow-untrusted", "add", "--force-overwrite",
                   "--force-reinstall", "/m4/candidate.apk"], out / "04-upgrade-candidate.json")
        report["stages"].append("upgrade")
        run(work, ["--no-network", "del", "dnsmasq"], out / "05-uninstall-candidate.json")
        report["stages"].append("uninstall")
        if (work / "usr/sbin/dnsmasq").exists():
            raise RuntimeError("candidate uninstall left /usr/sbin/dnsmasq")
        run(work, ["--no-network", "--no-scripts", "--allow-untrusted", "add", "--force-overwrite",
                   "/m4/stock.apk"], out / "06-rollback-stock.json")
        report["stages"].append("rollback")
        restored = hashes(work)
        if restored != before:
            raise RuntimeError("rollback did not restore stock contract hashes")
        report["restored_hashes"] = restored
        report["status"] = "passed"
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = repr(error)
    finally:
        report["recorded_at"] = time.time()
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({"status": report["status"], "stages": report["stages"]}))
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
