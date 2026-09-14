#!/usr/bin/env python3
"""Finish an authorized R92 acceptance after every timed experiment is complete.

Only the byte-verified, task-owned diagnostic directory is removed. Retained
release bundles, installed artifacts, configuration and active processes are
verified without changing them. All raw evidence belongs in private storage.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tarfile

from r84_device_probe import probe

STAGES = ("WINDOWS_COMPLETE", "COMPONENTS_COMPLETE", "DIAGNOSTICS_COMPLETE",
          "REFERENCE_CACHE_COMPLETE", "HOST_HINTS_COMPLETE", "HTTP_LIVE_COMPLETE")
ABSENT = ("/etc/r84-pending", "/etc/r84-reverting", "/etc/p6-pending", "/etc/p6-reverting",
          "/etc/init.d/r84-canary", "/etc/rc.d/S99r84-canary", "/root/r92-prepared",
          "/root/r84-prior-r86", "/root/r84-prior-r87", "/root/r84-prior-r89")
EXECUTION_PLANE = r'''for name in dnsmasq odhcpd hostapd wpa_supplicant; do
    for pid in $(pidof "$name" 2>/dev/null || true); do
        printf '%s %s ' "$name" "$pid"
        sha256sum /proc/"$pid"/exe
    done
done'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def file_hashes(data):
    result = {}
    for line in data.decode().splitlines():
        digest, name = line.split(None, 1)
        name = name.removeprefix("./")
        assert re.fullmatch(r"[a-f0-9]{64}", digest)
        assert name not in result and not Path(name).is_absolute() and ".." not in Path(name).parts
        result[name] = digest
    return result


def normalize_rules(data):
    data = re.sub(r"packets \d+ bytes \d+", "packets N bytes N", data.decode())
    return re.sub(r"(expires|timeout) [0-9smhd]+", r"\1 T", data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("private_root", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--host", default="openwrt")
    p.add_argument("--interface", default="en0")
    a = p.parse_args()
    device = a.private_root / "device"
    assert all((device / name).exists() for name in STAGES), "acceptance experiments are incomplete"
    recovery = device / "recovery-01"
    gate = read(recovery / "gate.json")
    assert gate["offline_backup_verified"] and gate["configuration_matches_backup"]
    assert gate["canonical_validation_passed"] and gate["automatic_rollback_seconds"] == 900
    for name, record in gate["archives"].items():
        assert sha(recovery / name) == record["sha256"]
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    ssh = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
           "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=6", a.host]

    def remote(command, timeout=60):
        return subprocess.check_output(ssh + [command], timeout=timeout)

    def save(name, data):
        (a.output / name).write_text(json.dumps(data, indent=2) + "\n")

    before = probe(host=a.host, mode="rust", interface=a.interface)
    save("health-before.json", before)
    boot = read(device / "windows/rust-2/health.json")["post"]["boot_id"]
    assert before["boot_id"] == boot
    config = remote("sha256sum /etc/config/*")
    assert config == (recovery / "config-before.sha256").read_bytes()
    (a.output / "config-before.sha256").write_bytes(config)
    identity = remote("/bin/sh /root/r84/stack-switch.sh verify rust")
    (a.output / "running-identities.txt").write_bytes(identity)
    manifest_bytes = remote("cat /root/r84/manifest.json")
    assert hashlib.sha256(manifest_bytes).hexdigest() == gate["candidate_manifest_sha256"]
    manifest = json.loads(manifest_bytes)
    actual = {v[0]: v[2] for line in identity.decode().splitlines() if (v := line.split())}
    assert actual == {name: c["rust"]["sha256"] for name, c in manifest["components"].items()}

    retained = []
    candidate_files = {str(f.relative_to(a.private_root / "deployment-r92")): sha(f)
                       for f in (a.private_root / "deployment-r92").rglob("*") if f.is_file()}
    # stack-switch creates these two operational files after installation.
    # A confirmed R92 window leaves an empty rollback log and a Rust next boot.
    candidate_files["canary.log"] = hashlib.sha256(b"").hexdigest()
    candidate_files["next-boot-mode"] = hashlib.sha256(b"rust\n").hexdigest()
    for label, directory, expected in (
        ("R92", "/root/r84", candidate_files),
        ("R90", "/root/r90-before-r92", file_hashes((recovery / "r84.files.sha256").read_bytes())),
        ("R89", "/root/r89-before-r90", file_hashes((recovery / "r89-before-r90.files.sha256").read_bytes())),
    ):
        remote("test -d " + directory + " && test ! -L " + directory)
        hashes = remote("cd " + directory + " && find . -type f -exec sha256sum '{}' ';'")
        (a.output / (label + "-bundle.sha256")).write_bytes(hashes)
        assert file_hashes(hashes) == expected, label + " retained bundle changed"
        retained.append({"release": label, "path": directory, "regular_files_verified": len(expected),
                         "apks_verified": sum(name.startswith("apk/") for name in expected),
                         "files_sha256": hashlib.sha256(hashes).hexdigest()})
    remote("sha256sum -c /root/r84/original.sha256 > /dev/null")
    remote("sha256sum -c /root/r84/installed.sha256 > /dev/null")

    # The original task archive plus the reviewed collector fix defines the
    # complete allowed contents. Unexpected files stop cleanup for inspection.
    archive = device / "diagnostics.tar.gz"
    assert sha(archive) == gate["diagnostic_archive_sha256"]
    expected_diagnostics = {}
    with tarfile.open(archive) as tar:
        for member in tar:
            if member.isfile():
                name = str(Path(member.name).relative_to("r92-diagnostics"))
                expected_diagnostics[name] = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    expected_diagnostics["file_pages.sh"] = sha(Path(__file__).parent / "benchmark/file_pages.sh")
    directory = "/root/r92-diagnostics"
    remote("test -d " + directory + " && test ! -L " + directory)
    hashes = remote("cd " + directory + " && find . -type f -exec sha256sum '{}' ';'")
    (a.output / "diagnostic-files.sha256").write_bytes(hashes)
    assert file_hashes(hashes) == expected_diagnostics
    assert not remote("find " + directory + " -type l").strip(), "diagnostic directory contains symlinks"
    remote(r'''for proc in /proc/[0-9]*; do
    path=$(readlink "$proc/exe" 2>/dev/null || true)
    case "$path" in /root/r92-diagnostics/*) exit 1 ;; esac
done''')
    for path in ABSENT:
        remote("test ! -e " + shlex.quote(path) + " && test ! -L " + shlex.quote(path))
    # Report any remaining task directories; never erase them by a wildcard.
    leftovers = remote("find /tmp -maxdepth 1 -type d -name 'r92-*'")
    (a.output / "temporary-directories.txt").write_bytes(leftovers)
    assert not leftovers.strip(), "a task directory remains; inspect its ownership before removal"
    for category in ("components", "affinity"):
        for collector in (device / category).glob("*/collector.json"):
            directory = read(collector)["remote"]
            assert directory.startswith("/tmp/r85-")
            remote("test ! -e " + shlex.quote(directory))

    execution = remote(EXECUTION_PLANE)
    (a.output / "execution-plane.txt").write_bytes(execution)
    parse_execution = lambda data: {(v[0], v[2]) for line in data.decode().splitlines() if (v := line.split())}
    reference = device / "windows/rust-2/measurements"
    assert parse_execution(execution) == parse_execution((reference / "live/execution-plane.txt").read_bytes())
    rules = remote("nft list ruleset")
    (a.output / "nft-ruleset.txt").write_bytes(rules)
    assert normalize_rules(rules) == normalize_rules((reference / "nft-ruleset.txt").read_bytes())
    kernel = remote("uname -r")
    assert kernel == (reference / "live/kernel.txt").read_bytes()
    remote("rm -rf -- /root/r92-diagnostics && sync")
    remote("test ! -e /root/r92-diagnostics")
    storage = remote("df -k /overlay /tmp")
    (a.output / "storage.txt").write_bytes(storage)
    overlay = next(line.split() for line in storage.decode().splitlines() if line.endswith(" /overlay"))
    available = int(overlay[3])
    assert available > 0
    (a.output / "retained-storage.txt").write_bytes(remote("du -sk /root/r84 /root/r89-before-r90 /root/r90-before-r92"))
    after = probe(host=a.host, mode="rust", interface=a.interface)
    assert after["boot_id"] == boot
    save("health-after.json", after)
    assert remote("/bin/sh /root/r84/stack-switch.sh verify rust") == identity
    final_config = remote("sha256sum /etc/config/*")
    assert final_config == config
    (a.output / "config-after.sha256").write_bytes(final_config)
    save("summary.json", {"schema": 1, "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_commit": manifest["fix_commit"], "client_health_passed": True,
        "same_final_cold_boot": True, "configuration_unchanged": True, "execution_plane_unchanged": True,
        "firewall_rules_unchanged": True, "kernel": kernel.decode().strip(),
        "active_component_sha256": actual, "retained_bundles": retained,
        "original_and_installed_artifacts_verified": True, "diagnostic_files_removed": len(expected_diagnostics),
        "no_pending_rollback_or_canary": True, "no_task_temporary_directory": True,
        "overlay_available_kib": available, "firmware_flashed": False,
        "automatic_fallback": "Exact original C stack; R90 needs its retained APKs reinstalled before switching.",
        "driver_sha256": sha(Path(__file__))})
    (a.output / "COMPLETE").touch()
    print(json.dumps({"final_device_acceptance": True, "overlay_available_kib": available}))


if __name__ == "__main__":
    main()
