#!/usr/bin/env python3
"""Exercise the candidate image shell and complete C recovery off-device.

Clock, health, sysupgrade and reboot are mocked; exact C recovery is real.
No physical flash, networking, watchdog or reboot access. Handoff ambiguity
is tested as a no-second-action contract, not claimed as a real flash test.
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


BOOT = "11111111-1111-1111-1111-111111111111"
BASE = "root/owrt-native-trial"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("bounded", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == "Linux"
    assert platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists()
    source, out = args.rootfs.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tools = Path(__file__).resolve().parent
    manifest = json.loads((source / "usr/share/owrt-control-plane/release.json").read_text())
    results = {}

    def case(name, setup, command="run", stock=False, success=True, handoff=False):
        root = out / name
        subprocess.run(["cp", "-a", str(source), str(root)], check=True)
        base = root / BASE
        base.mkdir()
        shutil.copy2(tools / "native_trial_guard.sh", base / "native_trial_guard.sh")
        shutil.copy2(args.bounded, base / "bounded-real")
        (base / "bounded-real").chmod(0o755)
        (base / "bounded").write_text('''#!/bin/sh
if [ "$1" = bounded ] && [ "${5:-}" = health ]; then
    [ ! -f /tmp/fail-health ]
    exit $?
fi
if [ "$1" = bounded ] && [ "${3:-}" = ubus ]; then
    [ ! -f /tmp/fail-bus ] || exit 1
    echo '{"board_name":"xiaomi,mi-router-ax3000t"}'
    exit 0
fi
exec /root/owrt-native-trial/bounded-real "$@"
''')
        (base / "bounded").chmod(0o755)
        (base / "armed").write_text("fixture-token\n")
        (base / "recovery.sha256").write_text(
            (source / "usr/share/owrt-control-plane/stock.sha256").read_text())
        (base / "rollback.bin").write_bytes(b"synthetic-image-never-flashed")
        with tarfile.open(base / "rollback-config.tar.gz", "w:gz") as archive:
            # Real sysupgrade backups commonly omit parent directory members.
            # Repacking must not add 0700 /etc or /etc/config from umask077.
            for path in (source / "etc/config").iterdir():
                archive.add(path, arcname="etc/config/" + path.name)
        with tarfile.open(base / "rollback-config.tar.gz") as archive:
            names = [member.name for member in archive.getmembers()]
        (base / "rollback-members.txt").write_text("\n".join(names) + "\n")
        (base / "rollback.sha256").write_text("".join(
            hashlib.sha256((base / name).read_bytes()).hexdigest() + "  /" + BASE + "/" + name + "\n"
            for name in ("rollback.bin", "rollback-config.tar.gz", "rollback-members.txt")))
        (root / "sbin/sysupgrade").write_text('''#!/bin/sh
printf '%s\n' "$*" >> /tmp/sysupgrade-calls
if [ "$1" = -T ]; then
    [ ! -f /tmp/fail-preflight ]
    exit $?
fi
[ "$1" = -f ] || exit 2
cmp -s /root/owrt-native-trial/rollback.bin "$3" || exit 3
mkdir /tmp/restored-config
tar -xzf "$2" -C /tmp/restored-config || exit 4
[ ! -f /tmp/handoff-timeout ] || exit 124
exit 0
''')
        (root / "sbin/sysupgrade").chmod(0o755)
        for directory in ("proc/1", "proc/self", "proc/sys/kernel/random", "tmp/test-bin", "dev"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / "sbin/procd", root / "proc/1/exe")
        (root / "proc/sys/kernel/random/boot_id").write_text(BOOT + "\n")
        (root / "proc/uptime").write_text("0.00 0.00\n")
        (root / "proc/self/mountinfo").write_text("1 0 0:1 / / rw - overlay overlay rw\n")
        if not (root / "dev/null").exists():
            subprocess.run(["mknod", "-m", "666", str(root / "dev/null"), "c", "1", "3"], check=True)
        (root / "tmp/test-bin/reboot").write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> /tmp/reboots\n')
        (root / "tmp/test-bin/sleep").write_text('''#!/bin/sh
n=$(cat /tmp/sleep-count); n=$((n+1)); echo "$n" > /tmp/sleep-count
t=$(cut -d. -f1 /proc/uptime)
printf '%s.00 0.00\n' "$((t + 150))" > /proc/uptime
if [ "$n" -ge 3 ]; then
    [ ! -f /tmp/disarm-after-three ] || rm /root/owrt-native-trial/armed
    [ ! -f /tmp/fail-after-three ] || touch /tmp/fail-health
fi
if [ "$n" -eq 5 ] && [ -f /tmp/confirm-at-deadline ]; then
    rmdir /tmp/owrt-native-decision-lock
    printf 'fixture-token %s\n' "$(cat /proc/sys/kernel/random/boot_id)" > /root/owrt-native-trial/accepted
fi
if [ "$n" -ge 7 ] && [ -f /tmp/confirm-at-deadline ]; then
    rm /root/owrt-native-trial/armed
fi
''')
        for p in (root / "tmp/test-bin").iterdir():
            p.chmod(0o755)
        (root / "tmp/sleep-count").write_text("0\n")
        script = f'''set -eu
export PATH=/tmp/test-bin:/usr/sbin:/usr/bin:/sbin:/bin
{setup}
exec /bin/sh /{BASE}/native_trial_guard.sh {command}
'''
        result = subprocess.run(["chroot", str(root), "/bin/sh", "-s"], input=script,
                                text=True, capture_output=True, timeout=30)
        (out / (name + ".log")).write_text(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, (name, result.returncode, result.stderr)
        for c in manifest["components"].values():
            expected = c["stock_sha256" if stock else "rust_sha256"]
            assert hashlib.sha256((root / c["path"].lstrip("/")).read_bytes()).hexdigest() == expected, (name, c["path"])
        for c in manifest["integration_files"].values():
            expected = c["stock_sha256" if stock else "replacement_sha256"]
            target = root / c["path"].lstrip("/")
            assert hashlib.sha256(target.read_bytes()).hexdigest() == expected
            assert target.stat().st_mode & 0o777 == (source / c["recovery_path"].lstrip("/")).stat().st_mode & 0o777
        for p in (source / "etc/config").iterdir():
            assert p.read_bytes() == (root / "etc/config" / p.name).read_bytes(), (name, p.name)
        if stock:
            assert (root / "tmp/reboots").read_text() == "-f\n"
            assert (base / "c-bridge-used").read_text().strip() == BOOT
        else:
            assert not (root / "tmp/reboots").exists()
        calls = (root / "tmp/sysupgrade-calls").read_text().splitlines() if (root / "tmp/sysupgrade-calls").exists() else []
        submitted = [line for line in calls if line.startswith("-f ")]
        assert len(submitted) == int(handoff), (name, calls)
        if handoff:
            restored = root / "tmp/restored-config"
            with tarfile.open(root / "tmp/owrt-native-rollback/config.tar.gz") as archive, tarfile.open(base / "rollback-config.tar.gz") as original:
                assert "etc" not in archive.getnames() and "etc/config" not in archive.getnames()
                for old in original.getmembers():
                    new = archive.getmember(old.name)
                    assert (old.type, old.mode, old.uid, old.gid, old.linkname, int(old.mtime)) == (
                        new.type, new.mode, new.uid, new.gid, new.linkname, int(new.mtime))
                    if old.isfile():
                        assert original.extractfile(old).read() == archive.extractfile(new).read()
            for p in (source / "etc/config").iterdir():
                assert p.read_bytes() == (restored / "etc/config" / p.name).read_bytes()
                assert p.stat().st_mode & 0o777 == (restored / "etc/config" / p.name).stat().st_mode & 0o777
            assert (restored / "root/owrt-native-rollback-receipt/guard.log").is_file()
            assert not (restored / "root/owrt-native-trial").exists()
            assert not (restored / "etc/init.d/owrt-native-trial").exists()
        if command == "run":
            assert not (root / "tmp/owrt-native-guard-lock").exists()
        results[name] = True
        print("PASS:", name, flush=True)
        return root

    accepted = f"printf 'fixture-token {BOOT}\\n' > /{BASE}/accepted"
    case("first_boot_requires_client_confirmation", "", handoff=True)
    case("previous_boot_confirmation_is_not_reused", f"echo 'fixture-token another-boot' > /{BASE}/accepted", handoff=True)
    case("accepted_no_network_requests_rollback_after_300s", accepted + "; touch /tmp/fail-health", handoff=True)
    case("third_unhealthy_boot_requests_rollback", f"echo 2 > /{BASE}/unhealthy-boots", handoff=True)
    root = case("healthy_accepted_boot_resets_counter", accepted + f"; echo 1 > /{BASE}/unhealthy-boots; touch /tmp/disarm-after-three")
    assert (root / BASE / "unhealthy-boots").read_text() == "0\n"
    assert (root / BASE / "healthy-boot").read_text().strip() == BOOT
    case("health_lost_after_acceptance_requests_rollback", accepted + "; touch /tmp/fail-after-three", handoff=True)
    root = case("matching_client_confirmation_accepted", "", f"confirm fixture-token {BOOT}")
    assert (root / BASE / "accepted").read_text() == f"fixture-token {BOOT}\n"
    case("stale_client_confirmation_rejected", "", f"confirm wrong-token {BOOT}", success=False)
    for filename in ("rollback.bin", "rollback-config.tar.gz"):
        case("damaged_" + filename + "_blocks_rollback", f"echo corrupt > /{BASE}/{filename}", "restore", success=False)
    case("damaged_C_original_blocks_rollback", "echo corrupt > /usr/libexec/owrt-stock/sbin/netifd", "restore", success=False)
    case("failed_sysupgrade_preflight_has_no_handoff_or_bridge", "touch /tmp/fail-preflight", "restore", success=False)
    case("unavailable_bus_before_handoff_uses_one_C_bridge", "touch /tmp/fail-bus", "restore", stock=True)
    case("returned_sysupgrade_never_forces_reboot", "", "restore", handoff=True)
    case("ambiguous_timeout_never_forces_reboot", "touch /tmp/handoff-timeout", "restore", handoff=True)
    case("submitted_handoff_not_repeated_after_boot", f"echo older-boot > /{BASE}/rollback-requested", success=False)
    case("C_bridge_retry_requires_C_PID1", f"echo older-boot > /{BASE}/c-bridge-used", success=False)
    cboot = f"echo older-boot > /{BASE}/c-bridge-used; cp /usr/libexec/owrt-stock/sbin/procd /proc/1/exe"
    case("C_bridge_boot_submits_complete_rollback_once", cboot, handoff=True)
    case("C_bridge_second_bus_failure_has_no_reboot", cboot + "; touch /tmp/fail-bus", success=False)
    case("C_bridge_retry_fuse_survives_boot", cboot + f"; echo older-boot > /{BASE}/c-bridge-rollback-attempted", success=False)
    case("handoff_marker_write_failure_prevents_submission", f"mkdir /{BASE}/rollback-requested.new", "restore", success=False)
    case("C_bridge_marker_write_failure_prevents_replacement", f"touch /tmp/fail-bus; mkdir /{BASE}/c-bridge-used.new", "restore", success=False)
    case("deadline_racing_confirmation_keeps_guard", "mkdir /tmp/owrt-native-decision-lock; touch /tmp/confirm-at-deadline")
    (out / "result.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
