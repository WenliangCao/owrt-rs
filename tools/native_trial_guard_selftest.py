#!/usr/bin/env python3
"""Exercise native trial recovery with the real image shell and C restorer.

Build host only. Each case gets a disposable chroot, fake uptime/PID1, mocked
health and reboot. No physical networking, flash, watchdog or reboot access.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


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

    def case(name, setup, command="run", stock=False, success=True):
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
exec /root/owrt-native-trial/bounded-real "$@"
''')
        (base / "bounded").chmod(0o755)
        (base / "armed").write_text("fixture-token\n")
        (base / "recovery.sha256").write_text(
            (source / "usr/share/owrt-control-plane/stock.sha256").read_text())
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
        for p in (source / "etc/config").iterdir():
            assert p.read_bytes() == (root / "etc/config" / p.name).read_bytes(), (name, p.name)
        if stock:
            assert (root / "tmp/reboots").read_text() == "-f\n"
            assert (base / "restored").read_text().strip() == BOOT
        else:
            assert not (root / "tmp/reboots").exists()
        results[name] = True
        print("PASS:", name, flush=True)
        return root

    case("first_boot_requires_client_confirmation", "", stock=True)
    case("accepted_but_no_network_restores_after_300s", f"cp /{BASE}/armed /{BASE}/accepted; touch /tmp/fail-health", stock=True)
    case("third_unhealthy_boot_restores", f"echo 2 > /{BASE}/unhealthy-boots", stock=True)
    root = case("healthy_accepted_boot_resets_counter", f"cp /{BASE}/armed /{BASE}/accepted; echo 1 > /{BASE}/unhealthy-boots; touch /tmp/disarm-after-three")
    assert (root / BASE / "unhealthy-boots").read_text() == "0\n"
    assert (root / BASE / "healthy-boot").read_text().strip() == BOOT
    case("health_lost_after_acceptance_restores", f"cp /{BASE}/armed /{BASE}/accepted; touch /tmp/fail-after-three", stock=True)
    root = case("matching_client_confirmation_accepted", "", f"confirm fixture-token {BOOT}")
    assert (root / BASE / "accepted").read_text() == "fixture-token\n"
    root = case("stale_client_confirmation_rejected", "", f"confirm wrong-token {BOOT}", success=False)
    assert not (root / BASE / "accepted").exists()
    case("damaged_C_original_blocks_recovery", "echo corrupt > /usr/libexec/owrt-stock/sbin/netifd", "restore", success=False)
    case("recovered_C_boot_does_not_reboot", "cp /usr/libexec/owrt-stock/sbin/procd /proc/1/exe")
    (out / "result.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
