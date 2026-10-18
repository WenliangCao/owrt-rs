#!/usr/bin/env python3
"""Run the configuration guard with exact image BusyBox in Linux chroots.

No device, network namespace, real /proc, sysfs or reboot is exposed. Clocks,
reboot, setsid and sync are stubs. Production guard/init files are unchanged.
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


BASE = "root/owrt-offload-trial"
ORIGIN = "11111111-1111-1111-1111-111111111111"
TRIAL = "22222222-2222-2222-2222-222222222222"
RECOVERY = "33333333-3333-3333-3333-333333333333"
TOKEN = "abcdef12-1234-1234-1234-abcdef123456"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == "Linux"
    assert platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists()
    source, out = args.rootfs.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tools = Path(__file__).resolve().parent
    results = {}

    def case(name, setup="", command="run", expected="rollback-requested", success=True, present=True, reboot=True):
        root = out / (name + "-root")
        subprocess.run(["cp", "-a", str(source), str(root)], check=True)
        base = root / BASE
        (base / "original").mkdir(parents=True)
        shutil.copy2(tools / "offload_trial_guard.sh", base / "guard.sh")
        shutil.copy2(tools / "offload_trial.init", root / "etc/init.d/owrt-offload-trial")
        (root / "etc/init.d/owrt-offload-trial").chmod(0o755)
        (root / "etc/rc.d/S01owrt-offload-trial").symlink_to("../init.d/owrt-offload-trial")
        for name2, data in {"firewall": b"original firewall\n", "modules.conf": b"# original modules\n"}.items():
            path = base / "original" / name2
            if name2 == "modules.conf" and not present:
                continue
            path.write_bytes(data)
            path.chmod(0o640)
            os.utime(path, (1700000000, 1700000000))
        (base / "modules-presence").write_text("present\n" if present else "absent\n")
        (base / "originals.sha256").write_text("".join(
            hashlib.sha256(p.read_bytes()).hexdigest() + "  " + str(p.relative_to(base)) + "\n"
            for p in [*(base / "original").iterdir(), base / "modules-presence"]))
        with tarfile.open(base / "config-backup.tar.gz", "w:gz") as tar:
            tar.add(base / "original/firewall", "etc/config/firewall")
        (root / "etc/config/firewall").write_bytes(b"trial firewall\n")
        (root / "etc/modules.conf").write_bytes(b"options mt7915e wed_enable=1\n")
        (root / "etc/config/network").write_bytes(b"unrelated network configuration\n")
        network = (root / "etc/config/network").read_bytes()
        for name2, value in {"state": "armed", "token": TOKEN, "origin-boot": ORIGIN,
                             "origin-deadline": "180", "trial-seconds": "600"}.items():
            (base / name2).write_text(value + "\n")
        for directory in ("proc/sys/kernel/random", "sys/module/mt7915e/parameters", "tmp", "dev"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / "proc/sys/kernel/random/boot_id").write_text(TRIAL + "\n")
        (root / "proc/uptime").write_text("10.00 0.00\n")
        (root / "sys/module/mt7915e/parameters/wed_enable").write_text("Y\n")
        if not (root / "dev/null").exists():
            subprocess.run(["mknod", "-m", "666", str(root / "dev/null"), "c", "1", "3"], check=True)
        stubs = {
            "sbin/reboot": '#!/bin/sh\nprintf "%s\\n" "$*" >> /tmp/reboots\n',
            "bin/sync": "#!/bin/sh\nexit 0\n",
            "usr/bin/setsid": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> /tmp/setsid\n",
            "bin/sleep": '''#!/bin/sh
t=$(cut -d. -f1 /proc/uptime)
printf '%s.00 0.00\n' "$((t + 100))" > /proc/uptime
if [ -f /tmp/confirm ]; then
    rm /tmp/confirm
    /bin/sh /root/owrt-offload-trial/guard.sh confirm ''' + TOKEN + " " + TRIAL + "\nfi\n",
        }
        for path, data in stubs.items():
            p = root / path
            p.unlink(missing_ok=True)
            p.write_text(data)
            p.chmod(0o755)
        for p in (root / "bin/setsid", root / "sbin/setsid"):
            if p.exists() or p.is_symlink():
                p.unlink()
        (base / "trial-config.sha256").write_text("".join(
            hashlib.sha256((root / p).read_bytes()).hexdigest() + "  " + p + "\n"
            for p in ("etc/config/firewall", "etc/modules.conf")))
        script = f"set -eu\n{setup}\nexec /bin/sh /{BASE}/guard.sh {command}\n"
        result = subprocess.run(["chroot", str(root), "/bin/sh", "-s"], input=script,
                                text=True, capture_output=True, timeout=10)
        (out / (name + ".log")).write_text(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, (name, result.returncode, result.stderr)
        assert (base / "state").read_text().strip() == expected, (name, (base / "state").read_text())
        assert (root / "etc/config/network").read_bytes() == network
        assert not (root / "tmp/owrt-offload-running").exists()
        assert not (root / "tmp/owrt-offload-decision").exists()
        if reboot:
            assert (root / "tmp/reboots").read_text() == "-f\n", name
            for rel, original in (("etc/config/firewall", "firewall"), ("etc/modules.conf", "modules.conf")):
                path = root / rel
                if original == "modules.conf" and not present:
                    assert not path.exists()
                    continue
                assert path.read_bytes() == (base / "original" / original).read_bytes()
                assert path.stat().st_mode & 0o777 == 0o640
                assert int(path.stat().st_mtime) == 1700000000
            # Simulate recovery boot. No second reboot is allowed.
            (root / "proc/sys/kernel/random/boot_id").write_text(RECOVERY + "\n")
            subprocess.run(["chroot", str(root), "/bin/sh", "/" + BASE + "/guard.sh", "run"], check=True, timeout=10)
            assert (root / "tmp/reboots").read_text() == "-f\n"
            assert (base / "state").read_text() == "rolled-back\n"
        else:
            assert not (root / "tmp/reboots").exists()
        if (base / "events.log").exists():
            shutil.copy2(base / "events.log", out / (name + "-events.log"))
        results[name] = True
        shutil.rmtree(root)
        print("PASS:", name, flush=True)

    case("target_boot_timeout_restores_exact_originals")
    case("originally_absent_modules_conf_is_removed", present=False)
    case("origin_boot_without_reboot_times_out", f"echo {ORIGIN} > /proc/sys/kernel/random/boot_id")
    case("extra_unconfirmed_boot_restores_immediately", f"echo {ORIGIN} > /{BASE}/trial-boot")
    case("restart_preserves_existing_deadline", f"echo {TRIAL} > /{BASE}/trial-boot; echo 1 > /{BASE}/trial-deadline")
    case("explicit_confirmation_stops_guard", "touch /tmp/confirm", expected="accepted", reboot=False)
    ready = f"echo observing > /{BASE}/state; echo {TRIAL} > /{BASE}/trial-boot; echo 600 > /{BASE}/trial-deadline"
    for name, setup, token in (
        ("wrong_token_rejected", "", "bad-token"),
        ("wed_disabled_rejected", "echo N > /sys/module/mt7915e/parameters/wed_enable", TOKEN),
        ("changed_trial_config_rejected", "echo changed >> /etc/config/firewall", TOKEN),
        ("expired_confirmation_rejected", f"echo 1 > /{BASE}/trial-deadline", TOKEN),
    ):
        case(name, ready + "\n" + setup, f"confirm {token} {TRIAL}", expected="observing", success=False, reboot=False)
    case("corrupt_original_refuses_restore", f"echo corrupt >> /{BASE}/original/firewall", command="restore", success=False, expected="armed", reboot=False)
    case("same_boot_reboot_fuse_prevents_repeat", f"echo {TRIAL} > /{BASE}/rollback-reboot; echo rollback-requested > /{BASE}/state", expected="rollback-requested", success=False, reboot=False)
    arm_setup = f"rm /{BASE}/state\ncp -p /{BASE}/original/firewall /etc/config/firewall\ncp -p /{BASE}/original/modules.conf /etc/modules.conf\necho {ORIGIN} > /proc/sys/kernel/random/boot_id"
    case("arm_checks_originals_and_launches_detached_guard", arm_setup, f"arm {TOKEN} {ORIGIN} 600", expected="armed", reboot=False)
    (out / "result.json").write_text(json.dumps({"guard_sha256": hashlib.sha256((tools / "offload_trial_guard.sh").read_bytes()).hexdigest(), "cases": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
