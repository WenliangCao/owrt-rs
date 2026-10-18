#!/usr/bin/env python3
"""Qualify the unchanged guard with image BusyBox in isolated Linux chroots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("bounded", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == "Linux"
    assert platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists()
    args.output.mkdir(parents=True, exist_ok=False)
    token, boot = "abcdef12-1234-1234-1234-abcdef123456", "11111111-1111-1111-1111-111111111111"
    rel = "tmp/owrt-offload-runtime-" + token
    guard = Path(__file__).with_name("offload_runtime_guard.sh")
    results = {}
    for name in ("timeout_restores", "explicit_finish_restores", "bounded_reload_failure", "corrupt_original_rejected"):
        root = args.output / (name + "-root")
        subprocess.run(["cp", "-a", str(args.rootfs), str(root)], check=True)
        base = root / rel
        base.mkdir(parents=True)
        shutil.copy2(guard, base / "guard.sh")
        shutil.copy2(args.bounded, base / "bounded")
        for directory in ("proc/sys/kernel/random", "sys/module/mt7915e/parameters", "dev"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / "proc/sys/kernel/random/boot_id").write_text(boot + "\n")
        (root / "proc/uptime").write_text("1.00 0.00\n")
        (root / "sys/module/mt7915e/parameters/wed_enable").write_text("Y\n")
        if not (root / "dev/null").exists():
            subprocess.run(["mknod", "-m", "666", str(root / "dev/null"), "c", "1", "3"], check=True)
        original = base / "original-firewall"
        original.write_text("1\n")
        original.chmod(0o640)
        shutil.copy2(original, root / "etc/config/firewall")
        (root / "etc/config/network").write_text("unchanged network\n")
        (root / "etc/modules.conf").write_text("unchanged modules\n")
        (base / "unchanged.sha256").write_text("".join(
            hashlib.sha256((root / p).read_bytes()).hexdigest() + "  /" + p + "\n"
            for p in ("etc/config/network", "etc/modules.conf")))
        stubs = {
            "sbin/uci": '#!/bin/sh\ncase "$*" in *get*) cat /etc/config/firewall;; *revert*) rm -f /tmp/pending;; changes) cat /tmp/pending 2>/dev/null || true;; esac\n',
            "sbin/fw4": '#!/bin/sh\necho reload >> /tmp/reloads\n[ ! -e /tmp/fail-reload ] || exit 1\ncp /etc/config/firewall /tmp/runtime-hw\n',
            "usr/sbin/nft": '#!/bin/sh\necho "table inet fw4 {"\necho "  flowtable ft {"\necho "    hook ingress priority filter"\necho "    devices = { br-lan, wan }"\nif [ "$(cat /tmp/runtime-hw)" = 1 ]; then\n  if [ -e /tmp/semicolon ]; then echo "    flags offload;"; else echo "    flags offload"; fi\nfi\necho "    counter"\necho "  }"\necho "}"\n',
            "bin/sleep": '#!/bin/sh\necho 700.00 > /proc/uptime\n',
        }
        # After arming, sleep emulates only the caller's authorized temporary
        # firewall change; no production script source is patched for testing.
        stubs["bin/sleep"] = '''#!/bin/sh
if [ ! -e /tmp/changed ]; then
  touch /tmp/changed
  echo 0 > /etc/config/firewall
  echo 0 > /tmp/runtime-hw
'''
        if name == "explicit_finish_restores":
            stubs["bin/sleep"] += f"  touch /{rel}/finish-requested\n"
        elif name == "bounded_reload_failure":
            stubs["bin/sleep"] += "  touch /tmp/fail-reload\n"
        stubs["bin/sleep"] += "fi\necho 700.00 > /proc/uptime\n"
        for path, content in stubs.items():
            target = root / path
            target.unlink(missing_ok=True)
            target.write_text(content)
            target.chmod(0o755)
        (root / "tmp/runtime-hw").write_text("1\n")
        if name == "explicit_finish_restores":
            (root / "tmp/semicolon").touch()
        manifest = base / "bundle.sha256"
        manifest.write_text("".join(hashlib.sha256((base / p).read_bytes()).hexdigest() + "  " + p + "\n"
                                    for p in ("guard.sh", "bounded", "original-firewall", "unchanged.sha256")))
        sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
        action = "run"
        if name == "corrupt_original_rejected":
            original.write_text("corrupt\n")
            action = "check"
        result = subprocess.run(["chroot", str(root), "/bin/sh", "/" + rel + "/guard.sh", action, token, boot, sha, "60"],
                                capture_output=True, text=True, timeout=10)
        (args.output / (name + ".log")).write_text(result.stdout + result.stderr)
        state = (base / "state").read_text().strip() if (base / "state").exists() else None
        reloads = (root / "tmp/reloads").read_text().splitlines() if (root / "tmp/reloads").exists() else []
        if name == "corrupt_original_rejected":
            assert result.returncode != 0 and state is None and not reloads
        else:
            assert (root / "etc/config/firewall").read_bytes() == b"1\n"
            assert (root / "etc/config/firewall").stat().st_mode & 0o777 == 0o640
            if name == "bounded_reload_failure":
                assert result.returncode != 0 and state == "recovery-failed" and len(reloads) == 3
            else:
                assert result.returncode == 0 and state == "restored" and len(reloads) == 1, (name, result, state)
                assert (root / "tmp/runtime-hw").read_text() == "1\n"
                assert not (root / "tmp/owrt-offload-runtime.lock").exists()
        assert (root / "etc/config/network").read_text() == "unchanged network\n"
        assert (root / "etc/modules.conf").read_text() == "unchanged modules\n"
        results[name] = True
        shutil.rmtree(root)
        print("PASS:", name, flush=True)
    (args.output / "result.json").write_text(json.dumps({"guard_sha256": hashlib.sha256(guard.read_bytes()).hexdigest(), "cases": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
