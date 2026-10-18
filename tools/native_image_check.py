#!/usr/bin/env python3
"""Exercise native firmware configuration migration and C recovery off-device.

Run as root on an aarch64 Linux build host. Every case uses a disposable image
copy plus mount/network/PID namespaces, never a physical router or live bus.
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

from native_image import native_layout


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


NAMESPACE = r'''
set -eu
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
exec chroot "$root" /bin/sh -eu
'''


class Check:
    def __init__(self, source, out):
        self.source = source
        self.out = out
        out.mkdir(parents=True, exist_ok=False)
        self.manifest = json.loads((source / "usr/share/owrt-control-plane/release.json").read_text())
        assert self.manifest["layout"] == native_layout(self.manifest["components"])
        assert {c["path"] for c in self.manifest["integration_files"].values()} == {
            "/etc/init.d/dnsmasq", "/usr/share/acl.d/dnsmasq_acl.json"}
        self.results = {}

    def component_word(self):
        return self.manifest["layout"].removeprefix("native-")

    def copy(self, name):
        root = self.out / name
        assert not root.exists()
        subprocess.run(["cp", "-a", str(self.source), str(root)], check=True)
        return root

    def shell(self, name, root, script, success=True):
        command = ["unshare", "--mount", "--net", "--pid", "--uts", "--ipc", "--fork", "--kill-child",
                   "/bin/sh", "-c", NAMESPACE, "sh", str(root)]
        script = "mkdir -p /var/lock /var/run /var/log /var/state\n" + script
        result = subprocess.run(command, input=script, text=True, capture_output=True, timeout=90)
        (self.out / (name + ".log")).write_text(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, (name, result.returncode, result.stdout, result.stderr)

    def identities(self, root, mode="rust"):
        for c in self.manifest["components"].values():
            assert sha(root / c["path"].lstrip("/")) == c[mode + "_sha256"], c["path"]
        for c in self.manifest["integration_files"].values():
            path = root / c["path"].lstrip("/")
            key = "stock_sha256" if mode == "stock" else "replacement_sha256"
            assert sha(path) == c[key], c["path"]
            original = self.source / c["recovery_path"].lstrip("/")
            assert path.stat().st_mode & 0o7777 == original.stat().st_mode & 0o7777, c["path"]

    def passed(self, name):
        self.results[name] = True
        (self.out / "result.json").write_text(json.dumps(self.results, indent=2) + "\n")
        print("PASS:", name, flush=True)

    def configuration(self, native):
        case = "native_upgrade" if native else "layered_migration"
        old = self.copy(case + "-old")
        (old / "etc/config/network").write_text("config interface 'lan'\n option proto 'static'\n option ipaddr '192.0.2.1'\n")
        (old / "etc/config/wireless").write_text("config wifi-iface 'fixture'\n option ssid 'upgrade-fixture'\n option disabled '1'\n")
        (old / "etc/crontabs").mkdir(exist_ok=True)
        (old / "etc/crontabs/root").write_text("# retained synthetic LED schedule\n")
        (old / "etc/rc.local").write_text("# retained fixture\nexit 0\n")
        (old / "etc/sysupgrade.conf").write_text("/etc/native-config-fixture\n")
        (old / "etc/native-config-fixture").write_text("selected by sysupgrade.conf\n")
        if native:
            (old / "etc/owrt-control-plane-layout").write_text("native-nine-v1\n")
            disable = "uhttpd"
        else:
            disable = "log rpcd uhttpd"
            for c in ("uci", "reload-config", "logd", "httpd", "fw4", "rpcd"):
                (old / ("etc/owrt-" + c + ".boot-enable")).touch()
        self.shell(case + "-backup", old, f'''
for s in {disable} cron; do /etc/init.d/$s disable; done
/sbin/sysupgrade -b /tmp/native-config.tar.gz
''')
        archive = old / "tmp/native-config.tar.gz"
        with tarfile.open(archive) as tar:
            members = {m.name.lstrip("/"): m for m in tar.getmembers()}
            disabled = tar.extractfile(members["etc/uci-defaults/10_disable_services"]).read().decode()
            for s in disable.split():
                assert f"/etc/init.d/{s} disable" in disabled
            assert not any("owrt-" in n and n.endswith(".boot-enable") for n in members)
        new = self.copy(case + "-new")
        shutil.copy2(archive, new / "sysupgrade.tgz")
        # Execute the exact image's restore implementation. Only hardware root
        # mounting and hook registration are stubbed inside this disposable fs.
        self.shell(case + "-restore", new, '''
mount_root() { :; }
boot_run_hook() { :; }
boot_hook_add() { :; }
set +u
. /lib/preinit/80_mount_root
do_mount_root
set -u
/bin/sh /etc/uci-defaults/05-owrt-native
/bin/sh /etc/uci-defaults/10_disable_services
test "$(cat /etc/owrt-control-plane-layout)" = native-nine-v1
/etc/init.d/log enabled
/etc/init.d/rpcd enabled
if /etc/init.d/cron enabled; then exit 1; fi
''' + ("if /etc/init.d/uhttpd enabled; then exit 1; fi\n" if native else "/etc/init.d/uhttpd enabled\n"))
        for relative in ("etc/config/network", "etc/config/wireless", "etc/crontabs/root",
                         "etc/rc.local", "etc/sysupgrade.conf", "etc/native-config-fixture",
                         "etc/passwd", "etc/shadow"):
            assert (old / relative).read_bytes() == (new / relative).read_bytes(), relative
        self.identities(new)
        self.passed(case + "_configuration_and_service_policy")

    def recovery(self):
        root = self.copy("recovery")
        for name, relative in (
                ("netifd", "sbin/netifd"), ("dnsmasq", "usr/sbin/dnsmasq"),
                ("dnsmasq-init", "etc/init.d/dnsmasq"),
                ("dnsmasq-acl", "usr/share/acl.d/dnsmasq_acl.json")):
            original = root / "usr/libexec/owrt-stock" / relative
            good = original.read_bytes()
            original.write_bytes(good + b"corrupt")
            self.shell("recovery-corrupt-" + name, root, "/usr/sbin/owrt-recover-c\n", success=False)
            self.identities(root)
            original.write_bytes(good)
        self.passed("corrupt_program_init_or_ACL_rejected_before_any_replacement")
        sums = root / "usr/share/owrt-control-plane/stock.sha256"
        valid_sums = sums.read_text()
        if self.manifest["layout"] == "native-eleven":
            odhcpd_source = self.manifest["components"]["odhcpd"]["recovery_path"]
            rows = [row for row in valid_sums.splitlines() if row.split()[1] != odhcpd_source]
            assert len(rows) == 12
            sums.write_text("\n".join(rows) + "\n")
            self.shell("recovery-missing-odhcpd", root, "/usr/sbin/owrt-recover-c\n", success=False)
            self.identities(root)
            assert not list(root.rglob("*.owrt-recovery-new"))
            sums.write_text(valid_sums)
            self.passed("eleven_component_recovery_cannot_downgrade_to_ten_before_any_replacement")
        # A correct hash of an active target must never be accepted as a
        # recovery original outside the pinned stock directory.
        rows = valid_sums.splitlines()
        rows[0] = sha(root / "sbin/procd") + "  /sbin/procd"
        sums.write_text("\n".join(rows) + "\n")
        self.shell("recovery-outside-stock", root, "/usr/sbin/owrt-recover-c\n", success=False)
        self.identities(root)
        sums.write_text(valid_sums)
        self.passed("non_stock_recovery_source_rejected_before_any_replacement")
        self.shell("recovery-mounted", root, '''
mount -o bind /sbin/uci /sbin/uci
/usr/sbin/owrt-recover-c
''', success=False)
        self.identities(root)
        self.passed("mounted_target_rejected_before_any_replacement")
        self.shell("recovery-mounted-init", root, '''
mount -o bind /etc/init.d/dnsmasq /etc/init.d/dnsmasq
/usr/sbin/owrt-recover-c
''', success=False)
        self.identities(root)
        self.passed("mounted_dnsmasq_integration_target_rejected")
        self.shell("recovery-stage", root, "/usr/sbin/owrt-recover-c\n")
        self.identities(root, "stock")
        assert not list(root.rglob("*.owrt-recovery-new"))
        self.shell("recovery-repeat", root, "/usr/sbin/owrt-recover-c\n")
        self.identities(root, "stock")
        for path in (self.source / "etc/config").iterdir():
            assert path.read_bytes() == (root / "etc/config" / path.name).read_bytes()
        self.passed(f"all_{self.component_word()}_C_and_dnsmasq_init_ACL_staged_idempotently_with_configuration_unchanged")

    def package_reinstall(self, apk_dir):
        root = self.copy("package-reinstall")
        cache = root / "tmp/native-apks"
        cache.mkdir()
        for source in apk_dir.glob("*.apk"):
            shutil.copy2(source, cache / source.name)
        owner_apks = " ".join(
            f"/tmp/native-apks/{name}-{info['version']}.apk"
            for name, info in self.manifest["stock_packages"].items())
        # fix --reinstall may return success after skipping an unavailable
        # installed APK identity. Explicit payloads and missing-file repair
        # prove that every original owner fixture was actually extracted.
        # These disposable roots may live on tmpfs. APK's non-repository
        # persistence refusal does not apply to this no-reboot fixture; allow
        # only that condition, without changing ownership or integrity checks.
        file_lists = {}
        for name in self.manifest["stock_packages"]:
            path = root / "lib/apk/packages" / (name + ".list")
            file_lists[path] = path.read_bytes()
            path.unlink()
        ownership = "\n".join(
            f"apk info --who-owns {c['path']} | grep -Fx '{c['path']} is owned by owrt-control-plane-{self.manifest['version']}'"
            for c in [*self.manifest["components"].values(),
                      *self.manifest["integration_files"].values()]) + "\n"
        self.shell("package-stock-reinstall", root, f'''
apk --no-scripts --no-network --allow-untrusted --force-non-repository --repositories-file /dev/null add --force-reinstall {owner_apks}
sha256sum -c /usr/share/owrt-control-plane/rust.sha256
''' + ownership)
        assert "APK unavailable" not in (self.out / "package-stock-reinstall.log").read_text()
        for path, expected in file_lists.items():
            assert path.read_bytes() == expected, path
        self.identities(root)
        self.passed(f"stock_package_reinstall_preserves_{self.component_word()}_Rust_files_and_dnsmasq_integration")
        recovery = root / "usr/libexec/owrt-stock/sbin/procd"
        recovery.unlink()
        self.shell("package-native-reinstall", root, f'''
apk --no-scripts --no-network --allow-untrusted --force-non-repository --repositories-file /dev/null add --force-reinstall /tmp/native-apks/owrt-control-plane-{self.manifest['version']}.apk
sha256sum -c /usr/share/owrt-control-plane/rust.sha256
sha256sum -c /usr/share/owrt-control-plane/stock.sha256
''' + ownership)
        assert "APK unavailable" not in (self.out / "package-native-reinstall.log").read_text()
        assert sha(recovery) == self.manifest["components"]["procd"]["stock_sha256"]
        self.identities(root)
        self.passed("native_package_reinstall_preserves_Rust_and_recovery_files")

    def firmware_metadata(self, image):
        root = self.copy("firmware-metadata")
        shutil.copy2(image, root / "tmp/native-image.bin")
        self.shell("firmware-metadata", root, '''
set +u
. /lib/functions.sh
. /lib/upgrade/fwtool.sh
v() { echo "$@"; }
REQUIRE_IMAGE_METADATA=1
FORCE=0
SAVE_CONFIG=1
IGNORE_MINOR_COMPAT=0
mkdir -p /tmp/sysinfo
echo xiaomi,mi-router-ax3000t > /tmp/sysinfo/board_name
if ! fwtool_check_image /tmp/native-image.bin; then exit 1; fi
echo deliberately-wrong-board > /tmp/sysinfo/board_name
if fwtool_check_image /tmp/native-image.bin; then exit 1; fi
''')
        self.identities(root)
        self.passed("firmware_metadata_accepts_AX3000T_keep_config_and_rejects_wrong_board")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--apk-dir", type=Path,
                        help="directory containing the native APK and pinned stock owner APKs")
    parser.add_argument("--image", type=Path, help="sysupgrade image for the stock fwtool compatibility check")
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.system() == "Linux"
    assert platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists()
    check = Check(args.rootfs.resolve(), args.output.resolve())
    check.configuration(native=False)
    check.configuration(native=True)
    check.recovery()
    if args.apk_dir:
        check.package_reinstall(args.apk_dir.resolve())
    if args.image:
        check.firmware_metadata(args.image.resolve())


if __name__ == "__main__":
    main()
