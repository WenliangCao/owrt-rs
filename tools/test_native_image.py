#!/usr/bin/env python3
"""Local release integration checks; no router, SDK build or network access."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ci_build_dnsmasq
import native_apk_fixtures
import native_image
import native_image_check
import native_package_reinstall_selftest


REPO = Path(__file__).resolve().parent.parent
SPEC = json.loads((REPO / "packaging/image/native-25.12.5.json").read_text())
FILES = REPO / "packaging/openwrt/owrt-dnsmasq/files"


class NativeDnsmasqTests(unittest.TestCase):
    def test_reinstall_negative_controls_still_find_tmpfs_fixture_commands(self):
        # Exercise the actual negative-control selector for both transaction
        # stages. Adding a global APK option must not bypass the no-op test.
        for stage in ("stock", "native"):
            check = object.__new__(native_package_reinstall_selftest.SkipReinstall)
            check.stage, check.skipped = stage, 0
            script = ("apk --no-scripts --no-network --allow-untrusted --force-non-repository "
                      "--repositories-file /dev/null add --force-reinstall /tmp/native-apks/fixture.apk\n"
                      "sha256sum -c /usr/share/owrt-control-plane/rust.sha256\n")
            with patch.object(native_image_check.Check, "shell") as shell:
                check.shell(f"package-{stage}-reinstall", Path("/unused"), script)
                rewritten = shell.call_args.args[2]
                self.assertEqual(check.skipped, 1)
                self.assertNotIn("add --force-reinstall", rewritten)
                self.assertIn("sha256sum -c", rewritten)

    def test_prepare_rejects_unprivileged_before_reading_or_mutating_files(self):
        with patch.object(native_image.os, "geteuid", return_value=1000), \
                patch.object(native_image, "read", side_effect=AssertionError("read before privilege gate")), \
                patch.object(native_image, "install", side_effect=AssertionError("write before privilege gate")):
            with self.assertRaisesRegex(AssertionError, "requires root"):
                native_image.prepare(Path("/unused"), SPEC, Path("/unused-apk"))

    def test_reinstall_fixtures_cover_every_original_package_owner(self):
        owners = {component["stock_package"] for component in SPEC["components"].values()}
        owners |= {item["stock_package"] for item in SPEC["integration_files"].values()}
        self.assertEqual(set(native_apk_fixtures.STOCK_OWNERS), owners)
        self.assertEqual(len(native_apk_fixtures.STOCK_OWNERS), len(owners))

    def fixture(self, directory):
        root = Path(directory)
        base, candidate, payload = (root / name for name in ("base", "candidate", "payload"))
        init = (FILES / "dnsmasq.init").read_bytes()
        stock_init = init.replace(b'\tprocd_set_param file $CONFIGFILE $PROG\n',
                                  b'\tprocd_set_param file $CONFIGFILE\n')
        stock_init = stock_init.replace(
            b'\t# Bind the socket directory so an ubusd restart can replace ubus.sock.\n'
            b'\t# The ubus jail shortcut pins the old socket inode until dnsmasq restarts.\n'
            b'\tprocd_add_jail dnsmasq log\n\tprocd_add_jail_mount /var/run/ubus\n',
            b'\tprocd_add_jail dnsmasq ubus log\n')
        acl = (FILES / "dnsmasq_acl.json").read_bytes()
        stock_acl = acl.replace(b'"publish": [ "dnsmasq", "dnsmasq.dns" ]', b'"publish": [ "dnsmasq" ]')
        for name, original, replacement in (("etc/init.d/dnsmasq", stock_init, init),
                                             ("usr/share/acl.d/dnsmasq_acl.json", stock_acl, acl)):
            for tree, content in ((base, original), (candidate, replacement)):
                file = tree / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(content)
                file.chmod(SPEC["integration_files"][name]["mode"])
        for source, target in {
            "dhcp.conf": "etc/config/dhcp", "dnsmasq.conf": "etc/dnsmasq.conf",
            "dnsmasqsec.hotplug": "etc/hotplug.d/ntp/25-dnsmasqsec",
            "50-dnsmasq-migrate-ipset.sh": "etc/uci-defaults/50-dnsmasq-migrate-ipset.sh",
            "50-dnsmasq-migrate-resolv-conf-auto.sh": "etc/uci-defaults/50-dnsmasq-migrate-resolv-conf-auto.sh",
            "dhcp-script.sh": "usr/lib/dnsmasq/dhcp-script.sh",
            "dhcpbogushostname.conf": "usr/share/dnsmasq/dhcpbogushostname.conf",
            "rfc6761.conf": "usr/share/dnsmasq/rfc6761.conf",
        }.items():
            for tree in (base, candidate):
                file = tree / target
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes((FILES / source).read_bytes())
        return payload, base, candidate

    def integrate(self, paths, spec=SPEC):
        with patch.object(native_image, "run", return_value="fixture is owned by dnsmasq-2.93-r1"):
            return native_image.integration_files(*paths, spec, Path("/fake/apk"), {"dnsmasq": {"version": "2.93-r1"}})

    def test_only_accepted_files_installed_with_paired_stock_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(temporary)
            result = self.integrate(paths)
            payload, base, candidate = paths
            for name, item in result.items():
                self.assertEqual((payload / name).read_bytes(), (candidate / name).read_bytes())
                recovery = payload / item["recovery_path"].lstrip("/")
                self.assertEqual(recovery.read_bytes(), (base / name).read_bytes())
                self.assertEqual(recovery.stat().st_mode & 0o7777, item["mode"])
            self.assertEqual(len(list(p for p in payload.rglob("*") if p.is_file())), 4)

    def test_stock_or_candidate_drift_rejected(self):
        for side in (1, 2):
            with self.subTest(side=side), tempfile.TemporaryDirectory() as temporary:
                paths = self.fixture(temporary)
                file = paths[side] / "etc/init.d/dnsmasq"
                file.write_bytes(file.read_bytes() + b"# drift\n")
                with self.assertRaisesRegex(AssertionError, "identity drift"):
                    self.integrate(paths)

    def test_defaults_and_helpers_must_remain_stock(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(temporary)
            (paths[2] / "usr/lib/dnsmasq/dhcp-script.sh").write_bytes(b"changed helper\n")
            with self.assertRaisesRegex(AssertionError, "dhcp-script"):
                self.integrate(paths)

    def test_extra_replacement_path_rejected(self):
        spec = copy.deepcopy(SPEC)
        spec["integration_files"]["etc/config/dhcp"] = {}
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(AssertionError):
                self.integrate(self.fixture(temporary), spec)

    def test_mode_change_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(temporary)
            (paths[2] / "usr/share/acl.d/dnsmasq_acl.json").chmod(0o777)
            with self.assertRaises(AssertionError):
                self.integrate(paths)

    def test_current_source_matches_accepted_product(self):
        files, digest = ci_build_dnsmasq.source_identity(SPEC["dnsmasq_build"])
        self.assertEqual(len(files), 181)
        self.assertEqual(digest, "6505f110f02b8488c14a9261c37e13362d4227fdaffb4c2a23380e17029de4b7")

    def test_source_drift_cannot_inherit_accepted_identity(self):
        with patch.object(ci_build_dnsmasq.audit, "inputs", return_value={"changed": "a" * 64}):
            with self.assertRaisesRegex(ValueError, "differs from accepted"):
                ci_build_dnsmasq.source_identity(SPEC["dnsmasq_build"])

    def test_ten_component_inventory_does_not_change_original_nine(self):
        # Canonical digest of these four fields at v0.1.1. No historical Git
        # objects are required in Actions' shallow checkout.
        previous = {key: copy.deepcopy(SPEC[key]) for key in
                    ("components", "stock_image", "luci_source", "translations")}
        previous["components"].pop("dnsmasq")
        self.assertEqual(len(previous["components"]), 9)
        digest = hashlib.sha256(json.dumps(previous, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, "bac71f5c50f91dce84dcf7652cb353f1c5d92852118a13c7b5df24eb1e07d496")


if __name__ == "__main__":
    unittest.main()
