#!/usr/bin/env python3
"""Local release integration checks; no router, SDK build or network access."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ci_build_dnsmasq
import native_apk_fixtures
import native_image
import native_image_check
import native_package_reinstall_selftest


REPO = Path(__file__).resolve().parent.parent
NEXT_SPEC = json.loads((REPO / "packaging/image/native-25.12.5.json").read_text())
# Exercise historical ten-component recovery using the same accepted inputs.
SPEC = copy.deepcopy(NEXT_SPEC)
SPEC["version"] = "0.2.3-r1"
SPEC["components"].pop("odhcpd")
FILES = REPO / "packaging/openwrt/owrt-dnsmasq/files"


class NativeRpcdCompatTests(unittest.TestCase):
    def fixture(self, temporary):
        root = Path(temporary)
        base, payload = root / "base", root / "payload"
        base.mkdir()
        payload.mkdir()
        descriptor = native_image.install_rpcd_compat_acl(payload, base)
        return base, payload, {"rpcd_compat_acl": descriptor}

    def verify(self, base, payload, manifest, owner=None):
        if owner is None:
            owner = "fixture is owned by " + SPEC["package"] + "-" + SPEC["version"]
        with patch.object(native_image, "run", return_value=owner):
            native_image.verify_rpcd_compat_acl(payload, base, manifest, SPEC, Path("/fake/apk"))

    def test_only_existing_flash_read_group_gains_resolved_mounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            base, payload, manifest = self.fixture(temporary)
            descriptor = manifest["rpcd_compat_acl"]
            path = descriptor["path"].lstrip("/")
            self.assertEqual(json.loads((payload / path).read_text()), {
                "luci-mod-system-flash": {"read": {"file": {"/proc/*/mounts": ["read"]}}}})
            self.assertEqual(native_image.sha(payload / path), descriptor["sha256"])
            self.assertEqual((payload / path).stat().st_mode & 0o7777, 0o644)
            self.assertEqual(list(base.iterdir()), [])
            self.assertFalse((payload / native_image.STOCK).exists())
            self.assertNotIn(path, SPEC["integration_files"])
            self.verify(base, payload, manifest)

    def test_stock_file_or_dangling_symlink_collision_is_rejected(self):
        for link in (False, True):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / "base" / native_image.RPCD_COMPAT_ACL["path"].lstrip("/")
                target.parent.mkdir(parents=True)
                if link:
                    target.symlink_to(root / "missing")
                else:
                    target.write_text("stock file")
                with self.assertRaisesRegex(AssertionError, "collides with stock"):
                    native_image.install_rpcd_compat_acl(root / "payload", root / "base")
                self.assertFalse((root / "payload").exists())

    def test_source_drift_is_rejected_before_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "packaging/openwrt/owrt-rpcd/files/owrt-rpcd-compat.json"
            source.parent.mkdir(parents=True)
            source.write_text('{"unexpected": {}}\n')
            with patch.object(native_image, "REPO", root), \
                    self.assertRaisesRegex(AssertionError, "source drift"):
                native_image.install_rpcd_compat_acl(root / "payload", root / "base")
            self.assertFalse((root / "payload").exists())

    def test_final_content_mode_symlink_and_manifest_drift_are_rejected(self):
        for changed in ("content", "mode", "symlink", "manifest"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                base, payload, manifest = self.fixture(temporary)
                path = payload / native_image.RPCD_COMPAT_ACL["path"].lstrip("/")
                if changed == "content":
                    path.write_text('{"unexpected": {}}\n')
                elif changed == "mode":
                    path.chmod(0o666)
                elif changed == "symlink":
                    target = path.with_suffix(".target")
                    path.rename(target)
                    path.symlink_to(target)
                else:
                    manifest["rpcd_compat_acl"]["sha256"] = "0" * 64
                with self.assertRaises(AssertionError):
                    self.verify(base, payload, manifest)

    def test_final_acl_must_be_owned_by_the_native_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            base, payload, manifest = self.fixture(temporary)
            with self.assertRaises(AssertionError):
                self.verify(base, payload, manifest, "fixture is owned by luci-mod-system-1")


class NativeDnsmasqTests(unittest.TestCase):
    def test_current_recipe_includes_the_qualified_odhcpd(self):
        expected = copy.deepcopy(SPEC)
        expected["version"] = "0.3.2-r1"
        expected["components"]["odhcpd"] = {
            "path": "/usr/sbin/odhcpd", "binary": "odhcpd-rs", "stock_package": "odhcpd-ipv6only",
            "stock_sha256": "53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82",
            "reference_elf_sha256": "f6e4eecb8882522d304e13b2ccccc268743e4d267c4a3e41db63c62009752d39"}
        self.assertEqual(NEXT_SPEC, expected)
        self.assertEqual(NEXT_SPEC["version"], "0.3.2-r1")
        frozen = json.loads((REPO / "manifests/dnsmasq-pgo-frozen-v032.json").read_text())
        self.assertEqual(NEXT_SPEC["dnsmasq_build"], frozen)

    def test_only_exact_ten_and_eleven_native_inventories_are_accepted(self):
        self.assertEqual(native_image.native_layout(SPEC["components"]), "native-ten")
        self.assertEqual(native_image.native_layout(NEXT_SPEC["components"]), "native-eleven")
        bad = []
        for missing in ("fw4", "dnsmasq"):
            value = copy.deepcopy(NEXT_SPEC["components"])
            value.pop(missing)
            bad.append(value)
        for field, value in (("path", "/usr/sbin/odhcpd-rs"), ("binary", "another-rs"),
                             ("stock_package", "odhcpd")):
            changed = copy.deepcopy(NEXT_SPEC["components"])
            changed["odhcpd"][field] = value
            bad.append(changed)
        bad.append(dict(NEXT_SPEC["components"], extra=NEXT_SPEC["components"]["odhcpd"]))
        for components in bad:
            with self.subTest(components=components), self.assertRaises(AssertionError):
                native_image.native_layout(components)

    def test_eleven_fixtures_include_stock_odhcpd_owner_and_reference_is_required(self):
        self.assertEqual(set(native_apk_fixtures.stock_owners(NEXT_SPEC)),
                         {c["stock_package"] for c in NEXT_SPEC["components"].values()})
        hashes = {item["binary"]: item.get("reference_elf_sha256", "0" * 64)
                  for item in NEXT_SPEC["components"].values()}
        native_image.verify_component_references(hashes, NEXT_SPEC)
        hashes["odhcpd-rs"] = "f" * 64
        with self.assertRaisesRegex(AssertionError, "identity drift: odhcpd"):
            native_image.verify_component_references(hashes, NEXT_SPEC)

    def test_recovery_shell_accepts_only_complete_legacy_or_odhcpd_sets(self):
        # Run the actual shell against owned temporary paths, replacing only its
        # fixed root-path bindings. No chroot, active executable or router is used.
        source = (REPO / "packaging/image/owrt-recover-c").read_text()
        for variant in ("ten", "eleven", "missing", "substituted", "duplicate", "unknown",
                        "missing-odhcpd", "missing-odhcpd-rehashed", "bad-layout", "bad-digest"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                stock = root / "stock"
                active = root / "active"
                active.mkdir()
                paths = [c["path"] for c in SPEC["components"].values()]
                paths += [c["path"] for c in SPEC["integration_files"].values()]
                if variant != "ten": paths.append("/usr/sbin/odhcpd")
                if variant == "missing": paths.remove("/sbin/fw4")
                if variant == "substituted": paths.remove("/etc/init.d/dnsmasq")
                if variant == "duplicate": paths[-1] = paths[0]
                if variant == "unknown": paths[-1] = "/usr/sbin/unknown"
                lines = []
                for name in set(paths):
                    file = stock / name.lstrip("/")
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text("stock:" + name)
                    file.chmod(0o755)
                    live = active / name.lstrip("/")
                    live.parent.mkdir(parents=True, exist_ok=True)
                    live.write_text("candidate:" + name)
                for name in paths:
                    file = stock / name.lstrip("/")
                    lines.append(hashlib.sha256(file.read_bytes()).hexdigest() + "  " + str(file) + "\n")
                manifest = root / "stock.sha256"
                manifest.write_text("".join(lines))
                release = root / "release.json"
                metadata = {"layout": "native-ten" if variant == "ten" else "native-eleven",
                            "stock_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}
                if variant in ("missing-odhcpd", "missing-odhcpd-rehashed"):
                    manifest.write_text("".join(row for row in lines if not row.endswith("/usr/sbin/odhcpd\n")))
                if variant == "missing-odhcpd-rehashed":
                    metadata["stock_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
                if variant == "bad-layout": metadata["layout"] = "native-unknown"
                if variant == "bad-digest": metadata["stock_manifest_sha256"] = "0" * 64
                release.write_text(json.dumps(metadata))
                # The host unit fixture substitutes only JSON field extraction;
                # native_image_check uses the exact rootfs jsonfilter executable.
                reader = root / "jsonfilter"
                reader.write_text("#!/usr/bin/env python3\nimport json,sys\n"
                                  "data=json.load(open(sys.argv[sys.argv.index('-i')+1]))\n"
                                  "print(data[sys.argv[sys.argv.index('-e')+1][2:]])\n")
                reader.chmod(0o755)
                mounts = root / "mountinfo"
                mounts.write_text("")
                script = source.replace("base=/usr/libexec/owrt-stock", "base=" + str(stock))
                script = script.replace("manifest=/usr/share/owrt-control-plane/stock.sha256", "manifest=" + str(manifest))
                script = script.replace("release=/usr/share/owrt-control-plane/release.json", "release=" + str(release))
                script = script.replace("/proc/self/mountinfo", str(mounts))
                script = script.replace('    cp -p "$source"', '    target="' + str(active) + '$target"\n    cp -p "$source"')
                script = script.replace('    mv -f "$target.owrt-recovery-new"', '    target="' + str(active) + '$target"\n    mv -f "$target.owrt-recovery-new"')
                script = script.replace('rm -f "${source#"$base"}', 'rm -f "' + str(active) + '${source#"$base"}')
                script = script.replace("\nsync\n", "\n: # fixture: no global sync\n")
                result = subprocess.run(["sh", "-eu"], input=script, text=True, capture_output=True,
                                        env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"]))
                accepted = variant in ("ten", "eleven")
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                for name in set(paths):
                    self.assertEqual((active / name.lstrip("/")).read_text(), ("stock:" if accepted else "candidate:") + name)
                self.assertFalse(list(root.rglob("*.owrt-recovery-new")))

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

    def test_all_nine_release_rebuilds_must_equal_the_accepted_binaries(self):
        spec = copy.deepcopy(SPEC)
        spec["version"] = "0.2.2-r1"
        hashes = {}
        for name, component in spec["components"].items():
            value = hashlib.sha256(name.encode()).hexdigest()
            hashes[component["binary"]] = value
            if name != "dnsmasq":
                component["reference_elf_sha256"] = value
        native_image.verify_component_references(hashes, spec)
        for name, component in spec["components"].items():
            if name == "dnsmasq":
                continue
            with self.subTest(component=name):
                changed = dict(hashes, **{component["binary"]: "f" * 64})
                with self.assertRaisesRegex(AssertionError, "identity drift"):
                    native_image.verify_component_references(changed, spec)
                incomplete = copy.deepcopy(spec)
                del incomplete["components"][name]["reference_elf_sha256"]
                with self.assertRaisesRegex(AssertionError, "missing accepted"):
                    native_image.verify_component_references(hashes, incomplete)
        legacy = copy.deepcopy(spec)
        legacy["version"] = "0.2.1-r1"
        for component in legacy["components"].values():
            component.pop("reference_elf_sha256", None)
        native_image.verify_component_references(hashes, legacy)
        legacy["version"] = "0.2.2-r1"
        with self.assertRaisesRegex(AssertionError, "missing accepted"):
            native_image.verify_component_references(hashes, legacy)

    def test_native_integration_rejects_unqualified_or_changed_dnsmasq(self):
        spec = {"source_commit": "a" * 40, "source_digest": "b" * 64,
                "reference_elf_sha256": "c" * 64, "reference_elf_bytes": 1234,
                "source_date_epoch": 2345, "pgo": {
                    "profile_url": "https://example.invalid/frozen.profdata",
                    "profile_sha256": "d" * 64, "profile_bytes": 10,
                    "build_slot": "/fixed/product-slot", "training": {"receipt": "e" * 64}}}
        report = {"status": "built-and-audited", "source_digest": spec["source_digest"],
                  "accepted_product_commit": spec["source_commit"], "source_date_epoch": "2345",
                  "elf": {"sha256": "c" * 64, "reference_sha256": "c" * 64,
                          "size": 1234, "matches_accepted_reference": True},
                  "pgo": dict(spec["pgo"], mode="use", profile_diagnostics=[])}
        native_image.verify_dnsmasq_reference(report, spec)
        mutations = [("elf", "sha256", "f" * 64), ("elf", "size", 1235),
                     ("elf", "matches_accepted_reference", False), ("pgo", "mode", "generate"),
                     ("pgo", "build_slot", "/different/slot"),
                     ("pgo", "profile_diagnostics", ["hash mismatch"])]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                changed = copy.deepcopy(report)
                changed[section][key] = value
                with self.assertRaises(AssertionError):
                    native_image.verify_dnsmasq_reference(changed, spec)
        with self.assertRaisesRegex(AssertionError, "diagnostic"):
            native_image.verify_dnsmasq_reference(dict(report, release_qualified=False), spec)
        with self.assertRaisesRegex(AssertionError, "epoch"):
            native_image.verify_dnsmasq_reference(dict(report, source_date_epoch=2346), spec)

    @unittest.skipUnless(subprocess.run(
        ["git", "-C", str(REPO), "cat-file", "-e",
         ci_build_dnsmasq.resolve_commit(REPO, SPEC["dnsmasq_build"]["source_commit"]) + "^{commit}"],
        capture_output=True).returncode == 0, "shallow checkout lacks the accepted dnsmasq commit")
    def test_release_source_is_the_frozen_product(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "out").mkdir()
            frozen = ci_build_dnsmasq.release_source(work, SPEC["dnsmasq_build"])
            files, digest = ci_build_dnsmasq.source_identity(SPEC["dnsmasq_build"], frozen)
        self.assertEqual(len(files), 212)
        self.assertEqual(digest, "c3daefd7b94be1e42120f6ae9cec7c56264ed2dc430639ceea5d63812d151725")

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
        # New reference hashes bind the rebuilt implementations; the original
        # paths, stock identities, package owners and binary names stay fixed.
        for component in previous["components"].values():
            component.pop("reference_elf_sha256", None)
        self.assertEqual(len(previous["components"]), 9)
        digest = hashlib.sha256(json.dumps(previous, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, "bac71f5c50f91dce84dcf7652cb353f1c5d92852118a13c7b5df24eb1e07d496")


class V033ReleaseInputs(unittest.TestCase):
    def test_new_recipe_preserves_qualified_pgo_and_exact_stock_recovery(self):
        spec = json.loads((REPO / "packaging/image/native-25.12.6.json").read_text())
        frozen = json.loads((REPO / "manifests/dnsmasq-pgo-frozen-v033.json").read_text())
        intake = json.loads((REPO / "manifests/ax3000t-stock-openwrt-25.12.6/intake.json").read_text())
        self.assertEqual((spec["openwrt"], spec["version"]), ("25.12.6", "0.3.3-r1"))
        self.assertEqual(spec["dnsmasq_build"], frozen)
        self.assertEqual(frozen["reference_elf_sha256"],
                         "b2192268615d7be8ec30397de2a4b67cc5efa292017237d03b47a55324e5aa41")
        self.assertEqual(spec["stock_image"]["sha256"], intake["artifacts"]["stock_image"]["sha256"])
        self.assertEqual(len(spec["components"]), 11)
        for name, component in spec["components"].items():
            self.assertEqual(component["stock_sha256"], intake["stock_replacement_paths"][name]["sha256"])

    def test_new_recipe_archives_the_actual_qualified_25126_source(self):
        spec = json.loads((REPO / "packaging/image/native-25.12.6.json").read_text())["dnsmasq_build"]
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "out").mkdir()
            frozen = ci_build_dnsmasq.release_source(work, spec)
            files, digest = ci_build_dnsmasq.source_identity(spec, frozen)
            self.assertEqual(len(files), 231)
            self.assertEqual(digest, "9d3c45da3a3f7a12073610f34de0868187eaca6472c148f1f3626ff22c207657")
            self.assertIn("manifests/release-25.12.6.json", files)
            self.assertNotIn("manifests/release-25.12.5.json", files)


if __name__ == "__main__":
    unittest.main()
