#!/usr/bin/env python3
"""Local failure-boundary checks; no SDK commands or network access."""
from pathlib import Path
import copy
import contextlib
import io
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import build_package as package
import m4_package_lifecycle as lifecycle


class PackageBuildTests(unittest.TestCase):
    def test_platform_manifest_covers_source_but_not_local_build_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            required = ["rust-toolchain.toml", "manifests/release-25.12.5.json",
                        "packaging/openwrt/owrt-dnsmasq/Makefile",
                        "tools/dnsmasq/build_package.sh", "tools/dnsmasq/build_package.py",
                        "components/dnsmasq/Cargo.lock"]
            for component in ("dnsmasq", "dnsmasq/platform", "ubus", "platform"):
                required += [f"components/{component}/Cargo.toml", f"components/{component}/src/lib.rs"]
            for name in required + ["components/dnsmasq/platform/target/local-artifact",
                                    "components/platform/target/local-artifact"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            (root / "components/dnsmasq/Cargo.toml").write_text('[package]\nname = "dnsmasq-rs"\n')
            self.assertEqual(set(package.inputs(root)), set(required))
            source = root / "components/dnsmasq/platform/src/lib.rs"
            before = package.inputs(root)
            source.write_text("changed platform implementation")
            self.assertNotEqual(package.inputs(root), before)
            source.unlink()
            source.symlink_to(root / "rust-toolchain.toml")
            with self.assertRaisesRegex(ValueError, "symlink"):
                package.inputs(root)

    def test_executable_platform_adapters_are_snapshotted_and_missing_targets_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            files = ["rust-toolchain.toml", "manifests/release-25.12.5.json",
                     "packaging/openwrt/owrt-dnsmasq/Makefile", "tools/dnsmasq/build_package.sh",
                     "tools/dnsmasq/build_package.py", "components/dnsmasq/Cargo.lock"]
            for component in ("dnsmasq", "dnsmasq/platform", "ubus", "platform"):
                files += [f"components/{component}/Cargo.toml", f"components/{component}/src/lib.rs"]
            adapters = ["platform/entry.rs", "platform/register.rs",
                        "platform/tests/process_forks.rs", "platform/tests/process_owner.rs",
                        "platform/tests/panic_hook.rs", "tests/process_forks.rs", "tests/process_owner.rs"]
            for name in files + ["components/dnsmasq/" + path for path in adapters]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            (root / "components/dnsmasq/Cargo.toml").write_text(
                '[package]\nname = "dnsmasq-rs"\n[[bin]]\nname = "dnsmasq-rs"\n'
                'path = "platform/entry.rs"\n'
                '[[test]]\nname = "process_forks"\npath = "platform/tests/process_forks.rs"\n'
                '[[test]]\nname = "process_owner"\npath = "platform/tests/process_owner.rs"\n')
            expected = package.inputs(root)
            destination = Path(temp) / "snapshot"
            package.snapshot(root, destination, expected)
            for name in adapters:
                self.assertEqual((destination / "components/dnsmasq" / name).read_bytes(),
                                 (root / "components/dnsmasq" / name).read_bytes())
            for name in adapters[:4]:
                path = root / "components/dnsmasq" / name
                saved = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(ValueError, "missing"):
                    package.inputs(root)
                path.write_bytes(saved)

    def test_automatic_activation_allows_only_the_executable_file_dependency(self):
        stock = b'#!/bin/sh\n\tprocd_set_param file $CONFIGFILE\n\tprocd_set_param respawn\n'
        candidate = stock.replace(b'file $CONFIGFILE\n', b'file $CONFIGFILE $PROG\n')
        lifecycle.require_init_contract(stock, candidate, True)
        lifecycle.require_init_contract(stock, stock, False)
        for wrong in (stock, candidate.replace(b'respawn', b'reload_signal HUP')):
            with self.assertRaisesRegex(RuntimeError, 'executable content tracking'):
                lifecycle.require_init_contract(stock, wrong, True)

    def test_automatic_activation_cannot_hide_a_manual_restart(self):
        report = {'automatic_activation_required': True}
        case = lifecycle.Scenario(None, None, report)
        with patch.object(case, 'run', side_effect=AssertionError('manual activation')):
            case.activate_after_transaction('candidate-upgrade')
        self.assertIsNone(report['activation_steps'][0]['command'])

    def test_legacy_setup_restart_cannot_be_used_for_candidate_transactions(self):
        report = {'automatic_activation_required': True}
        case = lifecycle.Scenario(None, None, report)
        with patch.object(case, 'run') as run:
            case.activate_after_transaction('stock-to-m5-baseline', legacy_setup=True)
            run.assert_called_once_with(['/etc/init.d/dnsmasq', 'restart'],
                                        'stock-to-m5-baseline-explicit-restart')
            self.assertTrue(report['activation_steps'][0]['legacy_reference_setup'])
            with self.assertRaisesRegex(RuntimeError, 'unexpected legacy setup'):
                case.activate_after_transaction('m5-to-candidate-upgrade', legacy_setup=True)

    def test_dns_object_acl_allows_only_the_exact_publish_addition(self):
        stock = b'{"user":"dnsmasq","publish": [ "dnsmasq" ],"access":{"hotplug.dhcp":{"methods":["call"]}}}'
        candidate = stock.replace(b'[ "dnsmasq" ]', b'[ "dnsmasq", "dnsmasq.dns" ]')
        lifecycle.require_acl_contract(stock, candidate, True)
        lifecycle.require_acl_contract(stock, stock, False)
        for wrong in (stock, candidate.replace(b'dnsmasq.dns', b'dnsmasq.*'),
                      candidate.replace(b'"call"', b'"*"'), candidate.replace(b'"user":"dnsmasq"', b'"user":"root"')):
            with self.assertRaisesRegex(RuntimeError, 'exact dnsmasq.dns'):
                lifecycle.require_acl_contract(stock, wrong, True)

    def test_ubus_mount_preserves_jail_flags_and_mount_scope(self):
        stock = b'\tprocd_set_param file $CONFIGFILE\n\tprocd_add_jail dnsmasq ubus log\n'
        candidate = (b'\tprocd_set_param file $CONFIGFILE $PROG\n'
                     b'\t# Bind the socket directory so an ubusd restart can replace ubus.sock.\n'
                     b'\t# The ubus jail shortcut pins the old socket inode until dnsmasq restarts.\n'
                     b'\tprocd_add_jail dnsmasq log\n\tprocd_add_jail_mount /var/run/ubus\n')
        lifecycle.require_init_contract(stock, candidate, True, True)
        for wrong in (candidate.replace(b'/var/run/ubus', b'/var/run'),
                      candidate.replace(b'procd_add_jail_mount ', b'procd_add_jail_mount_rw '),
                      candidate.replace(b'dnsmasq log', b'dnsmasq log procfs')):
            with self.assertRaisesRegex(RuntimeError, 'exact ubus directory mount'):
                lifecycle.require_init_contract(stock, wrong, True, True)

    def test_sigterm_unwinds_sdk_recipe_and_records_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); sdk = root / 'sdk'; active = sdk / 'package/owrt-dnsmasq'
            active.mkdir(parents=True); (active / 'old').write_text('preserve')
            source = root / 'recipe'; source.mkdir(); (source / 'Makefile').write_text('candidate')
            budget = root / 'budget.json'; budget.write_text(json.dumps({'schema': 1, 'elf_max_bytes': 1000000, 'apk_max_bytes': 700000}))
            output = root / 'private/attempt'
            def interrupted_build(args, out, report):
                with package.package_recipe(sdk, source, out, report): os.kill(os.getpid(), signal.SIGTERM)
            argv = ['build_package.py', str(sdk), str(output), '--budget', str(budget), '--expected-elf-sha256', 'a' * 64]
            previous = signal.getsignal(signal.SIGTERM)
            with patch.object(package, 'ROOT', root), patch.object(package, 'audit_build', interrupted_build), \
                    patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(package.main(), 1)
            report = json.loads((output / 'manifest.json').read_text())
            self.assertEqual(report['status'], 'failed'); self.assertTrue(report['sdk_recipe_restored'])
            self.assertIn('interrupted by signal', report['error'])
            self.assertEqual((active / 'old').read_text(), 'preserve')
            self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_failed_build_restores_existing_recipe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sdk = root / "sdk"
            active = sdk / "package/owrt-dnsmasq"
            active.mkdir(parents=True)
            (active / "old").write_text("preserve")
            source = root / "source"
            source.mkdir()
            (source / "Makefile").write_text("current")
            report = {}
            with self.assertRaisesRegex(ValueError, "deliberate build failure"):
                with package.package_recipe(sdk, source, root / "output", report):
                    self.assertEqual((active / "Makefile").read_text(), "current")
                    self.assertEqual((sdk / ".dnsmasq-backup-output/old").read_text(), "preserve")
                    self.assertEqual([p.name for p in (sdk / "package").iterdir()], ["owrt-dnsmasq"])
                    raise ValueError("deliberate build failure")
            self.assertEqual([p.name for p in active.iterdir()], ["old"])
            self.assertEqual((active / "old").read_text(), "preserve")
            self.assertTrue(report["sdk_recipe_restored"])

    def test_failed_copy_restores_existing_recipe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            active = root / "sdk/package/owrt-dnsmasq"
            active.mkdir(parents=True)
            (active / "old").write_text("preserve")
            with patch.object(package.shutil, "copytree", side_effect=OSError("copy failure")):
                with self.assertRaises(OSError):
                    with package.package_recipe(root / "sdk", root / "source", root / "output", {}):
                        self.fail("failed copy entered the build")
            self.assertEqual((active / "old").read_text(), "preserve")

    def test_payload_rejects_extra_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in package.REPLACEMENT_FILES | {
                "lib/apk/packages/dnsmasq.conffiles",
                "lib/apk/packages/dnsmasq.conffiles_static",
                "lib/apk/packages/dnsmasq.list",
                "lib/apk/packages/dnsmasq.rusers",
                "lib/upgrade/keep.d/dnsmasq",
            }:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
            listing = root / "lib/apk/packages/dnsmasq.list"
            listing.write_text("\n".join(package.OWNERSHIP_LIST) + "\n")
            keep = root / "lib/upgrade/keep.d/dnsmasq"
            keep.write_text("/etc/dnsmasq.d/\n")
            self.assertEqual(len(package.audit_payload(root)), len(package.PAYLOAD_FILES))
            keep.write_text("/etc/dnsmasq.d/\n/etc/dnsmasq.d/\n")
            with self.assertRaisesRegex(ValueError, "upgrade keep file"):
                package.audit_payload(root)
            keep.write_text("/etc/dnsmasq.d/\n")
            extra = root / "usr/libexec/extra"
            extra.parent.mkdir(parents=True)
            extra.write_text("unexpected")
            with self.assertRaises(ValueError):
                package.audit_payload(root)
            extra.unlink()
            extra.symlink_to("dnsmasq-rs")
            with self.assertRaises(ValueError):
                package.audit_payload(root)

    def test_make_path_rejects_shell_and_make_metacharacters(self):
        for path in ("/tmp/a b", "/tmp/a;id", "/tmp/$(id)", "/tmp/a\nb", "/tmp/a#b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                package.safe_path(Path(path))

    def test_exceeded_size_targets_keep_both_measurements(self):
        report = {"artifact": {"size": 801_000}, "elf": {"size": 1_200_000},
                  "budget": {"apk_max_bytes": 800_000, "elf_max_bytes": 700_000}}
        with self.assertRaisesRegex(ValueError, "APK size 801000.*ELF size 1200000"):
            package.audit_sizes(report)
        self.assertEqual(report["budget_checks"], {"apk": False, "elf": False})
        self.assertEqual(report["elf"]["size"], 1_200_000)

    def test_user_size_exception_is_bound_to_one_elf_and_retains_original_miss(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "budget.json"
            path.write_text(json.dumps({"schema": 1, "elf_max_bytes": 1159280, "apk_max_bytes": 700000,
                "user_accepted_elf": {"bytes": 1159280, "sha256": "f" * 64, "original_target_bytes": 1000000,
                                      "reason": "User explicitly accepted measured option A"}}))
            report = {"budget": package.read_budget(path), "elf": {"size": 1159280, "sha256": "f" * 64},
                      "artifact": {"size": 600000}}
            package.audit_sizes(report)
            self.assertFalse(report["original_elf_target_met"])
            self.assertIn("explicit-user-exception", report["size_acceptance"])
            report["elf"]["sha256"] = "a" * 64
            with self.assertRaisesRegex(ValueError, "does not authorize"):
                package.audit_sizes(report)

    def test_candidate_metadata_requires_actual_lifecycle_scripts(self):
        metadata = """info:
  name: dnsmasq
  version: 2.93-r4
  arch: aarch64_cortex-a53
  depends: # 2 items
    - libc
    - libubus20251202
  provides: # 1 items
    - dnsmasq-any
scripts:
  post-install: |
  pre-deinstall: |
  post-upgrade: |
"""
        self.assertEqual(package.audit_metadata(metadata)["version"], "2.93-r4")
        for script in ("post-install", "pre-deinstall", "post-upgrade"):
            with self.subTest(script=script), self.assertRaisesRegex(ValueError, script):
                package.audit_metadata(metadata.replace(f"  {script}: |\n", ""))
        with self.assertRaisesRegex(ValueError, "depends"):
            package.audit_metadata(metadata.replace("    - libc\n", ""))
        for dependency in ("libgcc", "libgcc1", "libgcc1>=14.3.0-r1"):
            changed = metadata.replace("    - libubus20251202\n",
                                       f"    - libubus20251202\n    - {dependency}\n")
            with self.subTest(dependency=dependency), self.assertRaisesRegex(ValueError, "direct libgcc"):
                package.audit_metadata(changed)
        package.audit_metadata(metadata.replace("    - libubus20251202\n",
                                                "    - libubus20251202\n    - libmnl0\n"))

    def test_pie_elf_gate_rejects_linkage_and_protection_regressions(self):
        data = bytearray(512)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", data, 16, 3, 183)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 5)
        interpreter = b"/lib/ld-musl-aarch64.so.1\0"
        headers = [
            (1, 5, 0, 0, 0, 448, 448, 4096),
            (1, 6, 448, 448, 448, 64, 64, 4096),
            (0, 4, 384, 384, 384, len(interpreter), len(interpreter), 1),
            (0x6474e551, 6, 0, 0, 0, 0, 0, 16),
            (0x6474e552, 4, 448, 448, 448, 64, 64, 1),
        ]
        for index, row in enumerate(headers):
            struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, *row)
        data[384:384 + len(interpreter)] = interpreter
        dynamic = """ 0x18 (BIND_NOW)
 0x6ffffffb (FLAGS_1) Flags: NOW PIE
"""
        result = package.audit_elf(data, dynamic)
        self.assertEqual(result["needed"], [])
        self.assertIsNone(result["interpreter"])
        self.assertFalse(result["runtime_protections_verified"])
        no_binding = dynamic.replace(" 0x18 (BIND_NOW)\n", "").replace("NOW PIE", "PIE")
        self.assertFalse(package.audit_elf(data, no_binding)["bind_now"])
        mutations = [
            ("static ET_EXEC", 16, "<H", 2),
            ("wrong architecture", 18, "<H", 62),
            ("dynamic interpreter", 64 + 2 * 56, "<I", 3),
            ("executable stack", 64 + 3 * 56 + 4, "<I", 7),
            ("missing stack", 64 + 3 * 56, "<I", 0),
            ("missing RELRO", 64 + 4 * 56, "<I", 0),
            ("empty RELRO", 64 + 4 * 56 + 40, "<Q", 0),
            ("WX load", 64 + 56 + 4, "<I", 7),
            ("truncated header table", 32, "<Q", len(data)),
            ("segment outside file", 64 + 56 + 32, "<Q", len(data)),
        ]
        for label, offset, fmt, value in mutations:
            changed = bytearray(data)
            struct.pack_into(fmt, changed, offset, value)
            with self.subTest(label=label), self.assertRaises(ValueError):
                package.audit_elf(changed, dynamic)
        for label, changed in [
            ("shared library", dynamic + " 0x1 (NEEDED) Shared library: [libc.so]\n"),
            ("missing PIE", dynamic.replace("NOW PIE", "NOW")),
            ("text relocation", dynamic + " 0x16 (TEXTREL)\n"),
            ("library search override", dynamic + " 0x1d (RUNPATH) Library runpath: [/tmp]\n"),
        ]:
            with self.subTest(label=label), self.assertRaises(ValueError):
                package.audit_elf(data, changed)

    def test_static_pie_linker_only_rewrites_pinned_startup_inputs(self):
        helper = package.ROOT / "packaging/openwrt/owrt-dnsmasq/static-pie-linker.py"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            crt = root / "rustlib/aarch64-unknown-linux-musl/lib/self-contained"
            crt.mkdir(parents=True)
            names = ("crt1.o", "crtbegin.o", "crtend.o", "rcrt1.o", "crtbeginS.o", "crtendS.o")
            for name in names:
                (crt / name).touch()
            (root / "crt1.o").touch()
            (root / "rcrt1.o").touch()
            compiler = root / "sdk-gcc"
            compiler.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
            compiler.chmod(0o755)
            environment = dict(os.environ, DNSMASQ_STATIC_PIE_CC=str(compiler))
            args = [str(crt / "crt1.o"), str(crt / "crtbegin.o"), "input.o",
                    "-static", "-no-pie", "-static-libgcc", "-Wl,-z,relro", str(crt / "crtend.o")]
            def invoke(arguments, env=environment):
                return subprocess.run([sys.executable, str(helper), *arguments],
                                      env=env, text=True, capture_output=True)
            result = invoke(args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [str(crt / "rcrt1.o"), str(crt / "crtbeginS.o"),
                "input.o", "-static-pie", "-static-libgcc", "-Wl,-z,relro", str(crt / "crtendS.o")])
            for label, changed in [
                ("no static", [arg for arg in args if arg != "-static"]),
                ("duplicate static", [*args, "-static"]),
                ("dynamic PIE", [*args, "-pie"]),
                ("response file", [*args, "@hidden-arguments"]),
                ("missing startup", args[1:]),
                ("duplicate startup", [*args, str(crt / "crt1.o")]),
                ("unrecognized startup source", [str(root / "crt1.o"), *args[1:]]),
            ]:
                with self.subTest(label=label):
                    self.assertNotEqual(invoke(changed).returncode, 0)
            (crt / "rcrt1.o").unlink()
            self.assertNotEqual(invoke(args).returncode, 0)
            self.assertNotEqual(invoke(args, dict(environment, DNSMASQ_STATIC_PIE_CC="")).returncode, 0)

    def test_frozen_elf_requires_full_source_sdk_and_binary_identity(self):
        source = {"components/dnsmasq/src/main.rs": "a" * 64,
                  "packaging/openwrt/owrt-dnsmasq/Makefile": "b" * 64,
                  "tools/dnsmasq/build_package.py": "c" * 64}
        sdk = {"archive_sha256": "d" * 64, "files": {"rules.mk": "e" * 64}}
        freeze = {"schema": 1, "frozen": True, "package_release": "4", "source_commit": "1" * 40,
                  "source_date_epoch": 123, "rust_elf_sha256": "f" * 64,
                  "source_files": source, "sdk_archive_sha256": sdk["archive_sha256"],
                  "sdk_files": sdk["files"],
                  "postprocess": {"mode": "none", "reason": "rustc strip=true; preserve qualified identity",
                                  "input_sha256": "f" * 64, "output_sha256": "f" * 64}}
        package.verify_freeze(freeze, source, sdk, "1" * 40, "123", "f" * 64)
        mutations = [
            ("source_commit", "2" * 40), ("rust_elf_sha256", "0" * 64),
            ("source_date_epoch", 456), ("frozen", False), ("pending", ["pressure"]),
            ("source_files", {k: v for k, v in source.items() if not k.startswith("tools/")}),
            ("source_files", dict(source, extra="0" * 64)),
            ("source_files", dict(source, **{"components/dnsmasq/src/main.rs": "0" * 64})),
            ("source_files", dict(source, **{"packaging/openwrt/owrt-dnsmasq/Makefile": "0" * 64})),
            ("sdk_archive_sha256", "0" * 64), ("sdk_files", {"rules.mk": "0" * 64}),
            ("postprocess", {"mode": "none", "reason": "identity changed unexpectedly",
                             "input_sha256": "0" * 64, "output_sha256": "f" * 64}),
            ("postprocess", {"mode": "sdk-sstrip", "input_sha256": "0" * 64, "output_sha256": "1" * 64}),
        ]
        for field, value in mutations:
            changed = dict(freeze, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                package.verify_freeze(changed, source, sdk, "1" * 40, "123", "f" * 64)

    def test_release_recipe_resolves_sdk_compiler_through_buildpackage_eval(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / "rules.mk").write_text("")
            (root / "package.mk").write_text("define BuildPackage\ncheck:\n\t$(Build/Compile)\nendef\n")
            binaries = root / "bin"
            binaries.mkdir()
            compiler = binaries / "aarch64-openwrt-linux-musl-gcc"
            compiler.write_text("#!/bin/sh\nexit 99\n")
            compiler.chmod(0o755)
            captured = root / "cargo-environment.json"
            cargo = binaries / "cargo"
            cargo.write_text(f"#!{sys.executable}\nimport json,os\nfrom pathlib import Path\n"
                             "names = ('DNSMASQ_STATIC_PIE_CC', 'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER')\n"
                             f"Path({str(captured)!r}).write_text(json.dumps({{name: os.environ[name] for name in names}}))\n")
            cargo.chmod(0o755)
            recipe = package.ROOT / "packaging/openwrt/owrt-dnsmasq/Makefile"
            result = subprocess.run(["make", "--no-print-directory", "-f", str(recipe),
                                     f"TOPDIR={root}", f"INCLUDE_DIR={root}", f"PKG_BUILD_DIR={root / 'build'}",
                                     f"V1_CARGO={cargo}", f"TARGET_CC_NOCACHE={compiler.name}",
                                     "TARGET_LINKER=bfd", "check"], cwd=recipe.parent,
                                    env=dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"]),
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            environment = json.loads(captured.read_text())
            self.assertEqual(environment["DNSMASQ_STATIC_PIE_CC"], str(compiler))
            self.assertTrue(Path(environment["DNSMASQ_STATIC_PIE_CC"]).is_absolute())
            self.assertEqual(environment["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"],
                             str(recipe.parent / "static-pie-linker.py"))

    def test_frozen_recipe_never_calls_cargo_or_restrips(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "rules.mk").write_text("")
            (root / "package.mk").write_text("")
            (root / "frozen-dnsmasq").write_bytes(b"already-validated-ELF-fixture")
            harness = root / "harness.mk"
            harness.write_text("check:\n\t$(Build/Compile)\n"
                               "\ttest '$(RSTRIP)' = ':'\n"
                               "\ttest '$(DNSMASQ_INSTALL_ELF)' = '$(PKG_BUILD_DIR)/frozen-dnsmasq'\n")
            recipe = package.ROOT / "packaging/openwrt/owrt-dnsmasq/Makefile"
            result = subprocess.run(["make", "--no-print-directory", "-f", str(recipe), "-f", str(harness),
                                     f"TOPDIR={root}", f"INCLUDE_DIR={root}", f"PKG_BUILD_DIR={root}",
                                     f"OWRT_DNSMASQ_FROZEN_ELF={root / 'frozen-dnsmasq'}",
                                     "V1_CARGO=/must-not-call-cargo", "check"], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_oversized_experiment_keeps_artifacts_and_failure_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            budget = root / "budget.json"
            budget.write_text(json.dumps({"schema": 1, "elf_max_bytes": 700000, "apk_max_bytes": 800000}))
            out = root / "private/result"
            def oversized(args, output, report):
                (output / "dnsmasq.apk").write_bytes(b"artifact")
                (output / "dnsmasq").write_bytes(b"ELF")
                report.update(artifact={"size": 510000}, elf={"size": 980000})
                package.audit_sizes(report)
            argv = ["build_package.py", str(root / "sdk"), str(out), "--budget", str(budget),
                    "--expected-elf-sha256", "f" * 64]
            with patch.object(package, "ROOT", root), patch.object(package, "audit_build", side_effect=oversized), \
                    patch.object(sys, "argv", argv), patch("builtins.print"):
                self.assertEqual(package.main(), 1)
            report = json.loads((out / "manifest.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["failure_boundary"], "size-target")
            self.assertEqual(report["budget_checks"], {"apk": True, "elf": False})
            self.assertTrue((out / "dnsmasq.apk").is_file())
            self.assertTrue((out / "dnsmasq").is_file())


class PackageLifecycleTests(unittest.TestCase):
    def test_restart_is_reported_as_operator_activation_not_postinst(self):
        report = {}
        scenario = lifecycle.Scenario(Path("/unused"), Path("/unused"), report)
        with patch.object(scenario, "run") as run:
            scenario.activate_after_transaction("stock-to-candidate-upgrade")
        run.assert_called_once_with(["/etc/init.d/dnsmasq", "restart"],
                                    "stock-to-candidate-upgrade-explicit-restart")
        self.assertEqual(report["activation_steps"], [{
            "transaction": "stock-to-candidate-upgrade",
            "command": ["/etc/init.d/dnsmasq", "restart"], "automatic_restart_claimed": False}])

    def test_database_rejects_duplicate_package_and_escaping_path(self):
        base = "P:dnsmasq\nV:2.93-r1\nF:usr/sbin\nR:dnsmasq\n"
        with self.assertRaisesRegex(RuntimeError, "duplicate package"):
            lifecycle.installed_packages(base + "\n" + base)
        with self.assertRaisesRegex(RuntimeError, "unsafe path"):
            lifecycle.installed_packages(base.replace("R:dnsmasq", "R:../../../outside"))

    def test_upgrade_requires_new_version_and_exclusive_ownership(self):
        baseline = {
            "dnsmasq": {"version": "2.93-r1", "files": sorted(package.PAYLOAD_FILES)},
            "libc": {"version": "1", "files": ["lib/libc.so"]},
        }
        with self.assertRaisesRegex(RuntimeError, "wrong dnsmasq version"):
            lifecycle.assert_database(baseline, "2.93-r2", baseline)
        current = copy.deepcopy(baseline)
        current["dnsmasq"]["version"] = "2.93-r2"
        lifecycle.assert_database(current, "2.93-r2", baseline)
        current["libc"]["version"] = "2"
        with self.assertRaisesRegex(RuntimeError, "another installed package"):
            lifecycle.assert_database(current, "2.93-r2", baseline)
        baseline["libc"]["files"].append("usr/sbin/dnsmasq")
        current = copy.deepcopy(baseline)
        current["dnsmasq"]["version"] = "2.93-r2"
        with self.assertRaisesRegex(RuntimeError, "duplicate file owner"):
            lifecycle.assert_database(current, "2.93-r2", baseline)

    def test_missing_variant_dependency_is_not_conflict_evidence(self):
        result = {"returncode": 1, "stdout": "", "stderr":
                  "dnsmasq-full-2.93-r1: conflicts: dnsmasq-2.93-r2\n"}
        lifecycle.assert_variant_rejected(result, "dnsmasq-full")
        result["stderr"] += "libnettle (no such package)\n"
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            lifecycle.assert_variant_rejected(result, "dnsmasq-full")
        result["stderr"] = "APK archive is corrupt\n"
        with self.assertRaisesRegex(RuntimeError, "without evidence"):
            lifecycle.assert_variant_rejected(result, "dnsmasq-full")
        result["stderr"] = "world: dnsmasq-full=2.93-r1 dnsmasq=2.93-r2\n  libexample-2:\n    conflicts: libexample-1\n"
        with self.assertRaisesRegex(RuntimeError, "without evidence"):
            lifecycle.assert_variant_rejected(result, "dnsmasq-full")
        result["stderr"] = "  dnsmasq-2.93-r2:\n    breaks: dnsmasq-full-2.93-r1[dnsmasq=2.93-r1]\n"
        lifecycle.assert_variant_rejected(result, "dnsmasq-full")

    def test_timed_out_script_is_forcibly_reaped_and_failure_logged(self):
        with tempfile.TemporaryDirectory() as temp:
            root, log = Path(temp), Path(temp) / "timeout.json"
            argv = [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"]
            with patch.object(lifecycle, "command", return_value=argv):
                with self.assertRaisesRegex(RuntimeError, "timed out"):
                    lifecycle.invoke(root, ["unused"], log, timeout=.5)
            result = json.loads(log.read_text())
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["returncode"], -signal.SIGKILL)

    def test_failure_record_does_not_suppress_apk_scripts(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "failed.json"
            process = unittest.mock.Mock()
            process.communicate.return_value = ("", "post-install failed")
            process.returncode = 1
            with patch.object(lifecycle.subprocess, "Popen", return_value=process) as popen:
                with self.assertRaisesRegex(RuntimeError, "command failed"):
                    lifecycle.invoke(Path(temp), ["/usr/bin/apk", "add", "candidate.apk"], log)
            environment = popen.call_args.kwargs["env"]
            self.assertNotIn("IPKG_INSTROOT", environment)
            self.assertNotIn("IPKG_NO_SCRIPT", environment)
            self.assertEqual(json.loads(log.read_text())["returncode"], 1)


if __name__ == "__main__":
    unittest.main()
