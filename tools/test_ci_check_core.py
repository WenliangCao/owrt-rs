"""Compiler warnings and standalone candidate selection have explicit gates."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import ci_check_core as core
from ci_check_core import warnings


class WarningBoundaryTests(unittest.TestCase):
    INDEX = ("WARNING: opening /work/openwrt-imagebuilder-25.12.5-mediatek-filogic.Linux-x86_64/"
             "packages/packages.adb: No such file or directory")

    def classify(self, name, text):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / name
            log.write_text(text + "\n")
            with contextlib.redirect_stdout(io.StringIO()):
                return warnings(root / "warnings.json", [log])

    def test_initial_local_index_is_metadata_only_in_the_image_log(self):
        accepted = self.classify("image.log", self.INDEX)
        self.assertTrue(accepted["strict_compiler_warnings_zero"])
        self.assertEqual(len(accepted["sdk_metadata"]), 1)
        rejected = self.classify("compile.log", self.INDEX)
        self.assertFalse(rejected["strict_compiler_warnings_zero"])
        self.assertEqual(len(rejected["compiler_or_unclassified"]), 1)

    def test_other_missing_paths_and_compiler_warnings_still_fail(self):
        for text in [self.INDEX.replace("packages.adb", "other.adb"),
                     self.INDEX.replace("openwrt-imagebuilder-", "openwrt-sdk-"),
                     "warning: linker stderr: " + self.INDEX,
                     self.INDEX + "\nwarning: an actual compiler diagnostic"]:
            with self.subTest(text=text):
                self.assertFalse(self.classify("image.log", text)["strict_compiler_warnings_zero"])


class OdhcpdBuildBoundaryTests(unittest.TestCase):
    def test_core_recipe_default_stays_three_and_opt_in_copies_netifd_dependency(self):
        """Run the real recipe with a recording compiler, never a Rust build."""
        for include in (None, "1"):
            with self.subTest(include=include), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tools = root / "tools"
                tools.mkdir()
                script = (core.REPO / "tools/ci_build_core.sh").read_text()
                # Keep the production canonical source slot unchanged; relocate
                # only this fixture's copy so tests cannot touch a real build.
                self.assertEqual(script.count("/tmp/owrt-core-release/"), 1)
                (tools / "ci_build_core.sh").write_text(script.replace(
                    "/tmp/owrt-core-release/", str(root / "source-slot") + "/"))
                (root / "rust-toolchain.toml").write_text('channel = "1.98.1"\n')
                (tools / "toolchain_identity.sh").write_text("printf '%s\\n' 'official=yes'\n")
                adapter = tools / "mbx_cargo.sh"
                adapter.write_bytes((core.REPO / "tools/mbx_cargo.sh").read_bytes())
                adapter.chmod(0o755)
                (tools / "check_abi.sh").write_text("exit 0\n")
                (tools / "ci_check_core.py").write_text("import sys; assert sys.argv[1] == 'warnings'\n")
                for name in ("procd", "ubusd", "netifd", "odhcpd", "ubus", "uci", "platform"):
                    crate = root / "components" / name
                    crate.mkdir(parents=True)
                    (crate / "Cargo.toml").write_text(f'[package]\nname = "{name}"\n')
                work = root / "work"
                out = work / "out"
                out.mkdir(parents=True)
                (out / "manifest.json").write_text(json.dumps({
                    "source_commit": "a" * 40, "openwrt": "25.12.5"}))
                linker = work / "openwrt-sdk-25.12.5-fixture/staging_dir/toolchain-aarch64_fixture/bin/aarch64-openwrt-linux-musl-gcc"
                linker.parent.mkdir(parents=True)
                linker.write_text("#!/bin/sh\nexit 0\n")
                linker.chmod(0o755)
                commands = root / "commands"
                commands.mkdir()
                stubs = {
                    "git": "import sys\nprint('1' if '--format=%ct' in sys.argv else 'a'*40)\n",
                    "rsync": "import sys,shutil\nshutil.copytree(sys.argv[-2],sys.argv[-1],dirs_exist_ok=True)\n",
                    "mbx": """import os,sys
from pathlib import Path
args=sys.argv[1:]
manifest=Path(args[args.index('--manifest-path')+1])
component=manifest.parent.name
if component=='odhcpd':
    assert (manifest.parent.parent/'netifd/Cargo.toml').is_file()
target=Path(args[args.index('--target-dir')+1])/'aarch64-unknown-linux-musl/release'
target.mkdir(parents=True,exist_ok=True)
(target/(component+'-rs')).write_bytes(('fixture '+component).encode())
with open(os.environ['TEST_CARGO_LOG'],'a') as stream: stream.write(component+'\\n')
""",
                }
                for name, body in stubs.items():
                    path = commands / name
                    path.write_text("#!/usr/bin/env python3\n" + body)
                    path.chmod(0o755)
                env = dict(os.environ, OPENWRT_VERSION="25.12.5",
                           PATH=str(commands) + os.pathsep + os.environ["PATH"],
                           TEST_CARGO_LOG=str(root / "cargo.log"))
                env.pop("OWRT_CORE_INCLUDE_ODHCPD", None)
                if include is not None:
                    env["OWRT_CORE_INCLUDE_ODHCPD"] = include
                result = subprocess.run(["sh", str(tools / "ci_build_core.sh"), str(work)],
                                        env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                expected = ["procd", "ubusd", "netifd"] + (["odhcpd"] if include else [])
                self.assertEqual((root / "cargo.log").read_text().splitlines(), expected)
                manifest = json.loads((out / "core-manifest.json").read_text())
                names = {name + "-rs" for name in expected}
                self.assertEqual(set(manifest["binary_sha256"]), names)
                with tarfile.open(out / "core-binaries.tar.gz") as archive:
                    self.assertEqual(set(archive.getnames()), names)

    def test_sdk_diagnostics_opt_in_and_require_actual_odhcpd_output(self):
        for present in (True, False):
            with self.subTest(present=present), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                out = work / "out"
                out.mkdir()
                compiler = work / "openwrt-sdk-25.12.5-fixture/staging_dir/toolchain-aarch64_fixture/bin/aarch64-openwrt-linux-musl-gcc"
                compiler.parent.mkdir(parents=True)
                compiler.touch()
                inventories = {
                    "binary-sha256.txt": (work / "verify/rootfs/usr/sbin",
                                          ["uci-rs", "reload_config_rs", "logd-rs", "httpd-rs", "fw4-rs", "rpcd-rs"]),
                    "core-binary-sha256.txt": (out / "core-binaries",
                                               ["procd-rs", "ubusd-rs", "netifd-rs"] + (["odhcpd-rs"] if present else [])),
                }
                for filename, (base, names) in inventories.items():
                    base.mkdir(parents=True)
                    rows = []
                    for name in names:
                        content = name.encode()
                        (base / name).write_bytes(content)
                        rows.append(hashlib.sha256(content).hexdigest() + "  " + name)
                    (out / filename).write_text("\n".join(rows) + "\n")
                env = {"OPENWRT_VERSION": "25.12.5", "RUSTFLAGS": "-Dwarnings"}
                with mock.patch.object(core, "run", return_value=0) as run:
                    if present:
                        _, passed = core.sdk_check(work, env, {"commands": []})
                        self.assertTrue(passed)
                        self.assertEqual((out / "core-candidates/odhcpd-rs").read_bytes(), b"odhcpd-rs")
                    else:
                        with self.assertRaisesRegex(ValueError, "all ten actual"):
                            core.sdk_check(work, env, {"commands": []})
                    self.assertNotIn("OWRT_CORE_INCLUDE_ODHCPD", run.call_args_list[0].args[2])
                    self.assertEqual(run.call_args_list[1].args[2]["OWRT_CORE_INCLUDE_ODHCPD"], "1")
                    self.assertTrue(any("odhcpd" in str(call.args[0]) and "--tests" in call.args[0]
                                        for call in run.call_args_list))
                self.assertNotIn("OWRT_CORE_INCLUDE_ODHCPD", env)


if __name__ == "__main__":
    unittest.main()
