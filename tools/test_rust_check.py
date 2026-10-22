#!/usr/bin/env python3
"""Guard the Linux-only compile boundary and isolated test-runner command matrix."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import rust_check as gate


class RustGateTests(unittest.TestCase):
    def test_mac_is_rejected_before_a_compiler_or_runner_is_started(self):
        with patch.object(gate.platform, "system", return_value="Darwin"), \
                patch.object(gate.subprocess, "run") as run, \
                patch.object(gate.subprocess, "check_output") as read:
            with self.assertRaisesRegex(RuntimeError, "ssh oracle"):
                gate.main(["test"])
            run.assert_not_called()
            read.assert_not_called()

    def test_manifest_inventory_includes_both_platform_crates(self):
        actual = {
            path.parent.relative_to(gate.ROOT / "components").as_posix()
            for path in (gate.ROOT / "components").glob("*/Cargo.toml")
        }
        actual.add("dnsmasq/platform")
        self.assertEqual(set(gate.COMPONENTS), actual)

    def test_dns_features_and_real_main_process_tests_keep_the_runner(self):
        manifest = gate.ROOT / "components/dnsmasq/Cargo.toml"
        rows = list(gate.commands("test", manifest, "x86_64-unknown-linux-gnu"))
        test_rows = [(label, command) for label, command in rows if label.startswith("test-")]
        self.assertEqual([label for label, _ in test_rows], ["test-default", "test-all-features"])
        for _, command in test_rows:
            self.assertEqual(command[0], "mbx")
            self.assertIn("--locked", command)
            self.assertIn("--all-targets", command)
            self.assertIn("--test-threads=1", command)
            config = command[command.index("--config") + 1]
            self.assertEqual(json.loads(config.split("=", 1)[1])[-1], "run-test")
        self.assertIn("--all-features", test_rows[1][1])

    def test_example_checks_compile_normal_profiler_programs(self):
        manifest = gate.ROOT / "components/rpcd/Cargo.toml"
        rows = dict(gate.commands("check", manifest, "x86_64-unknown-linux-gnu"))
        self.assertIn("--examples", rows["examples-default"])
        self.assertNotIn("--all-targets", rows["examples-default"])
        self.assertEqual(rows["clippy-default"][-3:], ["--", "-D", "warnings"])

    def test_compilation_failure_cannot_be_reported_as_success(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)):
                with self.assertRaises(subprocess.CalledProcessError):
                    gate.execute(["mbx", "check"], Path(folder) / "failure.log", {})

    def test_runner_elevates_only_the_elf_and_cleans_its_own_temporary_path(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / "test binary"
            executable.touch()
            private = Path(folder) / "private"
            with patch.object(gate.platform, "system", return_value="Linux"), \
                    patch.object(gate.tempfile, "mkdtemp", return_value=str(private)), \
                    patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 5)) as run:
                self.assertEqual(gate.run_test([str(executable), "--exact", "fixture"]), 5)
                execution, cleanup = run.call_args_list
                command = execution.args[0]
                self.assertEqual(command[:3], ["sudo", "-n", "env"])
                self.assertIn(str(gate.ROOT / "tools/dnsmasq/run_isolated.sh"), command)
                self.assertEqual(command[-3:], [str(executable), "--exact", "fixture"])
                self.assertNotIn("mbx", command)
                self.assertEqual(cleanup.args[0], ["sudo", "-n", "rm", "-rf", "--", str(private)])


if __name__ == "__main__":
    unittest.main()
