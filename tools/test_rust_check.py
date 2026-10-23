#!/usr/bin/env python3
"""Guard the Linux-only compile boundary and isolated test-runner command matrix."""
import json
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import rust_check as gate


class RustGateTests(unittest.TestCase):
    def test_business_boundary_rejects_deny_and_conditional_forbid(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "components/example/src/lib.rs"
            source.parent.mkdir(parents=True)
            with patch.object(gate, "BUSINESS_ROOTS", ("example/src/lib.rs",)):
                source.write_text("#![forbid(unsafe_code)]\npub fn safe() {}\n")
                gate.verify_business_boundaries(root)
                for weakened in (
                    "#![deny(unsafe_code)]",
                    "#![cfg_attr(test, forbid(unsafe_code))]",
                    "// #![forbid(unsafe_code)]",
                ):
                    source.write_text(weakened + "\n")
                    with self.assertRaisesRegex(RuntimeError, "must retain"):
                        gate.verify_business_boundaries(root)

    def recorded_entry(self, arguments):
        output = io.StringIO()
        with patch.object(gate.platform, "system", return_value="Linux"), \
                patch.object(gate.os, "geteuid", return_value=1000), \
                patch.object(gate.shutil, "which", return_value="/tools/mbx"), \
                patch.object(gate.subprocess, "check_output", return_value="host: x86_64-unknown-linux-gnu\n"), \
                patch.object(gate, "verify_business_boundaries"), \
                patch.object(gate, "execute") as execute, \
                contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(arguments), 0)
        return [call.args[0] for call in execute.call_args_list], output.getvalue()

    def test_component_check_entry_also_checks_locked_fuzz_bins(self):
        commands, output = self.recorded_entry(["check"])
        fuzz = str(gate.ROOT / "components/dnsmasq/fuzz/Cargo.toml")
        self.assertEqual([command for command in commands if fuzz in command], [[
            "mbx", "check", "--locked", "--manifest-path", fuzz,
            "--target", "x86_64-unknown-linux-gnu", "--bins",
        ]])
        self.assertIn("Rust check: passed (14 crates)", output)
        self.assertIn("Rust fuzz check: passed", output)

    def test_fmt_entry_includes_fuzz_but_benchmark_entries_stay_scoped(self):
        fuzz = str(gate.ROOT / "components/dnsmasq/fuzz/Cargo.toml")
        commands, output = self.recorded_entry(["fmt-check"])
        self.assertIn(["mbx", "fmt", "--manifest-path", fuzz, "--check"], commands)
        self.assertIn("Rust fuzz fmt-check: passed", output)
        for mode in ["check", "fmt-check"]:
            commands, output = self.recorded_entry([mode, "--benchmark"])
            self.assertTrue(commands)
            self.assertFalse(any(fuzz in command for command in commands))
            self.assertNotIn("Rust fuzz", output)

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

    def test_explicit_business_library_path_keeps_doctest_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "src").mkdir()
            (root / "src/main.rs").write_text("#![forbid(unsafe_code)]\n")
            manifest = root / "Cargo.toml"
            manifest.write_text('[package]\nname="fixture"\n[lib]\npath="src/main.rs"\n')
            self.assertEqual(gate.configuration(manifest), (False, True))
            rows = dict(gate.commands("test", manifest, "x86_64-unknown-linux-gnu"))
            self.assertIn("--doc", rows["doc"])

    def test_namespace_discovery_keeps_platform_adapter_test_names(self):
        name = "daemon::tests::dns_listener_factories_preserve_bound_ipv4_policy_on_rebind"
        executed = []

        def capture(command, log, env):
            executed.append(command)
            if "--list" in command:
                log.write_text(name + ": test\n" if "--bin" in command else "")

        with tempfile.TemporaryDirectory() as folder, patch.object(gate, "execute", capture):
            gate.namespace_tests(gate.ROOT / "components/dnsmasq/Cargo.toml",
                                 "x86_64-unknown-linux-gnu", Path(folder), {})
        invocations = [row for row in executed if "--list" not in row]
        self.assertEqual(len(invocations), 1)
        self.assertIn(name, invocations[0])
        self.assertIn("--exact", invocations[0])

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
