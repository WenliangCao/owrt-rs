#!/usr/bin/env python3
"""Offline negative controls for diagnostic trace scope and restart gates."""
import io
import json
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import m6a_window as window
import m6b_intermediate as intermediate


class TraceAccounting(unittest.TestCase):
    def test_controlled_sigint_detach_does_not_hide_failed_or_early_tracer(self):
        row = {"forced_kill": False, "exited_before_stop": False, "returncode": -signal.SIGINT}
        self.assertTrue(window.diagnostic_tools_finished({"stopped": {"strace": row}}))
        for change in ({"returncode": 1}, {"forced_kill": True}, {"exited_before_stop": True}):
            self.assertFalse(window.diagnostic_tools_finished({"stopped": {"strace": {**row, **change}}}))

    def test_full_scope_denominator_includes_warmup_and_cross_window_success(self):
        load = {"warmup": {"correct": 40}, "measurement": {"correct": 100, "correct_in_window": 90}}
        trace = {"completed_calls": 700, "calls": {"recvmsg": 280}, "eagain_calls": 140,
                 "errno": {"recvmsg": {"EAGAIN": 140}}}
        result = window.syscall_accounting(trace, load)
        self.assertEqual(result["correct_requests"], 140)
        self.assertEqual(result["calls_per_correct_request"], 5)
        self.assertEqual(result["syscalls_per_correct_request"]["recvmsg"], 2)
        self.assertEqual(result["eagain_per_correct_request"], 1)

    def test_raw_calls_retain_errno_and_do_not_double_count_unfinished(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "syscalls.log"
            path.write_text("""17 1728300000.000001 recvmsg(4, 0xabc, 0) = -1 EAGAIN (Resource temporarily unavailable) <0.00001>
17 1728300000.000002 poll([{fd=4, events=POLLIN}], 1, -1 <unfinished ...>
18 1728300000.000003 sendto(5, \"\", 42, 0, NULL, 0) = 42 <0.00001>
17 1728300000.000004 <... poll resumed>) = 1 <0.00001>
% time     seconds  usecs/call     calls    errors syscall
 10.00    0.000001           1         1         1 recvmsg
17 1728300000.000005 +++ exited with 0 +++
""")
            result = window.parse_strace(path)
        self.assertEqual(result["completed_calls"], 3)
        self.assertEqual(result["calls"], {"recvmsg": 1, "poll": 1, "sendto": 1})
        self.assertEqual(result["errno"], {"recvmsg": {"EAGAIN": 1}})
        self.assertEqual(result["unresolved_unfinished_calls"], 0)

    def test_capture_stop_is_idempotent_and_preserves_failure(self):
        class Process:
            returncode = None
            def poll(self):
                return self.returncode
            def send_signal(self, value):
                self.signal = value
            def wait(self, timeout):
                self.returncode = 1
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(output=Path(directory), perf_record=False, strace_summary=True, cpu_control=3)
            capture = window.DiagnosticCapture(args, 123)
            process = Process()
            capture.processes["strace"] = process
            capture.streams["strace"] = io.BytesIO()
            first = capture.stop()
            second = capture.stop()
            self.assertEqual(first, second)
            self.assertEqual(process.signal, signal.SIGINT)
            self.assertEqual(first["stopped"]["strace"]["returncode"], 1)
            self.assertFalse(first["stopped"]["strace"]["exited_before_stop"])


class InstrumentationManifest(unittest.TestCase):
    def spec(self, diagnostic=False, wake=False, features=""):
        return {"m6b": True, "root": "/unused", "image_root": "/image", "protocol": "/protocol",
                "groups": {"r3": {"elf": "/r3", "sha256": "r3"},
                           "rs": {"elf": "/rs", "sha256": "rs"}},
                "native": {name: {"path": "/" + name} for name in ("m6a_loadgen", "m6a_upstream")},
                "instrumentation": {"diagnostic_only": diagnostic, "wake_metrics": wake,
                                    "build_features": {"r3": features, "rs": features}}}

    def test_final_feature_off_commands_never_require_wake(self):
        spec = self.spec()
        for pilot in (False, True):
            for group in ("c", "r3", "rs"):
                command = intermediate.suite.command_for(spec, intermediate.suite.PROFILES[0],
                                                          group, 1, Path("fresh"), pilot)
                self.assertNotIn("--wake-metrics", command)
        self.assertNotIn("--preflight", intermediate.suite.command_for(
            spec, intermediate.suite.PROFILES[0], "r3", 1, Path("fresh"), False))

    def test_feature_on_and_missing_m6b_rules_are_rejected_for_formal(self):
        with self.assertRaisesRegex(ValueError, "explicit instrumentation"):
            intermediate.suite.check_instrumentation({"m6b": True})
        with self.assertRaisesRegex(ValueError, "feature-on"):
            intermediate.suite.check_instrumentation(self.spec(features="m6b-diagnostics"))
        spec = self.spec(diagnostic=True, wake=True, features="m6b-diagnostics")
        with self.assertRaisesRegex(ValueError, "diagnostic-only"):
            intermediate.suite.check_instrumentation(spec, formal=True)
        pilot = intermediate.suite.command_for(spec, intermediate.suite.PROFILES[0], "r3", 1, Path("fresh"), True)
        self.assertIn("--wake-metrics", pilot)
        c_pilot = intermediate.suite.command_for(spec, intermediate.suite.PROFILES[0], "c", 1, Path("fresh"), True)
        self.assertNotIn("--wake-metrics", c_pilot)

    def test_foreign_trace_and_m6b_controller_are_rejected(self):
        row = lambda parent, start, *names: {"parent": parent, "start": start, "names": names,
                                             "cmdline_sha256": "redacted"}
        rows = {1: row(0, 1, "init"), 10: row(1, 2, "m6b_intermediate.py"),
                11: row(10, 3, "strace"), 20: row(1, 4, "perf"),
                21: row(1, 5, "m6b_intermediate.py")}
        with patch.object(intermediate.suite.os, "getpid", return_value=10), \
                patch.object(intermediate.suite, "pid_state", side_effect=[rows, rows]):
            self.assertEqual({item["pid"] for item in intermediate.suite.foreign_load()}, {20, 21})

    def test_external_controller_must_match_frozen_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "m6b_intermediate.py"
            script.write_text("frozen bytes")
            spec = {"tools_files": {script.name: intermediate.suite.sha256(script)}}
            self.assertEqual(intermediate.suite.verify_controller(spec, script)["sha256"], spec["tools_files"][script.name])
            script.write_text("external changed controller")
            with self.assertRaisesRegex(ValueError, "executing controller"):
                intermediate.suite.verify_controller(spec, script)


class IntermediateRestart(unittest.TestCase):
    def test_short_trace_command_is_excluded_and_cpu_args_are_preserved(self):
        frozen = ["python3", "window.py", "--warmup", "2", "--duration", "10", "--preflight",
                  "--saturation-seconds", "3", "--idle-seconds", "60", "--drain-sample-seconds", "0,1,5,60",
                  "--cpu-daemon", "0", "--cpu-load", "2", "--cpu-control", "3", "--wake-metrics"]
        with patch.object(intermediate.suite, "command_for", return_value=frozen):
            result = intermediate.command_for({}, (), "r3", Path("fresh"), "strace")
        self.assertIn("--preflight", result)
        self.assertIn("--strace-summary", result)
        self.assertNotIn("--wake-metrics", result)
        self.assertEqual(result[result.index("--duration") + 1], "15")
        self.assertEqual(result[result.index("--drain-sample-seconds") + 1], "0")
        self.assertEqual(result[result.index("--cpu-control") + 1], "3")

    def test_archive_barrier_finishes_before_valid_attempt_is_published(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            state_path = private / "state.json"
            record = {"job_id": "r01-tcp-cache-r3", "attempt": 2, "methodology_valid": True}
            state = {"archive_gate": {"job_id": record["job_id"], "attempt": 2},
                     "windows": {record["job_id"]: {"attempts": [record], "valid_attempt": None}}}
            observed = []
            def archive(spec, attempt, active, value, path):
                self.assertIsNone(value["windows"][record["job_id"]]["valid_attempt"])
                observed.append(str(attempt))
                value.pop("archive_gate")
            with patch.object(intermediate.suite, "archive_gate", side_effect=archive):
                intermediate.resume_archive_gate({}, private, state, state_path)
            self.assertEqual(state["windows"][record["job_id"]]["valid_attempt"], 2)
            self.assertTrue(observed[0].endswith("runs/r01-tcp-cache-r3/attempt-2"))
            self.assertNotIn("archive_gate", json.loads(state_path.read_text()))


if __name__ == "__main__":
    unittest.main()
