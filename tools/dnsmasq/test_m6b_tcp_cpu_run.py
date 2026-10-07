#!/usr/bin/env python3
"""Offline adapter simulations: no Oracle, namespaces, builds or product edits."""
import copy
import contextlib
import fcntl
import io
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

import m6b_tcp_cpu_run as run
from test_m6b_tcp_cpu_gate import inputs, reference, save, write_window


def write_phase(directory, plan, planned, phase, number=1):
    adjusted = copy.deepcopy(planned)
    adjusted["formal_argv"] = run.gate.attempt_argv(planned, number, phase)
    write_window(directory, plan, adjusted, {"C": 25, "R3_new": 20, "A": 20}[planned["group"]])
    if phase != "pilot":
        return
    result = run.gate.read(directory / "result.json")
    identity = result["identity"]
    identity.update(warmup_seconds=2, duration_seconds=10, saturation_seconds=3,
                    idle_cpu_seconds=5, excluded_preflight=True)
    measured = result["measurement"]
    epoch = {"measurement_start_ns": 1_000_000_000, "saturation_start_ns": 8_000_000_000,
             "measurement_end_ns": 11_000_000_000}
    measured["epoch"] = epoch
    for label, key in (("measurement-start", "measurement_start_ns"), ("saturation-start", "saturation_start_ns"),
                       ("measurement-end", "measurement_end_ns")):
        point = measured["cpu_points"][label]
        point.update(scheduled_monotonic_ns=epoch[key], capture_lag_ns=1000)
        point["cgroup_cpu"]["monotonic_ns"] = epoch[key] + 1000
    path = directory / "load.latencies.bin"
    rows = list(run.gate.arithmetic.LATENCY.iter_unpack(path.read_bytes()))
    sent = (2_000_000_000, 3_000_000_000, 7_900_000_000, 8_100_000_000, 10_900_000_000)
    rows = [(*row[:2], when, *row[3:]) for row, when in zip(rows, sent)]
    path.write_bytes(b"".join(run.gate.arithmetic.LATENCY.pack(*row) for row in rows))
    save(directory / "resources.json", run.gate.read(directory / "resources.json")[:10])
    save(directory / "epoch.json", epoch)
    save(directory / "identity.json", identity)
    save(directory / "result.json", result)


class Adapter(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = inputs(self.root)
        common_path = Path(self.inputs["common_manifest"]["path"])
        common = run.gate.read(common_path)
        tools = self.root / "tools/dnsmasq"
        for module in (run, run.cleanup):
            path = Path(module.__file__)
            (tools / path.name).write_bytes(path.read_bytes())
        common["tools_files"] = run.suite.file_map(tools)
        save(common_path, common)
        self.inputs["common_manifest"] = reference(common_path)
        self.stock_patch = patch.object(run.gate, "STOCK_SHA256", common["groups"]["c"]["sha256"])
        self.stock_patch.start()
        self.addCleanup(self.stock_patch.stop)
        self.private = self.root / "private"
        self.private.mkdir()
        self.plan = run.gate.freeze(self.inputs, self.private)
        self.plan_path = self.private / "plan.json"
        save(self.plan_path, self.plan)
        self.plan = run.gate.read(self.plan_path)
        self.sha = run.suite.sha256(self.plan_path)
        self.prepared = {"manifest_sha256": self.plan["common_manifest"]["sha256"], "windows": {}, "events": [],
                         "expected_windows": 135, "formal_valid_windows": 0, "status": "prepared"}
        save(self.private / "state.json", self.prepared)
        self.original_state = (self.private / "state.json").read_bytes()
        self.events, self.count = [], 0
        self.change = None
        self.cancel_stage = None

    def execute(self, command, log, state, state_path, observer=None):
        job, number, phase = state["current_job"], state["current_attempt"], state["current_phase"]
        self.events.append(("execute", job, phase))
        self.count += 1
        record = {"argv": command, "started_ns": self.count * 1_000_000_000_000,
                  "finished_ns": self.count * 1_000_000_000_000 + 1000, "returncode": 0, "foreign_load": []}
        save(log.with_suffix(".command.json"), record)
        if self.cancel_stage == (job, phase):
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            signal.getsignal(signal.SIGINT).__self__.check()
        planned = next(row for row in self.plan["schedule"] if row["job_id"] == job)
        directory = log.parent / phase
        write_phase(directory, self.plan, planned, phase, number)
        if self.change:
            self.change(job, phase, directory, record)
        save(log.with_suffix(".command.json"), record)
        log.write_text("offline simulation\n")
        return record

    def archive(self, common, attempt, record, state, state_path):
        self.events.append(("archive", record["job_id"], record["attempt"]))
        if self.cancel_stage == (record["job_id"], "archive"):
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
        record["archive"] = {"local_verified": True, "pruned": True}
        run.suite.save(state_path, state)

    def invoke(self):
        with patch.object(run.sys, "platform", "linux"), patch.object(run.os, "geteuid", return_value=0), \
             patch.object(run.os, "sched_setaffinity", create=True), patch.object(run.suite, "TARGET", self.root), \
             patch.object(run.suite, "foreign_load", return_value=[]), patch.object(run.cleanup, "process_tree", return_value={}), \
             patch.object(run.suite, "execute", side_effect=self.execute), patch.object(run.suite, "archive_gate", side_effect=self.archive):
            # The build receipt's target path remains the frozen production
            # target, while only the empty lock file is redirected for tests.
            with patch.object(run.gate, "rust_binding", wraps=run.gate.rust_binding):
                target = run.suite.TARGET
                run.suite.TARGET = Path("/home/ubuntu/dnsmasq-cargo-target")
                real_verify = run.verify
                def verify(*args):
                    run.suite.TARGET = Path("/home/ubuntu/dnsmasq-cargo-target")
                    try:
                        return real_verify(*args)
                    finally:
                        run.suite.TARGET = target
                with patch.object(run, "verify", side_effect=verify):
                    with contextlib.redirect_stdout(io.StringIO()):
                        return run.run(self.plan_path)

    def test_full_interleaved_schedule_and_archives_before_next_window(self):
        self.assertEqual(self.invoke(), 0)
        state = run.gate.read(self.private / "state.json")
        self.assertEqual(state["formal_valid_windows"], 45)
        self.assertEqual(state["status"], "complete")
        expected = []
        for row in self.plan["schedule"]:
            expected += [("execute", row["job_id"], "pilot"), ("execute", row["job_id"], "formal"),
                         ("archive", row["job_id"], 1)]
        self.assertEqual(self.events, expected)
        self.assertEqual((self.private / "common-state-before-cpu.json").read_bytes(), self.original_state)
        for planned in self.plan["schedule"]:
            record = state["windows"][planned["job_id"]]["attempts"][0]
            self.assertEqual((record["source_commit"], record["elf_sha256"]),
                             (planned["source_commit"], planned["expected_elf_sha256"]))

    def test_a_error_stops_after_archive_and_remains_method_valid(self):
        job = self.plan["schedule"][2]["job_id"]
        def fail(current, phase, directory, execution):
            if (current, phase) == (job, "formal"):
                result = run.gate.read(directory / "result.json")
                result.update(accepted=False, measurement_valid=False,
                              cleanup={"forced_kill": True, "returncode": -9})
                save(directory / "result.json", result)
                execution["returncode"] = 1
        self.change = fail
        self.assertEqual(self.invoke(), 1)
        state = run.gate.read(self.private / "state.json")
        self.assertEqual(state["stop_reason"], "behavior-budget")
        self.assertEqual(state["formal_valid_windows"], 3)
        self.assertTrue(state["windows"][job]["attempts"][0]["methodology_valid"])
        self.assertEqual(self.events[-1], ("archive", job, 1))

    def test_baseline_error_is_reported_and_does_not_stop_a_schedule(self):
        job = self.plan["schedule"][0]["job_id"]
        def wrong(current, phase, directory, execution):
            if (current, phase) != (job, "formal"):
                return
            path = directory / "load.latencies.bin"
            rows = list(run.gate.arithmetic.LATENCY.iter_unpack(path.read_bytes()))
            rows[0] = (*rows[0][:5], 2, *rows[0][6:])
            path.write_bytes(b"".join(run.gate.arithmetic.LATENCY.pack(*row) for row in rows))
            result = run.gate.read(directory / "result.json")
            for label in ("measurement", "steady"):
                result["measurement"]["load"][label]["correct"] -= 1
                result["measurement"]["load"][label]["wrong"] += 1
            save(directory / "load.json", result["measurement"]["load"])
            save(directory / "result.json", result)
        self.change = wrong
        self.assertEqual(self.invoke(), 0)
        state = run.gate.read(self.private / "state.json")
        self.assertEqual(state["formal_valid_windows"], 45)
        self.assertTrue(state["windows"][job]["attempts"][0]["behavior_failures"])
        self.assertEqual(state["windows"][job]["valid_attempt"], 1)

    def test_cancel_during_execution_or_archive_is_terminal_and_never_restarts(self):
        job = self.plan["schedule"][0]["job_id"]
        self.cancel_stage = (job, "formal")
        self.assertEqual(self.invoke(), 130)
        state = run.gate.read(self.private / "state.json")
        self.assertEqual(state["stop_reason"], "cancelled")
        self.assertEqual(self.events[-1], ("archive", job, 1))
        before = list(self.events)
        self.assertEqual(self.invoke(), 130)
        self.assertEqual(self.events, before)

    def test_cancellation_while_archiving_finishes_gate_before_stopping(self):
        job = self.plan["schedule"][0]["job_id"]
        self.cancel_stage = (job, "archive")
        self.assertEqual(self.invoke(), 130)
        state = run.gate.read(self.private / "state.json")
        self.assertTrue(state["windows"][job]["attempts"][0]["archive"]["local_verified"])
        self.assertEqual(len(self.events), 3)

    def test_methods_fail_without_next_window_and_nonempty_state_is_not_replaced(self):
        job = self.plan["schedule"][0]["job_id"]
        def corrupt(current, phase, directory, execution):
            if (current, phase) == (job, "formal"):
                path = directory / "load.latencies.bin"
                path.write_bytes(path.read_bytes()[:-1])
        self.change = corrupt
        self.assertEqual(self.invoke(), 1)
        state = run.gate.read(self.private / "state.json")
        self.assertEqual(state["formal_valid_windows"], 0)
        self.assertEqual(state["status"], "failed-tools-or-environment")
        self.assertEqual(self.events[-1], ("archive", job, 1))
        self.assertEqual(state["windows"][job]["attempts"][0]["failure_kind"], "methodology")
        prior = copy.deepcopy(self.prepared)
        prior["windows"] = {"unexpected": {}}
        save(self.private / "state.json", prior)
        with self.assertRaisesRegex(ValueError, "nonempty"):
            run.initial_state(self.plan, self.sha, self.private)

    def test_old_tool_manifest_and_nested_results_cannot_execute(self):
        nested = copy.deepcopy(self.plan)
        nested["output_root"] = str(self.private / "nested")
        nested["schedule"] = run.gate.schedule(nested["common"], nested["groups"], nested["output_root"])
        save(self.plan_path, nested)
        with self.assertRaisesRegex(ValueError, "nested"):
            run.verify(nested, self.plan_path, run.suite.sha256(self.plan_path))
        save(self.plan_path, self.plan)
        common_path = Path(self.inputs["common_manifest"]["path"])
        common = run.gate.read(common_path)
        (self.root / "tools/dnsmasq" / Path(run.__file__).name).unlink()
        common["tools_files"] = run.suite.file_map(self.root / "tools/dnsmasq")
        save(common_path, common)
        self.plan["common"] = common
        self.plan["common_manifest"] = reference(common_path)
        save(self.plan_path, self.plan)
        with self.assertRaisesRegex(ValueError, "executing controller"):
            run.verify(self.plan, self.plan_path, run.suite.sha256(self.plan_path))

    def interrupted(self, group="C", hard=False):
        planned = next(row for row in self.plan["schedule"] if row["group"] == group)
        state = run.initial_state(self.plan, self.sha, self.private)
        state.update(current_job=planned["job_id"], current_attempt=1)
        record = {"job_id": planned["job_id"], "group": group, "round": planned["round"],
                  "profile": planned["profile"], "attempt": 1, "source_commit": planned["source_commit"],
                  "elf_sha256": planned["expected_elf_sha256"], "protocol_sha256": self.plan["protocol_sha256"],
                  "plan_sha256": self.sha, "methodology_valid": False, "pilot_passed": False, "failures": []}
        state["windows"][planned["job_id"]] = {"valid_attempt": None, "attempts": [record]}
        attempt = self.private / "runs" / planned["job_id"] / "attempt-1"
        attempt.mkdir(parents=True)
        if hard:
            def failed(job, phase, directory, execution):
                if phase == "formal":
                    result = run.gate.read(directory / "result.json")
                    result.update(accepted=False, measurement_valid=False, cleanup={"forced_kill": True, "returncode": -9})
                    save(directory / "result.json", result)
                    execution["returncode"] = 1
            self.change = failed
        for phase in ("pilot", "formal"):
            state["current_phase"] = phase
            self.execute(run.gate.attempt_argv(planned, 1, phase), attempt / (phase + ".log"), state,
                         self.private / "state.json")
        save(self.private / "state.json", state)  # sidecars durable, journal still incomplete
        return planned, state, record

    def test_completed_sidecars_recovered_after_crash_without_new_attempt(self):
        planned, state, record = self.interrupted()
        cancel = run.Cancellation(state, self.private / "state.json")
        with patch.object(run.cleanup, "process_tree", return_value={}), \
             patch.object(run.suite, "archive_gate", side_effect=self.archive):
            run.settle_pending(self.plan, self.private, state, self.private / "state.json", cancel)
        self.assertTrue(record["methodology_valid"])
        self.assertEqual(state["windows"][planned["job_id"]]["valid_attempt"], 1)
        self.assertIn("formal_command", record)
        self.assertIn("formal_result_sha256", record)
        self.assertEqual(self.events[-1], ("archive", planned["job_id"], 1))
        self.assertEqual(len(state["windows"][planned["job_id"]]["attempts"]), 1)

    def test_completed_hard_failure_recovered_after_crash_is_terminal(self):
        _, state, record = self.interrupted("A", hard=True)
        cancel = run.Cancellation(state, self.private / "state.json")
        with patch.object(run.cleanup, "process_tree", return_value={}), \
             patch.object(run.suite, "archive_gate", side_effect=self.archive):
            run.settle_pending(self.plan, self.private, state, self.private / "state.json", cancel)
        self.assertTrue(record["methodology_valid"])
        self.assertEqual(state["stop_reason"], "behavior-budget")
        self.assertEqual(record["failure_kind"], "behavior")
        self.assertEqual(run.stopped(state)[1], 1)

    def test_second_controller_cannot_touch_state_or_cleanup_active_job(self):
        with (self.private / ".cpu-controller.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.invoke()
        self.assertEqual((self.private / "state.json").read_bytes(), self.original_state)
        self.assertEqual(self.events, [])


class Signals(unittest.TestCase):
    def test_explicit_int_handler_replaces_inherited_ignore_and_restores_it(self):
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            cancel = run.Cancellation({}, None)
            with cancel.installed():
                self.assertNotEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
                cancel.handler(signal.SIGINT, None)
                with self.assertRaises(run.Cancelled):
                    cancel.check()
                self.assertEqual(cancel.state["cancellation"]["signal"], signal.SIGINT)
                # Repeated signals cannot break the shared cleanup/archive gate.
                cancel.handler(signal.SIGTERM, None)
            self.assertEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_cancellation_between_spawn_and_observer_cannot_escape_cleanup(self):
        class Process:
            pid, returncode = 73, None
            def poll(self):
                return self.returncode
            def wait(self, timeout):
                self.returncode = -signal.SIGTERM
                return self.returncode
        process = Process()
        seen, killed = [], []
        cancel = run.Cancellation({}, None)
        def spawn(*args, **kwargs):
            cancel.handler(signal.SIGINT, None)  # before Popen returns its handle
            return process
        def observe(child):
            seen.append(child.pid)
            cancel.check()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with cancel.installed(), patch.object(run.suite.subprocess, "Popen", side_effect=spawn), \
                 patch.object(run.suite.os, "killpg", side_effect=lambda pid, sig: killed.append((pid, sig))), \
                 patch.object(run.suite.Path, "read_text", return_value="host sample"), \
                 patch.object(run.suite, "foreign_load", return_value=[]):
                with self.assertRaises(run.Cancelled):
                    run.suite.execute(["fake-window"], root / "formal.log", {}, root / "state.json", observe)
            self.assertEqual(seen, [73, 73])
            self.assertEqual(killed, [(73, signal.SIGTERM)])
            self.assertEqual(run.gate.read(root / "formal.command.json")["returncode"], -signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
