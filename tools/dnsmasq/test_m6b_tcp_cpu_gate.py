#!/usr/bin/env python3
"""Hand-counted raw-window tests for the Scheme A incremental CPU gate."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import m6b_tcp_cpu_gate as gate
from test_m6a_analyze import fixture as raw_fixture


def save(path, value):
    path.write_text(json.dumps(value))


def reference(path):
    return {"path": str(path), "sha256": gate.arithmetic.sha256(path)}


def group(root, name, commit, elf_bytes):
    source = root / name
    source.mkdir()
    (source / "src.txt").write_text(name)
    elf = source / "dnsmasq-rs"
    elf.write_bytes(elf_bytes)
    freeze = source / "freeze.json"
    save(freeze, {"source_commit": commit, "source_root": str(source),
                  "source_files": {"src.txt": gate.arithmetic.sha256(source / "src.txt")}})
    build = source / "build.json"
    save(build, {"kind": "release", "source": str(source), "opt_level": "3", "features": "",
                 "cargo_target_dir": str(gate.suite.TARGET),
                 "rustflags": "--remap-path-prefix=" + str(source) + "=/build -Cforce-unwind-tables=no",
                 "artifacts": [{"path": "dnsmasq-rs", "bytes": len(elf_bytes), "sha256": gate.arithmetic.sha256(elf)}]})
    return {"source_commit": commit, "source_freeze": reference(freeze), "build": reference(build),
            "elf": {**reference(elf), "bytes": len(elf_bytes)}}


def inputs(root):
    tools = root / "tools/dnsmasq"
    tools.mkdir(parents=True)
    for module in (gate, gate.arithmetic, gate.suite, gate.window):
        path = Path(module.__file__)
        (tools / path.name).write_bytes(path.read_bytes())
    groups = {"R3_new": group(root, "no-a", "1" * 40, b"opt3 no A"),
              "A": group(root, "a", "2" * 40, b"opt3 A")}
    stock = root / "c-elf"
    stock.write_bytes(b"test fixture C")
    protocol = root / "protocol.md"
    protocol.write_text("unchanged thresholds")
    common = root / "common.json"
    native = {}
    for name in ("m6a_loadgen", "m6a_upstream"):
        path = root / name
        path.write_text(name)
        native[name] = reference(path)
    no_a = gate.read(groups["R3_new"]["source_freeze"]["path"])
    save(common, {"m6b": True, "root": str(root), "source_commit": no_a["source_commit"],
                  "source_root": no_a["source_root"], "source_files": no_a["source_files"],
                  "protocol": str(protocol), "protocol_sha256": gate.arithmetic.sha256(protocol),
                  "image_root": str(root / "image"), "tools_files": gate.suite.file_map(tools),
                  "instrumentation": {"diagnostic_only": False, "wake_metrics": False,
                                      "build_features": {"r3": "", "rs": ""}},
                  "groups": {"c": {"elf": str(stock), "sha256": gate.arithmetic.sha256(stock)},
                             "r3": {"elf": groups["R3_new"]["elf"]["path"], "sha256": groups["R3_new"]["elf"]["sha256"]}},
                  "builds": {"r3": groups["R3_new"]["build"]}, "native": native,
                  "product_freeze": groups["R3_new"]["source_freeze"],
                  "profiles": gate.suite.PROFILES})
    proof = root / "prerequisites.json"
    evidence = root / "gate-evidence.json"
    save(evidence, {"fixture": True})
    save(proof, {"source_commit": groups["A"]["source_commit"], "elf_sha256": groups["A"]["elf"]["sha256"],
                 "gates": {name: {"passed": True, "evidence": reference(evidence)} for name in gate.PREREQUISITES}})
    return {"common_manifest": reference(common), "groups": groups, "prerequisites": reference(proof)}


def write_window(directory, plan, planned, cpu):
    raw_fixture(directory)
    latencies = list(gate.arithmetic.LATENCY.iter_unpack((directory / "load.latencies.bin").read_bytes()))[:5]
    base = ((0x4d364100 + planned["round"]) << 32) & ((1 << 64) - 1)
    latencies = [(base + i, *row[1:]) for i, row in enumerate(latencies, 1)]
    (directory / "load.latencies.bin").write_bytes(b"".join(gate.arithmetic.LATENCY.pack(*row) for row in latencies))
    (directory / "load.send-lag.bin").write_bytes(b"".join(gate.arithmetic.LAG.pack(base + i, 1000) for i in range(1, 6)))
    result = gate.read(directory / "result.json")
    load = result["measurement"]["load"]
    load["measurement"].update(sent=5, correct=5, timeout=0, wrong=0, correct_in_window=4, send_lag_sum_ns=5000)
    load["steady"].update(sent=3, correct=3, timeout=0, wrong=0)
    # Two correct completions per phase; one success crosses phases and one is
    # late. This fixture catches denominator substitution and child-CPU sums.
    points = result["measurement"]["cpu_points"]
    points["saturation-start"]["cgroup_cpu"]["usage_usec"] = 2 * cpu
    points["measurement-end"]["cgroup_cpu"]["usage_usec"] = 4 * cpu
    result["measurement"]["cpu_segments"] = {
        "measurement-start..saturation-start": {"cpu_seconds": 2 * cpu / 1e6},
        "saturation-start..measurement-end": {"cpu_seconds": 2 * cpu / 1e6}}
    result["measurement"]["measurement_cpu_seconds"] = 4 * cpu / 1e6
    result["measurement"]["proc_measurement_cpu_seconds"] = 1000  # secondary only
    completed = 122_000_000_000
    barrier = {"completed_monotonic_ns": completed, "idle_fd_count": 3, "stable_samples_required": 3,
               "observations": [{"fd_count": 3, "child_processes": 0, "ready": True, "stable_samples": i + 1,
                                 "monotonic_ns": completed - (2 - i) * 20_000_000} for i in range(3)]}
    samples = {str(n): {"scheduled_offset_seconds": n, "scheduled_monotonic_ns": completed + n * 1_000_000_000,
                        "captured_monotonic_ns": completed + n * 1_000_000_000 + 1000,
                        "snapshot": {"tree": {"fd_count": 3, "child_processes": 0}}} for n in (0, 1, 5, 60)}
    result["measurement"].update(idle_fd_count=3, drain_barrier=barrier, drain_samples=samples,
                                 cpu_before_warmup={"tree": {"fd_count": 3}},
                                 quality={key: True for key in gate.QUALITY_KEYS},
                                 idle_cpu={"enabled": True, "requested_seconds": 60,
                                           "started_monotonic_ns": 0, "ended_monotonic_ns": 60_000_000_000,
                                           "elapsed_seconds": 60, "cgroup_before": {"usage_usec": 100},
                                           "cgroup_after": {"usage_usec": 200}, "cpu_seconds": .0001})
    result.update(cleanup={"forced_kill": False, "returncode": 0},
                  cgroup_cleanup={"remaining_pids": [], "removed": True})
    identity = result["identity"]
    identity.update(implementation=planned["runner_implementation"], scenario="tcp",
                    tcp_profile={"tcp-local": "local", "tcp-cache": "hit", "tcp-miss": "miss"}[planned["profile"]],
                    round=planned["round"], seed=0x4d364100 + planned["round"],
                    expected_elf_sha256=planned["expected_elf_sha256"], protocol_sha256=plan["protocol_sha256"],
                    warmup_seconds=30, idle_cpu_seconds=60, drain_sample_seconds=[0, 1, 5, 60],
                    rate=10000, wake_metrics=False, perf_record=False, strace_summary=False,
                    cpus={"daemon": 0, "upstream": 1, "loadgen": 2, "control": 3},
                    runner_sha256=plan["common"]["tools_files"]["m6a_window.py"],
                    loadgen_sha256=plan["common"]["native"]["m6a_loadgen"]["sha256"],
                    upstream_sha256=plan["common"]["native"]["m6a_upstream"]["sha256"],
                    argv=planned["formal_argv"][3:])
    save(directory / "identity.json", identity)
    save(directory / "process-identity.json", {"sha256": planned["expected_elf_sha256"]})
    (directory / "config").write_text(plan["configs"][planned["profile"]])
    save(directory / "load.json", load)
    save(directory / "result.json", result)


class CpuGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = inputs(self.root)
        stock = gate.read(self.inputs["common_manifest"]["path"])["groups"]["c"]["sha256"]
        self.stock_patch = patch.object(gate, "STOCK_SHA256", stock)
        self.stock_patch.start()
        self.addCleanup(self.stock_patch.stop)
        self.plan = gate.freeze(self.inputs, self.root / "private")
        self.plan_path = self.root / "plan.json"
        save(self.plan_path, self.plan)
        self.plan = gate.read(self.plan_path)  # exercise JSON's tuple->list conversion
        self.plan_sha = gate.arithmetic.sha256(self.plan_path)

    def matrix(self, a_cpu=21, c_cpu=25, r_cpu=20):
        private = self.root / "private"
        private.mkdir()
        state = {"plan_sha256": self.plan_sha, "windows": {}}
        for planned in self.plan["schedule"]:
            job = planned["job_id"]
            directory = private / "runs" / job / "attempt-1/formal"
            write_window(directory, self.plan, planned, {"C": c_cpu, "R3_new": r_cpu, "A": a_cpu}[planned["group"]])
            pilot = directory.parent / "pilot"
            pilot.mkdir()
            save(pilot / "result.json", {"measurement_valid": True,
                 "identity": {"expected_elf_sha256": planned["expected_elf_sha256"], "argv": planned["pilot_argv"][3:],
                              "protocol_sha256": self.plan["protocol_sha256"], "implementation": planned["runner_implementation"]},
                 "measurement": {"load": {"measurement": {"correct": 10, "wrong": 0, "timeout": 0, "transport_error": 0}}}})
            save(pilot / "process-identity.json", {"sha256": planned["expected_elf_sha256"]})
            (pilot / "config").write_text(self.plan["configs"][planned["profile"]])
            stamp = (1 + self.plan["schedule"].index(planned)) * 1_000_000_000_000
            record = {"attempt": 1, "plan_sha256": self.plan_sha, "methodology_valid": True,
                      "group": planned["group"], "source_commit": planned["source_commit"],
                      "elf_sha256": planned["expected_elf_sha256"], "protocol_sha256": self.plan["protocol_sha256"],
                      "formal_result_sha256": gate.arithmetic.sha256(directory / "result.json"),
                      "pilot_passed": True, "pilot_result_sha256": gate.arithmetic.sha256(pilot / "result.json"),
                      "pilot_command": {"argv": planned["pilot_argv"], "started_ns": stamp,
                                        "finished_ns": stamp + 100_000, "returncode": 0, "foreign_load": []},
                      "formal_command": {"argv": planned["formal_argv"], "started_ns": stamp + 200_000,
                                         "finished_ns": stamp + 300_000, "returncode": 0, "foreign_load": []},
                      "archive": {"local_verified": True}}
            state["windows"][job] = {"valid_attempt": 1, "attempts": [record]}
        save(private / "state.json", state)
        return private, state

    def mutate_result(self, private, state, job, change):
        path = private / "runs" / job / "attempt-1/formal/result.json"
        result = gate.read(path)
        change(result)
        save(path, result)
        state["windows"][job]["attempts"][0]["formal_result_sha256"] = gate.arithmetic.sha256(path)
        save(private / "state.json", state)

    def test_plan_labels_rotated_order_and_no_executor(self):
        self.assertEqual(len(self.plan["schedule"]), 45)
        self.assertEqual(self.plan["orders"], [["C", "R3_new", "A"], ["R3_new", "A", "C"],
                                               ["A", "C", "R3_new"], ["C", "A", "R3_new"], ["A", "R3_new", "C"]])
        self.assertFalse(self.plan["execution_enabled"])
        for row in self.plan["schedule"]:
            self.assertNotIn("rs", row["formal_argv"])
            self.assertNotIn("--wake-metrics", row["formal_argv"])
            self.assertEqual(row["formal_argv"][row["formal_argv"].index("--duration") + 1], "120")
            if row["group"] == "A":
                self.assertEqual(row["expected_elf_sha256"], self.inputs["groups"]["A"]["elf"]["sha256"])

    def test_cpu_at_five_percent_budget_passes_and_cgroup_counts_once(self):
        private, _ = self.matrix()
        result = gate.analyze(self.plan_path, private)
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual((result["valid_windows"], len(result["budget_gates"])), (45, 6))
        self.assertEqual(result["budget_gates"][0]["median_cpu_us_per_correct"], {"C": 25, "R3_new": 20, "A": 21})
        self.assertAlmostEqual(result["budget_gates"][0]["cpu_ratio_to_R3_new"], 1.05)

    def test_above_five_percent_or_equal_to_c_fails_without_changing_method_validity(self):
        for a, c in ((21.5, 25), (21, 21)):
            with self.subTest(a=a, c=c):
                private, _ = self.matrix(a_cpu=a, c_cpu=c)
                result = gate.analyze(self.plan_path, private)
                self.assertTrue(result["complete"])
                self.assertFalse(result["passed"])
                self.assertEqual(result["valid_windows"], 45)
                # Keep the distinct experiment, then prepare another fixture.
                private.rename(self.root / f"old-{a}-{c}")

    def test_wrong_answer_is_real_failed_budget_not_method_invalid(self):
        private, state = self.matrix()
        job = self.plan["schedule"][2]["job_id"]
        directory = private / "runs" / job / "attempt-1/formal"
        path = directory / "load.latencies.bin"
        rows = list(gate.arithmetic.LATENCY.iter_unpack(path.read_bytes()))
        rows[0] = (*rows[0][:5], 2, *rows[0][6:])
        path.write_bytes(b"".join(gate.arithmetic.LATENCY.pack(*row) for row in rows))
        result = gate.read(directory / "result.json")
        for label in ("measurement", "steady"):
            result["measurement"]["load"][label]["correct"] -= 1
            result["measurement"]["load"][label]["wrong"] += 1
        save(directory / "load.json", result["measurement"]["load"])
        self.mutate_result(private, state, job, lambda current: current.update(result))
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 45)
        self.assertFalse(result["passed"])
        self.assertTrue(any(row["kind"] == "behavior" for row in result["failures"]))

    def test_incomplete_matrix_and_tampered_group_invocation_fail(self):
        private, state = self.matrix()
        job = self.plan["schedule"][2]["job_id"]
        state["windows"].pop(job)
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertFalse(result["complete"])
        self.assertEqual(result["valid_windows"], 44)
        self.assertIn(job, result["missing_jobs"])
        job = self.plan["schedule"][5]["job_id"]
        self.mutate_result(private, state, job, lambda r: r["identity"]["argv"].extend(["--cache-names", "150"]))
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 43)
        self.assertTrue(any("invocation" in row.get("reason", "") for row in result["failures"]))

    def test_fd_leak_and_child_only_drain_cannot_pass(self):
        private, state = self.matrix()
        job = self.plan["schedule"][2]["job_id"]
        self.mutate_result(private, state, job,
                           lambda r: r["measurement"]["drain_samples"]["60"]["snapshot"]["tree"].update(fd_count=4))
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 45)
        self.assertFalse(result["passed"])
        self.assertTrue(any("FD/child leak" in str(row) for row in result["failures"]))
        self.mutate_result(private, state, job, lambda r: r["measurement"]["drain_barrier"].update(idle_fd_count=None))
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 44)
        self.assertTrue(any("child-only" in str(row) for row in result["failures"]))

    def test_later_faster_attempt_cannot_replace_genuine_result(self):
        private, state = self.matrix()
        job = self.plan["schedule"][2]["job_id"]
        state["windows"][job]["valid_attempt"] = 2
        record = copy.deepcopy(state["windows"][job]["attempts"][0])
        record["attempt"] = 2
        state["windows"][job]["attempts"].append(record)
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 44)
        self.assertTrue(any("earlier genuine result" in str(row) for row in result["failures"]))

    def test_instrumented_or_s_build_and_incomplete_prerequisites_rejected(self):
        binding = self.inputs["groups"]["A"]
        path = Path(binding["build"]["path"])
        original = gate.read(path)
        for field, value in (("features", "m6b-diagnostics"), ("opt_level", "s")):
            mutated = {**original, field: value}
            save(path, mutated)
            binding["build"] = reference(path)
            with self.assertRaisesRegex(ValueError, "feature-off opt3"):
                gate.freeze(self.inputs, self.root / "private")
        save(path, original)
        binding["build"] = reference(path)
        proof = Path(self.inputs["prerequisites"]["path"])
        receipt = gate.read(proof)
        receipt["gates"].pop("empty-cache")
        save(proof, receipt)
        self.inputs["prerequisites"] = reference(proof)
        with self.assertRaisesRegex(ValueError, "all Scheme A prerequisites"):
            gate.freeze(self.inputs, self.root / "private")

    def test_source_binding_and_frozen_schedule_cannot_be_relabeled(self):
        self.inputs["groups"]["A"]["source_commit"] = "913a2347"
        with self.assertRaisesRegex(ValueError, "full lowercase 40"):
            gate.freeze(self.inputs, self.root / "private")
        self.plan["schedule"][2]["group"] = "Rs"
        save(self.plan_path, self.plan)
        with self.assertRaisesRegex(ValueError, "schedule"):
            gate.validate_plan(gate.read(self.plan_path))

    def test_known_cleanup_failure_is_terminal_even_when_old_runner_rejects_it(self):
        private, state = self.matrix()
        job = self.plan["schedule"][2]["job_id"]
        self.mutate_result(private, state, job,
                           lambda r: r.update(accepted=False, measurement_valid=False,
                                              cleanup={"forced_kill": True, "returncode": -9}))
        state["windows"][job]["attempts"][0]["formal_command"]["returncode"] = 1
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertTrue(result["complete"])
        self.assertFalse(result["passed"])
        self.assertTrue(any(row["kind"] == "behavior" and row["job_id"] == job for row in result["failures"]))
        # Old collectors may have no selected attempt. Its real raw failure
        # still remains terminal and cannot disappear as a retryable method gap.
        state["windows"][job]["valid_attempt"] = None
        state["windows"][job]["attempts"][0]["methodology_valid"] = False
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertTrue(any(row["kind"] == "behavior" and row["job_id"] == job for row in result["failures"]))

    def test_contaminated_forced_cleanup_is_method_invalid_and_retryable(self):
        private, state = self.matrix()
        job = self.plan["schedule"][2]["job_id"]
        self.mutate_result(private, state, job,
                           lambda r: r.update(accepted=False, measurement_valid=False,
                                              cleanup={"forced_kill": True, "returncode": -9}))
        record = state["windows"][job]["attempts"][0]
        record["formal_command"].update(returncode=1, foreign_load=[{"name": "cargo"}])
        record["methodology_valid"] = False
        state["windows"][job]["valid_attempt"] = None
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertFalse(any(row["kind"] == "behavior" and row["job_id"] == job for row in result["failures"]))
        self.assertFalse(result["complete"])

    def test_generator_limit_preserves_numeric_cpu_but_cannot_qualify_throughput(self):
        private, _ = self.matrix()
        for planned in self.plan["schedule"]:
            path = private / "runs" / planned["job_id"] / "attempt-1/formal/resources.json"
            rows = gate.read(path)
            for i, row in enumerate(rows):
                row["loadgen"]["user_ticks"] = i * 95
            save(path, rows)
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 45)
        self.assertTrue(result["complete"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["qualification"], "unproven")
        self.assertTrue(all(row["cpu_budget_passed"] and row["numeric_passed"] for row in result["budget_gates"]))
        self.assertTrue(all("restricted" in row["throughput_qualification"] for row in result["budget_gates"]))
        self.assertTrue(all(row["classification"] == "受限" for row in result["comparisons"] if row["metric"] == "qps"))
        self.assertTrue(all(row["classification"] != "受限" for row in result["comparisons"] if row["metric"] == "cpu_us_per_correct"))

    def test_baseline_error_remains_observation_and_does_not_become_a_regression(self):
        private, state = self.matrix()
        job = self.plan["schedule"][0]["job_id"]  # C
        directory = private / "runs" / job / "attempt-1/formal"
        path = directory / "load.latencies.bin"
        rows = list(gate.arithmetic.LATENCY.iter_unpack(path.read_bytes()))
        rows[0] = (*rows[0][:5], 2, *rows[0][6:])
        path.write_bytes(b"".join(gate.arithmetic.LATENCY.pack(*row) for row in rows))
        result = gate.read(directory / "result.json")
        for label in ("measurement", "steady"):
            result["measurement"]["load"][label]["correct"] -= 1
            result["measurement"]["load"][label]["wrong"] += 1
        save(directory / "load.json", result["measurement"]["load"])
        self.mutate_result(private, state, job, lambda current: current.update(result))
        result = gate.analyze(self.plan_path, private)
        self.assertTrue(result["passed"], result["failures"])
        self.assertEqual(result["per_group_counts"]["C"]["measurement"]["wrong"], 1)
        self.assertTrue(any(row["job_id"] == job and not row["hard_failure"] for row in result["failures"]))

    def test_partial_quality_cannot_requalify_rejected_observation(self):
        private, state = self.matrix()
        job = self.plan["schedule"][2]["job_id"]
        def reject(result):
            result.update(accepted=False, measurement_valid=False, cleanup={"forced_kill": True, "returncode": -9})
            result["measurement"]["quality"] = {"sample_count_passed": True}
        self.mutate_result(private, state, job, reject)
        state["windows"][job]["attempts"][0]["formal_command"]["returncode"] = 1
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 44)
        self.assertTrue(any(row["kind"] == "behavior" and row["job_id"] == job for row in result["failures"]))

    def test_baseline_pilot_and_receipt_errors_remain_observed_without_retry(self):
        private, state = self.matrix()
        job = self.plan["schedule"][0]["job_id"]  # C
        path = private / "runs" / job / "attempt-1/pilot/result.json"
        report = gate.read(path)
        report["measurement"]["load"]["measurement"]["timeout"] = 1
        save(path, report)
        record = state["windows"][job]["attempts"][0]
        record.update(pilot_result_sha256=gate.arithmetic.sha256(path), failure_kind="behavior",
                      failures=["measurement contains genuine wrong/timeout/transport errors"])
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 45)
        self.assertTrue(result["passed"], result["failures"])
        self.assertTrue(any(row["job_id"] == job and row.get("phase") == "pilot" for row in result["failures"]))
        self.assertFalse(any(row.get("hard_failure") for row in result["failures"]))

    def test_missing_pilot_overlapping_windows_and_fake_idle_count_rejected(self):
        private, state = self.matrix()
        job = self.plan["schedule"][2]["job_id"]
        state["windows"][job]["attempts"][0]["pilot_passed"] = False
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertEqual(result["valid_windows"], 44)
        self.assertTrue(any("pilot was not passed" in row.get("reason", "") for row in result["failures"]))
        state["windows"][job]["attempts"][0]["pilot_passed"] = True
        state["windows"][job]["attempts"][0]["pilot_command"]["started_ns"] = 1
        save(private / "state.json", state)
        result = gate.analyze(self.plan_path, private)
        self.assertTrue(any("overlapped" in row.get("reason", "") for row in result["failures"]))
        # Correct the schedule and check the independently captured idle value.
        state["windows"][job]["attempts"][0]["pilot_command"]["started_ns"] = 3_000_000_000_000
        self.mutate_result(private, state, job, lambda r: r["measurement"].update(idle_fd_count=4))
        result = gate.analyze(self.plan_path, private)
        self.assertTrue(any("actual pre-load snapshot" in row.get("reason", "") for row in result["failures"]))


if __name__ == "__main__":
    unittest.main()
