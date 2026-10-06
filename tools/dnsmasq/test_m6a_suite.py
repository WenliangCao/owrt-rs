#!/usr/bin/env python3
"""Offline contract checks for rejected load, interrupted copies and resume.

These tests use synthetic process tables and temporary files. No Oracle,
namespace, daemon, build or performance window is started.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import m6a_analyze as analyze
import m6a_archive_watch as watcher
import m6a_suite as suite


def process(parent, start, *names):
    return {"parent": parent, "start": start, "names": list(names),
            "cmdline_sha256": hashlib.sha256(" ".join(names).encode()).hexdigest()}


class ForeignLoad(unittest.TestCase):
    def test_owned_namespace_children_are_excluded_but_foreign_m6a_is_rejected(self):
        rows = {1: process(0, 1, "init"), 77: process(1, 2, "m6a_suite.py"),
                80: process(77, 3, "unshare"), 81: process(80, 4, "dnsmasq"),
                82: process(80, 5, "m6a_loadgen"),
                90: process(1, 6, "python3", "m6a_suite.py"),
                91: process(1, 7, "m6a_upstream"),
                92: process(1, 8, "aarch64-linux-gnu-gcc")}
        with patch.object(suite.os, "getpid", return_value=77), \
                patch.object(suite, "pid_state", side_effect=[rows, rows]):
            self.assertEqual({r["pid"] for r in suite.foreign_load()}, {90, 91, 92})

    def test_new_ancestry_and_reused_pid_do_not_reject_our_window(self):
        first = {1: process(0, 1, "init"), 77: process(1, 2, "m6a_suite.py"),
                 90: process(0, 6, "dnsmasq"), 91: process(1, 7, "rustc")}
        second = {**first, 90: process(77, 6, "dnsmasq"),
                  91: process(1, 99, "sleep")}
        with patch.object(suite.os, "getpid", return_value=77), \
                patch.object(suite, "pid_state", side_effect=[first, second]):
            self.assertEqual(suite.foreign_load(), [])


class InterruptedCopy(unittest.TestCase):
    def test_half_copy_never_replaces_final_bytes_and_retry_is_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            final = Path(directory) / "archive.tar.gz"
            final.write_bytes(b"previous verified bytes")

            def broken(args, **kwargs):
                Path(args[-1]).write_bytes(b"half of new archive")
                raise subprocess.CalledProcessError(255, args, stderr="transport closed")

            with patch.object(watcher.subprocess, "run", side_effect=broken):
                with self.assertRaises(subprocess.CalledProcessError):
                    watcher.copy("oracle:/ignored/archive.tar.gz", final)
            self.assertEqual(final.read_bytes(), b"previous verified bytes")
            self.assertTrue(final.with_suffix(".gz.part").exists())

            def complete(args, **kwargs):
                Path(args[-1]).write_bytes(b"complete new archive")
                return subprocess.CompletedProcess(args, 0, "", "")

            with patch.object(watcher.subprocess, "run", side_effect=complete):
                watcher.copy("oracle:/ignored/archive.tar.gz", final)
            self.assertEqual(final.read_bytes(), b"complete new archive")
            self.assertFalse(final.with_suffix(".gz.part").exists())


class PilotContract(unittest.TestCase):
    def report(self):
        return {"measurement": {"load": {"measurement": {
            "correct": 100, "wrong": 0, "transport_error": 0, "timeout": 0}}},
            "behavior_checks": {"reload_publications": [
                {"publication_correct": True} for _ in range(3)],
                "tftp": {"correct": 100, "errors": 0},
                "dhcp_release_endstate": {"leasefile_empty": True}}}

    def test_flat_tftp_and_all_three_reload_events_are_required(self):
        profile = next(p for p in suite.PROFILES if p[0] == "reload-concurrent")
        report = self.report()
        self.assertTrue(suite.pilot_behavior(report, profile))
        report["behavior_checks"]["reload_publications"] = []
        self.assertFalse(suite.pilot_behavior(report, profile))
        report = self.report()
        report["behavior_checks"]["tftp"]["errors"] = 1
        self.assertFalse(suite.pilot_behavior(report, profile))

    def test_release_without_empty_server_endstate_is_not_a_pass(self):
        profile = next(p for p in suite.PROFILES if p[0] == "dhcp-lease")
        report = self.report()
        self.assertTrue(suite.pilot_behavior(report, profile))
        report["behavior_checks"]["dhcp_release_endstate"]["leasefile_empty"] = False
        self.assertFalse(suite.pilot_behavior(report, profile))

    def test_formal_profile_or_group_filter_is_rejected_before_io(self):
        for field in ("profile", "group"):
            args = SimpleNamespace(pilot_only=False, profile=None, group=None)
            setattr(args, field, ["one"])
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "cannot filter"):
                suite.run(args)


class ResumeContract(unittest.TestCase):
    def test_valid_measurement_with_bad_product_answers_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir()
            target = private / "target"
            target.mkdir()
            spec = {"root": str(root), "image_root": "/unused-image",
                    "protocol": str(root / "protocol"), "protocol_sha256": "frozen-protocol",
                    "groups": {"c": {"elf": "/unused-c", "sha256": suite.STOCK_SHA256},
                               "r3": {"elf": "/unused-r3", "sha256": suite.R3}},
                    "native": {name: {"path": "/unused-" + name}
                               for name in ("m6a_loadgen", "m6a_upstream")}}
            manifest = private / "manifest.json"
            suite.save(manifest, spec)
            state_path = private / "state.json"
            suite.save(state_path, {"manifest_sha256": suite.sha256(manifest), "windows": {},
                                    "formal_valid_windows": 0, "expected_windows": 135})

            def execute(argv, log, state, state_path):
                output = Path(argv[argv.index("--output") + 1])
                output.mkdir(parents=True)
                if "--preflight" in argv:
                    result = {"measurement_valid": True, "measurement": {"load": {
                        "measurement": {"correct": 100, "wrong": 0, "transport_error": 0, "timeout": 0}}}}
                else:
                    result = {"measurement_valid": True,
                              "behavior_checks": {"wrong_answers": 7, "timeouts": 3}}
                suite.save(output / "result.json", result)
                return {"returncode": 0}

            def archived(spec, attempt, record, state, state_path):
                record["archive"] = {"pruned": True, "local_verified": True}

            args = SimpleNamespace(manifest=manifest, pilot_only=False, profile=None, group=None)
            with patch.object(suite, "verify"), patch.object(suite, "foreign_load", return_value=[]), \
                    patch.object(suite, "execute", side_effect=execute), \
                    patch.object(suite, "archive_gate", side_effect=archived), \
                    patch.object(suite, "ORDERS", [("c",)]), \
                    patch.object(suite, "PROFILES", [suite.PROFILES[0]]), \
                    patch.object(suite, "TARGET", target), \
                    patch.object(suite.os, "sched_setaffinity", create=True), \
                    patch.dict(suite.os.environ):
                self.assertEqual(suite.run(args), 0)
            job = "r01-udp-hit-c"
            state = json.loads(state_path.read_text())
            result = json.loads((private / "runs" / job / "attempt-1/formal/result.json").read_text())
            self.assertEqual(state["windows"][job]["valid_attempt"], 1)
            self.assertEqual(state["formal_valid_windows"], 1)
            self.assertEqual(result["behavior_checks"]["wrong_answers"], 7)
            self.assertEqual(result["behavior_checks"]["timeouts"], 3)
            self.assertEqual(state["windows"][job]["attempts"][0]["failures"], [])

    def test_pending_gate_is_completed_before_any_new_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir()
            manifest = private / "manifest.json"
            suite.save(manifest, {"root": str(root)})
            job = "r01-udp-hit-c"
            record = {"job_id": job, "attempt": 1, "methodology_valid": True}
            state = {"manifest_sha256": suite.sha256(manifest),
                     "windows": {job: {"attempts": [record], "valid_attempt": None}},
                     "formal_valid_windows": 0, "expected_windows": 135,
                     "current_job": "stale-another-job", "current_attempt": 99,
                     "archive_gate": {"job_id": job, "attempt": 1}}
            state_path = private / "state.json"
            suite.save(state_path, state)
            received = []

            def finish(spec, attempt, active, resumed, path):
                received.append((attempt, active["job_id"], active["attempt"]))
                resumed.pop("archive_gate")

            args = SimpleNamespace(manifest=manifest, pilot_only=False, profile=None, group=None)
            with patch.object(suite, "verify"), patch.object(suite, "archive_gate", side_effect=finish), \
                    patch.object(suite, "ORDERS", []), \
                    patch.object(suite.os, "sched_setaffinity", create=True), \
                    patch.dict(suite.os.environ):
                self.assertEqual(suite.run(args), 0)
            final = json.loads(state_path.read_text())
            self.assertEqual(received, [(private / "runs" / job / "attempt-1", job, 1)])
            self.assertEqual(final["windows"][job]["valid_attempt"], 1)
            self.assertEqual(len(final["windows"][job]["attempts"]), 1)
            self.assertEqual(final["formal_valid_windows"], 1)
            self.assertEqual(final["status"], "partial-complete")

    def archive_case(self, root, pruned):
        private = root / "private"
        job = "r01-udp-hit-c"
        attempt = private / "runs" / job / "attempt-1"
        folder = private / "archives" / job / "attempt-1"
        attempt.mkdir(parents=True)
        folder.mkdir(parents=True)
        original = {"kind": "file", "mode": 0o644, "uid": 0, "gid": 0,
                    "mtime_ns": 123, "xattrs": {}, "sha256": "frozen-file"}
        inventory = {"formal/result.json": original}
        tar = folder / "archive.tar.gz"
        tar.write_bytes(b"already locally verified full archive")
        packed_sha = suite.sha256(tar)
        suite.save(folder / "manifest.json", {"entries": inventory})
        suite.save(folder / "local-verification.json", {
            "verified": True, "local_full_metadata_verified": True,
            "verifier_host": "separate-local-verifier", "archive_sha256": packed_sha,
            "manifest_sha256": suite.sha256(folder / "manifest.json")})
        record = {"job_id": job, "attempt": 1, "methodology_valid": True}
        state = {"archive_gate": {"job_id": job, "attempt": 1,
                 "run": str(attempt), "archive_folder": str(folder),
                 "archive_sha256": packed_sha}}
        if pruned:
            suite.save(folder / "prune.json", {"removed": str(attempt)})
            tar.unlink()
        return {"root": str(root)}, attempt, folder, record, state, inventory

    def test_already_pruned_gate_finishes_without_repeating_destructive_prune(self):
        with tempfile.TemporaryDirectory() as directory:
            spec, attempt, folder, record, state, inventory = self.archive_case(Path(directory), True)
            with patch.object(suite.archive, "inventory", return_value=inventory), \
                    patch.object(suite.archive, "prune") as prune:
                suite.archive_gate(spec, attempt, record, state, Path(directory) / "state.json")
            prune.assert_not_called()
            self.assertNotIn("archive_gate", state)
            self.assertTrue(record["archive"]["pruned"])

    def test_death_after_prune_before_gate_restore_recovers_from_verified_tar(self):
        with tempfile.TemporaryDirectory() as directory:
            spec, attempt, folder, record, state, inventory = self.archive_case(Path(directory), False)
            suite.save(folder / "prune-intent.json", {
                "run": str(attempt), "archive_sha256": state["archive_gate"]["archive_sha256"],
                "allocated_bytes": 0, "local_full_metadata_verified": True})
            shutil.rmtree(attempt)

            def extract(args, **kwargs):
                attempt.mkdir(parents=True, exist_ok=True)
                return subprocess.CompletedProcess(args, 0)

            def destructive_prune(run, manifest):
                if not run.exists():
                    raise ValueError("cannot prune a run already removed before interruption")
                raise AssertionError("an interrupted prune must not run twice")

            with patch.object(suite.archive, "inventory", return_value=inventory), \
                    patch.object(suite.archive, "prune", side_effect=destructive_prune), \
                    patch.object(suite.subprocess, "run", side_effect=extract):
                suite.archive_gate(spec, attempt, record, state, Path(directory) / "state.json")
            self.assertTrue((folder / "prune.json").exists())
            self.assertTrue(record["archive"]["pruned"])
            self.assertNotIn("archive_gate", state)

    def test_unarchived_changes_without_an_existing_prune_intent_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            spec, attempt, folder, record, state, inventory = self.archive_case(Path(directory), False)
            changed = {key: {**value, "sha256": "new unarchived bytes"}
                       for key, value in inventory.items()}
            with patch.object(suite.archive, "inventory", return_value=changed), \
                    patch.object(suite.archive, "assert_finished"), \
                    patch.object(suite.shutil, "rmtree", side_effect=AssertionError("unverified changes cannot be removed")):
                with self.assertRaisesRegex(ValueError, "changed|differs|match"):
                    suite.archive_gate(spec, attempt, record, state, Path(directory) / "state.json")
            self.assertTrue(attempt.exists())
            self.assertFalse((folder / "prune-intent.json").exists())


class ClassificationContract(unittest.TestCase):
    def test_generator_limit_does_not_hide_real_cpu_or_latency_regression(self):
        windows = []
        for number in range(1, 6):
            for group, scale in (("C", 1), ("R3", 1.2)):
                phase = {"phase": "steady", "qps": 100 * scale,
                         "cpu_us_per_correct": 100 * scale, "generator_limited": True,
                         "latency_ns": {"p50": 100 * scale, "p95": 100 * scale, "p99": None},
                         "origin_counts": {"correct": 100, "wrong": 0, "transport_error": 0, "timeout": 0},
                         "resources": {"sampled_tree_peaks": dict.fromkeys(analyze.RESOURCE_KEYS, 100)}}
                windows.append({"profile": "udp-hit", "group": group, "round": number,
                                "pilot": False, "methodology_valid": True, "phases": [phase]})
        rows = {r["metric"]: r for r in analyze.comparison_tables(windows, True)
                if r["comparison"] == "R3/C"}
        self.assertEqual(rows["qps"]["classification"], "受限")
        self.assertEqual(rows["cpu_us_per_correct"]["classification"], "变差")
        self.assertEqual(rows["p95_ns"]["classification"], "变差")


if __name__ == "__main__":
    unittest.main()
