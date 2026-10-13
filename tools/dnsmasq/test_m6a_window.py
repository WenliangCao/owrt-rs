#!/usr/bin/env python3
"""Fixture negative controls; actual rootfs qualification uses Linux pilots."""
import json
import io
from pathlib import Path
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import m6a_window as window
from dns_service_probe import query


class MeasurementCorrections(unittest.TestCase):
    def test_drain_requires_stable_idle_fd_and_no_children(self):
        rows = [
            {"tree": {"fd_count": 11, "child_processes": 0}},
            {"tree": {"fd_count": 10, "child_processes": 1}},
            {"tree": {"fd_count": 10, "child_processes": 0}},
            {"tree": {"fd_count": 10, "child_processes": 0}},
        ]
        with patch.object(window, "process_tree", side_effect=rows):
            result = window.wait_for_drain(123, 10, timeout=1, stable_samples=2, interval=0)
        self.assertEqual(result["idle_fd_count"], 10)
        self.assertEqual(result["observations"][-1]["stable_samples"], 2)
        self.assertEqual(len(result["observations"]), 4)

    def test_fixed_drain_sample_offsets(self):
        self.assertEqual(window.parse_drain_sample_seconds(None), (0.0, 1.0, 5.0, 60.0))
        with self.assertRaises(ValueError):
            window.parse_drain_sample_seconds("1,5,60")
        with self.assertRaises(ValueError):
            window.parse_drain_sample_seconds("0,5,1")

    def test_idle_cpu_disabled_still_writes_explicit_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result = window.measure_idle_cpu(123, Path(directory), 0)
            self.assertFalse(result["enabled"])
            self.assertEqual(json.loads((Path(directory) / "idle-cpu.json").read_text()), result)

    def test_wake_telemetry_jsonl_is_normalized_and_summarized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wake.jsonl"
            path.write_text(json.dumps({"loop_rounds": 12, "poll_calls": 4,
                                        "poll_wait_ns": 800, "wait_durations_ns": [100, 700],
                                        "wait_reasons": {"network": 2, "timer": 1},
                                        "udp_listeners": {"dns": {"steps": 3, "packets": 2}}}) + "\n")
            first = window.read_wake_telemetry(path)
            path.write_text(path.read_text() + json.dumps({"loop_rounds": 22, "poll_calls": 9,
                                                             "poll_wait_ns": 1900,
                                                             "wait_reasons": {"network": 7, "timer": 2},
                                                             "wait_durations_ns": [200, 600, 800]}) + "\n")
            second = window.read_wake_telemetry(path)
        self.assertEqual(first["loop_rounds"], 12)
        summary = window.summarize_wake_telemetry([
            {"observed_monotonic_ns": 1_000_000_000, "counters": first},
            {"observed_monotonic_ns": 2_000_000_000, "counters": second},
        ])
        self.assertEqual(summary["intervals"][0]["loop_rounds_per_second"], 10.0)
        self.assertEqual(summary["intervals"][0]["poll_calls"], 5)
        self.assertEqual(summary["intervals"][0]["poll_wait_ns"], 1100)
        self.assertEqual(summary["intervals"][0]["poll_wait_stats_ns"]["p95_ns"], 800)
        self.assertEqual(summary["intervals"][0]["wait_reasons"], {"network": 5, "timer": 1})


class DiagnosticOptions(unittest.TestCase):
    def parse_options(self, extra):
        argv = ["m6a_window.py", "--scenario", "tcp", "--implementation", "rs",
                "--rust", "/unused/elf", "--image-root", "/unused/image",
                "--loadgen", "/unused/loadgen", "--upstream", "/unused/upstream",
                "--output", "/unused/output", *extra]
        with patch.object(window.sys, "argv", argv), patch.object(window, "run_window", return_value=0) as run:
            self.assertEqual(window.main(), 0)
            return run.call_args.args[0]

    def test_defaults_and_explicit_cpu_clock_record_exact_command_and_metadata(self):
        for extra, expected, event_args, graph_args in [
            ([], {"event": "cycles", "frequency_hz": 997, "call_graph": "dwarf"},
             [], ["--call-graph", "dwarf"]),
            (["--perf-event", "cpu-clock", "--perf-call-graph", "none", "--duration", "300"],
             {"event": "cpu-clock", "frequency_hz": 997, "call_graph": "none"},
             ["-e", "cpu-clock"], []),
        ]:
            args = self.parse_options(["--preflight", "--perf-record", *extra])
            self.assertEqual(window.perf_settings(args), expected)
            with tempfile.TemporaryDirectory() as directory:
                args.output = Path(directory)
                process = SimpleNamespace(poll=lambda: None, send_signal=lambda _: None,
                                          wait=lambda _: 0, returncode=0)
                capture = window.DiagnosticCapture(args, 123)
                with patch.object(window.subprocess, "Popen", return_value=process) as launch, \
                        patch.object(window.time, "sleep"):
                    capture.start()
                    command = ["taskset", "-c", "3", "perf", "record", "-F", "997",
                               *event_args, *graph_args, "-p", "123", "-o", str(args.output / "perf.data")]
                    self.assertEqual(launch.call_args.args[0], command)
                    self.assertEqual(json.loads((args.output / "perf-command.json").read_text()), command)
                    capture.stop()
                self.assertEqual(json.loads((args.output / "diagnostic-scope.json").read_text())["perf_settings"], expected)

    def test_tracing_remains_diagnostic_only_and_options_need_recording(self):
        for extra in (["--perf-record"], ["--preflight", "--perf-event", "cpu-clock"],
                      ["--preflight", "--perf-call-graph", "none"]):
            with self.subTest(extra=extra), patch.object(window.sys, "stderr", io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    self.parse_options(extra)
                self.assertEqual(error.exception.code, 2)
        args = self.parse_options(["--preflight"])
        self.assertIsNone(window.perf_settings(args))


class FrozenInputs(unittest.TestCase):
    def test_mixed_bank_counts_and_cname_labels(self):
        counts = {"a": 0, "aaaa": 0, "cname": 0, "txt": 0}
        for index in range(256):
            host, kind = window.bank_question(index, True)
            key = "cname" if host.startswith("cname-") else {1: "a", 28: "aaaa", 16: "txt"}[kind]
            counts[key] += 1
            reply = window.answer(query(host, kind, index))
            self.assertTrue(window.correct_answer(host, kind, index, reply))
        self.assertEqual(counts, {"a": 130, "aaaa": 65, "cname": 37, "txt": 24})

    def test_negative_controls_wrong_id_address_ttl_and_question(self):
        host = "q0000.m6a.test"
        original = window.answer(query(host, ident=17))
        for changed in (original[:1] + b"\x12" + original[2:],
                        original[:-1] + b"\x02",
                        original + b"trailing",
                        original[:2] + bytes([original[2] | 2]) + original[3:],
                        original[:12] + b"\x05other" + original[18:]):
            try:
                valid = window.correct_answer(host, 1, 17, changed)
            except (ValueError, IndexError, struct.error):
                valid = False
            self.assertFalse(valid)
        zero_ttl = bytearray(original)
        _, end = window.read_name(original, 12)
        struct.pack_into("!I", zero_ttl, end + 4 + 6, 0)
        self.assertFalse(window.correct_answer(host, 1, 17, bytes(zero_ttl)))

    def test_reload_probe_rejects_wrong_class_owner_section_and_tc(self):
        host = "reload-proof.m6a.test"
        original = window.answer(query(host, ident=23))[:-1] + b"\x0b"
        self.assertTrue(window.correct_reload_reply(original, 23, "192.0.2.11"))
        _, question_end = window.read_name(original, 12)
        answer_start = question_end + 4
        wrong_class = bytearray(original)
        struct.pack_into("!H", wrong_class, answer_start + 4, 3)
        wrong_section = bytearray(original)
        struct.pack_into("!HH", wrong_section, 6, 0, 1)
        wrong_owner = original[:answer_start] + window.name("other.m6a.test") + original[answer_start + 2:]
        for changed in (bytes(wrong_class), bytes(wrong_section), wrong_owner,
                        original[:2] + bytes([original[2] | 2]) + original[3:],
                        original + b"trailing"):
            self.assertFalse(window.correct_reload_reply(changed, 23, "192.0.2.11"))

    def test_common_config_and_fixed_dhcp_identities(self):
        for scenario in ("hit", "miss", "mixed", "fault", "tcp", "dhcp", "reload"):
            config = window.config_for(scenario)
            for line in ("cache-size=4096", "local-ttl=3600", "dns-forward-max=1024",
                         "cache-rr=TXT", "no-poll", "no-0x20-encode", "group=root"):
                self.assertIn(line + "\n", config)
        dhcp = window.config_for("dhcp")
        self.assertIn("127.255.255.255,3600s\n", dhcp)
        self.assertEqual(dhcp.count("dhcp-host="), 20)
        self.assertIn("dhcp-host=02:00:00:6a:00:13,127.0.0.29\n", dhcp)

    def test_tcp_local_does_not_need_an_upstream_answer(self):
        config = window.config_for("tcp", "local")
        self.assertIn("address=/localbank.m6a.test/192.0.2.1\n", config)

    def test_epoch_boundaries_are_immutable(self):
        epoch = {"measurement_start_ns": 2_000_000_000, "measurement_end_ns": 122_000_000_000}
        args = SimpleNamespace(scenario="hit", saturation_seconds=30)
        self.assertEqual(window.boundaries_for(args, epoch), [
            ("measurement-start", 2_000_000_000), ("saturation-start", 92_000_000_000),
            ("measurement-end", 122_000_000_000)])
        args = SimpleNamespace(scenario="fault", saturation_seconds=0, fault_start=30, fault_end=60)
        self.assertEqual(window.boundaries_for(args, epoch), [
            ("measurement-start", 2_000_000_000), ("fault-start", 32_000_000_000),
            ("fault-end", 62_000_000_000), ("measurement-end", 122_000_000_000)])

    def test_cgroup_is_required_and_does_not_silently_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(window, "CGROUP_PATH", root):
                (root / "cpu.stat").write_text("usage_usec 150\nuser_usec 100\nsystem_usec 50\n")
                value = window.cgroup_cpu()
                self.assertEqual(value["usage_usec"], 150)
                (root / "cpu.stat").write_text("user_usec 100\nsystem_usec 50\n")
                with self.assertRaisesRegex(RuntimeError, "usage_usec"):
                    window.cgroup_cpu()

    def test_evidence_save_preserves_actual_newlines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "value.json"
            window.save(path, {"value": "a\nb"})
            self.assertEqual(json.loads(path.read_text()), {"value": "a\nb"})
            self.assertFalse(path.with_suffix(".json.new").exists())

    def test_tftp_worker_validates_full_file_and_terminal_empty_block(self):
        class Endpoint:
            def __init__(self):
                payload = bytes(range(256)) * 4
                self.packets = [struct.pack("!HH", 3, 1) + payload[:512],
                                struct.pack("!HH", 3, 2) + payload[512:],
                                struct.pack("!HH", 3, 3)]
                self.sent = []

            def settimeout(self, _timeout):
                pass

            def sendto(self, packet, peer):
                self.sent.append((packet, peer))

            def recvfrom(self, _size):
                return self.packets.pop(0), ("127.0.0.1", 12345)

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            now = time.monotonic_ns()
            window.save(output / "epoch.json", {"warmup_start_ns": now - 1_000_000,
                                                 "measurement_start_ns": now - 1_000_000,
                                                 "measurement_end_ns": now + 20_000_000})
            endpoint = Endpoint()
            args = SimpleNamespace(output=output, cpu_load=2, timeout_ms=1000)
            with patch.object(window.os, "sched_setaffinity", create=True), patch.object(window.socket, "socket", return_value=endpoint):
                self.assertEqual(window.tftp_worker(args), 0)
            value = json.loads((output / "tftp.json").read_text())
            self.assertEqual(value["correct"], 1)
            self.assertEqual(value["errors"], 0)
            row = json.loads((output / "tftp-transfers.jsonl").read_text())
            self.assertEqual(len(row["wire"]), 3)
            self.assertEqual(endpoint.sent[-1], (struct.pack("!HH", 4, 3), ("127.0.0.1", 12345)))


if __name__ == "__main__":
    unittest.main()
