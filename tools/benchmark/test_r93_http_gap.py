#!/usr/bin/env python3
"""Local evidence-integrity and interval-accounting checks; no SSH."""
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from r93_http_gap import GAPS, derive, make_harness, proc_cpu, save, schedule, verify_download


class GapTests(unittest.TestCase):
    def test_schedule_has_four_three_side_rounds_at_each_gap(self):
        rows = schedule(4, 1000, 10000)
        self.assertEqual(len(rows), 60)
        self.assertEqual(len({r["name"] for r in rows}), 60)
        for gap in GAPS:
            for side in ("stock", "r89", "candidate"):
                group = [r for r in rows if r["side"] == side and r["gap_ms"] == gap]
                self.assertEqual({r["repeat"] for r in group}, {1, 2, 3, 4})
                self.assertTrue(all(r["iterations"] == (10000 if gap == 0 else 1000) for r in group))

    def test_harness_keeps_namespace_setup_and_is_valid_shell(self):
        base = Path(__file__).with_name("isolated.sh").read_text()
        for fixture in ("512", "16384", "image-css"):
            with self.subTest(fixture=fixture), tempfile.TemporaryDirectory() as tmp:
                text = make_harness(base, fixture, 530)
                file = Path(tmp) / "harness.sh"
                file.write_text(text)
                subprocess.run(["sh", "-n", str(file)], check=True)
                self.assertIn('"$bundle/ns-exec" /bin/sh "$script" --namespace', text)
                self.assertIn('mount -o remount,bind,ro "$root"', text)
                self.assertIn('sleep 530', text)
                self.assertIn('kill -KILL "$gap_owner"', text)
                self.assertNotIn('/bin/busybox timeout', text)
                self.assertEqual(text.count('> "$out/outer-before.json"'), 1)
                self.assertEqual(text.count('> "$out/outer-after.json"'), 1)
                if fixture == "image-css":
                    self.assertIn('http-paced 127.0.0.1:18080 /static.css /tmp/www/static.css', text)

    def test_changed_harness_cannot_silently_skip_instrumentation(self):
        with self.assertRaisesRegex(RuntimeError, "interface changed"):
            make_harness("unrecognized harness", "512", 530)

    def test_watchdog_kills_only_its_captured_command_after_exec(self):
        base = Path(__file__).with_name("isolated.sh").read_text()
        text = make_harness(base, "512", 530)
        snippet = re.search(r'    gap_owner=\$\$\n.*?    \) &', text, re.S).group()
        # The owned shell execs sleep in place, just as the namespace shell
        # execs chroot. No inherited PID, process group or PID 1 is targeted.
        script = "set -eu\n" + snippet.replace("sleep 530", "sleep 0.05") + "\nexec sleep 30\n"
        run = subprocess.run(["sh", "-c", script], capture_output=True, timeout=2)
        self.assertEqual(run.returncode, -9)
        self.assertIn(b"namespace deadline expired", run.stderr)

    def test_cpu_rejects_replaced_process_and_regressed_counters(self):
        before = {"pid": 1, "start_ticks": 10, "cpu_ticks": 20, "child_cpu_ticks": 2}
        after = {**before, "cpu_ticks": 24, "child_cpu_ticks": 3}
        self.assertAlmostEqual(proc_cpu(before, after, 100)["total_s"], .05)
        for change in ({"start_ticks": 11}, {"cpu_ticks": 19}, {"child_cpu_ticks": 1}):
            with self.assertRaises(RuntimeError):
                proc_cpu(before, {**after, **change}, 100)

    def test_archive_verification_requires_exact_file_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one").write_bytes(b"one")
            checksums = (hashlib.sha256(b"one").hexdigest() + "  ./one\n").encode()
            verify_download(root, checksums)
            (root / "unexpected").write_bytes(b"two")
            with self.assertRaisesRegex(RuntimeError, "file set"):
                verify_download(root, checksums)
            with self.assertRaisesRegex(RuntimeError, "checksum"):
                verify_download(root, checksums.replace(b"./one", b"../one"))

    def test_derive_uses_one_outer_interval_and_rejects_failed_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp)
            run = {"name": "sample", "side": "candidate", "gap_ms": 80, "iterations": 4, "repeat": 1}
            settings = {"subjects": {"candidate": "candidate"}, "harness_sha256": "harness",
                        "diagnostic_sha256": "diag", "boot_id": "boot", "clients": 2,
                        "dependencies": {"rpcd": "rpc", "ubusd": "bus"},
                        "tools": {"ns-exec": "ns", "owrt-benchmark": "bench"},
                        "fixture_sha256": "fixture", "fixture_bytes": 512}
            for name, content in {"COMPLETE": "", "binary-sha256.txt": "candidate file",
                "subject-sha256.txt": "candidate file", "harness-sha256.txt": "harness file",
                "diagnostic-sha256.txt": "diag file", "boot-id.txt": "boot",
                "dependencies-sha256.txt": "rpc /proc/2/exe\nbus /proc/3/exe\n",
                "benchmark-sha256.txt": "ns /tmp/ns-exec\nbench /tmp/owrt-benchmark\n",
                "fixture-sha256.txt": "fixture file", "fixture-bytes.txt": "512"}.items():
                (raw / name).write_text(content)
            save(raw / "meta.json", {"component": "httpd", "dependencies": "original OpenWrt",
                                    "subject_pid": 1, "iterations": 4})
            save(raw / "roles.json", {"httpd": 1, "rpcd": 2, "ubusd": 3})

            def sample(pid, cpu):
                return {"pid": pid, "start_ticks": 100, "cpu_ticks": cpu, "child_cpu_ticks": 0,
                        "VmRSS": 20, "RssAnon": 10, "RssFile": 10, "VmHWM": 20, "fds": 3, "Threads": 1}

            for file, ticks in (("outer-before", (0, 0, 0)), ("outer-after", (10, 3, 2)),
                                ("idle-1s", (10, 3, 2)), ("idle-2s", (10, 3, 2))):
                save(raw / (file + ".json"), {"uptime_s": 1 if file == "outer-before" else 2,
                      "clock_ticks_per_second": 100,
                      "processes": [sample(pid, n) for pid, n in zip((1, 2, 3), ticks)]})
            data = {"diagnostic_only": True, "errors": 0, "successful": 4, "clients": 2, "gap_ms": 80,
                    "latency_ns": [1000, 2000, 3000, 4000], "wall_ns": 160010000, "ticks_per_second": 100,
                    "before": sample(1, 2), "after": sample(1, 10),
                    "thread_births_observed_lower_bound": 1, "observer_interval_ms": 2}
            save(raw / "paced.json", data)
            row = derive(raw, run, settings)
            self.assertAlmostEqual(row["subject_measured_cpu"]["total_s"], .08)
            self.assertAlmostEqual(row["outer_including_warmup"]["all_daemons_cpu_s"], .15)
            self.assertEqual(row["outer_including_warmup"]["successful"], 6)
            self.assertAlmostEqual(row["outer_including_warmup"]["us_per_request"], 25000)
            self.assertEqual(row["latency_us"]["p95"], 4)
            for change in ({"errors": 1}, {"successful": 3}, {"clients": 1},
                           {"ticks_per_second": 1000}, {"wall_ns": 1000000},
                           {"wall_ns": 1100000000}, {"after": sample(1, 11)},
                           {"after": {**sample(1, 10), "child_cpu_ticks": 1}}):
                save(raw / "paced.json", {**data, **change})
                with self.assertRaises(RuntimeError):
                    derive(raw, run, settings)
            save(raw / "paced.json", data)
            (raw / "subject-sha256.txt").write_text("wrong file")
            with self.assertRaisesRegex(RuntimeError, "subject checksum"):
                derive(raw, run, settings)


if __name__ == "__main__":
    unittest.main()
