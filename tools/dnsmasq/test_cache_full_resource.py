#!/usr/bin/env python3
"""Proof rejection and forced cleanup tests; no DNS service is started."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cache_full_resource import (CAPACITY, NAMES, Fixture, clean, occupancy_proof,
                                 query, require_binary_identity, summary,
                                 upstream_answer, valid_reply, RESOURCE_KEYS)


class OccupancyProofTests(unittest.TestCase):
    def rows(self):
        return [{"name": name, "hit": True} for name in NAMES]

    def test_names_are_fixed_unique_short_names(self):
        self.assertEqual(len(set(NAMES)), CAPACITY)
        self.assertEqual({len(name) for name in NAMES}, {16})

    def test_every_name_without_upstream_proves_full_cache(self):
        proof = occupancy_proof(self.rows(), 0)
        self.assertTrue(proof["accepted"])
        self.assertEqual(proof["live_dynamic_a_entries"], CAPACITY)

    def test_missing_one_with_forwarding_rejects_occupancy(self):
        rows = self.rows()
        rows[-1]["hit"] = False
        proof = occupancy_proof(rows, 1)
        self.assertFalse(proof["accepted"])
        self.assertIsNone(proof["live_dynamic_a_entries"])
        self.assertEqual(proof["unique_correct_hits"], CAPACITY - 1)

    def test_duplicate_hit_does_not_replace_missing_name(self):
        rows = self.rows()
        rows[-1] = dict(rows[0])
        self.assertFalse(occupancy_proof(rows, 0)["accepted"])

    def test_forwarded_query_disqualifies_otherwise_complete_proof(self):
        self.assertFalse(occupancy_proof(self.rows(), 1)["accepted"])

    def test_insert_count_is_not_a_supported_proof(self):
        self.assertFalse(occupancy_proof([], 0)["accepted"])

    def test_running_binary_mismatch_is_rejected(self):
        with self.assertRaises(AssertionError):
            require_binary_identity({"sha256": "old-elf"}, "final-elf")
        require_binary_identity({"sha256": "final-elf"}, "final-elf")

    def test_resource_growth_is_reported_without_an_automatic_verdict(self):
        rows = [{key: value for key in RESOURCE_KEYS} for value in range(8)]
        report = summary(rows)
        self.assertEqual(report["rss_kib"]["q4_minus_q3"], 2)
        self.assertNotIn("accepted", report)

    def test_reply_requires_correct_id_name_address_and_positive_ttl(self):
        host = NAMES[32]
        packet = upstream_answer(query(host, ident=7))
        self.assertTrue(valid_reply(host, 7, packet))
        self.assertFalse(valid_reply(host, 8, packet))
        self.assertFalse(valid_reply(NAMES[33], 7, packet))
        wrong_address = packet[:-1] + bytes([packet[-1] ^ 1])
        self.assertFalse(valid_reply(host, 7, wrong_address))
        # Last A RR consists of TTL (4), RDLENGTH (2), IPv4 (4).
        expired = packet[:-10] + bytes(4) + packet[-6:]
        self.assertFalse(valid_reply(host, 7, expired))


class CleanupTests(unittest.TestCase):
    def test_forced_stop_reaps_child_and_records_runner_pid_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = object.__new__(Fixture)
            fixture.out = Path(temporary)
            fixture.pidfile = fixture.out / "pid"
            fixture.upstream = fixture.client = fixture.log = fixture.wire = None
            fixture.process = subprocess.Popen(
                [sys.executable, "-u", "-c",
                 "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(30)"],
                stdout=subprocess.PIPE)
            try:
                self.assertEqual(fixture.process.stdout.readline().strip(), b"ready")
                fixture.pidfile.write_text(str(fixture.process.pid))
                result = fixture.close()
                self.assertTrue(result["forced_kill"])
                self.assertTrue(result["pid_file_before_runner_cleanup"])
                self.assertFalse(result["daemon_alive_after_stop"])
                self.assertFalse(fixture.pidfile.exists())
                self.assertIsNotNone(fixture.process.poll())
                self.assertFalse(clean(result))
            finally:
                if fixture.process.poll() is None:
                    fixture.process.kill()
                    fixture.process.wait()
                fixture.process.stdout.close()


if __name__ == "__main__":
    unittest.main()
