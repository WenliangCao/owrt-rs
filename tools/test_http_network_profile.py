#!/usr/bin/env python3
"""Offline checks for the metrics used by the offload decision."""
import json
import subprocess
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from http_network_profile import (curl_probes, distribution, mac_counters, selected_probes,
                                  shell_sampler, summarize_samples)


def sample(at, uptime, user, idle, rx, tx):
    return {"at_s": at, "raw": f"""@@uptime
{uptime} 0.0
@@stat
cpu {user * 2} 0 0 {idle * 2} 0 0 0 0
cpu0 {user} 0 0 {idle} 0 0 0 0
cpu1 {user} 0 0 {idle} 0 0 0 0
@@netdev
eth1: {rx} 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0
@@softirqs
 CPU0 CPU1
 NET_RX: {rx} {rx}
@@matching_conntrack
ipv4 2 tcp 6 100 ESTABLISHED src=192.0.2.1 dst=198.51.100.1 sport=45123 dport=443 packets=2 bytes=10 [HW_OFFLOAD] src=198.51.100.1 dst=192.0.2.1 sport=443 dport=45123
"""}


class Measurements(unittest.TestCase):
    def test_curl_probes_pin_path_and_preserve_failures(self):
        for code, actual_ip, success in ((0, "198.51.100.1", True),
                                        (28, "198.51.100.1", False),
                                        (0, "127.0.0.1", False)):
            with self.subTest(code=code, actual_ip=actual_ip):
                stop = threading.Event()
                data = {"http_code": 200, "time_connect": .01, "time_total": .03,
                        "remote_ip": actual_ip, "local_ip": "192.0.2.1", "local_port": 45678}
                def run(command, **kwargs):
                    stop.set()
                    self.assertEqual(command[0], "/usr/bin/curl")
                    self.assertIn("test.example:443:198.51.100.1", command)
                    self.assertIn("https://test.example/small", command)
                    return subprocess.CompletedProcess(command, code, json.dumps(data),
                                                       "request timeout" if code else "")
                with patch('subprocess.run', side_effect=run):
                    rows = curl_probes("https://test.example/small", "198.51.100.1",
                                       "en0", "192.0.2.1", 5, stop)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["time_connect_ms"], 10)
                self.assertEqual(rows[0]["time_total_ms"], 30)
                self.assertEqual(rows[0]["local_port"], 45678)
                self.assertEqual("ms" in rows[0], success)
                self.assertEqual("error" in rows[0], not success)

    def test_probe_path_defaults_and_split_do_not_change_load_path(self):
        args = SimpleNamespace(interface="en0", source_ip="192.0.2.1", probe_mode="curl",
                               probe_url="https://test.example/small")
        with patch("http_network_profile.curl_probes", return_value=[]) as probe:
            selected_probes(args, "endpoint", "198.51.100.1", 443, 5)
            probe.assert_called_once_with(args.probe_url, "198.51.100.1", "en0", "192.0.2.1", 5, None)
        args.probe_interface, args.probe_source_ip = "en5", "192.0.2.2"
        with patch("http_network_profile.curl_probes", return_value=[]) as probe:
            selected_probes(args, "router", "192.0.2.254", 80, 5)
            probe.assert_called_once_with("http://192.0.2.254/", "192.0.2.254", "en5", "192.0.2.2", 5, None)
        self.assertEqual((args.interface, args.source_ip), ("en0", "192.0.2.1"))

    def test_split_conntrack_preserves_source_identity(self):
        script = shell_sampler("192.0.2.1", "198.51.100.1", 5, "192.0.2.2")
        self.assertIn("src=192.0.2.1 dst=198.51.100.1", script)
        self.assertIn("src=192.0.2.2 dst=198.51.100.1", script)
        rows = [sample(1, 100, 0, 500, 10, 20), sample(3, 102, 100, 600, 30, 40)]
        rows[1]["raw"] += ("ipv4 2 tcp 6 100 ESTABLISHED src=192.0.2.2 dst=198.51.100.1 "
                           "sport=45124 dport=443 packets=2 bytes=10\n")
        result = summarize_samples(rows, 0, 4)
        self.assertEqual(result["direct_source_ports_by_ip"], {"192.0.2.1": [45123], "192.0.2.2": [45124]})

    def test_interior_window_cpu_and_counters(self):
        rows = [sample(0, 99, 0, 500, 5, 10),
                sample(1, 100, 0, 500, 10, 20),
                sample(3.5, 102.5, 100, 650, 30, 50),
                sample(5, 104, 10000, 650, 9000, 9000)]
        result = summarize_samples(rows, .5, 4)
        self.assertEqual(result['sample_count'], 2)
        self.assertEqual(result['interval_s'], 2.5)
        self.assertEqual(result['cpu']['cpu']['busy_pct'], 40)
        self.assertEqual(result['busy_cpu_seconds'], 2)
        self.assertEqual(result['netdev_delta']['eth1'], {'rx_bytes': 20, 'tx_bytes': 30})
        self.assertEqual(result['direct_source_ports'], [45123])
        self.assertEqual(result['hardware_flow_samples'], 2)
        self.assertEqual(result['softirq_delta']['NET_RX'], [20, 20])
        self.assertEqual(result['dropped_trailing_sampler_records'], 0)

    def test_sampler_close_drops_only_incomplete_last_record(self):
        rows = [sample(0, 99, 0, 500, 5, 10),
                sample(1, 100, 0, 500, 10, 20),
                sample(3.5, 102.5, 100, 650, 30, 50)]
        expected = summarize_samples(rows, .5, 4)
        # Actual shutdown boundary: @@sample arrived, then only @@uptime.
        tail = {"at_s": 3.8, "raw": "@@uptime\n"}
        result = summarize_samples(rows + [tail], .5, 4)
        expected["dropped_trailing_sampler_records"] = 1
        self.assertEqual(result, expected)
        self.assertEqual(tail["raw"], "@@uptime\n")

    def test_incomplete_interior_sample_is_rejected(self):
        rows = [sample(1, 100, 0, 500, 10, 20),
                {"at_s": 2, "raw": "@@uptime\n"},
                sample(3.5, 102.5, 100, 650, 30, 50)]
        with self.assertRaisesRegex(RuntimeError, "incomplete router sample at index 1"):
            summarize_samples(rows, .5, 4)

    def test_missing_section_in_final_record_is_not_a_truncated_tail(self):
        rows = [sample(1, 100, 0, 500, 10, 20),
                sample(3.5, 102.5, 100, 650, 30, 50)]
        rows[-1]["raw"] = rows[-1]["raw"].replace("@@netdev\n", "")
        with self.assertRaisesRegex(RuntimeError, "incomplete router sample at index 1"):
            summarize_samples(rows, .5, 4)

    def test_malformed_final_record_is_not_a_truncated_tail(self):
        rows = [sample(1, 100, 0, 500, 10, 20),
                sample(3.5, 102.5, 100, 650, 30, 50),
                {"at_s": 3.8, "raw": "invalid output\n"}]
        with self.assertRaisesRegex(RuntimeError, "incomplete router sample at index 2"):
            summarize_samples(rows, .5, 4)

    def test_latency_failures_not_silently_dropped(self):
        result = distribution([{'ms': 1}, {'error': 'timeout'}, {'ms': 10}])
        self.assertEqual(result['failures'], 1)
        self.assertEqual(result['p50_ms'], 5.5)
        self.assertEqual(result['p95_ms'], 10)
        self.assertIsNone(distribution([{'error': 'timeout'}])['p95_ms'])

    def test_mac_interface_duplicates_and_missing_link_address(self):
        raw = '''Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
en0 1500 <Link#1> aa:bb:cc:dd:ee:ff 100 0 1234 20 0 5678 0
en0 1500 192.0.2 192.0.2.1 100 - 1234 20 - 5678 -
utun7 1380 <Link#2> 0 0 100 0 0 200 0
en5 1500 <Link#3> aa:bb:cc:dd:ee:01 2 0 700 3 0 800 0
en5* 1500 192.0.2 192.0.2.2 2 - 700 3 - 800 -
'''
        with patch('subprocess.check_output', return_value=raw):
            self.assertEqual(mac_counters()['counters'], {
                'en0': {'rx_bytes': 1234, 'tx_bytes': 5678},
                'utun7': {'rx_bytes': 100, 'tx_bytes': 200}})
            self.assertEqual(mac_counters({"en0", "en5"})['counters'], {
                'en0': {'rx_bytes': 1234, 'tx_bytes': 5678},
                'en5': {'rx_bytes': 700, 'tx_bytes': 800},
                'utun7': {'rx_bytes': 100, 'tx_bytes': 200}})


if __name__ == '__main__':
    unittest.main()
