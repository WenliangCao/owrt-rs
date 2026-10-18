#!/usr/bin/env python3
"""Offline checks for the metrics used by the offload decision."""
import unittest
from unittest.mock import patch

from http_network_profile import distribution, mac_counters, summarize_samples


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
'''
        with patch('subprocess.check_output', return_value=raw):
            self.assertEqual(mac_counters()['counters'], {
                'en0': {'rx_bytes': 1234, 'tx_bytes': 5678},
                'utun7': {'rx_bytes': 100, 'tx_bytes': 200}})


if __name__ == '__main__':
    unittest.main()
