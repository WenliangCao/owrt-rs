#!/usr/bin/env python3
"""Offline controls for the prepared no-traffic interface actor driver."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import m6b_interface_idle as gate


class InventoryGate(unittest.TestCase):
    def test_added_binding_must_be_observed_before_any_service_request(self):
        process = SimpleNamespace(pid=26, poll=lambda: None)
        expected = {('udp', 15353), ('tcp', 15353)}
        rows = [[], [{'address': '10.77.0.9', 'transport': 'udp', 'port': 15353},
                     {'address': '10.77.0.9', 'transport': 'tcp', 'port': 15353}]]
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate.fixture, 'inventory', side_effect=rows), patch.object(gate.time, 'sleep'):
                result = gate.wait_inventory(process, '10.77.0.9', expected, True, Path(directory), 'added')
            self.assertEqual(result['ports'], [('tcp', 15353), ('udp', 15353)])
            self.assertEqual(result['service_requests_sent'], 0)

    def test_same_address_wrong_port_or_persistent_removed_socket_does_not_pass(self):
        process = SimpleNamespace(pid=26, poll=lambda: None)
        for present, row in [(True, {'address': '10.77.0.9', 'transport': 'udp', 'port': 69}),
                              (False, {'address': '10.77.0.9', 'transport': 'udp', 'port': 15353})]:
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(gate.fixture, 'inventory', return_value=[row]), \
                        patch.object(gate.time, 'monotonic', side_effect=[0, 1]), self.assertRaises(TimeoutError):
                    gate.wait_inventory(process, '10.77.0.9', {('udp', 15353)}, present, Path(directory), 'failed', seconds=.5)
                self.assertTrue((Path(directory) / 'failed.json').exists())


if __name__ == '__main__': unittest.main()
