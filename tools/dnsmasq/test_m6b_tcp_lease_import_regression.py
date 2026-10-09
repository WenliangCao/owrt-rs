#!/usr/bin/env python3
"""Pair comparer rejects wrong new-view answers and changed held order."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import m6b_tcp_lease_import_regression as gate


def run_record():
    reply = {'records': [{'section': 'answer', 'type': 1, 'data': '192.0.2.42', 'ttl': 120}]}
    observation = dict(label='warm-latest-view', query={'questions': [['leaseold.cache.test', 1, 1]]},
                       reply=reply, transport='tcp', ttl_ceiling=120)
    upstream = dict(transport='tcp', release=True, query={'questions': []}, reply={'records': []})
    return {'tools': {'same': 'sha'}}, {'observations': [observation]}, [upstream], {'same': 'image'}


class PairRejection(unittest.TestCase):
    def test_wrong_new_view_address_is_rejected(self):
        c = run_record()
        rust = copy.deepcopy(c)
        rust[1]['observations'][0]['reply']['records'][0]['data'] = '198.51.100.7'
        with tempfile.TemporaryDirectory() as root, patch.object(gate, 'read_run', side_effect=[c, rust]):
            with self.assertRaises(ValueError):
                gate.compare(SimpleNamespace(out=Path(root) / 'result.json'))

    def test_upstream_release_order_must_match_image_c(self):
        c = run_record()
        rust = copy.deepcopy(c)
        rust[2][0]['release'] = False
        with tempfile.TemporaryDirectory() as root, patch.object(gate, 'read_run', side_effect=[c, rust]):
            with self.assertRaises(ValueError):
                gate.compare(SimpleNamespace(out=Path(root) / 'result.json'))

    def test_lease_ttl_ceiling_is_not_normalized_away(self):
        c = run_record()
        rust = copy.deepcopy(c)
        rust[1]['observations'][0]['reply']['records'][0]['ttl'] = 600
        with tempfile.TemporaryDirectory() as root, patch.object(gate, 'read_run', side_effect=[c, rust]):
            with self.assertRaises(ValueError):
                gate.compare(SimpleNamespace(out=Path(root) / 'result.json'))

    def test_existing_result_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / 'result.json'
            out.write_text('original failed result')
            with self.assertRaises(ValueError):
                gate.compare(SimpleNamespace(out=out))
            self.assertEqual(out.read_text(), 'original failed result')


if __name__ == '__main__':
    unittest.main()
