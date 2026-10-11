"""Calibrate both DHCP helper probes' narrow random-timer comparison."""
import ast
import json
from copy import deepcopy
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROBES = [ROOT / 'tools/dnsmasq/audit_fix_20261011_dhcp_helper.py',
          ROOT / 'docs/dnsmasq/audits/20261011/independent/dhcp_handoff_helper.py']


def normalizers():
    for path in PROBES:
        # The historical standalone probe parses argv at import time. Extract
        # only its pure comparison function without starting any daemon.
        tree = ast.parse(path.read_text(), filename=str(path))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == 'normalize_renewal_timers')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
        yield path.name, namespace['normalize_renewal_timers']


def sample(lease=3600, fuzz=171):
    event = dict(kind=3, wanted=False, server=None, ciaddr='127.0.0.30', lease_time=lease)
    values = {'51': lease, '58': lease // 2 - fuzz, '59': lease * 7 // 8 - fuzz}
    reply = dict(message_type=5, hostname='dual', options={
        **{key: value.to_bytes(4, 'big').hex() for key, value in values.items()},
        '53': '05', '12': '6475616c'})
    return event, reply


class RenewalTimers(unittest.TestCase):
    def test_valid_bounds_and_only_timers_change(self):
        for name, normalize in normalizers():
            for lease in [3600, 1800]:
                for fuzz in [0, 1, lease // 16]:
                    with self.subTest(probe=name, lease=lease, fuzz=fuzz):
                        event, reply = sample(lease, fuzz)
                        expected = sample(lease, 0)[1]
                        normalize(event, reply)
                        self.assertEqual(reply, expected)

    def test_reject_invalid_timer_contract(self):
        for name, normalize in normalizers():
            for control in ['too-much-fuzz', 'negative-fuzz', 'different-fuzz',
                            'wrong-lease', 'short-timer', 'missing-timer', 'not-ack']:
                with self.subTest(probe=name, control=control):
                    event, reply = sample()
                    if control == 'too-much-fuzz': event, reply = sample(fuzz=226)
                    elif control == 'negative-fuzz': event, reply = sample(fuzz=-1)
                    elif control == 'different-fuzz': reply['options']['59'] = '00000ba4'
                    elif control == 'wrong-lease': reply['options']['51'] = '00000708'
                    elif control == 'short-timer': reply['options']['58'] = '065d'
                    elif control == 'missing-timer': del reply['options']['59']
                    elif control == 'not-ack': reply['message_type'] = 6
                    with self.assertRaises(ValueError): normalize(event, reply)

    def test_nonrenewal_and_other_fields_remain_comparable(self):
        for name, normalize in normalizers():
            for update in [dict(kind=1, rapid=True), dict(wanted=True),
                           dict(ciaddr='0.0.0.0'), dict(server='127.0.0.1')]:
                with self.subTest(probe=name, update=update):
                    event, reply = sample()
                    event.update(update)
                    before = deepcopy(reply)
                    normalize(event, reply)
                    self.assertEqual(reply, before)
            event, left = sample()
            right = deepcopy(left)
            right['options']['12'] = '6f74686572'
            normalize(event, left)
            normalize(event, right)
            self.assertNotEqual(left, right)

    def test_helper_counts_metadata_and_raw_rows_are_preserved(self):
        for path in PROBES:
            tree = ast.parse(path.read_text())
            functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                         and node.name in ['normalize_renewal_timers', 'normalized']]
            namespace = {'json': json}
            exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), namespace)
            compare = namespace['normalized']
            event, reply = sample()
            baseline = dict(events=[dict(input=event, reply=reply)], helper_events_full=[
                dict(argv=['add', '02:00:00:00:00:01', '127.0.0.30', 'dual'],
                     env={'DNSMASQ_VENDOR_CLASS': 'original', 'DNSMASQ_LEASE_EXPIRES': '1000'})])
            original = deepcopy(baseline)
            for control in ['extra-call', 'vendor', 'missing-data', 'argv']:
                with self.subTest(probe=path.name, control=control):
                    changed = deepcopy(baseline)
                    callback = changed['helper_events_full'][0]
                    if control == 'extra-call': changed['helper_events_full'].append(deepcopy(callback))
                    elif control == 'vendor': callback['env']['DNSMASQ_VENDOR_CLASS'] = 'replacement'
                    elif control == 'missing-data': callback['env']['DNSMASQ_DATA_MISSING'] = '1'
                    elif control == 'argv': callback['argv'][0] = 'old'
                    self.assertNotEqual(compare(baseline), compare(changed))
            self.assertEqual(baseline, original)


if __name__ == '__main__':
    unittest.main()
