"""Synthetic gate tests only: no daemon, device, timing run or network access."""
import copy
from fractions import Fraction
import json
from pathlib import Path
import tempfile
import unittest

import odhcpd_device_analyze as analysis


def option(code, body):
    return code.to_bytes(2, 'big') + len(body).to_bytes(2, 'big') + body


def exchange(kind, index, start, elapsed):
    pd = kind.startswith('pd_')
    ia = 25 if pd else 3
    header = bytes([0, 0, 0, index % 3 + 1]) + bytes(8)
    lifetimes = (2700).to_bytes(4, 'big') + (5400).to_bytes(4, 'big')
    address = lifetimes + bytes([62]) + bytes(16) if pd else bytes(16) + lifetimes
    sent_type = {'solicit': 1, 'request': 3, 'renew': 5, 'pd_solicit': 1, 'pd_request': 3}[kind]
    xid = index.to_bytes(3, 'big')
    return {'kind': kind, 'index': index, 'client': index % 3,
            'start_ns': start, 'end_ns': start + elapsed, 'elapsed_ns': elapsed,
            'request_hex': (bytes([sent_type]) + xid + option(ia, header)).hex(),
            'hex': (bytes([2 if sent_type == 1 else 7]) + xid
                    + option(ia, header + option(26 if pd else 5, address))).hex()}


def ra(dns=None):
    packet = b'\x86' + bytes(15)
    if dns:
        packet += bytes([25, 3, 0, 0]) + (1800).to_bytes(4, 'big') + analysis.ipaddress.IPv6Address(dns).packed
    return packet.hex()


def sample(latency=100, cpu=100, rss=100):
    instrument = {'kind': 'instrument', 'schema_version': 1, 'pid': 7, 'start_ticks': 9,
                  'exe_dev': 1, 'exe_ino': 8, 'cpu_clock_kind': 'process',
                  'clock_quantum_ns': 1, 'cpu_clock_quantum_ns': 1, 'page_size_bytes': 4096}
    records = [instrument,
               {'kind': 'idle', 'start_ns': 0, 'end_ns': 3_000_000_000,
                'cpu_before_ns': 400, 'cpu_after_ns': 700, 'solicited_count': 0, 'periodic_ra_count': 1},
               {'kind': 'memory', 'stage': 'empty', 'rss_kib': rss, 'rss_anon_kib': 20}]
    start = 3_000_000_001
    for index in range(16):
        records.append({'kind': 'rs', 'index': index, 'start_ns': start, 'end_ns': start + latency,
                        'elapsed_ns': latency, 'hex': ra()})
        start += 10_000_000
    for index in range(16):
        for kind in ('solicit', 'request', 'renew'):
            records.append(exchange(kind, index, start, latency))
            start += 10_000_000
    for kind in ('pd_solicit', 'pd_request'):
        records.append(exchange(kind, 0, start, latency))
        start += 10_000_000
    records.append({'kind': 'memory', 'stage': 'populated', 'rss_kib': rss + 4, 'rss_anon_kib': 24})
    for index in range(8):
        dns = f'2001:db8::{index + 1}'
        records.append({'kind': 'update', 'index': index, 'start_ns': start, 'end_ns': start + 2_000_000,
                        'ra_received_ns': start + 1_000_000, 'elapsed_ns': 2_000_000,
                        'drain_ns': 1_000_000, 'cpu_before_ns': 100, 'cpu_after_ns': 100 + cpu,
                        'cpu_ns': cpu, 'dns': dns, 'hex': ra(dns)})
        start += 10_000_000
    records.append({**{key: instrument[key] for key in ('schema_version', 'pid', 'start_ticks', 'exe_dev', 'exe_ino')},
                    'kind': 'complete', 'rs_count': 16, 'dhcp_count_each': 16,
                    'updates': 8, 'na_count': 3, 'pd_count': 1})
    return records


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for filename, content in {'COMPLETE': 'complete', 'mode.txt': 'device',
                                  'boot-before.txt': 'same-boot', 'boot-after.txt': 'same-boot',
                                  'parent-netns.txt': 'net:[1]'}.items():
            (self.root / filename).write_text(content)
        floor = self.root / 'floor'
        floor.mkdir()
        (floor / 'COMPLETE').write_text('complete')
        (floor / 'netns.txt').write_text('net:[2]')
        clocks = [{'kind': 'floor_clock', 'index': index, 'clock_quantum_ns': 1,
                   'start_ns': index * 10, 'end_ns': index * 10 + 1, 'elapsed_ns': 1}
                  for index in range(16)]
        echoes = [{'kind': 'floor_echo', 'index': index, 'start_ns': index * 10,
                   'end_ns': index * 10 + 5, 'elapsed_ns': 5, 'bytes': 64,
                   'payload_matches': True, 'request_hex': bytes([index] * 64).hex(),
                   'hex': bytes([index] * 64).hex()} for index in range(16)]
        self.write(floor / 'measurements.jsonl', clocks + echoes
                   + [{'kind': 'floor_complete', 'clock_count': 16, 'echo_count': 16}])
        for phase, schedule in analysis.SCHEDULE.items():
            for ordinal, side in enumerate(schedule):
                directory = self.root / f'{phase}-{ordinal}-{side}'
                directory.mkdir()
                identity = {'schema_version': 1, 'phase': phase, 'ordinal': ordinal,
                            'side': side, 'elf_sha256': analysis.ELFS[side]}
                (directory / 'identity.json').write_text(json.dumps(identity))
                (directory / 'COMPLETE').write_text('complete')
                (directory / 'netns.txt').write_text('net:[2]')  # Namespace inode reuse is valid.
                (directory / 'provider-final.json').write_text(json.dumps(
                    {'sequence': 8, 'notifications': 8, 'subscribed': True, 'dumps': 9}))
                self.write(directory / 'measurements.jsonl', sample())

    @staticmethod
    def write(path, records):
        path.write_text(''.join(json.dumps(record) + '\n' for record in records))

    def change(self, phase, ordinal, records):
        side = analysis.SCHEDULE[phase][ordinal]
        self.write(self.root / f'{phase}-{ordinal}-{side}' / 'measurements.jsonl', records)

    def test_gate_equality_and_page_quantization(self):
        self.change('formal', 1, sample(latency=102, rss=108))
        result = analysis.analyze(self.root)
        self.assertEqual(result['decision'], 'pass')
        self.assertEqual(result['metrics']['rs_latency_ns']['noise'], 2)
        self.assertEqual(result['metrics']['empty_rss_kib']['noise'], 8)
        self.assertEqual(result['metrics']['idle_cpu_ns_per_s']['quantum'], Fraction(1, 3))

    def test_one_slow_pair_cannot_be_averaged_away(self):
        for ordinal in [1, 2, 4, 7]:
            self.change('formal', ordinal, sample(latency=1))
        self.change('formal', 2, sample(latency=103))  # BA pair: B is first.
        result = analysis.analyze(self.root)
        self.assertEqual(result['decision'], 'stop_and_report')
        metric = result['metrics']['rs_latency_ns']
        self.assertLess(metric['formal_Rust_median'], metric['formal_C_median'])
        self.assertEqual(metric['pairs'][1]['Rust_minus_C'], 3)
        self.assertEqual(metric['pairs'][1]['classification'], 'regression')

    def test_calibration_range_of_either_implementation_sets_noise(self):
        self.change('calibration', 0, sample(cpu=80))
        self.change('calibration', 2, sample(cpu=130))
        self.change('formal', 7, sample(cpu=130))
        result = analysis.analyze(self.root)
        self.assertEqual(result['metrics']['update_cpu_ns']['noise'], 30)
        self.assertEqual(result['decision'], 'pass')

    def test_idle_rate_and_quantum_use_actual_window(self):
        records = sample()
        idle = records[1]
        idle['end_ns'] = 6_000_000_000
        for record in records:
            if record.get('kind') in analysis.CONTRACT['counts']:
                record['start_ns'] += 3_000_000_000
                record['end_ns'] += 3_000_000_000
                if 'ra_received_ns' in record:
                    record['ra_received_ns'] += 3_000_000_000
        values = analysis.aggregate({'schema_version': 1, 'side': 'A',
                                     'elf_sha256': analysis.ELFS['A']}, records)
        self.assertEqual(values['idle_cpu_ns_per_s'], (50, Fraction(1, 6)))

    def test_missing_event_restart_bad_cpu_and_false_completion_are_invalid(self):
        variants = []
        missing = sample()
        missing.pop(3)
        variants.append(missing)
        restarted = sample()
        restarted[-1]['start_ticks'] += 1
        variants.append(restarted)
        thread_clock = sample()
        thread_clock[0]['cpu_clock_kind'] = 'thread'
        variants.append(thread_clock)
        changed_cpu = sample()
        next(record for record in changed_cpu if record['kind'] == 'update')['cpu_ns'] += 1
        variants.append(changed_cpu)
        for records in variants:
            with self.subTest(records=records[0]), self.assertRaises(ValueError):
                self.change('formal', 0, records)
                analysis.analyze(self.root)

    def test_unobserved_dns_and_short_drain_rejected(self):
        for key, value in [('dns', '2001:db8::ffff'), ('drain_ns', 0), ('ra_received_ns', 10**18)]:
            records = sample()
            next(record for record in records if record['kind'] == 'update')[key] = value
            self.change('formal', 0, records)
            with self.subTest(key=key), self.assertRaises(ValueError):
                analysis.analyze(self.root)

    def test_raw_events_survive_median_and_original_records_are_not_modified(self):
        records = sample()
        original = copy.deepcopy(records)
        identity = {'schema_version': 1, 'side': 'A', 'elf_sha256': analysis.ELFS['A']}
        analysis.aggregate(identity, records)
        self.assertEqual(records, original)
        result = analysis.analyze(self.root)
        self.assertEqual(result['samples'][0]['records'], records)

    def test_schedule_elf_floor_and_quantum_changes_rejected(self):
        path = self.root / 'formal-0-A' / 'identity.json'
        identity = json.loads(path.read_text())
        for key, value in [('ordinal', 1), ('elf_sha256', 'bad')]:
            path.write_text(json.dumps({**identity, key: value}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                analysis.analyze(self.root)
        path.write_text(json.dumps(identity))
        records = sample()
        records[0]['cpu_clock_quantum_ns'] = 100
        self.change('formal', 0, records)
        with self.assertRaisesRegex(ValueError, 'quantization changed'):
            analysis.analyze(self.root)
        self.change('formal', 0, sample())
        (self.root / 'floor' / 'measurements.jsonl').unlink()
        with self.assertRaises(OSError):
            analysis.analyze(self.root)

    def test_driver_completion_is_required_after_valid_probe_output(self):
        for path in [self.root / 'COMPLETE', self.root / 'formal-0-A' / 'COMPLETE',
                     self.root / 'floor' / 'COMPLETE']:
            path.unlink()
            with self.subTest(path=path), self.assertRaises(OSError):
                analysis.analyze(self.root)
            path.write_text('complete')
        for filename, value in [('mode.txt', 'smoke'), ('boot-after.txt', 'rebooted'),
                                ('formal-0-A/netns.txt', 'net:[1]')]:
            path = self.root / filename
            before = path.read_text()
            path.write_text(value)
            with self.subTest(path=path), self.assertRaises(ValueError):
                analysis.analyze(self.root)
            path.write_text(before)

    def test_floor_raw_payload_and_provider_final_are_checked(self):
        path = self.root / 'floor' / 'measurements.jsonl'
        records = analysis.read_jsonl(path)
        records[16]['hex'] = bytes([255] * 64).hex()
        self.write(path, records)
        with self.assertRaisesRegex(ValueError, 'echo payload mismatch'):
            analysis.analyze(self.root)
        records[16]['hex'] = records[16]['request_hex']
        self.write(path, records)
        provider = self.root / 'formal-0-A' / 'provider-final.json'
        provider.write_text(json.dumps({'sequence': 8, 'notifications': 8, 'subscribed': False}))
        with self.assertRaisesRegex(ValueError, 'provider updates'):
            analysis.analyze(self.root)


if __name__ == '__main__':
    unittest.main()
