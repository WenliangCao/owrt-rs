#!/usr/bin/env python3
"""Guard profile evidence accounting and runtime-to-ELF address conversion."""
import unittest
from types import SimpleNamespace

import perf_link_map_profile as profile


class ProfileTests(unittest.TestCase):
    def test_actual_perf_format_and_period_crosscheck(self):
        samples = profile.samples_from_text(
            ' 13/13 K 1 cycles:P: ffff80008014bc30 finish_task_switch.isra.0 ([kernel.kallsyms])\n'
            ' 13/13 U 298808536 cycles:P: 00448898 0x448898 (/tmp/dnsmasq-rs)\n')
        report = ('# Total Lost Samples: 0\n'
                  '0.01%;1;1;[kernel.kallsyms];[k] finish_task_switch.isra.0;- -\n'
                  '99.99%;1;298808536;dnsmasq-rs;[.] 0x48898;- -\n')
        self.assertEqual(profile.check_report(report, samples),
                         {'samples': 2, 'period': 298808537, 'lost_samples': 0})
        with self.assertRaisesRegex(ValueError, 'exactly match'):
            profile.check_report(report.replace(';298808536;', ';298808535;'), samples)
        with self.assertRaisesRegex(ValueError, 'zero lost'):
            profile.check_report(report.replace('Lost Samples: 0', 'Lost Samples: 1'), samples)

    def test_callchain_or_multiple_events_are_not_silently_accepted(self):
        with self.assertRaisesRegex(ValueError, 'no callgraph'):
            profile.samples_from_text(' 13/13 U 10 cycles:P: 400080 sym (dnsmasq-rs)\n'
                                      ' 400060 caller (dnsmasq-rs)\n')
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            profile.samples_from_text(' 13/13 U 10 cycles:P: 400080 sym (dnsmasq-rs)\n'
                                      ' 13/13 U 20 cpu-clock: 400080 sym (dnsmasq-rs)\n')

    def test_nonzero_mapping_offset_and_pie_keep_gaps_and_other_modes(self):
        # A segment need not have vaddr == file offset; ASLR must preserve both.
        elf = SimpleNamespace(loads=[(5, 0x1000, 0x201000, 0, 0x3000, 0x3000, 0x1000)])
        mappings = profile.parse_proc_maps(
            '7f002000-7f004000 r-xp 00002000 00:41 123 /tmp/dnsmasq-rs\n')
        self.assertEqual(profile.elf_address(elf, mappings[0], 0x7f002123), 0x202123)
        samples = profile.samples_from_text(
            '13/13 U 100 cpu-clock: 7f002123 unknown (dnsmasq-rs)\n'
            '13/13 U 20 cpu-clock: 7f002180 unknown (dnsmasq-rs)\n'
            '13/13 U 5 cpu-clock: 1 unknown ([unknown])\n'
            '13/13 K 70 cpu-clock: ffff1000 send (kernel)\n'
            '13/13 G 3 cpu-clock: 1000 guest (guest)\n')
        result = profile.analyze(samples, elf, mappings,
                                 {'pid': 13, 'exe': '/tmp/dnsmasq-rs'},
                                 [(1, 0x202100, 0x80, 'function')], {'function': 'function'})
        self.assertEqual(result['period_by_mode'], {'user': 125, 'kernel': 70, 'G': 3})
        groups = {row['label']: row for row in result['ranges']}
        self.assertEqual(groups['function']['elf_range'], ['0x202100', '0x202180'])
        self.assertEqual(groups['function']['ips'][0]['elf_vma'], '0x202123')
        self.assertEqual(groups['link_map_gap']['period'], 20)
        self.assertEqual(groups['no_unique_executable_mapping']['period'], 5)
        self.assertEqual(sum(row['period'] for row in result['ranges']), 198)
        self.assertEqual(sum(row['samples'] for row in result['ranges']), 5)

    def test_missing_map_does_not_use_perf_guessed_symbol(self):
        elf = SimpleNamespace(loads=[(5, 0, 0x400000, 0, 0x1000, 0x1000, 0x1000)])
        mappings = profile.parse_proc_maps('00400000-00401000 r-xp 0 00:41 123 /tmp/dnsmasq-rs\n')
        samples = profile.samples_from_text('13/13 U 50 cycles:P: 400020 guessed (dnsmasq-rs)\n')
        result = profile.analyze(samples, elf, mappings,
                                 {'pid': 13, 'exe': '/tmp/dnsmasq-rs'}, [], {})
        self.assertEqual(result['ranges'][0]['label'], 'no_link_map')
        self.assertEqual(result['ranges'][0]['ips'][0]['elf_vma'], '0x400020')
        with self.assertRaisesRegex(ValueError, 'PID'):
            profile.analyze(samples, elf, mappings, {'pid': 14, 'exe': '/tmp/dnsmasq-rs'}, [], {})


if __name__ == '__main__':
    unittest.main()
