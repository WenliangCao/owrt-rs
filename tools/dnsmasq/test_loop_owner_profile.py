"""Small negative controls for exact-image mapping admission; no workload runs."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from loop_owner_profile import validate_load_counts, verify_mapped_files


class LoadCountTests(unittest.TestCase):
    def fixture(self, warm, measured):
        def counts(n):
            return dict(scheduled=n, sent=n, correct=n, timeout=0, wrong=0,
                        transport_error=0, scheduled_skipped=0)
        return dict(interrupted=False, output_failed=False,
                    warmup=counts(warm), measurement=counts(measured))

    def test_original_fixed_cohorts_remain_exact(self):
        validate_load_counts(self.fixture(1000, 4000), 5, 20, 200)
        for warm, measured in [(999, 4000), (1000, 3999)]:
            with self.assertRaises(AssertionError):
                validate_load_counts(self.fixture(warm, measured), 5, 20, 200)

    def test_unpaced_diagnostic_requires_complete_nonempty_cohorts(self):
        validate_load_counts(self.fixture(8100, 32400), 5, 20, 0)
        for field in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'):
            data = self.fixture(8100, 32400)
            data['measurement'][field] = 1
            with self.assertRaises(AssertionError):
                validate_load_counts(data, 5, 20, 0)
        for data in [self.fixture(0, 32400), self.fixture(8100, 0)]:
            with self.assertRaises(AssertionError):
                validate_load_counts(data, 5, 20, 0)


class MappingIdentityTests(unittest.TestCase):
    def test_data_mapping_is_recorded_without_widening_elf_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'binary'
            zone = Path(directory) / 'zone'
            binary.write_bytes(b'\x7fELFidentity')
            zone.write_bytes(b'TZifdata')
            expected = {str(binary): hashlib.sha256(binary.read_bytes()).hexdigest()}
            elf_line = f'1000-2000 r-xp 00000000 00:01 1 {binary}\n'
            data_line = f'3000-4000 r--p 00000000 00:01 2 {zone}\n'
            result = verify_mapped_files(elf_line + data_line + '5000-6000 r-xp 00000000 00:00 0 [vdso]\n', expected)
            self.assertEqual(result['elf_files'], expected)
            self.assertEqual(result['non_executable_data_files'][str(zone)]['mappings'],
                             [{'permissions': 'r--p', 'offset': '00000000'}])
            for wrong in [elf_line + data_line.replace('r--p', 'r-xp'),
                          elf_line + '7000-8000 r-xp 00000000 00:00 0\n']:
                with self.assertRaises(AssertionError):
                    verify_mapped_files(wrong, expected)
            with self.assertRaises(AssertionError):
                verify_mapped_files(elf_line, {str(binary): 'wrong'})
            zone.write_bytes(b'\x7fELFunexpected-library')
            with self.assertRaises(AssertionError):
                verify_mapped_files(elf_line + data_line, expected)


if __name__ == '__main__':
    unittest.main()
