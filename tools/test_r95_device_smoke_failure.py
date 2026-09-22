#!/usr/bin/env python3
"""Exercise cleanup and evidence retention without opening a network connection."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import r95_device_smoke as smoke


class DeviceFailureTests(unittest.TestCase):
    def exercise(self, timed_out=False, archive_fails=False, cleanup_fails=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, guard, workload, gate = [root / name for name in ('candidate', 'guard', 'workload', 'gate')]
            for path in (candidate, guard, workload):
                path.write_bytes(path.name.encode())
            gate.write_text(json.dumps({'offline_backup_verified': True, 'configuration_matches_backup': True,
                                        'boot_id': 'boot'}))
            hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (candidate, guard, workload)}
            output = root / 'output'
            events = []
            timeout = subprocess.TimeoutExpired('injected workload', 150)

            def remote(args, **kwargs):
                command = args[-1]
                if command.startswith('set -eu\nfor p in '):
                    events.append('cleanup')
                    if cleanup_fails:
                        raise RuntimeError('injected cleanup failure')
                    return b''
                if command == 'cat /root/r84/manifest.json':
                    return json.dumps({'tools': {'ns-exec': {'sha256': 'ns'},
                                                  'owrt-benchmark': {'sha256': 'bench'}}}).encode()
                if command.startswith('sha256sum /tmp/'):
                    name = command.rsplit('/', 1)[-1]
                    digest = {'ubusd-rs': hashes['candidate'], 'guard': hashes['guard'],
                              'probe.sh': hashes['workload'], 'ns-exec': 'ns', 'owrt-benchmark': 'bench'}[name]
                    return (digest + ' file\n').encode()
                return b'unchanged'

            def run(args, **kwargs):
                if args[0] == 'scp':
                    return subprocess.CompletedProcess(args, 0)
                command = args[-1]
                if command.startswith('tar -czf '):
                    events.append('archive')
                    if archive_fails:
                        kwargs['stdout'].write(b'partial archive')
                        kwargs['stderr'].write(b'injected transfer failure')
                        raise subprocess.CalledProcessError(1, args)
                    with tarfile.open(fileobj=kwargs['stdout'], mode='w:gz') as archive:
                        for name, content in [('COMPLETE', b''), ('daemon.log', b'original daemon log'),
                                              ('binary-sha256.txt', (hashes['candidate'] + ' file').encode())]:
                            info = tarfile.TarInfo(name)
                            info.size = len(content)
                            archive.addfile(info, io.BytesIO(content))
                    return subprocess.CompletedProcess(args, 0)
                events.append('workload')
                kwargs['stdout'].write(b'original run log')
                if timed_out:
                    raise timeout
                return subprocess.CompletedProcess(args, 0)

            argv = ['r95_device_smoke.py', 'ubusd', str(candidate), str(output),
                    '--guard', str(guard), '--recovery-gate', str(gate), '--workload-script', str(workload)]
            caught = None
            with patch('sys.argv', argv), patch.object(smoke, 'probe', return_value={'boot_id': 'boot'}), \
                    patch.object(smoke.subprocess, 'check_output', side_effect=remote), \
                    patch.object(smoke.subprocess, 'run', side_effect=run), patch('builtins.print'):
                try:
                    smoke.main()
                except BaseException as error:
                    caught = error
            if timed_out:
                self.assertIs(caught, timeout, 'archive/cleanup failure replaced the original exception')
            else:
                self.assertIsNone(caught)
            result = json.loads((output / 'result.json').read_text())
            self.assertEqual(events, ['workload', 'archive', 'cleanup'])
            self.assertEqual((output / 'run.log').read_bytes(), b'original run log')
            archive_name = 'failed-raw' if timed_out else 'raw'
            if archive_fails:
                self.assertEqual((output / f'{archive_name}.tar.gz').read_bytes(), b'partial archive')
                self.assertEqual((output / f'{archive_name}-archive.log').read_bytes(), b'injected transfer failure')
            else:
                self.assertEqual((output / archive_name / 'daemon.log').read_bytes(), b'original daemon log')
            return result

    def test_timeout_retains_evidence_before_cleanup(self):
        result = self.exercise(timed_out=True)
        self.assertFalse(result['passed'])
        self.assertTrue(result['cleanup_verified'])
        self.assertEqual(result['error']['type'], 'TimeoutExpired')
        self.assertEqual(result['failure_archive'], 'failed-raw.tar.gz')

    def test_archive_failure_still_cleans_and_preserves_original_error(self):
        result = self.exercise(timed_out=True, archive_fails=True)
        self.assertTrue(result['cleanup_verified'])
        self.assertEqual(result['failure_archive_error']['type'], 'CalledProcessError')

    def test_cleanup_failure_also_preserves_original_error(self):
        result = self.exercise(timed_out=True, archive_fails=True, cleanup_fails=True)
        self.assertFalse(result['cleanup_verified'])
        self.assertEqual(result['cleanup_error']['message'], 'injected cleanup failure')

    def test_success_keeps_the_existing_archive_layout(self):
        result = self.exercise()
        self.assertTrue(result['passed'])
        self.assertTrue(result['cleanup_verified'])
        self.assertNotIn('error', result)


if __name__ == '__main__':
    unittest.main()
