import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import m2_dhcp_suite as suite


class StopOnFailure(unittest.TestCase):
    def test_confirmed_failure_stops_before_next_profile(self):
        with tempfile.TemporaryDirectory(prefix='private-') as temporary:
            root = Path(temporary) / 'private'; root.mkdir()
            plan = root / 'plan.json'
            plan.write_text(json.dumps({'router_cidr': '192.168.1.1/24',
                                        'profiles': ['first', 'second']}))
            argv = ['suite', '--image-root', '/image', '--runtime-root', '/runtime',
                    '--rust-binary', '/elf', '--plan', str(plan), '--out', str(root / 'out'),
                    '--label', 'final']
            outcomes = [SimpleNamespace(returncode=code) for code in [0, 1, 1]]
            with patch.object(suite.sys, 'argv', argv), patch.object(suite.os, 'geteuid', return_value=0), \
                    patch.object(suite.subprocess, 'run', side_effect=outcomes) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(suite.main())
            self.assertEqual(run.call_count, 3)
            commands = json.loads((root / 'out/final-commands.json').read_text())
            self.assertTrue(all('second' not in item['argv'] for item in commands))
            self.assertEqual([item['exit'] for item in commands], [0, 1, 1])
