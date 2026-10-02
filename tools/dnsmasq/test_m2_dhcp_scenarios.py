#!/usr/bin/env python3
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from m2_dhcp_scenarios import stop_process


class StopCleanupTests(unittest.TestCase):
    def test_timeout_forces_kill_and_removes_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            pid = Path(directory) / 'daemon.pid'
            pid.write_text('123\n')
            process = subprocess.Popen([
                sys.executable, '-c',
                'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print("ready", flush=True); time.sleep(30)',
            ], stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(), 'ready')
                result = stop_process(process, (pid,), timeout=.05)
            finally:
                process.stdout.close()
                if process.poll() is None:
                    process.kill()
                    process.wait()
            self.assertTrue(result['forced'])
            self.assertTrue(result['reaped'])
            self.assertTrue(result['pid_removed'])
            self.assertEqual(result['removed_paths'], [str(pid)])


if __name__ == '__main__':
    unittest.main()
