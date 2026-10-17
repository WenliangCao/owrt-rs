"""Controlled PID-publication interleaving and observer-failure regression tests."""
import os
from pathlib import Path
import re
import select
import shlex
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name('device_perf_case.sh').read_text()
PUBLISHERS = re.findall(r"/bin/sh -c '([^']+)' sh \"\$out/(?:client|upstream)\.pid\"", SOURCE)


def function(name):
    return re.search(r'^' + name + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S).group()


class ObserverTests(unittest.TestCase):
    def publication(self, command, atomic):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'client.pid'
            ready_read, ready_write = os.pipe()
            gate_read, gate_write = os.pipe()
            # Shell redirection opens the PID file before calling echo. Pause
            # the actual publisher at that boundary, without timing or sleeps.
            script = (f'echo() {{ printf ready >&{ready_write}; '
                      f'IFS= read -r gate <&{gate_read}; printf "%s\\n" "$1"; }}\n'
                      + command)
            process = subprocess.Popen(['/bin/sh', '-c', script, 'sh', str(path), '/bin/sh', '-c', 'exit 0'],
                                       pass_fds=(ready_write, gate_read),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertTrue(select.select([ready_read], [], [], 3)[0], 'publisher never reached gate')
                self.assertEqual(os.read(ready_read, 5), b'ready')
                if atomic:
                    self.assertFalse(path.exists(), 'final PID path exposed before write')
                    self.assertEqual(Path(str(path) + '.tmp').read_bytes(), b'')
                else:
                    self.assertTrue(path.exists(), 'negative control must expose original race')
                    self.assertEqual(path.read_bytes(), b'')
                os.write(gate_write, b'go\n')
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual((process.returncode, stdout, stderr), (0, b'', b''))
                self.assertEqual(path.read_text(), str(process.pid) + '\n')
                self.assertFalse(Path(str(path) + '.tmp').exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
                for fd in (ready_read, ready_write, gate_read, gate_write):
                    os.close(fd)

    def test_original_publisher_exposes_empty_pid(self):
        self.publication('echo $$ > "$1"; shift; exec "$@"', atomic=False)

    def test_actual_publishers_expose_only_complete_pid(self):
        self.assertEqual(len(PUBLISHERS), 2)
        for command in PUBLISHERS:
            with self.subTest(command=command):
                self.publication(command, atomic=True)

    def test_invalid_pid_cannot_read_system_stat(self):
        for pid in ['', 'not-a-pid', '12/../stat']:
            script = 'awk() { printf called >&2; }\n' + function('starttime') + '\nstarttime "$1"'
            result = subprocess.run(['/bin/sh', '-c', script, 'sh', pid], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual((result.stdout, result.stderr), (b'', b''))

    def test_reaping_records_status_and_rejects_missing_observations(self):
        start = SOURCE.index('owned_signal "$observer" "$observer_start" TERM',
                             SOURCE.index('wait "$client_timer"'))
        end = SOURCE.index('owned_signal "$upstream"', start)
        finish = SOURCE[start:end]
        for status, rows, stderr, valid in [
            (0, b'{}\n', b'', True), (1, b'{}\n', b'', True),
            (2, b'', b'', False), (0, b'', b'', False),
            (137, b'{}\n', b'', False), (1, b'{}\n', b'sample failed\n', False),
        ]:
            with self.subTest(status=status, rows=bool(rows), stderr=bool(stderr)):
                with tempfile.TemporaryDirectory() as temporary:
                    out = Path(temporary)
                    (out / 'resources.jsonl').write_bytes(rows)
                    (out / 'resources.stderr').write_bytes(stderr)
                    script = ('set -eu\n' + function('reap_observer')
                              + '\nowned_signal() { :; }\n'
                              + 'out=' + shlex.quote(temporary) + '\n'
                              + f'/bin/sh -c "exit {status}" &\nobserver=$!\nobserver_start=1\n'
                              + finish + '\nprintf complete\n')
                    result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, timeout=3)
                    self.assertEqual((out / 'observer.exit').read_text(), str(status) + '\n')
                    self.assertEqual(result.returncode == 0, valid, result.stderr)
                    self.assertEqual(result.stdout, b'complete' if valid else b'')


if __name__ == '__main__':
    unittest.main()
