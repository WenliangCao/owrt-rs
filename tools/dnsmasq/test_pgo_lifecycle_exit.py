"""Real local child wait-status checks for the training-only exit fragment."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ExitStatus(unittest.TestCase):
    def test_normal_nonzero_signal_and_missing_child(self):
        original = (ROOT / 'tools/dnsmasq/device_perf_lifecycle.c').read_text()
        begin = original.index('static int end_child(void) {')
        end = original.index('static unsigned read16', begin)
        body = (ROOT / 'tools/dnsmasq/pgo_lifecycle_exit.c').read_text()
        adapted = original[:begin] + body + '\n' + original[end:]
        test_main = r'''
int main(int argc, char **argv) {
    (void)argc;
    int mode = atoi(argv[1]);
    child = fork();
    if (child < 0) return 90;
    if (!child) {
        if (mode == 2) raise(SIGKILL);
        _exit(mode == 1 ? 7 : 0);
    }
    /* Observe exit without reaping, so end_child receives the real status. */
    siginfo_t info;
    if (waitid(P_PID, child, &info, WEXITED | WNOWAIT)) return 91;
    if (mode == 3) { int status; if (waitpid(child, &status, 0) < 0) return 92; }
    return end_child() ? 0 : 1;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'fixture.c'
            source.write_text('#define main original_lifecycle_main\n' + adapted +
                              '\n#undef main\n' + test_main)
            binary = root / 'fixture'
            # The original Linux socket paths are not executed by this wait-only fixture.
            host_flags = ['-DSOCK_CLOEXEC=0'] if sys.platform == 'darwin' else []
            compiled = subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', *host_flags, str(source), '-o', str(binary)],
                                      text=True, capture_output=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            for mode, exit_status in ((0, 0), (1, 1), (2, 1), (3, 1)):
                result = subprocess.run([str(binary), str(mode)], text=True, capture_output=True)
                self.assertEqual(result.returncode, exit_status)
                lines = [line for line in result.stderr.splitlines() if line.startswith('pgo_child_exit ')]
                self.assertEqual(len(lines), 1)
                row = json.loads(lines[0].split(' ', 1)[1])
                self.assertFalse(row['forced'])
                if mode == 0:
                    self.assertTrue(row['exited'])
                    self.assertEqual((row['exit_code'], row['signal'], row['wait_errno']), (0, 0, 0))
                elif mode == 1:
                    self.assertTrue(row['exited'])
                    self.assertEqual(row['exit_code'], 7)
                elif mode == 2:
                    self.assertFalse(row['exited'])
                    self.assertGreater(row['signal'], 0)
                else:
                    self.assertFalse(row['exited'])
                    self.assertGreater(row['wait_errno'], 0)


if __name__ == '__main__':
    unittest.main()
