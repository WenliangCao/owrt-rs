"""Real detached sessions, namespace wrappers, and unrelated-process controls."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import m5_final_validation as final


LEAF = '''import json,os,pathlib,signal,sys,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'net_namespace':os.readlink('/proc/self/ns/net')}))
time.sleep(60)
'''
PARENT = '''import pathlib,subprocess,sys,time
root=pathlib.Path(sys.argv[1]);namespace=sys.argv[2]=='namespace'
for name in ['c','rust']:
 argv=[sys.executable,str(root/'m3_cleanup_leaf.py'),str(root/(name+'.json'))]
 if namespace:argv=['unshare','--net','--mount','--pid','--fork','--mount-proc',*argv]
 subprocess.Popen(argv,start_new_session=True)
time.sleep(60)
'''


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux /proc generation witnesses required')
class JobCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='m5-cleanup-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'm3_cleanup_leaf.py').write_text(LEAF)
        (self.root / 'parent.py').write_text(PARENT)

    def run_cleanup(self, namespace=False):
        foreign = subprocess.Popen([sys.executable, str(self.root / 'm3_cleanup_leaf.py'),
                                    str(self.root / 'foreign.json')], start_new_session=True)
        parent = subprocess.Popen([sys.executable, str(self.root / 'parent.py'), str(self.root),
                                   'namespace' if namespace else 'plain'], start_new_session=True)
        known = {}
        try:
            deadline = time.monotonic() + 3
            while not all((self.root / (name + '.json')).exists() for name in ['c', 'rust', 'foreign']):
                self.assertIsNone(parent.poll()); self.assertLess(time.monotonic(), deadline)
                final.remember_job_processes(parent, known); time.sleep(.005)
            active = final.remember_job_processes(parent, known)
            self.assertGreaterEqual(len(active), 3)
            self.assertNotIn(foreign.pid, active)
            groups = {pid: os.getpgid(pid) for pid in active}
            self.assertGreaterEqual(len(set(groups.values())), 3)
            started = time.monotonic()
            final.stop_job_processes(parent, known, grace_seconds=.2)
            self.assertLess(time.monotonic() - started, 2)
            self.assertIsNotNone(parent.returncode)
            self.assertEqual(final.remember_job_processes(parent, known), {})
            self.assertIsNone(foreign.poll())
            print(json.dumps({'namespace': namespace, 'owned_groups': groups,
                              'all_owned_live_processes_stopped': True,
                              'foreign_pid': foreign.pid, 'foreign_survived': True}, sort_keys=True), flush=True)
        finally:
            final.stop_job_processes(parent, known, grace_seconds=.2)
            os.kill(foreign.pid, signal.SIGKILL); foreign.wait(2)

    def test_detached_sessions_are_stopped_without_touching_foreign_sibling(self):
        self.run_cleanup()

    @unittest.skipUnless(os.geteuid() == 0, 'root namespaces required')
    def test_namespace_workers_in_separate_groups_are_stopped(self):
        self.run_cleanup(namespace=True)

    def test_mismatched_pid_generation_cannot_signal_unrelated_process(self):
        foreign = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'], start_new_session=True)
        parent = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'], start_new_session=True)
        known = {foreign.pid: dict(final.process_tree()[foreign.pid])}
        known[foreign.pid]['starttime'] += 1
        try:
            final.stop_job_processes(parent, known, grace_seconds=.2)
            self.assertIsNone(foreign.poll())
        finally:
            os.kill(foreign.pid, signal.SIGKILL); foreign.wait(2)
            if parent.poll() is None: os.kill(parent.pid, signal.SIGKILL)
            parent.wait(2)


if __name__ == '__main__': unittest.main()
