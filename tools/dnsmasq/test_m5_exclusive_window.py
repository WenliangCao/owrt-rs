"""Real Linux child-birth and unrelated sibling controls for the load guard."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
MONITOR = '''import json,os,pathlib,signal,subprocess,sys,time
from unittest.mock import patch
sys.path.insert(0,sys.argv[1]);import m5_final_validation as final
worker,ready,mode=sys.argv[2:5];child=None;first=[];calls=0
original=final.related_processes;scan=final.family_processes
def snapshot():
 global child,calls
 value=original();calls+=1
 if calls==1 and mode=='owned':
  child=subprocess.Popen(['unshare','--net','--mount','--pid','--fork','--mount-proc',sys.executable,worker,ready],start_new_session=True)
  deadline=time.monotonic()+3
  while not pathlib.Path(ready).exists():
   assert child.poll() is None and time.monotonic()<deadline
   time.sleep(.005)
 return value
def capture(excluded):
 value=scan(excluded);first.extend(value);return value
try:
 with patch.object(final,'related_processes',side_effect=snapshot),patch.object(final,'family_processes',side_effect=capture):
  busy=final.exclusive_busy_processes()
 if mode=='owned':
  candidates=[r for r in first if worker in r['argv']]
  assert candidates and not any(worker in r['argv'] for r in busy)
  namespace=json.loads(pathlib.Path(ready).read_text())
  assert namespace['net_namespace']!=os.readlink('/proc/self/ns/net')
  result={'own_child_accepted':True,'first_scan_candidates':candidates,'related_scans':calls,'namespace':namespace}
 else:
  assert any(worker in r['argv'] for r in busy)
  try:final.require(not busy,'exclusive window contaminated')
  except ValueError:rejected=True
  else:rejected=False
  assert rejected
  result={'foreign_rejected':True,'busy':busy,'related_scans':calls}
 print(json.dumps(result,sort_keys=True),flush=True)
finally:
 if child:
  try:os.killpg(child.pid,signal.SIGTERM)
  except ProcessLookupError:pass
  try:child.wait(1)
  except subprocess.TimeoutExpired:pass
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  child.wait(2)
'''
WORKER = '''import json,os,pathlib,sys,time
pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'net_namespace':os.readlink('/proc/self/ns/net')}))
time.sleep(60)
'''


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'root Linux namespaces required')
class ExclusiveWindowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='m5-window-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.monitor = self.root / 'guard_controller.py'; self.monitor.write_text(MONITOR)

    def worker(self, name):
        path = self.root / name; path.write_text(WORKER)
        return path

    def monitor_result(self, worker, ready, mode):
        process = subprocess.run([sys.executable, str(self.monitor), str(HERE), str(worker), str(ready), mode],
                                 check=True, capture_output=True, text=True, timeout=8)
        return json.loads(process.stdout)

    def test_new_namespace_child_is_rechecked_from_real_proc_ancestry(self):
        worker = self.worker('m3_owned_guard.py'); ready = self.root / 'owned-ready.json'
        result = self.monitor_result(worker, ready, 'owned')
        self.assertTrue(result['own_child_accepted'])
        self.assertEqual(result['related_scans'], 2)
        self.assertTrue(result['first_scan_candidates'])
        print(json.dumps(result, sort_keys=True), flush=True)

    def test_real_foreign_sibling_still_rejects_the_window(self):
        worker = self.worker('m3_foreign_guard.py'); ready = self.root / 'foreign-ready.json'
        foreign = subprocess.Popen([sys.executable, str(worker), str(ready)], start_new_session=True)
        try:
            deadline = time.monotonic() + 3
            while not ready.exists():
                self.assertIsNone(foreign.poll()); self.assertLess(time.monotonic(), deadline)
                time.sleep(.005)
            result = self.monitor_result(worker, ready, 'foreign')
            self.assertTrue(result['foreign_rejected'])
            self.assertTrue(any(row['pid'] == foreign.pid for row in result['busy']))
            print(json.dumps(result, sort_keys=True), flush=True)
        finally:
            os.killpg(foreign.pid, signal.SIGTERM); foreign.wait(2)


if __name__ == '__main__': unittest.main()
