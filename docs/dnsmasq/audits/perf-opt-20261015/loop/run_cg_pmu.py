"""Run the predeclared Oracle PMU matrix once, using the existing owner driver."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('plan', type=Path)
parser.add_argument('plan_sha256')
args = parser.parse_args()
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
assert sha(args.plan) == args.plan_sha256
plan = json.loads(args.plan.read_text())
assert plan['execution_authorized'] and plan['quiet_handoff'] and plan['protocol_supplement']
for path, digest in plan['input_files'].items():
    assert sha(path) == digest, path
root = Path(plan['raw_root'])
root.mkdir(exist_ok=False)
save = lambda name, obj: (root / name).write_text(json.dumps(obj, indent=2) + '\n')
save('launch.json', {'pid': os.getpid(), 'epoch': time.time(),
                     'plan_sha256': sha(args.plan), 'launcher_sha256': sha(__file__)})
progress = []
for window in plan['windows']:
    assert not Path(window['output']).exists()
    started = time.time()
    with (root / (window['id'] + '.stdout')).open('xb') as stdout, \
         (root / (window['id'] + '.stderr')).open('xb') as stderr:
        completed = subprocess.run(window['argv'], stdout=stdout, stderr=stderr)
    progress.append({'id': window['id'], 'started': started,
                     'ended': time.time(), 'returncode': completed.returncode})
    save('progress.json', progress)
    assert completed.returncode == 0, progress[-1]
save('complete.json', {'windows': len(progress), 'complete': True, 'epoch': time.time()})
