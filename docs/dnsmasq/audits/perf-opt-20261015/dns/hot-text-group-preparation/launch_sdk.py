"""Launch the preuploaded canonical SDK controller after fresh related quiet."""
from pathlib import Path
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


root = Path('/home/ubuntu/dnsmasq-perf-20261015')
inputs = root / 'dns/private/hot-text-group-execution-20261016'
plan_path = root / 'correctness/private/hot-text-group-execution-plan.json'
gate_path = root / 'correctness/private/hot-text-group-related-verified.json'
assert sha(plan_path) == sys.argv[1]
assert sha(gate_path) == sys.argv[2]
plan = json.loads(plan_path.read_text())
gate = json.loads(gate_path.read_text())
assert plan['execution_authorized']
assert gate['status'] == 'PASS_FRESH_ORIGINAL_FIVE_RELATED_GROUPS_AND_QUIET'
assert gate['source_commit'] == plan['source_commit']
assert gate['research'] == [] and gate['wrapper_exited']
controller = inputs / 'run_hot_text_group_sdk.py'
assert sha(controller) == 'f9e408c51c500fffd79d382abbfdd37922867b52f8a4870219758c571f01ab0b'
assert not (inputs / 'sdk-launch.json').exists()
assert not (inputs / 'sdk-command.json').exists()
assert not Path(plan['planned_remote_sdk_output']).exists()
assert not any(key.startswith('CARGO_PROFILE_RELEASE_') for key in os.environ)
research = []
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit() or int(proc.name) == os.getpid():
        continue
    try:
        fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        args = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
        comm = (proc / 'comm').read_text().strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if fields[0] != 'Z' and (str(root) in args or '/home/ubuntu/dnsmasq-image-bases/' in args or
            comm in ('dnsmasq', 'dnsmasq-rs', 'lib-dnsmasq_rs', 'bin-dnsmasq-rs',
                     'hosts_allocations', 'm6a_loadgen', 'm6a_upstream', 'perf', 'cargo',
                     'rustc', 'device_perf_netns')):
        research.append({'pid': int(proc.name), 'comm': comm, 'args': args})
assert not research, research
for path in gate['locks_available']:
    with Path(path).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lock, fcntl.LOCK_UN)
argv = ['python3', str(controller), sys.argv[1], sys.argv[2]]
with (inputs / 'controller.stdout').open('xb') as out, \
        (inputs / 'controller.stderr').open('xb') as err:
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                               start_new_session=True)
ticks = int((Path('/proc') / str(process.pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19])
receipt = {'status': 'SDK_CONTROLLER_RUNNING_NOT_YET_PASSED', 'epoch': time.time(),
           'pid': process.pid, 'start_ticks': ticks, 'argv': argv,
           'plan_sha256': sha(plan_path), 'related_verified_sha256': sha(gate_path),
           'controller_sha256': sha(controller), 'research': research,
           'locks_available': gate['locks_available']}
with (inputs / 'sdk-launch.json').open('x') as file:
    file.write(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
