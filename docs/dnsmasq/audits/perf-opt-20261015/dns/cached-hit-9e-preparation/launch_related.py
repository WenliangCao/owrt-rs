"""Detached original five-group entry, enabled only by a future selected plan."""
from pathlib import Path
import hashlib, json, subprocess, sys, time

sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
plan_path = Path(sys.argv[1])
assert sha(plan_path) == sys.argv[2]
plan = json.loads(plan_path.read_text())
assert plan['execution_authorized'] and plan['exclusive_slot_release']
release = plan['exclusive_slot_release']
assert sha(release['path']) == release['sha256']
p = Path('/home/ubuntu/dnsmasq-perf-20261015/correctness/private')
preflight_path = p / 'cached-hit-9e-related-preflight.json'
assert sha(preflight_path) == sys.argv[3]
preflight = json.loads(preflight_path.read_text())
assert preflight['status'] == 'PASS_EXACT_SOURCE_ORIGINAL_FIVE_GROUP_PREFLIGHT'
assert preflight['source_commit'] == plan['source_commit'] and preflight['research'] == []
assert preflight['git_identity_sha256'] == plan['git_identity_sha256']
assert preflight['source_manifest_sha256'] == plan['source_manifest_sha256']
argv = plan['execution_entries']['related']
wrapper = p / 'run_cached_hit_9e_related.py'
assert argv == ['python3', str(wrapper)]
assert sha(wrapper) == plan['related_wrappers'][wrapper.name]['sha256']
receipt_path = p / 'cached-hit-9e-related-launch.json'
assert not receipt_path.exists()
with (p / 'cached-hit-9e-related.stdout').open('x') as out, \
        (p / 'cached-hit-9e-related.stderr').open('x') as err:
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                               start_new_session=True)
ticks = int((Path('/proc') / str(process.pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19])
receipt = {'source_commit': plan['source_commit'], 'argv': argv, 'pid': process.pid,
           'start_ticks': ticks, 'epoch': time.time(), 'preflight_sha256': sha(preflight_path),
           'wrapper_sha256': sha(wrapper), 'plan_sha256': sha(plan_path),
           'scope': 'Original five related Linux groups only; actual results required.',
           'status': 'RUNNING_NOT_YET_PASSED'}
with receipt_path.open('x') as out:
    out.write(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
