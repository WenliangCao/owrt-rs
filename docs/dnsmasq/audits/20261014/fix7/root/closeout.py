#!/usr/bin/env python3
"""Bind final derived receipts to Oracle files and check only this audit's resources."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

here = Path(__file__).resolve().parent
evidence, repo = here.parent, here.parents[5]
root = '/home/ubuntu/dnsmasq-audit-fix7-20261014'
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
read = lambda path: json.loads(Path(path).read_text())
start = read(here / 'local-start.json')
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip() == start['head']
assert subprocess.check_output(['git', 'rev-parse', 'main'], cwd=repo, text=True).strip() == start['main']
assert {str(p.relative_to(repo)): sha(p) for p in sorted((repo / 'docs/prompts').glob('*.md'))} == start['prompt_sha256']
identity = read(here / 'identity-final.json')
assert identity['head'] == start['head'] and identity['worktree_input_match']
expected = {}
for run in read(here / 'boundary-invocation.json')['runs']:
    assert run['exit'] == 0
    expected.update(run['files'])
for local, remote in [
    ('root/run_boundary.py', 'tooling/root/run_boundary.py'),
    ('root/check_boundary.py', 'tooling/root/check_boundary.py'),
    ('root/boundary-invocation.json', 'private/boundary/invocation.json'),
    ('root/boundary-checked.json', 'private/boundary/checked.json'),
    ('regression/final-checked.json', 'private/regression/final-checked.json'),
    ('regression/inspection.json', 'private/regression/inspection.json'),
    ('regression/calibration.json', 'private/regression/calibration.json'),
    ('regression/invocations.json', 'private/regression/invocations.json'),
    ('negative/checked.json', 'private/negative/retry100/checked.json'),
    ('negative/large-soa-checked.json', 'private/negative/large-soa-valid/checked.json'),
    ('negative/large-soa-exploration.json', 'private/negative/large-soa/checked.json'),
    ('negative/repeat-soa-checked.json', 'private/negative/repeat-soa/checked.json'),
    ('negative/initial-attempt.json', 'private/negative/initial-attempt.json'),
    ('negative/calibration.json', 'private/negative/calibration.json'),
]:
    expected[root + '/' + remote] = sha(evidence / local)
for group in read(evidence / 'regression/final-checked.json')['groups'].values():
    expected[group['execution']['log_private_path']] = group['execution']['log_sha256']
for group in read(here / 'boundary-checked.json')['groups']:
    expected[group['raw_private_path']] = group['raw_sha256']
fixture = read(here / 'boundary-checked.json')['original_fix6_fixture_match']
expected[fixture['raw_private_path']] = fixture['raw_sha256']
expected[root + '/private/release/dnsmasq-rs'] = 'e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9'
remote = '''
import hashlib,json,os,pathlib
expected = EXPECTED
actual = {p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in expected}
assert actual == expected, [p for p in expected if actual[p] != expected[p]]
prefix = ROOT + '/'
owned = []
for proc in pathlib.Path('/proc').iterdir():
    if not proc.name.isdigit() or int(proc.name) == os.getpid(): continue
    links = {}
    for kind in ('root', 'exe', 'cwd'):
        try: value = os.readlink(proc / kind)
        except (FileNotFoundError, ProcessLookupError, PermissionError): continue
        if value == prefix.rstrip('/') or value.startswith(prefix): links[kind] = value
    try: command = (proc / 'cmdline').read_bytes().replace(b'\\0', b' ').decode(errors='replace')
    except (FileNotFoundError, ProcessLookupError, PermissionError): command = ''
    if prefix in command: links['command'] = command
    if links: owned.append({'pid': int(proc.name), 'references': links})
mounts = [line for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if prefix in line]
assert not owned and not mounts, (owned, mounts)
print(json.dumps({'verified_files': actual, 'task_processes': owned, 'task_mounts': mounts,
 'scope': 'Only this audit root; no other Oracle task inspected beyond path matching or changed.'}))
'''.replace('EXPECTED', repr(expected)).replace('ROOT', repr(root))
argv = ['ssh', 'oracle', 'sudo -n python3 -']
done = subprocess.run(argv, input=remote, text=True, capture_output=True, check=True)
result = {'checked_at_unix': time.time(), 'head': start['head'], 'main': start['main'],
          'argv': argv, 'oracle': json.loads(done.stdout), 'prompt_files_unchanged': True,
          'identity_final_sha256': sha(here / 'identity-final.json'), 'checker_sha256': sha(__file__)}
(here / 'closeout.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'verified_files': len(expected), 'task_processes': [], 'task_mounts': [],
                  'prompt_files_unchanged': True}))
