#!/usr/bin/env python3
"""Verify retained boundary/protection evidence and task-owned resource cleanup."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

here = Path(__file__).resolve().parent
evidence = here.parent
repo = here.parents[5]
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
read = lambda path: json.loads(path.read_text())
out = Path(sys.argv[1])
assert not out.exists()
old = read(evidence / 'build/new-boundary-invocations.json')
expected = dict(old['verified_oracle_files'])
for result in read(evidence / 'build/new-boundary-result.json')['checks']:
    path = old['local_to_oracle_inputs'][result['input']]
    assert result['input_sha256'] == expected[path]
root = '/home/ubuntu/dnsmasq-audit-fix6-20261014'
expected[root + '/private/build-relro/result.json'] = sha(evidence / 'build/relro.json')
expected.update(read(here / 'boundary-invocation.json')['files'])
expected[root + '/private/root-release-recheck/dnsmasq-rs'] = 'a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66'
package = read(evidence / 'build/package-tests.json')
assert package['exit'] == 0
assert all(sha(repo / name) == digest for name, digest in package['inputs'].items())
before = read(here / 'identity-before.json')
after = read(here / 'identity-after.json')
assert before['prompt_files_preserved'] == after['prompt_files_preserved']
assert before['oracle']['files'] == after['oracle']['files']
remote = '''
import hashlib, json, os, pathlib
expected = EXPECTED
actual = {path: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() for path in expected}
assert actual == expected
prefix = '/home/ubuntu/dnsmasq-audit-fix6-20261014/'
processes = []
for proc in pathlib.Path('/proc').iterdir():
    if not proc.name.isdigit() or int(proc.name) == os.getpid(): continue
    links = {}
    for kind in ('root', 'exe', 'cwd'):
        try: value = os.readlink(proc / kind)
        except (FileNotFoundError, ProcessLookupError, PermissionError): continue
        if value == prefix.rstrip('/') or value.startswith(prefix): links[kind] = value
    if links: processes.append({'pid': int(proc.name), 'links': links})
mounts = [line for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if prefix in line]
assert not processes and not mounts, (processes, mounts)
print(json.dumps({'verified_files': actual, 'task_processes': processes, 'task_mounts': mounts,
 'scope': 'Only this audit root, located via proc root/exe/cwd and host mountinfo; other Oracle tasks untouched.'}))
'''.replace('EXPECTED', repr(expected))
argv = ['ssh', 'oracle', 'sudo -n python3 -']
result = subprocess.run(argv, input=remote, text=True, capture_output=True, check=True)
receipt = {'checked_at_unix': time.time(), 'argv': argv, 'oracle': json.loads(result.stdout),
           'product_inputs_and_retained_artifacts_unchanged': True,
           'prompt_files_unchanged': True, 'package_test_inputs_match': True,
           'retained_boundary_result_sha_mappings_match': True,
           'checker_sha256': sha(Path(__file__))}
out.write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({key: value for key, value in receipt.items() if key != 'oracle'}))
