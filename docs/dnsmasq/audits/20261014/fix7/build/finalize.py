#!/usr/bin/env python3
"""Collect derived receipts and independently bind remote audit outputs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

repo = Path(__file__).resolve().parents[6]
out = Path(__file__).resolve().parent
root = '/home/ubuntu/dnsmasq-audit-fix7-20261014'
source = root + '/source'
private = root + '/private'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(name):
    return json.loads((out / name).read_text())

for remote, local in [('private/build-verification.json', 'result.json'),
                      ('private/build-relro/result.json', 'relro.json')]:
    subprocess.run(['scp', 'oracle:' + root + '/' + remote, str(out / local)], check=True)
report = read('result.json')
assert report['complete'] and report['source_postcheck_passed']
assert read('relro.json')['passed']
current = read('local-input-identity.json')
spec = importlib.util.spec_from_file_location('package', repo / 'tools/dnsmasq/build_package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
assert package.inputs(repo) == current['source_inputs']
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip() == current['head']
assert subprocess.check_output(['git', 'rev-parse', 'main'], cwd=repo, text=True).strip() == current['main']
verified = {source + '/' + name: sha(repo / name) for name in (
    'tools/dnsmasq/oracle_build.sh', 'tools/dnsmasq/run_isolated.sh',
    'tools/dnsmasq/m2_rootfs.py',
    'docs/dnsmasq/audits/20261011/independent/build_protections_probe.py')}
verified.update({private + '/' + name: sha(out / name) for name in (
    'verify_and_test.py', 'local-input-identity.json', 'retained-input-identity.json')})
verified[private + '/dnsmasq-fix7-02659da6.tar'] = read('archive.json')['archive_sha256']
verified[private + '/build-relro/result.json'] = sha(out / 'relro.json')
remote = '''import hashlib,json,pathlib
expected=EXPECTED
assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==v for p,v in expected.items())
root=pathlib.Path(ROOT)
files=[p for p in (root/'private/build-relro').iterdir() if p.is_file()]
files += [root/'private/tests'/name for name in ('build.json','build.log','build.stdout','clean.log','clean.stdout')]
files += [root/'private'/name for name in ('release-driver.stdout','release-driver.stderr','verify-driver.stdout','verify-driver.stderr','relro-driver.stdout','relro-driver.stderr')]
print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}))
'''.replace('EXPECTED', repr(verified)).replace('ROOT', repr(root))
p = subprocess.run(['ssh', 'oracle', 'python3 -'], input=remote, text=True, capture_output=True, check=True)
verified.update(json.loads(p.stdout))
result = {'verified_files': verified, 'argv': {
    'release_build': ['sh', source + '/tools/dnsmasq/oracle_build.sh', source, private + '/release', 'release'],
    'verify_and_test': ['python3', private + '/verify_and_test.py', root,
                        private + '/local-input-identity.json', private + '/retained-input-identity.json'],
    'relro': ['sudo', '-n', 'sh', source + '/tools/dnsmasq/run_isolated.sh', 'python3',
              source + '/docs/dnsmasq/audits/20261011/independent/build_protections_probe.py', source,
              private + '/release/dnsmasq-rs', private + '/build-relro', '--image-root',
              '/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files', '--require-relro']},
    'local_postcheck': {'head': current['head'], 'main': current['main'],
                       'input_count': len(current['source_inputs']), 'git_worktree_mismatches': []}}
(out / 'invocations.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'complete': report['complete'], 'commands': report['commands'], 'verified_file_count': len(verified)}, indent=2))
