#!/usr/bin/env python3
"""Freeze Git product inputs and upload an immutable audit snapshot to Oracle."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[6]
out = Path(__file__).resolve().parent
oracle = '/home/ubuntu/dnsmasq-audit-fix7-20261014'
head = '02659da6f35fb60ccc916a28b8abf761bf51913c'

def git(*args):
    return subprocess.check_output(['git', *args], cwd=repo)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def write(name, data):
    path = out / name
    assert not path.exists(), path
    path.write_text(json.dumps(data, indent=2) + '\n')

assert git('rev-parse', 'HEAD').decode().strip() == head
baseline = git('rev-parse', '137c2882').decode().strip()
main = git('rev-parse', 'main').decode().strip()
spec = importlib.util.spec_from_file_location('package', repo / 'tools/dnsmasq/build_package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
inputs = package.inputs(repo)
assert len(inputs) == 178
mismatches = [name for name, value in inputs.items() if digest(git('show', head + ':' + name)) != value]
assert not mismatches
identity = dict(head=head, baseline=baseline, main=main, source_inputs=inputs,
                source_digest=digest(json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode()),
                git_worktree_mismatches=mismatches)
write('local-input-identity.json', identity)
retained6 = json.loads((out.parents[1] / 'fix6/build/retained-input-identity.json').read_text())
before6 = json.loads((out.parents[1] / 'fix6/build/local-input-identity.json').read_text())
retained = {'main': retained6['main'],
            'before': dict(commit=baseline, source='/home/ubuntu/dnsmasq-audit-fix6-20261014/source',
                           source_inputs=before6['source_inputs'], source_digest=before6['source_digest'])}
assert retained['main']['commit'] == main
for role, row in retained.items():
    assert all(digest(git('show', row['commit'] + ':' + name)) == value
               for name, value in row['source_inputs'].items()), role
write('retained-input-identity.json', retained)
write('prompt-before.json', {str(p.relative_to(repo)): digest(p.read_bytes())
      for p in sorted((repo / 'docs/prompts').glob('*.md'))})
archive = Path('/tmp/dnsmasq-fix7-02659da6.tar')
assert not archive.exists()
with archive.open('wb') as f:
    subprocess.run(['git', 'archive', head], cwd=repo, stdout=f, check=True)
write('archive.json', dict(archive_path=str(archive), archive_sha256=digest(archive.read_bytes()),
                          archive_bytes=archive.stat().st_size, archive_argv=['git', 'archive', head],
                          input_enumeration='build_package.inputs(root), exactly matched frozen Git blobs',
                          oracle_root=oracle, python_version=sys.version))
subprocess.run(['ssh', 'oracle', 'test ! -e ' + oracle + '/source && test ! -e ' + oracle +
                '/private && mkdir -p ' + oracle + '/source ' + oracle + '/private'], check=True)
subprocess.run(['scp', str(archive), 'oracle:' + oracle + '/private/'], check=True)
subprocess.run(['scp', str(out / 'local-input-identity.json'), str(out / 'retained-input-identity.json'),
                str(out / 'verify_and_test.py'), 'oracle:' + oracle + '/private/'], check=True)
subprocess.run(['ssh', 'oracle', 'tar -xf ' + oracle + '/private/' + archive.name + ' -C ' + oracle + '/source'], check=True)
remote = '''import hashlib,json,pathlib
root=pathlib.Path(ORACLE)
identity=json.loads((root/'private/local-input-identity.json').read_text())
assert all(hashlib.sha256((root/'source'/name).read_bytes()).hexdigest()==value for name,value in identity['source_inputs'].items())
print(json.dumps({'source_ready':True,'count':len(identity['source_inputs']),'source_digest':identity['source_digest']}))
'''.replace('ORACLE', repr(oracle))
subprocess.run(['ssh', 'oracle', 'python3 -'], input=remote, text=True, check=True)
