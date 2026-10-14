#!/usr/bin/env python3
"""Read-only revalidation of the fresh FIX7 build and its frozen inputs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert not args.out.exists()
    repo = Path(__file__).resolve().parents[6]
    build = Path(__file__).resolve().parent
    current = read(build / 'local-input-identity.json')
    retained = read(build / 'retained-input-identity.json')
    report = read(build / 'result.json')
    oracle_root = '/home/ubuntu/dnsmasq-audit-fix7-20261014'
    expected = {}
    sources = dict(retained)
    sources['current'] = dict(commit=current['head'], source=oracle_root + '/source',
                              source_inputs=current['source_inputs'])
    git_counts = {}
    for role, item in sources.items():
        for name, digest in item['source_inputs'].items():
            blob = subprocess.check_output(['git', 'show', item['commit'] + ':' + name], cwd=repo)
            assert sha(blob) == digest, (role, name, 'Git')
            expected[item['source'] + '/' + name] = digest
        git_counts[role] = len(item['source_inputs'])
    spec = importlib.util.spec_from_file_location('package', repo / 'tools/dnsmasq/build_package.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    assert package.inputs(repo) == current['source_inputs']
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip() == current['head']
    assert subprocess.check_output(['git', 'rev-parse', 'main'], cwd=repo, text=True).strip() == current['main']
    expected.update(read(build / 'invocations.json')['verified_files'])
    for name, row in report['retained_artifacts'].items():
        expected[row['path']] = row['sha256']
    for directory, manifest in [('release', report['release_build']), ('tests', report['test_build'])]:
        for row in manifest['artifacts']:
            expected[oracle_root + '/private/' + directory + '/' + row['path']] = row['sha256']
    for name, digest in report['release_build_logs'].items():
        expected[oracle_root + '/private/release/' + name] = digest
    for row in report['commands']:
        assert row['exit'] == 0
        expected[oracle_root + '/private/' + row['name'] + '.log'] = row['log_sha256']
    assert report['complete'] and report['source_postcheck_passed']
    expected[oracle_root + '/private/build-verification.json'] = sha((build / 'result.json').read_bytes())
    remote = '''
import hashlib, json, pathlib
def digest(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
expected = EXPECTED
actual = {path: digest(path) for path in expected}
assert actual == expected, [path for path in expected if actual[path] != expected[path]]
root = pathlib.Path('/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93')
identity = json.loads((root.parent / 'identity.json').read_text())
assert identity['recipe_revision'] == 'f0a60eee2fe051741c643ea6118718aae1ef17fb'
assert all(digest(root / path) == value for path, value in identity['patched_files'].items())
print(json.dumps({'verified_file_count': len(actual), 'files': actual,
 'reference_files_verified': len(identity['patched_files']),
 'reference_identity_sha256': digest(root.parent / 'identity.json'),
 'rfc1035_sha256': digest(root / 'src/rfc1035.c')}))
'''.replace('EXPECTED', repr(expected))
    result = subprocess.run(['ssh', 'oracle', 'python3 -'], input=remote, text=True,
                            capture_output=True, check=True)
    remote_result = json.loads(result.stdout)
    preserved = {str(p.relative_to(repo)): sha(p.read_bytes())
                 for p in sorted((repo / 'docs/prompts').glob('*.md'))}
    assert preserved == read(build / 'prompt-before.json'), 'pre-existing prompt file changed'
    result = {'checked_at_unix': time.time(), 'head': current['head'], 'main': current['main'],
              'baseline': current['baseline'], 'git_input_counts': git_counts,
              'worktree_input_match': True, 'source_digest': current['source_digest'],
              'retained_build_complete': True, 'oracle': remote_result,
              'prompt_files_preserved': preserved,
              'checker_sha256': sha(Path(__file__).read_bytes())}
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('head', 'git_input_counts', 'worktree_input_match')}))
    print('Oracle files verified:', remote_result['verified_file_count'])


if __name__ == '__main__':
    main()
