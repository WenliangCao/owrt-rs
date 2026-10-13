#!/usr/bin/env python3
"""Archive one committed source revision and verify every product input."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--phase', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert re.fullmatch(r'[a-z][a-z0-9-]*', args.phase)
    source = args.repo.resolve()
    commit = subprocess.check_output(['git', 'rev-parse', args.commit + '^{commit}'], cwd=source, text=True).strip()
    spec = importlib.util.spec_from_file_location('package_build', source / 'tools/dnsmasq/build_package.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    source_files = package.inputs(source)
    for name, digest in source_files.items():
        data = subprocess.check_output(['git', 'show', commit + ':' + name], cwd=source)
        assert hashlib.sha256(data).hexdigest() == digest, name
    args.out.mkdir(parents=True, exist_ok=False)
    archive = args.out / ('source-' + args.phase + '.tar')
    subprocess.run(['git', 'archive', '--format=tar', '--output', str(archive), commit], cwd=source, check=True)
    identity = {'phase': args.phase, 'source_commit': commit, 'product_tip': commit,
                'source_date_epoch': subprocess.check_output(['git', 'show', '-s', '--format=%ct', commit], cwd=source, text=True).strip(),
                'source_files': source_files, 'source_input_count': len(source_files),
                'source_digest': hashlib.sha256(json.dumps(source_files, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'source_archive_sha256': sha(archive), 'source_archive_bytes': archive.stat().st_size,
                'all_inputs_match_git_blobs': True, 'archive_scope': 'git archive of the full committed revision',
                'freeze_driver_sha256': sha(__file__)}
    (args.out / ('source-' + args.phase + '-identity.json')).write_text(json.dumps(identity, indent=2) + '\n')
    print(json.dumps({key: value for key, value in identity.items() if key != 'source_files'}))


if __name__ == '__main__':
    main()
