#!/usr/bin/env python3
"""Verify and derive the final build receipt without starting workloads."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def receipt(path):
    path = Path(path)
    return {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--phase', default='final')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    private, phase = args.root / 'private', args.phase
    identity_path = private / f'source-{phase}-identity.json'
    controller_path = private / f'build-{phase}-result.json'
    identity, controller = read(identity_path), read(controller_path)
    assert controller['passed'] and controller['ordinary_units']['failed'] == 0
    assert controller['ordinary_units']['passed'] >= 846
    assert controller['source_digest'] == identity['source_digest']
    sdk = []
    for stage in ('acquire', 'verify'):
        path = private / f'sdk-{stage}-{phase}/manifest.json'
        manifest = read(path)
        assert manifest['source_build_passed'] and not manifest['frozen_elf']
        assert all(manifest[key] for key in ('sdk_inputs_unchanged', 'source_inputs_unchanged', 'sdk_recipe_restored'))
        assert manifest['source_digest'] == identity['source_digest']
        assert not manifest.get('error')
        if manifest.get('budget_error'):
            assert manifest['failure_boundary'] == 'size-target'
        for key in ('elf', 'artifact'):
            assert sha(manifest[key]['path']) == manifest[key]['sha256']
        omitted = {'source_files', 'prepared_source_files', 'sdk', 'payload_files'}
        row = {key: value for key, value in manifest.items() if key not in omitted}
        row.update(manifest=receipt(path), source_input_count=len(manifest['source_files']),
                   sdk_input_count=len(manifest['sdk']['files']),
                   sdk_archive_sha256=manifest['sdk']['archive_sha256'],
                   logs={name: receipt(path.parent / name) for name in
                         ('prepare.log', 'compile.log', 'elf-readelf.log', 'apk-metadata.log', 'sstrip-check.log')})
        sdk.append(row)
    assert sdk[0]['elf']['sha256'] == sdk[1]['elf']['sha256']
    assert sdk[0]['artifact']['sha256'] == sdk[1]['artifact']['sha256']
    assert sdk[1]['artifact_identity_verified'] and sdk[1]['apk_byte_identical']
    report = {'schema': 'dnsmasq-fix4-build-v1', 'source_commit': identity['source_commit'],
              'source_digest': identity['source_digest'], 'source_input_count': len(identity['source_files']),
              'source_identity': receipt(identity_path), 'controller': controller,
              'controller_result': receipt(controller_path),
              'invocation': receipt(private / f'build-{phase}-invocation.json'),
              'release': read(private / f'release-{phase}/build.json'),
              'tests': read(private / f'tests-{phase}/build.json'), 'sdk': sdk,
              'summary': {'ordinary_units': controller['ordinary_units'], 'sdk_source_builds': 2,
                          'standard_and_map_clean_rebuild_elf_apk_identical': True,
                          'original_size_budget_passed': not sdk[0].get('budget_error'),
                          'physical_router': False, 'deployed': False},
              'collector': receipt(__file__)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'summary': report['summary'], 'output': receipt(args.out)}))


if __name__ == '__main__':
    main()
