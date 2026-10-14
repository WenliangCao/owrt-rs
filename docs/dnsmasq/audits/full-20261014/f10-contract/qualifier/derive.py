#!/usr/bin/env python3
"""Requalify existing private archives and calibrate the checker without reruns."""
import argparse
import collections
import copy
import hashlib
import json
from pathlib import Path
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[6] / 'tools/dnsmasq'))
from f10_contract_check import build_manifest, check, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-archive', type=Path, required=True)
    parser.add_argument('--candidate-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with tarfile.open(args.baseline_archive, 'r:gz') as archive:
        reference = json.load(archive.extractfile('private/repeat-c/result.json'))
        controls = [json.load(archive.extractfile('private/' + name + '/result.json'))
                    for name in ('baseline-c', 'extra-repeat-c')]
    with tarfile.open(args.candidate_archive, 'r:gz') as archive:
        candidate = json.load(archive.extractfile('candidate-b99e/result.json'))
    manifest = build_manifest(reference, controls)
    recheck = check(reference, candidate, manifest)
    args.output.mkdir(parents=True, exist_ok=False)

    def write(name, value):
        (args.output / name).write_text(json.dumps(value, indent=2) + '\n')

    write('observed-ptr-order-manifest.json', manifest)
    write('b99e-recheck.json', recheck)
    negatives = []

    def calibrate(name, mutate):
        actual = copy.deepcopy(reference)
        mutate(actual)
        result = check(reference, actual, manifest)
        assert not result['passed'], name
        negatives.append({'name': name, 'expected': 'reject', 'passed': False,
            'failure_counts': dict(collections.Counter(row['kind'] for row in result['failures'])),
            'qualified_ptr_count': len(result['qualified_ptr_order']),
            'actual_document_sha256': digest(actual)})

    def rows(report, case):
        return next(row['observations'] for row in report['cases'] if row['case'] == case)

    def reverse_stable(report):
        # This state has two PTR owners but no C/C order variation in evidence.
        for row in rows(report, 'six-host-record'):
            if row['type'] == 12 and row['name'] == '1.2.0.192.in-addr.arpa':
                row['semantics']['records'].reverse()

    calibrate('observed-c-stable-case-ptr-order-flipped', reverse_stable)
    calibrate('missing-case', lambda report: report['cases'].pop())
    calibrate('missing-ptr-track-observation', lambda report: rows(report, 'six-addn').pop())
    calibrate('same-state-second-ptr-reversed', lambda report:
              rows(report, 'six-default')[1]['semantics']['records'].reverse())

    def splice_phases(report):
        for row in rows(report, 'six-default'):
            if row['type'] == 12 and row['name'] == '1.2.0.192.in-addr.arpa' and '-after-' in row['label']:
                row['semantics']['records'].reverse()

    calibrate('before-after-ptr-track-spliced-across-c-process-orders', splice_phases)
    for field, mutate in (
        ('ttl', lambda row: row['semantics']['records'][0].__setitem__('ttl', 99)),
        ('tc', lambda row: row['semantics'].__setitem__('flags', row['semantics']['flags'] ^ 0x200)),
        ('header', lambda row: row['semantics'].__setitem__('flags', row['semantics']['flags'] ^ 1)),
        ('count', lambda row: row['semantics']['records'].pop()),
        ('rrset', lambda row: row['semantics']['records'][0].__setitem__('data', 'wrong.test'))):
        calibrate('allowed-ptr-state-changed-' + field,
                  lambda report, mutate=mutate: mutate(rows(report, 'six-default')[0]))
    for kind in (1, 28):
        def flip_forward(report, kind=kind):
            row = next(row for row in rows(report, 'ipv6-three-duplicate')
                       if row['type'] == kind and len(row['semantics']['records']) >= 2)
            row['semantics']['records'].reverse()
        calibrate('forward-order-changed-' + str(kind), flip_forward)
    write('negative-controls.json', {'checks': negatives, 'all_rejected': True,
        'reference_document_sha256': digest(reference), 'allow_manifest_sha256': digest(manifest)})
    summary = {'runtime_repeated': False,
        'archives': {name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}
            for name, path in (('baseline', args.baseline_archive), ('candidate', args.candidate_archive))},
        'manifest_tracks': len(manifest['entries']),
        'manifest_states': sum(len(row['allowed_states']) for row in manifest['entries']),
        'b99e_passed': recheck['passed'], 'qualified_ptr_order': len(recheck['qualified_ptr_order']),
        'failure_counts': dict(collections.Counter(row['kind'] for row in recheck['failures'])),
        'failure_cases': dict(collections.Counter(row.get('case') for row in recheck['failures'])),
        'candidate_same_state_repeated_families': sum(len(row['same_state_repeats']) for row in recheck['ptr_sequence_checks']),
        'candidate_same_state_instability': [row for row in recheck['failures'] if row['kind'] == 'same-state-ptr-repeat-instability'],
        'actual_raw_negative_controls': len(negatives),
        'checker_sha256': hashlib.sha256((Path(__file__).resolve().parents[6] / 'tools/dnsmasq/f10_contract_check.py').read_bytes()).hexdigest()}
    write('summary.json', summary)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
