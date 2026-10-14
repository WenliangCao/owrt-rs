#!/usr/bin/env python3
"""Default-deny F10 checker with evidence-scoped PTR order qualifications.

An observed C/C order variation applies only to the same case, question,
transport, state labels and complete ordered query track. It never exempts
RRset/header/TTL/count changes, forward order, or an unobserved PTR state.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re


STOCK_SHA256 = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def unordered(value):
    result = copy.deepcopy(value)
    result['records'] = sorted(json.dumps(rr, sort_keys=True) for rr in result['records'])
    return result


def state(row):
    # Only remove the repeat index. before/after, generation, held/new and
    # transport prefixes remain distinct; no source-state family is generalized.
    return re.sub(r'-[0-9]+$', '', row['label'])


def key(case, row):
    return {'case': case, 'name': row['name'], 'type': row['type'],
            'transport': row['transport']}


def tracks(report):
    result = {}
    for case in report['cases']:
        for row in case['observations']:
            if row['type'] != 12:
                continue
            identity = key(case['case'], row)
            token = json.dumps(identity, sort_keys=True)
            result.setdefault(token, {'key': identity, 'sequence': []})['sequence'].append(
                {'label': row['label'], 'state': state(row), 'semantics': row['semantics']})
    return result


def order_only(left, right):
    return left != right and unordered(left) == unordered(right)


def build_manifest(reference, controls):
    """Allow only PTR states with observed C/C order variation, retaining tracks."""
    for report in (reference, *controls):
        assert report['binary_sha256'] == STOCK_SHA256 and not report.get('errors')
        assert all(row['completed'] and row['exit'] == 0 for row in report['cases'])
    reference_tracks = tracks(reference)
    control_tracks = [tracks(report) for report in controls]
    entries = []
    for token, track in reference_tracks.items():
        sequences = [track['sequence']]
        for alternative in control_tracks:
            if token not in alternative:
                continue
            sequence = alternative[token]['sequence']
            assert [row['label'] for row in sequence] == [row['label'] for row in track['sequence']], token
            assert all(unordered(left['semantics']) == unordered(right['semantics'])
                       for left, right in zip(track['sequence'], sequence)), token
            if sequence not in sequences:
                sequences.append(sequence)
        if len(sequences) < 2:
            continue
        variable_states = sorted({row['state'] for sequence in sequences[1:]
            for original, row in zip(track['sequence'], sequence)
            if original['semantics'] != row['semantics']})
        entries.append({'key': track['key'], 'allowed_states': variable_states,
                        'observed_sequences': sequences})
    return {'schema': 1, 'policy': 'observed-c-c-complete-track-only',
            'c_sha256': STOCK_SHA256, 'reference_document_sha256': digest(reference),
            'control_document_sha256': [digest(report) for report in controls],
            'entries': entries}


def fixture_input(case):
    """Bind service options, files, mutations and the entire ordered query schedule."""
    assert case['argv'][0] == 'chroot'
    return {'case': case['case'], 'service_options': case['argv'][3:],
            'initial_files': case['initial_files'], 'mutations': case['mutations'],
            'queries': [{field: row[field] for field in ('label', 'name', 'type', 'transport', 'request_wire')}
                        for row in case['observations']]}


def source_bound_track(reference, actual, entry):
    """Check the sole reviewed source-derived transformation, across UDP and TCP.

    This does not authorize its use: check() additionally requires an approved
    entry. The alternative sequence is derived only from the exact C reference.
    """
    result = {'contract_id': entry.get('contract_id'), 'matches': False}
    if (entry.get('entry_basis') != 'source-bound'
            or entry.get('contract_id') != 'six-host-record-ptr-initial-order-v1'
            or entry.get('reference_document_sha256') != digest(reference)
            or reference.get('binary_sha256') != STOCK_SHA256):
        return {**result, 'reason': 'source-contract-reference-mismatch'}
    expected = next((row for row in reference['cases'] if row['case'] == 'six-host-record'), None)
    candidate = next((row for row in actual['cases'] if row['case'] == 'six-host-record'), None)
    if expected is None or candidate is None:
        return {**result, 'reason': 'source-contract-case-missing'}
    if (expected.get('process_sha256') != STOCK_SHA256
            or digest(expected) != entry.get('reference_case_sha256')
            or digest(fixture_input(expected)) != entry['fixture_input_sha256']
            or fixture_input(candidate) != fixture_input(expected)):
        return {**result, 'reason': 'source-contract-fixture-mismatch'}
    targets = [row for row in expected['observations']
               if row['name'] == '1.2.0.192.in-addr.arpa' and row['type'] == 12]
    states = [f'{transport}-ptr-{phase}-192.0.2.1'
              for transport in ('udp', 'tcp') for phase in ('before', 'after')]
    labels = [f'{phase}-{repeat}' for phase in states for repeat in range(2)]
    if (entry.get('target_labels') != labels or entry.get('states') != states
            or entry.get('permutations') != [[0, 1], [1, 0]]
            or [row['label'] for row in targets] != labels
            or any(row['semantics']['records'] != entry['reference_records'] for row in targets)):
        return {**result, 'reason': 'source-contract-target-mismatch'}
    if [row['data'] for row in entry['reference_records']] != ['x.test', 'y.test']:
        return {**result, 'reason': 'source-contract-owner-mismatch'}
    for permutation in entry['permutations']:
        sequence = copy.deepcopy(expected['observations'])
        for row in sequence:
            if row['label'] in labels:
                row['semantics']['records'] = [copy.deepcopy(entry['reference_records'][i]) for i in permutation]
        if all(left['semantics'] == right['semantics']
               for left, right in zip(sequence, candidate['observations'])):
            return {**result, 'matches': True, 'permutation': permutation,
                    'target_labels': labels, 'fixture_input_sha256': entry['fixture_input_sha256']}
    return {**result, 'reason': 'cross-transport-complete-case-sequence-mismatch'}


def check(reference, actual, manifest=None, expected_cases=None):
    """Return unqualified failures separately from precisely qualified order rows."""
    failures, qualified = [], []
    if reference.get('errors') or reference.get('binary_sha256') != STOCK_SHA256:
        failures.append({'kind': 'invalid-c-reference'})
    if actual.get('errors'):
        failures.append({'kind': 'runtime-errors', 'errors': actual['errors']})
    allowed = {}
    source_checks = []
    if manifest is not None:
        valid = (manifest.get('schema') == 1
                 and manifest.get('policy') == 'observed-c-c-complete-track-only'
                 and manifest.get('c_sha256') == STOCK_SHA256
                 and manifest.get('reference_document_sha256') == digest(reference))
        if not valid:
            failures.append({'kind': 'allow-manifest-reference-mismatch'})
        else:
            allowed = {json.dumps(entry['key'], sort_keys=True): entry for entry in manifest['entries']}
            for entry in manifest.get('source_bound_entries', []):
                if entry.get('review_status') != 'approved':
                    failures.append({'kind': 'source-bound-entry-not-approved', 'contract_id': entry.get('contract_id')})
                    continue
                source_checks.append(source_bound_track(reference, actual, entry))
    actual_tracks = tracks(actual)
    reference_tracks = tracks(reference)
    sequence_checks = []
    for token, track in actual_tracks.items():
        if token not in reference_tracks:
            continue
        expected_track = reference_tracks[token]['sequence']
        entry = allowed.get(token)
        controls = entry['observed_sequences'] if entry else [expected_track]
        repeats = []
        for phase in dict.fromkeys(row['state'] for row in expected_track):
            expected_repeats = [[row for row in sequence if row['state'] == phase] for sequence in controls]
            if len(expected_repeats[0]) < 2:
                continue
            c_stable = all(all(row['semantics'] == rows[0]['semantics'] for row in rows)
                           for rows in expected_repeats)
            actual_repeats = [row for row in track['sequence'] if row['state'] == phase]
            actual_stable = bool(actual_repeats) and all(
                row['semantics'] == actual_repeats[0]['semantics'] for row in actual_repeats)
            repeats.append({'state': phase, 'count': len(actual_repeats),
                            'all_observed_c_repeats_stable': c_stable,
                            'candidate_repeats_stable': actual_stable})
            if c_stable and not actual_stable:
                failures.append({**track['key'], 'state': phase, 'kind': 'same-state-ptr-repeat-instability'})
        sequence_checks.append({**track['key'], 'observations': len(track['sequence']),
            'complete_sequence_matches_one_c_control': track['sequence'] in controls,
            'same_state_repeats': repeats})
    references = {row['case']: row for row in reference['cases']}
    expected_cases = set(references) if expected_cases is None else set(expected_cases)
    if not expected_cases or not expected_cases.issubset(references):
        failures.append({'kind': 'invalid-expected-cases', 'expected_cases': sorted(expected_cases)})
    seen = set()
    for candidate in actual['cases']:
        case = candidate['case']
        if case in seen or case not in references or case not in expected_cases:
            failures.append({'case': case, 'kind': 'unknown-or-duplicate-case'})
            continue
        seen.add(case)
        if not candidate.get('completed') or candidate.get('exit') != 0:
            failures.append({'case': case, 'kind': 'case-incomplete'})
        expected = references[case]
        if len(expected['observations']) != len(candidate['observations']):
            failures.append({'case': case, 'kind': 'observation-count',
                             'c': len(expected['observations']), 'actual': len(candidate['observations'])})
        for left, right in zip(expected['observations'], candidate['observations']):
            meta = ('label', 'name', 'type', 'transport')
            if any(left[field] != right[field] for field in meta):
                failures.append({'case': case, 'kind': 'observation-state-mismatch',
                                 'c': {field: left[field] for field in meta},
                                 'actual': {field: right[field] for field in meta}})
                continue
            c_value, value = left['semantics'], right['semantics']
            if c_value == value:
                continue
            difference = {'case': case, 'label': right['label'], 'name': right['name'],
                          'type': right['type'], 'transport': right['transport'],
                          'state': state(right), 'c': c_value, 'actual': value}
            difference['kind'] = 'rrset-ttl-count-or-header'
            if order_only(c_value, value):
                difference['kind'] = 'unqualified-ptr-order' if right['type'] == 12 else 'forward-order'
            if difference['kind'] == 'unqualified-ptr-order':
                token = json.dumps(key(case, right), sort_keys=True)
                entry = allowed.get(token)
                sequence = actual_tracks[token]['sequence']
                if entry and state(right) in entry['allowed_states'] and sequence in entry['observed_sequences']:
                    difference['kind'] = 'qualified-observed-ptr-order'
                    difference['sequence_sha256'] = digest(sequence)
                    qualified.append(difference)
                    continue
                source = next((row for row in source_checks if row['matches']
                    and case == 'six-host-record' and right['label'] in row['target_labels']), None)
                if source:
                    difference['kind'] = 'qualified-source-bound-ptr-order'
                    difference['contract_id'] = source['contract_id']
                    qualified.append(difference)
                    continue
                difference['reason'] = ('no-corresponding-c-c-state' if not entry or state(right) not in entry['allowed_states']
                                        else 'complete-query-sequence-not-observed-in-c')
            failures.append(difference)
        if expected.get('dhcp', {}).get('decoded') != candidate.get('dhcp', {}).get('decoded'):
            failures.append({'case': case, 'kind': 'dhcp-decoded',
                             'c': expected.get('dhcp', {}).get('decoded'),
                             'actual': candidate.get('dhcp', {}).get('decoded')})
    if seen != expected_cases:
        failures.append({'kind': 'case-set-mismatch', 'expected_cases': sorted(expected_cases),
                         'actual_cases': sorted(seen)})
    return {'passed': not failures, 'case_count': len(seen),
            'failures': failures, 'qualified_ptr_order': qualified,
            'ptr_sequence_checks': sequence_checks,
            'source_bound_checks': source_checks,
            'raw_order_preserved': True, 'policy': 'default-deny-exact-state-and-complete-track',
            'expected_cases': sorted(expected_cases),
            'elf_identity_scope': 'Candidate ELF identity is verified by the runner, independently of this semantic checker.',
            'reference_document_sha256': digest(reference),
            'actual_document_sha256': digest(actual),
            'allow_manifest_sha256': digest(manifest) if manifest is not None else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--control', type=Path, action='append', default=[])
    parser.add_argument('--actual', type=Path)
    parser.add_argument('--allow-manifest', type=Path)
    parser.add_argument('--case', action='append', help='Explicit expected subset; default requires every reference case.')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    read = lambda path: json.loads(path.read_text())
    reference = read(args.reference)
    if args.control:
        assert args.actual is None and args.allow_manifest is None and args.case is None
        result = build_manifest(reference, [read(path) for path in args.control])
    else:
        assert args.actual is not None
        result = check(reference, read(args.actual), read(args.allow_manifest) if args.allow_manifest else None, args.case)
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    return int(result.get('passed') is False)


if __name__ == '__main__':
    raise SystemExit(main())
