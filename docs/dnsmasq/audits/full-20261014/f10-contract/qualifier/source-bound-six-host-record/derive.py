#!/usr/bin/env python3
"""Build a proposed single-case source contract from C and exact source only."""
import argparse
import collections
import copy
import hashlib
import json
from pathlib import Path
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[7] / 'tools/dnsmasq'))
from f10_contract_check import STOCK_SHA256, check, digest, fixture_input

SIX = ('192.0.2.2 old.test\n192.0.2.1 x.test\n192.0.3.186 a.test\n'
       '192.0.3.185 a.test\n192.0.2.1 y.test\n192.0.2.2 y.test\n')
SOURCE_HASHES = {
    'cache.c': '51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c',
    'dnsmasq.c': 'd4bb7cde522376200a0293427b0812625ebc457f10dc9d3e2bef243ccba8ccd1',
    'rfc1035.c': '231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-archive', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--observed-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    with tarfile.open(args.baseline_archive, 'r:gz') as archive:
        reference = json.load(archive.extractfile('private/repeat-c/result.json'))
    manifest = json.loads(args.observed_manifest.read_text())
    identity = json.loads((args.source_dir / 'identity.json').read_text())
    for name, expected in SOURCE_HASHES.items():
        assert sha(args.source_dir / 'src' / name) == expected
        assert identity['patched_files']['src/' + name] == expected
    assert reference['binary_sha256'] == STOCK_SHA256
    assert manifest['reference_document_sha256'] == digest(reference)
    case = next(row for row in reference['cases'] if row['case'] == 'six-host-record')
    assert case['process_sha256'] == STOCK_SHA256 and case['completed'] and case['exit'] == 0
    options = case['argv'][3:]
    fixture_options = ['--host-record=' + ','.join(line.split()[1:] + line.split()[:1])
                       for line in SIX.splitlines()]
    assert [arg for arg in options if arg.startswith('--host-record=')][1:] == fixture_options
    assert case['initial_files'] == {} and case['mutations'] == [] and len(case['observations']) == 28
    states = [f'{transport}-ptr-{phase}-192.0.2.1'
              for transport in ('udp', 'tcp') for phase in ('before', 'after')]
    labels = [f'{state}-{repeat}' for state in states for repeat in range(2)]
    targets = [row for row in case['observations'] if row['label'] in labels]
    records = targets[0]['semantics']['records']
    assert len(targets) == 8 and [row['data'] for row in records] == ['x.test', 'y.test']
    assert all(row['semantics']['records'] == records for row in targets)
    evidence = {'source_identity_sha256': sha(args.source_dir / 'identity.json'),
        'package': identity['package'], 'version': identity['version'], 'openwrt': identity['openwrt'],
        'recipe_revision': identity['recipe_revision'], 'upstream_archive_sha256': identity['archive_sha256'],
        'exact_c_elf_sha256': STOCK_SHA256,
        'files': {name: {'sha256': value} for name, value in SOURCE_HASHES.items()},
        'anchors': [
            {'file': 'cache.c', 'lines': [38, 43], 'claim': 'typestr contains type plus name pointer and is also the hash mixing table.'},
            {'file': 'cache.c', 'lines': [295, 309], 'claim': 'hash_bucket reads raw typestr bytes, including relocated pointer bytes.'},
            {'file': 'cache.c', 'lines': [312, 341], 'claim': 'Hash-chain placement preserves reverse/immortal flag classes.'},
            {'file': 'cache.c', 'lines': [1174, 1231], 'claim': 'Forward lookup rotates only records with matching reverse/immortal flag class.'},
            {'file': 'cache.c', 'lines': [1262, 1317], 'claim': 'PTR lookup enumerates reverse records in bucket/chain order without moving the hash links.'},
            {'file': 'cache.c', 'lines': [1322, 1385], 'claim': 'Bulk reverse ownership and name-lookup temporary next links define the two-owner fixture.'},
            {'file': 'cache.c', 'lines': [1640, 1666], 'claim': 'Configured host-records use the same bulk add_hosts_entry path.'},
            {'file': 'rfc1035.c', 'lines': [1939, 1989], 'claim': 'Wire PTR records are emitted in cache_find_by_addr order.'},
            {'file': 'dnsmasq.c', 'lines': [2104, 2197], 'claim': 'Non-debug TCP handling forks the current parent address space before tcp_request.'},
        ]}
    entry = {'entry_basis': 'source-bound', 'review_status': 'proposed',
        'contract_id': 'six-host-record-ptr-initial-order-v1',
        'scope': {'case': 'six-host-record', 'name': '1.2.0.192.in-addr.arpa', 'type': 12,
                  'transports': ['udp', 'tcp'], 'source': 'host-record bulk initial load'},
        'reference_document_sha256': digest(reference), 'reference_case_sha256': digest(case),
        'fixture_text': SIX, 'fixture_text_sha256': hashlib.sha256(SIX.encode()).hexdigest(),
        'fixture_input_sha256': digest(fixture_input(case)), 'fixture_input': fixture_input(case),
        'states': states, 'target_labels': labels, 'reference_records': records,
        'permutations': [[0, 1], [1, 0]],
        'transformation_scope': 'One permutation uniformly across all eight target observations, both transports and every phase; other observations unchanged.',
        'derivation_inputs': 'Exact C reference, exact source identity and explicit six-row fixture only; no candidate response input.',
        'source_evidence': evidence,
        'invariants': ['Exactly two .1 owners, x.test and y.test, with unchanged full record fields.',
                       'y.test has one reverse and one non-reverse record; A lookup cannot rotate across those flag classes.',
                       'No x.test/a.test forward queries, DHCP, HUP, inotify or generation mutation in this case.',
                       'PTR lookup changes temporary next links, not hash-chain order.',
                       'TCP inherits the unchanged parent initial namehash placement; one order applies across UDP and TCP.']}
    proposal = copy.deepcopy(manifest)
    proposal['source_bound_entries'] = [entry]
    assert not check(reference, reference, proposal)['passed']
    # Validation activates the proposed transformation only in a local synthetic
    # copy. It does not approve the proposal or classify any real candidate.
    validation_manifest = copy.deepcopy(proposal)
    validation_manifest['source_bound_entries'][0]['review_status'] = 'approved'
    alternative = copy.deepcopy(reference)
    alternative_case = next(row for row in alternative['cases'] if row['case'] == 'six-host-record')
    for row in alternative_case['observations']:
        if row['label'] in labels:
            row['semantics']['records'].reverse()
    positive = check(reference, alternative, validation_manifest)
    assert positive['passed'] and len(positive['qualified_ptr_order']) == 8
    negatives = []

    def calibrate(name, mutate):
        actual = copy.deepcopy(alternative)
        actual_case = next(row for row in actual['cases'] if row['case'] == 'six-host-record')
        mutate(actual_case)
        result = check(reference, actual, validation_manifest)
        assert not result['passed'], name
        negatives.append({'name': name, 'expected': 'reject', 'passed': False,
            'failure_counts': dict(collections.Counter(row['kind'] for row in result['failures']))})

    for mode in ('udp', 'after', 'one-repeat'):
        def splice(case, mode=mode):
            for row in case['observations']:
                if row['label'] not in labels:
                    continue
                selected = (row['transport'] == 'udp' if mode == 'udp' else
                            '-after-' in row['label'] if mode == 'after' else row['label'] == labels[1])
                if selected:
                    row['semantics']['records'].reverse()
        calibrate('cross-transport-phase-repeat-splice-' + mode, splice)
    calibrate('unknown-case', lambda case: case.__setitem__('case', 'unreviewed-case'))
    calibrate('changed-service-input', lambda case: case['argv'].append('--no-round-robin'))
    for mode in ('ttl', 'header', 'tc', 'count', 'rrset', 'forward'):
        def mutate(case, mode=mode):
            row = case['observations'][0]['semantics']
            if mode == 'ttl': row['records'][0]['ttl'] += 1
            elif mode in ('header', 'tc'): row['flags'] ^= 1 if mode == 'header' else 0x200
            elif mode == 'count': row['records'].pop()
            elif mode == 'rrset': row['records'][0]['data'] = 'wrong.test'
            else: next(row for row in case['observations'] if row['type'] == 1)['semantics']['records'].reverse()
        calibrate('changed-' + mode, mutate)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, value in [('entry.proposed.json', entry), ('manifest.proposed.json', proposal),
                        ('source-evidence.json', evidence), ('negative-controls.json', {'proposed_does_not_activate': True,
                         'synthetic_c_uniform_reverse_qualifies': True, 'negative_controls': negatives,
                         'real_candidate_evaluated': False})]:
        (args.output / name).write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({'status': 'proposed', 'states': len(states), 'targets': len(labels),
                      'negative_controls': len(negatives), 'fixture_sha256': entry['fixture_text_sha256'],
                      'input_sha256': entry['fixture_input_sha256']}))


if __name__ == '__main__':
    main()
