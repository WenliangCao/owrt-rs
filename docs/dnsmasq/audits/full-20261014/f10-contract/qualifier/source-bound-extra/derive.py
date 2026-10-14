#!/usr/bin/env python3
"""Propose three fixed source contracts using only exact C and matching source."""
import argparse
import collections
import copy
import hashlib
import json
from pathlib import Path
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[7] / 'tools/dnsmasq'))
from f10_contract_check import STOCK_SHA256, check, digest, fixture_input, source_bound_spec

CONTRACTS = ('six-hostsdir-initial-ptr-initial-order-v1',
             'leases-dhcp-ptr-initial-order-v1', 'ipv6-repeated-ptr-initial-order-v1')
SIX = ('192.0.2.2 old.test\n192.0.2.1 x.test\n192.0.3.186 a.test\n'
       '192.0.3.185 a.test\n192.0.2.1 y.test\n192.0.2.2 y.test\n')
V6 = ('2001:db8::2 old6.test\n2001:db8::1 x6.test\n2001:db8::bc a6.test\n'
      '2001:db8::bb a6.test\n2001:db8::1 y6.test\n2001:db8::2 y6.test\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-archive', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--observed-manifest', type=Path, required=True)
    parser.add_argument('--source-evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    with tarfile.open(args.baseline_archive, 'r:gz') as archive:
        reference = json.load(archive.extractfile('private/repeat-c/result.json'))
    manifest = json.loads(args.observed_manifest.read_text())
    identity = json.loads((args.source_dir / 'identity.json').read_text())
    evidence = json.loads(args.source_evidence.read_text())
    for name in ('cache.c', 'dnsmasq.c', 'rfc1035.c', 'inotify.c', 'lease.c'):
        value = sha(args.source_dir / 'src' / name)
        assert identity['patched_files']['src/' + name] == value
        if name in evidence['files']:
            assert evidence['files'][name]['sha256'] == value
        evidence['files'][name] = {'sha256': value}
    assert evidence['files']['inotify.c']['sha256'] == '6a5b0239b9c9fbb1ca0bf638e18efd32914c88d4899602c030b23cf8221b96a7'
    assert evidence['files']['lease.c']['sha256'] == '4260039af27b40084cbe6dbbae2bb9417fa3a91806ea53f3f6bdd20234cad763'
    assert manifest['reference_document_sha256'] == digest(reference)
    evidence['anchors'] += [
        {'file': 'cache.c', 'lines': [1436, 1541], 'claim': 'Hosts parsing sets IPv4 or IPv6 flags and invokes bulk insertion; rehash belongs to hosts loading.'},
        {'file': 'cache.c', 'lines': [1716, 1720], 'claim': 'Hostsdir initial scan receives the bulk reverse-hash storage.'},
        {'file': 'inotify.c', 'lines': [193, 253], 'claim': 'Initial directory scan passes that bulk state to read_hostsfile.'},
        {'file': 'cache.c', 'lines': [1742, 1755], 'claim': 'DHCP refresh unlinks only F_DHCP nodes; static x/y remain linked in relative order.'},
        {'file': 'cache.c', 'lines': [1758, 1836], 'claim': 'DHCP publication looks up the new lease hostname/address then inserts the new node; unrelated x/y nodes are not permuted.'},
        {'file': 'cache.c', 'lines': [1846, 1912], 'claim': 'Non-terminal maintenance concerns the new name and suffix nodes, not these x/y addresses.'},
        {'file': 'lease.c', 'lines': [564, 618], 'claim': 'Lease DNS update republishes lease/FQDN names via cache_add_dhcp_entry; it does not rehash the static table.'},
    ]
    entries, negatives = [], []
    for contract in CONTRACTS:
        spec = source_bound_spec(contract)
        case = next(row for row in reference['cases'] if row['case'] == spec['case'])
        assert case['process_sha256'] == STOCK_SHA256 and case['completed'] and case['exit'] == 0
        assert case['mutations'] == []
        files = case['initial_files']
        fixture = V6 if case['case'] == 'ipv6-repeated-ptr' else SIX
        assert fixture in files.values()
        assert len(case['observations']) == (46 if case['case'] == 'leases-dhcp' else 28)
        if case['case'] == 'leases-dhcp':
            assert '0 02:00:00:00:00:02 127.0.0.31 restored *\n' in files.values()
            assert case['dhcp']['decoded']['hostname'] == 'lease' and case['dhcp']['decoded']['yiaddr'] == '127.0.0.30'
        targets = [row for row in case['observations'] if row['label'] in spec['target_labels']]
        records = targets[0]['semantics']['records']
        assert sorted(row['data'] for row in records) == spec['owners']
        assert len(targets) == len(spec['target_labels'])
        assert all(row['semantics']['records'] == records for row in targets)
        entry = {'entry_basis': 'source-bound', 'review_status': 'proposed', 'contract_id': contract,
            'scope': {'case': spec['case'], 'name': spec['name'], 'type': 12, 'transports': ['udp', 'tcp']},
            'reference_document_sha256': digest(reference), 'reference_case_sha256': digest(case),
            'fixture_text': fixture, 'fixture_text_sha256': hashlib.sha256(fixture.encode()).hexdigest(),
            'fixture_input': fixture_input(case), 'fixture_input_sha256': digest(fixture_input(case)),
            'states': spec['states'], 'target_labels': spec['target_labels'], 'reference_records': records,
            'permutations': [[0, 1], [1, 0]], 'source_evidence': evidence,
            'transformation_scope': 'One uniform permutation across every target, transport and phase; all other case semantics unchanged.',
            'derivation_inputs': 'Exact C reference, fixed fixture, and matching source only; no candidate input.',
            'invariants': ['x/x6 has one address; y/y6 has one reverse and one non-reverse address.',
                'Only y/y6 multi-address forward queries occur, and opposite reverse classes cannot cross-rotate.',
                'No file or generation mutation occurs after initial load; PTR enumeration does not reorder hash links.',
                'For leases-dhcp only: restored(.test) and lease(.test) at .31/.30 are disjoint from x/y names and addresses; refresh only removes DHCP nodes and inserts unrelated new nodes.',
                'One initial order is retained across UDP, forked TCP, and (where present) the entire after-DHCP sequence.']}
        entries.append(entry)
        validation = copy.deepcopy(manifest)
        validation['source_bound_entries'] = [copy.deepcopy(entry)]
        assert not check(reference, reference, validation)['passed']
        validation['source_bound_entries'][0]['review_status'] = 'approved'
        alternative = copy.deepcopy(reference)
        actual_case = next(row for row in alternative['cases'] if row['case'] == spec['case'])
        for row in actual_case['observations']:
            if row['label'] in spec['target_labels']:
                row['semantics']['records'].reverse()
        positive = check(reference, alternative, validation)
        assert positive['passed'] and len(positive['qualified_ptr_order']) == len(targets)

        def reject(name, mutate):
            actual = copy.deepcopy(alternative)
            current = next(row for row in actual['cases'] if row['case'] == spec['case'])
            mutate(current)
            result = check(reference, actual, validation)
            assert not result['passed'], (spec['case'], name)
            negatives.append({'case': spec['case'], 'name': name, 'expected': 'reject', 'passed': False,
                'failure_counts': dict(collections.Counter(row['kind'] for row in result['failures']))})

        for mode in ('transport', 'phase', 'repeat'):
            def splice(current, mode=mode):
                for row in current['observations']:
                    if row['label'] in spec['target_labels'] and (
                        row['transport'] == 'tcp' if mode == 'transport' else
                        '-after-' in row['label'] if mode == 'phase' else row['label'].endswith('-1')):
                        row['semantics']['records'].reverse()
            reject('splice-' + mode, splice)
        reject('unknown-case-same-input', lambda current: current.__setitem__('case', 'five-line-stateful-ptr'))
        reject('changed-options', lambda current: current['argv'].append('--no-round-robin'))
        reject('changed-mutations', lambda current: current['mutations'].append({'phase': 'unreviewed-hup'}))
        for mode in ('ttl', 'header', 'tc', 'count', 'rrset', 'forward'):
            def mutate(current, mode=mode):
                row = next(row for row in current['observations'] if row['label'] in spec['target_labels'])['semantics']
                if mode == 'ttl': row['records'][0]['ttl'] += 1
                elif mode in ('header', 'tc'): row['flags'] ^= 1 if mode == 'header' else 0x200
                elif mode == 'count': row['records'].pop()
                elif mode == 'rrset': row['records'][0]['data'] = 'wrong.test'
                else: next(row for row in current['observations'] if row['type'] in (1, 28) and len(row['semantics']['records']) == 2)['semantics']['records'].reverse()
            reject('changed-' + mode, mutate)
        if spec['case'] == 'leases-dhcp':
            reject('changed-dhcp-request', lambda current: current['dhcp'].__setitem__('request_wire', '00'))
            def after_dhcp_splice(current):
                for row in current['observations']:
                    if row['label'] in spec['target_labels'] and row['label'].startswith('after-dhcp-'):
                        row['semantics']['records'].reverse()
            reject('after-dhcp-splice', after_dhcp_splice)
    proposal = copy.deepcopy(manifest)
    proposal['source_bound_entries'] = entries
    args.output.mkdir(parents=True, exist_ok=False)
    values = {'entries.proposed.json': entries, 'manifest.proposed.json': proposal,
              'source-evidence.json': evidence, 'negative-controls.json': {'real_candidate_evaluated': False,
              'all_proposed_entries_inactive': True, 'synthetic_uniform_permutations_qualify': True, 'controls': negatives}}
    summary = {'status': 'proposed', 'no_new_c_run': True, 'real_candidate_evaluated': False,
        'cases': [{'case': entry['scope']['case'], 'fixture_sha256': entry['fixture_text_sha256'],
                   'input_sha256': entry['fixture_input_sha256'], 'states': len(entry['states']),
                   'targets': len(entry['target_labels']), 'queries': len(entry['fixture_input']['queries'])} for entry in entries],
        'negative_controls': len(negatives)}
    values['summary.json'] = summary
    for name, value in values.items():
        (args.output / name).write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
