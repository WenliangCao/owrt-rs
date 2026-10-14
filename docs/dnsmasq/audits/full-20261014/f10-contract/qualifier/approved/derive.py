#!/usr/bin/env python3
"""Apply only the four independently approved source contracts, offline."""
import argparse
import collections
import copy
import hashlib
import json
from pathlib import Path
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[7] / 'tools/dnsmasq'))
from f10_contract_check import check, digest

IDS = {'six-host-record-ptr-initial-order-v1', 'six-hostsdir-initial-ptr-initial-order-v1',
       'leases-dhcp-ptr-initial-order-v1', 'ipv6-repeated-ptr-initial-order-v1'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-archive', type=Path, required=True)
    parser.add_argument('--final238e-archive', type=Path, required=True)
    parser.add_argument('--sdk-result', type=Path, required=True)
    parser.add_argument('--qualifier-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    read = lambda path: json.loads(path.read_text())
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    review = read(args.qualifier_dir / 'approved/review.json')
    assert review['status'] == 'approved' and review['authority'] == 'independent audit/root source-contract review'
    assert {row['contract_id'] for row in review['scope']} == IDS
    observed = read(args.qualifier_dir / 'observed-ptr-order-manifest.json')
    proposals = [read(args.qualifier_dir / 'source-bound-six-host-record/entry.proposed.json')]
    proposals += read(args.qualifier_dir / 'source-bound-extra/entries.proposed.json')
    assert {entry['contract_id'] for entry in proposals} == IDS
    assert all(entry['review_status'] == 'proposed' for entry in proposals)
    manifest = copy.deepcopy(observed)
    manifest['source_bound_entries'] = copy.deepcopy(proposals)
    for entry in manifest['source_bound_entries']:
        entry['review_status'] = 'approved'
        entry['review'] = {'authority': review['authority'], 'audit_session_key': review['audit_session_key'],
            'decision_basis': review['decision_basis'], 'review_document_sha256': digest(review),
            'scope': next(row for row in review['scope'] if row['contract_id'] == entry['contract_id']),
            'independent_evidence_basis': review['source_evidence_basis']}
    args.output.mkdir(parents=True, exist_ok=False)

    def write(name, value):
        raw = (json.dumps(value, indent=2) + '\n').encode()
        (args.output / name).write_bytes(raw)
        return sha(raw)

    manifest_sha = write('manifest.json', manifest)
    with tarfile.open(args.baseline_archive, 'r:gz') as archive:
        reference_raw = archive.extractfile('private/repeat-c/result.json').read()
    reference = json.loads(reference_raw)
    with tarfile.open(args.final238e_archive, 'r:gz') as archive:
        final238e_raw = archive.extractfile('final238e/result.json').read()
    inputs = {'final238e': final238e_raw, 'sdk-final': args.sdk_result.read_bytes()}
    summary = {'manifest_file_sha256': manifest_sha, 'manifest_document_sha256': digest(manifest),
        'review_document_sha256': digest(review), 'reference_raw_sha256': sha(reference_raw),
        'observed_tracks': len(observed['entries']), 'observed_states': sum(len(row['allowed_states']) for row in observed['entries']),
        'approved_source_contract_ids': sorted(IDS), 'runtime_repeated': False,
        'checker_sha256': sha((Path(__file__).resolve().parents[7] / 'tools/dnsmasq/f10_contract_check.py').read_bytes()),
        'actuals': {}}
    for label, raw in inputs.items():
        actual = json.loads(raw)
        result = check(reference, actual, manifest)
        assert result['case_count'] == 13 and len(actual['cases']) == 13
        result['provenance'] = {'evaluation': 'read-only offline; no daemon run',
            'raw_actual_sha256': sha(raw), 'actual_elf_sha256': actual['binary_sha256'],
            'manifest_file_sha256': manifest_sha, 'review_document_sha256': digest(review)}
        output_sha = write(label + '-recheck.json', result)
        summary['actuals'][label] = {'passed': result['passed'], 'case_count': result['case_count'],
            'dns_observations': sum(len(row['observations']) for row in actual['cases']),
            'elf_sha256': actual['binary_sha256'], 'raw_result_sha256': sha(raw),
            'actual_document_sha256': result['actual_document_sha256'],
            'recheck_file_sha256': output_sha, 'recheck_document_sha256': digest(result),
            'failures': len(result['failures']), 'qualified_ptr_order': dict(collections.Counter(row['kind'] for row in result['qualified_ptr_order'])),
            'qualified_cases': dict(collections.Counter(row['case'] for row in result['qualified_ptr_order']))}
    write('summary.json', summary)
    print(json.dumps(summary, indent=2))
    return int(any(not row['passed'] for row in summary['actuals'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
