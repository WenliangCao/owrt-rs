#!/usr/bin/env python3
"""Derive the three final SDK DHCP receipts; retain full packets only privately."""
import argparse
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def receipt(path):
    path = Path(path)
    return {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    private = args.root / 'private'
    invocation_path = private / 'dhcp-final-invocations.json'
    invocation = read(invocation_path)
    assert invocation['passed'] and len(invocation['commands']) == 3
    assert sha(invocation['rust']) == invocation['rust_sha256']
    reports, files = {}, []
    for command, (label, count) in zip(invocation['commands'], [('negative', 24), ('soa', 64), ('cursor', 12)]):
        assert command['id'] == label and command['passed'] and command['returncode'] == 0
        assert sha(command['summary']) == command['summary_sha256']
        assert sha(command['log']) == command['log_sha256']
        summary = read(command['summary'])
        assert summary['status'] == 'passed' and len(summary['runs']) == count
        assert summary['identities']['rust'] == invocation['rust_sha256']
        assert summary['identities']['c'] == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
        rows = []
        for row in summary['runs']:
            assert all(value == 'passed' for value in row['status'].values()) and not row['differences']
            derived = {key: value for key, value in row.items() if key != 'boundary'}
            if 'boundary' in row:
                derived['boundary'] = {
                    side: {'reply': event['reply'], 'packet_bytes': len(bytes.fromhex(event['packet'])),
                           'packet_sha256': hashlib.sha256(bytes.fromhex(event['packet'])).hexdigest(),
                           'upstream_requests': len(event['upstream']), 'alive': event['alive']}
                    for side, event in row['boundary'].items()}
            rows.append(derived)
        reports[label] = {'cases': count, 'status': 'passed', 'identities': summary['identities'],
                          'exact_responses': sum(row['exact_responses'] for row in rows),
                          'clock_bounded_soa_responses': sum(row['clock_bounded_soa_responses'] for row in rows),
                          'summary': receipt(command['summary']), 'log': receipt(command['log']),
                          'command': command, 'runs': rows}
        folder = Path(command['summary']).parent
        files.extend(receipt(path) for path in sorted(folder.rglob('*')) if path.is_file())
    report = {'schema': 'dnsmasq-fix4-dhcp-sdk-v1', 'passed': True,
              'source_commit': invocation['source_commit'], 'SDK_elf': receipt(invocation['rust']),
              'invocation': receipt(invocation_path), 'probes': reports,
              'comparison': 'All decoded response fields and upstream requests; only cached SOA authority TTL may differ by one bounded wall-clock tick. DHCP TTL remains exact. Full packets retained privately.',
              'collector': receipt(__file__)}
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'dhcp-sdk.json').write_text(json.dumps(report, indent=2) + '\n')
    (args.out / 'dhcp-sdk-raw-index.json').write_text(json.dumps({'files': files}, indent=2) + '\n')
    print(json.dumps({'passed': True, 'cases': sum(row['cases'] for row in reports.values()),
                      'response_pairs': sum(row['exact_responses'] + row['clock_bounded_soa_responses'] for row in reports.values()),
                      'raw_files': len(files), 'receipt': receipt(args.out / 'dhcp-sdk.json')}))


if __name__ == '__main__':
    main()
