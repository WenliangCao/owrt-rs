#!/usr/bin/env python3
"""Derive reviewed no-proc conclusions without changing the original results.

This is offline evidence analysis, not a product run or final PGO qualification.
It requires the retained K, candidate and both original negative-control sets.
"""
import argparse
import hashlib
import json
from pathlib import Path


CALLBACK = 'old 02:00:00:de:00:01 127.0.0.10 startup\n'
K = 'f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08'
B861 = 'c30fad397d582fd544d7af31e8e70f1408f18bb6c29e143bcd5abc12ed309eaa'
NAMES = ('jail-k-helper-control', 'jail-8adc-positive', 'jail-b861-negative',
         'jail-b861-helper-negative-syslog')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition: raise ValueError(message)


def helper(report):
    matches = [row for row in report['cases'] if row['mode'] == 'helper']
    require(len(matches) == 1, 'exactly one helper case required')
    return matches[0]


def boundary(row, digest):
    inside, outside = row['entry_receipt'], row['entry_boundary']
    require(inside['target_sha256'] == digest and inside['uid'] == inside['gid'] == 0 and
            inside['namespace_pid'] == 1 and inside['proc_exists'] is False and
            outside['proc_exists'] is False and outside['errors'] == [], 'entry boundary differs')
    require(inside['target_metadata'] == {'file_capability': None, 'gid': 0, 'mode': 0o755,
                                         'regular': True, 'uid': 0}, 'executable metadata differs')
    require(not row['forced'] and 'error' not in row, 'tool/cleanup failure present')


def analyze(root):
    reports = {name: json.loads((root / name / 'result.json').read_text()) for name in NAMES}
    hashes = {name: sha(root / name / 'result.json') for name in NAMES}
    require(reports[NAMES[0]]['binary_sha256'] == K, 'control is not exact K')
    require(all(reports[name]['binary_sha256'] == B861 for name in NAMES[2:]), 'wrong blocked-source negative control')
    helpers = {name: helper(report) for name, report in reports.items()}
    config_files = ('config', 'script')
    configurations = {name: {part: sha(root / name / 'helper/rootfs/fixture' / part)
                             for part in config_files} for name in NAMES}
    require(all(value == configurations[NAMES[0]] for value in configurations.values()),
            'helper public configuration/script differs across controls')
    positives, negatives = {}, {}
    for name, row in helpers.items():
        boundary(row, reports[name]['binary_sha256'])
        callback = root / name / 'helper/rootfs/fixture/callback'
        raw = callback.read_text() if callback.exists() else None
        require(raw == row.get('callback'), 'retained callback file differs from original result')
        if name in NAMES[:2]:
            lines = raw.splitlines(keepends=True) if raw is not None else []
            require(lines and all(line == CALLBACK for line in lines), 'unexpected/incomplete startup callback')
            runtime, worker = row['runtime_boundary'], row['helper_child']
            require(row['exit'] == 0 and row['initial_dns']['ok'] and runtime['errors'] == [] and
                    runtime['status']['Uid'] == runtime['status']['Gid'] == [453] * 4 and
                    runtime['status']['CapEff'] == 0x3400 and worker['valid'] is True,
                    'helper positive runtime boundary failed')
            positives[name] = {'callback_count': len(lines), 'callback_sha256': sha(callback),
                               'exit': row['exit'], 'owner_uid': 453, 'owner_cap_eff': 0x3400,
                               'original_helper_passed': row['passed']}
        else:
            require(row['exit'] == 5 and row['initial_dns']['ok'] is False and raw in (None, '') and
                    row['helper_child']['captured'] is False, 'negative is not the expected typed failure')
            text = row.get('stderr', '') + row.get('daemon_log', '')
            text += ''.join(bytes.fromhex(value).decode(errors='replace') for value in row.get('syslog', []))
            negatives[name] = {'expected_exit': 5, 'ready': False, 'callback': False, 'helper': False,
                               'proc_absent_inside_and_outside': True,
                               'errno_observed_in_log': 'No such file or directory' in text or 'os error 2' in text,
                               'original_helper_passed': row['passed']}
    require(positives[NAMES[0]]['callback_count'] == positives[NAMES[1]]['callback_count'],
            'K and candidate performed different callback work')
    for name in NAMES[1:3]:
        resolver = [row for row in reports[name]['cases'] if row['mode'] == 'resolver']
        require(len(resolver) == 1 and resolver[0]['passed'] is True, 'existing resolver qualification failed')
    require(all(sha(root / name / 'result.json') == expected for name, expected in hashes.items()),
            'original result bytes changed during analysis')
    return {'schema': 1, 'status': 'REVIEWED_PLAIN_SDK_BOUNDARY_EVIDENCE',
            'source_commit': reports[NAMES[1]]['source_commit'],
            'candidate_elf_sha256': reports[NAMES[1]]['binary_sha256'],
            'original_results_sha256': hashes,
            'original_overall_passed': {name: report['passed'] for name, report in reports.items()},
            'fixture_config_sha256': configurations[NAMES[0]],
            'positive_controls': positives, 'negative_controls': negatives,
            'same_callback_work': True, 'helper_negative_bound_to_positive_controls': True,
            'resolver_original_positive_and_negative_retained': True,
            'source_inference': 'b861 executes /proc/self/exe and that path is unavailable in the observed jail; '
                                'helper errno was not traced and is not inferred to have been logged',
            'scope': 'Separate derived review; all original strict1/log-string false results remain unchanged. '
                     'Plain SDK evidence only; final PGO ELF still requires its own qualification.',
            'analyzer_sha256': sha(Path(__file__))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = analyze(args.root.resolve())
    with args.out.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'same_callback_work': True,
                      'original_results_changed': False, 'result_sha256': sha(args.out)}))


if __name__ == '__main__':
    main()
