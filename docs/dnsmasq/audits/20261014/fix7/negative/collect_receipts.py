#!/usr/bin/env python3
"""Recheck FIX7 negative raw results; emit compact initial-failure and closeout evidence."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys

from negative_final import decode, sha, strict_pair
from checker_calibration import records


def read(path):
    return json.loads(path.read_text())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    a = p.parse_args()
    private = a.root / 'private'
    out = private / 'negative'
    # Preserve the exact earlier experimental driver, reconstructed solely by
    # reversing the later optional-tail argument addition. Verify its saved SHA.
    driver = (private / 'soa_large_terminal.py').read_text()
    driver = driver.replace("    p.add_argument('--tails', default='184,192,211')\n", '')
    driver = driver.replace("itertools.product(tuple(map(int, a.tails.split(','))), (False, True))", "itertools.product((185, 193, 212), (False, True))")
    restored = out / 'large-soa/driver.py'
    restored.write_text(driver)
    assert sha(restored) == read(out / 'large-soa/checked.json')['script_sha256']
    checks = read(out / 'retry100/checked.json')
    assert checks['status'] == 'passed'
    for suite in checks['suites']:
        for case in suite['checks']:
            paths = [out / 'retry100' / suite['name'] / case['name'] / side / 'result.json' for side in ('c', 'rust')]
            assert [sha(x) for x in paths] == case['result_sha256']
            result = strict_pair(*map(read, paths))
            assert all(result[k] == case[k] for k in result)
    initial = dict(suites=[], successful_pairs=0, failures=[])
    for suite in ('negative', 'soa'):
        summary_path = out / suite / 'summary.json'
        summary = read(summary_path)
        receipt = dict(name=suite, summary_sha256=sha(summary_path), status=summary['status'], cases=[])
        for case in summary['runs']:
            folder = out / suite / case['name']
            results = {side: read(folder / side / 'result.json') for side in ('c', 'rust')}
            row = dict(name=case['name'], result_sha256=[sha(folder / side / 'result.json') for side in ('c', 'rust')])
            if all(r['status'] == 'passed' for r in results.values()):
                row['comparison'] = strict_pair(results['c'], results['rust'])
                initial['successful_pairs'] += row['comparison']['responses']
            else:
                row['sides'] = {side: dict(status=r['status'], error=r.get('error'), event_count=len(r['events']),
                    upstream_count=len(r['upstream']), upstream=[{k:u[k] for k in ('transport','host','type','class','enabled')} for u in r['upstream']],
                    daemon_log_sha256=sha(folder / side / 'daemon.log'), checks=r['dhcp_checks']) for side,r in results.items()}
                initial['failures'].append(dict(suite=suite, **row))
            receipt['cases'].append(row)
        initial['suites'].append(receipt)
    assert len(initial['failures']) == 1
    (out / 'initial-attempt.json').write_text(json.dumps(initial, indent=2) + '\n')
    for label in ('large-soa', 'large-soa-valid', 'repeat-soa'):
        checked = read(out / label / 'checked.json')
        for case in checked['runs']:
            folder = out / label / case['name']
            paths = [folder / side / 'result.json' for side in ('c', 'rust')]
            expected = case.get('result_sha256') or [case['sides'][side]['result_sha256'] for side in ('c','rust')]
            assert [sha(x) for x in paths] == expected
            try:
                result = strict_pair(*map(read, paths))
            except Exception:
                assert label == 'large-soa' and 'comparison_error' in case
            else:
                assert result == case['comparison']
        if label != 'large-soa':
            assert checked['status'] == 'passed'
    prefix = str(out)
    processes = []
    scanned = 0
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        scanned += 1
        links = {}
        for name in ('root', 'exe', 'cwd'):
            try:
                target = str((proc / name).readlink())
            except (OSError, PermissionError):
                continue
            if prefix in target:
                links[name] = target
        if links:
            processes.append(dict(pid=int(proc.name), links=links))
    mounts = [line for line in Path('/proc/self/mountinfo').read_text().splitlines() if prefix in line]
    closeout = dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), argv=sys.argv,
        script_sha256=sha(__file__), private_evidence=prefix, scanned_processes=scanned,
        matching_processes=processes, matching_host_mounts=mounts,
        release_sha256=sha(private / 'release/dnsmasq-rs'),
        verified_receipts={str(path.relative_to(out)):sha(path) for path in [out / 'initial-attempt.json', out / 'retry100/checked.json', out / 'large-soa/checked.json',out / 'large-soa-valid/checked.json',out / 'repeat-soa/checked.json',out / 'calibration.json']})
    assert not processes and not mounts
    (out / 'closeout.json').write_text(json.dumps(closeout, indent=2) + '\n')
    print(json.dumps(closeout))


if __name__ == '__main__':
    main()
