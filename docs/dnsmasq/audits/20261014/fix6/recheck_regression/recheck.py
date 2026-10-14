#!/usr/bin/env python3
"""Independently recollect retained FIX6 evidence and rerun regression controls.

Run on Oracle. No retained file is rewritten. The only new daemon outputs go
under --out, which must not exist. This is not a product test or build change.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--negative-checker', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.root, args.out
    assert 'private' in out.resolve().parts
    out.mkdir(parents=True, exist_ok=False)
    source = root / 'source'
    decoder_path = source / 'docs/dnsmasq/audits/20261014/fix5/dns/collect.py'
    decoder = module(decoder_path, 'fix5_decoder')
    negative = module(args.negative_checker, 'negative_decoder')
    invocations = json.loads((root / 'dns/all-invocations.json').read_text())
    runs = json.loads((root / 'dns/all-results.json').read_text())
    assert len(runs) == len(invocations) == 13
    expected = {
        'c': '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87',
        'main': 'ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863',
        'before': '7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c',
        'fix': 'a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66',
    }
    binaries = {
        'c': '/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/usr/sbin/dnsmasq',
        'main': '/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs',
        'before': '/home/ubuntu/dnsmasq-audit-fix5-20261014/private/release/dnsmasq-rs',
        'fix': str(root / 'private/release/dnsmasq-rs'),
    }
    assert {k: sha(v) for k, v in binaries.items()} == expected
    report = dict(script_sha256=sha(__file__), decoder_sha256=sha(decoder_path),
                  binaries=binaries, identities=expected, retained={}, fresh={},
                  retained_invocations_sha256=sha(root / 'dns/all-invocations.json'),
                  retained_results_sha256=sha(root / 'dns/all-results.json'))

    def collect(item, path):
        result = decoder.collect(path, str(path))
        raw = json.loads(path.read_text())
        argv = item['argv']
        driver = Path(argv[argv.index('python3') + 1])
        assert result['identities']['driver'] == sha(driver)
        if '--profiles' in argv:
            profiles = Path(argv[argv.index('--profiles') + 1])
            assert result['identities']['profiles'] == sha(profiles)
        for key, value in expected.items():
            if key in result['identities']:
                assert result['identities'][key] == value
        distinctions = dict(valid_fix_equals_c=0, malformed_c_raw_equal=0,
                            main_existing_difference=[], new_difference=[],
                            health_nonreply=[], warm_count=0,
                            raw_fix_equals_c=0, raw_main_equals_fix=0)
        for row in raw.get('cases', raw.get('runs', [])):
            label = row.get('label', row.get('name'))
            sides = row['sides']
            decoded = {k: decoder.decode(v['response']) for k, v in sides.items()}
            if sides['fix']['response'] == sides['c']['response']:
                distinctions['raw_fix_equals_c'] += 1
            if sides['main']['response'] == sides['fix']['response']:
                distinctions['raw_main_equals_fix'] += 1
            if 'parse_error' in decoded['c']:
                assert decoded['fix'] == decoded['c']
                distinctions['malformed_c_raw_equal'] += 1
            elif decoded['fix'] == decoded['c']:
                distinctions['valid_fix_equals_c'] += 1
            elif decoded['fix'] == decoded['main']:
                distinctions['main_existing_difference'].append(label)
            else:
                distinctions['new_difference'].append(label)
            for side, value in sides.items():
                health_key = 'health' if 'health' in value else 'health_after_connection_close'
                if value[health_key]['status'] != 'reply':
                    distinctions['health_nonreply'].append(dict(label=label, side=side, result=value[health_key]))
            if 'warm' in sides['c'] or 'warm_response' in sides['c']:
                distinctions['warm_count'] += 1
        result['distinctions'] = distinctions
        return result

    for item, run in zip(invocations, runs):
        name = item['name']
        assert run['name'] == name and run['exit'] == 0
        assert sha(run['log_private_path']) == run['log_sha256']
        report['retained'][name] = collect(item, root / 'private' / name / 'result.json')
    negative_root = root / 'private/negative-01'
    old_negative = json.loads((negative_root / 'checked.json').read_text())
    negative_receipt = dict(checker_sha256=sha(args.negative_checker),
        previous_checked_sha256=sha(negative_root / 'checked.json'), suites=[])
    for suite in old_negative['suites']:
        folder = negative_root / suite['name']
        assert sha(folder / 'summary.json') == suite['summary_sha256']
        checked = []
        for case in suite['checks']:
            paths = [folder / case['name'] / side / 'result.json' for side in ['c', 'rust']]
            assert [sha(path) for path in paths] == case['result_sha256']
            counts = negative.strict_pair(*(json.loads(path.read_text()) for path in paths))
            for key, value in counts.items():
                assert case[key] == value
            checked.append(dict(name=case['name'], **counts, result_sha256=case['result_sha256']))
        negative_receipt['suites'].append(dict(name=suite['name'], checks=checked))
    negative_receipt['cases'] = sum(len(s['checks']) for s in negative_receipt['suites'])
    for key in ['responses', 'exact', 'bounded_soa', 'dhcp_replies']:
        negative_receipt[key] = sum(c[key] for s in negative_receipt['suites'] for c in s['checks'])
    report['retained_negative'] = negative_receipt
    (out / 'retained-recheck.json').write_text(json.dumps(report, indent=2) + '\n')
    print('retained 13 DNS groups and 100 negative scenarios verified', flush=True)

    # Each command has separate net/mount/PID namespaces and an exclusive output
    # path. Running three independent groups concurrently only shares read inputs.
    plans = []
    for item in invocations:
        if item['name'] not in ['extended-controls', 'chain-dynamic', 'chain-anchor']:
            continue
        argv = list(item['argv'])
        argv[argv.index('--out') + 1] = str(out / item['name'])
        plans.append(dict(name=item['name'], argv=argv))
    (out / 'fresh-invocations.json').write_text(json.dumps(plans, indent=2) + '\n')

    def execute(item):
        started = time.time()
        log = out / (item['name'] + '.driver.log')
        with log.open('xb') as handle:
            proc = subprocess.run(item['argv'], stdout=handle, stderr=subprocess.STDOUT, timeout=300)
        assert proc.returncode == 0, item['name']
        result = collect(item, out / item['name'] / 'result.json')
        result['execution'] = dict(exit=proc.returncode, started=started,
                                   finished=time.time(), log_private_path=str(log), log_sha256=sha(log))
        return item['name'], result

    with ThreadPoolExecutor(max_workers=3) as pool:
        for name, result in pool.map(execute, plans):
            report['fresh'][name] = result
            print(name, json.dumps(result['counts']), flush=True)
    assert {k: sha(v) for k, v in binaries.items()} == expected
    report['release_unchanged'] = True
    (out / 'regression-recheck.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
