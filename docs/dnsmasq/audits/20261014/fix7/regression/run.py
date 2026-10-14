#!/usr/bin/env python3
"""Run fresh FIX7 DNS controls on Oracle and decode every raw wire response.

Uses established FIX5 extended and FIX4 N1 traffic generators; no product edits.
Terminal profiles are verbatim AST-extracted FIX4 profiles, run with the FIX5
driver so TCP closes before the UDP health query. No TTL normalization.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
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
    parser.add_argument('--fix-sha', required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    source = args.root / 'source'
    audit = Path(__file__).resolve().parent
    out = args.root / 'private/regression'
    out.mkdir(parents=True, exist_ok=False)
    decoder_path = source / 'docs/dnsmasq/audits/20261014/fix5/dns/collect.py'
    decoder = module(decoder_path, 'fix7_decoder')
    image = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
    binaries = {
        'c': image / 'usr/sbin/dnsmasq',
        'main': Path('/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs'),
        'before': Path('/home/ubuntu/dnsmasq-audit-fix6-20261014/private/root-release-recheck/dnsmasq-rs'),
        'fix': args.root / 'private/release/dnsmasq-rs',
    }
    expected = {
        'c': '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87',
        'main': 'ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863',
        'before': 'a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66',
        'fix': args.fix_sha,
    }
    assert {k: sha(v) for k, v in binaries.items()} == expected
    base = ['sudo', '-n', 'sh', str(source / 'tools/dnsmasq/run_isolated.sh'), 'python3']
    extended = source / 'docs/dnsmasq/audits/20261014/fix5/dns/terminal_extended.py'
    profiles = source / 'docs/dnsmasq/audits/20261014/fix5/dns'
    common = ['--source', str(source), '--image', str(image), '--main', str(binaries['main']),
              '--before', str(binaries['before']), '--fix', str(binaries['fix'])]
    plans = []

    def add(name, profile, options=()):
        plans.append({'name': name, 'argv': base + [str(extended)] + common +
                      ['--profiles', str(profile), '--out', str(out / name)] + list(options)})

    add('f2', profiles / 'cname-profiles.json', ['--upstream-cnames'])
    add('f2-anchor', profiles / 'cname-profiles.json', ['--upstream-cnames', '--host-anchor'])
    add('candidate-anchor', profiles / 'candidate-profiles.json', ['--host-anchor'])
    add('extended-controls', profiles / 'controls-profiles.json')
    for target, profile in [('query', 'raw-ns-pointer'), ('target', 'raw-ns-target-pointer')]:
        for anchor in [False, True]:
            add('f1-' + target + ('-anchor' if anchor else '-dynamic'), audit / 'terminal-profiles.json',
                ['--only', profile, '--qtype', '2', '--upstream-ns', '--upstream-ns-target', target] +
                (['--host-anchor'] if anchor else []))
    add('full-terminal', audit / 'terminal-profiles.json')
    for anchor in [False, True]:
        add('chain-anchor' if anchor else 'chain-dynamic',
            source / 'docs/dnsmasq/audits/20261014/fix6/dns/chain-profiles.json',
            ['--host-anchor'] if anchor else [])
    n1 = source / 'docs/dnsmasq/audits/20261014/fix4/dns/n1_fresh.py'
    plans.append({'name': 'n1', 'argv': base + [str(n1), '--tools', str(source / 'tools/dnsmasq'),
        '--image-root', str(image), '--main', str(binaries['main']), '--fix', str(binaries['fix']),
        '--out', str(out / 'n1')]})
    (out / 'invocations.json').write_text(json.dumps(plans, indent=2) + '\n')
    report = {'script_sha256': sha(__file__), 'decoder_sha256': sha(decoder_path),
              'identities': expected, 'binaries': {k: str(v) for k, v in binaries.items()},
              'comparison': 'All header/question/ordered RR/RDATA/TTL fields. Normalize compression only; malformed C requires exact raw equality. No TTL waiver.',
              'groups': {}}

    def execute(plan):
        name, argv = plan['name'], plan['argv']
        log = out / (name + '.driver.log')
        start = time.time()
        with log.open('xb') as handle:
            proc = subprocess.run(argv, stdout=handle, stderr=subprocess.STDOUT, timeout=480)
        assert proc.returncode == 0, (name, proc.returncode)
        path = out / name / 'result.json'
        raw = json.loads(path.read_text())
        result = decoder.collect(path, str(path))
        driver = Path(argv[argv.index('python3') + 1])
        assert raw['identities']['driver'] == sha(driver)
        if '--profiles' in argv:
            assert raw['identities']['profiles'] == sha(argv[argv.index('--profiles') + 1])
        for side, digest in expected.items():
            if side in raw['identities']:
                assert raw['identities'][side] == digest
        result['execution'] = {'argv': argv, 'exit': proc.returncode, 'start_unix': start,
            'end_unix': time.time(), 'log_private_path': str(log), 'log_sha256': sha(log)}
        result['classifications'] = {'valid_equal_c': [], 'malformed_c_raw_equal': [],
            'main_existing_difference': [], 'new_difference': [], 'warm_strict_equal': [],
            'health_strict_equal': [], 'final_wire_equal_c': [], 'main_wire_equal_fix': []}
        for row in raw.get('cases', raw.get('runs')):
            label = row.get('label', row.get('name'))
            sides = row['sides']
            decoded = {side: decoder.decode(value['response']) for side, value in sides.items()}
            c, fix, main = [decoded[side] for side in ['c', 'fix', 'main']]
            marks = result['classifications']
            if 'parse_error' in c:
                assert sides['fix']['response']['hex'] == sides['c']['response']['hex'], label
                marks['malformed_c_raw_equal'].append(label)
            elif fix == c:
                marks['valid_equal_c'].append(label)
            elif fix == main:
                marks['main_existing_difference'].append(label)
            else:
                marks['new_difference'].append(label)
            if sides['fix']['response'] == sides['c']['response']:
                marks['final_wire_equal_c'].append(label)
            if sides['main']['response'] == sides['fix']['response']:
                marks['main_wire_equal_fix'].append(label)
            for side, value in sides.items():
                assert value['alive'] is True and value['exit'] == 0, (label, side)
            health = 'health' if 'health' in sides['c'] else 'health_after_connection_close'
            assert all(v[health]['status'] == 'reply' for v in sides.values()), label
            assert all(decoder.decode(v[health]) == decoder.decode(sides['c'][health]) for v in sides.values()), label
            marks['health_strict_equal'].append(label)
            warm = 'warm' if 'warm' in sides['c'] else 'warm_response'
            if warm in sides['c']:
                assert all(decoder.decode(v[warm]) == decoder.decode(sides['c'][warm]) for v in sides.values()), label
                marks['warm_strict_equal'].append(label)
            if name == 'f2':
                assert c['header'] == [0x1234, 0x8580, 1, 5, 0, 0]
                assert [rr[3] for rr in c['sections'][0]] == [300, 60, 60, 60, 60]
                assert sides['fix']['response']['hex'] == sides['before']['response']['hex'] == sides['c']['response']['hex']
                assert len(bytes.fromhex(sides['fix']['response']['hex'])) == 154
                assert len(sides['fix']['upstream']) == len(sides['before']['upstream']) == len(sides['c']['upstream']) == 0
                assert len(sides['main']['upstream']) == 1
        return name, result

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for name, result in pool.map(execute, plans):
            report['groups'][name] = result
            (out / 'checked.json').write_text(json.dumps(report, indent=2) + '\n')
            print(name, json.dumps({key: len(value) for key, value in result['classifications'].items()}), flush=True)
    assert {k: sha(v) for k, v in binaries.items()} == expected
    report['identities_unchanged'] = True
    report['fresh_scenarios'] = sum(len(group['cases']) for group in report['groups'].values())
    report['fresh_daemon_runs'] = sum(len(case['statuses']) for group in report['groups'].values() for case in group['cases'])
    report['new_differences'] = sum(len(group['classifications']['new_difference']) for group in report['groups'].values())
    (out / 'checked.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['fresh_scenarios', 'fresh_daemon_runs', 'new_differences']}), flush=True)


if __name__ == '__main__':
    main()
