#!/usr/bin/env python3
"""Recollect all fresh FIX7 results without rerunning any daemon.

The interactive turn interrupted the coordinator's stdout after group 10.
Its 12 independent drivers completed and retained all raw output. Preserve the
partial coordinator receipt, verify all raw inputs anew, and write a separate
complete receipt. A driver's exit status is only claimed if observed earlier.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    a = p.parse_args()
    source = a.root / 'source'
    out = a.root / 'private/regression'
    decoder_path = source / 'docs/dnsmasq/audits/20261014/fix5/dns/collect.py'
    spec = importlib.util.spec_from_file_location('decoder', decoder_path)
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    old = json.loads((out / 'checked.json').read_text())
    plans = json.loads((out / 'invocations.json').read_text())
    report = {'script_sha256': sha(__file__), 'driver_coordinator_sha256': old['script_sha256'],
        'partial_coordinator_receipt_sha256': sha(out / 'checked.json'),
        'decoder_sha256': sha(decoder_path), 'identities': old['identities'],
        'binaries': old['binaries'], 'comparison': old['comparison'],
        'recollection_only': True, 'groups': {}}
    assert {k: sha(v) for k, v in old['binaries'].items()} == old['identities']
    counts = {'f2': 4, 'f2-anchor': 4, 'candidate-anchor': 4, 'extended-controls': 80,
        'f1-query-dynamic': 4, 'f1-query-anchor': 4, 'f1-target-dynamic': 4,
        'f1-target-anchor': 4, 'full-terminal': 88, 'chain-dynamic': 80,
        'chain-anchor': 80, 'n1': 72}
    for plan in plans:
        name, argv = plan['name'], plan['argv']
        path = out / name / 'result.json'
        raw = json.loads(path.read_text())
        rows = raw.get('cases', raw.get('runs'))
        assert len(rows) == counts[name]
        log = out / (name + '.driver.log')
        done = json.loads(log.read_text().splitlines()[-1])
        assert done == ({'complete': True, 'runs': 72} if name == 'n1' else {'completed': True, 'cases': counts[name]})
        driver = Path(argv[argv.index('python3') + 1])
        assert raw['identities']['driver'] == sha(driver)
        if '--profiles' in argv:
            assert raw['identities']['profiles'] == sha(argv[argv.index('--profiles') + 1])
        for side, digest in old['identities'].items():
            if side in raw['identities']:
                assert raw['identities'][side] == digest
        result = decoder.collect(path, str(path))
        result['execution'] = old['groups'].get(name, {}).get('execution', {
            'argv': argv, 'exit': None, 'exit_note': 'Coordinator receipt interrupted; driver completion marker and all daemon exits verified from retained fresh output.',
            'log_private_path': str(log), 'log_sha256': sha(log)})
        assert result['execution']['log_sha256'] == sha(log)
        marks = result['classifications'] = {'valid_equal_c': [], 'malformed_c_raw_equal': [],
            'main_existing_difference': [], 'new_difference': [], 'warm_strict_equal': [],
            'health_strict_equal': [], 'final_wire_equal_c': [], 'main_wire_equal_fix': []}
        for row in rows:
            label = row.get('label', row.get('name'))
            sides = row['sides']
            decoded = {side: decoder.decode(value['response']) for side, value in sides.items()}
            c, fix, main = [decoded[side] for side in ['c', 'fix', 'main']]
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
            assert all(v['alive'] is True and v['exit'] == 0 for v in sides.values()), label
            health = 'health' if 'health' in sides['c'] else 'health_after_connection_close'
            assert all(v[health]['status'] == 'reply' and decoder.decode(v[health]) == decoder.decode(sides['c'][health]) for v in sides.values()), label
            marks['health_strict_equal'].append(label)
            warm = 'warm' if 'warm' in sides['c'] else 'warm_response'
            if warm in sides['c']:
                assert all(decoder.decode(v[warm]) == decoder.decode(sides['c'][warm]) for v in sides.values()), label
                marks['warm_strict_equal'].append(label)
        report['groups'][name] = result
    report['identities_unchanged'] = True
    report['fresh_scenarios'] = sum(len(g['cases']) for g in report['groups'].values())
    report['fresh_daemon_runs'] = sum(len(c['statuses']) for g in report['groups'].values() for c in g['cases'])
    report['new_differences'] = sum(len(g['classifications']['new_difference']) for g in report['groups'].values())
    (out / 'final-checked.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ['fresh_scenarios', 'fresh_daemon_runs', 'new_differences']}))


if __name__ == '__main__':
    main()
