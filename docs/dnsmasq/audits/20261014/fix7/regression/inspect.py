#!/usr/bin/env python3
"""Additional independent FIX7 F2 layout, upstream, profile and cleanup checks."""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    a = p.parse_args()
    source = a.root / 'source'
    out = a.root / 'private/regression'
    audit = Path(__file__).resolve().parent
    checked = json.loads((out / 'final-checked.json').read_text())
    assert checked['fresh_scenarios'] == 428 and checked['fresh_daemon_runs'] == 1640
    narrow_path = source / 'docs/dnsmasq/audits/20261014/fix6/recheck_f2/decode.py'
    narrow = load(narrow_path, 'narrow')
    decoder_path = source / 'docs/dnsmasq/audits/20261014/fix5/dns/collect.py'
    decoder = load(decoder_path, 'wide')
    original_profiles_path = source / 'docs/dnsmasq/audits/20261014/fix4/dns/terminal_boundaries.py'
    original_ast = ast.parse(original_profiles_path.read_text())
    original_profiles = next(ast.literal_eval(n.value) for n in original_ast.body
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'profiles' for t in n.targets))
    assert json.loads(json.dumps(original_profiles)) == json.loads((audit / 'terminal-profiles.json').read_text())

    report = {'script_sha256': sha(__file__), 'checked_sha256': sha(out / 'final-checked.json'),
        'independent_f2_decoder_sha256': sha(narrow_path), 'upstream_decoder_sha256': sha(decoder_path),
        'terminal_origin_sha256': sha(original_profiles_path), 'terminal_profiles_sha256': sha(audit / 'terminal-profiles.json'),
        'terminal_profiles_match_original': True, 'f2': [], 'upstream': {}, 'closeout': {}}
    f2 = json.loads((out / 'f2/result.json').read_text())
    for row in f2['cases']:
        parsed = {k: narrow.packet(v['response']['hex']) for k, v in row['sides'].items()}
        c = parsed['c']
        assert all(v['semantic'] == c['semantic'] and not v['errors'] for v in parsed.values())
        assert c['wire_hex'] == parsed['fix']['wire_hex'] == parsed['before']['wire_hex']
        assert [r['owner_wire'] for r in c['layout']] == ['c00c'] + ['c02b'] * 4
        assert [r['rdata_offset'] for r in c['layout']] == [43, 71, 98, 125, 152]
        assert c['layout'][-1]['rdata_hex'] == 'c062'
        assert [rr[3] for rr in c['semantic']['answer']] == [300, 60, 60, 60, 60]
        report['f2'].append({'label': row['label'], 'semantic': c['semantic'], 'layout': c['layout'],
            'bytes': {k: v['bytes'] for k, v in parsed.items()}, 'wire_sha256': {k: v['sha256'] for k, v in parsed.items()}})

    def normalize(flows):
        result = []
        for flow in flows:
            item = {'protocol': flow['protocol']}
            for field in ['query', 'reply']:
                value = decoder.decode({'status': 'reply', 'hex': flow[field]})
                if 'header' in value:
                    value['header'][0] = 0
                item[field] = value
            result.append(item)
        return result

    for name, group in checked['groups'].items():
        path = out / name / 'result.json'
        assert sha(path) == group['sha256']
        data = json.loads(path.read_text())
        summary = {'final_equal_c': [], 'final_equal_main_existing': [], 'unexpected': [], 'warm_all_equal': [],
                   'before_fix_response_identical': [], 'old_difference_main_fix_response_identical': []}
        for row in data.get('cases', data.get('runs')):
            label = row.get('label', row.get('name'))
            sides = row['sides']
            if 'before' in sides:
                assert sides['before']['response'] == sides['fix']['response'], (name, label)
                summary['before_fix_response_identical'].append(label)
            if label in group['classifications']['main_existing_difference']:
                assert sides['main']['response'] == sides['fix']['response'], (name, label)
                summary['old_difference_main_fix_response_identical'].append(label)
            flows = {k: normalize(v['upstream']) for k, v in sides.items()}
            if flows['fix'] == flows['c']:
                summary['final_equal_c'].append(label)
            elif flows['fix'] == flows['main'] and label in group['classifications']['main_existing_difference']:
                summary['final_equal_main_existing'].append(label)
            else:
                summary['unexpected'].append(label)
            if 'warm_upstream' in sides['c']:
                warm = {k: normalize(v['warm_upstream']) for k, v in sides.items()}
                assert all(v == warm['c'] for v in warm.values()), (name, label)
                summary['warm_all_equal'].append(label)
        report['upstream'][name] = summary
    owners = []
    prefix = str(out)
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        for key in ['root', 'cwd', 'exe']:
            try:
                value = str((path / key).resolve(strict=True))
                if value == prefix or value.startswith(prefix + '/'):
                    owners.append({'pid': path.name, 'field': key, 'value': value})
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
    mounts = [line for line in Path('/proc/self/mountinfo').read_text().splitlines() if prefix in line]
    report['closeout'] = {'owned_processes': owners, 'host_mounts': mounts,
                          'release_sha256': sha(a.root / 'private/release/dnsmasq-rs')}
    assert not owners and not mounts
    assert report['closeout']['release_sha256'] == checked['identities']['fix']
    assert all(not value['unexpected'] for value in report['upstream'].values())
    (out / 'inspection.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'f2': len(report['f2']), 'upstream': {k: {s: len(v) for s, v in value.items()}
        for k, value in report['upstream'].items()}, 'closeout': report['closeout']}))


if __name__ == '__main__':
    main()
