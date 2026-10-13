#!/usr/bin/env python3
"""Offline verification of every completed screen/confirmation window."""
import hashlib
import json
from pathlib import Path

ROOT = Path('/home/ubuntu/dnsmasq-audit-fix3-20261013/private')


def counters(value):
    if isinstance(value, dict):
        if 'nr_throttled' in value:
            yield {k: value[k] for k in ('nr_throttled', 'throttled_usec')}
        for child in value.values():
            yield from counters(child)
    elif isinstance(value, list):
        for child in value:
            yield from counters(child)


result = {}
for directory in ('performance-dns', 'performance-raw-records', 'performance-raw-confirm'):
    root = ROOT / directory
    plan = json.loads((root / 'plan.json').read_text())
    state = json.loads((root / 'run.json').read_text())
    assert state['status'] == 'complete'
    assert len(state['windows']) == len(plan['windows'])
    assert all(w['returncode'] == 0 for w in state['windows'])
    row = dict(window_count=len(plan['windows']), foreign_before=json.loads((root / 'foreign-before.json').read_text()),
               counters=dict.fromkeys(('scheduled', 'sent', 'correct', 'wrong', 'timeout', 'transport_error', 'scheduled_skipped'), 0),
               cgroup_samples=0, maximum_nr_throttled=0, maximum_throttled_usec=0,
               result_hashes={}, windows=[], pair_config_checks=[])
    assert row['foreign_before'] == []
    pair_configs = {}
    for window in plan['windows']:
        directory_path = root / window['id']
        path = directory_path / 'result.json'
        row['result_hashes'][window['id']] = hashlib.sha256(path.read_bytes()).hexdigest()
        data = json.loads(path.read_text())
        assert data['measurement_valid']
        identity = json.loads((directory_path / 'process-identity.json').read_text())
        assert identity['sha256'] == plan['groups'][window['variant']]['sha256']
        config_sha = hashlib.sha256((directory_path / 'config').read_bytes()).hexdigest()
        pair_configs.setdefault((window['profile'], window['round']), {})[window['variant']] = config_sha
        assets = {name: hashlib.sha256((directory_path / name).read_bytes()).hexdigest()
                  for name in ('config', 'upstream.json', 'process-identity.json')}
        upstream = json.loads((directory_path / 'upstream.json').read_text())
        proof = None
        proof_path = directory_path / 'cache-proof.json'
        if proof_path.exists():
            assets['cache-proof.json'] = hashlib.sha256(proof_path.read_bytes()).hexdigest()
            all_proof = json.loads(proof_path.read_text())
            proof = {k: v for k, v in all_proof.items() if k != 'rows'}
            expected = 2048 if 'cname' in window['profile'] else 4096
            assert proof['capacity'] == 4096 and proof['filled_names'] == expected
            assert proof['validated_names'] == expected and len(all_proof['rows']) == expected
            assert all(p['correct'] for p in all_proof['rows'])
            assert proof['upstream_disabled'] and upstream['disabled']
            assert upstream['disabled_requests'] == 0
            assert upstream['phases']['steady']['requests'] == 0
        else:
            assert 'miss' in window['profile']
        load = data['measurement']['load']
        for phase in ('warmup', 'measurement'):
            assert load[phase]['scheduled'] == load[phase]['sent'] == load[phase]['correct']
            assert all(load[phase][key] == 0 for key in ('scheduled_skipped', 'wrong', 'timeout', 'transport_error'))
            for key in row['counters']:
                row['counters'][key] += load[phase][key]
        row['windows'].append(dict(id=window['id'], directory=str(directory_path), raw_assets=assets,
                                  actual_elf_sha256=identity['sha256'], cache_proof=proof,
                                  upstream_disabled=upstream['disabled'],
                                  upstream_disabled_requests=upstream['disabled_requests'],
                                  tcp_connections=load['tcp_connections'], tcp_reconnections=load['tcp_reconnections'],
                                  phases={p: {key: load[p][key] for key in row['counters']}
                                          for p in ('warmup', 'measurement')}))
        for values in counters(data):
            row['cgroup_samples'] += 1
            row['maximum_nr_throttled'] = max(row['maximum_nr_throttled'], values['nr_throttled'])
            row['maximum_throttled_usec'] = max(row['maximum_throttled_usec'], values['throttled_usec'])
    for (profile, round_no), configs in pair_configs.items():
        assert configs['main'] == configs['fix']
        row['pair_config_checks'].append(dict(profile=profile, round=round_no, sha256=configs['main'], identical=True))
    assert row['cgroup_samples'] > 0
    assert row['maximum_nr_throttled'] == row['maximum_throttled_usec'] == 0
    result[directory] = row
(ROOT / 'performance-counter-check.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: {key: value for key, value in v.items()
                     if key not in ('result_hashes', 'windows', 'pair_config_checks')}
                  for k, v in result.items()}, indent=2))
