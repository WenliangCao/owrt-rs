#!/usr/bin/env python3
"""Second review of local FIX7 boundary receipts; does not start daemons."""
import hashlib
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
checked_path = HERE.parent / 'root/boundary-checked.json'
checked = json.loads(checked_path.read_text())
invocation_path = HERE.parent / 'root/boundary-invocation.json'
invocation = json.loads(invocation_path.read_text())
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
checker = HERE.parent / 'root/check_boundary.py'
decoder = ROOT / 'docs/dnsmasq/audits/20261014/fix6/build/new-boundary-check.py'
assert digest(checker) == checked['checker_sha256']
assert digest(decoder) == checked['decoder_sha256']
rows = []
for group in checked['groups']:
    cases = group['cases']
    profiles = ([f'{family}-{size}' for family, size in itertools.product(('txt', 'dual', 'opaque'), (193, 201, 220))]
                if group['name'] == 'alias' else [f'{family}-220' for family in ('txt', 'dual', 'opaque')])
    expected = {f'{profile}-debug{debug}-{protocol}-255'
                for profile, debug, protocol in itertools.product(profiles, (0, 1), ('udp', 'tcp'))}
    assert len(cases) == len(expected) and {row['label'] for row in cases} == expected
    run = next(row for row in invocation['runs'] if row['name'] == group['name'])
    assert run['exit'] == 0 and run['files'][group['raw_private_path']] == group['raw_sha256']
    rows.extend(cases)
assert len(rows) == checked['cases'] == 48
assert sum(len(row['sides']) for row in rows) == checked['daemon_runs'] == 192
for row in rows:
    assert set(row['sides']) == {'c', 'main', 'before', 'fix'}
    eof = not row['direct'] and row['profile'].endswith('-220') and row['protocol'] == 'tcp'
    assert row['before_eof_expected_and_observed'] == eof
    assert row['all_warm_health_upstream_lifecycle_checks']
    for role, side in row['sides'].items():
        if role == 'before' and eof:
            assert side == {'status': 'eof'}
        else:
            assert side['status'] == 'reply' and side['all_fields_equal_c']

# Reconstruct the original normal TXT fixture independently from FIX6 prose.
base = ('port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\n'
        'no-round-robin\nlocal-ttl=60\ncache-size=150\nserver=127.0.0.1#15354\n'
        'host-record=ready.test,192.0.2.1\n')
fixture = (base + 'host-record=target.example,192.0.2.77\n'
           'host-record=example,192.0.2.20\nmx-host=target.example,example,10\n'
           + ''.join('txt-record=target.example,' + f'{i:03d}' + 'x' * 252 + '\n' for i in range(60))
           + 'txt-record=target.example,' + 'z' * 220 + '\n')
fixture_sha = hashlib.sha256(fixture.encode()).hexdigest()
original_rows = [row for row in rows if not row['direct'] and row['profile'] == 'txt-220']
assert len(original_rows) == 4 and all(row['config_sha256'] == fixture_sha for row in original_rows)
for row in original_rows:
    if row['protocol'] == 'tcp':
        assert row['c_header'] == [0x1234, 0x8580, 1, 64, 0, 1]
        assert row['mx_target'] == 16402
        assert row['sides']['c']['bytes'] == 16427
        assert row['sides']['fix']['bytes'] == row['sides']['main']['bytes'] == 16434
        assert row['sides']['fix']['sha256'] == row['sides']['main']['sha256']
        assert row['sides']['c']['tail_layout'][-1]['owner_wire'] == 'c012'
        assert row['sides']['fix']['tail_layout'][-1]['owner_wire'] == '076578616d706c6500'
        assert row['sides']['c']['tail_layout'][-1]['owner'] == row['sides']['fix']['tail_layout'][-1]['owner'] == ['6578616d706c65']
    else:
        assert all(side['bytes'] == 31 for side in row['sides'].values())
assert checked['calibration'] == dict.fromkeys(('head_eof', 'hide_before_eof', 'ttl', 'additional_owner', 'health'), 'rejected')
assert checked['original_fix6_fixture_match']['cases'] == 12
assert checked['original_fix6_fixture_match']['config_query_and_warm_query_byte_identical']
report = {
    'inputs': {str(p.relative_to(ROOT)): digest(p) for p in (checked_path, invocation_path, checker, decoder, Path(__file__))},
    'fresh_daemon_runs_in_this_review': 0,
    'reviewed_cases': 48, 'reviewed_daemon_runs': 192,
    'before_eof_negative_controls': sum(row['before_eof_expected_and_observed'] for row in rows),
    'current_c_full_field_equal_cases': 48,
    'independently_reconstructed_original_fixture_sha256': fixture_sha,
    'matrix_unique_complete': True, 'checker_decoder_identity_matches': True,
    'calibration': checked['calibration'],
}
(HERE / 'boundary-review.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
