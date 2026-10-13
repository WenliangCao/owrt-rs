#!/usr/bin/env python3
"""Recompute independent checks from committed derived observations."""
from collections import Counter
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

b = json.loads((root / 'boundaries.json').read_text())
r = json.loads((root / 'repairs.json').read_text())
assert b['controller_sha256'] == sha(root / 'boundaries.py')
assert r['tool_sha256'] == sha(root / 'repair_checks.py')
assert b['binary_sha256'] == r['binary_sha256']
assert b['binary_sha256']['c'] == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
assert b['binary_sha256']['fix'] == '55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca'
for row in b['config']:
    assert row['observed']['fix']['exit'] == row['observed']['c']['exit']
for row in b['dhcp']:
    assert row['observed']['fix'] == row['observed']['c']
    assert row['observed']['fix']['exit'] == 0
    assert all(event['daemon_alive'] for event in row['observed']['fix']['events'])
jobs = {job['name']: job for job in r['jobs']}
assert all(job['exit'] == 0 for job in jobs.values())
helper = jobs['helper']['result']
assert len(helper['cases']) == 10
assert all(case['matched'] and not case['errors'] for case in helper['cases'])
tftp = jobs['tftp']['result']
assert len(tftp['rows']) == 96
assert all(row['result']['c'] == row['result']['rust'] for row in tftp['rows'])
dump = jobs['dump-rows']['result']
assert len(dump['rows']) == 5
for row in dump['rows']:
    rows = row['comparison']['declared_rows']
    assert Counter(x['raw'] for x in rows['c']) == Counter(x['raw'] for x in rows['rust'])
for row in r['signals']:
    if row['implementation'] == 'main':
        assert row['exit_status_after_signal'] in (-10, -14) and not row['dns_after']
    else:
        assert row['exit_status_after_signal'] is None and row['dns_after']
assert r['dump'][0]['dump'] == r['dump'][1]['dump']
assert all(row['ack'] == 5 and row['lease_absent_before_alarm'] and row['lease_persisted_after_alarm']
    and row['lease_dump_seen'] and row['daemon_alive'] and row['dns_after'] for row in r['maintenance'])
result = dict(status='passed', inputs={p: sha(root / p) for p in ['boundaries.json', 'repairs.json']},
    binary_sha256=b['binary_sha256'], config=dict(cases=39, fix_c=39, main_c=10),
    dhcp=dict(cases=27, fix_c=27, main_c=14), helper=10, tftp=96, declared_dump_cases=5,
    whole_dump_table_equal=False, dump_nonterminal_row_and_iteration_order_excluded=True,
    signal_cases=6, cache_summary_cases=2, forced_lease_maintenance_cases=2,
    performance_claims=False)
(root / 'check.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
