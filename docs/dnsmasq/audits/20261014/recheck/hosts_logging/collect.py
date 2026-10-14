#!/usr/bin/env python3
"""Read-only reduction of fresh Oracle B1/B6 recheck observations."""
import hashlib
import json
from pathlib import Path
import sys

BASE = Path('/home/ubuntu/dnsmasq-recheck-hosts-20261014')
PRIVATE = BASE / 'private'
artifacts = {}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(relative):
    path = PRIVATE / relative
    artifacts[str(path)] = digest(path)
    return json.loads(path.read_text())


def has_address(reply, address):
    return reply.get('ok', False) and any(r.get('data') == address
        for r in reply.get('reply', reply).get('records', []))


def memory(name):
    rows = read(f'{name}/result.json')
    result = []
    for row in rows:
        trace = PRIVATE / name / ('memory-' + row['side']) / 'syscalls.log'
        artifacts[str(trace)] = digest(trace)
        reduced = {k: row.get(k) for k in ('side', 'binary_sha256', 'initial', 'limit_bytes',
            'after_reload_exit', 'pressure_status', 'before_stop_exit', 'exit')}
        reduced.update({'enomem_count': trace.read_text().count('ENOMEM'),
            'pressure_ready': has_address(row['during_pressure'], '192.0.2.41'),
            'recovered': has_address(row['recovered'], '192.0.2.44'),
            'last_host_answers': row['last_host'].get('reply', {}).get('records', [])})
        assert reduced['pressure_ready'] and reduced['recovered'] and row['exit'] == 0
        result.append(reduced)
    return result


def sweep(name):
    data = read(f'{name}/result.json')
    rows = []
    for row in data['cases']:
        trace = PRIVATE / name / f"{row['side']}-initial{row['initial_rows']}-extra{row['headroom_kib']}" / 'syscalls'
        artifacts[str(trace)] = digest(trace)
        reduced = {k: row.get(k) for k in ('side', 'initial_rows', 'headroom_kib', 'initial',
            'limit_bytes', 'pressure_exit', 'pressure_status', 'exit_before_stop', 'exit', 'enomem_count', 'error')}
        reduced['after_hup_answers'] = {transport: has_address(reply, '192.0.2.44')
            for transport, reply in row.get('after_hup', {}).items()}
        reduced['ready_under_pressure'] = has_address(row.get('pressure_udp', {}).get('ready.test', {}), '192.0.2.41')
        reduced['raw_result'] = str(trace.parent / 'result.json')
        reduced['trace_tail'] = trace.read_text().splitlines()[-3:]
        rows.append(reduced)
    return {'driver_sha256': data['driver_sha256'], 'rust_sha256': data['rust_sha256'], 'cases': rows}


result = {
    'scope': 'Fresh exact-image Oracle network/mount/PID namespaces; no physical router operations; product source unchanged.',
    'reviewed_head': 'aa8f12db',
    'product_commit': '807db8a15e43452414acc048874bf04a4c639bd9',
    'c_sha256': '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87',
    'rust_sha256': '0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728',
    'original_b1': memory('memory-01'),
    'no_pressure_control': memory('memory-control-01'),
    'sweep': sweep('sweep-01'),
    'sweep_repeat': sweep('sweep-repeat-02'),
    'sweep_final': sweep('sweep-final-03'),
    'old_rust_negative': sweep('sweep-old-01'),
}
pressure = read('pressure-01/result.json')
assert pressure['passed'] and len(pressure['cases']) == 8
result['hosts_pressure'] = []
for row in pressure['cases']:
    result['hosts_pressure'].append({k: row[k] for k in ('side', 'source', 'expand', 'passed',
        'limit_bytes', 'initial_memory', 'pressure_tcp_healthy', 'exit_before_stop', 'exit', 'enomem_count')}
        | {'rounds': len(row['pressure_rounds']), 'udp_ready_and_lease_all': all(
            r[key]['udp']['expected_address'] for r in row['pressure_rounds'] for key in ('ready', 'lease_dns')),
            'dhcp_ack_all': all(r['dhcp']['message_type'] == 5 for r in row['pressure_rounds']),
            'recovery_udp_tcp': all(r['expected_address'] for r in row['recovered'].values())})
logging = read('logging-01/result.json')
assert not logging['failures'] and len(logging['scenarios']) == 6
result['logging'] = []
for row in logging['scenarios']:
    result['logging'].append({k: row[k] for k in ('side', 'scenario', 'failures', 'forced',
        'alive_before_release', 'exit', 'held_after_term_seconds', 'exit_after_release_seconds',
        'shutdown_records', 'query_records_after_term', 'answer_records_after_term')}
        | {'tail_messages': row['tail_messages'] if row['scenario'] == 'tail-drain' else None,
            'queries': row.get('queries')})
    for raw in row['raw'].values():
        path = Path(raw['path'])
        assert digest(path) == raw['sha256']
        artifacts[str(path)] = raw['sha256']
generation = read('generation-01/summary.json')
assert not generation['failures']
result['generation'] = {'queries_per_side': sum(r['queries_per_side'] for r in generation['rounds']),
    'rounds': [{k: r[k] for k in ('no_round_robin', 'queries_per_side', 'mismatches',
        'c_transition_errors', 'rust_transition_errors', 'raw_order_differences', 'calibration')}
        for r in generation['rounds']]}
result['tool_sha256'] = {name: digest(BASE / 'source/tools/dnsmasq' / name) for name in (
    'run_isolated.sh', 'm2_rootfs.py', 'audit_integration_resources.py', 'predeploy_hosts_pressure.py',
    'predeploy_logging_shutdown.py', 'predeploy_hosts_generation.py', 'dns_hosts_generation_diff.py',
    'recheck_hosts_limits.py')}
result['tool_revision_note'] = 'sweep-01/repeat-02/old-01 used private/recheck_hosts_limits-v1.py; final-03 uses committed driver. Only rcode extraction changed from absent key to flags & 15; fault setup is identical.'
v1 = PRIVATE / 'recheck_hosts_limits-v1.py'
artifacts[str(v1)] = digest(v1)
result['limits'] = [
    'RLIMIT_AS synthetic process ENOMEM, not cgroup/global OOM or physical-router failure rate.',
    'No failure call stack; SIGABRT is observed, not attributed to a single source allocation.',
    'Existing hosts snapshot fallback differs from C per-record state under failed reload.',
    'Fresh B6 replay covers three selected scenarios; the prior 329-scenario logging suite was inspected but not rerun.',
]
result['artifacts'] = artifacts
Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'artifacts': len(artifacts), 'hosts_pressure_cases': 8, 'logging_cases': 6,
                  'generation_queries_per_side': result['generation']['queries_per_side']}))
