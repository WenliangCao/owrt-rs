#!/usr/bin/env python3
"""Derive the final B1 evidence from retained synthetic Oracle results."""
import hashlib
import json
from pathlib import Path
import re
import shutil

BASE = Path('/home/ubuntu/dnsmasq-predeploy-fixes-20261014')
PRIVATE = BASE / 'hosts/private'
SOURCE = BASE / 'root/source-02'
RUST = BASE / 'root/private/sdk-acquire-02/payload/usr/sbin/dnsmasq'
RUST_SHA = '0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728'
C_SHA = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retained(path):
    return {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}


def read(case, filename='result.json'):
    path = PRIVATE / ('final-' + case + '-02') / filename
    return json.loads(path.read_text()), retained(path)


def dns(reply):
    if not reply['ok']:
        return {'received': False, 'error': reply['error']}
    parsed = reply['reply']
    return {'received': True, 'rcode': parsed['flags'] & 15, 'records': parsed['records']}


def memory(case):
    rows, evidence = read(case)
    output = []
    for row in rows:
        expected = C_SHA if row['side'] == 'c' else RUST_SHA
        assert row['binary_sha256'] == expected
        trace = PRIVATE / ('final-' + case + '-02') / ('memory-' + row['side']) / 'syscalls.log'
        text = trace.read_text()
        assert row['after_reload_exit'] is None and row['exit'] == 0
        assert row['during_pressure']['ok'] and row['recovered']['ok']
        assert any(r.get('data') == '192.0.2.41' for r in row['during_pressure']['reply']['records'])
        assert any(r.get('data') == '192.0.2.44' for r in row['recovered']['reply']['records'])
        if case == 'memory':
            assert 'ENOMEM' in text
        else:
            assert any(r.get('data') == '192.0.2.250' for r in row['last_host']['reply']['records'])
        output.append({'side': row['side'], 'binary_sha256': expected, 'initial': row['initial'],
                       'limit_bytes': row['limit_bytes'], 'after_reload_exit': row['after_reload_exit'],
                       'pressure': row['pressure_status'], 'probe_attempts': len(row['during_pressure_attempts']),
                       'ready_under_pressure': dns(row['during_pressure']), 'last_host': dns(row['last_host']),
                       'recovered': dns(row['recovered']), 'exit': row['exit'],
                       'enomem_count': text.count('ENOMEM'), 'sigabrt': 'SIGABRT' in text,
                       'syscalls': retained(trace)})
    return {'passed': True, 'cases': output, 'evidence': evidence}


def main():
    assert sha(RUST) == RUST_SHA
    result = {'source': json.loads((PRIVATE / 'identity-final-02.json').read_text()),
              'rust': retained(RUST), 'c_sha256': C_SHA,
              'commands': json.loads((PRIVATE / 'commands-final-02.json').read_text()),
              'original_b1': memory('memory'), 'unlimited_control': memory('memory-control')}
    pressure, evidence = read('pressure')
    assert pressure['passed'] and pressure['rust_sha256'] == RUST_SHA
    result['extended_pressure'] = {'passed': True, 'evidence': evidence, 'cases': []}
    for row in pressure['cases']:
        assert row['passed'] and row['binary_sha256'] == (C_SHA if row['side'] == 'c' else RUST_SHA)
        item = {k: row[k] for k in ('side', 'source', 'expand', 'initial_memory', 'limit_bytes',
                                   'pressure_tcp_healthy', 'exit_before_stop', 'exit', 'enomem_count',
                                   'syscalls_sha256')}
        item['rounds'] = [{'generation': phase['generation'], 'alive': phase['alive'],
                           'ready': {k: v['expected_address'] for k, v in phase['ready'].items()},
                           'lease_dns': {k: v['expected_address'] for k, v in phase['lease_dns'].items()},
                           'dhcp_ack': phase['dhcp']['message_type'] == 5, 'memory': phase['memory']}
                          for phase in row['pressure_rounds']]
        item['recovered'] = {k: v['expected_address'] for k, v in row['recovered'].items()}
        item['recovered_dhcp_ack'] = row['recovered_dhcp']['message_type'] == 5
        result['extended_pressure']['cases'].append(item)
    result['regressions'] = {}
    for name, count in [('boundaries', 8), ('memory-boundary', 3), ('startup', 3), ('startup-dhcp', 1)]:
        data, evidence = read(name)
        assert data.get('passed', not data.get('failures'))
        assert data.get('rust_sha256', data.get('binary_sha256', {}).get('rust')) == RUST_SHA
        result['regressions'][name] = {'passed': True, 'paired_cases': count, 'evidence': evidence}
    generation, evidence = read('generation', 'summary.json')
    assert not generation['failures'] and generation['rust_sha256'] == RUST_SHA
    result['regressions']['generation'] = {'passed': True, 'evidence': evidence,
        'queries_per_side': sum(row['queries_per_side'] for row in generation['rounds']),
        'no_round_robin_modes': [row['no_round_robin'] for row in generation['rounds']],
        'inventory_sha256': generation['inventory_sha256'], 'rotation_sha256': generation['rotation_sha256'],
        'scope': 'Image ELF answers; matching native C objects supply only inventory/rotation fixtures.'}
    log = PRIVATE / 'allocation-final-02.log'
    text = log.read_text()
    assert 'test result: ok. 5 passed; 0 failed' in text
    binary = BASE.parent / re.search(r'Running tests/hosts_allocations.rs \(([^)]+)\)', text)[1]
    artifact = PRIVATE / 'allocation-final-02-test'
    if not artifact.exists():
        shutil.copy2(binary, artifact)
    result['allocation_tests'] = {'passed': 5, 'failed': 0, 'log': retained(log), 'binary': retained(artifact),
        'scope': 'Separate AArch64 musl debug test executable from frozen source-02, not the shipped ELF.',
        'command': ['/home/ubuntu/.cargo/bin/cargo', '+1.98.1', 'test', '--frozen', '--target',
                    'aarch64-unknown-linux-musl', '--manifest-path', str(SOURCE / 'components/dnsmasq/Cargo.toml'),
                    '--test', 'hosts_allocations', '--', '--test-threads=1'],
        'environment': {'CARGO_TARGET_DIR': str(PRIVATE / 'allocation-target'),
                        'STAGING_DIR': '/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl',
                        'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER': '/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc'}}
    fixture = BASE / 'hosts/final-fixtures-02/docs/dnsmasq/audits/20261011/independent/dns_hosts_probe.py'
    result['harness_preparation'] = {
        'note': 'The first boundaries invocation stopped before daemon startup because source-02 omits documentation fixtures. Retried using the unchanged fixture from commit 807db8a1 via PYTHONPATH.',
        'initial_error': retained(PRIVATE / 'final-boundaries-02.stderr'), 'fixture': retained(fixture)}
    result['limits'] = [
        'C skips individual failed records; Rust can retain a previously published source/snapshot when staging or publication fails. Partial hosts contents under pressure are not asserted identical.',
        'C TCP children can fail under RLIMIT_AS while the parent still answers UDP/DHCP. Both implementations recover TCP after removing the limit; pressure TCP outcomes are retained separately.',
        'The allocator test covers parser/name expansion, records/diagnostics staging, indexes/removal and snapshot copies, including two consecutive copy failures. It is not a global daemon allocation-failure proof.',
        'A separate owner state-sequence unit test verifies restoring an invalid view before changing another hosts source; the complete binary test suite is reported by the parent validation.',
        'No global OOM-killer, arbitrary sustained allocator failure, physical router or target-kernel claim.']
    result['passed'] = True
    path = PRIVATE / 'summary-final-02.json'
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': True, 'summary': str(path), 'sha256': sha(path)}))


if __name__ == '__main__':
    main()
