#!/usr/bin/env python3
"""Derive compact trial checks without substituting for original results."""
import hashlib
import json
from pathlib import Path

BASE = Path('/dev/shm/full-final-trial-20261014/private')
EXPECTED = 'fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b'
STOCK = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
FAULT_PHASES = {'rollback-killed': 'requested', 'confirmed-rollback-killed': 'unmounted',
                'rollback-cleanup-killed': 'helpers-cleared'}
FAULTS = {
    'confirm-rollback': 'confirm; wait 12 seconds; explicit rollback twice',
    'deadline': 'unconfirmed candidate; deadline 20 seconds',
    'crash': 'bind static exit(1) ELF over candidate; SIGKILL running candidate',
    'hang': 'SIGSTOP running candidate',
    'watch-killed': 'SIGKILL watch helper; deadline 25 seconds',
    'partial-rollback': 'SIGKILL watch and deadline helpers; unmount candidate; explicit rollback',
    'reload': 'stock init reload; assert candidate PID unchanged',
    'rollback-killed': 'ptrace observes rollback request with candidate mounted; SIGKILL rollback process',
    'confirmed-rollback-killed': 'confirm candidate; ptrace observes unmount; SIGKILL rollback process',
    'rollback-cleanup-killed': 'ptrace observes helpers cleared; SIGKILL rollback process',
    'rollback-c-dns-loss': 'drop UDP and TCP DNS; reject unhealthy C; retain owners; remove drop rules; automatic recovery',
    'documented-path': 'documented /tmp script and ELF; confirm; explicit rollback; reject bad upload hash',
}


def read(name):
    return json.loads((BASE / name).read_text())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    suite = read('trial-suite.json')
    pre, post = read('preflight.json'), read('postflight.json')
    rows = []
    for receipt in suite['cases']:
        case = receipt['case']
        result_path = BASE / ('trial-' + case) / 'result.json'
        report = json.loads(result_path.read_text())
        steps = report.get('steps', {})
        clients = {'stock_client': report.get('stock_client', {})}
        clients.update({name: value for name, value in steps.items() if name.endswith('_client')})
        client_checks = {name: all((value.get('dhcp_offer') is True, value.get('dhcp_ack') is True,
            value.get('dns', {}).get('udp') is True, value.get('dns', {}).get('tcp') is True,
            value.get('server') == '192.168.1.1', value.get('dns_option') == '192.168.1.1',
            value.get('router_option') == '192.168.1.1')) for name, value in clients.items()}
        identities = {'stock_initial': report.get('stock_initial', {}).get('sha256')}
        identities.update({name: value['sha256'] for name, value in steps.items()
                           if isinstance(value, dict) and 'sha256' in value})
        expected_identities = {name: EXPECTED if name == 'candidate' else STOCK for name in identities}
        checks = {
            'raw_result_passed': report.get('passed') is True,
            'runner_exit_zero': receipt['exit'] == 0,
            'same_candidate_elf': report.get('candidate_sha256') == EXPECTED,
            'stock_image_elf': report.get('stock_sha256') == STOCK,
            'frozen_trial_script': report.get('trial_sha256') == pre['tools_sha256']['deploy/dnsmasq-trial'],
            'result_receipt_hash': receipt['result_sha256'] == sha256(result_path),
            'candidate_process_observed': identities.get('candidate') == EXPECTED,
            'all_process_identities_match': identities == expected_identities,
            'stock_candidate_recovery_clients_present': len(client_checks) >= 3 and 'candidate_client' in client_checks,
            'all_dhcp_and_dns_clients_healthy': all(client_checks.values()),
        }
        if case in FAULT_PHASES:
            fault = report.get('fault', {})
            checks.update(injected_phase_matches=fault.get('phase') == FAULT_PHASES[case],
                          injected_signal_sigkill=fault.get('signal') == 'SIGKILL',
                          rollback_was_killed=report.get('rollback_exit') == -9,
                          helpers_cleared=steps.get('helpers_cleared') is True)
        if case == 'rollback-c-dns-loss':
            checks.update(unhealthy_c_rejected=report.get('unhealthy_rollback', {}).get('exit') == 1,
                          owners_kept_for_unresponsive_c=steps.get('owners_kept_for_unresponsive_c') is True)
        if case == 'documented-path':
            checks['bad_upload_hash_rejected'] = steps.get('bad_upload_hash_rejected') is True
        rows.append({'case': case, 'passed': all(checks.values()), 'checks': checks,
            'fault_or_boundary': FAULTS[case], 'fault': report.get('fault'),
            'error': report.get('error'), 'runner_error': receipt.get('runner_error'),
            'elapsed_seconds': receipt['elapsed_seconds'], 'process_sha256': identities,
            'client_checks': client_checks, 'result_sha256': receipt['result_sha256'],
            'receipt': str(BASE / ('trial-' + case + '.receipt.json'))})
    summary = {'passed': suite['passed'] and all(row['passed'] for row in rows),
        'source_commit': suite['source_commit'], 'candidate_path': pre['candidate_path'],
        'candidate_sha256': EXPECTED, 'stock_sha256': STOCK,
        'trial_sha256': pre['tools_sha256']['deploy/dnsmasq-trial'],
        'source_tools_verification': read('source-tools-verification.json'),
        'image_root': pre['image_root'], 'raw_root': str(BASE),
        'started_at': min(row['started_at'] for row in suite['cases']),
        'finished_at': max(row['finished_at'] for row in suite['cases']),
        'max_workers': 2, 'timeout_seconds_per_case': 210,
        'identities_unchanged': suite['identities_unchanged'] and post['unchanged'],
        'case_count': len(rows), 'passed_case_count': sum(row['passed'] for row in rows),
        'client_check_count': sum(len(row['client_checks']) for row in rows),
        'case_failures': [row['case'] for row in rows if not row['passed']],
        'cases': rows, 'physical_router_accessed': False,
        'scope': 'Oracle exact-image fixture; isolated network, mount, PID namespaces; same frozen ELF and tools',
        'setup_note': 'Unprivileged initial mkdir under /dev/shm was denied; dedicated empty directory created with sudo before any case ran. No test failure was discarded.'}
    summary['source_tools_verification'].pop('files')
    (BASE / 'derived-result.json').write_text(json.dumps(summary, indent=2) + '\n')
    index = {str(path.relative_to(BASE)): {'sha256': sha256(path), 'bytes': path.stat().st_size}
        for path in sorted(BASE.rglob('*')) if path.is_file() and not path.is_symlink()
        and path.name != 'raw-index.json'}
    (BASE / 'raw-index.json').write_text(json.dumps(index, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items() if key != 'cases'}))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
