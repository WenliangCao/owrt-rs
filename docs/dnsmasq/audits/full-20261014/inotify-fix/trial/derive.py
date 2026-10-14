#!/usr/bin/env python3
"""Check the requested single trial result and retain raw evidence identities."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

BASE = Path('/dev/shm/full-inotify-trial-20261014/private')
CASE = 'confirmed-rollback-killed'
EXPECTED = 'edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d'
STOCK = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'


def read(name):
    return json.loads((BASE / name).read_text())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    pre, post = read('preflight.json'), read('postflight.json')
    suite, tools = read('trial-suite.json'), read('source-tools-verification.json')
    row = read('trial-' + CASE + '/result.json')
    receipt = read('trial-' + CASE + '.receipt.json')
    steps = row['steps']
    clients = {'stock_client': row['stock_client'],
               'candidate_client': steps['candidate_client'],
               'automatic_recovery_client': steps['automatic_recovery_client']}
    healthy = {name: all((client['dhcp_offer'], client['dhcp_ack'], client['dns']['udp'],
        client['dns']['tcp'], client['server'] == '192.168.1.1',
        client['dns_option'] == '192.168.1.1', client['router_option'] == '192.168.1.1'))
        for name, client in clients.items()}
    processes = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            root = os.readlink(proc / 'root')
            if root.startswith(str(BASE)):
                processes.append({'pid': int(proc.name), 'root': root})
        except OSError:
            pass
    mounts = [line for line in Path('/proc/self/mountinfo').read_text().splitlines() if str(BASE) in line]
    cleanup = {'fixture_processes_remaining': processes, 'fixture_mounts_in_host_namespace': mounts,
               'clean': not processes and not mounts, 'recorded_at': datetime.now(timezone.utc).isoformat()}
    (BASE / 'cleanup-receipt.json').write_text(json.dumps(cleanup, indent=2) + '\n')
    checks = {
        'one_requested_case_only': len(suite['cases']) == 1 and row['case'] == CASE,
        'raw_result_passed': row['passed'] is True,
        'runner_exit_zero': receipt['exit'] == 0,
        'candidate_input_matches': row['candidate_sha256'] == EXPECTED,
        'candidate_running_elf_matches': steps['candidate']['sha256'] == EXPECTED,
        'stock_initial_elf_matches': row['stock_initial']['sha256'] == STOCK,
        'stock_recovery_elf_matches': steps['automatic_recovery']['sha256'] == STOCK,
        'trial_script_matches_preflight': row['trial_sha256'] == pre['tools_sha256']['deploy/dnsmasq-trial'],
        'tools_match_source_commit': tools['all_match'],
        'pre_post_identities_unchanged': post['unchanged'] and suite['identities_unchanged'],
        'fault_after_unmount': row['fault']['phase'] == 'unmounted' and row['fault']['mounted'] is False,
        'actual_sigkill': row['fault']['signal'] == 'SIGKILL' and row['rollback_exit'] == -9,
        'automatic_helpers_cleared': steps['helpers_cleared'] is True,
        'all_dhcp_and_dns_clients_healthy': all(healthy.values()),
        'raw_result_receipt_hash_matches': receipt['result_sha256'] == sha256(BASE / ('trial-' + CASE) / 'result.json'),
        'cleanup_complete': cleanup['clean'],
    }
    tools.pop('files')
    result = {'passed': all(checks.values()), 'case': CASE, 'checks': checks,
        'source_commit': pre['source_commit'], 'source_path': pre['source_path'],
        'candidate_path': pre['candidate_path'], 'candidate_sha256': EXPECTED,
        'stock_sha256': STOCK, 'trial_sha256': row['trial_sha256'],
        'trial_harness_sha256': pre['tools_sha256']['test_trial_oracle.py'],
        'source_tools_verification': tools, 'case_count': 1, 'client_check_count': len(healthy),
        'client_checks': healthy, 'fault': row['fault'], 'rollback_exit': row['rollback_exit'],
        'started_at': receipt['started_at'], 'finished_at': receipt['finished_at'],
        'elapsed_seconds': receipt['elapsed_seconds'], 'error': row.get('error'),
        'runner_error': receipt.get('runner_error'), 'cleanup': cleanup,
        'raw_root': str(BASE), 'argv_receipt': str(BASE / ('trial-' + CASE + '.command.json')),
        'result_sha256': receipt['result_sha256'], 'physical_router_accessed': False,
        'scope': 'One requested recovery case only; exact-image Oracle fixture; isolated network, mount and PID namespaces.'}
    (BASE / 'derived-result.json').write_text(json.dumps(result, indent=2) + '\n')
    index = {str(path.relative_to(BASE)): {'sha256': sha256(path), 'bytes': path.stat().st_size}
        for path in sorted(BASE.rglob('*')) if path.is_file() and not path.is_symlink()
        and path.name != 'raw-index.json'}
    (BASE / 'raw-index.json').write_text(json.dumps(index, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
