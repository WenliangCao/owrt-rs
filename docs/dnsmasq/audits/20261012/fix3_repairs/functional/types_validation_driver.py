#!/usr/bin/env python3
"""Fresh complete validation after encapsulating the generic RR type summary.

48 daemon/family commands use the actual SDK payload; one original config-state
command compiles distinct native C/Rust read_opts probes, with separate identity. prepare does no workloads;
run never retries/replaces a failed window. A failed command keeps all evidence.
Performance and source packaging are intentionally separate controllers.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time


SELECTED = {
    'm5_config_inputs': 'RecordConfig raw encapsulation across config files and scripts',
    'm5_dns_cache': 'shared cache/local precedence, negatives, CNAME, stale and TCP caller',
    'm5_edns': 'DO/RD/EDNS reply construction and truncation',
    'm5_local_records': 'shared configured records and Additional records',
    'm5_option_matrix': 'known-name, localise, local precedence and rebind semantics',
    'm5_option_matrix_next': 'TCP admission and forwarding controls surrounding shared answer',
    'm5_option_matrix_third': 'local/address/bogus-nxdomain rules and CNAME terminals',
    'm5_option_matrix_lease_names': 'fresh DHCP names versus existing cached negatives',
    'm5_rr_filter': 'shared answer and forwarded RR filtering',
    'filterwin2k': 'N1 filtered CNAME, RD/DO/SOA/SRV combinations',
    'm5_dns_endpoints': 'shared terminal local/server/address selection',
    'm5_interface_records': 'shared interface, synthesis and inherited TCP views',
    'dns-files': 'TCP snapshots and published hosts/resolver changes',
    'logging-all-scopes': 'shared answer log origin and ordinary/debug lifecycle',
}


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--plan', type=Path, required=True)
    for name in ('source', 'image-root', 'rust', 'main', 'link-map', 'base-identity', 'reference-build', 'state-probe-driver', 'out'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--source-commit')
    parser.add_argument('--rust-sha256')
    parser.add_argument('--tool-commit')
    args = parser.parse_args()
    frozen_source = args.source if args.action == 'prepare' else Path(read(args.plan)['source'])
    if frozen_source is None:
        parser.error('--source required for prepare')
    shared_checks = frozen_source / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional'
    sys.path.insert(0, str(shared_checks))
    from result_checks import check_acl, check_matrix, check_n1, check_n2, observe_stale
    from types_result_checks import check_original_dns
    if args.action == 'prepare':
        for name in ('source', 'image_root', 'rust', 'main', 'link_map', 'base_identity', 'reference_build', 'state_probe_driver', 'out', 'source_commit', 'rust_sha256', 'tool_commit'):
            if not getattr(args, name):
                parser.error('--' + name.replace('_', '-') + ' required for prepare')
        assert not args.plan.exists() and not args.out.exists()
        source = args.source.resolve()
        tools = source / 'tools/dnsmasq'
        sys.path.insert(0, str(tools))
        import m5_final_validation as final
        import build_package as package
        from m2_rootfs import STOCK_SHA256
        assert sha(args.rust) == args.rust_sha256
        assert sha(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
        review1 = source / 'docs/dnsmasq/audits/20261011/independent'
        review2 = source / 'docs/dnsmasq/audits/20261011/fix2'
        review3 = source / 'docs/dnsmasq/audits/20261012/fix3'
        current = shared_checks
        state_probe_output = args.out / 'config-state-probe'
        jobs = [{'id': 'config-state-probe', 'argv': [
                    'env', 'RUSTUP_HOME=/home/ubuntu/.rustup', 'CARGO_HOME=/home/ubuntu/.cargo',
                    'PATH=/home/ubuntu/.cargo/bin:/usr/bin:/bin', sys.executable,
                    str(args.state_probe_driver), '--source', str(source),
                    '--reference-build', str(args.reference_build), '--out', str(state_probe_output)],
                 'result': str(state_probe_output / 'result.json'), 'custom_check': 'state-probe',
                 'reference_binary_sha256': sha(args.reference_build / 'dnsmasq/dnsmasq'),
                 'timeout_seconds': 1800}]
        def directed(name, script, arguments, check, timeout=1800):
            output = args.out / name
            argv = ['sh', str(tools / 'run_isolated.sh'), sys.executable, str(script),
                    *map(str, arguments), '--out', str(output)]
            jobs.append({'id': name, 'argv': argv, 'result': str(output / 'result.json'),
                         'custom_check': check, 'timeout_seconds': timeout})
        image_args = ['--image-root', args.image_root, '--rust', args.rust]
        matrix_args = ['--tools', tools, '--image-root', args.image_root, '--main', args.main, '--fix', args.rust]
        directed('F02-cached-cname', review1 / 'dns_hosts_cname.py', [*image_args, '--require-match'], 'pass')
        directed('fresh-DHCP-over-NXDOMAIN', review1 / 'dns_hosts_stale.py', ['--tools', tools, *image_args, '--fresh-only', '--require-match'], 'pass')
        directed('F08-stale-observation', review1 / 'dns_hosts_stale.py', ['--tools', tools, *image_args], 'stale')
        directed('R1-cname', review2 / 'dns/cname_compat.py', [*image_args, '--require-match'], 'r1')
        directed('R1-flags', review2 / 'dns/cname_flags.py', [*image_args, '--require-match'], 'flags')
        directed('N1-filter-cname', review3 / 'dns/filter_cname_tcp.py', matrix_args, 'n1')
        directed('review3-matrix', review3 / 'dns/matrix.py', matrix_args, 'matrix')
        directed('TCP-UDP-parity', current / 'tcp_udp_parity.py', ['--tools', tools, *image_args,
                 '--matrix-source', review3 / 'dns/matrix.py'], 'parity')
        directed('A10-and-original-DNS', tools / 'audit_20261011_dns.py', image_args, 'audit')
        directed('N2-intentional-permissions', review3 / 'dhcp/hosts_permissions.py', ['--source', source,
                 '--image', args.image_root, '--main', args.main, '--fix', args.rust], 'n2')
        directed('O3-auth-ACL', review2 / 'config/config_normal.py', ['--source', source,
                 '--image', args.image_root, '--rust', args.rust], 'acl')
        spec = read(args.base_identity)
        spec.update(source_root=str(source), tools_root=str(tools), source_commit=args.source_commit,
                    image_root=str(args.image_root), elf=str(args.rust), elf_sha256=args.rust_sha256,
                    selected_families=list(SELECTED), family_registry=read(tools / 'm5_final_families.draft.json'))
        spec.pop('family_tool_overrides', None)
        spec['bindings']['link_map'] = str(args.link_map)
        family_jobs = final.commands(spec, 'families', args.out / 'families')
        assert len(family_jobs) == 35 and {job['family'] for job in family_jobs} == set(SELECTED)
        jobs += family_jobs
        directed('hosts-original-TCP', review1 / 'dns_hosts_probe.py', image_args, 'hosts-original')
        directed('hosts-diagnostics-TCP', tools / 'audit_fix_20261011_hosts.py', image_args, 'hosts-diagnostics')
        assert len(jobs) == 49
        assets = {str(path): sha(path) for path in (args.rust, args.main, args.link_map,
                  args.image_root / 'usr/sbin/dnsmasq', args.base_identity, args.state_probe_driver, Path(__file__).resolve())}
        # Native state probes are not SDK daemon artifacts. Bind their exact
        # patched C objects, headers and helper libraries separately.
        assets.update({str(path): sha(path) for path in args.reference_build.rglob('*') if path.is_file()})
        for root in (tools, review1, review2, review3, current):
            assets.update({str(path): sha(path) for path in root.rglob('*')
                           if path.is_file() and '__pycache__' not in path.parts and path.suffix in ('.py', '.sh', '.json')})
        plan = {'schema': 'dnsmasq-fix3-types-functional-v2', 'tool_commit': args.tool_commit, 'source': str(source), 'source_commit': args.source_commit,
                'rust': str(args.rust), 'rust_sha256': args.rust_sha256, 'output': str(args.out),
                'source_files': package.inputs(source), 'assets': assets, 'selected_families': SELECTED,
                'directed_commands': 14, 'SDK_daemon_family_commands': 48, 'native_state_probe_commands': 1, 'family_commands': len(family_jobs), 'jobs': jobs,
                'reference_build': str(args.reference_build), 'limits': 'All 49 commands run fresh; no prior pass reused. F08 stale remains explicitly observed; two inherited forward-pointer differences retained; nine C-internal UDP/TCP mismatches follow shared UDP behavior; no arbitrary differences waived'}
        args.plan.parent.mkdir(parents=True, exist_ok=True)
        save(args.plan, plan)
        print(json.dumps({'prepared': True, 'commands': len(jobs), 'plan_sha256': sha(args.plan)}))
        return
    assert os.geteuid() == 0 and not sys.flags.optimize
    plan = read(args.plan)
    source, output = Path(plan['source']), Path(plan['output'])
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    import m5_final_validation as final
    import build_package as package
    from m2_rootfs import STOCK_SHA256
    def identity():
        assert package.inputs(source) == plan['source_files']
        for path, digest in plan['assets'].items():
            assert sha(path) == digest, path
    identity()
    output.mkdir(parents=True, exist_ok=False)
    state = {'passed': False, 'plan_sha256': sha(args.plan), 'source_commit': plan['source_commit'],
             'elf_sha256': plan['rust_sha256'], 'commands': [], 'families': {}}
    save(output / 'state.json', state)
    for job in plan['jobs']:
        record = dict(job, passed=False, started=time.time())
        state['commands'].append(record)
        save(output / 'state.json', state)
        print('START', job['id'], flush=True)
        with (output / (job['id'] + '.log')).open('wb') as log:
            process = subprocess.Popen(job['argv'], cwd=source, stdout=log, stderr=log, start_new_session=True)
            descendants = {}
            try:
                while process.poll() is None:
                    final.remember_job_processes(process, descendants)
                    if time.time() - record['started'] > job['timeout_seconds']:
                        raise TimeoutError(job['id'])
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                final.stop_job_processes(process, descendants)
        record['returncode'] = process.returncode
        try:
            assert process.returncode == 0, f'exit {process.returncode}'
            value = read(job['result'])
            check = job.get('custom_check')
            if check in ('pass', 'r1', 'flags', 'parity'):
                assert value['passed']
            if check == 'r1':
                assert len(value['cases']) == 20
            if check == 'flags':
                assert len(value['cases']) == 16
            if check == 'parity':
                assert len(value['profiles']) == 56 and value['case_count'] == 1736
            if check in ('n1', 'matrix', 'n2', 'stale', 'acl'):
                record['strict_result'] = {'n1': check_n1, 'matrix': check_matrix,
                                          'n2': check_n2, 'stale': observe_stale, 'acl': check_acl}[check](value)
                assert record['strict_result']['passed'], record['strict_result']
            if check == 'audit':
                record['strict_result'] = check_original_dns(value)
                assert record['strict_result']['passed']
            if check == 'state-probe':
                assert value['cases'] == 19 and not value['failures']
                assert value['accepted'] >= 10 and value['rejected'] >= 2
                assert len(value['results']) == 19 and all(row['match'] for row in value['results'])
                assert value['reference_binary_sha256'] == job['reference_binary_sha256']
                folder = Path(job['result']).parent
                record['native_probe_identity'] = {name: {'path': str(folder / name), 'sha256': sha(folder / name)}
                                                    for name in ('c-state', 'rust-state', 'state_probe.c', 'dnsmasq-without-main.o')}
                record['probe_scope'] = value['scope']
                adaptation = read(folder / 'adapter-identity.json')
                assert adaptation['probe_imports_only'] and adaptation['C_corpus_and_comparison_unchanged']
                assert adaptation['target'] == 'aarch64-unknown-linux-gnu' and adaptation['features'] == ''
                assert adaptation['source'] == str(source)
                assert sha(folder / 'rust-state') == adaptation['cargo_probe_sha256']
                record['native_adapter_identity'] = adaptation
                record['native_adapter_receipt'] = {'path': str(folder / 'adapter-identity.json'), 'sha256': sha(folder / 'adapter-identity.json')}
            if check in ('hosts-original', 'hosts-diagnostics'):
                assert value['rust_sha256'] == plan['rust_sha256'] and value['c_sha256'] == STOCK_SHA256
                if check == 'hosts-original':
                    assert len(value['rows']) == 4
                    for row in value['rows']:
                        assert row['c']['alive'] and row['rust']['alive']
                        assert {k: v for k, v in row['c'].items() if k != 'dump'} == {k: v for k, v in row['rust'].items() if k != 'dump'}
                        if row['mode'] in ('addn-hosts', 'hostsdir'):
                            diagnostics = {side: re.findall(r'bad (?:name|address) at [^\n]+', row[side]['dump']) for side in ('c', 'rust')}
                            assert diagnostics['c'] and diagnostics['c'] == diagnostics['rust']
                            assert any(value.startswith('bad name at ') and value.endswith(' line 6') for value in diagnostics['c'])
                else:
                    assert value['passed'] and len(value['cases']) == 8
            if 'family' in job:
                final.check_result(Path(job['result']), job['checks'], job.get('inventory'))
            record.update(passed=True, result_sha256=sha(job['result']))
        except Exception as error:
            record['error'] = repr(error)
        record['elapsed_seconds'] = time.time() - record['started']
        save(output / 'state.json', state)
        print('PASS' if record['passed'] else 'FAIL', job['id'], record.get('error'), flush=True)
        if not record['passed']:
            raise SystemExit(1)
    identity()
    for family in SELECTED:
        expected = [job for job in plan['jobs'] if job.get('family') == family]
        actual = [job for job in state['commands'] if job.get('family') == family]
        assert len(expected) == len(actual) and all(job['passed'] for job in actual)
        state['families'][family] = {'passed': True, 'commands': len(actual)}
    assert len(state['commands']) == 49
    state['passed'] = True
    save(output / 'state.json', state)
    print('ALL PASS', flush=True)


if __name__ == '__main__':
    main()
