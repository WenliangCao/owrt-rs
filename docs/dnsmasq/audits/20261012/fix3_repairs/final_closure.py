#!/usr/bin/env python3
"""Read retained build, functional and performance receipts; never run workloads.

Run git-witness on the working repository, then remote on Oracle only after all
controllers have exited. Counts come from frozen inventories, not old rounds.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path('/home/ubuntu/dnsmasq-fix3-repair-20261013')
COMMIT = '0ff33bb025bd789aac78e3f6878456449fbde7fc'
MAIN = 'be531cee49e366bb5044443d473944dbea45b87e'
BRANCH = 'fix/audit-20261011'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def digest(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def file(path):
    path = Path(path)
    return dict(path=str(path), sha256=sha(path), bytes=path.stat().st_size)


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def witness(args):
    repo = args.repo.resolve()
    sys.path.insert(0, str(repo / 'tools/dnsmasq'))
    import build_package
    files = build_package.inputs(repo)
    assert files
    assert git(repo, 'rev-parse', 'main').decode().strip() == MAIN
    assert git(repo, 'branch', '--show-current').decode().strip() == BRANCH
    for name, value in files.items():
        for ref in (COMMIT, 'HEAD'):
            assert hashlib.sha256(git(repo, 'show', ref + ':' + name)).hexdigest() == value, (ref, name)
    result = dict(passed=True, created_unix=time.time(), source_commit=COMMIT,
        main_actual=MAIN, head=git(repo, 'rev-parse', 'HEAD').decode().strip(), branch=BRANCH,
        product_input_count=len(files), source_digest=digest(files), source_files=files,
        worktree_status=git(repo, 'status', '--short').decode(),
        scope='Current worktree and HEAD product inputs equal frozen commit; unrelated user files retained.')
    save(args.out, result)
    print(json.dumps({k: v for k, v in result.items() if k not in ('source_files', 'worktree_status')}))
    return 0


def remote(args):
    root = args.root.resolve()
    private, source = root / 'private', root / 'source'
    report = dict(passed=False, created_unix=time.time(), controller=file(__file__), argv=sys.argv,
        checks={}, inputs={}, limits=[
            'Integrity/cleanup closure only; this does not waive size budgets or authorize deployment.',
            'Functional identity is bound through frozen SDK bytes, actual command argv and retained result identities.',
            'Local Git is independently read by the witness; regenerate after any product/main change.',
            'Nine exact C UDP/TCP routing differences retain the frozen shared-UDP disposition; no blanket waiver.',
            'Original C malformed/transport differences and stale observations remain in their explicit result checks.'])
    handles = []

    def check(name, value):
        if not value:
            raise ValueError(name)
        report['checks'][name] = True

    def bind(name, path):
        report['inputs'][name] = file(path)

    try:
        check('root_and_assertions', os.geteuid() == 0 and not sys.flags.optimize)
        local = read(args.git_witness)
        check('git_witness', local['passed'] and local['source_commit'] == COMMIT
              and local['main_actual'] == MAIN and local['branch'] == BRANCH)
        bind('git_witness', args.git_witness)
        sys.path.insert(0, str(source / 'tools/dnsmasq'))
        import build_package
        import m5_final_validation as final
        build = read(private / 'build-result.json')
        manifests = [read(private / name / 'manifest.json') for name in ('sdk-acquire', 'sdk-verify')]
        for lock in (Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock'),
                     Path(manifests[1]['sdk']['path']) / '.owrt-dnsmasq-build.lock'):
            handle = lock.open('r')
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            handles.append(handle)
        check('build_sdk_performance_locks_idle', True)
        excluded, busy = final.related_processes(), []
        for path in Path('/proc').glob('[0-9]*/cmdline'):
            if int(path.parent.name) in excluded:
                continue
            try:
                raw = path.read_bytes()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if not raw:
                continue
            parts = raw.split(b'\0')
            argv = b' '.join(parts).decode(errors='replace')
            executable = Path(parts[0].decode(errors='replace')).name
            if str(root) in argv or executable in {
                'cargo', 'rustc', 'make', 'perf', 'strace', 'dnsmasq', 'dnsmasq-rs', 'm6a_loadgen', 'm6a_upstream'}:
                busy.append(dict(pid=int(path.parent.name), argv=argv))
        report['remaining_workloads'] = busy
        check('no_task_or_matching_workloads', not busy)

        identity_path = private / 'source-identity.json'
        identity = read(identity_path)
        files = build_package.inputs(source)
        check('product_inputs_match_frozen_git', bool(files) and files == identity['source_files'] == local['source_files'])
        check('source_count_digest_revision', len(files) == identity['source_input_count'] == local['product_input_count']
              and digest(files) == identity['source_digest'] == local['source_digest'] and identity['source_commit'] == COMMIT)
        check('source_archive', sha(private / 'source.tar') == identity['source_archive_sha256'])
        bind('source_identity', identity_path)
        check('build_complete', build['passed'] and build['source_commit'] == COMMIT
              and build['source_digest'] == digest(files) and build['identity_sha256'] == sha(identity_path))
        check('build_controllers', build['controller_sha256'] == sha(private / 'build_sequence.py')
              and build['sdk_driver_sha256'] == sha(private / 'sdk_source_build.py'))
        commands = {row['name']: row for row in build['commands']}
        check('build_stage_inventory', len(commands) == len(build['commands']) and set(commands) == {
            'release-build', 'tests-build', 'lib-dnsmasq_rs', 'bin-dnsmasq-rs', 'sdk-acquire', 'sdk-verify'})
        for name, row in commands.items():
            check('build_log_' + name, sha(row['log_path']) == row['log_sha256'])
        for kind in ('release', 'tests'):
            folder = private / kind
            receipt = read(folder / 'build.json')
            check(kind + '_receipt', commands[kind + '-build']['returncode'] == 0
                  and sha(folder / 'build.json') == commands[kind + '-build']['build_receipt_sha256']
                  and receipt['source'] == str(source) and receipt['kind'] == kind)
            for artifact in receipt['artifacts']:
                check(kind + '_artifact_' + artifact['path'], sha(folder / artifact['path']) == artifact['sha256'])
        totals = {}
        for name in ('lib-dnsmasq_rs', 'bin-dnsmasq-rs'):
            row = commands[name]
            found = re.search(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', Path(row['log_path']).read_text())
            actual = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'), map(int, found.groups()))) if found else None
            check('ordinary_unit_' + name, row['returncode'] == 0 and actual == row['counts']
                  and row['counts']['failed'] == row['counts']['filtered_out'] == 0
                  and sha(private / 'tests' / name) == row['elf_sha256'])
            for key, value in actual.items():
                totals[key] = totals.get(key, 0) + value
        check('unit_aggregate', totals == build['ordinary_units'])
        report['ordinary_units'] = totals
        for name, manifest in zip(('sdk-acquire', 'sdk-verify'), manifests):
            folder = private / name
            check(name + '_manifest', sha(folder / 'manifest.json') == commands[name]['manifest_sha256'])
            check(name + '_real_source_build', manifest['build_mode'] == 'compile-and-package' and not manifest['frozen_elf']
                  and not manifest.get('error') and all(manifest[k] for k in ('source_build_passed', 'source_inputs_unchanged',
                  'sdk_inputs_unchanged', 'sdk_recipe_restored', 'sdk_strip_payload_identity_verified')))
            check(name + '_source_identity', manifest['source_commit'] == COMMIT and manifest['source_files'] == files
                  and manifest['source_digest'] == digest(files) and build_package.inputs(Path(manifest['fixed_source_path'])) == files)
            check(name + '_stages', manifest['stages'] == {'prepare': {'exit_code': 0}, 'compile': {'exit_code': 0}}
                  and len(manifest['commands']) == 2 and all(not any('FROZEN_ELF' in arg for arg in row) for row in manifest['commands']))
            for key in ('elf', 'artifact', 'pre_sdk_strip_elf'):
                check(name + '_' + key, sha(manifest[key]['path']) == manifest[key]['sha256'])
            check(name + '_sstrip', sha(folder / 'dnsmasq-sdk-sstrip') == manifest['elf']['sha256'])
            check(name + '_sdk_identity', build_package.sdk_inputs(Path(manifest['sdk']['path'])) == manifest['sdk']['files'])
            check(name + '_budget_status_retained', commands[name]['returncode'] == (1 if manifest.get('budget_error') else 0)
                  and (not manifest.get('budget_error') or manifest['failure_boundary'] == 'size-target'))
            bind(name + '_manifest', folder / 'manifest.json')
        first, second = manifests
        sdk_sha = first['elf']['sha256']
        release_sha = sha(private / 'release/dnsmasq-rs')
        check('sdk_clean_rebuild', second['prior_build_tree_archived'] and Path(second['prior_build_tree_archived']).is_dir()
              and first['fixed_build_path'] == second['fixed_build_path']
              and second['artifact_identity_verified'] and second['apk_byte_identical']
              and second['elf']['sha256'] == sdk_sha and first['artifact']['sha256'] == second['artifact']['sha256'])
        check('exact_link_map_identity', sha(second['link_map']['path']) == second['link_map']['sha256']
              and build['exact_sdk_link_map'] == second['link_map'] and build['map_build_elf_and_apk_identical_to_standard'])
        check('sdk_build_aggregate', build['sdk_elf_sha256'] == sdk_sha and build['sdk_apk_sha256'] == first['artifact']['sha256']
              and build['original_budget_passed'] == (not first.get('budget_error')))
        report['original_budget'] = {name: manifest['budget_checks'] for name, manifest in zip(('acquire', 'verify'), manifests)}
        bind('build_result', private / 'build-result.json')

        plan_path = args.functional_plan or private / 'functional-plan.json'
        plan = read(plan_path)
        functional = Path(plan['output'])
        state = read(functional / 'state.json')
        check('original_functional_identity', not state['passed'] and state['source_commit'] == plan['source_commit'] == COMMIT
              and state['plan_sha256'] == sha(plan_path)
              and len(plan['jobs']) == plan['directed_commands'] + plan['family_commands'])
        check('functional_source_elf', plan['source_files'] == files and sha(plan['rust']) == plan['rust_sha256'] == state['elf_sha256'] == sdk_sha)
        check('functional_assets', all(sha(path) == expected for path, expected in plan['assets'].items()))
        failed_index = next(i for i, job in enumerate(plan['jobs']) if job['id'] == 'A10-and-original-DNS')
        check('original_stopped_at_strict_baseline', len(state['commands']) == failed_index + 1)
        functional_results = {}
        for expected, actual in zip(plan['jobs'][:failed_index], state['commands'][:failed_index]):
            name = expected['id']
            check('functional_command_' + name, all(actual[key] == value for key, value in expected.items())
                  and actual['passed'] and actual['returncode'] == 0 and sha(actual['result']) == actual['result_sha256'])
            if 'strict_result' in actual:
                check('functional_strict_' + name, actual['strict_result']['passed'])
            functional_results[name] = dict(result=file(actual['result']), log=file(functional / (name + '.log')))
        bind('functional_plan', plan_path)
        bind('original_functional_failed_state', functional / 'state.json')

        supplement_path = args.supplemental_plan or private / 'functional-supplement-plan.json'
        supplement = read(supplement_path)
        check('supplemental_primary_binding', Path(supplement['primary_plan']) == plan_path
              and supplement['primary_plan_sha256'] == sha(plan_path)
              and Path(supplement['primary_state']) == functional / 'state.json')
        check('supplemental_identity', supplement['source_commit'] == COMMIT
              and Path(supplement['source']) == source
              and sha(supplement['rust']) == supplement['rust_sha256'] == sdk_sha and bool(supplement['jobs']))
        check('supplemental_assets', all(sha(path) == expected for path, expected in supplement['assets'].items()))
        bind('supplemental_plan', supplement_path)

        continuation_path = args.continuation_plan or private / 'functional-continuation-plan.json'
        continuation = read(continuation_path)
        continuation_out = Path(continuation['output'])
        continuation_state_path = continuation_out / 'state.json'
        complete = read(continuation_state_path)
        check('continuation_frozen_inputs', Path(continuation['primary_plan']) == plan_path
              and continuation['primary_plan_sha256'] == sha(plan_path)
              and Path(continuation['primary_state']) == functional / 'state.json'
              and continuation['primary_state_sha256'] == sha(functional / 'state.json')
              and Path(continuation['supplement_plan']) == supplement_path
              and continuation['supplement_plan_sha256'] == sha(supplement_path))
        check('continuation_identity', continuation['source_commit'] == complete['source_commit'] == COMMIT
              and continuation['source_files'] == files and Path(continuation['source']) == source
              and sha(continuation['rust']) == continuation['rust_sha256'] == complete['elf_sha256'] == sdk_sha
              and complete['plan_sha256'] == sha(continuation_path))
        check('continuation_assets', all(sha(path) == expected for path, expected in continuation['assets'].items()))
        check('continuation_reused_commands', continuation['reused_commands'] == complete['reused_commands'] == state['commands'][:failed_index])
        remaining = plan['jobs'][failed_index + 1:] + [dict(job, supplemental_check=job['id']) for job in supplement['jobs']]
        check('continuation_exact_inventory', continuation['jobs'] == remaining
              and len(remaining) == len(complete['commands']) == continuation['expected_new_commands']
              and len({row['id'] for row in remaining}) == len(remaining))

        failed = state['commands'][failed_index]
        check('original_nonzero_exit_retained', not failed['passed'] and failed['returncode'] == 1
              and all(failed[key] == value for key, value in plan['jobs'][failed_index].items()))
        original_result = read(failed['result'])
        assessment = continuation['strict_script_assessment']
        check('strict_assessment_bound', assessment == complete['strict_script_assessment']
              and assessment['result'] == failed['result'] and assessment['result_sha256'] == sha(failed['result'])
              and assessment['original_returncode'] == 1 and not assessment['original_passed'] and assessment['accepted'])
        history = read(assessment['historical_fixture'])
        check('historical_raw_identity', sha(assessment['historical_fixture']) == assessment['historical_fixture_sha256']
              and sha(history['source_result']) == history['sha256'] == assessment['prior_raw_matrix_sha256'])
        old_raw = read(history['source_result'])
        old = next(row for row in old_raw['profiles'] if row['name'] == 'malformed')['cases']
        check('original_dns_binary_identities', original_result['rust_sha256'] == sdk_sha
              and original_result['c_sha256'] == old_raw['identities']['c']
              and original_result['tool_sha256'] == sha(source / 'tools/dnsmasq/audit_20261011_dns.py'))
        equal_count, exceptions, response_count = 0, set(), 0
        check('original_dns_profile_inventory', set(original_result['profiles']) == {'local', 'forward', 'filter', 'rebind'})
        for profile, value in original_result['profiles'].items():
            for side in ('c', 'rust'):
                health = value['processes'][side]
                check('original_health_' + profile + '_' + side, health['ready'] and health['alive_after_cases']
                      and health['exit'] == 0 and health['health_after']['status'] == 'reply')
            check('original_equal_health_' + profile, value['processes']['c']['health_after'] == value['processes']['rust']['health_after'])
            for row in value['cases']:
                response_count += 1
                observed = {side: {key: item for key, item in row[side].items() if key != 'upstream'} for side in ('c', 'rust')}
                key = (profile, row['name'], row['protocol'])
                if profile == 'local' and row['name'] == 'forward-pointer':
                    prior = old['forward-pointer-' + row['protocol']]
                    check('exact_prior_wire_' + row['protocol'], key not in exceptions
                          and row['query_hex'] == prior['query'] and observed['c'] == prior['c']['response']
                          and observed['rust'] == prior['fix']['response'] and not row['same_client_result']
                          and not row['c']['upstream'] and not row['rust']['upstream'])
                    exceptions.add(key)
                else:
                    check('original_response_' + '-'.join(key), row['same_client_result'] and observed['c'] == observed['rust'])
                    equal_count += 1
        check('exact_original_exception_inventory', exceptions == {('local', 'forward-pointer', 'udp'), ('local', 'forward-pointer', 'tcp')}
              and response_count == assessment['total_responses'] and equal_count == assessment['other_responses_equal'])
        report['strict_script_disposition'] = assessment
        functional_results[failed['id']] = dict(result=file(failed['result']), log=file(functional / (failed['id'] + '.log')),
                                                original_returncode=1, original_passed=False, accepted_as_exact_historical_baseline=True)
        for expected, actual in zip(remaining, complete['commands']):
            name = expected['id']
            check('continuation_command_' + name, all(actual[key] == value for key, value in expected.items())
                  and actual['passed'] and actual['returncode'] == 0 and sha(actual['result']) == actual['result_sha256'])
            if 'strict_result' in actual:
                check('continuation_strict_' + name, actual['strict_result']['passed'])
            functional_results[name] = dict(result=file(actual['result']), log=file(continuation_out / (name + '.log')))
        check('functional_family_inventory', set(complete['families']) == set(plan['selected_families']) == set(continuation['selected_families']))
        for name, family in complete['families'].items():
            expected = [job for job in plan['jobs'] if job.get('family') == name]
            check('functional_family_' + name, family['passed'] and family['commands'] == len(expected))
        total = len(plan['jobs']) + len(supplement['jobs'])
        check('functional_union_complete', complete['passed'] and len(functional_results) == total
              and complete['total_dispositions'] == continuation['expected_total'] == total
              and complete['executed_zero_exit_commands'] == total - 1 and complete['original_strict_script_nonzero_exit'] == 1)
        check('continuation_started_after_original_stopped', min(row['started'] for row in complete['commands'])
              >= max(row['started'] + row['elapsed_seconds'] for row in state['commands']))
        report['functional_results'] = functional_results
        report['functional_inventory'] = dict(primary_commands=len(plan['jobs']), supplemental_commands=len(supplement['jobs']),
            total_dispositions=total, zero_exit_commands=total - 1, retained_original_nonzero_exit=1, families=complete['families'])
        bind('continuation_plan', continuation_path)
        bind('continuation_state', continuation_state_path)

        published = read(args.functional_receipt)
        published_index = read(args.functional_raw_index)
        entries = {row['path']: row for row in published_index['files']}
        check('published_functional_inventory', published['passed_with_declared_baselines']
              and published['source_commit'] == COMMIT and published['source_files'] == files
              and published['elf']['sha256'] == sdk_sha and published['total_dispositions'] == total
              and published['zero_exit_commands'] == total - 1 and published['strict_script_exit_1'] == 1
              and published['complete_families'] == complete['families']
              and published['strict_script_assessment'] == assessment
              and len(entries) == len(published_index['files']))
        check('published_functional_raw_hashes', all(file(path) == value for path, value in entries.items()))
        for name, bound in functional_results.items():
            for kind in ('result', 'log'):
                check('published_' + kind + '_' + name, entries[bound[kind]['path']] == bound[kind])
        for name, bound in published['retained'].items():
            check('published_retained_' + name, entries[bound['path']] == bound)
        for name, archive in published['endpoint_archives'].items():
            evidence = archive['files']
            check('endpoint_receipt_inventory_' + name, set(evidence) == {
                '.tar.gz', '.manifest.json', '.pack.json', '.local-verification.json', '.prune.json', '.restore.json'}
                and all(entries[bound['path']] == bound for bound in evidence.values()))
            manifest = read(evidence['.manifest.json']['path'])
            local_receipt = read(evidence['.local-verification.json']['path'])
            packed = read(evidence['.pack.json']['path'])
            pruned = read(evidence['.prune.json']['path'])
            restored = read(evidence['.restore.json']['path'])
            check('endpoint_archive_binding_' + name, local_receipt['verified'] and local_receipt['local_full_metadata_verified']
                  and local_receipt['archive_sha256'] == manifest['archive_sha256'] == evidence['.tar.gz']['sha256']
                  and local_receipt['manifest_sha256'] == evidence['.manifest.json']['sha256']
                  and local_receipt['entries'] == archive['entries'] == len(manifest['entries'])
                  and packed['result']['archive_sha256'] == manifest['archive_sha256']
                  and pruned['archive_sha256'] == manifest['archive_sha256']
                  and pruned['removed'] == manifest['run'] and pruned['allocated_bytes_removed'] > 0
                  and archive['local_full_metadata_verified'] and archive['original_result_bytes_retained'])
            check('endpoint_original_result_retained_' + name, sha(Path(manifest['run']) / 'result.json')
                  == manifest['entries']['result.json']['sha256'])
            report.setdefault('endpoint_archives', {})[name] = dict(entries=archive['entries'], files=evidence, restore_receipt=restored)
        bind('published_functional_receipt', args.functional_receipt)
        bind('published_functional_raw_index', args.functional_raw_index)

        perf = args.performance_out or private / 'performance-paired-01'
        pp, run, summary, inv = [read(perf / name) for name in ('plan.json', 'run.json', 'summary.json', 'driver-invocation.json')]
        ready_path = args.ready_receipt or private / 'performance-ready.json'
        ready = read(ready_path)
        check('performance_ready', ready['functional_complete'] and ready['builds_complete']
              and ready['source_commit'] == COMMIT and ready['candidate_sha256'] == release_sha)
        for field, target in (('functional_state_sha256', continuation_state_path),
                              ('original_functional_state_sha256', functional / 'state.json'),
                              ('continuation_plan_sha256', continuation_path),
                              ('supplemental_plan_sha256', supplement_path),
                              ('build_result_sha256', private / 'build-result.json')):
            check('performance_ready_' + field, ready[field] == sha(target))
        check('performance_ready_copy', sha(ready_path) == sha(perf / 'ready-receipt.json') == run['ready_receipt_sha256'] == inv['ready_receipt_sha256'])
        check('performance_plan_identity', pp['source_commit'] == COMMIT and pp['main_commit'] == MAIN and pp['source_identity'] == identity
              and sha(perf / 'plan.json') == run['plan_sha256'] == summary['plan_sha256'] == inv['plan_sha256'])
        check('performance_complete', run['status'] == 'complete' and inv['returncode'] == 0 and summary['complete'] and not summary['errors'])
        check('performance_inventory', [w['id'] for w in pp['windows']] == [w['id'] for w in run['windows']] == [w['id'] for w in summary['windows']]
              and len(pp['windows']) == pp['measurement']['total_windows'])
        check('performance_assets', all(sha(path) == expected for path, expected in pp['assets'].items()))
        for variant, group in pp['groups'].items():
            check('performance_group_' + variant, sha(group['elf']) == group['sha256'] and read(group['build_receipt']) == group['build'])
        check('performance_final_release', pp['groups']['fix']['sha256'] == release_sha)
        driver = next(Path(arg) for arg in inv['argv'] if str(arg).endswith('paired_tcp_records.py'))
        check('performance_driver', sha(driver) == inv['driver_sha256'])
        if 'driver_log_sha256' in inv:
            check('performance_driver_log', sha(perf / 'driver.log') == inv['driver_log_sha256'])
        raw_index = {}
        for planned, executed, observed in zip(pp['windows'], run['windows'], summary['windows']):
            name = planned['id']
            folder = perf / name
            row = read(folder / 'result.json')
            expected_argv = planned['argv'][3:4] + planned['argv'][6:]
            check('performance_window_' + name, executed['returncode'] == 0 and row['accepted'] and row['measurement_valid']
                  and row['identity']['expected_elf_sha256'] == pp['groups'][planned['variant']]['sha256']
                  and row['identity']['argv'] == expected_argv and observed['valid_for_comparison'])
            check(name + '_instrumentation_off', all(not row['identity'][key] for key in ('perf_record', 'strace_summary', 'wake_metrics')))
            check(name + '_raw_hashes', bool(observed['raw_files']) and all(sha(folder / path) == expected for path, expected in observed['raw_files'].items()))
            check(name + '_controller_hashes', all(sha(value['path']) == value['sha256'] for value in observed['controller_evidence'].values()))
            raw_index[name] = observed['raw_files']
        report['performance_raw_index'] = raw_index
        report['performance_comparisons'] = summary['comparisons']
        report['performance_guards'] = summary['guards']
        for name in ('plan.json', 'ready-receipt.json', 'run.json', 'summary.json', 'driver-invocation.json'):
            bind('performance_' + name, perf / name)
        check('performance_started_after_functional', min(row['started_ns'] for row in run['windows']) / 1e9
              >= max(row['started'] + row['elapsed_seconds'] for row in state['commands'] + complete['commands']))
        check('closure_after_controllers', report['created_unix'] >= run['ended_ns'] / 1e9 and report['created_unix'] >= build['ended'])
        report['passed'] = True
    except Exception as error:
        report['error'] = repr(error)
    finally:
        for handle in handles:
            handle.close()
        save(args.out, report)
    print(json.dumps(dict(passed=report['passed'], checks=len(report['checks']), error=report.get('error'), output=str(args.out))))
    return int(not report['passed'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    local = sub.add_parser('git-witness')
    local.add_argument('--repo', type=Path, required=True)
    local.add_argument('--out', type=Path, required=True)
    remote_args = sub.add_parser('remote')
    remote_args.add_argument('--root', type=Path, default=ROOT)
    remote_args.add_argument('--git-witness', type=Path, required=True)
    remote_args.add_argument('--functional-plan', type=Path)
    remote_args.add_argument('--supplemental-plan', type=Path)
    remote_args.add_argument('--continuation-plan', type=Path)
    remote_args.add_argument('--functional-receipt', type=Path, required=True)
    remote_args.add_argument('--functional-raw-index', type=Path, required=True)
    remote_args.add_argument('--performance-out', type=Path)
    remote_args.add_argument('--ready-receipt', type=Path)
    remote_args.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    return witness(args) if args.mode == 'git-witness' else remote(args)


if __name__ == '__main__':
    raise SystemExit(main())
