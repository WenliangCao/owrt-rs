#!/usr/bin/env python3
"""Rehash final build/function evidence and check oracle cleanup; no reruns."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def receipt(path):
    path = Path(path)
    return {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}


def recipe_files(path):
    if path.is_symlink():
        return {'symlink': os.readlink(path)}
    if not path.exists():
        return None
    return {str(child.relative_to(path)): ('link:' + os.readlink(child) if child.is_symlink() else sha(child))
            for child in sorted(path.rglob('*')) if child.is_symlink() or child.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--functional-derived', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, private = args.root.resolve(), args.root.resolve() / 'private'
    source = root / 'source-final'
    assert os.geteuid() == 0 and not sys.flags.optimize and not args.out.exists()
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    import build_package as package
    import m5_final_validation as final
    identity = read(private / 'source-final-identity.json')
    build = read(private / 'build-final-result.json')
    manifests = [read(private / ('sdk-' + kind + '-final/manifest.json')) for kind in ('acquire', 'verify')]
    report = {'schema': 'dnsmasq-fix4-final-closure-v1', 'passed': False, 'started': time.time(),
              'source_commit': identity['source_commit'], 'checks': {}, 'bindings': {},
              'limits': ['Only this final SDK, 49-command validation and three new DHCP probes are rehashed.',
                         'Earlier performance raw evidence and all historical audits are not rechecked here.',
                         'Local main/worktree/prompt checks are performed separately by the root agent.',
                         'Original size-budget failure is retained; no physical-router or deployment qualification.'],
              'controller': receipt(__file__)}
    handles = []

    def check(name, condition):
        if not condition:
            raise ValueError(name)
        report['checks'][name] = True

    def bind(name, path):
        report['bindings'][name] = receipt(path)

    try:
        locks = [Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock'),
                 Path(manifests[1]['sdk']['path']) / '.owrt-dnsmasq-build.lock']
        for lock in locks:
            handle = lock.open('r')
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            handles.append(handle)
        report['locks'] = [str(path) for path in locks]
        check('both_build_locks_acquired', True)
        excluded, busy = final.related_processes(), []
        for path in Path('/proc').glob('[0-9]*/cmdline'):
            if int(path.parent.name) in excluded:
                continue
            try:
                raw = path.read_bytes()
                if not raw:
                    continue
                argv = raw.replace(b'\0', b' ').decode(errors='replace')
                executable = Path(raw.split(b'\0')[0].decode(errors='replace')).name
                process_root = os.readlink(path.parent / 'root')
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if '/dnsmasq-fix4-' in argv or str(root) in process_root or executable in {
                    'cargo', 'rustc', 'make', 'perf', 'strace', 'dnsmasq', 'dnsmasq-rs', 'm6a_loadgen', 'm6a_upstream'}:
                busy.append({'pid': int(path.parent.name), 'argv': argv})
        report['remaining_workloads'] = busy
        check('no_task_or_matching_workloads', not busy)
        files = package.inputs(source)
        check('all_frozen_product_inputs', files == identity['source_files'] and len(files) == 178)
        check('source_digest', hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == identity['source_digest'])
        check('source_archive', sha(private / 'source-final.tar') == identity['source_archive_sha256'])
        check('final_build_passed', build['passed'] and build['source_digest'] == identity['source_digest'])
        bind('source_identity', private / 'source-final-identity.json')
        bind('build', private / 'build-final-result.json')
        bind('build_derived', private / 'build-final-derived.json')
        copy = read(private / 'sdk-copy.json')
        sdk = Path(manifests[0]['sdk']['path'])
        for kind, manifest in zip(('acquire', 'verify'), manifests):
            check(kind + '_real_source_build', manifest['source_build_passed'] and not manifest['frozen_elf'])
            check(kind + '_sdk_inputs', package.sdk_inputs(sdk) == manifest['sdk']['files'])
            for name in ('elf', 'artifact'):
                check(kind + '_' + name, sha(manifest[name]['path']) == manifest[name]['sha256'])
                bind(kind + '_' + name, manifest[name]['path'])
            recipe = Path(manifest['sdk_recipe_path'])
            original = Path(copy['source']) / recipe.relative_to(Path(copy['destination']))
            check(kind + '_recipe_restored', manifest['sdk_recipe_restored'] and recipe_files(recipe) == recipe_files(original))
            check(kind + '_no_recipe_backup', not (sdk / ('.dnsmasq-backup-sdk-' + kind + '-final')).exists())
            bind(kind + '_manifest', private / ('sdk-' + kind + '-final/manifest.json'))
        check('two_clean_sdk_artifacts_equal', all(manifests[0][name]['sha256'] == manifests[1][name]['sha256'] for name in ('elf', 'artifact')))
        check('actual_sdk_link_map', sha(manifests[1]['link_map']['path']) == manifests[1]['link_map']['sha256'])
        bind('actual_sdk_link_map', manifests[1]['link_map']['path'])
        plan_path = private / 'functional-final-plan.json'
        state_path = private / 'functional-final/state.json'
        plan, state = read(plan_path), read(state_path)
        check('49_fresh_jobs', state['passed'] and len(state['commands']) == 49 and len(plan['jobs']) == 49)
        check('frozen_functional_plan', state['plan_sha256'] == sha(plan_path))
        for job in state['commands']:
            check('job_' + job['id'], job['passed'] and job['returncode'] == 0 and sha(job['result']) == job['result_sha256'])
        n1 = next(row for row in state['commands'] if row['id'] == 'N1-filter-cname')['strict_result']
        check('N1_exact_72', n1['passed'] and n1['cases'] == 72 and not n1['failures'])
        bind('functional_plan', plan_path)
        bind('functional_state', state_path)
        indexes = {'functional': args.functional_derived / 'raw-index.json',
                   'new_DHCP': private / 'dhcp-final-derived/dhcp-sdk-raw-index.json'}
        report['raw_indexes'] = {}
        for name, path in indexes.items():
            rows = read(path)['files']
            for row in rows:
                if receipt(row['path']) != row:
                    raise ValueError('raw identity: ' + row['path'])
            report['raw_indexes'][name] = {'index': receipt(path), 'verified_files': len(rows)}
        bind('functional_derived', args.functional_derived / 'validation.json')
        bind('DHCP_derived', private / 'dhcp-final-derived/dhcp-sdk.json')
        dhcp = read(private / 'dhcp-final-invocations.json')
        check('three_new_DHCP_probes', dhcp['passed'] and len(dhcp['commands']) == 3)
        for row, count in zip(dhcp['commands'], (24, 64, 12)):
            check('DHCP_' + row['id'], row['passed'] and row['returncode'] == 0 and row['cases'] == count
                  and sha(row['summary']) == row['summary_sha256'] and sha(row['log']) == row['log_sha256'])
        bind('DHCP_invocations', private / 'dhcp-final-invocations.json')
        failed = read(private / 'build-scan-result.json')
        check('first_scan_failure_preserved', not failed['passed'] and failed['commands'][-1]['returncode'] == 101)
        bind('first_scan_failed_build', private / 'build-scan-result.json')
        report['passed'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        for handle in handles:
            fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()
        report['locks_released'] = len(handles) == 2
        report['ended'] = time.time()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('x') as stream:
            stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'closure': receipt(args.out),
                      'verified_files': {name: row['verified_files'] for name, row in report['raw_indexes'].items()}}))


if __name__ == '__main__':
    main()
